//! Acceptance tests for #1117 (`update --open-pr`), written tests-first against spec 104
//! (FR-002 to FR-014) and its plan's contracts.
//!
//! The git phase runs against a real git repository with a bare `origin`; `gh`/`glab` are shell
//! shims in `RepoContext::tool_dir` that record their argv (NUL separated) and print a URL.
//! `RepoContext::{tool_dir, group}` are private fields, assigned here as a child module.
//! Declared in `update/pr/mod.rs` as `#[cfg(all(test, unix))] mod acceptance_tests;`.
//!
//! The two `PrSignals` tests raise a real SIGINT in the test process and rely on nextest's
//! process-per-test isolation (the project's runner).

#![expect(clippy::expect_used, reason = "test code")]
#![allow(clippy::panic)]

use std::assert_matches;
use std::collections::HashSet;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use clap::Parser;
use deps_core::ConcreteVersion;
use deps_core::EcosystemId;

use super::git::{Step, Tool};
use super::{
    BranchCheck, PrError, PrHost, PrOutcome, PrPhase, PrSignals, Readiness, RepoContext,
    branch_for, check_branch, describe, open, preflight, readiness, restore,
};
use crate::cli::Cli;
use crate::update::group::UpdateGroup;
use crate::update::group_tests::{applied, group_from, item, skipped};
use crate::update::regen::{LockfileOutcome, NotApplicableReason, ProcessGroup};
use crate::update::{CurrentVersion, Outcome, SkipReason, UnfixableReason, UpdatePlan, UpdateRun};

fn no_run() -> UpdateRun {
    UpdateRun {
        plan: UpdatePlan::default(),
        lockfile: LockfileOutcome::NotApplicable(NotApplicableReason::NoLockfilePresent),
    }
}

pub(super) const STUB_FORMATTER: deps_core::test_util::StubFormatter =
    deps_core::test_util::StubFormatter::new().with_package_url_prefix("");
pub(super) const URL: &str = "https://example.test/pr/1";

// --- fixture ---

pub(super) fn git(dir: &Path, args: &[&str]) -> String {
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .expect("run git");
    assert!(
        output.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout)
        .trim_end()
        .to_owned()
}

pub(super) struct Fixture {
    pub(super) tmp: tempfile::TempDir,
    pub(super) root: PathBuf,
    pub(super) origin: PathBuf,
}

impl Fixture {
    pub(super) fn new() -> Self {
        let tmp = tempfile::tempdir().expect("fixture dir");
        let origin = tmp.path().join("origin.git");
        let root = tmp.path().join("work");
        for dir in [
            &origin,
            &root,
            &tmp.path().join("tools"),
            &tmp.path().join("hooks"),
        ] {
            std::fs::create_dir_all(dir).expect("mkdir");
        }
        git(&origin, &["init", "--bare", "--initial-branch=main"]);
        git(&root, &["init", "--initial-branch=main"]);
        for (key, value) in [
            ("user.name", "Fixture"),
            ("user.email", "fixture@example.test"),
            ("commit.gpgsign", "false"),
            (
                "core.hooksPath",
                tmp.path().join("hooks").to_str().expect("utf-8"),
            ),
        ] {
            git(&root, &["config", key, value]);
        }
        let fixture = Self { tmp, root, origin };
        for file in [
            "Cargo.toml",
            "Cargo.lock",
            "app/Cargo.toml",
            "app/Cargo.lock",
            "app/sub/inner.txt",
            "other/file.txt",
            "a/b/Cargo.toml",
            "a-b/Cargo.toml",
        ] {
            fixture.write(file, &format!("initial {file}\n"));
        }
        git(&fixture.root, &["add", "--all"]);
        git(&fixture.root, &["commit", "--message=initial"]);
        git(
            &fixture.root,
            &[
                "remote",
                "add",
                "origin",
                fixture.origin.to_str().expect("utf-8"),
            ],
        );
        git(&fixture.root, &["push", "--set-upstream", "origin", "main"]);
        fixture
    }

    pub(super) fn write(&self, relative: &str, content: &str) {
        let path = self.root.join(relative);
        std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
        std::fs::write(path, content).expect("write");
    }

    pub(super) fn read(&self, relative: &str) -> String {
        std::fs::read_to_string(self.root.join(relative)).expect("read")
    }

    pub(super) fn tools(&self) -> PathBuf {
        self.tmp.path().join("tools")
    }

    pub(super) fn record(&self, file: &str) -> PathBuf {
        self.tmp.path().join(file)
    }

    /// A shim named `name` that records argv, `GH_PROMPT_DISABLED` and cwd, then prints noise and a URL.
    pub(super) fn url_shim(&self, name: &str) {
        self.shim(
            name,
            &format!(
                "for a in \"$@\"; do printf '%s\\0' \"$a\"; done > '{argv}'\nprintf '%s' \"$GH_PROMPT_DISABLED\" > '{env}'\npwd -P > '{cwd}'\necho 'Creating pull request...'\necho '{URL}'\necho\n",
                argv = self.record(&format!("{name}.argv")).display(),
                env = self.record(&format!("{name}.env")).display(),
                cwd = self.record(&format!("{name}.cwd")).display(),
            ),
        );
    }

    pub(super) fn shim(&self, name: &str, body: &str) {
        let path = self.tools().join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}")).expect("write shim");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    }

    pub(super) fn argv(&self, name: &str) -> Vec<String> {
        let bytes = std::fs::read(self.record(&format!("{name}.argv"))).expect("shim was not run");
        bytes
            .split(|byte| *byte == 0)
            .filter(|part| !part.is_empty())
            .map(|part| String::from_utf8_lossy(part).into_owned())
            .collect()
    }

    pub(super) async fn ctx(&self, manifest: &str) -> RepoContext {
        let mut ctx = match preflight(&self.root.join(manifest)).await {
            Ok(ctx) => ctx,
            Err(error) => panic!("preflight must pass on the fixture: {error:?}"),
        };
        ctx.tool_dir = Some(self.tools());
        ctx.group = ProcessGroup::Own;
        ctx
    }

    pub(super) fn status(&self) -> Vec<String> {
        let mut lines: Vec<String> = git(
            &self.root,
            &["status", "--porcelain", "--untracked-files=no"],
        )
        .lines()
        .map(str::to_owned)
        .collect();
        lines.sort();
        lines
    }

    pub(super) fn head(&self) -> String {
        git(&self.root, &["symbolic-ref", "--short", "HEAD"])
    }

    pub(super) fn origin_has(&self, branch: &str) -> bool {
        std::process::Command::new("git")
            .arg("--git-dir")
            .arg(&self.origin)
            .args([
                "rev-parse",
                "--verify",
                "--quiet",
                &format!("refs/heads/{branch}"),
            ])
            .status()
            .expect("run git")
            .success()
    }
}

/// `readiness` then `describe`, as `main.rs` does; the run must be publishable.
fn text_of(
    ctx: &RepoContext,
    run: &UpdateRun,
    group: Option<&UpdateGroup>,
) -> super::PullRequestText {
    let Readiness::Ready(publishable) = readiness(run) else {
        panic!("the run must be publishable");
    };
    describe(ctx, &publishable, group)
}

pub(super) fn error<T>(result: Result<T, PrError>) -> PrError {
    match result {
        Ok(_) => panic!("expected an error"),
        Err(error) => error,
    }
}

pub(super) fn plan(updates: &[(&str, &str, &str)]) -> UpdatePlan {
    UpdatePlan {
        items: updates
            .iter()
            .map(|(name, current, target)| item(name, current, applied(target)))
            .collect(),
    }
}

pub(super) fn run_of(plan: UpdatePlan) -> UpdateRun {
    UpdateRun {
        plan,
        lockfile: LockfileOutcome::NotApplicable(NotApplicableReason::NothingApplied),
    }
}

fn branch(ctx: &RepoContext, plan: &UpdatePlan, group: Option<&UpdateGroup>) -> String {
    branch_for(ctx, EcosystemId::Cargo, plan, &STUB_FORMATTER, group)
        .expect("the plan proposes an update")
        .as_str()
        .to_owned()
}

fn hash_suffix(branch: &str) -> &str {
    let (_, hash) = branch.rsplit_once('-').expect("branch ends in -<h8>");
    assert!(
        hash.len() == 8
            && hash
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "{branch} must end in -<8 lowercase hex digits>"
    );
    hash
}

fn assert_all_distinct(branches: &[String]) {
    let unique: HashSet<&String> = branches.iter().collect();
    assert_eq!(
        unique.len(),
        branches.len(),
        "branches collide: {branches:#?}"
    );
    for branch in branches {
        hash_suffix(branch);
        assert!(branch.starts_with("deps-cli/"), "{branch}");
        assert!(branch.len() <= 140, "{branch} is {} bytes", branch.len());
    }
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(0x0100_0000_01b3)
    })
}

fn alive(pid: u32) -> bool {
    std::process::Command::new("kill")
        .args(["-0", &pid.to_string()])
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

async fn gone_within(pid: u32, within: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < within {
        if !alive(pid) {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    !alive(pid)
}

async fn pid_from(path: &Path) -> u32 {
    for _ in 0..400 {
        if let Ok(text) = std::fs::read_to_string(path)
            && let Ok(pid) = text.trim().parse()
        {
            return pid;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("{} was never written", path.display());
}

// --- FR-002: preflight ---

#[tokio::test]
async fn test_preflight_clean_repository_on_a_named_branch_passes_also_from_a_subdirectory() {
    let fx = Fixture::new();
    fx.write("untracked.txt", "not tracked\n");

    assert!(preflight(&fx.root.join("Cargo.toml")).await.is_ok());
    assert!(preflight(&fx.root.join("app/Cargo.toml")).await.is_ok());
}

#[tokio::test]
async fn test_preflight_tracked_modification_is_a_dirty_tree() {
    let fx = Fixture::new();
    fx.write("other/file.txt", "edited\n");

    let result = preflight(&fx.root.join("Cargo.toml")).await;

    assert_matches!(error(result), PrError::DirtyWorkingTree);
}

#[tokio::test]
async fn test_preflight_detached_head_is_refused() {
    let fx = Fixture::new();
    git(&fx.root, &["checkout", "--detach"]);

    let result = preflight(&fx.root.join("Cargo.toml")).await;

    assert_matches!(error(result), PrError::DetachedHead);
}

#[tokio::test]
async fn test_preflight_head_on_an_update_branch_is_refused() {
    let fx = Fixture::new();
    git(&fx.root, &["switch", "--create", "deps-cli/x"]);

    let result = preflight(&fx.root.join("Cargo.toml")).await;

    assert_matches!(
        error(result),
        PrError::OnUpdateBranch { branch } if branch == "deps-cli/x"
    );
}

#[tokio::test]
async fn test_preflight_without_committer_identity_is_refused() {
    let fx = Fixture::new();
    git(&fx.root, &["config", "user.name", ""]);
    git(&fx.root, &["config", "user.email", ""]);

    let result = preflight(&fx.root.join("Cargo.toml")).await;

    assert_matches!(error(result), PrError::MissingIdentity);
}

#[tokio::test]
async fn test_preflight_outside_a_repository_is_refused() {
    let dir = tempfile::tempdir().expect("plain dir");
    std::fs::write(dir.path().join("Cargo.toml"), "x\n").expect("write");

    let result = preflight(&dir.path().join("Cargo.toml")).await;

    assert_matches!(error(result), PrError::NotARepository);
}

// --- spec 5: branch grammar ---

#[tokio::test]
async fn test_branch_for_without_a_proposed_item_is_none() {
    let fx = Fixture::new();
    let ctx = fx.ctx("Cargo.toml").await;
    let only_skipped = UpdatePlan {
        items: vec![item("dep", "1.0.0", skipped(SkipReason::IgnoreRule))],
    };

    for plan in [UpdatePlan::default(), only_skipped] {
        assert!(branch_for(&ctx, EcosystemId::Cargo, &plan, &STUB_FORMATTER, None).is_none());
    }
}

#[tokio::test]
async fn test_branch_for_shapes_label_dir_and_group() {
    let fx = Fixture::new();
    let root_ctx = fx.ctx("Cargo.toml").await;
    let app_ctx = fx.ctx("app/Cargo.toml").await;
    let one = plan(&[("serde", "1.0.0", "1.2.0")]);
    let two = plan(&[("serde", "1.0.0", "1.2.0"), ("tokio", "1.0.0", "1.1.0")]);
    let group = group_from("[update.groups.minor-patch]\n", "minor-patch");

    let single = branch(&root_ctx, &one, None);
    let several = branch(&root_ctx, &two, None);
    let grouped = branch(&root_ctx, &two, Some(&group));
    let in_dir = branch(&app_ctx, &one, None);

    assert!(
        single.starts_with("deps-cli/cargo/serde-1.2.0-"),
        "{single}"
    );
    assert!(several.starts_with("deps-cli/cargo/all-"), "{several}");
    assert!(
        grouped.starts_with("deps-cli/cargo/minor-patch-"),
        "{grouped}"
    );
    assert!(
        in_dir.starts_with("deps-cli/cargo/app/serde-1.2.0-"),
        "{in_dir}"
    );
    for branch in [&single, &several, &grouped, &in_dir] {
        hash_suffix(branch);
    }
}

/// Pins the `<h8>` input of spec 104 section 5 byte for byte: first 8 hex digits of FNV-1a 64
/// over `<eco>\n<manifest path>\n<group or empty>\n` and the sorted `<name>\t<target>\n` lines.
#[tokio::test]
async fn test_branch_for_hash_is_fnv1a_over_ecosystem_path_group_and_sorted_items() {
    assert_eq!(fnv1a64(b""), 0xcbf2_9ce4_8422_2325);
    assert_eq!(fnv1a64(b"a"), 0xaf63_dc4c_8601_ec8c);
    let fx = Fixture::new();
    let ctx = fx.ctx("app/Cargo.toml").await;
    let two = plan(&[("beta", "2.0.0", "2.1.0"), ("alpha", "1.0.0", "1.1.0")]);
    let group = group_from("[update.groups.minor-patch]\n", "minor-patch");
    let h8 = |input: &str| format!("{:08x}", fnv1a64(input.as_bytes()) >> 32);

    let ungrouped = branch(&ctx, &two, None);
    let grouped = branch(&ctx, &two, Some(&group));

    assert_eq!(
        ungrouped,
        format!(
            "deps-cli/cargo/app/all-{}",
            h8("cargo\napp/Cargo.toml\n\nalpha\t1.1.0\nbeta\t2.1.0\n")
        )
    );
    assert_eq!(
        grouped,
        format!(
            "deps-cli/cargo/app/minor-patch-{}",
            h8("cargo\napp/Cargo.toml\nminor-patch\nalpha\t1.1.0\nbeta\t2.1.0\n")
        )
    );
}

#[tokio::test]
async fn test_branch_for_ignores_item_order_and_skipped_items() {
    let fx = Fixture::new();
    let ctx = fx.ctx("Cargo.toml").await;
    let forward = plan(&[("alpha", "1.0.0", "1.1.0"), ("beta", "2.0.0", "2.1.0")]);
    let backward = plan(&[("beta", "2.0.0", "2.1.0"), ("alpha", "1.0.0", "1.1.0")]);
    let mut with_skipped = forward.clone();
    with_skipped
        .items
        .push(item("gamma", "1.0.0", skipped(SkipReason::NotRequested)));

    let expected = branch(&ctx, &forward, None);

    assert_eq!(branch(&ctx, &backward, None), expected);
    assert_eq!(branch(&ctx, &with_skipped, None), expected);
}

#[tokio::test]
async fn test_branch_for_requires_lockfile_update_item_counts_as_proposed() {
    let fx = Fixture::new();
    let ctx = fx.ctx("Cargo.toml").await;
    let plan = UpdatePlan {
        items: vec![item(
            "serde",
            "1.0.0",
            Outcome::RequiresLockfileUpdate {
                target: ConcreteVersion::from("1.0.5"),
                ecosystem: EcosystemId::Cargo,
            },
        )],
    };

    assert!(branch(&ctx, &plan, None).starts_with("deps-cli/cargo/serde-1.0.5-"));
}

#[tokio::test]
async fn test_branch_for_hostile_names_are_valid_git_refs() {
    let fx = Fixture::new();
    let ctx = fx.ctx("Cargo.toml").await;
    let long = "x".repeat(300);
    let hostile = [
        "@scope/x",
        "g:a",
        "..",
        "a.lock",
        "-x",
        "@{",
        "has space",
        "\u{fc}n\u{ef}c\u{f6}de",
        "a..b",
        "~^:?*[\\",
        "",
        "/",
        "x/../y",
        "@",
        ".hidden",
        "trailing.",
        long.as_str(),
    ];

    let branches: Vec<String> = hostile
        .iter()
        .map(|name| branch(&ctx, &plan(&[(name, "1.0.0", "1.0.1")]), None))
        .collect();

    assert_all_distinct(&branches);
    for branch in &branches {
        git(&fx.root, &["check-ref-format", "--branch", branch]);
    }
}

#[tokio::test]
async fn test_branch_for_cuts_the_human_label_to_48_characters_but_keeps_the_hash() {
    let fx = Fixture::new();
    let ctx = fx.ctx("Cargo.toml").await;
    let name = "n".repeat(200);

    let branch = branch(&ctx, &plan(&[(&name, "1.0.0", "1.0.1")]), None);

    let leaf = branch.rsplit('/').next().expect("leaf");
    assert!(leaf.len() <= 48 + "-".len() + 8, "{leaf}");
    hash_suffix(&branch);
}

#[tokio::test]
async fn test_branch_for_lossy_sanitizing_never_makes_different_names_share_a_branch() {
    let fx = Fixture::new();
    let ctx = fx.ctx("Cargo.toml").await;

    let branches = [
        branch(&ctx, &plan(&[("@scope/x", "1.0.0", "1.0.1")]), None),
        branch(&ctx, &plan(&[("scope-x", "1.0.0", "1.0.1")]), None),
    ];

    assert_all_distinct(&branches);
}

#[tokio::test]
async fn test_branch_for_manifests_in_dirs_that_sanitize_alike_get_different_branches() {
    let fx = Fixture::new();
    let one = plan(&[("serde", "1.0.0", "1.0.1")]);

    let branches = [
        branch(&fx.ctx("a/b/Cargo.toml").await, &one, None),
        branch(&fx.ctx("a-b/Cargo.toml").await, &one, None),
    ];

    assert_all_distinct(&branches);
}

#[tokio::test]
async fn test_branch_for_long_group_name_with_different_update_sets_get_different_branches() {
    let fx = Fixture::new();
    let ctx = fx.ctx("Cargo.toml").await;
    let name = "g".repeat(64);
    let group = group_from(&format!("[update.groups.{name}]\n"), &name);

    let branches = [
        branch(&ctx, &plan(&[("serde", "1.0.0", "1.0.1")]), Some(&group)),
        branch(&ctx, &plan(&[("serde", "1.0.0", "1.0.2")]), Some(&group)),
    ];

    assert_all_distinct(&branches);
}

#[tokio::test]
async fn test_branch_for_long_single_name_at_two_targets_gets_different_branches() {
    let fx = Fixture::new();
    let ctx = fx.ctx("Cargo.toml").await;
    let name = "p".repeat(200);

    let branches = [
        branch(&ctx, &plan(&[(&name, "1.0.0", "1.0.1")]), None),
        branch(&ctx, &plan(&[(&name, "1.0.0", "1.0.2")]), None),
    ];

    assert_all_distinct(&branches);
}

#[tokio::test]
async fn test_branch_for_same_update_set_with_and_without_a_group_gets_different_branches() {
    let fx = Fixture::new();
    let ctx = fx.ctx("Cargo.toml").await;
    let group = group_from("[update.groups.g]\n", "g");
    let one = plan(&[("serde", "1.0.0", "1.0.1")]);

    let branches = [branch(&ctx, &one, None), branch(&ctx, &one, Some(&group))];

    assert_all_distinct(&branches);
}

// --- FR-004 to FR-006: branch check ---

async fn checked(ctx: &RepoContext) -> Result<BranchCheck, PrError> {
    let one = plan(&[("serde", "1.0.0", "1.2.0")]);
    let proposed =
        branch_for(ctx, EcosystemId::Cargo, &one, &STUB_FORMATTER, None).expect("branch");
    check_branch(ctx, proposed).await
}

#[tokio::test]
async fn test_check_branch_absent_everywhere_is_free() {
    let fx = Fixture::new();
    let ctx = fx.ctx("Cargo.toml").await;

    let result = checked(&ctx).await;

    assert_matches!(result, Ok(BranchCheck::Free(_)));
}

#[tokio::test]
async fn test_check_branch_present_on_origin_is_already_proposed() {
    let fx = Fixture::new();
    let ctx = fx.ctx("Cargo.toml").await;
    let name = branch(&ctx, &plan(&[("serde", "1.0.0", "1.2.0")]), None);
    git(
        &fx.root,
        &["push", "origin", &format!("HEAD:refs/heads/{name}")],
    );

    let result = checked(&ctx).await;

    assert_matches!(
        result,
        Ok(BranchCheck::AlreadyProposed(found)) if found.as_str() == name
    );
}

#[tokio::test]
async fn test_check_branch_only_local_is_a_stale_local_branch() {
    let fx = Fixture::new();
    let ctx = fx.ctx("Cargo.toml").await;
    let name = branch(&ctx, &plan(&[("serde", "1.0.0", "1.2.0")]), None);
    git(&fx.root, &["branch", &name]);

    let result = checked(&ctx).await;

    assert_matches!(
        result,
        Err(PrError::StaleLocalBranch { branch }) if branch == name
    );
}

// --- FR-007: restore ---

#[tokio::test]
async fn test_restore_reverts_only_files_directly_inside_the_manifest_directory() {
    let fx = Fixture::new();
    let ctx = fx.ctx("app/Cargo.toml").await;
    for file in [
        "app/Cargo.toml",
        "app/Cargo.lock",
        "app/sub/inner.txt",
        "other/file.txt",
        "Cargo.toml",
    ] {
        fx.write(file, "edited\n");
    }
    git(&fx.root, &["add", "app/Cargo.lock"]);
    fx.write("app/untracked.txt", "keep me\n");

    restore(&ctx, &no_run()).await.expect("restore");

    assert_eq!(fx.read("app/Cargo.toml"), "initial app/Cargo.toml\n");
    assert_eq!(fx.read("app/Cargo.lock"), "initial app/Cargo.lock\n");
    assert_eq!(
        fx.status(),
        [" M Cargo.toml", " M app/sub/inner.txt", " M other/file.txt"],
        "the index must be restored too; other paths stay modified"
    );
    assert_eq!(fx.read("app/untracked.txt"), "keep me\n");
}

#[tokio::test]
async fn test_restore_at_the_repository_root_leaves_subdirectories_alone() {
    let fx = Fixture::new();
    let ctx = fx.ctx("Cargo.toml").await;
    for file in [
        "Cargo.toml",
        "Cargo.lock",
        "app/Cargo.toml",
        "other/file.txt",
    ] {
        fx.write(file, "edited\n");
    }

    restore(&ctx, &no_run()).await.expect("restore");

    assert_eq!(fx.status(), [" M app/Cargo.toml", " M other/file.txt"]);
}

// --- FR-008 to FR-013: open ---

struct Opened {
    branch: String,
    title: String,
    body: String,
    commit_body: String,
}

fn withheld_and_applied() -> UpdatePlan {
    UpdatePlan {
        items: vec![
            item("serde", "1.0.0", applied("1.2.0")),
            item(
                "tokio",
                "1.0.0",
                Outcome::Unfixable(UnfixableReason::ResolvesWithinCooldown {
                    target: ConcreteVersion::from("1.5.0"),
                    resolved: ConcreteVersion::from("1.6.0"),
                }),
            ),
        ],
    }
}

#[tokio::test]
async fn test_describe_leaves_a_withheld_fix_out_of_the_request_text() {
    let fx = Fixture::new();
    let ctx = fx.ctx("Cargo.toml").await;

    let text = text_of(&ctx, &run_of(withheld_and_applied()), None);

    assert!(text.body.contains("serde"), "{}", text.body);
    for part in [&text.title, &text.body, &text.commit_body] {
        assert!(
            !part.contains("tokio") && !part.contains("1.5.0"),
            "withheld fix leaked into: {part}"
        );
    }
}

#[test]
fn test_readiness_with_only_a_withheld_fix_is_nothing_settled() {
    let plan = UpdatePlan {
        items: vec![withheld_and_applied().items.remove(1)],
    };

    assert_matches!(readiness(&run_of(plan)), Readiness::NothingSettled);
}

#[test]
fn test_readiness_with_only_a_held_lock_only_fix_is_nothing_settled() {
    let plan = UpdatePlan {
        items: vec![item(
            "tokio",
            "1.0.0",
            Outcome::RequiresLockfileUpdate {
                target: ConcreteVersion::from("1.5.0"),
                ecosystem: EcosystemId::Cargo,
            },
        )],
    };

    assert_matches!(readiness(&run_of(plan)), Readiness::NothingSettled);
}

async fn open_with(
    fx: &Fixture,
    host: PrHost,
) -> (Opened, RepoContext, Result<PrOutcome, PrError>) {
    let ctx = fx.ctx("Cargo.toml").await;
    fx.write("Cargo.toml", "bumped\n");
    fx.write("notes.txt", "untracked, must not be committed\n");
    let one = plan(&[("serde", "1.0.0", "1.2.0")]);
    let run = run_of(one.clone());
    let name = branch(&ctx, &one, None);
    let proposed =
        branch_for(&ctx, EcosystemId::Cargo, &one, &STUB_FORMATTER, None).expect("branch");
    let Ok(BranchCheck::Free(free)) = check_branch(&ctx, proposed).await else {
        panic!("the branch must be free");
    };
    let text = text_of(&ctx, &run, None);
    let result = open(&ctx, host, free, &text).await;
    let opened = Opened {
        branch: name,
        title: text.title.clone(),
        body: text.body.clone(),
        commit_body: text.commit_body.clone(),
    };
    (opened, ctx, result)
}

#[tokio::test]
async fn test_open_github_commits_pushes_opens_the_pull_request_and_switches_back() {
    let fx = Fixture::new();
    fx.url_shim("gh");
    std::fs::write(
        fx.tmp.path().join("hooks/pre-commit"),
        format!(
            "#!/bin/sh\nprintf '%s' \"$GIT_TERMINAL_PROMPT\" > '{}'\n",
            fx.record("hook.env").display()
        ),
    )
    .expect("hook");
    std::fs::set_permissions(
        fx.tmp.path().join("hooks/pre-commit"),
        std::fs::Permissions::from_mode(0o755),
    )
    .expect("chmod");

    let (opened, ctx, result) = open_with(&fx, PrHost::Github).await;

    let Ok(PrOutcome::Opened(request)) = result else {
        panic!("the request must be opened");
    };
    assert_eq!(request.url(), URL);
    assert_eq!(
        fx.head(),
        opened.branch,
        "HEAD stays on the update branch until switch_back"
    );
    assert!(fx.origin_has(&opened.branch), "the branch must be pushed");
    let argv = fx.argv("gh");
    assert_eq!(&argv[..2], ["pr", "create"]);
    for expected in [
        "--base=main".to_owned(),
        format!("--head={}", opened.branch),
        format!("--title={}", opened.title),
        format!("--body={}", opened.body),
    ] {
        assert!(
            argv.contains(&expected),
            "{expected:?} missing from {argv:?}"
        );
    }
    assert_eq!(
        git(&fx.root, &["log", "-1", "--format=%s", &opened.branch]),
        opened.title
    );
    assert_eq!(
        git(&fx.root, &["log", "-1", "--format=%b", &opened.branch]).trim(),
        opened.commit_body.trim()
    );
    assert_eq!(
        git(
            &fx.root,
            &["show", "--name-only", "--format=", &opened.branch]
        ),
        "Cargo.toml",
        "only the tracked modification is committed"
    );
    request.switch_back(&ctx).await.expect("switch back");
    assert_eq!(fx.head(), "main");
    assert!(fx.status().is_empty());
    assert_eq!(
        std::fs::read_to_string(fx.record("gh.env")).expect("env"),
        "1",
        "GH_PROMPT_DISABLED"
    );
    assert_eq!(
        std::fs::read_to_string(fx.record("hook.env")).expect("hook env"),
        "0",
        "GIT_TERMINAL_PROMPT reaches the hooks a step triggers"
    );
    assert_eq!(
        std::fs::read_to_string(fx.record("gh.cwd"))
            .expect("cwd")
            .trim(),
        fx.root
            .canonicalize()
            .expect("canonical root")
            .to_str()
            .expect("utf-8")
    );
}

#[tokio::test]
async fn test_open_gitlab_creates_a_merge_request_with_glab() {
    let fx = Fixture::new();
    fx.url_shim("glab");

    let (opened, _ctx, result) = open_with(&fx, PrHost::Gitlab).await;

    let Ok(PrOutcome::Opened(request)) = result else {
        panic!("the request must be opened");
    };
    assert_eq!(request.url(), URL);
    let argv = fx.argv("glab");
    assert_eq!(&argv[..2], ["mr", "create"]);
    for expected in [
        format!("--source-branch={}", opened.branch),
        "--target-branch=main".to_owned(),
        format!("--title={}", opened.title),
    ] {
        assert!(
            argv.contains(&expected),
            "{expected:?} missing from {argv:?}"
        );
    }
}

#[tokio::test]
async fn test_open_without_tracked_changes_is_nothing_to_commit_and_creates_no_branch() {
    let fx = Fixture::new();
    fx.url_shim("gh");
    let ctx = fx.ctx("Cargo.toml").await;
    let one = plan(&[("serde", "1.0.0", "1.2.0")]);
    let run = run_of(one.clone());
    let name = branch(&ctx, &one, None);
    let proposed =
        branch_for(&ctx, EcosystemId::Cargo, &one, &STUB_FORMATTER, None).expect("branch");
    let Ok(BranchCheck::Free(free)) = check_branch(&ctx, proposed).await else {
        panic!("the branch must be free");
    };
    let text = text_of(&ctx, &run, None);

    let result = open(&ctx, PrHost::Github, free, &text).await;

    assert_matches!(result, Ok(PrOutcome::NothingToCommit));
    assert_eq!(git(&fx.root, &["branch", "--list", &name]), "");
    assert!(!fx.record("gh.argv").exists(), "gh must not run");
    assert_eq!(fx.head(), "main");
}

#[tokio::test]
async fn test_open_without_the_host_cli_is_tool_missing() {
    let fx = Fixture::new();

    let (_, _ctx, result) = open_with(&fx, PrHost::Github).await;

    assert_matches!(error(result), PrError::ToolMissing { tool: Tool::Gh });
}

#[tokio::test]
async fn test_open_host_cli_failure_names_the_step_and_the_exit_code() {
    let fx = Fixture::new();
    fx.shim("gh", "exit 3\n");

    let (_, _ctx, result) = open_with(&fx, PrHost::Github).await;

    assert_matches!(
        error(result),
        PrError::ToolFailed {
            tool: Tool::Gh,
            step: Step::CreateRequest,
            code: Some(3)
        }
    );
}

/// NFR-002: dropping the publish phase terminates the host CLI's whole process tree.
#[tokio::test]
async fn test_open_dropped_future_terminates_the_host_cli_process_tree() {
    let fx = Fixture::new();
    let pid_file = fx.record("sleep.pid");
    fx.shim(
        "gh",
        &format!("sleep 30 &\necho $! > '{}'\nwait\n", pid_file.display()),
    );
    let ctx = fx.ctx("Cargo.toml").await;
    fx.write("Cargo.toml", "bumped\n");
    let one = plan(&[("serde", "1.0.0", "1.2.0")]);
    let run = run_of(one.clone());
    let proposed =
        branch_for(&ctx, EcosystemId::Cargo, &one, &STUB_FORMATTER, None).expect("branch");
    let Ok(BranchCheck::Free(free)) = check_branch(&ctx, proposed).await else {
        panic!("the branch must be free");
    };
    let text = text_of(&ctx, &run, None);
    let mut publishing = Box::pin(open(&ctx, PrHost::Github, free, &text));

    let sleeper = tokio::select! {
        result = &mut publishing => panic!("open finished while gh blocks: {result:?}"),
        pid = pid_from(&pid_file) => pid,
    };
    drop(publishing);

    assert!(
        gone_within(sleeper, Duration::from_secs(4)).await,
        "the host CLI's child {sleeper} survived the dropped publish phase"
    );
}

// --- FR-012: PrSignals ---

#[tokio::test]
async fn test_signals_guard_returns_the_output_when_the_future_finishes_first() {
    let mut signals = PrSignals::install();

    let result = signals.guard(PrPhase::Update, async { 7 }).await;

    assert_eq!(result.expect("no signal arrived"), 7);
}

#[tokio::test]
async fn test_signals_guard_sigint_during_publish_drops_the_phase_and_terminates_its_tree() {
    let fx = Fixture::new();
    let pid_file = fx.record("sleep.pid");
    fx.shim(
        "gh",
        &format!("sleep 30 &\necho $! > '{}'\nwait\n", pid_file.display()),
    );
    let ctx = fx.ctx("Cargo.toml").await;
    fx.write("Cargo.toml", "bumped\n");
    let one = plan(&[("serde", "1.0.0", "1.2.0")]);
    let run = run_of(one.clone());
    let proposed =
        branch_for(&ctx, EcosystemId::Cargo, &one, &STUB_FORMATTER, None).expect("branch");
    let Ok(BranchCheck::Free(free)) = check_branch(&ctx, proposed).await else {
        panic!("the branch must be free");
    };
    let text = text_of(&ctx, &run, None);
    let mut signals = PrSignals::install();
    let guarded = signals.guard(PrPhase::Publish, open(&ctx, PrHost::Github, free, &text));
    let interrupter = async {
        let sleeper = pid_from(&pid_file).await;
        rustix::process::kill_process(rustix::process::getpid(), rustix::process::Signal::INT)
            .expect("raise SIGINT");
        sleeper
    };

    let (result, sleeper) = tokio::join!(guarded, interrupter);

    assert_matches!(
        error(result),
        PrError::Interrupted {
            phase: PrPhase::Publish
        }
    );
    assert!(
        gone_within(sleeper, Duration::from_secs(4)).await,
        "the host CLI's child {sleeper} survived the interrupt"
    );
}

// --- FR-014: text ---

fn describe_plan(
    ctx: &RepoContext,
    plan: UpdatePlan,
    group: Option<&UpdateGroup>,
) -> super::PullRequestText {
    text_of(ctx, &run_of(plan), group)
}

#[tokio::test]
async fn test_describe_titles_follow_the_one_several_and_group_forms() {
    let fx = Fixture::new();
    let root = fx.ctx("Cargo.toml").await;
    let app = fx.ctx("app/Cargo.toml").await;
    let one = || plan(&[("serde", "1.0.0", "1.2.0")]);
    let two = || plan(&[("serde", "1.0.0", "1.2.0"), ("tokio", "1.0.0", "1.1.0")]);
    let group = group_from("[update.groups.minor-patch]\n", "minor-patch");
    let mut unknown_current = one();
    unknown_current.items[0].current = CurrentVersion::Unknown;

    assert_eq!(
        describe_plan(&root, one(), None).title,
        "Bump serde from 1.0.0 to 1.2.0"
    );
    assert_eq!(
        describe_plan(&app, one(), None).title,
        "Bump serde from 1.0.0 to 1.2.0 in app"
    );
    assert_eq!(
        describe_plan(&root, unknown_current, None).title,
        "Bump serde to 1.2.0"
    );
    assert_eq!(
        describe_plan(&root, two(), None).title,
        "Bump 2 dependencies in Cargo.toml"
    );
    assert_eq!(
        describe_plan(&app, two(), None).title,
        "Bump 2 dependencies in app/Cargo.toml"
    );
    assert_eq!(
        describe_plan(&root, two(), Some(&group)).title,
        "Bump the minor-patch group with 2 updates in Cargo.toml"
    );
    assert!(
        describe_plan(&root, two(), None)
            .commit_body
            .contains("- serde 1.0.0 -> 1.2.0")
    );
}

#[tokio::test]
async fn test_describe_title_stays_within_250_bytes_for_long_ascii_and_multibyte_names() {
    let fx = Fixture::new();
    let ctx = fx.ctx("app/Cargo.toml").await;
    let long_version = format!("1.{}", "9".repeat(300));

    for name in ["a".repeat(300), "\u{e9}".repeat(300)] {
        let text = describe_plan(&ctx, plan(&[(&name, &long_version, &long_version)]), None);

        assert!(text.title.len() <= 250, "{} bytes", text.title.len());
        assert!(text.title.ends_with("..."), "{}", text.title);
        assert!(!text.title.contains(&name));
    }
}

#[tokio::test]
async fn test_describe_renders_names_as_code_spans_without_mentions_or_table_breaks() {
    let fx = Fixture::new();
    let ctx = fx.ctx("Cargo.toml").await;
    let text = describe_plan(
        &ctx,
        plan(&[
            ("@types/node", "1.0.0", "1.1.0"),
            ("a`b|c\nd", "1.0.0", "1.1.0"),
        ]),
        None,
    );

    assert!(text.body.contains("`ab\\|cd`"), "{}", text.body);
    for (index, _) in text.body.match_indices("@types/node") {
        assert_eq!(text.body.as_bytes()[index - 1], b'`', "{}", text.body);
    }
}

#[tokio::test]
async fn test_describe_caps_the_body_rows_and_bytes() {
    let fx = Fixture::new();
    let ctx = fx.ctx("Cargo.toml").await;
    let names: Vec<String> = (0..1000)
        .map(|i| format!("dep-{i}-{}", "n".repeat(300)))
        .collect();
    let updates: Vec<(&str, &str, &str)> = names
        .iter()
        .map(|name| (name.as_str(), "1.0.0", "1.1.0"))
        .collect();

    let text = describe_plan(&ctx, plan(&updates), None);

    let rows = text
        .body
        .lines()
        .filter(|line| line.starts_with("| `"))
        .count();
    assert!(rows <= 50, "{rows} rows");
    assert!(
        text.body.contains("and 950 more"),
        "the overflow line is missing"
    );
    assert!(text.body.len() < 60_000, "{} bytes", text.body.len());
}

#[tokio::test]
async fn test_describe_covers_applied_items_only() {
    let fx = Fixture::new();
    let ctx = fx.ctx("Cargo.toml").await;
    let mixed = UpdatePlan {
        items: vec![
            item("applied-dep", "1.0.0", applied("1.1.0")),
            item(
                "lockfile-dep",
                "1.0.0",
                Outcome::AppliedViaLockfile {
                    target: ConcreteVersion::from("1.0.1"),
                },
            ),
            item("zzz-skipped", "1.0.0", skipped(SkipReason::IgnoreRule)),
        ],
    };

    let text = describe_plan(&ctx, mixed, None);

    assert!(text.body.contains("applied-dep") && text.body.contains("lockfile-dep"));
    assert!(!text.body.contains("zzz-skipped") && !text.title.contains("zzz-skipped"));
    assert_eq!(text.title, "Bump 2 dependencies in Cargo.toml");
}

// --- FR-001: clap surface ---

#[test]
fn test_cli_open_pr_conflicts_with_dry_run_and_offline_and_takes_only_known_hosts() {
    let parse = |extra: &[&str]| {
        let mut args = vec!["deps-cli", "update"];
        args.extend_from_slice(extra);
        args.push("Cargo.toml");
        Cli::try_parse_from(args)
    };

    assert!(parse(&["--open-pr", "github", "--lockfile", "regenerate"]).is_ok());
    assert!(parse(&["--open-pr", "gitlab", "--lockfile", "regenerate"]).is_ok());
    assert!(
        parse(&[
            "--open-pr",
            "github",
            "--lockfile",
            "regenerate",
            "--dry-run"
        ])
        .is_err()
    );
    assert!(
        parse(&[
            "--open-pr",
            "github",
            "--lockfile",
            "regenerate",
            "--offline"
        ])
        .is_err()
    );
    assert!(parse(&["--open-pr", "bitbucket", "--lockfile", "regenerate"]).is_err());
}
