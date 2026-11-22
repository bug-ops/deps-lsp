//! Acceptance tests for #1116 lockfile regeneration (`update::regen`), written against the
//! plan's API before the implementation exists.
//!
//! Layers:
//! - pure tables: `compat_class`, `ArgComponent`, `NpmClient`, `strategy`, the gate, exit codes;
//! - real `cargo` against the committed offline local registry
//!   (`tests/fixtures/cargo-local-registry`, registry only; manifests, lock and
//!   `.cargo/config.toml` are generated into a tempdir at run time);
//! - fake `npm`/`pnpm`/`go`/`cargo` shell scripts (unix) injected through
//!   `SearchPath::Override`, checked through the real npm/go lockfile providers.
//!
//! Real `go`/`npm`/`pnpm` runs against live registries belong to the live-tester.

#![allow(clippy::panic, clippy::too_many_lines)]
// Helpers serve the feature-gated cargo/npm/go tests; a partial feature build leaves them unused.
#![cfg_attr(
    not(all(feature = "cargo", feature = "npm", feature = "go")),
    allow(dead_code)
)]

use std::assert_matches;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use deps_core::edit::ManifestEdit;
use deps_core::net_policy::{MapEnv, RegistryEnvironment};
use deps_core::policy_config::PolicyConfig;
use deps_core::position::{Position, Range};
use deps_core::{
    ConcreteVersion, Ecosystem, EcosystemId, EcosystemRegistry, HttpCache, NetworkMode,
};
use deps_engine::setup::{EcosystemRuntime, register_ecosystems};
use url::Url;

use super::command::{ArgComponent, NpmClient, Program, compat_class};
use super::run::{ProcessGroup, SearchPath, ToolRunner};
use super::{
    LockfileMode, LockfileOutcome, LockfileScope, ManifestTarget, NotApplicableReason,
    PinResolution, RegenerationError, RegenerationGate, SkipCause, Strategy, UnsupportedReason,
    regenerate_lockfile_with, regenerate_until, strategy,
};
use crate::exit::{EXIT_CLEAN, EXIT_EXECUTION_ERROR, EXIT_POLICY_VIOLATION, update_exit_code};
use crate::format::DryRun;
use crate::update::{
    CooldownFallbackNote, CurrentVersion, Outcome, PlannedUpdateItem, SkipReason, UpdatePlan,
    UpdateRun, apply_plan,
};

// ---------------------------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------------------------

struct Project {
    root: PathBuf,
    _dir: tempfile::TempDir,
}

impl Project {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("temp dir");
        let root = dir.path().canonicalize().expect("canonical temp dir");
        Self { root, _dir: dir }
    }

    fn path(&self, rel: &str) -> PathBuf {
        self.root.join(rel)
    }

    fn write(&self, rel: &str, content: &str) -> PathBuf {
        let path = self.path(rel);
        std::fs::create_dir_all(path.parent().expect("parent")).expect("create dirs");
        std::fs::write(&path, content).expect("write file");
        path
    }

    fn read(&self, rel: &str) -> String {
        std::fs::read_to_string(self.path(rel)).expect("read file")
    }
}

fn ecosystem(id: EcosystemId) -> Arc<dyn Ecosystem> {
    let runtime = EcosystemRuntime::from_policy(
        &PolicyConfig::default(),
        &RegistryEnvironment::read(&MapEnv::new()),
    );
    let cache = Arc::new(HttpCache::with_policy(Arc::clone(&runtime.policy)));
    let registry = EcosystemRegistry::new();
    let _ = register_ecosystems(&registry, cache, &runtime);
    registry.get(id).expect("ecosystem registered")
}

/// One requirement rewrite: replaces `from` inside the first line containing `anchor` with `to`.
struct Bump {
    name: &'static str,
    anchor: &'static str,
    from: &'static str,
    to: &'static str,
    current: &'static str,
    target: &'static str,
    cooldown_fallback: bool,
}

impl Bump {
    const fn new(
        name: &'static str,
        anchor: &'static str,
        from: &'static str,
        to: &'static str,
        current: &'static str,
        target: &'static str,
    ) -> Self {
        Self {
            name,
            anchor,
            from,
            to,
            current,
            target,
            cooldown_fallback: false,
        }
    }
}

fn plan_of(content: &str, bumps: &[Bump]) -> UpdatePlan {
    let items = bumps
        .iter()
        .map(|bump| {
            let (line_no, line) = content
                .lines()
                .enumerate()
                .find(|(_, line)| line.contains(bump.anchor))
                .expect("anchor line");
            let anchor_at = line.find(bump.anchor).expect("anchor");
            let start = line
                .match_indices(bump.from)
                .map(|(index, _)| index)
                .find(|index| *index >= anchor_at)
                .expect("from text on anchor line");
            let line_no = u32::try_from(line_no).expect("line fits");
            let start = u32::try_from(start).expect("col fits");
            let end = start + u32::try_from(bump.from.len()).expect("len fits");
            let edit = ManifestEdit {
                range: Range::new(Position::new(line_no, start), Position::new(line_no, end)),
                new_text: bump.to.to_string(),
            };
            PlannedUpdateItem::new(
                bump.name.to_string(),
                CurrentVersion::Resolved(ConcreteVersion::from(bump.current)),
                Outcome::Applied {
                    edit,
                    target: ConcreteVersion::from(bump.target),
                },
                vec![],
                false,
                None,
                bump.cooldown_fallback.then(|| {
                    CooldownFallbackNote::AppliedInsteadOf(ConcreteVersion::from("99.0.0"))
                }),
            )
        })
        .collect();
    UpdatePlan { items }
}

fn run_gate() -> RegenerationGate {
    RegenerationGate::new(LockfileMode::Regenerate, DryRun::No, NetworkMode::Online)
}

fn inherit_runner() -> ToolRunner {
    ToolRunner {
        deadline: Duration::from_mins(5),
        search_path: SearchPath::Inherit,
        group: ProcessGroup::Own,
    }
}

/// Applies the bumps to `manifest` (whose on-disk content must equal `content`) and regenerates.
async fn apply_and_regenerate(
    id: EcosystemId,
    manifest: &Path,
    display: &str,
    content: &str,
    bumps: &[Bump],
    gate: RegenerationGate,
    runner: &ToolRunner,
) -> LockfileOutcome {
    let plan = plan_of(content, bumps);
    apply_plan(&plan, manifest, content, DryRun::No).expect("apply the plan");
    regenerate(id, manifest, display, &plan, gate, runner).await
}

async fn regenerate(
    id: EcosystemId,
    manifest: &Path,
    display: &str,
    plan: &UpdatePlan,
    gate: RegenerationGate,
    runner: &ToolRunner,
) -> LockfileOutcome {
    let ecosystem = ecosystem(id);
    let uri = Url::from_file_path(manifest).expect("file url");
    let display_path = PathBuf::from(display);
    let original_text = std::fs::read_to_string(manifest).unwrap_or_default();
    let target = ManifestTarget {
        ecosystem: &ecosystem,
        manifest_path: manifest,
        display_path: &display_path,
        uri: &uri,
        original: super::OriginalManifest::new(&original_text),
    };
    regenerate_lockfile_with(plan, &target, gate, runner).await
}

/// Like [`regenerate`], but only for lock files inside `root`, as `--open-pr` runs.
async fn regenerate_within(
    id: EcosystemId,
    manifest: &Path,
    plan: &UpdatePlan,
    runner: &ToolRunner,
    root: &Path,
) -> LockfileOutcome {
    let ecosystem = ecosystem(id);
    let uri = Url::from_file_path(manifest).expect("file url");
    let display_path = PathBuf::from("Cargo.toml");
    let original_text = std::fs::read_to_string(manifest).unwrap_or_default();
    let target = ManifestTarget {
        ecosystem: &ecosystem,
        manifest_path: manifest,
        display_path: &display_path,
        uri: &uri,
        original: super::OriginalManifest::new(&original_text),
    };
    regenerate_until(
        plan,
        &target,
        run_gate(),
        runner,
        LockfileScope::Within(root),
        std::future::pending(),
    )
    .await
    .lockfile
}

fn pin_rows(outcome: &LockfileOutcome) -> Vec<(String, String, PinResolution)> {
    let LockfileOutcome::Regenerated { pins, .. } = outcome else {
        panic!("expected Regenerated, got {outcome:?}");
    };
    pins.iter()
        .map(|pin| {
            (
                pin.package.as_str().to_string(),
                pin.target.as_str().to_string(),
                pin.resolution.clone(),
            )
        })
        .collect()
}

#[cfg(unix)]
fn mismatch(outcome: &LockfileOutcome) -> (String, String, Option<String>) {
    let LockfileOutcome::Failed(RegenerationError::VersionMismatch {
        package,
        expected,
        found,
    }) = outcome
    else {
        panic!("expected VersionMismatch, got {outcome:?}");
    };
    (
        package.as_str().to_string(),
        expected.as_str().to_string(),
        found.as_ref().map(|v| v.as_str().to_string()),
    )
}

fn lock_has(lock: &str, name: &str, version: &str) -> bool {
    lock.contains(&format!("name = \"{name}\"\nversion = \"{version}\""))
}

// ---------------------------------------------------------------------------------------------
// Pure tables
// ---------------------------------------------------------------------------------------------

#[test]
fn test_compat_class_maps_versions_to_their_caret_class() {
    for (version, class) in [
        ("1.2.3", "1"),
        ("0.2.3", "0.2"),
        ("0.0.3", "0.0.3"),
        ("1.1.0-rc.1", "1"),
        ("1.2.3+b", "1"),
    ] {
        assert_eq!(
            compat_class(&ConcreteVersion::from(version)).map(|class| class.to_string()),
            Some(class.to_string()),
            "{version}"
        );
    }
}

#[test]
fn test_compat_class_rejects_non_three_part_versions() {
    for version in ["1.2", "latest", "v1.2.3", ""] {
        assert!(
            compat_class(&ConcreteVersion::from(version)).is_none(),
            "{version:?}"
        );
    }
}

#[test]
fn test_arg_component_parse_accepts_plain_names_and_versions() {
    for value in [
        "serde",
        "1.0.200",
        "golang.org/x/text",
        "v0.31.0",
        "1.0.0-rc.1",
        "a_b-c",
    ] {
        assert!(ArgComponent::parse(value).is_ok(), "{value:?}");
    }
}

#[test]
fn test_arg_component_parse_rejects_flag_like_and_unsafe_values() {
    for value in [
        "",
        "-x",
        "--precise=1.0.0",
        "a@b",
        "@scope/pkg",
        "a\0b",
        "a b",
        "a\nb",
        "a\tb",
        "a\u{7f}b",
    ] {
        assert!(ArgComponent::parse(value).is_err(), "{value:?}");
    }
}

#[test]
fn test_npm_client_from_lockfile_name_is_exact_match() {
    assert_eq!(
        NpmClient::from_lockfile_name("package-lock.json"),
        Some(NpmClient::Npm)
    );
    assert_eq!(
        NpmClient::from_lockfile_name("pnpm-lock.yaml"),
        Some(NpmClient::Pnpm)
    );
    assert_eq!(
        NpmClient::from_lockfile_name("yarn.lock"),
        Some(NpmClient::Yarn)
    );
    assert_eq!(
        NpmClient::from_lockfile_name("bun.lock"),
        Some(NpmClient::Bun)
    );
    for name in [
        "package.json",
        "Package-Lock.json",
        "x/package-lock.json",
        "",
    ] {
        assert_eq!(NpmClient::from_lockfile_name(name), None, "{name:?}");
    }
}

/// Drift guard: every lockfile name the real npm ecosystem recognizes maps to a client.
#[cfg(feature = "npm")]
#[test]
fn test_npm_client_from_lockfile_name_covers_every_npm_lockfile_name() {
    let npm = ecosystem(EcosystemId::Npm);
    for name in npm.lockfile_filenames() {
        assert!(
            NpmClient::from_lockfile_name(name).is_some(),
            "npm lockfile name {name} has no NpmClient"
        );
    }
}

#[test]
fn test_strategy_is_decided_for_every_ecosystem() {
    for id in EcosystemId::ALL {
        let expected = match id {
            EcosystemId::GithubActions
            | EcosystemId::GitlabCi
            | EcosystemId::PreCommit
            | EcosystemId::Maven => "no-format",
            EcosystemId::Cargo => "cargo",
            EcosystemId::Npm => "npm",
            EcosystemId::Go => "go",
            EcosystemId::Pypi => "pypi",
            EcosystemId::Bundler => "bundler",
            EcosystemId::Deno => "deno",
            EcosystemId::Dart => "dart",
            EcosystemId::Composer => "composer",
            EcosystemId::Gradle => "gradle",
            EcosystemId::Swift => "swift",
            EcosystemId::NuGet => "nuget",
        };
        let actual = match strategy(*id) {
            Strategy::NoLockfileFormat => "no-format",
            Strategy::Cargo => "cargo",
            Strategy::NpmFamily => "npm",
            Strategy::Go => "go",
            Strategy::Pypi => "pypi",
            Strategy::Bundler => "bundler",
            Strategy::Deno => "deno",
            Strategy::Composer => "composer",
            Strategy::Dart => "dart",
            Strategy::Gradle => "gradle",
            Strategy::Swift => "swift",
            Strategy::NuGet => "nuget",
        };
        assert_eq!(actual, expected, "{id:?}");
    }
}

#[test]
fn test_regeneration_gate_new_precedence_over_all_inputs() {
    for mode in [LockfileMode::Skip, LockfileMode::Regenerate] {
        for dry in [DryRun::No, DryRun::Yes] {
            for network in [NetworkMode::Online, NetworkMode::Offline] {
                let expected = match (mode, dry, network) {
                    (LockfileMode::Skip, _, _) => RegenerationGate::Skip(SkipCause::NotEnabled),
                    (LockfileMode::Regenerate, DryRun::Yes, _) => {
                        RegenerationGate::Skip(SkipCause::DryRun)
                    }
                    (LockfileMode::Regenerate, DryRun::No, NetworkMode::Offline) => {
                        RegenerationGate::Skip(SkipCause::Offline)
                    }
                    (LockfileMode::Regenerate, DryRun::No, NetworkMode::Online) => {
                        RegenerationGate::Run
                    }
                };
                assert_eq!(
                    RegenerationGate::new(mode, dry, network),
                    expected,
                    "{mode:?} {dry:?} {network:?}"
                );
            }
        }
    }
}

#[test]
fn test_lockfile_mode_defaults_to_skip() {
    assert_eq!(LockfileMode::default(), LockfileMode::Skip);
}

#[test]
fn test_update_exit_code_only_failed_lockfile_raises_to_execution_error() {
    let run = |plan: UpdatePlan, lockfile: LockfileOutcome| {
        update_exit_code(&UpdateRun { plan, lockfile })
    };
    let unresolved = || UpdatePlan {
        items: vec![PlannedUpdateItem::new(
            "x".to_string(),
            CurrentVersion::Unknown,
            Outcome::Skipped {
                reason: SkipReason::NotSafelyEditable(
                    deps_core::edit::UnplannableReason::NoOpRewrite,
                ),
                target: None,
            },
            vec![],
            false,
            None,
            None,
        )],
    };

    for lockfile in [
        LockfileOutcome::Skipped(SkipCause::NotEnabled),
        LockfileOutcome::NotApplicable(NotApplicableReason::NothingApplied),
        LockfileOutcome::Unsupported {
            lockfile: None,
            reason: UnsupportedReason::CooldownFallbackTarget,
        },
    ] {
        assert_eq!(run(UpdatePlan::default(), lockfile), EXIT_CLEAN);
    }
    assert_eq!(
        run(
            unresolved(),
            LockfileOutcome::NotApplicable(NotApplicableReason::NothingApplied)
        ),
        EXIT_POLICY_VIOLATION
    );
    let failed = || {
        LockfileOutcome::Failed(RegenerationError::ToolFailed {
            program: Program::Cargo,
            code: Some(101),
        })
    };
    assert_eq!(run(UpdatePlan::default(), failed()), EXIT_EXECUTION_ERROR);
    assert_eq!(run(unresolved(), failed()), EXIT_EXECUTION_ERROR);
}

// ---------------------------------------------------------------------------------------------
// Real cargo against the committed offline local registry
// ---------------------------------------------------------------------------------------------

mod display_path_normalization {
    use super::super::lexically_normalized;
    use std::path::{Path, PathBuf};

    #[cfg(unix)]
    #[test]
    fn sibling_project_route_collapses_against_the_display_dir() {
        use super::super::DisplayLockPath;

        let lock = DisplayLockPath::for_test("app/Cargo.lock", Path::new("/r/app/Cargo.lock"));
        assert_eq!(
            lock.display_of(Path::new("/r/lib/gradle.lockfile")),
            PathBuf::from("lib/gradle.lockfile")
        );
    }

    #[test]
    fn clean_paths_are_unchanged() {
        for clean in ["app/gradle/dependency-locks/a.lockfile", "Cargo.lock"] {
            assert_eq!(lexically_normalized(Path::new(clean)), PathBuf::from(clean));
        }
    }

    #[test]
    fn parent_beyond_the_root_is_preserved() {
        assert_eq!(
            lexically_normalized(Path::new("../outside.txt")),
            PathBuf::from("../outside.txt")
        );
        assert_eq!(
            lexically_normalized(Path::new("app/../../outside.txt")),
            PathBuf::from("../outside.txt")
        );
        assert_eq!(
            lexically_normalized(Path::new("/../x")),
            PathBuf::from("/../x")
        );
    }
}

mod inside_workspace_seam {
    use super::super::inside_workspace;
    use super::*;
    use std::ffi::OsString;

    fn no_env(_: &str) -> Option<OsString> {
        None
    }

    fn leaf(project: &Project, rel: &str) -> PathBuf {
        let dir = project.path(rel);
        std::fs::create_dir_all(&dir).expect("create dir");
        dir
    }

    #[test]
    fn test_inside_workspace_pnpm_env_vars_are_workspace_hits_in_both_spellings() {
        let project = Project::new();
        let dir = leaf(&project, "a");
        assert!(!inside_workspace(&dir, NpmClient::Pnpm, no_env));
        for name in ["NPM_CONFIG_WORKSPACE_DIR", "npm_config_workspace_dir"] {
            let env = |key: &str| (key == name).then(|| OsString::from("/ws"));
            assert!(inside_workspace(&dir, NpmClient::Pnpm, env), "{name}");
            assert!(
                !inside_workspace(&dir, NpmClient::Npm, env),
                "{name} must not affect npm"
            );
        }
    }

    #[test]
    fn test_inside_workspace_missing_manifest_dir_is_fail_safe_hit() {
        let project = Project::new();
        assert!(inside_workspace(
            &project.path("missing"),
            NpmClient::Npm,
            no_env
        ));
    }

    #[test]
    fn test_inside_workspace_npm_looks_only_at_workspaces_key() {
        let project = Project::new();
        let dir = leaf(&project, "a/b");
        project.write("a/package.json", "{\"name\":\"x\"}");
        assert!(!inside_workspace(&dir, NpmClient::Npm, no_env));
        project.write("a/package.json", "{\"workspaces\":[\"b\"]}");
        assert!(inside_workspace(&dir, NpmClient::Npm, no_env));
        project.write("a/package.json", "{ broken");
        assert!(inside_workspace(&dir, NpmClient::Npm, no_env));
    }

    #[test]
    fn test_inside_workspace_pnpm_looks_only_at_workspace_yaml() {
        let project = Project::new();
        let dir = leaf(&project, "a/b");
        project.write("a/package.json", "{\"workspaces\":[\"b\"]}");
        assert!(!inside_workspace(&dir, NpmClient::Pnpm, no_env));
        project.write("a/pnpm-workspace.yaml", "packages: []\n");
        assert!(inside_workspace(&dir, NpmClient::Pnpm, no_env));
    }

    #[test]
    fn test_inside_workspace_manifest_dir_own_file_is_not_an_ancestor_hit() {
        let project = Project::new();
        let dir = leaf(&project, "a");
        project.write("a/package.json", "{\"workspaces\":[\"x\"]}");
        project.write("a/pnpm-workspace.yaml", "packages: []\n");
        assert!(!inside_workspace(&dir, NpmClient::Npm, no_env));
        assert!(!inside_workspace(&dir, NpmClient::Pnpm, no_env));
    }

    #[test]
    fn test_inside_workspace_depth_cap_before_root_is_fail_safe_hit() {
        let project = Project::new();
        let deep = (0..70).fold(project.path(""), |path, _| path.join("d"));
        std::fs::create_dir_all(&deep).expect("deep dirs");
        assert!(inside_workspace(&deep, NpmClient::Npm, no_env));
    }
}

#[test]
fn test_regeneration_error_display_version_mismatch_names_found_version_or_none() {
    let mismatch = |found: Option<&str>| {
        RegenerationError::VersionMismatch {
            package: "lodash".into(),
            expected: ConcreteVersion::from("4.17.21"),
            found: found.map(ConcreteVersion::from),
        }
        .to_string()
    };
    assert!(
        mismatch(Some("1.2.0")).contains("found 1.2.0"),
        "{}",
        mismatch(Some("1.2.0"))
    );
    assert!(mismatch(None).contains("found none"), "{}", mismatch(None));
}

#[test]
fn test_regeneration_error_display_tool_failed_names_status_or_signal() {
    let failed = |code: Option<i32>| {
        RegenerationError::ToolFailed {
            program: Program::Cargo,
            code,
        }
        .to_string()
    };
    assert!(
        failed(Some(101)).contains("exited with status 101"),
        "{}",
        failed(Some(101))
    );
    assert!(
        failed(None).contains("terminated by a signal"),
        "{}",
        failed(None)
    );
    assert!(
        !failed(Some(101)).contains("Some("),
        "Debug formatting leaked"
    );
}

#[test]
fn test_program_and_client_tokens_are_the_wire_names() {
    for (program, token) in [
        (Program::Cargo, "cargo"),
        (Program::Go, "go"),
        (Program::Npm, "npm"),
        (Program::Pnpm, "pnpm"),
    ] {
        assert_eq!(program.to_string(), token);
    }
    for (client, token) in [
        (NpmClient::Npm, "npm"),
        (NpmClient::Pnpm, "pnpm"),
        (NpmClient::Yarn, "yarn"),
        (NpmClient::Bun, "bun"),
    ] {
        assert_eq!(client.as_str(), token);
    }
}

#[test]
fn test_reason_display_texts_are_distinct_and_non_empty() {
    let skips = [SkipCause::NotEnabled, SkipCause::DryRun, SkipCause::Offline]
        .map(|cause| cause.to_string());
    let not_applicable = [
        NotApplicableReason::NothingApplied,
        NotApplicableReason::NoLockfileFormat,
        NotApplicableReason::NoLockfilePresent,
    ]
    .map(|reason| reason.to_string());
    let unsupported = [
        UnsupportedReason::WorkspaceMemberLockfile,
        UnsupportedReason::LockfileOwnershipMismatch,
        UnsupportedReason::CooldownFallbackTarget,
        UnsupportedReason::LockfileSymlink,
    ]
    .map(|reason| reason.to_string());
    for group in [&skips[..], &not_applicable[..], &unsupported[..]] {
        let unique: std::collections::HashSet<_> = group.iter().collect();
        assert_eq!(unique.len(), group.len(), "{group:?}");
        assert!(group.iter().all(|text| !text.is_empty()), "{group:?}");
    }
}

#[cfg(feature = "cargo")]
mod cargo_real {
    use super::*;

    fn registry_path() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/cargo-local-registry")
    }

    const CARGO_TOML: &str = "[package]\nname = \"fx\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[workspace]\n\n[dependencies]\nstuba = \"1.0.0\"\nstubb = \"1.0.0\"\n";

    fn project() -> Project {
        let project = Project::new();
        project.write(
            ".cargo/config.toml",
            &format!(
                "[net]\noffline = true\n\n[source.crates-io]\nreplace-with = \"lr\"\n\n[source.lr]\nlocal-registry = '{}'\n",
                registry_path().display()
            ),
        );
        project.write("src/lib.rs", "");
        project
    }

    /// Writes `content` with every caret requirement pinned to `=`, locks it, then restores
    /// the caret form so the lock holds the pre-update versions.
    fn lock_then_restore(project: &Project, rel: &str, content: &str) -> PathBuf {
        let manifest = project.write(rel, &content.replace("\"1.0.0\"", "\"=1.0.0\""));
        generate_lock(&manifest);
        project.write(rel, content)
    }

    fn generate_lock(manifest: &Path) {
        let status = std::process::Command::new("cargo")
            .args(["generate-lockfile", "--manifest-path"])
            .arg(manifest)
            .current_dir(manifest.parent().expect("manifest dir"))
            .status()
            .expect("run cargo generate-lockfile");
        assert!(status.success(), "generate-lockfile failed");
    }

    fn two_bumps() -> [Bump; 2] {
        [
            Bump::new("stuba", "stuba = ", "1.0.0", "1.0.1", "1.0.0", "1.0.1"),
            Bump::new("stubb", "stubb = ", "1.0.0", "1.0.2", "1.0.0", "1.0.2"),
        ]
    }

    #[tokio::test]
    async fn test_regenerate_lockfile_cargo_pins_non_newest_targets_exactly() {
        let project = project();
        let manifest = lock_then_restore(&project, "Cargo.toml", CARGO_TOML);

        let outcome = apply_and_regenerate(
            EcosystemId::Cargo,
            &manifest,
            "Cargo.toml",
            CARGO_TOML,
            &two_bumps(),
            run_gate(),
            &inherit_runner(),
        )
        .await;

        assert_eq!(
            pin_rows(&outcome),
            vec![
                ("stuba".into(), "1.0.1".into(), PinResolution::Exact),
                ("stubb".into(), "1.0.2".into(), PinResolution::Exact),
            ],
            "{outcome:?}"
        );
        let LockfileOutcome::Regenerated { lockfile, tool, .. } = &outcome else {
            unreachable!()
        };
        assert_eq!(*tool, Program::Cargo);
        assert_eq!(lockfile.to_string(), "Cargo.lock");
        let lock = project.read("Cargo.lock");
        assert!(lock_has(&lock, "stuba", "1.0.1"), "{lock}");
        assert!(lock_has(&lock, "stubb", "1.0.2"), "{lock}");
        assert!(!lock.contains("version = \"1.0.0\"\nsource"), "{lock}");
    }

    #[tokio::test]
    async fn test_regenerate_lockfile_cargo_renamed_coexisting_major_is_unambiguous() {
        let content = format!(
            "{}stuba2 = {{ package = \"stuba\", version = \"2.0.0\" }}\n",
            CARGO_TOML.replace("stubb = \"1.0.0\"\n", "")
        );
        let project = project();
        let manifest = lock_then_restore(&project, "Cargo.toml", &content);

        let outcome = apply_and_regenerate(
            EcosystemId::Cargo,
            &manifest,
            "Cargo.toml",
            &content,
            &[Bump::new(
                "stuba", "stuba = ", "1.0.0", "1.0.1", "1.0.0", "1.0.1",
            )],
            run_gate(),
            &inherit_runner(),
        )
        .await;

        assert_eq!(
            pin_rows(&outcome),
            vec![("stuba".into(), "1.0.1".into(), PinResolution::Exact)],
            "{outcome:?}"
        );
        let lock = project.read("Cargo.lock");
        assert!(lock_has(&lock, "stuba", "1.0.1"), "{lock}");
        assert!(lock_has(&lock, "stuba", "2.0.0"), "{lock}");
    }

    #[tokio::test]
    async fn test_regenerate_lockfile_cargo_workspace_member_updates_root_lock() {
        let project = project();
        project.write("Cargo.toml", "[workspace]\nmembers = [\"m\"]\n");
        let member = "[package]\nname = \"m\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nstuba = \"1.0.0\"\n";
        project.write("m/src/lib.rs", "");
        lock_then_restore_root(&project, member);
        let manifest = project.path("m/Cargo.toml");

        let outcome = apply_and_regenerate(
            EcosystemId::Cargo,
            &manifest,
            "Cargo.toml",
            member,
            &[Bump::new(
                "stuba", "stuba = ", "1.0.0", "1.0.1", "1.0.0", "1.0.1",
            )],
            run_gate(),
            &inherit_runner(),
        )
        .await;

        let LockfileOutcome::Regenerated { lockfile, .. } = &outcome else {
            panic!("{outcome:?}");
        };
        assert_eq!(
            lockfile.to_string(),
            Path::new("..").join("Cargo.lock").display().to_string()
        );
        assert!(lock_has(&project.read("Cargo.lock"), "stuba", "1.0.1"));
        assert!(!project.path("m/Cargo.lock").exists());
    }

    fn member_plan(member: &str) -> UpdatePlan {
        plan_of(
            member,
            &[Bump::new(
                "stuba", "stuba = ", "1.0.0", "1.0.1", "1.0.0", "1.0.1",
            )],
        )
    }

    #[tokio::test]
    async fn test_regenerate_within_the_repository_reports_the_members_root_lock_as_real() {
        let project = project();
        project.write("Cargo.toml", "[workspace]\nmembers = [\"m\"]\n");
        let member = "[package]\nname = \"m\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nstuba = \"1.0.0\"\n";
        project.write("m/src/lib.rs", "");
        lock_then_restore_root(&project, member);
        let manifest = project.path("m/Cargo.toml");
        let plan = member_plan(member);
        apply_plan(&plan, &manifest, member, DryRun::No).expect("apply the plan");

        let outcome = regenerate_within(
            EcosystemId::Cargo,
            &manifest,
            &plan,
            &inherit_runner(),
            &project.root,
        )
        .await;

        let LockfileOutcome::Regenerated { lockfile, .. } = &outcome else {
            panic!("{outcome:?}");
        };
        assert_eq!(lockfile.real_path(), project.path("Cargo.lock"));
        assert!(lock_has(&project.read("Cargo.lock"), "stuba", "1.0.1"));
    }

    #[tokio::test]
    async fn test_regenerate_within_a_root_below_the_workspace_refuses_without_writing() {
        let project = project();
        project.write("Cargo.toml", "[workspace]\nmembers = [\"m\"]\n");
        let member = "[package]\nname = \"m\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nstuba = \"1.0.0\"\n";
        project.write("m/src/lib.rs", "");
        lock_then_restore_root(&project, member);
        let manifest = project.path("m/Cargo.toml");
        let before = project.read("Cargo.lock");
        let plan = member_plan(member);
        apply_plan(&plan, &manifest, member, DryRun::No).expect("apply the plan");

        let outcome = regenerate_within(
            EcosystemId::Cargo,
            &manifest,
            &plan,
            &inherit_runner(),
            &project.path("m"),
        )
        .await;

        assert_matches!(
            outcome,
            LockfileOutcome::Unsupported {
                reason: UnsupportedReason::LockfileOutsideRepository,
                ..
            }
        );
        assert_eq!(project.read("Cargo.lock"), before);
    }

    fn lock_then_restore_root(project: &Project, member: &str) {
        project.write("m/Cargo.toml", &member.replace("\"1.0.0\"", "\"=1.0.0\""));
        generate_lock(&project.path("Cargo.toml"));
        project.write("m/Cargo.toml", member);
    }

    #[tokio::test]
    async fn test_regenerate_lockfile_cargo_nested_workspace_without_lock_is_not_applicable() {
        let project = project();
        let content = "[package]\nname = \"nested\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[workspace]\n\n[dependencies]\nstuba = \"1.0.0\"\n";
        project.write("nested/src/lib.rs", "");
        let manifest = project.write("nested/Cargo.toml", content);

        let outcome = apply_and_regenerate(
            EcosystemId::Cargo,
            &manifest,
            "Cargo.toml",
            content,
            &[Bump::new(
                "stuba", "stuba = ", "1.0.0", "1.0.1", "1.0.0", "1.0.1",
            )],
            run_gate(),
            &inherit_runner(),
        )
        .await;

        assert_matches!(
            outcome,
            LockfileOutcome::NotApplicable(NotApplicableReason::NoLockfilePresent)
        );
        assert!(
            !project.path("nested/Cargo.lock").exists(),
            "a lock must never be created"
        );
        assert!(!project.path("Cargo.lock").exists());
    }

    #[tokio::test]
    async fn test_regenerate_lockfile_cargo_non_member_under_ancestor_workspace_fails_tool() {
        let project = project();
        project.write("Cargo.toml", "[workspace]\nmembers = []\n");
        let content = "[package]\nname = \"sub\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nstuba = \"1.0.0\"\n";
        project.write("sub/src/lib.rs", "");
        let manifest = project.write("sub/Cargo.toml", content);

        let outcome = apply_and_regenerate(
            EcosystemId::Cargo,
            &manifest,
            "Cargo.toml",
            content,
            &[Bump::new(
                "stuba", "stuba = ", "1.0.0", "1.0.1", "1.0.0", "1.0.1",
            )],
            run_gate(),
            &inherit_runner(),
        )
        .await;

        assert_matches!(
            outcome,
            LockfileOutcome::Failed(RegenerationError::ToolFailed {
                program: Program::Cargo,
                code: Some(101)
            })
        );
    }

    #[tokio::test]
    async fn test_regenerate_lockfile_cargo_stray_lock_between_member_and_root_is_ownership_mismatch()
     {
        let project = project();
        project.write("Cargo.toml", "[workspace]\nmembers = [\"mid/m\"]\n");
        let member = "[package]\nname = \"m\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nstuba = \"1.0.0\"\n";
        project.write("mid/m/src/lib.rs", "");
        let manifest = project.write("mid/m/Cargo.toml", member);
        generate_lock(&project.path("Cargo.toml"));
        let root_lock_before = project.read("Cargo.lock");
        project.write("mid/Cargo.lock", "version = 4\n");

        let outcome = apply_and_regenerate(
            EcosystemId::Cargo,
            &manifest,
            "Cargo.toml",
            member,
            &[Bump::new(
                "stuba", "stuba = ", "1.0.0", "1.0.1", "1.0.0", "1.0.1",
            )],
            run_gate(),
            &inherit_runner(),
        )
        .await;

        assert_matches!(
            outcome,
            LockfileOutcome::Unsupported {
                reason: UnsupportedReason::LockfileOwnershipMismatch,
                ..
            }
        );
        assert_eq!(project.read("Cargo.lock"), root_lock_before);
        assert_eq!(project.read("mid/Cargo.lock"), "version = 4\n");
    }

    /// A target below the version the edited requirement forces makes `--precise` fail, and the
    /// lock is restored to its pre-run bytes (#2071).
    #[tokio::test]
    async fn test_regenerate_lockfile_cargo_precise_below_requirement_floor_fails_and_restores_the_lock()
     {
        let project = project();
        let manifest = lock_then_restore(&project, "Cargo.toml", CARGO_TOML);

        // The requirement is raised to 1.0.2 while the pin claims 1.0.1.
        let outcome = apply_and_regenerate(
            EcosystemId::Cargo,
            &manifest,
            "Cargo.toml",
            CARGO_TOML,
            &[Bump::new(
                "stuba", "stuba = ", "1.0.0", "1.0.2", "1.0.0", "1.0.1",
            )],
            run_gate(),
            &inherit_runner(),
        )
        .await;

        assert_matches!(
            outcome,
            LockfileOutcome::Failed(RegenerationError::ToolFailed {
                program: Program::Cargo,
                code: Some(101)
            })
        );
        let lock = project.read("Cargo.lock");
        assert!(!lock_has(&lock, "stuba", "1.0.2"));
        assert!(lock_has(&lock, "stuba", "1.0.0"));
    }

    /// The same failure for a cooldown-fallback pin is a typed rejection; the manifest keeps its
    /// edit and the lock stays at its pre-run bytes (#2087).
    #[tokio::test]
    async fn test_regenerate_lockfile_cargo_fallback_pin_below_requirement_floor_is_rejected() {
        let project = project();
        let manifest = lock_then_restore(&project, "Cargo.toml", CARGO_TOML);
        let lock_before = project.read("Cargo.lock");
        let mut bump = [Bump::new(
            "stuba", "stuba = ", "1.0.0", "1.0.2", "1.0.0", "1.0.1",
        )];
        bump[0].cooldown_fallback = true;

        let outcome = apply_and_regenerate(
            EcosystemId::Cargo,
            &manifest,
            "Cargo.toml",
            CARGO_TOML,
            &bump,
            run_gate(),
            &inherit_runner(),
        )
        .await;

        assert_matches!(
            outcome,
            LockfileOutcome::Failed(RegenerationError::FallbackPinRejected {
                code: Some(101),
                ..
            })
        );
        assert_eq!(project.read("Cargo.lock"), lock_before);
        assert!(project.read("Cargo.toml").contains("\"1.0.2\""));
    }
}

// ---------------------------------------------------------------------------------------------
// Fake tools (unix): argv/cwd/env, failures, and verification through the real providers
// ---------------------------------------------------------------------------------------------

#[cfg(unix)]
mod fake_tools {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    struct FakeBin {
        dir: tempfile::TempDir,
    }

    impl FakeBin {
        fn new() -> Self {
            Self {
                dir: tempfile::tempdir().expect("bin dir"),
            }
        }

        fn log(&self) -> PathBuf {
            self.dir.path().join("calls.log")
        }

        /// Installs `name`; every call appends `argv|cwd|COREPACK_ENABLE_DOWNLOAD_PROMPT` first.
        fn install(&self, name: &str, body: &str) {
            let script = format!(
                "#!/bin/sh\nprintf '%s|%s|%s\\n' \"$*\" \"$(pwd)\" \"$COREPACK_ENABLE_DOWNLOAD_PROMPT\" >> '{}'\n{body}\n",
                self.log().display()
            );
            let path = self.dir.path().join(name);
            std::fs::write(&path, script).expect("write script");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        }

        fn runner(&self, deadline: Duration) -> ToolRunner {
            ToolRunner {
                deadline,
                search_path: SearchPath::Override(self.dir.path().as_os_str().to_owned()),
                group: ProcessGroup::Own,
            }
        }

        fn calls(&self) -> Vec<String> {
            std::fs::read_to_string(self.log())
                .map(|log| log.lines().map(str::to_string).collect())
                .unwrap_or_default()
        }
    }

    fn call(argv: &str, cwd: &Path, prompt: &str) -> String {
        format!("{argv}|{}|{prompt}", cwd.display())
    }

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    // ----- cargo argv (fake) -----

    #[cfg(feature = "cargo")]
    #[tokio::test]
    async fn test_regenerate_lockfile_cargo_runs_probe_then_two_step_update_in_manifest_dir() {
        let project = Project::new();
        let content = "[package]\nname = \"fx\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[workspace]\n\n[dependencies]\nstuba = \"1.0.0\"\n";
        let manifest = project.write("Cargo.toml", content);
        project.write(
            "Cargo.lock",
            "version = 4\n\n[[package]]\nname = \"fx\"\nversion = \"0.1.0\"\ndependencies = [\n \"stuba\",\n]\n\n[[package]]\nname = \"stuba\"\nversion = \"1.0.1\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"1cfe8cbac33b06e98f6e403cac490acea6ce20d4cf11a75ac068b8c16bd3c30c\"\n",
        );
        let bin = FakeBin::new();
        bin.install(
            "cargo",
            &format!(
                "if [ \"$1\" = locate-project ]; then echo '{}'; fi",
                manifest.display()
            ),
        );

        let outcome = apply_and_regenerate(
            EcosystemId::Cargo,
            &manifest,
            "Cargo.toml",
            content,
            &[Bump::new(
                "stuba", "stuba = ", "1.0.0", "1.0.1", "1.0.0", "1.0.1",
            )],
            run_gate(),
            &bin.runner(secs(30)),
        )
        .await;

        let m = manifest.display();
        assert_eq!(
            bin.calls(),
            vec![
                call(
                    &format!(
                        "locate-project --workspace --message-format plain --manifest-path {m}"
                    ),
                    &project.root,
                    ""
                ),
                call(
                    &format!("update --workspace --manifest-path {m}"),
                    &project.root,
                    ""
                ),
                call(
                    &format!("update --manifest-path {m} --package=stuba@1 --precise=1.0.1"),
                    &project.root,
                    ""
                ),
            ]
        );
        assert_eq!(
            pin_rows(&outcome),
            vec![("stuba".into(), "1.0.1".into(), PinResolution::Exact)]
        );
    }

    #[cfg(feature = "cargo")]
    mod cargo_pre_spawn {
        use super::*;

        const CONTENT: &str = "[package]\nname = \"fx\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[workspace]\n\n[dependencies]\nstuba = \"1.0.0\"\n";

        async fn run(probe_body: &str, bump: Bump) -> (LockfileOutcome, Vec<String>) {
            let project = Project::new();
            let manifest = project.write("Cargo.toml", CONTENT);
            project.write("Cargo.lock", "version = 4\n");
            let bin = FakeBin::new();
            bin.install("cargo", probe_body);
            let outcome = apply_and_regenerate(
                EcosystemId::Cargo,
                &manifest,
                "Cargo.toml",
                CONTENT,
                &[bump],
                run_gate(),
                &bin.runner(secs(30)),
            )
            .await;
            (outcome, bin.calls())
        }

        fn locate_ok() -> String {
            "if [ \"$1\" = locate-project ]; then echo \"$PWD/Cargo.toml\"; fi".to_string()
        }

        #[tokio::test]
        async fn test_regenerate_lockfile_cargo_flag_like_package_is_unsafe_argument_without_update()
         {
            let (outcome, calls) = run(
                &locate_ok(),
                Bump::new("--evil", "stuba = ", "1.0.0", "1.0.1", "1.0.0", "1.0.1"),
            )
            .await;
            assert_matches!(
                outcome,
                LockfileOutcome::Failed(RegenerationError::UnsafeArgument { .. })
            );
            assert!(
                calls.iter().all(|c| !c.starts_with("update")),
                "no update may be spawned: {calls:?}"
            );
        }

        #[tokio::test]
        async fn test_regenerate_lockfile_cargo_oversized_probe_output_is_unexpected() {
            let flood = "if [ \"$1\" = locate-project ]; then i=0; while [ $i -lt 600 ]; do printf 'xxxxxxxxxx'; i=$((i+1)); done; echo; fi";
            let (outcome, calls) = run(
                flood,
                Bump::new("stuba", "stuba = ", "1.0.0", "1.0.1", "1.0.0", "1.0.1"),
            )
            .await;
            assert_matches!(
                outcome,
                LockfileOutcome::Failed(RegenerationError::UnexpectedProbeOutput {
                    program: Program::Cargo
                })
            );
            assert!(calls.iter().all(|c| !c.starts_with("update")), "{calls:?}");
        }
    }

    /// Probe-cap boundary and pin deduplication (mutation survivors of the first pass).
    #[cfg(feature = "cargo")]
    mod cargo_boundaries {
        use super::*;

        const CONTENT: &str = "[package]\nname = \"fx\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[workspace]\n\n[dependencies]\nstuba = \"1.0.0\"\n\n[dev-dependencies]\nstuba   = \"1.0.0\"\n";

        async fn run(body: &str, bumps: &[Bump]) -> (LockfileOutcome, Vec<String>) {
            let project = Project::new();
            let manifest = project.write("Cargo.toml", CONTENT);
            project.write(
                "Cargo.lock",
                "version = 4\n\n[[package]]\nname = \"stuba\"\nversion = \"1.0.1\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"1cfe8cbac33b06e98f6e403cac490acea6ce20d4cf11a75ac068b8c16bd3c30c\"\n",
            );
            let bin = FakeBin::new();
            bin.install("cargo", body);
            let outcome = apply_and_regenerate(
                EcosystemId::Cargo,
                &manifest,
                "Cargo.toml",
                CONTENT,
                bumps,
                run_gate(),
                &bin.runner(secs(30)),
            )
            .await;
            (outcome, bin.calls())
        }

        fn bump(anchor: &'static str) -> Bump {
            Bump::new("stuba", anchor, "1.0.0", "1.0.1", "1.0.0", "1.0.1")
        }

        fn flood(bytes_including_newline: usize) -> String {
            format!(
                "if [ \"$1\" = locate-project ]; then i=1; while [ $i -lt {bytes_including_newline} ]; do printf x; i=$((i+1)); done; echo; fi"
            )
        }

        #[tokio::test]
        async fn test_probe_output_exactly_at_cap_is_accepted() {
            let (outcome, _) = run(&flood(4096), &[bump("stuba = ")]).await;
            assert!(
                !matches!(
                    outcome,
                    LockfileOutcome::Failed(RegenerationError::UnexpectedProbeOutput { .. })
                ),
                "{outcome:?}"
            );
        }

        #[tokio::test]
        async fn test_probe_output_one_byte_over_cap_is_unexpected() {
            let (outcome, _) = run(&flood(4097), &[bump("stuba = ")]).await;
            assert_matches!(
                outcome,
                LockfileOutcome::Failed(RegenerationError::UnexpectedProbeOutput { .. })
            );
        }

        #[tokio::test]
        async fn test_collect_pins_duplicate_name_and_target_runs_precise_once() {
            let body = "if [ \"$1\" = locate-project ]; then echo \"$PWD/Cargo.toml\"; fi";
            let (outcome, calls) = run(body, &[bump("stuba = "), bump("stuba   = ")]).await;

            assert_eq!(
                calls.iter().filter(|c| c.contains("--precise=")).count(),
                1,
                "{calls:?}"
            );
            assert_eq!(
                pin_rows(&outcome),
                vec![("stuba".into(), "1.0.1".into(), PinResolution::Exact)],
                "{outcome:?}"
            );
        }
    }

    /// Architect rulings R1/R2: ancestor-workspace refusal and symlinked owned lockfiles.
    mod rulings {
        use super::*;
        use std::os::unix::fs::symlink;

        const PACKAGE_JSON: &str =
            "{\n  \"name\": \"a\",\n  \"dependencies\": {\n    \"lodash\": \"^4.17.20\"\n  }\n}\n";
        const NPM_LOCK: &str = "{\"name\":\"a\",\"lockfileVersion\":3,\"packages\":{\"\":{\"name\":\"a\",\"dependencies\":{\"lodash\":\"^4.17.20\"}},\"node_modules/lodash\":{\"version\":\"4.17.20\"}}}";
        const PNPM_LOCK: &str = "lockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    dependencies:\n      lodash:\n        specifier: ^4.17.20\n        version: 4.17.20\n";

        fn lodash() -> Bump {
            Bump::new(
                "lodash",
                "\"lodash\": ",
                "^4.17.20",
                "^4.17.21",
                "4.17.20",
                "4.17.21",
            )
        }

        /// Member at `<root>/packages/a` with its own lock; returns (project, manifest, bin).
        async fn run_member(
            lock_name: &str,
            lock: &str,
            tool: &str,
            ancestor: impl Fn(&Project),
        ) -> (LockfileOutcome, Vec<String>) {
            let project = Project::new();
            ancestor(&project);
            let manifest = project.write("packages/a/package.json", PACKAGE_JSON);
            project.write(&format!("packages/a/{lock_name}"), lock);
            let bin = FakeBin::new();
            bin.install(tool, "exit 0");
            let outcome = apply_and_regenerate(
                EcosystemId::Npm,
                &manifest,
                "package.json",
                PACKAGE_JSON,
                &[lodash()],
                run_gate(),
                &bin.runner(secs(30)),
            )
            .await;
            (outcome, bin.calls())
        }

        fn assert_workspace_member(outcome: &LockfileOutcome, calls: &[String]) {
            assert_matches!(
                outcome,
                LockfileOutcome::Unsupported {
                    reason: UnsupportedReason::WorkspaceMemberLockfile,
                    ..
                }
            );
            assert!(
                calls.iter().all(|c| !c.starts_with("install")),
                "no install may be spawned: {calls:?}"
            );
        }

        #[cfg(feature = "npm")]
        #[tokio::test]
        async fn test_npm_ancestor_package_json_with_workspaces_is_workspace_member() {
            let (outcome, calls) = run_member("package-lock.json", NPM_LOCK, "npm", |p| {
                p.write(
                    "package.json",
                    "{\"name\":\"root\",\"workspaces\":[\"packages/*\"]}",
                );
            })
            .await;
            assert_workspace_member(&outcome, &calls);
        }

        #[cfg(feature = "npm")]
        #[tokio::test]
        async fn test_npm_invalid_ancestor_package_json_is_workspace_member_fail_safe() {
            let (outcome, calls) = run_member("package-lock.json", NPM_LOCK, "npm", |p| {
                p.write("package.json", "{ not json");
            })
            .await;
            assert_workspace_member(&outcome, &calls);
        }

        /// Every symlinked ancestor `package.json` counts as a workspace hit (fail-safe), never
        /// followed: a benign target, `/dev/stdin` (would hang a following read), and a dangling link.
        #[cfg(feature = "npm")]
        #[tokio::test]
        async fn test_npm_symlinked_ancestor_package_json_is_workspace_member_without_hanging() {
            let targets = ["benign", "/dev/stdin", "dangling"];
            for target in targets {
                let run = run_member("package-lock.json", NPM_LOCK, "npm", |p| {
                    let link = p.path("package.json");
                    match target {
                        "benign" => {
                            let real = p.write("elsewhere/package.json", "{\"name\":\"root\"}");
                            symlink(real, link).expect("symlink");
                        }
                        "dangling" => symlink(p.path("missing.json"), link).expect("symlink"),
                        other => symlink(other, link).expect("symlink"),
                    }
                });
                let (outcome, calls) = tokio::time::timeout(secs(30), run)
                    .await
                    .unwrap_or_else(|_| panic!("{target}: ancestor read hung"));
                assert_workspace_member(&outcome, &calls);
            }
        }

        #[cfg(feature = "npm")]
        #[tokio::test]
        async fn test_npm_ancestor_package_json_without_workspaces_does_not_block() {
            let (outcome, calls) = run_member("package-lock.json", NPM_LOCK, "npm", |p| {
                p.write("package.json", "{\"name\":\"root\"}");
            })
            .await;
            assert!(
                !matches!(outcome, LockfileOutcome::Unsupported { .. }),
                "{outcome:?}"
            );
            assert_eq!(calls.len(), 1, "{calls:?}");
        }

        #[cfg(feature = "npm")]
        #[tokio::test]
        async fn test_pnpm_ancestor_workspace_yaml_is_workspace_member() {
            let (outcome, calls) = run_member("pnpm-lock.yaml", PNPM_LOCK, "pnpm", |p| {
                p.write("pnpm-workspace.yaml", "packages:\n  - 'packages/*'\n");
            })
            .await;
            assert_workspace_member(&outcome, &calls);
        }

        /// Member reached through a symlinked directory: `view/m -> real/ws/m`, the workspace
        /// root lives next to the real directory, so only a canonical upward search finds it.
        async fn run_symlinked_member(
            lock_name: &str,
            lock: &str,
            tool: &str,
            root_marker: (&str, &str),
        ) -> (LockfileOutcome, Vec<String>) {
            let project = Project::new();
            project.write(&format!("real/ws/{}", root_marker.0), root_marker.1);
            project.write("real/ws/m/package.json", PACKAGE_JSON);
            project.write(&format!("real/ws/m/{lock_name}"), lock);
            std::fs::create_dir_all(project.path("view")).expect("view dir");
            symlink(project.path("real/ws/m"), project.path("view/m")).expect("symlink dir");
            let manifest = project.path("view/m/package.json");
            let bin = FakeBin::new();
            bin.install(tool, "exit 0");
            let outcome = apply_and_regenerate(
                EcosystemId::Npm,
                &manifest,
                "package.json",
                PACKAGE_JSON,
                &[lodash()],
                run_gate(),
                &bin.runner(secs(30)),
            )
            .await;
            (outcome, bin.calls())
        }

        #[cfg(feature = "npm")]
        #[tokio::test]
        async fn test_npm_member_behind_symlinked_dir_is_workspace_member() {
            let (outcome, calls) = run_symlinked_member(
                "package-lock.json",
                NPM_LOCK,
                "npm",
                ("package.json", "{\"name\":\"root\",\"workspaces\":[\"m\"]}"),
            )
            .await;
            assert_workspace_member(&outcome, &calls);
        }

        #[cfg(feature = "npm")]
        #[tokio::test]
        async fn test_pnpm_member_behind_symlinked_dir_is_workspace_member() {
            let (outcome, calls) = run_symlinked_member(
                "pnpm-lock.yaml",
                PNPM_LOCK,
                "pnpm",
                ("pnpm-workspace.yaml", "packages:\n  - 'm'\n"),
            )
            .await;
            assert_workspace_member(&outcome, &calls);
        }

        // `NPM_CONFIG_WORKSPACE_DIR` needs `set_var`, which is `unsafe` and the workspace
        // forbids unsafe code; that branch is left to the developer's unit test or live-tester.

        // ----- R2: symlinked owned lockfile -----

        fn assert_symlink(
            outcome: &LockfileOutcome,
            calls: &[String],
            outside: &Path,
            before: &str,
        ) {
            assert_matches!(
                outcome,
                LockfileOutcome::Unsupported {
                    reason: UnsupportedReason::LockfileSymlink,
                    ..
                }
            );
            assert_eq!(std::fs::read_to_string(outside).expect("outside"), before);
            assert!(
                calls
                    .iter()
                    .all(|c| c.starts_with("locate-project") || c.starts_with("env GOWORK")),
                "only probes may run: {calls:?}"
            );
        }

        #[cfg(feature = "npm")]
        #[tokio::test]
        async fn test_npm_symlinked_lockfile_is_unsupported_and_untouched() {
            for (lock_name, lock, tool) in [
                ("package-lock.json", NPM_LOCK, "npm"),
                ("pnpm-lock.yaml", PNPM_LOCK, "pnpm"),
            ] {
                let project = Project::new();
                let manifest = project.write("package.json", PACKAGE_JSON);
                let outside = project.write("outside/real.lock", lock);
                symlink(&outside, project.path(lock_name)).expect("symlink");
                let bin = FakeBin::new();
                bin.install(tool, "exit 0");

                let outcome = apply_and_regenerate(
                    EcosystemId::Npm,
                    &manifest,
                    "package.json",
                    PACKAGE_JSON,
                    &[lodash()],
                    run_gate(),
                    &bin.runner(secs(30)),
                )
                .await;

                assert_symlink(&outcome, &bin.calls(), &outside, lock);
                if tool == "npm" {
                    let json = crate::format::json::update_to_document(
                        &UpdateRun {
                            plan: UpdatePlan::default(),
                            lockfile: outcome,
                        },
                        DryRun::No,
                    );
                    let json = serde_json::to_value(&json).expect("serialize");
                    assert_eq!(json["lockfile"]["reason"], "lockfile-symlink");
                }
            }
        }

        #[cfg(feature = "go")]
        #[tokio::test]
        async fn test_go_symlinked_go_sum_is_unsupported_and_untouched() {
            let project = Project::new();
            let go_mod = "module example.com/app\n\ngo 1.21\n\nrequire golang.org/x/text v0.30.0\n";
            let manifest = project.write("go.mod", go_mod);
            let sum = "golang.org/x/text v0.30.0 h1:old=\n";
            let outside = project.write("outside/go.sum", sum);
            symlink(&outside, project.path("go.sum")).expect("symlink");
            let bin = FakeBin::new();
            bin.install("go", "if [ \"$1\" = env ]; then echo; fi");

            let outcome = apply_and_regenerate(
                EcosystemId::Go,
                &manifest,
                "go.mod",
                go_mod,
                &[Bump::new(
                    "golang.org/x/text",
                    "golang.org/x/text",
                    "v0.30.0",
                    "v0.31.0",
                    "v0.30.0",
                    "v0.31.0",
                )],
                run_gate(),
                &bin.runner(secs(30)),
            )
            .await;

            assert_symlink(&outcome, &bin.calls(), &outside, sum);
        }

        #[cfg(feature = "cargo")]
        #[tokio::test]
        async fn test_cargo_symlinked_cargo_lock_is_unsupported_and_untouched() {
            let project = Project::new();
            let content = "[package]\nname = \"fx\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[workspace]\n\n[dependencies]\nstuba = \"1.0.0\"\n";
            let manifest = project.write("Cargo.toml", content);
            let lock = "version = 4\n";
            let outside = project.write("outside/Cargo.lock", lock);
            symlink(&outside, project.path("Cargo.lock")).expect("symlink");
            let bin = FakeBin::new();
            bin.install(
                "cargo",
                "if [ \"$1\" = locate-project ]; then echo \"$PWD/Cargo.toml\"; fi",
            );

            let outcome = apply_and_regenerate(
                EcosystemId::Cargo,
                &manifest,
                "Cargo.toml",
                content,
                &[Bump::new(
                    "stuba", "stuba = ", "1.0.0", "1.0.1", "1.0.0", "1.0.1",
                )],
                run_gate(),
                &bin.runner(secs(30)),
            )
            .await;

            assert_symlink(&outcome, &bin.calls(), &outside, lock);
        }
    }

    // ----- npm / pnpm -----

    #[cfg(feature = "npm")]
    mod npm {
        use super::*;

        struct Dep {
            name: &'static str,
            from: &'static str,
            to: &'static str,
            current: &'static str,
            target: &'static str,
            /// Version the fake tool leaves in the lock; empty means absent from the lock.
            lock_after: &'static str,
        }

        fn package_json(deps: &[Dep], requirement: fn(&Dep) -> &'static str) -> String {
            let body = deps
                .iter()
                .map(|dep| format!("    \"{}\": \"{}\"", dep.name, requirement(dep)))
                .collect::<Vec<_>>()
                .join(",\n");
            format!(
                "{{\n  \"name\": \"app\",\n  \"version\": \"1.0.0\",\n  \"dependencies\": {{\n{body}\n  }}\n}}\n"
            )
        }

        fn package_lock(
            deps: &[Dep],
            requirement: fn(&Dep) -> &'static str,
            version: fn(&Dep) -> &'static str,
        ) -> String {
            let root = deps
                .iter()
                .map(|dep| format!("\"{}\":\"{}\"", dep.name, requirement(dep)))
                .collect::<Vec<_>>()
                .join(",");
            let entries = deps
                .iter()
                .filter(|dep| !version(dep).is_empty())
                .map(|dep| {
                    format!(
                        ",\"node_modules/{}\":{{\"version\":\"{}\",\"resolved\":\"https://registry.npmjs.org/{}/-/{}-{}.tgz\"}}",
                        dep.name,
                        version(dep),
                        dep.name,
                        dep.name,
                        version(dep)
                    )
                })
                .collect::<Vec<_>>()
                .concat();
            format!(
                "{{\"name\":\"app\",\"version\":\"1.0.0\",\"lockfileVersion\":3,\"requires\":true,\"packages\":{{\"\":{{\"name\":\"app\",\"version\":\"1.0.0\",\"dependencies\":{{{root}}}}}{entries}}}}}"
            )
        }

        fn bumps(deps: &[Dep]) -> Vec<Bump> {
            deps.iter()
                .map(|dep| {
                    let anchor: &'static str =
                        Box::leak(format!("\"{}\": ", dep.name).into_boxed_str());
                    Bump::new(dep.name, anchor, dep.from, dep.to, dep.current, dep.target)
                })
                .collect()
        }

        struct NpmRun {
            outcome: LockfileOutcome,
            calls: Vec<String>,
            root: PathBuf,
        }

        /// Project with a package-lock at the pre-update versions; the fake `npm` rewrites it
        /// to `lock_after`.
        async fn run_npm(deps: &[Dep], gate: RegenerationGate) -> NpmRun {
            let project = Project::new();
            let content = package_json(deps, |d| d.from);
            let manifest = project.write("package.json", &content);
            project.write(
                "package-lock.json",
                &package_lock(deps, |d| d.from, |d| d.current),
            );
            let after = package_lock(deps, |d| d.to, |d| d.lock_after);
            let bin = FakeBin::new();
            bin.install(
                "npm",
                &format!("cat > package-lock.json <<'EOF'\n{after}\nEOF"),
            );

            let outcome = apply_and_regenerate(
                EcosystemId::Npm,
                &manifest,
                "package.json",
                &content,
                &bumps(deps),
                gate,
                &bin.runner(secs(30)),
            )
            .await;
            NpmRun {
                outcome,
                calls: bin.calls(),
                root: project.root.clone(),
            }
        }

        const LODASH_EXACT: Dep = Dep {
            name: "lodash",
            from: "^4.17.20",
            to: "^4.17.21",
            current: "4.17.20",
            target: "4.17.21",
            lock_after: "4.17.21",
        };

        #[tokio::test]
        async fn test_regenerate_lockfile_npm_exact_lock_runs_constant_argv_and_reports_exact() {
            let run = run_npm(&[LODASH_EXACT], run_gate()).await;

            assert_eq!(
                run.calls,
                vec![call(
                    "install --package-lock-only --ignore-scripts --no-audit --no-fund",
                    &run.root,
                    "0"
                )]
            );
            assert_eq!(
                pin_rows(&run.outcome),
                vec![("lodash".into(), "4.17.21".into(), PinResolution::Exact)],
                "{:?}",
                run.outcome
            );
            let LockfileOutcome::Regenerated { lockfile, tool, .. } = &run.outcome else {
                unreachable!()
            };
            assert_eq!(*tool, Program::Npm);
            assert_eq!(lockfile.to_string(), "package-lock.json");
        }

        #[tokio::test]
        async fn test_regenerate_lockfile_npm_newer_lock_reports_newer() {
            let dep = Dep {
                lock_after: "4.17.22",
                ..LODASH_EXACT
            };
            let run = run_npm(&[dep], run_gate()).await;
            assert_eq!(
                pin_rows(&run.outcome),
                vec![(
                    "lodash".into(),
                    "4.17.21".into(),
                    PinResolution::Newer(ConcreteVersion::from("4.17.22"))
                )],
                "{:?}",
                run.outcome
            );
        }

        #[tokio::test]
        async fn test_regenerate_lockfile_npm_stale_lock_is_version_mismatch() {
            let dep = Dep {
                lock_after: "4.17.20",
                ..LODASH_EXACT
            };
            let run = run_npm(&[dep], run_gate()).await;
            assert_eq!(
                mismatch(&run.outcome),
                ("lodash".into(), "4.17.21".into(), Some("4.17.20".into()))
            );
        }

        #[tokio::test]
        async fn test_regenerate_lockfile_npm_package_missing_from_lock_is_version_mismatch() {
            let missing = Dep {
                lock_after: "",
                ..LODASH_EXACT
            };
            let other = Dep {
                name: "minimist",
                from: "^1.2.5",
                to: "^1.2.5",
                current: "1.2.5",
                target: "1.2.5",
                lock_after: "1.2.5",
            };
            let run = run_npm(&[missing, other], run_gate()).await;
            assert_eq!(
                mismatch(&run.outcome),
                ("lodash".into(), "4.17.21".into(), None)
            );
        }

        /// Guards the `compile_requirement().matches()` path: the shared heuristic has no `>=`.
        #[tokio::test]
        async fn test_regenerate_lockfile_npm_greater_equal_requirement_accepts_newer_lock() {
            let dep = Dep {
                name: "qs",
                from: ">=1.2.0",
                to: ">=1.3.0",
                current: "1.2.0",
                target: "1.3.0",
                lock_after: "1.3.5",
            };
            let run = run_npm(&[dep], run_gate()).await;
            assert_eq!(
                pin_rows(&run.outcome),
                vec![(
                    "qs".into(),
                    "1.3.0".into(),
                    PinResolution::Newer(ConcreteVersion::from("1.3.5"))
                )],
                "{:?}",
                run.outcome
            );
        }

        #[tokio::test]
        async fn test_regenerate_lockfile_npm_lock_below_target_but_inside_range_is_mismatch() {
            let dep = Dep {
                name: "qs",
                from: ">=1.2.0",
                to: ">=1.3.0",
                current: "1.2.0",
                target: "1.3.0",
                lock_after: "1.2.9",
            };
            let run = run_npm(&[dep], run_gate()).await;
            assert_eq!(
                mismatch(&run.outcome),
                ("qs".into(), "1.3.0".into(), Some("1.2.9".into()))
            );
        }

        /// Default `--lockfile skip` (and dry-run / offline): nothing is spawned.
        #[tokio::test]
        async fn test_regenerate_lockfile_skip_gates_spawn_nothing() {
            for (gate, cause) in [
                (
                    RegenerationGate::new(LockfileMode::Skip, DryRun::No, NetworkMode::Online),
                    SkipCause::NotEnabled,
                ),
                (
                    RegenerationGate::new(
                        LockfileMode::Regenerate,
                        DryRun::Yes,
                        NetworkMode::Online,
                    ),
                    SkipCause::DryRun,
                ),
                (
                    RegenerationGate::new(
                        LockfileMode::Regenerate,
                        DryRun::No,
                        NetworkMode::Offline,
                    ),
                    SkipCause::Offline,
                ),
            ] {
                let run = run_npm(&[LODASH_EXACT], gate).await;
                assert_matches!(&run.outcome, LockfileOutcome::Skipped(c) if *c == cause);
                assert!(run.calls.is_empty(), "{cause:?} spawned {:?}", run.calls);
            }
        }

        #[tokio::test]
        async fn test_regenerate_lockfile_empty_plan_is_nothing_applied_and_spawns_nothing() {
            let project = Project::new();
            let content = package_json(&[LODASH_EXACT], |d| d.from);
            let manifest = project.write("package.json", &content);
            project.write(
                "package-lock.json",
                &package_lock(&[LODASH_EXACT], |d| d.from, |d| d.current),
            );
            let bin = FakeBin::new();
            bin.install("npm", "exit 0");

            for gate in [
                run_gate(),
                RegenerationGate::new(LockfileMode::Skip, DryRun::No, NetworkMode::Online),
            ] {
                let outcome = regenerate(
                    EcosystemId::Npm,
                    &manifest,
                    "package.json",
                    &UpdatePlan::default(),
                    gate,
                    &bin.runner(secs(30)),
                )
                .await;
                assert_matches!(
                    outcome,
                    LockfileOutcome::NotApplicable(NotApplicableReason::NothingApplied)
                );
            }
            assert!(bin.calls().is_empty());
        }

        #[tokio::test]
        async fn test_regenerate_lockfile_npm_without_lockfile_is_not_applicable() {
            let project = Project::new();
            let content = package_json(&[LODASH_EXACT], |d| d.from);
            let manifest = project.write("package.json", &content);
            let bin = FakeBin::new();
            bin.install("npm", "exit 0");

            let outcome = apply_and_regenerate(
                EcosystemId::Npm,
                &manifest,
                "package.json",
                &content,
                &bumps(&[LODASH_EXACT]),
                run_gate(),
                &bin.runner(secs(30)),
            )
            .await;

            assert_matches!(
                outcome,
                LockfileOutcome::NotApplicable(NotApplicableReason::NoLockfilePresent)
            );
            assert!(bin.calls().is_empty());
            assert!(!project.path("package-lock.json").exists());
        }

        #[tokio::test]
        async fn test_regenerate_lockfile_npm_workspace_member_lockfile_is_unsupported() {
            let project = Project::new();
            project.write("package-lock.json", "{}");
            let content = package_json(&[LODASH_EXACT], |d| d.from);
            let manifest = project.write("packages/a/package.json", &content);
            let bin = FakeBin::new();
            bin.install("npm", "exit 0");

            let outcome = apply_and_regenerate(
                EcosystemId::Npm,
                &manifest,
                "package.json",
                &content,
                &bumps(&[LODASH_EXACT]),
                run_gate(),
                &bin.runner(secs(30)),
            )
            .await;

            assert_matches!(
                outcome,
                LockfileOutcome::Unsupported {
                    reason: UnsupportedReason::WorkspaceMemberLockfile,
                    ..
                }
            );
            assert!(bin.calls().is_empty());
        }

        #[tokio::test]
        async fn test_regenerate_lockfile_pnpm_dir_outside_the_workspace_globs_is_refused_before_any_write()
         {
            let project = Project::new();
            project.write("package.json", "{\"name\":\"root\",\"private\":true}");
            project.write("pnpm-workspace.yaml", "packages:\n  - packages/*\n");
            project.write("pnpm-lock.yaml", "lockfileVersion: '9.0'\n");
            let content = package_json(&[LODASH_EXACT], |d| d.from);
            let manifest = project.write("examples/b/package.json", &content);
            let bin = FakeBin::new();
            let root = project.root.display();
            bin.install(
                "pnpm",
                &format!(
                    "case \"$1\" in\n  root) echo '{root}/node_modules';;\n  list) echo '[]';;\nesac\nexit 0"
                ),
            );

            let outcome = apply_and_regenerate(
                EcosystemId::Npm,
                &manifest,
                "package.json",
                &content,
                &bumps(&[LODASH_EXACT]),
                run_gate(),
                &bin.runner(secs(30)),
            )
            .await;

            assert_matches!(
                outcome,
                LockfileOutcome::Unsupported {
                    reason: UnsupportedReason::WorkspaceMemberLockfile,
                    ..
                }
            );
            assert!(
                bin.calls()
                    .iter()
                    .all(|call| !call.starts_with("install") && !call.starts_with("update")),
                "{:?}",
                bin.calls()
            );
        }

        #[tokio::test]
        async fn test_regenerate_lockfile_bun_lockfile_runs_the_lockfile_only_install() {
            let project = Project::new();
            let content = package_json(&[LODASH_EXACT], |d| d.from);
            let manifest = project.write("package.json", &content);
            project.write("bun.lock", "{}\n");
            let bin = FakeBin::new();
            bin.install("bun", "exit 0");

            let outcome = apply_and_regenerate(
                EcosystemId::Npm,
                &manifest,
                "package.json",
                &content,
                &bumps(&[LODASH_EXACT]),
                run_gate(),
                &bin.runner(secs(30)),
            )
            .await;

            assert_matches!(outcome, LockfileOutcome::Failed(_));
            let calls = bin.calls();
            assert_eq!(calls.len(), 1, "{calls:?}");
            assert!(
                calls[0].starts_with("install --lockfile-only --ignore-scripts|"),
                "{calls:?}"
            );
        }

        #[tokio::test]
        async fn test_regenerate_lockfile_npm_cooldown_fallback_target_not_held_exactly_fails() {
            let project = Project::new();
            let content = package_json(&[LODASH_EXACT], |d| d.from);
            let manifest = project.write("package.json", &content);
            project.write(
                "package-lock.json",
                &package_lock(&[LODASH_EXACT], |d| d.from, |d| d.current),
            );
            let bin = FakeBin::new();
            bin.install("npm", "exit 0");
            let mut bump = bumps(&[LODASH_EXACT]);
            bump[0].cooldown_fallback = true;

            let outcome = apply_and_regenerate(
                EcosystemId::Npm,
                &manifest,
                "package.json",
                &content,
                &bump,
                run_gate(),
                &bin.runner(secs(30)),
            )
            .await;

            assert_matches!(
                outcome,
                LockfileOutcome::Failed(RegenerationError::VersionMismatch { .. })
            );
            let calls = bin.calls();
            assert_eq!(calls.len(), 2, "{calls:?}");
            assert!(
                calls
                    .iter()
                    .all(|call| call.starts_with("install --package-lock-only ")),
                "{calls:?}"
            );
        }

        #[tokio::test]
        async fn test_regenerate_lockfile_npm_tool_failure_reports_exit_code() {
            let project = Project::new();
            let content = package_json(&[LODASH_EXACT], |d| d.from);
            let manifest = project.write("package.json", &content);
            project.write(
                "package-lock.json",
                &package_lock(&[LODASH_EXACT], |d| d.from, |d| d.current),
            );
            let bin = FakeBin::new();
            bin.install("npm", "exit 3");

            let outcome = apply_and_regenerate(
                EcosystemId::Npm,
                &manifest,
                "package.json",
                &content,
                &bumps(&[LODASH_EXACT]),
                run_gate(),
                &bin.runner(secs(30)),
            )
            .await;

            assert_matches!(
                outcome,
                LockfileOutcome::Failed(RegenerationError::ToolFailed {
                    program: Program::Npm,
                    code: Some(3)
                })
            );
        }

        #[tokio::test]
        async fn test_regenerate_lockfile_npm_missing_toolchain_is_toolchain_missing() {
            let project = Project::new();
            let content = package_json(&[LODASH_EXACT], |d| d.from);
            let manifest = project.write("package.json", &content);
            project.write(
                "package-lock.json",
                &package_lock(&[LODASH_EXACT], |d| d.from, |d| d.current),
            );
            let bin = FakeBin::new();

            let outcome = apply_and_regenerate(
                EcosystemId::Npm,
                &manifest,
                "package.json",
                &content,
                &bumps(&[LODASH_EXACT]),
                run_gate(),
                &bin.runner(secs(30)),
            )
            .await;

            assert_matches!(
                outcome,
                LockfileOutcome::Failed(RegenerationError::ToolchainMissing {
                    program: Program::Npm
                })
            );
        }

        #[tokio::test]
        async fn test_regenerate_lockfile_npm_hung_tool_times_out() {
            let project = Project::new();
            let content = package_json(&[LODASH_EXACT], |d| d.from);
            let manifest = project.write("package.json", &content);
            project.write(
                "package-lock.json",
                &package_lock(&[LODASH_EXACT], |d| d.from, |d| d.current),
            );
            let bin = FakeBin::new();
            bin.install("npm", "while :; do :; done");

            let outcome = apply_and_regenerate(
                EcosystemId::Npm,
                &manifest,
                "package.json",
                &content,
                &bumps(&[LODASH_EXACT]),
                run_gate(),
                &bin.runner(Duration::from_millis(300)),
            )
            .await;

            assert_matches!(
                outcome,
                LockfileOutcome::Failed(RegenerationError::TimedOut { .. })
            );
        }

        #[tokio::test]
        async fn test_regenerate_lockfile_pnpm_runs_constant_argv_and_reports_exact() {
            let project = Project::new();
            let pnpm_lock = |req: &str, version: &str| {
                format!(
                    "lockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    dependencies:\n      react:\n        specifier: {req}\n        version: {version}\n"
                )
            };
            let content = "{\n  \"name\": \"app\",\n  \"version\": \"1.0.0\",\n  \"dependencies\": {\n    \"react\": \"^16.0.0\"\n  }\n}\n";
            let manifest = project.write("package.json", content);
            project.write("pnpm-lock.yaml", &pnpm_lock("^16.0.0", "16.0.0"));
            let bin = FakeBin::new();
            bin.install(
                "pnpm",
                &format!(
                    "cat > pnpm-lock.yaml <<'EOF'\n{}EOF",
                    pnpm_lock("^16.1.0", "16.1.0")
                ),
            );

            let outcome = apply_and_regenerate(
                EcosystemId::Npm,
                &manifest,
                "package.json",
                content,
                &[Bump::new(
                    "react",
                    "\"react\": ",
                    "^16.0.0",
                    "^16.1.0",
                    "16.0.0",
                    "16.1.0",
                )],
                run_gate(),
                &bin.runner(secs(30)),
            )
            .await;

            assert_eq!(
                bin.calls(),
                vec![call(
                    "install --lockfile-only --ignore-scripts --no-frozen-lockfile",
                    &project.root,
                    "0"
                )]
            );
            assert_eq!(
                pin_rows(&outcome),
                vec![("react".into(), "16.1.0".into(), PinResolution::Exact)],
                "{outcome:?}"
            );
            let LockfileOutcome::Regenerated { tool, lockfile, .. } = &outcome else {
                unreachable!()
            };
            assert_eq!(*tool, Program::Pnpm);
            assert_eq!(lockfile.to_string(), "pnpm-lock.yaml");
        }

        // ----- JSON / table wire output -----

        fn run_of(outcome: LockfileOutcome) -> UpdateRun {
            UpdateRun {
                plan: UpdatePlan::default(),
                lockfile: outcome,
            }
        }

        fn lockfile_json(outcome: LockfileOutcome) -> serde_json::Value {
            let document = crate::format::json::update_to_document(&run_of(outcome), DryRun::No);
            serde_json::to_value(&document).expect("serialize")["lockfile"].clone()
        }

        #[tokio::test]
        async fn test_update_to_document_lockfile_regenerated_lists_pins() {
            let lodash = LODASH_EXACT;
            let minimist = Dep {
                name: "minimist",
                from: "^1.2.5",
                to: "^1.2.6",
                current: "1.2.5",
                target: "1.2.6",
                lock_after: "1.2.8",
            };
            let run = run_npm(&[lodash, minimist], run_gate()).await;

            assert_eq!(
                lockfile_json(run.outcome),
                serde_json::json!({
                    "status": "regenerated",
                    "path": "package-lock.json",
                    "tool": "npm",
                    "pins": [
                        {"name": "lodash", "target": "4.17.21", "resolved": "4.17.21", "match": "exact"},
                        {"name": "minimist", "target": "1.2.6", "resolved": "1.2.8", "match": "newer"},
                    ],
                })
            );
        }

        #[tokio::test]
        async fn test_update_to_document_lockfile_failed_version_mismatch_carries_package_fields() {
            let stale = Dep {
                lock_after: "4.17.20",
                ..LODASH_EXACT
            };
            let run = run_npm(&[stale], run_gate()).await;

            let json = lockfile_json(run.outcome);
            assert_eq!(json["status"], "failed");
            assert_eq!(json["kind"], "version-mismatch");
            assert_eq!(json["package"], "lodash");
            assert_eq!(json["expected"], "4.17.21");
            assert_eq!(json["found"], "4.17.20");
            assert!(json["message"].is_string(), "{json}");
        }

        #[test]
        fn test_update_to_document_lockfile_simple_variants_have_wire_tokens() {
            assert_eq!(
                lockfile_json(LockfileOutcome::Skipped(SkipCause::NotEnabled)),
                serde_json::json!({"status": "skipped", "reason": "not-enabled"})
            );
            assert_eq!(
                lockfile_json(LockfileOutcome::Skipped(SkipCause::DryRun))["reason"],
                "dry-run"
            );
            assert_eq!(
                lockfile_json(LockfileOutcome::Skipped(SkipCause::Offline))["reason"],
                "offline"
            );
            assert_eq!(
                lockfile_json(LockfileOutcome::NotApplicable(
                    NotApplicableReason::NothingApplied
                )),
                serde_json::json!({"status": "not-applicable", "reason": "nothing-applied"})
            );
            let unsupported = lockfile_json(LockfileOutcome::Unsupported {
                lockfile: None,
                reason: UnsupportedReason::ToolTooOld(Program::Poetry),
            });
            assert_eq!(
                unsupported,
                serde_json::json!({
                    "status": "unsupported",
                    "reason": "tool-too-old",
                    "path": null,
                    "detail": "poetry",
                })
            );
            let failed = lockfile_json(LockfileOutcome::Failed(RegenerationError::ToolFailed {
                program: Program::Pnpm,
                code: Some(1),
            }));
            assert_eq!(failed["status"], "failed");
            assert_eq!(failed["kind"], "tool-failed");
            assert!(
                failed["package"].is_null()
                    && failed["expected"].is_null()
                    && failed["found"].is_null()
            );
        }

        #[tokio::test]
        async fn test_render_update_table_prints_lockfile_line_and_indented_pins() {
            let minimist = Dep {
                name: "minimist",
                from: "^1.2.5",
                to: "^1.2.6",
                current: "1.2.5",
                target: "1.2.6",
                lock_after: "1.2.8",
            };
            let run = run_npm(&[minimist], run_gate()).await;

            let table = crate::format::table::render_update(&run_of(run.outcome), DryRun::No);
            assert!(
                table
                    .lines()
                    .any(|l| l.starts_with("lockfile: regenerated")),
                "{table}"
            );
            assert!(
                table
                    .lines()
                    .any(|l| l.starts_with("  ") && l.contains("minimist") && l.contains("1.2.8")),
                "{table}"
            );
        }
    }

    // ----- Go -----

    #[cfg(feature = "go")]
    mod go {
        use super::*;

        const GO_MOD: &str =
            "module example.com/app\n\ngo 1.21\n\nrequire golang.org/x/text v0.30.0\n";
        const OLD_SUM: &str =
            "golang.org/x/text v0.30.0 h1:old=\ngolang.org/x/text v0.30.0/go.mod h1:oldmod=\n";

        fn bump() -> [Bump; 1] {
            [Bump::new(
                "golang.org/x/text",
                "golang.org/x/text",
                "v0.30.0",
                "v0.31.0",
                "v0.30.0",
                "v0.31.0",
            )]
        }

        struct GoRun {
            outcome: LockfileOutcome,
            calls: Vec<String>,
            root: PathBuf,
        }

        /// `gowork` is what `go env GOWORK` prints; `sum_after` what `go get` leaves in go.sum.
        async fn run_go(gowork: &str, sum_after: &str) -> GoRun {
            let project = Project::new();
            let manifest = project.write("go.mod", GO_MOD);
            project.write("go.sum", OLD_SUM);
            let bin = FakeBin::new();
            bin.install(
                "go",
                &format!(
                    "if [ \"$1\" = env ]; then printf '%s\\n' '{gowork}'; exit 0; fi\ncat > go.sum <<'EOF'\n{sum_after}EOF"
                ),
            );
            let outcome = apply_and_regenerate(
                EcosystemId::Go,
                &manifest,
                "go.mod",
                GO_MOD,
                &bump(),
                run_gate(),
                &bin.runner(secs(30)),
            )
            .await;
            GoRun {
                outcome,
                calls: bin.calls(),
                root: project.root.clone(),
            }
        }

        #[tokio::test]
        async fn test_regenerate_lockfile_go_content_checksum_for_target_is_exact() {
            let sum = "golang.org/x/text v0.30.0 h1:old=\ngolang.org/x/text v0.31.0 h1:new=\ngolang.org/x/text v0.31.0/go.mod h1:newmod=\n";
            let run = run_go("", sum).await;

            assert_eq!(
                run.calls,
                vec![
                    call("env GOWORK", &run.root, ""),
                    call("get -- golang.org/x/text@v0.31.0", &run.root, ""),
                ]
            );
            assert_eq!(
                pin_rows(&run.outcome),
                vec![(
                    "golang.org/x/text".into(),
                    "v0.31.0".into(),
                    PinResolution::Exact
                )],
                "{:?}",
                run.outcome
            );
            let LockfileOutcome::Regenerated { tool, lockfile, .. } = &run.outcome else {
                unreachable!()
            };
            assert_eq!(*tool, Program::Go);
            assert_eq!(lockfile.to_string(), "go.sum");
        }

        #[tokio::test]
        async fn test_regenerate_lockfile_go_only_go_mod_checksum_for_target_is_version_mismatch() {
            let sum =
                "golang.org/x/text v0.30.0 h1:old=\ngolang.org/x/text v0.31.0/go.mod h1:newmod=\n";
            let run = run_go("off", sum).await;

            assert_eq!(
                mismatch(&run.outcome),
                (
                    "golang.org/x/text".into(),
                    "v0.31.0".into(),
                    Some("v0.30.0".into())
                )
            );
        }

        #[tokio::test]
        async fn test_regenerate_lockfile_go_workspace_probe_path_runs_get_with_gowork_off() {
            let run = run_go("/ws/go.work", "").await;

            assert_eq!(
                run.calls,
                vec![
                    call("env GOWORK", &run.root, ""),
                    call("get -- golang.org/x/text@v0.31.0", &run.root, ""),
                ]
            );
        }

        struct VendoredRun {
            outcome: LockfileOutcome,
            calls: Vec<String>,
            flags: Vec<String>,
            project: Project,
        }

        /// A fake `go` whose `mod vendor -o <dir>` records `vendored_version` in `modules.txt`.
        async fn run_vendored_go(vendored_version: &str) -> VendoredRun {
            let project = Project::new();
            let manifest = project.write("go.mod", GO_MOD);
            project.write("go.sum", OLD_SUM);
            project.write("vendor/modules.txt", "# golang.org/x/text v0.30.0\n");
            project.write("vendor/old.go", "package old\n");
            let bin = FakeBin::new();
            bin.install(
                "go",
                &format!(
                    "if [ \"$1\" = env ]; then echo; exit 0; fi\n\
                     echo \"$GOFLAGS\" >> \"$(dirname \"$0\")/flags.log\"\n\
                     if [ \"$1\" = mod ]; then\n\
                     printf '# golang.org/x/text {vendored_version}\\n' > \"$4/modules.txt\"\n\
                     echo new > \"$4/new.go\"\n\
                     else printf 'golang.org/x/text v0.31.0 h1:new=\\ngolang.org/x/text v0.31.0/go.mod h1:m=\\n' > go.sum; fi"
                ),
            );
            let outcome = apply_and_regenerate(
                EcosystemId::Go,
                &manifest,
                "go.mod",
                GO_MOD,
                &bump(),
                run_gate(),
                &bin.runner(secs(30)),
            )
            .await;
            let flags = std::fs::read_to_string(bin.dir.path().join("flags.log"))
                .map(|log| log.lines().map(str::to_string).collect())
                .unwrap_or_default();
            VendoredRun {
                outcome,
                calls: bin.calls(),
                flags,
                project,
            }
        }

        fn scratch_residue(root: &Path) -> Vec<String> {
            std::fs::read_dir(root)
                .expect("read project dir")
                .map(|entry| {
                    entry
                        .expect("entry")
                        .file_name()
                        .to_string_lossy()
                        .into_owned()
                })
                .filter(|name| name.starts_with(".deps-cli-vendor-"))
                .collect()
        }

        #[tokio::test]
        async fn test_regenerate_lockfile_go_vendored_swaps_in_the_rebuilt_tree() {
            let run = run_vendored_go("v0.31.0").await;

            let root = &run.project.root;
            assert_eq!(run.calls.len(), 3, "{:?}", run.calls);
            assert!(run.calls[1].starts_with("get -- golang.org/x/text@v0.31.0|"));
            assert!(
                run.calls[2].starts_with("mod vendor -o "),
                "{:?}",
                run.calls
            );
            assert_eq!(run.flags, vec!["-mod=mod", "-mod=mod"]);
            assert_matches!(
                &run.outcome,
                LockfileOutcome::Regenerated { companions, .. }
                    if companions.len() == 1
                        && matches!(&companions[0], crate::update::regen::Companion::Tree(tree) if *tree == root.join("vendor"))
            );
            assert!(run.project.read("vendor/modules.txt").contains("v0.31.0"));
            assert!(root.join("vendor/new.go").is_file());
            assert!(!root.join("vendor/old.go").exists());
            assert_eq!(scratch_residue(root), Vec::<String>::new());
        }

        #[tokio::test]
        async fn test_regenerate_lockfile_go_vendored_mismatch_keeps_the_old_tree_and_restores_the_module_files()
         {
            let run = run_vendored_go("v0.30.0").await;

            let root = &run.project.root;
            assert_matches!(
                run.outcome,
                LockfileOutcome::Failed(RegenerationError::VersionMismatch { .. })
            );
            assert!(root.join("vendor/old.go").is_file());
            assert!(!root.join("vendor/new.go").exists());
            assert_eq!(run.project.read("go.sum"), OLD_SUM);
            assert_eq!(scratch_residue(root), Vec::<String>::new());
        }

        #[tokio::test]
        async fn test_regenerate_lockfile_go_symlinked_module_files_are_refused_without_spawning() {
            for linked in ["go.sum", "go.mod"] {
                let project = Project::new();
                project.write("real", if linked == "go.sum" { OLD_SUM } else { GO_MOD });
                let other = if linked == "go.sum" {
                    "go.mod"
                } else {
                    "go.sum"
                };
                let manifest =
                    project.write(other, if linked == "go.sum" { GO_MOD } else { OLD_SUM });
                std::os::unix::fs::symlink(project.path("real"), project.path(linked))
                    .expect("symlink module file");
                let manifest = if linked == "go.mod" {
                    project.path("go.mod")
                } else {
                    manifest
                };
                let bin = FakeBin::new();
                bin.install("go", "echo");

                let plan = plan_of(GO_MOD, &bump());
                let outcome = regenerate(
                    EcosystemId::Go,
                    &manifest,
                    "go.mod",
                    &plan,
                    run_gate(),
                    &bin.runner(secs(30)),
                )
                .await;

                assert_matches!(
                    outcome,
                    LockfileOutcome::Unsupported {
                        reason: UnsupportedReason::LockfileSymlink,
                        ..
                    },
                    "{linked}"
                );
                assert!(
                    bin.calls()
                        .iter()
                        .all(|call| call.starts_with("env GOWORK")),
                    "{linked}: {:?}",
                    bin.calls()
                );
            }
        }

        #[tokio::test]
        async fn test_regenerate_lockfile_go_vendored_symlinked_tree_is_refused_without_spawning() {
            let project = Project::new();
            let manifest = project.write("go.mod", GO_MOD);
            project.write("go.sum", OLD_SUM);
            project.write("real/modules.txt", "# golang.org/x/text v0.30.0\n");
            std::os::unix::fs::symlink(project.path("real"), project.path("vendor"))
                .expect("symlink vendor");
            let bin = FakeBin::new();
            bin.install("go", "exit 0");

            let outcome = apply_and_regenerate(
                EcosystemId::Go,
                &manifest,
                "go.mod",
                GO_MOD,
                &bump(),
                run_gate(),
                &bin.runner(secs(30)),
            )
            .await;

            assert_matches!(
                outcome,
                LockfileOutcome::Unsupported {
                    reason: UnsupportedReason::LockfileSymlink,
                    ..
                }
            );
            assert!(bin.calls().is_empty(), "{:?}", bin.calls());
        }
    }
}

#[test]
fn test_process_group_choose_inherits_only_for_the_terminals_foreground_group() {
    assert_eq!(ProcessGroup::choose(Some(100), 100), ProcessGroup::Inherit);
    assert_eq!(ProcessGroup::choose(Some(200), 100), ProcessGroup::Own);
    assert_eq!(ProcessGroup::choose(None, 100), ProcessGroup::Own);
}

#[cfg(unix)]
#[tokio::test]
async fn test_interrupts_recv_resolves_on_sigterm_instead_of_killing_the_process() {
    let mut interrupts = super::interrupt::Interrupts::install().expect("install handlers");

    rustix::process::kill_process(rustix::process::getpid(), rustix::process::Signal::TERM)
        .expect("signal self");

    tokio::time::timeout(Duration::from_secs(5), interrupts.recv())
        .await
        .expect("SIGTERM was delivered to the handler");
}

#[cfg(feature = "npm")]
#[tokio::test]
async fn test_regenerate_until_refuses_a_lockfile_outside_the_scope_without_spawning() {
    use crate::update::regen::{LockfileScope, regenerate_until};

    let project = Project::new();
    let content =
        "{\"name\":\"a\",\"version\":\"1.0.0\",\"dependencies\":{\"lodash\":\"^4.17.0\"}}";
    let manifest = project.write("package.json", content);
    project.write("package-lock.json", "{}");
    let elsewhere = Project::new();
    let plan = plan_of(
        content,
        &[Bump::new(
            "lodash", "lodash", "^4.17.0", "^4.17.21", "4.17.20", "4.17.21",
        )],
    );
    let ecosystem = ecosystem(EcosystemId::Npm);
    let uri = Url::from_file_path(&manifest).expect("file url");
    let display = PathBuf::from("package.json");
    let original_text = std::fs::read_to_string(&manifest).unwrap_or_default();
    let target = ManifestTarget {
        ecosystem: &ecosystem,
        manifest_path: &manifest,
        display_path: &display,
        uri: &uri,
        original: super::OriginalManifest::new(&original_text),
    };

    let outcome = regenerate_until(
        &plan,
        &target,
        run_gate(),
        &inherit_runner(),
        LockfileScope::Within(&elsewhere.root),
        std::future::pending(),
    )
    .await
    .lockfile;

    assert_matches!(
        outcome,
        LockfileOutcome::Unsupported {
            reason: UnsupportedReason::LockfileOutsideRepository,
            ..
        }
    );
}

#[cfg(all(unix, feature = "npm"))]
mod interrupted {
    use super::*;
    use crate::update::regen::{LockfileScope, regenerate_until};
    use std::os::unix::fs::PermissionsExt;

    fn alive(pid: u32) -> bool {
        std::process::Command::new("kill")
            .args(["-0", &pid.to_string()])
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
    }

    fn read_pid(path: &Path) -> u32 {
        for _ in 0..100 {
            if let Ok(text) = std::fs::read_to_string(path)
                && let Ok(pid) = text.trim().parse()
            {
                return pid;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        panic!("{} was never written", path.display());
    }

    #[tokio::test]
    async fn test_regenerate_until_interrupt_kills_the_tool_tree_and_reports_interrupted() {
        let project = Project::new();
        let content =
            "{\"name\":\"a\",\"version\":\"1.0.0\",\"dependencies\":{\"lodash\":\"^4.17.0\"}}";
        let manifest = project.write("package.json", content);
        project.write("package-lock.json", "{}");
        let bin = tempfile::tempdir().expect("bin dir");
        let leader = bin.path().join("leader.pid");
        let grandchild = bin.path().join("grandchild.pid");
        let script = format!(
            "#!/bin/sh\necho $$ > '{}'\nsleep 30 &\necho $! > '{}'\nsleep 30\n",
            leader.display(),
            grandchild.display()
        );
        let npm = bin.path().join("npm");
        std::fs::write(&npm, script).expect("write shim");
        std::fs::set_permissions(&npm, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        let runner = ToolRunner {
            deadline: Duration::from_mins(1),
            search_path: SearchPath::Override(bin.path().as_os_str().to_owned()),
            group: ProcessGroup::Own,
        };
        let plan = plan_of(
            content,
            &[Bump::new(
                "lodash", "lodash", "^4.17.0", "^4.17.21", "4.17.20", "4.17.21",
            )],
        );
        let ecosystem = ecosystem(EcosystemId::Npm);
        let uri = Url::from_file_path(&manifest).expect("file url");
        let display = PathBuf::from("package.json");
        let original_text = std::fs::read_to_string(&manifest).unwrap_or_default();
        let target = ManifestTarget {
            ecosystem: &ecosystem,
            manifest_path: &manifest,
            display_path: &display,
            uri: &uri,
            original: crate::update::regen::OriginalManifest::new(&original_text),
        };
        let (fire, fired) = tokio::sync::oneshot::channel::<()>();
        let interrupt = async move {
            fired.await.expect("sender alive");
        };
        let signaller = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(500)).await;
            fire.send(()).expect("receiver alive");
        });

        let outcome = regenerate_until(
            &plan,
            &target,
            run_gate(),
            &runner,
            LockfileScope::Unrestricted,
            interrupt,
        )
        .await
        .lockfile;
        signaller.await.expect("signaller");

        assert_matches!(
            outcome,
            LockfileOutcome::Failed(RegenerationError::Interrupted)
        );
        for pid in [read_pid(&leader), read_pid(&grandchild)] {
            let start = std::time::Instant::now();
            // Async sleep: a blocked runtime thread would never reap the killed leader.
            while alive(pid) && start.elapsed() < Duration::from_secs(2) {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            assert!(!alive(pid), "pid {pid} survived the interrupt");
        }
    }
}

// ---------------------------------------------------------------------------------------------
// restore_after: which failures put the lock files back (#2118)
// ---------------------------------------------------------------------------------------------

fn held(package: &str) -> super::HeldVersion {
    super::HeldVersion {
        package: deps_core::PackageName::new(package),
        version: ConcreteVersion::from("1.0.1"),
        target: ConcreteVersion::from("1.0.0"),
    }
}

/// The decision `restore_after` must make for `error`. The match has no wildcard arm, so a new
/// [`RegenerationError`] variant fails to compile here until its decision is stated.
fn expected_restore(error: &RegenerationError) -> bool {
    match error {
        RegenerationError::SnapshotFailed { .. } | RegenerationError::RestoreFailed { .. } => false,
        RegenerationError::TimedOut { .. } | RegenerationError::Interrupted => cfg!(unix),
        RegenerationError::ToolchainMissing { .. }
        | RegenerationError::Spawn { .. }
        | RegenerationError::ToolFailed { .. }
        | RegenerationError::UnexpectedProbeOutput { .. }
        | RegenerationError::UnsafeArgument { .. }
        | RegenerationError::UnrecognizedLockfile { .. }
        | RegenerationError::ManifestReparseFailed { .. }
        | RegenerationError::LockfileUnreadable { .. }
        | RegenerationError::VersionMismatch { .. }
        | RegenerationError::CooldownHeldVersion { .. }
        | RegenerationError::FallbackPinRejected { .. }
        | RegenerationError::ManifestChanged { .. }
        | RegenerationError::Io { .. }
        | RegenerationError::FallbackPinNotKept { .. }
        | RegenerationError::LockfilePinNotKept { .. }
        | RegenerationError::LockStateDrift { .. } => true,
    }
}

#[test]
fn test_restore_after_pins_every_regeneration_error_variant() {
    let path = || PathBuf::from("Cargo.lock");
    let io = || std::io::Error::other("denied");
    let program = Program::Cargo;
    let package = || deps_core::PackageName::new("x");
    let version = || ConcreteVersion::from("1.0.0");
    let samples = [
        RegenerationError::ToolchainMissing { program },
        RegenerationError::Spawn {
            program,
            source: io(),
        },
        RegenerationError::Interrupted,
        RegenerationError::TimedOut {
            after: Duration::from_secs(1),
        },
        RegenerationError::ToolFailed {
            program,
            code: Some(1),
        },
        RegenerationError::UnexpectedProbeOutput { program },
        RegenerationError::UnsafeArgument {
            package: "x".into(),
        },
        RegenerationError::UnrecognizedLockfile { path: path() },
        RegenerationError::ManifestReparseFailed { path: path() },
        RegenerationError::LockfileUnreadable { path: path() },
        RegenerationError::VersionMismatch {
            package: package(),
            expected: version(),
            found: None,
        },
        RegenerationError::CooldownHeldVersion {
            first: held("x"),
            rest: Vec::new(),
        },
        RegenerationError::SnapshotFailed { path: path() },
        RegenerationError::RestoreFailed {
            cause: Box::new(RegenerationError::Interrupted),
            path: path(),
            source: io(),
        },
        RegenerationError::FallbackPinRejected {
            package: package(),
            target: version(),
            code: Some(1),
        },
        RegenerationError::ManifestChanged { path: path() },
        RegenerationError::Io {
            operation: super::IoOperation::RewriteLockfile,
            path: path(),
            source: io(),
        },
        RegenerationError::FallbackPinNotKept {
            package: package(),
            target: version(),
            path: path(),
            reason: super::RekeyRefusal::PinnedEntryMissing,
        },
    ];
    for error in &samples {
        assert_eq!(
            super::restore_after(error),
            expected_restore(error),
            "{error:?}"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// rekey_lock: the lock rewrite fails after the rename succeeded (#2112)
// ---------------------------------------------------------------------------------------------

#[cfg(feature = "npm")]
#[test]
fn test_rekey_lock_write_failure_is_reported_as_the_lockfile_rewrite() {
    use super::fallback::DescriptorLock;
    use super::rekey::LockRekey;
    use super::{IoOperation, Session};

    let dir = tempfile::tempdir().expect("temp dir");
    let lockfile = dir.path().join("yarn.lock");
    let original = "\"x@npm:1.2.8\":\n  version: 1.2.8\n";
    std::fs::write(&lockfile, original).expect("write lock");
    let ecosystem = ecosystem(EcosystemId::Npm);
    let manifest = dir.path().join("package.json");
    let uri = Url::from_file_path(&manifest).expect("file url");
    let display_path = PathBuf::from("package.json");
    let target = ManifestTarget {
        ecosystem: &ecosystem,
        manifest_path: &manifest,
        display_path: &display_path,
        uri: &uri,
        original: super::OriginalManifest::new(""),
    };
    let runner = inherit_runner();
    let snapshot = std::sync::OnceLock::new();
    let session = Session {
        target: &target,
        runner: &runner,
        deadline: tokio::time::Instant::now() + Duration::from_secs(60),
        pins: &[],
        manifest_dir: dir.path(),
        snapshot: &snapshot,
        scope: LockfileScope::Unrestricted,
    };
    let rekeys = [LockRekey {
        package: deps_core::PackageName::new("x"),
        pinned: ConcreteVersion::from("1.2.8"),
        declared: deps_core::VersionReq::new("^1.2.5"),
    }];
    let mut attempted = None;

    let error = session
        .rekey_lock(DescriptorLock::YarnBerry, &lockfile, &rekeys, |_, bytes| {
            attempted = Some(String::from_utf8_lossy(bytes).into_owned());
            Err(std::io::Error::other("denied"))
        })
        .expect_err("the write fails");

    assert_matches!(
        error,
        RegenerationError::Io {
            operation: IoOperation::RewriteLockfile,
            ..
        }
    );
    assert_eq!(
        attempted.as_deref(),
        Some("\"x@npm:^1.2.5\":\n  version: 1.2.8\n"),
        "the rename succeeded before the write failed"
    );
    assert_eq!(std::fs::read_to_string(&lockfile).expect("read"), original);
}
