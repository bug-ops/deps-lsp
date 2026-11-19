//! Acceptance tests for #2049 (security-only fixes applied through the lock file), written
//! tests-first against plan revision 3 (`.local/handoff/2026-11-18T00-57-21-architect.md`).
//!
//! Requires `#[cfg(test)] mod lockfile_only_tests;` in `regen/mod.rs`. Helpers are deliberately
//! local: the sibling `tests` module keeps its own private.
//!
//! Layers:
//! - `NpmPackageArg` table (legacy names accepted, `*` and leading `!`/`-`/`.` rejected);
//! - outcome wording and wire shape of `Outcome::AppliedViaLockfile`;
//! - shim `cargo`/`npm`/`pnpm` tools checked through the real lockfile providers;
//! - real `cargo` against the committed offline local registry, through the public
//!   `regenerate_lockfile` settlement.

#![allow(clippy::expect_used, clippy::panic, clippy::too_many_lines)]
// Helpers serve the feature-gated cargo/npm/go/pypi tests; a partial feature build leaves them unused.
#![cfg_attr(
    not(all(feature = "cargo", feature = "npm", feature = "go", feature = "pypi")),
    allow(dead_code, unused_imports)
)]

use std::assert_matches;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use deps_core::edit::ManifestEdit;
use deps_core::net_policy::{MapEnv, RegistryEnvironment};
#[cfg(unix)]
use deps_core::osv::{AffectedRanges, OsvEcosystem, OsvPackageName};
use deps_core::policy_config::PolicyConfig;
use deps_core::position::{Position, Range};
use deps_core::{
    ConcreteVersion, Ecosystem, EcosystemId, EcosystemRegistry, HttpCache, NetworkMode,
};
use deps_engine::setup::{EcosystemRuntime, register_ecosystems};
use url::Url;

#[cfg(unix)]
use super::PinResolution;
use super::command::NpmPackageArg;
use super::run::{ProcessGroup, SearchPath, ToolRunner};
use super::{
    LockfileMode, LockfileOutcome, ManifestTarget, NotApplicableReason, RegenerationGate,
    SkipCause, regenerate_lockfile, regenerate_lockfile_with,
};
#[cfg(unix)]
use crate::exit::EXIT_EXECUTION_ERROR;
use crate::exit::{EXIT_CLEAN, EXIT_POLICY_VIOLATION, update_exit_code};
use crate::format::DryRun;
#[cfg(unix)]
use crate::update::LockfileState;
use crate::update::{CurrentVersion, Outcome, PlannedUpdateItem, UpdatePlan, UpdateRun};

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

    fn write(&self, rel: &str, content: &str) -> PathBuf {
        let path = self.root.join(rel);
        std::fs::create_dir_all(path.parent().expect("parent")).expect("create dirs");
        std::fs::write(&path, content).expect("write file");
        path
    }

    fn read(&self, rel: &str) -> String {
        std::fs::read_to_string(self.root.join(rel)).expect("read file")
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

fn item(name: &str, current: &str, outcome: Outcome) -> PlannedUpdateItem {
    PlannedUpdateItem::new(
        name.to_string(),
        CurrentVersion::Resolved(ConcreteVersion::from(current)),
        outcome,
        vec![],
        false,
        None,
        None,
    )
}

/// A dependency whose requirement already admits `target`: nothing to edit in the manifest.
fn lockfile_only(name: &str, locked: &str, target: &str) -> PlannedUpdateItem {
    item(
        name,
        locked,
        Outcome::RequiresLockfileUpdate {
            target: ConcreteVersion::from(target),
        },
    )
}

/// A dependency whose first `from` text in `content` is replaced by `to`, with the real range.
#[cfg(unix)]
fn real_edit(
    content: &str,
    name: &str,
    (current, target): (&str, &str),
    (from, to): (&str, &str),
) -> PlannedUpdateItem {
    let offset = content.find(from).expect("text to replace");
    let before = content.get(..offset).expect("char boundary");
    let line = u32::try_from(before.matches('\n').count()).expect("line");
    let column = before.rsplit('\n').next().map_or(0, str::len);
    let start = Position::new(line, u32::try_from(column).expect("column"));
    let end = Position::new(line, u32::try_from(column + from.len()).expect("column"));
    item(
        name,
        current,
        Outcome::Applied {
            edit: ManifestEdit {
                range: Range::new(start, end),
                new_text: to.to_string(),
            },
            target: ConcreteVersion::from(target),
        },
    )
}

/// A dependency with a manifest edit at line 0 (never written by these tests).
fn manifest_edit(name: &str, current: &str, target: &str) -> PlannedUpdateItem {
    item(
        name,
        current,
        Outcome::Applied {
            edit: ManifestEdit {
                range: Range::new(Position::new(0, 0), Position::new(0, 1)),
                new_text: target.to_string(),
            },
            target: ConcreteVersion::from(target),
        },
    )
}

fn run_gate() -> RegenerationGate {
    RegenerationGate::new(LockfileMode::Regenerate, DryRun::No, NetworkMode::Online)
}

async fn regenerate(
    id: EcosystemId,
    manifest: &Path,
    plan: &UpdatePlan,
    gate: RegenerationGate,
    runner: &ToolRunner,
) -> LockfileOutcome {
    let ecosystem = ecosystem(id);
    let uri = Url::from_file_path(manifest).expect("file url");
    let display_path = PathBuf::from(manifest.file_name().expect("file name"));
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

/// Like [`regenerate`], but with the retry, settlement and held-item marking of a real run.
#[cfg(unix)]
async fn regenerate_run(
    id: EcosystemId,
    manifest: &Path,
    plan: UpdatePlan,
    runner: &ToolRunner,
) -> UpdateRun {
    let original = std::fs::read_to_string(manifest).unwrap_or_default();
    regenerate_run_from(id, manifest, plan, runner, &original).await
}

/// [`regenerate_run`] with the manifest text from before the plan's edits (for plans whose edits
/// are already written to `manifest`).
#[cfg(unix)]
async fn regenerate_run_from(
    id: EcosystemId,
    manifest: &Path,
    plan: UpdatePlan,
    runner: &ToolRunner,
    original: &str,
) -> UpdateRun {
    let ecosystem = ecosystem(id);
    let uri = Url::from_file_path(manifest).expect("file url");
    let display_path = PathBuf::from(manifest.file_name().expect("file name"));
    let target = ManifestTarget {
        ecosystem: &ecosystem,
        manifest_path: manifest,
        display_path: &display_path,
        uri: &uri,
        original: super::OriginalManifest::new(original),
    };
    super::regenerate_run_with(plan, &target, run_gate(), runner).await
}

// ---------------------------------------------------------------------------------------------
// NpmPackageArg
// ---------------------------------------------------------------------------------------------

#[cfg(feature = "npm")]
#[test]
fn test_npm_package_arg_parse_accepts_plain_scoped_and_legacy_names() {
    for name in [
        "lodash",
        "left-pad",
        "@scope/pkg",
        "@babel/core",
        "JSONStream",
        "Base64",
        "a.b_c-d",
        "which-module~",
        "is-(odd)",
        "it's",
    ] {
        let parsed = NpmPackageArg::parse(name).unwrap_or_else(|_| panic!("{name:?} must parse"));
        assert_eq!(parsed.as_str(), name, "output passes through unchanged");
    }
}

#[cfg(feature = "npm")]
#[test]
fn test_npm_package_arg_parse_rejects_patterns_flags_and_malformed_shapes() {
    for name in [
        "",
        "-x",
        "--save",
        ".hidden",
        "!ms",
        "deb*",
        "a*b",
        "*",
        "a b",
        "a\tb",
        "a\nb",
        "a\0b",
        "a\u{7f}b",
        "@a/b/c",
        "@scope",
        "@/pkg",
        "@scope/",
        "a@b",
        "@a@b/c",
        "caf\u{e9}",
    ] {
        assert!(NpmPackageArg::parse(name).is_err(), "{name:?} must reject");
    }
}

#[cfg(feature = "npm")]
#[test]
fn test_npm_package_arg_parse_enforces_the_214_byte_cap() {
    assert!(NpmPackageArg::parse(&"a".repeat(214)).is_ok());
    assert!(NpmPackageArg::parse(&"a".repeat(215)).is_err());
}

// ---------------------------------------------------------------------------------------------
// Outcome::AppliedViaLockfile: wire shape, wording, exit code
// ---------------------------------------------------------------------------------------------

fn applied_via_lockfile(name: &str, target: &str) -> PlannedUpdateItem {
    item(
        name,
        "1.0.0",
        Outcome::AppliedViaLockfile {
            target: ConcreteVersion::from(target),
        },
    )
}

#[test]
fn test_applied_via_lockfile_wire_token_is_applied_and_target_is_carried() {
    let outcome = Outcome::AppliedViaLockfile {
        target: ConcreteVersion::from("1.0.1"),
    };
    assert_eq!(outcome.wire_token(), "applied");
    assert_eq!(outcome.target(), Some(&ConcreteVersion::from("1.0.1")));
}

#[test]
fn test_applied_via_lockfile_reason_says_the_lock_file_carried_the_fix() {
    let reason = applied_via_lockfile("stuba", "1.0.1").reason();
    assert!(reason.contains("lock file"), "{reason}");
    assert!(reason.contains("admits"), "{reason}");
    assert_ne!(
        reason,
        item_reason_of_manifest_edit(),
        "distinct from `Applied`"
    );
}

fn item_reason_of_manifest_edit() -> String {
    manifest_edit("stuba", "1.0.0", "1.0.1").reason()
}

fn lockfile_only_in(id: EcosystemId, name: &str) -> PlannedUpdateItem {
    let mut item = lockfile_only(name, "1.0.0", "1.0.1");
    item.lockfile_fix.ecosystem = Some(id);
    item
}

#[test]
fn test_requires_lockfile_update_reason_names_the_flag_and_only_its_ecosystems_tools() {
    let reason = lockfile_only_in(EcosystemId::Npm, "stuba").reason();

    assert!(!reason.contains("#1116"), "{reason}");
    assert!(
        reason.ends_with("--lockfile regenerate for npm, pnpm, Yarn 2+ and Bun)"),
        "{reason}"
    );
    for other in ["Cargo", "Go", "Poetry"] {
        assert!(!reason.contains(other), "{other} listed: {reason}");
    }
}

#[test]
fn test_requires_lockfile_update_reason_for_pypi_lists_pipenv_with_the_other_lockers() {
    let reason = lockfile_only_in(EcosystemId::Pypi, "stuba").reason();

    assert!(
        reason.ends_with("for uv, Poetry, PDM and Pipenv)"),
        "{reason}"
    );
}

#[test]
fn test_requires_lockfile_update_reason_omits_the_sentence_when_no_tool_can_move_the_lock() {
    for reason in [
        lockfile_only_in(EcosystemId::NuGet, "stuba").reason(),
        lockfile_only("stuba", "1.0.0", "1.0.1").reason(),
    ] {
        assert!(!reason.contains("--lockfile regenerate"), "{reason}");
        assert!(reason.ends_with("update the lock file"), "{reason}");
    }
}

#[test]
fn test_update_exit_code_applied_via_lockfile_is_clean() {
    let run = UpdateRun {
        plan: UpdatePlan {
            items: vec![applied_via_lockfile("stuba", "1.0.1")],
        },
        lockfile: LockfileOutcome::NotApplicable(NotApplicableReason::NothingApplied),
    };
    assert_eq!(update_exit_code(&run), EXIT_CLEAN);
}

#[test]
fn test_update_exit_code_requires_lockfile_update_still_violates_policy() {
    let run = UpdateRun {
        plan: UpdatePlan {
            items: vec![lockfile_only("stuba", "1.0.0", "1.0.1")],
        },
        lockfile: LockfileOutcome::Skipped(SkipCause::NotEnabled),
    };
    assert_eq!(update_exit_code(&run), EXIT_POLICY_VIOLATION);
}

#[test]
fn test_update_to_document_applied_via_lockfile_serializes_as_applied() {
    let run = UpdateRun {
        plan: UpdatePlan {
            items: vec![applied_via_lockfile("stuba", "1.0.1")],
        },
        lockfile: LockfileOutcome::NotApplicable(NotApplicableReason::NothingApplied),
    };
    let document = crate::format::json::update_to_document(&run, DryRun::No);
    let json = serde_json::to_value(&document).expect("serialize");
    let text = json.to_string();
    assert!(text.contains("\"outcome\":\"applied\""), "{text}");
    assert!(!text.contains("requires-lockfile-update"), "{text}");
}

// ---------------------------------------------------------------------------------------------
// Gate and strategy behaviour that needs no tool
// ---------------------------------------------------------------------------------------------

#[cfg(feature = "npm")]
#[tokio::test]
async fn test_regenerate_lockfile_with_skip_gate_reports_skipped_for_lockfile_only_plan() {
    let project = Project::new();
    let manifest = project.write("package.json", "{}");
    let plan = UpdatePlan {
        items: vec![lockfile_only("lodash", "4.17.20", "4.17.21")],
    };
    let runner = ToolRunner {
        deadline: Duration::from_secs(5),
        search_path: SearchPath::Inherit,
        group: ProcessGroup::Own,
    };
    for cause in [SkipCause::NotEnabled, SkipCause::DryRun, SkipCause::Offline] {
        let outcome = regenerate(
            EcosystemId::Npm,
            &manifest,
            &plan,
            RegenerationGate::Skip(cause),
            &runner,
        )
        .await;
        assert_matches!(outcome, LockfileOutcome::Skipped(c) if c == cause);
    }
}

#[cfg(feature = "pypi")]
#[tokio::test]
async fn test_regenerate_lockfile_without_a_lock_file_keeps_requires_lockfile_update() {
    let project = Project::new();
    let manifest = project.write("pyproject.toml", "[project]\nname = \"x\"\n");
    let ecosystem = ecosystem(EcosystemId::Pypi);
    let uri = Url::from_file_path(&manifest).expect("file url");
    let display = PathBuf::from("pyproject.toml");
    let original_text = std::fs::read_to_string(&manifest).unwrap_or_default();
    let target = ManifestTarget {
        ecosystem: &ecosystem,
        manifest_path: &manifest,
        display_path: &display,
        uri: &uri,
        original: super::OriginalManifest::new(&original_text),
    };
    let plan = UpdatePlan {
        items: vec![lockfile_only_in(EcosystemId::Pypi, "requests")],
    };

    let run = regenerate_lockfile(plan, &target, run_gate()).await;

    assert_matches!(
        run.plan.items[0].outcome,
        Outcome::RequiresLockfileUpdate { .. }
    );
    assert_eq!(update_exit_code(&run), EXIT_POLICY_VIOLATION);
    let reason = run.plan.items[0].reason();
    assert!(
        reason.contains(
            &super::lockfile_only_tools_text(EcosystemId::Pypi)
                .expect("some tool moves a lock file")
        ),
        "the text names exactly the tools that can move a lock file alone: {reason}"
    );
}

#[test]
fn test_cooldown_held_error_counts_the_other_held_pins_in_its_message() {
    use super::{HeldVersion, RegenerationError};

    let held = |name: &str| HeldVersion {
        package: deps_core::PackageName::new(name),
        version: ConcreteVersion::from("1.0.1"),
        target: ConcreteVersion::from("1.0.0"),
    };
    let alone = RegenerationError::CooldownHeldVersion {
        first: held("a"),
        rest: Vec::new(),
    };
    let with_two_more = RegenerationError::CooldownHeldVersion {
        first: held("a"),
        rest: vec![held("b"), held("c")],
    };

    assert!(!alone.to_string().contains("more"), "{alone}");
    assert!(
        with_two_more.to_string().ends_with(" (and 2 more)"),
        "{with_two_more}"
    );
}

#[test]
fn test_lockfile_only_move_table_pins_every_program() {
    use super::Program::{
        Bun, Bundle, Cargo, Composer, Dart, Deno, Dotnet, Flutter, Go, Gradle, Npm, Pdm, Pipenv,
        Pnpm, Poetry, Swift, Uv, Yarn,
    };
    use super::command::LockfileOnlyMove::{Refused, Supported};

    let expected = [
        (Cargo, Supported),
        (Go, Supported),
        (Npm, Supported),
        (Pnpm, Supported),
        (Yarn, Supported),
        (Uv, Supported),
        (Bundle, Supported),
        (Deno, Supported),
        (Bun, Supported),
        (Poetry, Supported),
        (Pdm, Supported),
        (Pipenv, Supported),
        (Composer, Supported),
        (Dart, Supported),
        (Flutter, Supported),
        (Dotnet, Refused),
        (Gradle, Supported),
        (Swift, Supported),
    ];

    for (program, move_kind) in expected {
        assert_eq!(program.lockfile_only_move(), move_kind, "{program}");
    }
}

#[test]
fn test_lockfile_only_tools_text_is_none_for_ecosystems_without_a_capable_tool() {
    for id in [
        EcosystemId::NuGet,
        EcosystemId::Maven,
        EcosystemId::GithubActions,
    ] {
        assert_eq!(super::lockfile_only_tools_text(id), None, "{id:?}");
    }
    assert_eq!(
        super::lockfile_only_tools_text(EcosystemId::Cargo).as_deref(),
        Some("Cargo")
    );
}

// ---------------------------------------------------------------------------------------------
// Shim tools (unix)
// ---------------------------------------------------------------------------------------------

#[cfg(unix)]
mod shim_tools {
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

        fn install(&self, name: &str, body: &str) {
            let script = format!(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\n{body}\n",
                self.log().display()
            );
            let path = self.dir.path().join(name);
            std::fs::write(&path, script).expect("write script");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        }

        fn runner(&self) -> ToolRunner {
            ToolRunner {
                deadline: Duration::from_secs(30),
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

    fn rows(outcome: &LockfileOutcome) -> Vec<(String, String, PinResolution)> {
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

    // ----- cargo -----

    const CARGO_TOML: &str = "[package]\nname = \"fx\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[workspace]\n\n[dependencies]\nstuba = \"1\"\n";

    fn cargo_lock(stuba: &str) -> String {
        format!(
            "version = 4\n\n[[package]]\nname = \"fx\"\nversion = \"0.1.0\"\ndependencies = [\n \"stuba\",\n]\n\n[[package]]\nname = \"stuba\"\nversion = \"{stuba}\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"1cfe8cbac33b06e98f6e403cac490acea6ce20d4cf11a75ac068b8c16bd3c30c\"\n"
        )
    }

    fn cargo_shim(bin: &FakeBin, manifest: &Path) {
        bin.install(
            "cargo",
            &format!(
                "if [ \"$1\" = locate-project ]; then echo '{}'; fi",
                manifest.display()
            ),
        );
    }

    #[cfg(feature = "cargo")]
    #[tokio::test]
    async fn test_regenerate_lockfile_cargo_lockfile_only_pin_skips_workspace_update() {
        let project = Project::new();
        let manifest = project.write("Cargo.toml", CARGO_TOML);
        project.write("Cargo.lock", &cargo_lock("1.0.1"));
        let bin = FakeBin::new();
        cargo_shim(&bin, &manifest);
        let plan = UpdatePlan {
            items: vec![lockfile_only("stuba", "1.0.0", "1.0.1")],
        };

        let outcome = regenerate(
            EcosystemId::Cargo,
            &manifest,
            &plan,
            run_gate(),
            &bin.runner(),
        )
        .await;

        let m = manifest.display();
        let calls = bin.calls();
        assert_eq!(
            calls,
            vec![
                format!("locate-project --workspace --message-format plain --manifest-path {m}"),
                format!("update --manifest-path {m} --package=stuba@1 --precise=1.0.1"),
            ],
            "no `update --workspace`: nothing was edited"
        );
        assert_eq!(
            rows(&outcome),
            vec![("stuba".into(), "1.0.1".into(), PinResolution::Exact)]
        );
    }

    #[cfg(feature = "cargo")]
    #[tokio::test]
    async fn test_regenerate_lockfile_cargo_lockfile_only_class_comes_from_the_locked_version() {
        let project = Project::new();
        let manifest = project.write("Cargo.toml", CARGO_TOML);
        project.write("Cargo.lock", &cargo_lock("2.0.0"));
        let bin = FakeBin::new();
        cargo_shim(&bin, &manifest);
        let plan = UpdatePlan {
            items: vec![lockfile_only("stuba", "1.0.0", "2.0.0")],
        };

        let outcome = regenerate(
            EcosystemId::Cargo,
            &manifest,
            &plan,
            run_gate(),
            &bin.runner(),
        )
        .await;

        let m = manifest.display();
        assert_eq!(
            bin.calls().last().map(String::as_str),
            Some(format!("update --manifest-path {m} --package=stuba@1 --precise=2.0.0").as_str()),
            "class is that of the locked 1.0.0, not of the 2.0.0 target"
        );
        assert_eq!(
            rows(&outcome),
            vec![("stuba".into(), "2.0.0".into(), PinResolution::Exact)]
        );
    }

    #[cfg(feature = "cargo")]
    #[tokio::test]
    async fn test_regenerate_lockfile_cargo_mixed_pins_run_workspace_update_once() {
        let project = Project::new();
        let manifest = project.write("Cargo.toml", CARGO_TOML);
        project.write("Cargo.lock", &cargo_lock("1.0.1"));
        let bin = FakeBin::new();
        cargo_shim(&bin, &manifest);
        let plan = UpdatePlan {
            items: vec![
                manifest_edit("stuba", "1.0.0", "1.0.1"),
                lockfile_only("stubb", "1.0.0", "1.0.2"),
            ],
        };

        let _ = regenerate(
            EcosystemId::Cargo,
            &manifest,
            &plan,
            run_gate(),
            &bin.runner(),
        )
        .await;

        let calls = bin.calls();
        let workspace_updates = calls
            .iter()
            .filter(|c| c.starts_with("update --workspace"))
            .count();
        assert_eq!(workspace_updates, 1, "{calls:?}");
        for package in ["stuba@1 --precise=1.0.1", "stubb@1 --precise=1.0.2"] {
            assert!(
                calls
                    .iter()
                    .any(|c| c.contains(&format!("--package={package}"))),
                "{package} missing: {calls:?}"
            );
        }
    }

    #[cfg(feature = "cargo")]
    #[tokio::test]
    async fn test_regenerate_lockfile_cargo_manifest_edit_wins_over_lockfile_only_duplicate() {
        let project = Project::new();
        let manifest = project.write("Cargo.toml", CARGO_TOML);
        project.write("Cargo.lock", &cargo_lock("1.0.1"));
        let bin = FakeBin::new();
        cargo_shim(&bin, &manifest);
        let plan = UpdatePlan {
            items: vec![
                lockfile_only("stuba", "1.0.0", "1.0.1"),
                manifest_edit("stuba", "1.0.0", "1.0.1"),
            ],
        };

        let outcome = regenerate(
            EcosystemId::Cargo,
            &manifest,
            &plan,
            run_gate(),
            &bin.runner(),
        )
        .await;

        let calls = bin.calls();
        assert_eq!(
            calls
                .iter()
                .filter(|c| c.contains("--precise=1.0.1"))
                .count(),
            1,
            "{calls:?}"
        );
        assert!(
            calls.iter().any(|c| c.starts_with("update --workspace")),
            "ManifestEdit pin keeps the workspace update: {calls:?}"
        );
        assert_eq!(rows(&outcome).len(), 1);
    }

    // ----- npm / pnpm -----

    const PACKAGE_JSON: &str = "{\n  \"name\": \"app\",\n  \"version\": \"1.0.0\",\n  \"dependencies\": {\n    \"lodash\": \"^4.17.0\",\n    \"JSONStream\": \"^1.3.0\",\n    \"@babel/core\": \"^7.0.0\"\n  }\n}\n";

    fn package_lock(lodash: &str, jsonstream: &str, babel: &str) -> String {
        let entry = |name: &str, version: &str| {
            format!(
                ",\"node_modules/{name}\":{{\"version\":\"{version}\",\"resolved\":\"https://registry.npmjs.org/{name}/-/x-{version}.tgz\"}}"
            )
        };
        format!(
            "{{\"name\":\"app\",\"version\":\"1.0.0\",\"lockfileVersion\":3,\"requires\":true,\"packages\":{{\"\":{{\"name\":\"app\",\"version\":\"1.0.0\",\"dependencies\":{{\"lodash\":\"^4.17.0\",\"JSONStream\":\"^1.3.0\",\"@babel/core\":\"^7.0.0\"}}}}{}{}{}}}}}",
            entry("lodash", lodash),
            entry("JSONStream", jsonstream),
            entry("@babel/core", babel)
        )
    }

    async fn run_npm_lockfile_only(
        client_lock: (&str, &str, &str),
        shim: &str,
    ) -> (LockfileOutcome, Vec<String>) {
        let project = Project::new();
        let manifest = project.write("package.json", PACKAGE_JSON);
        let (lock_name, before, after) = client_lock;
        project.write(lock_name, before);
        let bin = FakeBin::new();
        bin.install(shim, &format!("cat > {lock_name} <<'EOF'\n{after}\nEOF"));
        let plan = UpdatePlan {
            items: vec![
                lockfile_only("lodash", "4.17.20", "4.17.21"),
                lockfile_only("JSONStream", "1.3.4", "1.3.5"),
                lockfile_only("@babel/core", "7.0.0", "7.0.1"),
            ],
        };
        let outcome = regenerate(
            EcosystemId::Npm,
            &manifest,
            &plan,
            run_gate(),
            &bin.runner(),
        )
        .await;
        let calls = bin.calls();
        drop(project);
        (outcome, calls)
    }

    #[cfg(feature = "npm")]
    #[tokio::test]
    async fn test_regenerate_lockfile_npm_lockfile_only_pins_run_update_no_save_with_names() {
        let (outcome, calls) = run_npm_lockfile_only(
            (
                "package-lock.json",
                &package_lock("4.17.20", "1.3.4", "7.0.0"),
                &package_lock("4.17.21", "1.3.5", "7.0.1"),
            ),
            "npm",
        )
        .await;

        assert_eq!(
            calls.last().map(String::as_str),
            Some(
                "update --no-save --package-lock-only --ignore-scripts --no-audit --no-fund lodash JSONStream @babel/core"
            ),
            "{calls:?}"
        );
        assert!(
            calls.iter().all(|c| !c.contains("install lodash@")
                && !c.contains("install JSONStream@")
                && !c.contains("@4.17.21")),
            "versions are never passed to npm: {calls:?}"
        );
        assert_eq!(rows(&outcome).len(), 3, "{outcome:?}");
    }

    #[cfg(feature = "npm")]
    #[tokio::test]
    async fn test_regenerate_lockfile_npm_lockfile_only_stale_lock_is_a_mismatch() {
        let (outcome, _) = run_npm_lockfile_only(
            (
                "package-lock.json",
                &package_lock("4.17.20", "1.3.4", "7.0.0"),
                &package_lock("4.17.20", "1.3.5", "7.0.1"),
            ),
            "npm",
        )
        .await;
        assert_matches!(
            outcome,
            LockfileOutcome::Failed(super::super::RegenerationError::VersionMismatch { .. })
        );
    }

    #[cfg(feature = "npm")]
    #[tokio::test]
    async fn test_regenerate_lockfile_pnpm_lockfile_only_pins_run_update_lockfile_only() {
        let pnpm = |lodash: &str| {
            format!(
                "lockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    dependencies:\n      lodash:\n        specifier: ^4.17.0\n        version: {lodash}\n"
            )
        };
        let project = Project::new();
        let manifest = project.write(
            "package.json",
            "{\n  \"name\": \"app\",\n  \"version\": \"1.0.0\",\n  \"dependencies\": {\n    \"lodash\": \"^4.17.0\"\n  }\n}\n",
        );
        project.write("pnpm-lock.yaml", &pnpm("4.17.20"));
        let bin = FakeBin::new();
        bin.install(
            "pnpm",
            &format!("cat > pnpm-lock.yaml <<'EOF'\n{}EOF", pnpm("4.17.21")),
        );
        let plan = UpdatePlan {
            items: vec![lockfile_only("lodash", "4.17.20", "4.17.21")],
        };

        let outcome = regenerate(
            EcosystemId::Npm,
            &manifest,
            &plan,
            run_gate(),
            &bin.runner(),
        )
        .await;

        assert_eq!(
            bin.calls().last().map(String::as_str),
            Some("update --lockfile-only --no-save --ignore-scripts lodash"),
            "{:?}",
            bin.calls()
        );
        assert_eq!(
            rows(&outcome),
            vec![("lodash".into(), "4.17.21".into(), PinResolution::Exact)]
        );
        assert!(project.read("pnpm-lock.yaml").contains("4.17.21"));
    }

    #[cfg(feature = "npm")]
    #[tokio::test]
    async fn test_regenerate_lockfile_npm_unsafe_lockfile_only_name_is_rejected_before_any_update()
    {
        let project = Project::new();
        let manifest = project.write("package.json", PACKAGE_JSON);
        project.write(
            "package-lock.json",
            &package_lock("4.17.20", "1.3.4", "7.0.0"),
        );
        let bin = FakeBin::new();
        bin.install("npm", "true");
        let plan = UpdatePlan {
            items: vec![lockfile_only("!ms", "1.0.0", "1.0.1")],
        };

        let outcome = regenerate(
            EcosystemId::Npm,
            &manifest,
            &plan,
            run_gate(),
            &bin.runner(),
        )
        .await;

        assert_matches!(
            outcome,
            LockfileOutcome::Failed(super::super::RegenerationError::UnsafeArgument { .. })
        );
        assert!(
            bin.calls().iter().all(|c| !c.starts_with("update")),
            "{:?}",
            bin.calls()
        );
    }

    // ----- mixed manifest-edit and lockfile-only pins (npm, pnpm), Go -----

    fn npm_two_lock(react: &str, lodash: &str) -> String {
        let entry = |name: &str, version: &str| {
            format!(
                ",\"node_modules/{name}\":{{\"version\":\"{version}\",\"resolved\":\"https://registry.npmjs.org/{name}/-/x-{version}.tgz\"}}"
            )
        };
        format!(
            "{{\"name\":\"app\",\"version\":\"1.0.0\",\"lockfileVersion\":3,\"requires\":true,\"packages\":{{\"\":{{\"name\":\"app\",\"version\":\"1.0.0\",\"dependencies\":{{\"react\":\"^16.0.0\",\"lodash\":\"^4.17.0\"}}}}{}{}}}}}",
            entry("react", react),
            entry("lodash", lodash)
        )
    }

    const TWO_PACKAGE_JSON: &str = "{\n  \"name\": \"app\",\n  \"version\": \"1.0.0\",\n  \"dependencies\": {\n    \"react\": \"^16.0.0\",\n    \"lodash\": \"^4.17.0\"\n  }\n}\n";

    fn mixed_plan() -> UpdatePlan {
        UpdatePlan {
            items: vec![
                manifest_edit("react", "16.0.0", "16.1.0"),
                lockfile_only("lodash", "4.17.20", "4.17.21"),
            ],
        }
    }

    #[cfg(feature = "npm")]
    #[tokio::test]
    async fn test_regenerate_lockfile_npm_mixed_pins_install_then_update_naming_only_lockfile_only()
    {
        let project = Project::new();
        let manifest = project.write("package.json", TWO_PACKAGE_JSON);
        project.write("package-lock.json", &npm_two_lock("16.0.0", "4.17.20"));
        let bin = FakeBin::new();
        bin.install(
            "npm",
            &format!(
                "cat > package-lock.json <<'EOF'\n{}\nEOF",
                npm_two_lock("16.1.0", "4.17.21")
            ),
        );

        let outcome = regenerate(
            EcosystemId::Npm,
            &manifest,
            &mixed_plan(),
            run_gate(),
            &bin.runner(),
        )
        .await;

        assert_eq!(
            bin.calls(),
            vec![
                "install --package-lock-only --ignore-scripts --no-audit --no-fund".to_string(),
                "update --no-save --package-lock-only --ignore-scripts --no-audit --no-fund lodash"
                    .to_string(),
            ]
        );
        assert_eq!(
            rows(&outcome),
            vec![
                ("react".into(), "16.1.0".into(), PinResolution::Exact),
                ("lodash".into(), "4.17.21".into(), PinResolution::Exact),
            ]
        );
    }

    /// An npm shim: `install` writes the lock for the manifest edit (react 16.1.0), `update`
    /// moves lodash to `lodash_after` on top of it.
    #[cfg(feature = "npm")]
    fn two_step_npm(bin: &FakeBin, react_after_install: &str, lodash_after: &str) {
        bin.install(
            "npm",
            &format!(
                "case \"$1\" in\nupdate) cat > package-lock.json <<'EOF'\n{}\nEOF\n;;\n*) cat > package-lock.json <<'EOF'\n{}\nEOF\n;;\nesac",
                npm_two_lock(react_after_install, lodash_after),
                npm_two_lock(react_after_install, "4.17.20"),
            ),
        );
    }

    #[cfg(feature = "npm")]
    #[tokio::test]
    async fn test_regenerate_run_mixed_plan_retries_without_the_cooldown_held_lock_only_pin() {
        let project = Project::new();
        let manifest = project.write("package.json", TWO_PACKAGE_JSON);
        project.write("package-lock.json", &npm_two_lock("16.0.0", "4.17.20"));
        let bin = FakeBin::new();
        two_step_npm(&bin, "16.1.0", "4.17.22");
        let mut plan = mixed_plan();
        plan.items[1].lockfile_fix.cooldown_held = vec![ConcreteVersion::from("4.17.22")];
        plan.items[1].lockfile_fix.cooldown_window =
            Some(deps_core::CooldownWindow::from_secs(3 * 86_400));
        plan.items[1].lockfile_fix.ecosystem = Some(EcosystemId::Npm);

        let run = regenerate_run(EcosystemId::Npm, &manifest, plan, &bin.runner()).await;

        let install = "install --package-lock-only --ignore-scripts --no-audit --no-fund";
        assert_eq!(
            bin.calls(),
            vec![
                install.to_string(),
                "update --no-save --package-lock-only --ignore-scripts --no-audit --no-fund lodash"
                    .to_string(),
                install.to_string(),
            ],
            "one retry, without lodash"
        );
        assert_eq!(
            rows(&run.lockfile),
            vec![("react".into(), "16.1.0".into(), PinResolution::Exact)]
        );
        assert_eq!(
            project.read("package-lock.json").trim_end(),
            npm_two_lock("16.1.0", "4.17.20"),
            "react's bump kept, lodash left where it was"
        );
        assert_matches!(
            run.plan.items[1].outcome,
            Outcome::RequiresLockfileUpdate { .. }
        );
        assert_eq!(
            run.plan.items[1].lockfile_fix.lockfile,
            LockfileState::HeldByCooldown(ConcreteVersion::from("4.17.22"))
        );
        let reason = run.plan.items[1].reason();
        assert!(
            reason.contains("4.17.22") && reason.contains("3 days"),
            "{reason}"
        );
        assert!(!reason.contains("--lockfile regenerate"), "{reason}");
        assert_eq!(update_exit_code(&run), EXIT_POLICY_VIOLATION);
    }

    #[cfg(feature = "npm")]
    #[tokio::test]
    async fn test_regenerate_run_retry_that_holds_again_fails_after_exactly_one_retry() {
        let before = npm_two_lock("16.0.0", "4.17.20");
        let project = Project::new();
        let manifest = project.write("package.json", TWO_PACKAGE_JSON);
        project.write("package-lock.json", &before);
        let bin = FakeBin::new();
        // The first run holds lodash only; the retry, naming react alone, lands react on a
        // held version.
        bin.install(
            "npm",
            &format!(
                "if [ -f .seen ]; then cat > package-lock.json <<'EOF'\n{}\nEOF\nelse touch .seen; cat > package-lock.json <<'EOF'\n{}\nEOF\nfi",
                npm_two_lock("16.2.0", "4.17.20"),
                npm_two_lock("16.1.0", "4.17.22"),
            ),
        );
        let mut plan = UpdatePlan {
            items: vec![
                lockfile_only("react", "16.0.0", "16.1.0"),
                lockfile_only("lodash", "4.17.20", "4.17.21"),
            ],
        };
        plan.items[0].lockfile_fix.cooldown_held = vec![ConcreteVersion::from("16.2.0")];
        plan.items[1].lockfile_fix.cooldown_held = vec![ConcreteVersion::from("4.17.22")];

        let run = regenerate_run(EcosystemId::Npm, &manifest, plan, &bin.runner()).await;

        assert_eq!(bin.calls().len(), 2, "exactly one retry: {:?}", bin.calls());
        assert_matches!(
            &run.lockfile,
            LockfileOutcome::Failed(super::super::RegenerationError::CooldownHeldVersion {
                first,
                rest,
            }) if first.package.as_str() == "react" && rest.is_empty()
        );
        assert_eq!(project.read("package-lock.json"), before);
        assert_eq!(update_exit_code(&run), EXIT_EXECUTION_ERROR);
    }

    #[cfg(feature = "npm")]
    #[tokio::test]
    async fn test_regenerate_run_held_edit_is_not_withheld_when_the_manifest_changed_during_the_run()
     {
        let before = npm_two_lock("16.0.0", "4.17.20");
        let project = Project::new();
        let manifest = project.write("package.json", TWO_PACKAGE_JSON);
        project.write("package-lock.json", &before);
        let bin = FakeBin::new();
        two_step_npm(&bin, "16.2.0", "4.17.21");
        let mut plan = mixed_plan();
        plan.items[0].lockfile_fix.cooldown_held = vec![ConcreteVersion::from("16.2.0")];

        let run = regenerate_run(EcosystemId::Npm, &manifest, plan, &bin.runner()).await;

        assert_eq!(bin.calls().len(), 2, "no retry: {:?}", bin.calls());
        assert_matches!(
            &run.lockfile,
            LockfileOutcome::Failed(super::super::RegenerationError::CooldownHeldVersion {
                first,
                ..
            }) if first.package.as_str() == "react"
        );
        assert_eq!(project.read("package-lock.json"), before);
        assert_eq!(update_exit_code(&run), EXIT_EXECUTION_ERROR);
    }

    /// An npm shim for a held manifest-edit pin: `install` locks react 16.2.0 (inside the window),
    /// the first `update` moves lodash on top of it, and the retry's `update` (the manifest
    /// without react's edit) leaves react at 16.0.0.
    #[cfg(feature = "npm")]
    fn npm_react_held_on_install(bin: &FakeBin) {
        bin.install(
            "npm",
            &format!(
                "case \"$1\" in\ninstall) cat > package-lock.json <<'EOF'\n{}\nEOF\n;;\nupdate) if [ -f .seen ]; then cat > package-lock.json <<'EOF'\n{}\nEOF\nelse touch .seen; cat > package-lock.json <<'EOF'\n{}\nEOF\nfi;;\nesac",
                npm_two_lock("16.2.0", "4.17.20"),
                npm_two_lock("16.0.0", "4.17.21"),
                npm_two_lock("16.2.0", "4.17.21"),
            ),
        );
    }

    #[cfg(feature = "npm")]
    fn react_edit_and_lodash_lock_only() -> UpdatePlan {
        let mut plan = UpdatePlan {
            items: vec![
                real_edit(
                    TWO_PACKAGE_JSON,
                    "react",
                    ("16.0.0", "16.1.0"),
                    ("^16.0.0", "^16.1.0"),
                ),
                lockfile_only("lodash", "4.17.20", "4.17.21"),
            ],
        };
        plan.items[0].lockfile_fix.cooldown_held = vec![ConcreteVersion::from("16.2.0")];
        plan.items[0].lockfile_fix.cooldown_window =
            Some(deps_core::CooldownWindow::from_secs(3 * 86_400));
        plan
    }

    #[cfg(feature = "npm")]
    #[tokio::test]
    async fn test_regenerate_run_held_manifest_edit_pin_is_withheld_and_the_manifest_written_back()
    {
        let project = Project::new();
        let plan = react_edit_and_lodash_lock_only();
        let edited = crate::update::planned_manifest(&plan, TWO_PACKAGE_JSON);
        assert_ne!(edited, TWO_PACKAGE_JSON);
        let manifest = project.write("package.json", &edited);
        project.write("package-lock.json", &npm_two_lock("16.0.0", "4.17.20"));
        let bin = FakeBin::new();
        npm_react_held_on_install(&bin);

        let run = regenerate_run_from(
            EcosystemId::Npm,
            &manifest,
            plan,
            &bin.runner(),
            TWO_PACKAGE_JSON,
        )
        .await;

        assert_eq!(
            project.read("package.json"),
            TWO_PACKAGE_JSON,
            "react's edit is gone from the manifest"
        );
        assert_eq!(
            project.read("package-lock.json").trim_end(),
            npm_two_lock("16.0.0", "4.17.21"),
            "the lock matches the manifest: lodash moved, react untouched"
        );
        assert_eq!(
            rows(&run.lockfile),
            vec![("lodash".into(), "4.17.21".into(), PinResolution::Exact)]
        );
        assert_matches!(
            &run.plan.items[0].outcome,
            Outcome::Unfixable(crate::update::UnfixableReason::ResolvesWithinCooldown { target, .. })
                if target.as_str() == "16.1.0"
        );
        assert_matches!(
            &run.plan.items[1].outcome,
            Outcome::AppliedViaLockfile { target } if target.as_str() == "4.17.21"
        );
        let reason = run.plan.items[0].reason();
        assert!(
            reason.contains("16.2.0") && reason.contains("3 days"),
            "{reason}"
        );
        assert_eq!(update_exit_code(&run), EXIT_POLICY_VIOLATION);
    }

    #[cfg(feature = "npm")]
    #[tokio::test]
    async fn test_regenerate_run_withholds_only_the_held_target_of_a_package_pinned_twice() {
        let project = Project::new();
        let manifest = project.write("package.json", TWO_PACKAGE_JSON);
        project.write("package-lock.json", &npm_two_lock("16.0.0", "4.17.20"));
        let bin = FakeBin::new();
        bin.install(
            "npm",
            &format!(
                "cat > package-lock.json <<'EOF'\n{}\nEOF",
                npm_two_lock("16.0.0", "4.17.22")
            ),
        );
        let mut held = lockfile_only("lodash", "4.17.20", "4.17.21");
        held.lockfile_fix.cooldown_held = vec![ConcreteVersion::from("4.17.22")];
        let plan = UpdatePlan {
            items: vec![held, lockfile_only("lodash", "4.17.20", "4.17.22")],
        };

        let run = regenerate_run(EcosystemId::Npm, &manifest, plan, &bin.runner()).await;

        assert_eq!(
            bin.calls().len(),
            2,
            "the other target is retried: {:?}",
            bin.calls()
        );
        assert_eq!(
            rows(&run.lockfile),
            vec![("lodash".into(), "4.17.22".into(), PinResolution::Exact)]
        );
        assert_eq!(
            run.plan.items[0].lockfile_fix.lockfile,
            LockfileState::HeldByCooldown(ConcreteVersion::from("4.17.22"))
        );
        assert_matches!(
            &run.plan.items[1].outcome,
            Outcome::AppliedViaLockfile { target } if target.as_str() == "4.17.22"
        );
    }

    /// `plan` written to a fresh project (manifest edited, lock at the old versions), regenerated
    /// with the original text known; returns the project, the run and the fake `npm`.
    #[cfg(feature = "npm")]
    async fn run_withheld(plan: UpdatePlan, lodash_after: &str) -> (Project, UpdateRun, FakeBin) {
        let project = Project::new();
        let edited = crate::update::planned_manifest(&plan, TWO_PACKAGE_JSON);
        let manifest = project.write("package.json", &edited);
        project.write("package-lock.json", &npm_two_lock("16.0.0", "4.17.20"));
        let bin = FakeBin::new();
        two_step_npm(&bin, "16.2.0", lodash_after);
        let run = regenerate_run_from(
            EcosystemId::Npm,
            &manifest,
            plan,
            &bin.runner(),
            TWO_PACKAGE_JSON,
        )
        .await;
        (project, run, bin)
    }

    #[cfg(feature = "npm")]
    #[tokio::test]
    async fn test_regenerate_run_lone_held_manifest_edit_is_withheld_without_rerunning_the_tool() {
        let mut plan = react_edit_and_lodash_lock_only();
        plan.items.truncate(1);

        let (project, run, bin) = run_withheld(plan, "4.17.20").await;

        assert_eq!(bin.calls().len(), 1, "no rerun: {:?}", bin.calls());
        assert_eq!(project.read("package.json"), TWO_PACKAGE_JSON);
        assert_eq!(
            project.read("package-lock.json"),
            npm_two_lock("16.0.0", "4.17.20"),
            "the lock is restored"
        );
        assert_matches!(
            run.lockfile,
            LockfileOutcome::NotApplicable(
                super::super::NotApplicableReason::AllWithheldByCooldown
            )
        );
        assert_matches!(
            &run.plan.items[0].outcome,
            Outcome::Unfixable(crate::update::UnfixableReason::ResolvesWithinCooldown {
                target,
                resolved,
            }) if target.as_str() == "16.1.0" && resolved.as_str() == "16.2.0"
        );
        assert_eq!(update_exit_code(&run), EXIT_POLICY_VIOLATION);
    }

    #[cfg(feature = "npm")]
    #[tokio::test]
    async fn test_regenerate_run_every_pin_held_withholds_all_and_leaves_manifest_and_lock_alone() {
        let mut plan = react_edit_and_lodash_lock_only();
        plan.items[1].lockfile_fix.cooldown_held = vec![ConcreteVersion::from("4.17.22")];

        let (project, run, bin) = run_withheld(plan, "4.17.22").await;

        assert_eq!(bin.calls().len(), 2, "no rerun: {:?}", bin.calls());

        assert_eq!(project.read("package.json"), TWO_PACKAGE_JSON);
        assert_eq!(
            project.read("package-lock.json"),
            npm_two_lock("16.0.0", "4.17.20")
        );
        assert_matches!(
            &run.plan.items[0].outcome,
            Outcome::Unfixable(crate::update::UnfixableReason::ResolvesWithinCooldown { .. })
        );
        assert_matches!(
            &run.plan.items[1].outcome,
            Outcome::RequiresLockfileUpdate { .. }
        );
        assert_eq!(
            run.plan.items[1].lockfile_fix.lockfile,
            LockfileState::HeldByCooldown(ConcreteVersion::from("4.17.22"))
        );
        assert_eq!(update_exit_code(&run), EXIT_POLICY_VIOLATION);
    }

    #[cfg(feature = "nuget")]
    const CSPROJ: &str = "<Project Sdk=\"Microsoft.NET.Sdk\">\n  <ItemGroup>\n    <PackageReference Include=\"Newtonsoft.Json\" Version=\"13.0.1\" />\n    <PackageReference Include=\"Serilog\" Version=\"2.10.0\" />\n  </ItemGroup>\n</Project>\n";

    #[cfg(feature = "nuget")]
    fn nuget_lock(newtonsoft: &str, serilog: &str) -> String {
        let entry = |name: &str, version: &str| {
            format!(
                "      \"{name}\": {{\n        \"type\": \"Direct\",\n        \"requested\": \"[{version}, )\",\n        \"resolved\": \"{version}\",\n        \"contentHash\": \"abc\"\n      }}"
            )
        };
        format!(
            "{{\n  \"version\": 1,\n  \"dependencies\": {{\n    \"net8.0\": {{\n{},\n{}\n    }}\n  }}\n}}\n",
            entry("Newtonsoft.Json", newtonsoft),
            entry("Serilog", serilog)
        )
    }

    #[cfg(feature = "nuget")]
    #[tokio::test]
    async fn test_regenerate_lockfile_nuget_lock_only_plan_is_refused_before_any_tool_runs() {
        let project = Project::new();
        let manifest = project.write("App.csproj", CSPROJ);
        project.write("packages.lock.json", &nuget_lock("13.0.1", "2.10.0"));
        let bin = FakeBin::new();
        bin.install("dotnet", "exit 0");
        let plan = UpdatePlan {
            items: vec![lockfile_only("Serilog", "2.10.0", "2.12.0")],
        };

        let outcome = regenerate(
            EcosystemId::NuGet,
            &manifest,
            &plan,
            run_gate(),
            &bin.runner(),
        )
        .await;

        assert_matches!(
            outcome,
            LockfileOutcome::Unsupported {
                reason: super::super::UnsupportedReason::LockfileOnlyUpdateUnsupported(
                    super::super::Program::Dotnet
                ),
                ..
            }
        );
        assert!(bin.calls().is_empty(), "{:?}", bin.calls());
    }

    #[cfg(feature = "nuget")]
    #[tokio::test]
    async fn test_regenerate_lockfile_nuget_mixed_plan_restores_for_the_edit_pins_only() {
        let project = Project::new();
        let manifest = project.write("App.csproj", CSPROJ);
        project.write("packages.lock.json", &nuget_lock("13.0.1", "2.10.0"));
        let bin = FakeBin::new();
        bin.install(
            "dotnet",
            &format!(
                "cat > packages.lock.json <<'EOF'\n{}EOF",
                nuget_lock("13.0.3", "2.10.0")
            ),
        );
        let plan = UpdatePlan {
            items: vec![
                manifest_edit("Newtonsoft.Json", "13.0.1", "13.0.3"),
                lockfile_only("Serilog", "2.10.0", "2.12.0"),
            ],
        };

        let outcome = regenerate(
            EcosystemId::NuGet,
            &manifest,
            &plan,
            run_gate(),
            &bin.runner(),
        )
        .await;

        assert_eq!(
            rows(&outcome),
            vec![(
                "Newtonsoft.Json".into(),
                "13.0.3".into(),
                PinResolution::Exact
            )]
        );
    }

    #[cfg(feature = "pypi")]
    fn pipfile_lock(version: &str) -> String {
        format!(
            "{{\"_meta\": {{\"pipfile-spec\": 6}}, \"default\": {{\"requests\": {{\"version\": \"=={version}\"}}}}, \"develop\": {{}}}}\n"
        )
    }

    /// Runs a lock-only Pipenv pin to 2.31.0 whose tool locks 2.31.1, with `held` inside the
    /// window; returns the outcome and whether the lock file is back to its original bytes.
    #[cfg(feature = "pypi")]
    async fn run_pipenv_lock_only(held: &str) -> (LockfileOutcome, bool) {
        let before = pipfile_lock("2.0.0");
        let project = Project::new();
        let manifest = project.write("Pipfile", "[packages]\nrequests = \">=2.0\"\n");
        project.write("Pipfile.lock", &before);
        let bin = FakeBin::new();
        bin.install(
            "pipenv",
            &format!("cat > Pipfile.lock <<'EOF'\n{}EOF", pipfile_lock("2.31.1")),
        );
        let mut item = lockfile_only("requests", "2.0.0", "2.31.0");
        item.lockfile_fix.cooldown_held = vec![ConcreteVersion::from(held)];
        let plan = UpdatePlan { items: vec![item] };

        let outcome = regenerate(
            EcosystemId::Pypi,
            &manifest,
            &plan,
            run_gate(),
            &bin.runner(),
        )
        .await;
        (outcome, project.read("Pipfile.lock") == before)
    }

    #[cfg(feature = "pypi")]
    #[tokio::test]
    async fn test_regenerate_lockfile_pipenv_lock_only_pin_on_a_held_version_restores_the_lock() {
        let (outcome, restored) = run_pipenv_lock_only("2.31.1").await;

        assert_matches!(
            outcome,
            LockfileOutcome::NotApplicable(
                super::super::NotApplicableReason::AllWithheldByCooldown
            )
        );
        assert!(restored);
    }

    #[cfg(feature = "pypi")]
    #[tokio::test]
    async fn test_regenerate_lockfile_pipenv_held_version_is_matched_under_pep_440_normalization() {
        let (outcome, restored) = run_pipenv_lock_only("2.31.1.0").await;

        assert_matches!(
            outcome,
            LockfileOutcome::NotApplicable(
                super::super::NotApplicableReason::AllWithheldByCooldown
            )
        );
        assert!(restored);
    }

    #[cfg(feature = "pypi")]
    #[tokio::test]
    async fn test_regenerate_lockfile_pipenv_newer_version_outside_the_held_set_is_kept() {
        let (outcome, restored) = run_pipenv_lock_only("2.32.0").await;

        assert_matches!(
            &outcome,
            LockfileOutcome::Regenerated { pins, .. }
                if matches!(&pins[0].resolution, PinResolution::Newer(version) if version.as_str() == "2.31.1")
        );
        assert!(!restored);
    }

    #[cfg(feature = "npm")]
    #[tokio::test]
    async fn test_regenerate_lockfile_npm_mixed_pins_stale_lockfile_only_pin_is_a_mismatch() {
        let project = Project::new();
        let manifest = project.write("package.json", TWO_PACKAGE_JSON);
        project.write("package-lock.json", &npm_two_lock("16.0.0", "4.17.20"));
        let bin = FakeBin::new();
        bin.install(
            "npm",
            &format!(
                "cat > package-lock.json <<'EOF'\n{}\nEOF",
                npm_two_lock("16.1.0", "4.17.20")
            ),
        );

        let outcome = regenerate(
            EcosystemId::Npm,
            &manifest,
            &mixed_plan(),
            run_gate(),
            &bin.runner(),
        )
        .await;

        assert_matches!(
            outcome,
            LockfileOutcome::Failed(super::super::RegenerationError::VersionMismatch { .. })
        );
    }

    #[cfg(feature = "npm")]
    #[tokio::test]
    async fn test_regenerate_lockfile_pnpm_mixed_pins_install_then_update_naming_only_lockfile_only()
     {
        let pnpm = |react: &str, lodash: &str| {
            format!(
                "lockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    dependencies:\n      lodash:\n        specifier: ^4.17.0\n        version: {lodash}\n      react:\n        specifier: ^16.0.0\n        version: {react}\n"
            )
        };
        let project = Project::new();
        let manifest = project.write("package.json", TWO_PACKAGE_JSON);
        project.write("pnpm-lock.yaml", &pnpm("16.0.0", "4.17.20"));
        let bin = FakeBin::new();
        bin.install(
            "pnpm",
            &format!(
                "cat > pnpm-lock.yaml <<'EOF'\n{}EOF",
                pnpm("16.1.0", "4.17.21")
            ),
        );

        let outcome = regenerate(
            EcosystemId::Npm,
            &manifest,
            &mixed_plan(),
            run_gate(),
            &bin.runner(),
        )
        .await;

        assert_eq!(
            bin.calls(),
            vec![
                "install --lockfile-only --ignore-scripts --no-frozen-lockfile".to_string(),
                "update --lockfile-only --no-save --ignore-scripts lodash".to_string(),
            ]
        );
        assert_eq!(
            rows(&outcome),
            vec![
                ("react".into(), "16.1.0".into(), PinResolution::Exact),
                ("lodash".into(), "4.17.21".into(), PinResolution::Exact),
            ]
        );
    }

    #[cfg(feature = "go")]
    const GO_MOD: &str = "module example.com/app\n\ngo 1.21\n\nrequire (\n\tgolang.org/x/net v0.20.0\n\tgolang.org/x/text v0.30.0\n)\n";
    #[cfg(feature = "go")]
    const GO_SUM_AFTER: &str = "golang.org/x/net v0.21.0 h1:net=\ngolang.org/x/net v0.21.0/go.mod h1:netmod=\ngolang.org/x/text v0.31.0 h1:text=\ngolang.org/x/text v0.31.0/go.mod h1:textmod=\n";

    #[cfg(feature = "go")]
    async fn run_go(plan: &UpdatePlan, sum_after: &str) -> (LockfileOutcome, Vec<String>) {
        let project = Project::new();
        let manifest = project.write("go.mod", GO_MOD);
        project.write(
            "go.sum",
            "golang.org/x/net v0.20.0 h1:old=\ngolang.org/x/text v0.30.0 h1:old=\n",
        );
        let bin = FakeBin::new();
        bin.install(
            "go",
            &format!(
                "if [ \"$1\" = env ]; then echo; exit 0; fi\ncat > go.sum <<'EOF'\n{sum_after}EOF"
            ),
        );
        let outcome = regenerate(EcosystemId::Go, &manifest, plan, run_gate(), &bin.runner()).await;
        (outcome, bin.calls())
    }

    #[cfg(feature = "go")]
    #[tokio::test]
    async fn test_regenerate_lockfile_go_lockfile_only_pin_shares_the_go_get_list() {
        let plan = UpdatePlan {
            items: vec![
                manifest_edit("golang.org/x/text", "v0.30.0", "v0.31.0"),
                lockfile_only("golang.org/x/net", "v0.20.0", "v0.21.0"),
            ],
        };

        let (outcome, calls) = run_go(&plan, GO_SUM_AFTER).await;

        assert_eq!(
            calls,
            vec![
                "env GOWORK".to_string(),
                "get -- golang.org/x/text@v0.31.0 golang.org/x/net@v0.21.0".to_string(),
            ],
            "one `go get` for both origins"
        );
        assert_eq!(
            rows(&outcome),
            vec![
                (
                    "golang.org/x/text".into(),
                    "v0.31.0".into(),
                    PinResolution::Exact
                ),
                (
                    "golang.org/x/net".into(),
                    "v0.21.0".into(),
                    PinResolution::Exact
                ),
            ]
        );
    }

    #[cfg(feature = "go")]
    #[tokio::test]
    async fn test_regenerate_lockfile_go_only_lockfile_only_pins_still_run_go_get() {
        let plan = UpdatePlan {
            items: vec![lockfile_only("golang.org/x/net", "v0.20.0", "v0.21.0")],
        };

        let (outcome, calls) = run_go(&plan, GO_SUM_AFTER).await;

        assert_eq!(
            calls.last().map(String::as_str),
            Some("get -- golang.org/x/net@v0.21.0")
        );
        assert_eq!(
            rows(&outcome),
            vec![(
                "golang.org/x/net".into(),
                "v0.21.0".into(),
                PinResolution::Exact
            )]
        );
    }
}

// ---------------------------------------------------------------------------------------------
// Real cargo, offline local registry: settlement through the public entry point
// ---------------------------------------------------------------------------------------------

#[cfg(feature = "cargo")]
mod cargo_real {
    use super::*;

    fn registry_path() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/cargo-local-registry")
    }

    const LOCKED: &str = "[package]\nname = \"fx\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[workspace]\n\n[dependencies]\nstuba = \"=1.0.0\"\n";
    const CARET: &str = "[package]\nname = \"fx\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[workspace]\n\n[dependencies]\nstuba = \"1\"\nstubb = \"1\"\n";

    fn project() -> (Project, PathBuf) {
        let project = Project::new();
        project.write(
            ".cargo/config.toml",
            &format!(
                "[net]\noffline = true\n\n[source.crates-io]\nreplace-with = \"lr\"\n\n[source.lr]\nlocal-registry = '{}'\n",
                registry_path().display()
            ),
        );
        project.write("src/lib.rs", "");
        let manifest = project.write(
            "Cargo.toml",
            &LOCKED.replace("[dependencies]\n", "[dependencies]\nstubb = \"=1.0.0\"\n"),
        );
        let status = std::process::Command::new("cargo")
            .args(["generate-lockfile", "--manifest-path"])
            .arg(&manifest)
            .current_dir(&project.root)
            .status()
            .expect("run cargo generate-lockfile");
        assert!(status.success());
        project.write("Cargo.toml", CARET);
        (project, manifest)
    }

    fn lock_has(lock: &str, name: &str, version: &str) -> bool {
        lock.contains(&format!("name = \"{name}\"\nversion = \"{version}\""))
    }

    #[cfg(feature = "cargo")]
    #[tokio::test]
    async fn test_regenerate_lockfile_cargo_caret_range_fix_settles_as_applied_via_lockfile() {
        let (project, manifest) = project();
        let before = project.read("Cargo.toml");
        let ecosystem = ecosystem(EcosystemId::Cargo);
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
        let plan = UpdatePlan {
            items: vec![lockfile_only("stuba", "1.0.0", "1.0.1")],
        };

        let run = regenerate_lockfile(plan, &target, run_gate()).await;

        assert_matches!(
            run.lockfile,
            LockfileOutcome::Regenerated { .. },
            "{:?}",
            run.lockfile
        );
        assert_matches!(
            &run.plan.items[0].outcome,
            Outcome::AppliedViaLockfile { target } if target.as_str() == "1.0.1"
        );
        assert_eq!(update_exit_code(&run), EXIT_CLEAN);
        let lock = project.read("Cargo.lock");
        assert!(lock_has(&lock, "stuba", "1.0.1"), "{lock}");
        assert!(
            lock_has(&lock, "stubb", "1.0.0"),
            "untouched sibling: {lock}"
        );
        assert_eq!(project.read("Cargo.toml"), before, "manifest never edited");
    }

    #[cfg(feature = "cargo")]
    #[tokio::test]
    async fn test_regenerate_lockfile_cargo_mixed_plan_settles_only_lockfile_only_items() {
        let (project, manifest) = project();
        let ecosystem = ecosystem(EcosystemId::Cargo);
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
        let plan = UpdatePlan {
            items: vec![
                manifest_edit("stubb", "1.0.0", "1.0.2"),
                lockfile_only("stuba", "1.0.0", "1.0.1"),
            ],
        };

        let run = regenerate_lockfile(plan, &target, run_gate()).await;

        assert_matches!(run.plan.items[0].outcome, Outcome::Applied { .. });
        assert_matches!(
            run.plan.items[1].outcome,
            Outcome::AppliedViaLockfile { .. }
        );
        let lock = project.read("Cargo.lock");
        assert!(lock_has(&lock, "stuba", "1.0.1"), "{lock}");
        assert!(lock_has(&lock, "stubb", "1.0.2"), "{lock}");
    }
}

/// Security M1: only a lock file holding exactly the fix target settles a lock-file-only item;
/// a newer in-range version was never checked against advisories.
#[cfg(unix)]
mod newer_in_range {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    const MANIFEST: &str =
        "{\"name\":\"app\",\"version\":\"1.0.0\",\"dependencies\":{\"lodash\":\"^4.17.0\"}}";

    fn lock(lodash: &str) -> String {
        format!(
            "{{\"name\":\"app\",\"version\":\"1.0.0\",\"lockfileVersion\":3,\"requires\":true,\"packages\":{{\"\":{{\"name\":\"app\",\"version\":\"1.0.0\",\"dependencies\":{{\"lodash\":\"^4.17.0\"}}}},\"node_modules/lodash\":{{\"version\":\"{lodash}\",\"resolved\":\"https://registry.npmjs.org/lodash/-/lodash-{lodash}.tgz\"}}}}}}"
        )
    }

    /// Runs the regeneration with an npm shim that rewrites the lock to `after`, then settles.
    async fn settle_with_lock_after_update(
        after: &str,
        affected: Vec<AffectedRanges>,
    ) -> UpdateRun {
        settle_with_cooldown_held(after, affected, vec![]).await
    }

    async fn settle_with_cooldown_held(
        after: &str,
        affected: Vec<AffectedRanges>,
        cooldown_held: Vec<ConcreteVersion>,
    ) -> UpdateRun {
        let project = Project::new();
        let manifest = project.write("package.json", MANIFEST);
        project.write("package-lock.json", &lock("4.17.20"));
        let bin = tempfile::tempdir().expect("bin dir");
        let npm = bin.path().join("npm");
        std::fs::write(
            &npm,
            format!(
                "#!/bin/sh\ncat > package-lock.json <<'EOF'\n{}\nEOF\n",
                lock(after)
            ),
        )
        .expect("write shim");
        std::fs::set_permissions(&npm, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        let runner = ToolRunner {
            deadline: Duration::from_secs(30),
            search_path: SearchPath::Override(bin.path().as_os_str().to_owned()),
            group: ProcessGroup::Own,
        };
        let mut item = lockfile_only("lodash", "4.17.20", "4.17.21");
        item.lockfile_fix.affected = affected;
        item.lockfile_fix.cooldown_held = cooldown_held;
        regenerate_run(
            EcosystemId::Npm,
            &manifest,
            UpdatePlan { items: vec![item] },
            &runner,
        )
        .await
    }

    /// Fixed in 4.17.21, re-introduced from 4.18.0 up to a fix in 4.18.5.
    fn ranges() -> AffectedRanges {
        AffectedRanges::from_affected_json_for_test(
            OsvPackageName::new("lodash").expect("name"),
            OsvEcosystem::Npm,
            r#"[{"package":{"name":"lodash","ecosystem":"npm"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.17.21"},{"introduced":"4.18.0"},{"fixed":"4.18.5"}]}]}]"#,
        ).expect("valid affected JSON")
    }

    fn assert_stays_unsettled_at(run: &UpdateRun, version: &str) {
        assert_matches!(
            run.plan.items[0].outcome,
            Outcome::RequiresLockfileUpdate { .. }
        );
        assert_eq!(
            run.plan.items[0].lockfile_fix.lockfile,
            LockfileState::MovedTo(ConcreteVersion::from(version))
        );
        assert_eq!(update_exit_code(run), EXIT_POLICY_VIOLATION);
        assert!(
            run.plan.items[0].reason().contains("review it manually"),
            "{}",
            run.plan.items[0].reason()
        );
    }

    #[cfg(feature = "npm")]
    #[tokio::test]
    async fn test_settle_npm_newer_version_without_captured_ranges_stays_unsettled() {
        let run = settle_with_lock_after_update("4.17.22", vec![]).await;

        assert_matches!(
            &run.lockfile,
            LockfileOutcome::Regenerated { pins, .. }
                if matches!(pins[0].resolution, PinResolution::Newer(_))
        );
        assert_stays_unsettled_at(&run, "4.17.22");
    }

    #[cfg(feature = "npm")]
    #[tokio::test]
    async fn test_settle_npm_newer_version_inside_a_later_affected_range_stays_unsettled() {
        let run = settle_with_lock_after_update("4.18.1", vec![ranges()]).await;

        assert_stays_unsettled_at(&run, "4.18.1");
    }

    #[cfg(feature = "npm")]
    #[tokio::test]
    async fn test_settle_npm_newer_version_outside_every_affected_range_becomes_applied() {
        let run = settle_with_lock_after_update("4.17.22", vec![ranges()]).await;

        assert_matches!(
            &run.lockfile,
            LockfileOutcome::Regenerated { pins, .. }
                if matches!(pins[0].resolution, PinResolution::Newer(_))
        );
        assert_matches!(
            &run.plan.items[0].outcome,
            Outcome::AppliedViaLockfile { target } if target.as_str() == "4.17.22"
        );
        assert_eq!(update_exit_code(&run), EXIT_CLEAN);
    }

    #[cfg(feature = "npm")]
    #[tokio::test]
    async fn test_regenerate_npm_lone_lock_only_pin_inside_the_cooldown_window_stays_unsettled_with_exit_1()
     {
        let run = settle_with_cooldown_held(
            "4.17.22",
            vec![ranges()],
            vec![ConcreteVersion::from("4.17.22")],
        )
        .await;

        assert_matches!(
            &run.lockfile,
            LockfileOutcome::NotApplicable(
                super::super::NotApplicableReason::AllWithheldByCooldown
            )
        );
        assert_matches!(
            run.plan.items[0].outcome,
            Outcome::RequiresLockfileUpdate { .. }
        );
        assert_eq!(
            run.plan.items[0].lockfile_fix.lockfile,
            LockfileState::HeldByCooldown(ConcreteVersion::from("4.17.22"))
        );
        assert!(
            !run.plan.items[0].reason().contains("--lockfile regenerate"),
            "{}",
            run.plan.items[0].reason()
        );
        assert_eq!(update_exit_code(&run), EXIT_POLICY_VIOLATION);
    }

    #[cfg(feature = "npm")]
    #[tokio::test]
    async fn test_settle_npm_newer_version_outside_the_cooldown_window_still_becomes_applied() {
        let run = settle_with_cooldown_held(
            "4.17.22",
            vec![ranges()],
            vec![ConcreteVersion::from("4.17.23")],
        )
        .await;

        assert_matches!(
            &run.plan.items[0].outcome,
            Outcome::AppliedViaLockfile { target } if target.as_str() == "4.17.22"
        );
    }

    #[cfg(feature = "npm")]
    #[tokio::test]
    async fn test_settle_npm_exact_target_inside_the_cooldown_window_still_becomes_applied() {
        let run = settle_with_cooldown_held(
            "4.17.21",
            vec![ranges()],
            vec![ConcreteVersion::from("4.17.21")],
        )
        .await;

        assert_matches!(
            &run.plan.items[0].outcome,
            Outcome::AppliedViaLockfile { target } if target.as_str() == "4.17.21"
        );
    }

    #[cfg(feature = "npm")]
    #[tokio::test]
    async fn test_settle_npm_newer_version_with_one_undecidable_range_set_stays_unsettled() {
        let undecidable = AffectedRanges::from_affected_json_for_test(
            OsvPackageName::new("lodash").expect("name"),
            OsvEcosystem::Npm,
            r#"[{"package":{"name":"lodash","ecosystem":"npm"},"ranges":[{"type":"GIT","events":[{"introduced":"0"}]}]}]"#,
        ).expect("valid affected JSON");
        let run = settle_with_lock_after_update("4.17.22", vec![ranges(), undecidable]).await;

        assert_stays_unsettled_at(&run, "4.17.22");
    }

    #[cfg(feature = "npm")]
    #[tokio::test]
    async fn test_settle_npm_lock_resolving_exactly_the_target_becomes_applied_via_lockfile() {
        let run = settle_with_lock_after_update("4.17.21", vec![]).await;

        assert_matches!(
            run.plan.items[0].outcome,
            Outcome::AppliedViaLockfile { .. }
        );
        assert_eq!(update_exit_code(&run), EXIT_CLEAN);
    }

    #[cfg(feature = "npm")]
    #[test]
    fn test_settle_records_the_moved_lockfile_only_on_requires_lockfile_update_items() {
        let skipped = item(
            "lodash",
            "4.17.20",
            Outcome::Skipped {
                reason: crate::update::SkipReason::NotRequested,
                target: Some(ConcreteVersion::from("4.17.21")),
            },
        );
        let mut plan = UpdatePlan {
            items: vec![
                manifest_edit("lodash", "4.17.20", "4.17.21"),
                skipped,
                lockfile_only("lodash", "4.17.20", "4.17.21"),
            ],
        };
        let newer = |version: &str| super::super::PinReport {
            package: deps_core::PackageName::new("lodash"),
            target: ConcreteVersion::from("4.17.21"),
            resolution: PinResolution::Newer(ConcreteVersion::from(version)),
        };
        let outcome = LockfileOutcome::Regenerated {
            lockfile: super::super::DisplayLockPath {
                shown: PathBuf::from("package-lock.json"),
                real: PathBuf::from("package-lock.json"),
            },
            tool: super::super::Program::Npm,
            pins: vec![newer("4.18.1")],
            companions: Vec::new(),
        };

        super::super::settle_lockfile_only(
            &mut plan,
            &outcome,
            ecosystem(EcosystemId::Npm).formatter(),
        );

        assert_eq!(
            plan.items[0].lockfile_fix,
            crate::update::LockfileFix::default()
        );
        assert_eq!(
            plan.items[1].lockfile_fix,
            crate::update::LockfileFix::default()
        );
        assert_eq!(
            plan.items[2].lockfile_fix.lockfile,
            LockfileState::MovedTo(ConcreteVersion::from("4.18.1"))
        );
    }
}

#[cfg(feature = "npm")]
#[test]
fn test_npm_package_arg_parse_rejects_non_registry_specs_and_non_url_safe_characters() {
    for spec in [
        "file:x",
        "file:../x",
        "npm:lodash",
        "git+https://example.com/x.git",
        "github:user/repo",
        "https://example.com/x.tgz",
        "user/repo",
        "a:b",
        "a%20b",
        "a,b",
        "a;b",
        "a|b",
        "a$b",
        "a`b",
        "a\\b",
        "a<b>",
        "a#b",
        "a?b",
        "a=b",
        "a+b",
    ] {
        assert!(NpmPackageArg::parse(spec).is_err(), "{spec:?} must reject");
    }
}
