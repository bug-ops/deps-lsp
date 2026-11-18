//! Shared harness for the `--lockfile regenerate` acceptance tests (#2071, #2046, #2047).
//!
//! `regenerate_lockfile` resolves tools through the inherited `PATH`, so a test cannot inject fake
//! tools in-process without `unsafe`. Each scenario therefore re-executes the current test binary
//! (`regen_child`, an `#[ignore]`d test that is only meaningful when driven from here) with `PATH`
//! pointing at a directory of shell-script fakes, and reads the child's printed outcome.
//!
//! Included with `#[path = "common/regen_harness.rs"] mod harness;` by each acceptance file,
//! which also declares the `regen_child` test calling [`regen_child_main`].

#![allow(dead_code, clippy::expect_used, clippy::panic)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

pub(crate) const OUTCOME_OPEN: &str = "OUTCOME<<";
pub(crate) const OUTCOME_CLOSE: &str = ">>";

/// One scenario: project files, fake tools, and the update to regenerate for.
pub(crate) struct Case<'a> {
    pub(crate) ecosystem: &'a str,
    /// Manifest path relative to the project root.
    pub(crate) manifest: &'a str,
    /// `(relative path, bytes)` written before the run, manifest included.
    pub(crate) files: Vec<(&'a str, Vec<u8>)>,
    /// `(tool name, shell body)`; `ROOT` in a body is replaced by the project root.
    pub(crate) tools: Vec<(&'a str, &'a str)>,
    /// `edit` (manifest bump applied first) or `lockonly` (`RequiresLockfileUpdate`).
    pub(crate) mode: &'a str,
    /// `name|anchor|from|to|current|target`, one per line.
    pub(crate) bumps: &'a str,
    pub(crate) cooldown_fallback: bool,
    pub(crate) unlistened: bool,
}

pub(crate) struct Ran {
    pub(crate) root: PathBuf,
    /// The child's `Debug` rendering of the `LockfileOutcome`.
    pub(crate) outcome: String,
    /// One entry per fake-tool call: `tool argv|cwd|selected env`.
    pub(crate) calls: Vec<String>,
    _keep: Project,
}

impl Ran {
    pub(crate) fn read(&self, rel: &str) -> Vec<u8> {
        std::fs::read(self.root.join(rel)).expect("read project file")
    }

    pub(crate) fn calls_of(&self, tool: &str) -> Vec<&String> {
        let prefix = format!("{tool} ");
        self.calls
            .iter()
            .filter(|call| call.starts_with(&prefix))
            .collect()
    }
}

pub(crate) struct Project {
    pub(crate) root: PathBuf,
    pub(crate) bin: PathBuf,
    _dir: tempfile::TempDir,
}

impl Project {
    pub(crate) fn new() -> Self {
        let dir = tempfile::tempdir().expect("temp dir");
        let base = dir.path().canonicalize().expect("canonical");
        let root = base.join("project");
        let bin = base.join("bin");
        std::fs::create_dir_all(&root).expect("project dir");
        std::fs::create_dir_all(&bin).expect("bin dir");
        Self {
            root,
            bin,
            _dir: dir,
        }
    }

    pub(crate) fn write(&self, rel: &str, content: &[u8]) {
        let path = self.root.join(rel);
        std::fs::create_dir_all(path.parent().expect("parent")).expect("dirs");
        std::fs::write(path, content).expect("write");
    }

    pub(crate) fn log(&self) -> PathBuf {
        self.bin.join("calls.log")
    }

    pub(crate) fn install(&self, name: &str, body: &str) {
        let body = body.replace("ROOT", &self.root.display().to_string());
        let script = format!(
            "#!/bin/sh\nprintf '%s %s|%s|%s\\n' '{name}' \"$*\" \"$(pwd)\" \"$(env | grep -E '^(GOWORK|COREPACK_ENABLE_[A-Z_]+|YARN_ENABLE_[A-Z_]+)=' | sort | tr '\\n' ' ')\" >> '{}'\n{body}\n",
            self.log().display()
        );
        let path = self.bin.join(name);
        std::fs::write(&path, script).expect("script");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    }

    pub(crate) fn calls(&self) -> Vec<String> {
        std::fs::read_to_string(self.log())
            .map(|log| log.lines().map(str::to_owned).collect())
            .unwrap_or_default()
    }

    pub(crate) fn child(&self, case: &Case<'_>) -> Command {
        let path = format!(
            "{}:{}",
            self.bin.display(),
            std::env::var("PATH").unwrap_or_default()
        );
        let mut command = Command::new(std::env::current_exe().expect("test binary"));
        command
            .args(["--exact", "regen_child", "--ignored", "--nocapture"])
            .env("PATH", path)
            .env_remove("GOWORK")
            .env_remove("COREPACK_ENABLE_AUTO_PIN")
            .env_remove("COREPACK_ENABLE_DOWNLOAD_PROMPT")
            .env_remove("COREPACK_ENABLE_STRICT")
            .env_remove("YARN_ENABLE_IMMUTABLE_INSTALLS")
            .env_remove("YARN_ENABLE_SCRIPTS")
            .env("REGEN_DIR", &self.root)
            .env("REGEN_ECO", case.ecosystem)
            .env("REGEN_MANIFEST", case.manifest)
            .env("REGEN_MODE", case.mode)
            .env("REGEN_BUMPS", case.bumps)
            .env(
                "REGEN_COOLDOWN",
                if case.cooldown_fallback { "1" } else { "0" },
            )
            .env("REGEN_UNLISTENED", if case.unlistened { "1" } else { "0" })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command
    }
}

pub(crate) fn outcome_of(stdout: &str) -> String {
    let (_, rest) = stdout
        .split_once(OUTCOME_OPEN)
        .unwrap_or_else(|| panic!("no outcome in: {stdout}"));
    let (outcome, _) = rest.split_once(OUTCOME_CLOSE).expect("outcome end");
    outcome.to_owned()
}

pub(crate) fn prepare(case: &Case<'_>) -> Project {
    let project = Project::new();
    for (rel, bytes) in &case.files {
        project.write(rel, bytes);
    }
    for (name, body) in &case.tools {
        project.install(name, body);
    }
    project
}

pub(crate) fn run(case: &Case<'_>) -> Ran {
    let project = prepare(case);
    let output = project.child(case).output().expect("run the child test");
    assert!(
        output.status.success(),
        "child failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ran {
        outcome: outcome_of(&String::from_utf8_lossy(&output.stdout)),
        calls: project.calls(),
        root: project.root.clone(),
        _keep: project,
    }
}

/// Body of the `regen_child` test every including file declares:
/// `#[tokio::test] #[ignore = "..."] async fn regen_child() { harness::regen_child_main().await }`.
pub(crate) async fn regen_child_main() {
    use std::str::FromStr;
    use std::sync::Arc;

    use deps_cli::format::DryRun;
    use deps_cli::update::regen::{
        LockfileMode, ManifestTarget, RegenerationGate, regenerate_lockfile,
        regenerate_lockfile_unlistened,
    };
    use deps_cli::update::{
        CooldownFallbackNote, CurrentVersion, Outcome, PlannedUpdateItem, UpdatePlan, apply_plan,
    };
    use deps_core::edit::ManifestEdit;
    use deps_core::net_policy::{MapEnv, RegistryEnvironment};
    use deps_core::policy_config::PolicyConfig;
    use deps_core::position::{Position, Range};
    use deps_core::{ConcreteVersion, EcosystemId, EcosystemRegistry, HttpCache, NetworkMode};
    use deps_engine::setup::{EcosystemRuntime, register_ecosystems};

    let root = PathBuf::from(env("REGEN_DIR"));
    let manifest = root.join(env("REGEN_MANIFEST"));
    let id = EcosystemId::from_str(&env("REGEN_ECO")).expect("ecosystem id");
    let lock_only = env("REGEN_MODE") == "lockonly";
    let fallback = env("REGEN_COOLDOWN") == "1";
    let content = std::fs::read_to_string(&manifest).expect("manifest");

    let items = env("REGEN_BUMPS")
        .lines()
        .map(|line| {
            let mut fields = line.split('|');
            let mut next = || fields.next().expect("bump field");
            let (name, anchor, from, to, current, target) =
                (next(), next(), next(), next(), next(), next());
            let outcome = if lock_only {
                Outcome::RequiresLockfileUpdate {
                    target: ConcreteVersion::from(target),
                }
            } else {
                let (line_no, text) = content
                    .lines()
                    .enumerate()
                    .find(|(_, text)| text.contains(anchor))
                    .expect("anchor line");
                let anchor_at = text.find(anchor).expect("anchor");
                let start = text
                    .match_indices(from)
                    .map(|(index, _)| index)
                    .find(|index| *index >= anchor_at)
                    .expect("from text");
                let line_no = u32::try_from(line_no).expect("line");
                let start = u32::try_from(start).expect("col");
                let end = start + u32::try_from(from.len()).expect("len");
                Outcome::Applied {
                    edit: ManifestEdit {
                        range: Range::new(
                            Position::new(line_no, start),
                            Position::new(line_no, end),
                        ),
                        new_text: to.to_owned(),
                    },
                    target: ConcreteVersion::from(target),
                }
            };
            PlannedUpdateItem::new(
                name.to_owned(),
                CurrentVersion::Resolved(ConcreteVersion::from(current)),
                outcome,
                vec![],
                false,
                None,
                fallback.then(|| {
                    CooldownFallbackNote::AppliedInsteadOf(ConcreteVersion::from("99.0.0"))
                }),
            )
        })
        .collect();
    let plan = UpdatePlan { items };
    if !lock_only {
        apply_plan(&plan, &manifest, &content, DryRun::No).expect("apply the plan");
    }

    let runtime = EcosystemRuntime::from_policy(
        &PolicyConfig::default(),
        &RegistryEnvironment::read(&MapEnv::new()),
    );
    let cache = Arc::new(HttpCache::with_policy(Arc::clone(&runtime.policy)));
    let registry = EcosystemRegistry::new();
    let _ = register_ecosystems(&registry, cache, &runtime);
    let ecosystem = registry.get(id).expect("ecosystem registered");
    let uri = url::Url::from_file_path(&manifest).expect("uri");
    let display = PathBuf::from(env("REGEN_MANIFEST"));
    let target = ManifestTarget {
        ecosystem: &ecosystem,
        manifest_path: &manifest,
        display_path: &display,
        uri: &uri,
    };
    let gate = RegenerationGate::new(LockfileMode::Regenerate, DryRun::No, NetworkMode::Online);
    let run = if env("REGEN_UNLISTENED") == "1" {
        regenerate_lockfile_unlistened(plan, &target, gate, &root).await
    } else {
        regenerate_lockfile(plan, &target, gate).await
    };
    println!("{OUTCOME_OPEN}{:?}{OUTCOME_CLOSE}", run.lockfile);
}

pub(crate) fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} not set"))
}

pub(crate) fn exists(path: &Path) -> bool {
    path.exists()
}
