//! Opt-in lockfile regeneration after `deps-cli update` edits a manifest (#1116).
//!
//! The planner and [`super::apply_plan`] only rewrite the manifest; this module asks the
//! ecosystem's own tool (`cargo`, `npm`, `pnpm`, `go`) to bring the lockfile in line, then
//! verifies the fresh lockfile against the applied pins. Every outcome, failures included, is
//! a [`LockfileOutcome`] value so the plan report is always printed.

mod command;
mod interrupt;
#[cfg(all(test, unix))]
mod leader_state_tests;
#[cfg(test)]
mod lockfile_only_tests;
#[cfg(all(test, unix))]
mod process_group_tests;
mod run;
#[cfg(test)]
mod tests;

use std::fmt;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use deps_core::lockfile::LockFileCache;
use deps_core::lsp_helpers::{EcosystemFormatter, RequirementGate};
use deps_core::osv::AffectsVersion;
use deps_core::{
    ConcreteVersion, Ecosystem, EcosystemId, NetworkMode, NormalizeName, NormalizedName,
    PackageName, VersionReq,
};
use deps_engine::classify::resolved::{LockfileLoad, load_resolved_versions};
use tokio::time::Instant;
use url::Url;

use command::{ArgComponent, Invocation, NpmPackageArg, compat_class};
pub use command::{NpmClient, Program};
pub(in crate::update) use interrupt::Interrupts;
pub(in crate::update) use run::{ChildGuard, ProcessGroup};
use run::{SearchPath, ToolRunner};

use super::{CooldownFallbackNote, CurrentVersion, LockfileState, Outcome, UpdatePlan, UpdateRun};
use crate::format::DryRun;

/// Shared time budget for every probe and tool call of one regeneration.
const TOOL_BUDGET: Duration = Duration::from_mins(5);

/// Whether `update` should regenerate the lockfile (`--lockfile`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum LockfileMode {
    /// Leave the lockfile alone (default).
    #[default]
    Skip,
    /// Run the ecosystem's tool to regenerate the lockfile after the manifest edit.
    Regenerate,
}

/// Why regeneration was not attempted although the plan applied edits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipCause {
    /// `--lockfile regenerate` was not passed.
    NotEnabled,
    /// `--dry-run`: no manifest edit was written, so there is nothing to regenerate.
    DryRun,
    /// Offline mode forbids the tool's registry traffic.
    Offline,
}

/// Whether the regeneration may run, decided once from the run's flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegenerationGate {
    /// Regeneration may proceed.
    Run,
    /// Regeneration is skipped for the stated cause.
    Skip(SkipCause),
}

impl RegenerationGate {
    /// Combines the flags with precedence `NotEnabled` > `DryRun` > `Offline`.
    #[must_use]
    pub const fn new(mode: LockfileMode, dry_run: DryRun, network: NetworkMode) -> Self {
        match (mode, dry_run, network) {
            (LockfileMode::Skip, _, _) => Self::Skip(SkipCause::NotEnabled),
            (LockfileMode::Regenerate, DryRun::Yes, _) => Self::Skip(SkipCause::DryRun),
            (LockfileMode::Regenerate, DryRun::No, NetworkMode::Offline) => {
                Self::Skip(SkipCause::Offline)
            }
            (LockfileMode::Regenerate, DryRun::No, NetworkMode::Online) => Self::Run,
        }
    }
}

/// The manifest an `update` run edited, with everything regeneration needs to locate and
/// verify its lockfile.
#[derive(Clone, Copy)]
pub struct ManifestTarget<'a> {
    /// The ecosystem that parsed the manifest.
    pub ecosystem: &'a Arc<dyn Ecosystem>,
    /// Real path of the manifest; the working directory of every spawned tool is its parent.
    pub manifest_path: &'a Path,
    /// The path shown to the user, never absolute unless the user passed an absolute path.
    pub display_path: &'a Path,
    /// `file://` URI of [`Self::manifest_path`].
    pub uri: &'a Url,
}

/// The lockfile path as shown to the user, relative to the manifest's display directory
/// (`Cargo.lock`, `../Cargo.lock`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisplayLockPath(PathBuf);

impl DisplayLockPath {
    /// The lock file's own name (`Cargo.lock`), without any directory part.
    ///
    /// A regeneration only runs for a lock file beside the manifest, so `--open-pr` stages the
    /// file under the manifest's directory by this name.
    #[must_use]
    pub fn file_name(&self) -> Option<&std::ffi::OsStr> {
        self.0.file_name()
    }

    /// Builds a display path for fixtures that stand in for a regeneration result.
    #[cfg(all(test, unix))]
    pub(in crate::update) fn for_test(path: &str) -> Self {
        Self(PathBuf::from(path))
    }
}

impl fmt::Display for DisplayLockPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.display().fmt(f)
    }
}

/// How a pin's target compares with the version the regenerated lockfile holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinResolution {
    /// The lockfile holds exactly the target.
    Exact,
    /// The lockfile holds a newer version that still satisfies the edited requirement.
    Newer(ConcreteVersion),
}

/// One applied update and the verified lockfile result for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinReport {
    /// The updated package.
    pub package: PackageName,
    /// The version the plan applied.
    pub target: ConcreteVersion,
    /// What the regenerated lockfile holds.
    pub resolution: PinResolution,
}

/// Why there was nothing to regenerate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotApplicableReason {
    /// The plan applied no edit.
    NothingApplied,
    /// The ecosystem has no lockfile format.
    NoLockfileFormat,
    /// No lockfile exists for this manifest, and none is ever created.
    NoLockfilePresent,
}

/// Why regeneration is not supported for this manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnsupportedReason {
    /// The ecosystem has a lockfile but regeneration is not implemented for it yet.
    EcosystemDeferred(EcosystemId),
    /// The lockfile belongs to a JavaScript client that is not supported yet.
    NpmClientDeferred(NpmClient),
    /// The manifest may be a workspace member: its lockfile is in an ancestor directory, an
    /// ancestor declares a workspace, or the pnpm workspace directory is set via the environment.
    WorkspaceMemberLockfile,
    /// The located lockfile is not the one the tool would update.
    LockfileOwnershipMismatch,
    /// The Go module vendors its dependencies.
    GoVendored,
    /// A Go workspace is active, so checksums would land in `go.work.sum`.
    GoWorkspace,
    /// A target chosen by the cooldown fallback cannot be pinned by range resolution.
    CooldownFallbackTarget,
    /// The lockfile is a symlink or not a regular file, so the tool would rewrite elsewhere.
    LockfileSymlink,
}

/// Why a regeneration that started did not produce a verified lockfile.
#[derive(Debug, thiserror::Error)]
pub enum RegenerationError {
    /// The tool is not installed or not on `PATH`.
    #[error("{program} was not found on PATH")]
    ToolchainMissing {
        /// The missing tool.
        program: Program,
    },
    /// The tool could not be started.
    #[error("failed to start {program}: {source}")]
    Spawn {
        /// The tool that failed to start.
        program: Program,
        /// The underlying I/O error.
        source: std::io::Error,
    },
    /// SIGINT or SIGTERM arrived while the tool was running.
    #[error("regeneration was interrupted")]
    Interrupted,
    /// The shared time budget ran out.
    #[error("regeneration timed out after {:.1}s", after.as_secs_f64())]
    TimedOut {
        /// The exhausted budget.
        after: Duration,
    },
    /// The tool exited unsuccessfully.
    #[error("{program} {}", exit_description(*code))]
    ToolFailed {
        /// The failing tool.
        program: Program,
        /// Its exit code, `None` when killed by a signal.
        code: Option<i32>,
    },
    /// A probe printed more than the cap or non-UTF-8 output.
    #[error("{program} printed unexpected probe output")]
    UnexpectedProbeOutput {
        /// The probed tool.
        program: Program,
    },
    /// A package name or version is unsafe to pass on a command line.
    #[error("refusing to pass an unsafe argument for package {package}")]
    UnsafeArgument {
        /// The offending package, sanitized for display.
        package: String,
    },
    /// The located lockfile's name matches no known client.
    #[error("unrecognized lockfile {}", path.display())]
    UnrecognizedLockfile {
        /// The lockfile's display path.
        path: PathBuf,
    },
    /// The edited manifest could not be re-parsed for verification.
    #[error("could not re-parse {}", path.display())]
    ManifestReparseFailed {
        /// The manifest's display path.
        path: PathBuf,
    },
    /// The regenerated lockfile could not be read for verification.
    #[error("could not read the regenerated lockfile {}", path.display())]
    LockfileUnreadable {
        /// The lockfile's display path.
        path: PathBuf,
    },
    /// The regenerated lockfile does not hold the applied target.
    #[error(
        "lockfile does not resolve {} to {expected} (found {})",
        package.as_str(),
        found.as_ref().map_or("none", ConcreteVersion::as_str)
    )]
    VersionMismatch {
        /// The package whose pin failed verification.
        package: PackageName,
        /// The version the plan applied.
        expected: ConcreteVersion,
        /// The lockfile's version for the package, if any.
        found: Option<ConcreteVersion>,
    },
}

fn exit_description(code: Option<i32>) -> String {
    code.map_or_else(
        || "terminated by a signal".to_owned(),
        |code| format!("exited with status {code}"),
    )
}

/// The result of the lockfile step of an `update` run.
#[derive(Debug)]
pub enum LockfileOutcome {
    /// The lockfile was regenerated and every pin verified against it.
    Regenerated {
        /// The lockfile that was updated.
        lockfile: DisplayLockPath,
        /// The tool that updated it.
        tool: Program,
        /// One entry per applied pin.
        pins: Vec<PinReport>,
    },
    /// Regeneration was gated off.
    Skipped(SkipCause),
    /// There was nothing to regenerate.
    NotApplicable(NotApplicableReason),
    /// Regeneration is not supported for this manifest.
    Unsupported {
        /// The lockfile found, if any.
        lockfile: Option<DisplayLockPath>,
        /// Why it is unsupported.
        reason: UnsupportedReason,
    },
    /// Regeneration started and failed.
    Failed(RegenerationError),
}

impl fmt::Display for SkipCause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotEnabled => "not enabled (pass --lockfile regenerate)",
            Self::DryRun => "dry run",
            Self::Offline => "offline",
        })
    }
}

impl fmt::Display for NotApplicableReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NothingApplied => "no update was applied",
            Self::NoLockfileFormat => "this ecosystem has no lockfile format",
            Self::NoLockfilePresent => "no lockfile present",
        })
    }
}

impl fmt::Display for UnsupportedReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EcosystemDeferred(id) => {
                write!(f, "regeneration is not supported for {} yet", id.id())
            }
            Self::NpmClientDeferred(client) => {
                write!(
                    f,
                    "regeneration is not supported for {} yet",
                    client.as_str()
                )
            }
            Self::WorkspaceMemberLockfile => {
                f.write_str(
                    "the manifest may belong to a workspace (the lockfile is in an ancestor directory, an \
ancestor declares a workspace, or the workspace directory is set through the environment)",
                )
            }
            Self::LockfileOwnershipMismatch => {
                f.write_str("the lockfile is not the one the tool would update")
            }
            Self::GoVendored => f.write_str("the Go module vendors its dependencies"),
            Self::GoWorkspace => f.write_str("a Go workspace is active"),
            Self::CooldownFallbackTarget => {
                f.write_str("a cooldown-fallback target cannot be pinned by range resolution")
            }
            Self::LockfileSymlink => f.write_str("the lockfile is a symlink or not a regular file"),
        }
    }
}

/// How regeneration treats an ecosystem; exhaustive over [`EcosystemId`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Strategy {
    NoLockfileFormat,
    Cargo,
    NpmFamily,
    Go,
    Deferred,
}

const fn strategy(id: EcosystemId) -> Strategy {
    match id {
        EcosystemId::GithubActions
        | EcosystemId::GitlabCi
        | EcosystemId::PreCommit
        | EcosystemId::Maven => Strategy::NoLockfileFormat,
        EcosystemId::Cargo => Strategy::Cargo,
        EcosystemId::Npm => Strategy::NpmFamily,
        EcosystemId::Go => Strategy::Go,
        EcosystemId::Pypi
        | EcosystemId::Bundler
        | EcosystemId::Dart
        | EcosystemId::Composer
        | EcosystemId::Gradle
        | EcosystemId::Swift
        | EcosystemId::NuGet
        | EcosystemId::Deno => Strategy::Deferred,
    }
}

/// Whether regeneration is implemented for an ecosystem, decided from its identity alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockfileSupport {
    /// A tool regenerates the lock file (Cargo, npm family, Go).
    Regenerates,
    /// The ecosystem has no lock file format, so there is nothing to regenerate.
    NoLockfileFormat,
    /// The ecosystem has a lock file but regeneration is not implemented for it yet.
    Deferred,
}

/// How [`regenerate_lockfile`] treats `id`, known before anything is analyzed or written.
///
/// # Examples
///
/// ```
/// use deps_cli::update::regen::{LockfileSupport, lockfile_support};
/// use deps_core::EcosystemId;
///
/// assert_eq!(lockfile_support(EcosystemId::Cargo), LockfileSupport::Regenerates);
/// assert_eq!(lockfile_support(EcosystemId::Pypi), LockfileSupport::Deferred);
/// ```
#[must_use]
pub const fn lockfile_support(id: EcosystemId) -> LockfileSupport {
    match strategy(id) {
        Strategy::Cargo | Strategy::NpmFamily | Strategy::Go => LockfileSupport::Regenerates,
        Strategy::NoLockfileFormat => LockfileSupport::NoLockfileFormat,
        Strategy::Deferred => LockfileSupport::Deferred,
    }
}

/// How a pin is proven against the regenerated lockfile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PinCheck {
    /// The lockfile holds exactly the target (cargo, go).
    ExactInLock,
    /// The lockfile holds a version that satisfies the edited requirement and is at least the
    /// target (npm, pnpm).
    SatisfiesInLock,
}

/// Where a pin's fix comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
enum PinOrigin {
    /// The plan edited the manifest.
    ManifestEdit,
    /// The declared requirement already admits the target; only the lock file moves.
    LockfileOnly {
        /// The version the lock file held before, when the plan resolved it.
        locked: Option<ConcreteVersion>,
    },
}

/// One update to verify, deduplicated by `(normalized, target)`.
struct LockPin {
    package: PackageName,
    normalized: NormalizedName,
    target: ConcreteVersion,
    cooldown_fallback: bool,
    origin: PinOrigin,
}

impl LockPin {
    /// The version whose caret class `cargo update --package` addresses.
    fn compat_basis(&self) -> &ConcreteVersion {
        match &self.origin {
            PinOrigin::LockfileOnly {
                locked: Some(locked),
            } => locked,
            PinOrigin::ManifestEdit | PinOrigin::LockfileOnly { locked: None } => &self.target,
        }
    }

    const fn is_lockfile_only(&self) -> bool {
        matches!(self.origin, PinOrigin::LockfileOnly { .. })
    }
}

fn collect_pins(plan: &UpdatePlan, formatter: &dyn EcosystemFormatter) -> Vec<LockPin> {
    let mut pins: Vec<LockPin> = Vec::new();
    for item in &plan.items {
        let (target, origin) = match &item.outcome {
            Outcome::Applied { target, .. } => (target, PinOrigin::ManifestEdit),
            Outcome::RequiresLockfileUpdate { target } => (
                target,
                PinOrigin::LockfileOnly {
                    locked: match &item.current {
                        CurrentVersion::Resolved(version) => Some(version.clone()),
                        CurrentVersion::Declared(_) | CurrentVersion::Unknown => None,
                    },
                },
            ),
            _ => continue,
        };
        let package = PackageName::new(item.name.as_str());
        let normalized = formatter.normalize_package_name(&package);
        if let Some(existing) = pins
            .iter_mut()
            .find(|pin| pin.normalized == normalized && pin.target == *target)
        {
            if origin == PinOrigin::ManifestEdit {
                existing.origin = origin;
            }
            continue;
        }
        pins.push(LockPin {
            package,
            normalized,
            target: target.clone(),
            cooldown_fallback: matches!(
                item.cooldown_fallback,
                Some(CooldownFallbackNote::AppliedInsteadOf(_))
            ),
            origin,
        });
    }
    pins
}

/// Regenerates the lockfile for the manifest `plan` was applied to, using the inherited `PATH`,
/// and settles every `RequiresLockfileUpdate` item the regenerated lockfile now satisfies into
/// `AppliedViaLockfile`.
///
/// Never panics and never writes a file itself; a failure is a [`LockfileOutcome`] variant.
pub async fn regenerate_lockfile(
    plan: UpdatePlan,
    target: &ManifestTarget<'_>,
    gate: RegenerationGate,
) -> UpdateRun {
    let interrupt = interrupt_listener(&plan, target, gate);
    regenerate_with_interrupt(plan, target, gate, interrupt).await
}

/// Like [`regenerate_lockfile`], but installs no signal listener of its own.
///
/// For a caller that already drops this future on SIGINT/SIGTERM (`--open-pr`'s
/// [`PrSignals`](super::pr::PrSignals)): two competing listeners would make an interrupt end
/// either as a dropped phase or as a `failed` lock file outcome, depending on which fired first.
/// The dropped future still terminates the tool's process tree through the child guards.
pub async fn regenerate_lockfile_unlistened(
    plan: UpdatePlan,
    target: &ManifestTarget<'_>,
    gate: RegenerationGate,
) -> UpdateRun {
    regenerate_with_interrupt(plan, target, gate, std::future::pending()).await
}

async fn regenerate_with_interrupt(
    plan: UpdatePlan,
    target: &ManifestTarget<'_>,
    gate: RegenerationGate,
    interrupt: impl Future<Output = ()>,
) -> UpdateRun {
    let runner = ToolRunner {
        deadline: TOOL_BUDGET,
        search_path: SearchPath::Inherit,
        group: ProcessGroup::detect(),
    };
    let lockfile = regenerate_until(&plan, target, gate, &runner, interrupt).await;
    let mut plan = plan;
    settle_lockfile_only(&mut plan, &lockfile, target.ecosystem.formatter());
    UpdateRun { plan, lockfile }
}

/// Installs the signal handlers right before the first spawn, when the gate is `Run` and there
/// is at least one pin.
///
/// This is decided before the strategy is known, so handlers are also installed for runs that
/// end up spawning nothing (deferred ecosystems, a missing lock file); the signals are then
/// swallowed for the rest of the short-lived process. Under `--open-pr`,
/// [`PrSignals`](super::pr::PrSignals) owns the only listener and regeneration runs through
/// [`regenerate_lockfile_unlistened`].
///
/// The returned future resolves on the first SIGINT/SIGTERM and never when no handler could be
/// installed (the previous behaviour: the signal kills deps-cli itself).
fn interrupt_listener(
    plan: &UpdatePlan,
    target: &ManifestTarget<'_>,
    gate: RegenerationGate,
) -> impl Future<Output = ()> + use<> {
    let will_spawn = gate == RegenerationGate::Run
        && !collect_pins(plan, target.ecosystem.formatter()).is_empty();
    let interrupts = will_spawn
        .then(Interrupts::install)
        .and_then(|installed| match installed {
            Ok(interrupts) => Some(interrupts),
            Err(error) => {
                tracing::warn!(%error, "could not install signal handlers for the lockfile tool");
                None
            }
        });
    async move {
        match interrupts {
            Some(mut interrupts) => interrupts.recv().await,
            None => std::future::pending().await,
        }
    }
}

/// Turns each `RequiresLockfileUpdate` item whose regenerated lockfile holds the fix target, or
/// a newer version provably outside every advisory's affected ranges, into `AppliedViaLockfile`.
///
/// A newer in-range version (npm and pnpm always pick the newest) is settled only when every
/// captured advisory range says it is unaffected; anything else, including missing or
/// undecidable ranges, keeps the item `RequiresLockfileUpdate` (exit 1) and records where the
/// lock file now stands.
fn settle_lockfile_only(
    plan: &mut UpdatePlan,
    lockfile: &LockfileOutcome,
    formatter: &dyn EcosystemFormatter,
) {
    let LockfileOutcome::Regenerated { pins, .. } = lockfile else {
        return;
    };
    for item in &mut plan.items {
        let Outcome::RequiresLockfileUpdate { target } = &item.outcome else {
            continue;
        };
        let name = formatter.normalize_package_name(&PackageName::new(item.name.as_str()));
        let Some(resolution) = pins.iter().find_map(|pin| {
            (pin.target == *target && formatter.normalize_package_name(&pin.package) == name)
                .then_some(&pin.resolution)
        }) else {
            continue;
        };
        match resolution {
            PinResolution::Exact => {
                item.outcome = Outcome::AppliedViaLockfile {
                    target: target.clone(),
                };
            }
            PinResolution::Newer(version) if outside_affected_ranges(item, version, formatter) => {
                item.outcome = Outcome::AppliedViaLockfile {
                    target: version.clone(),
                };
            }
            PinResolution::Newer(version) => {
                item.lockfile_fix.lockfile = LockfileState::MovedTo(version.clone());
            }
        }
    }
}

/// Whether the item captured at least one advisory range set and every one of them places
/// `version` outside its affected ranges.
fn outside_affected_ranges(
    item: &super::PlannedUpdateItem,
    version: &ConcreteVersion,
    formatter: &dyn EcosystemFormatter,
) -> bool {
    let osv_version = formatter.osv_version(version);
    !item.lockfile_fix.affected.is_empty()
        && item
            .lockfile_fix
            .affected
            .iter()
            .all(|ranges| ranges.affects(&osv_version) == AffectsVersion::No)
}

#[cfg(test)]
async fn regenerate_lockfile_with(
    plan: &UpdatePlan,
    target: &ManifestTarget<'_>,
    gate: RegenerationGate,
    runner: &ToolRunner,
) -> LockfileOutcome {
    regenerate_until(plan, target, gate, runner, std::future::pending()).await
}

/// Regenerates like [`regenerate_lockfile`], but abandons the run when `interrupt` resolves: dropping
/// the session fires every child guard, so the tool's process tree is killed.
async fn regenerate_until(
    plan: &UpdatePlan,
    target: &ManifestTarget<'_>,
    gate: RegenerationGate,
    runner: &ToolRunner,
    interrupt: impl Future<Output = ()>,
) -> LockfileOutcome {
    let pins = collect_pins(plan, target.ecosystem.formatter());
    if pins.is_empty() {
        return LockfileOutcome::NotApplicable(NotApplicableReason::NothingApplied);
    }
    if let RegenerationGate::Skip(cause) = gate {
        return LockfileOutcome::Skipped(cause);
    }
    let session = Session {
        target,
        runner,
        deadline: Instant::now() + runner.deadline,
        pins: &pins,
        manifest_dir: target
            .manifest_path
            .parent()
            .unwrap_or_else(|| Path::new("")),
    };
    tokio::select! {
        result = session.execute() => result.unwrap_or_else(LockfileOutcome::Failed),
        () = interrupt => LockfileOutcome::Failed(RegenerationError::Interrupted),
    }
}

/// The state of one regeneration: the target, the shared deadline and the pins to verify.
struct Session<'a> {
    target: &'a ManifestTarget<'a>,
    runner: &'a ToolRunner,
    deadline: Instant,
    pins: &'a [LockPin],
    manifest_dir: &'a Path,
}

impl Session<'_> {
    async fn execute(&self) -> Result<LockfileOutcome, RegenerationError> {
        let id = self.target.ecosystem.ecosystem_id();
        match strategy(id) {
            Strategy::NoLockfileFormat => Ok(LockfileOutcome::NotApplicable(
                NotApplicableReason::NoLockfileFormat,
            )),
            Strategy::Deferred => Ok(unsupported(None, UnsupportedReason::EcosystemDeferred(id))),
            Strategy::Cargo => self.cargo().await,
            Strategy::NpmFamily => self.npm_family().await,
            Strategy::Go => self.go().await,
        }
    }

    async fn cargo(&self) -> Result<LockfileOutcome, RegenerationError> {
        let manifest = self.target.manifest_path;
        let probe = Invocation::cargo_locate_workspace(self.manifest_dir, manifest);
        let root_manifest = self.runner.probe(&probe, self.deadline).await?;
        let root_dir = (!root_manifest.is_empty())
            .then(|| self.manifest_dir.join(&root_manifest))
            .and_then(|path| path.parent().map(Path::to_path_buf))
            .ok_or(RegenerationError::UnexpectedProbeOutput {
                program: Program::Cargo,
            })?;
        let owned = root_dir.join("Cargo.lock");
        if !owned.is_file() {
            return Ok(LockfileOutcome::NotApplicable(
                NotApplicableReason::NoLockfilePresent,
            ));
        }
        if let Some(outcome) = self.ownership_refusal(&owned).await? {
            return Ok(outcome);
        }

        let mut updates = Vec::with_capacity(self.pins.len());
        for pin in self.pins {
            let class = compat_class(pin.compat_basis()).ok_or_else(|| unsafe_argument(pin))?;
            let (name, version) = arg_pair(pin)?;
            updates.push(Invocation::cargo_update_precise(
                self.manifest_dir,
                manifest,
                &name,
                &class,
                &version,
            ));
        }

        if self.pins.iter().any(|pin| !pin.is_lockfile_only()) {
            self.runner
                .run(
                    &Invocation::cargo_update_workspace(self.manifest_dir, manifest),
                    self.deadline,
                )
                .await?;
        }
        for update in &updates {
            self.runner.run(update, self.deadline).await?;
        }
        self.verified(Program::Cargo, &owned, PinCheck::ExactInLock)
            .await
    }

    async fn go(&self) -> Result<LockfileOutcome, RegenerationError> {
        if self.manifest_dir.join("vendor/modules.txt").is_file() {
            return Ok(unsupported(None, UnsupportedReason::GoVendored));
        }
        let workspace = self
            .runner
            .probe(&Invocation::go_env_gowork(self.manifest_dir), self.deadline)
            .await?;
        if !(workspace.is_empty() || workspace == "off") {
            return Ok(unsupported(None, UnsupportedReason::GoWorkspace));
        }
        let owned = self.manifest_dir.join("go.sum");
        if !owned.is_file() {
            return Ok(LockfileOutcome::NotApplicable(
                NotApplicableReason::NoLockfilePresent,
            ));
        }
        if let Some(outcome) = self.ownership_refusal(&owned).await? {
            return Ok(outcome);
        }

        let modules = self
            .pins
            .iter()
            .map(arg_pair)
            .collect::<Result<Vec<_>, _>>()?;
        self.runner
            .run(
                &Invocation::go_get(self.manifest_dir, &modules),
                self.deadline,
            )
            .await?;
        self.verified(Program::Go, &owned, PinCheck::ExactInLock)
            .await
    }

    async fn npm_family(&self) -> Result<LockfileOutcome, RegenerationError> {
        let Some(located) = self.locate().await? else {
            return Ok(LockfileOutcome::NotApplicable(
                NotApplicableReason::NoLockfilePresent,
            ));
        };
        let display = self.display_lock_path(&located);
        if !same_file(located.parent(), Some(self.manifest_dir)) {
            return Ok(unsupported(
                Some(display),
                UnsupportedReason::WorkspaceMemberLockfile,
            ));
        }
        let client = located
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .and_then(NpmClient::from_lockfile_name);
        let (client, program, install, update): (
            _,
            _,
            _,
            fn(&Path, &[NpmPackageArg]) -> Invocation,
        ) = match client {
            Some(client @ NpmClient::Npm) => (
                client,
                Program::Npm,
                Invocation::npm_lock(self.manifest_dir),
                Invocation::npm_update,
            ),
            Some(client @ NpmClient::Pnpm) => (
                client,
                Program::Pnpm,
                Invocation::pnpm_lock(self.manifest_dir),
                Invocation::pnpm_update,
            ),
            Some(deferred @ (NpmClient::Yarn | NpmClient::Bun)) => {
                return Ok(unsupported(
                    Some(display),
                    UnsupportedReason::NpmClientDeferred(deferred),
                ));
            }
            None => return Err(RegenerationError::UnrecognizedLockfile { path: display.0 }),
        };
        if inside_workspace(self.manifest_dir, client, |name| std::env::var_os(name)) {
            return Ok(unsupported(
                Some(display),
                UnsupportedReason::WorkspaceMemberLockfile,
            ));
        }
        if self.pins.iter().any(|pin| pin.cooldown_fallback) {
            return Ok(unsupported(
                Some(display),
                UnsupportedReason::CooldownFallbackTarget,
            ));
        }
        if let Some(outcome) = self.symlink_refusal(&located) {
            return Ok(outcome);
        }

        let lockfile_only = self
            .pins
            .iter()
            .filter(|pin| pin.is_lockfile_only())
            .map(|pin| NpmPackageArg::parse(pin.package.as_str()).map_err(|_| unsafe_argument(pin)))
            .collect::<Result<Vec<_>, _>>()?;

        if self.pins.iter().any(|pin| !pin.is_lockfile_only()) {
            self.runner.run(&install, self.deadline).await?;
        }
        if !lockfile_only.is_empty() {
            self.runner
                .run(&update(self.manifest_dir, &lockfile_only), self.deadline)
                .await?;
        }
        self.verified(program, &located, PinCheck::SatisfiesInLock)
            .await
    }

    /// The lockfile the ecosystem's own provider associates with the manifest.
    async fn locate(&self) -> Result<Option<PathBuf>, RegenerationError> {
        let Some(provider) = self.target.ecosystem.lockfile_provider() else {
            return Ok(None);
        };
        let uri = self.target.uri.clone();
        tokio::task::spawn_blocking(move || provider.locate_lockfile(&uri))
            .await
            .map_err(|_| RegenerationError::LockfileUnreadable {
                path: self.target.display_path.to_path_buf(),
            })
    }

    /// `Some(Unsupported)` unless the provider's lockfile is the one the tool owns and is a
    /// plain file.
    async fn ownership_refusal(
        &self,
        owned: &Path,
    ) -> Result<Option<LockfileOutcome>, RegenerationError> {
        let located = self.locate().await?;
        if same_file(located.as_deref(), Some(owned)) {
            return Ok(self.symlink_refusal(owned));
        }
        let display = located.as_deref().map(|path| self.display_lock_path(path));
        Ok(Some(unsupported(
            display,
            UnsupportedReason::LockfileOwnershipMismatch,
        )))
    }

    /// Refuses a lockfile whose final component is a symlink or not a regular file: the tool
    /// would rewrite the link's target, or replace the link, outside the manifest's tree.
    fn symlink_refusal(&self, lockfile: &Path) -> Option<LockfileOutcome> {
        let plain = std::fs::symlink_metadata(lockfile)
            .is_ok_and(|metadata| metadata.file_type().is_file());
        (!plain).then(|| {
            unsupported(
                Some(self.display_lock_path(lockfile)),
                UnsupportedReason::LockfileSymlink,
            )
        })
    }

    /// Verifies every pin against a freshly read lockfile and builds the final outcome.
    async fn verified(
        &self,
        tool: Program,
        lockfile: &Path,
        check: PinCheck,
    ) -> Result<LockfileOutcome, RegenerationError> {
        let lockfile = self.display_lock_path(lockfile);
        let pins = self.verify_pins(check, &lockfile).await?;
        Ok(LockfileOutcome::Regenerated {
            lockfile,
            tool,
            pins,
        })
    }

    async fn verify_pins(
        &self,
        check: PinCheck,
        lockfile: &DisplayLockPath,
    ) -> Result<Vec<PinReport>, RegenerationError> {
        let reparse_failed = || RegenerationError::ManifestReparseFailed {
            path: self.target.display_path.to_path_buf(),
        };
        let content = deps_core::fs_probe::read_to_string_capped_no_follow(
            self.target.manifest_path,
            crate::MAX_MANIFEST_FILE_SIZE,
        )
        .ok()
        .flatten()
        .ok_or_else(reparse_failed)?;
        let parsed = deps_core::ecosystem::parse_manifest_now(
            self.target.ecosystem,
            &content,
            self.target.uri,
        )
        .ok_or_else(reparse_failed)?;

        let load = load_resolved_versions(
            self.target.uri,
            &Arc::new(LockFileCache::new()),
            self.target.ecosystem.as_ref(),
        )
        .await;
        let LockfileLoad::Loaded {
            versions,
            candidates,
        } = load
        else {
            return Err(RegenerationError::LockfileUnreadable {
                path: lockfile.0.clone(),
            });
        };

        let formatter = self.target.ecosystem.formatter();
        self.pins
            .iter()
            .map(|pin| {
                let evidence: Vec<&ConcreteVersion> = versions
                    .get(&pin.normalized)
                    .into_iter()
                    .chain(
                        candidates
                            .get(&pin.normalized)
                            .into_iter()
                            .flat_map(|found| found.versions()),
                    )
                    .collect();
                let resolution = match check {
                    PinCheck::ExactInLock => evidence
                        .contains(&&pin.target)
                        .then_some(PinResolution::Exact),
                    PinCheck::SatisfiesInLock => {
                        let requirements: Vec<&VersionReq> = parsed
                            .dependencies()
                            .into_iter()
                            .filter(|dep| {
                                formatter.normalize_package_name(dep.name()) == pin.normalized
                            })
                            .filter_map(|dep| dep.version_requirement())
                            .collect();
                        satisfying_version(formatter, &requirements, &evidence, &pin.target).map(
                            |version| {
                                if version == pin.target {
                                    PinResolution::Exact
                                } else {
                                    PinResolution::Newer(version)
                                }
                            },
                        )
                    }
                };
                resolution
                    .map(|resolution| PinReport {
                        package: pin.package.clone(),
                        target: pin.target.clone(),
                        resolution,
                    })
                    .ok_or_else(|| RegenerationError::VersionMismatch {
                        package: pin.package.clone(),
                        expected: pin.target.clone(),
                        found: versions.get(&pin.normalized).cloned(),
                    })
            })
            .collect()
    }

    /// The lockfile as shown to the user: the manifest's display directory joined with the
    /// route from the manifest directory to the lockfile.
    fn display_lock_path(&self, lockfile: &Path) -> DisplayLockPath {
        let from = std::fs::canonicalize(self.manifest_dir)
            .unwrap_or_else(|_| self.manifest_dir.to_path_buf());
        let to = std::fs::canonicalize(lockfile).unwrap_or_else(|_| lockfile.to_path_buf());
        let display_dir = self
            .target
            .display_path
            .parent()
            .unwrap_or_else(|| Path::new(""));
        DisplayLockPath(display_dir.join(relative_route(&from, &to)))
    }
}

/// The first of `evidence` that satisfies one of `requirements` and is at least `target`.
///
/// `None` from a matcher (an uncompilable requirement or an unparsable version) fails closed.
fn satisfying_version(
    formatter: &dyn EcosystemFormatter,
    requirements: &[&VersionReq],
    evidence: &[&ConcreteVersion],
    target: &ConcreteVersion,
) -> Option<ConcreteVersion> {
    let at_least_target = formatter.compile_requirement(&VersionReq::new(format!(">={target}")))?;
    let matchers: Vec<_> = requirements
        .iter()
        .filter_map(|requirement| formatter.compile_requirement(requirement))
        .collect();
    evidence
        .iter()
        .find(|version| {
            at_least_target.matches(version) == Some(true)
                && matchers
                    .iter()
                    .any(|matcher| matcher.matches(version) == Some(true))
        })
        .map(|version| (*version).clone())
}

fn unsupported(lockfile: Option<DisplayLockPath>, reason: UnsupportedReason) -> LockfileOutcome {
    LockfileOutcome::Unsupported { lockfile, reason }
}

fn unsafe_argument(pin: &LockPin) -> RegenerationError {
    RegenerationError::UnsafeArgument {
        package: crate::sanitize::sanitize_message_for_display(pin.package.as_str()),
    }
}

fn arg_pair(pin: &LockPin) -> Result<(ArgComponent, ArgComponent), RegenerationError> {
    let name = ArgComponent::parse(pin.package.as_str()).map_err(|_| unsafe_argument(pin))?;
    let version = ArgComponent::parse(pin.target.as_str()).map_err(|_| unsafe_argument(pin))?;
    Ok((name, version))
}

fn same_file(a: Option<&Path>, b: Option<&Path>) -> bool {
    match (a.map(std::fs::canonicalize), b.map(std::fs::canonicalize)) {
        (Some(Ok(a)), Some(Ok(b))) => a == b,
        _ => false,
    }
}

/// The relative route from directory `from` to `to`; `to` itself when they share no root.
fn relative_route(from: &Path, to: &Path) -> PathBuf {
    let from: Vec<_> = from.components().collect();
    let to_components: Vec<_> = to.components().collect();
    let common = from
        .iter()
        .zip(&to_components)
        .take_while(|(a, b)| a == b)
        .count();
    if common == 0 {
        return to.to_path_buf();
    }
    let mut route = PathBuf::new();
    for _ in common..from.len() {
        route.push("..");
    }
    route.extend(to_components.iter().skip(common));
    route
}

/// Whether the manifest in `manifest_dir` may belong to a workspace: pnpm's workspace directory
/// is set in the environment (read through `env_var`), or a strict ancestor declares one.
///
/// Spawns nothing. Deliberately conservative: an unreadable, oversized or invalid ancestor
/// `package.json` (including a symlink, never followed), a `manifest_dir` that cannot be
/// canonicalized, or running out of ancestor depth counts as a workspace. The answer can go
/// stale between this check and the spawn (check then spawn); the window is accepted, as for
/// every other precondition of the run.
fn inside_workspace(
    manifest_dir: &Path,
    client: NpmClient,
    env_var: impl Fn(&str) -> Option<std::ffi::OsString>,
) -> bool {
    if client == NpmClient::Pnpm
        && ["NPM_CONFIG_WORKSPACE_DIR", "npm_config_workspace_dir"]
            .iter()
            .any(|name| env_var(name).is_some())
    {
        return true;
    }
    // The tool runs in the physical directory, so a member reached through a symlinked
    // directory must be walked from its real location.
    let Ok(physical_dir) = std::fs::canonicalize(manifest_dir) else {
        return true;
    };
    let mut ancestor = physical_dir.parent();
    for _ in 0..deps_core::fs_probe::MAX_CONFIG_ANCESTOR_DEPTH {
        let Some(dir) = ancestor else {
            return false;
        };
        if declares_workspace(dir, client) {
            return true;
        }
        ancestor = dir.parent();
    }
    ancestor.is_some()
}

/// The top-level shape of a `package.json` that matters for workspace detection.
#[derive(serde::Deserialize)]
struct PackageJsonWorkspaces {
    workspaces: Option<serde::de::IgnoredAny>,
}

/// Whether `dir` declares an npm (`package.json` `workspaces`) or pnpm (`pnpm-workspace.yaml`)
/// workspace. Anything that cannot be read or parsed counts as declaring one.
fn declares_workspace(dir: &Path, client: NpmClient) -> bool {
    match client {
        NpmClient::Pnpm => dir.join("pnpm-workspace.yaml").try_exists().unwrap_or(true),
        NpmClient::Npm | NpmClient::Yarn | NpmClient::Bun => {
            match deps_core::fs_probe::read_to_string_capped_no_follow(
                &dir.join("package.json"),
                crate::MAX_MANIFEST_FILE_SIZE,
            ) {
                Ok(Some(text)) => serde_json::from_str::<PackageJsonWorkspaces>(&text)
                    .map_or(true, |package| package.workspaces.is_some()),
                Ok(None) => true,
                Err(error) => error.kind() != std::io::ErrorKind::NotFound,
            }
        }
    }
}
