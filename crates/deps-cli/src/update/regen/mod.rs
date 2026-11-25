//! Opt-in lockfile regeneration after `deps-cli update` edits a manifest (#1116).
//!
//! The planner and [`super::apply_plan`] only rewrite the manifest; this module asks the
//! ecosystem's own tool (`cargo`, `npm`, `pnpm`, `go`) to bring the lockfile in line, then
//! verifies the fresh lockfile against the applied pins. Every outcome, failures included, is
//! a [`LockfileOutcome`] value so the plan report is always printed.

mod cargo;
mod command;
mod composer;
mod dart;
mod fallback;
mod go;
mod gradle;
mod interrupt;
mod js;
#[cfg(all(test, unix))]
mod leader_state_tests;
mod lockers;
#[cfg(test)]
mod lockfile_only_tests;
mod nuget;
#[cfg(all(test, unix))]
mod process_group_tests;
mod python;
#[cfg(test)]
mod read_capped_tests;
mod rekey;
mod run;
mod swift;
#[cfg(test)]
mod tests;

use std::fmt;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
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

use command::{ArgComponent, Invocation, NpmPackageArg};
pub use command::{NpmClient, Program, PythonLocker};
pub use gradle::{LockConfiguration, LockStateChange, LockedCoordinate};
pub(in crate::update) use interrupt::Interrupts;
pub use rekey::RekeyRefusal;
pub(in crate::update) use run::{Capped, ChildGuard, ProcessGroup, read_capped};
use run::{SearchPath, ToolRunner};

use super::{
    CooldownFallbackNote, CurrentVersion, HeldEdit, LockfileState, Outcome, SkipReason,
    UnfixableReason, UpdatePlan, UpdateRun,
};
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
    /// The manifest as it was before the plan's edits were written, so a run that finds an edit
    /// resolving to a version inside the cooldown window can write the manifest back without it.
    pub original: OriginalManifest<'a>,
}

/// The text of a manifest before any edit of an `update` run was written to it.
#[derive(Debug, Clone, Copy)]
pub struct OriginalManifest<'a>(&'a str);

impl<'a> OriginalManifest<'a> {
    /// Wraps the manifest text the plan's edit ranges were computed against.
    #[must_use]
    pub const fn new(content: &'a str) -> Self {
        Self(content)
    }
}

/// The lockfile path as shown to the user, relative to the manifest's display directory
/// (`Cargo.lock`, `../Cargo.lock`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisplayLockPath {
    shown: PathBuf,
    real: PathBuf,
}

impl DisplayLockPath {
    /// The lock file's own name (`Cargo.lock`), without any directory part.
    ///
    /// A regeneration only runs for a lock file beside the manifest, so `--open-pr` stages the
    /// file under the manifest's directory by this name.
    #[must_use]
    pub fn file_name(&self) -> Option<&std::ffi::OsStr> {
        self.shown.file_name()
    }

    /// The canonical absolute path of the regenerated lock file, never a symlink.
    #[must_use]
    pub fn real_path(&self) -> &Path {
        &self.real
    }

    /// The display path of `path`, a canonical path the same run wrote, in the way this lock
    /// file's display path relates to its real one.
    #[must_use]
    pub fn display_of(&self, path: &Path) -> PathBuf {
        let from = self.real.parent().unwrap_or_else(|| Path::new(""));
        let shown_dir = self.shown.parent().unwrap_or_else(|| Path::new(""));
        lexically_normalized(&shown_dir.join(relative_route(from, path)))
    }

    /// Builds a display path for fixtures that stand in for a regeneration result.
    #[cfg(all(test, unix))]
    pub(in crate::update) fn for_test(shown: &str, real: &Path) -> Self {
        Self {
            shown: PathBuf::from(shown),
            real: real.to_path_buf(),
        }
    }
}

impl fmt::Display for DisplayLockPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.shown.display().fmt(f)
    }
}

/// A path besides the lock file that a regeneration writes and `--open-pr` must publish or
/// restore.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Companion {
    /// One file.
    File(PathBuf),
    /// A directory tree, tracked in `HEAD` when it reaches publishing.
    Tree(PathBuf),
    /// A file the run created, to be staged and restored by removal.
    Created(PathBuf),
    /// A file the run deleted, to be staged as a removal and restored from `HEAD`.
    Removed {
        /// The deleted file.
        path: PathBuf,
        /// Why it was deleted.
        removal: Removal,
    },
}

/// Why a run deleted a legacy lock file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Removal {
    /// The configuration was migrated into the unified lock file.
    Migrated,
    /// The configuration is no longer resolved and its legacy file held no coordinates.
    StaleEmpty,
    /// The configuration is no longer resolved and its legacy file held coordinates that are dropped.
    StaleDropped,
}

/// Why a legacy `gradle/dependency-locks` layout cannot be migrated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegacyLayoutConflict {
    /// A unified lock file of the same project exists beside the legacy directory.
    BesideUnifiedLock,
    /// The legacy directory holds a settings lock file.
    SettingsLock,
    /// An edited dependency is locked at several versions in the legacy layout, so the migration
    /// would move it.
    EditedPinLockedAtSeveralVersions,
    /// An edited dependency has no single declaration with a version the migration can hold fixed.
    EditedPinWithoutSingleDeclaration,
}

/// How a pin's target compares with the version the regenerated lockfile holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinResolution {
    /// The lockfile holds exactly the target.
    Exact,
    /// The lockfile holds a newer version that still satisfies the edited requirement.
    Newer(ConcreteVersion),
}

/// A pin whose regenerated lock entry sits on a version inside the freshness cooldown window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldVersion {
    /// The package whose pin landed on the version.
    pub package: PackageName,
    /// The version the lock file held.
    pub version: ConcreteVersion,
    /// The fix target of the pin.
    pub target: ConcreteVersion,
}

fn more_held(rest: &[HeldVersion]) -> String {
    if rest.is_empty() {
        String::new()
    } else {
        format!(" (and {} more)", rest.len())
    }
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
    /// The tool ran, but every fix resolved to a version inside the freshness cooldown window and
    /// was withheld, so the lock files are as they were.
    AllWithheldByCooldown,
}

/// Why regeneration is not supported for this manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnsupportedReason {
    /// The manifest may be a workspace member: its lockfile is in an ancestor directory, an
    /// ancestor declares a workspace, or the pnpm workspace directory is set via the environment.
    WorkspaceMemberLockfile,
    /// The located lockfile is not the one the tool would update.
    LockfileOwnershipMismatch,
    /// A target chosen by the cooldown fallback cannot be pinned by range resolution.
    CooldownFallbackTarget,
    /// The lockfile is a symlink or not a regular file, so the tool would rewrite elsewhere.
    LockfileSymlink,
    /// The project uses Yarn Classic (1.x), which has no lockfile-only mode.
    YarnClassic,
    /// The lock file or a companion path resolves outside the repository.
    LockfileOutsideRepository,
    /// A `.venv` file or symlink in the project directory would select a repository-chosen
    /// interpreter for the tool to run.
    SavedVirtualenv,
    /// The project uses a legacy lock layout the tool cannot update safely.
    LegacyLockLayout(LegacyLayoutConflict),
    /// The project centralizes package versions outside the edited manifest.
    CentralPackageVersions,
    /// The project has more lock files than one run handles.
    LockfileSetTooLarge,
    /// The tool has no lock-only update mode that leaves unrelated pins alone.
    LockfileOnlyUpdateUnsupported(Program),
    /// The installed tool is older than the first version the run supports.
    ToolTooOld(Program),
    /// Other dependencies of the project have floating or range requirements the tool would
    /// re-resolve as a side effect of the run.
    OtherFloatingRequirements,
}

/// A file operation of a regeneration run, named as a verb phrase for error messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoOperation {
    /// Writing the manifest with exact pins for the cooldown-fallback targets.
    WriteExactPinManifest,
    /// Writing the declared requirements back into the manifest.
    WriteBackManifest,
    /// Rewriting the lock file.
    RewriteLockfile,
    /// Creating the scratch directory for a vendor refresh.
    CreateScratchDirectory,
    /// Moving the vendor directory aside.
    MoveVendorAside,
    /// Moving the refreshed vendor directory into place.
    MoveVendorIntoPlace,
    /// Deleting a legacy Gradle lock file after its migration.
    RemoveLegacyLockfile,
}

impl fmt::Display for IoOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::WriteExactPinManifest => "write the exact-pin manifest",
            Self::WriteBackManifest => "write back the manifest",
            Self::RewriteLockfile => "rewrite the lock file",
            Self::CreateScratchDirectory => "create a scratch directory in",
            Self::MoveVendorAside => "move aside the vendor directory",
            Self::MoveVendorIntoPlace => "move the refreshed vendor directory into place at",
            Self::RemoveLegacyLockfile => "remove the legacy lock file",
        })
    }
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
    /// The tool locked a newer in-range version inside the freshness cooldown window; the lock
    /// files are restored.
    #[error(
        "lockfile resolves {} to {}, which is inside the freshness cooldown window{}",
        first.package.as_str(),
        first.version,
        more_held(rest)
    )]
    CooldownHeldVersion {
        /// The first pin that landed on a version inside the window.
        first: HeldVersion,
        /// Every other pin that did.
        rest: Vec<HeldVersion>,
    },
    /// A lock file could not be read before the tool ran, so nothing was spawned.
    #[error("could not snapshot {} before regeneration", path.display())]
    SnapshotFailed {
        /// The lock file's display path.
        path: PathBuf,
    },
    /// The regeneration failed and the lock file could not be put back.
    #[error("{cause}; restoring {} failed: {source}", path.display())]
    RestoreFailed {
        /// The failure that triggered the restore.
        cause: Box<Self>,
        /// The display path of the file that could not be restored.
        path: PathBuf,
        /// The underlying I/O error.
        source: std::io::Error,
    },
    /// The tool could not pin a cooldown-fallback target.
    ///
    /// Either a dependent requires a newer version, or the version or registry is unavailable.
    #[error(
        "{} could not be pinned to the cooldown-fallback target {} (tool {}): a dependent may require a newer version, or the version or registry is unavailable",
        package.as_str(),
        target.as_str(),
        exit_description(*code)
    )]
    FallbackPinRejected {
        /// The package whose pin was rejected.
        package: PackageName,
        /// The cooldown-fallback target.
        target: ConcreteVersion,
        /// The tool's exit code, `None` when killed by a signal.
        code: Option<i32>,
    },
    /// The manifest changed during the run in a way the run did not make.
    #[error("{} changed during regeneration", path.display())]
    ManifestChanged {
        /// The manifest's display path.
        path: PathBuf,
    },
    /// A file operation of the run failed.
    #[error("could not {operation} {}: {source}", path.display())]
    Io {
        /// The operation that failed.
        operation: IoOperation,
        /// The display path the operation addressed.
        path: PathBuf,
        /// The underlying I/O error.
        source: std::io::Error,
    },
    /// A cooldown-fallback pin could not be kept in the lock file after the manifest write-back.
    #[error(
        "{} could not be kept at the cooldown-fallback target {} in {}: {reason}",
        package.as_str(),
        target.as_str(),
        path.display()
    )]
    FallbackPinNotKept {
        /// The package whose pin was not kept.
        package: PackageName,
        /// The cooldown-fallback target.
        target: ConcreteVersion,
        /// The lock file's display path.
        path: PathBuf,
        /// Why the lock file could not be re-keyed.
        reason: RekeyRefusal,
    },
    /// A lock-only pin could not be kept in the lock file after the declared requirement was restored.
    #[error(
        "{} could not be kept at {} in {}: {reason}",
        package.as_str(),
        target.as_str(),
        path.display()
    )]
    LockfilePinNotKept {
        /// The package whose pin was not kept.
        package: PackageName,
        /// The pinned target.
        target: ConcreteVersion,
        /// The lock file's display path.
        path: PathBuf,
        /// Why the lock file could not be re-keyed.
        reason: RekeyRefusal,
    },
    /// The run changed which coordinates a configuration locks beyond the requested update.
    #[error("the run changed the lock state of configuration {configuration} in {}: {change}", path.display())]
    LockStateDrift {
        /// The lock file's display path.
        path: PathBuf,
        /// The configuration that drifted.
        configuration: LockConfiguration,
        /// The coordinate that appeared or vanished.
        change: LockStateChange,
    },
}

impl RegenerationError {
    /// Builds a [`Self::LockStateDrift`] for tests outside this module, whose lock-state types
    /// have module-private constructors; `None` for a malformed configuration or coordinate.
    ///
    /// `change` is the variant constructor (`LockStateChange::Gained` or `::Lost`).
    #[cfg(test)]
    pub(crate) fn lock_state_drift_for_test(
        path: PathBuf,
        configuration: &str,
        coordinate: &str,
        change: fn(LockedCoordinate) -> LockStateChange,
    ) -> Option<Self> {
        Some(Self::LockStateDrift {
            path,
            configuration: LockConfiguration::new(configuration)?,
            change: change(LockedCoordinate::new(coordinate)?),
        })
    }

    /// The failure behind any restore wrapper: `self` unless this is a
    /// [`Self::RestoreFailed`], then the failure that triggered the restore.
    #[must_use]
    pub(crate) fn root_cause(&self) -> &Self {
        if let Self::RestoreFailed { cause, .. } = self {
            cause.root_cause()
        } else {
            self
        }
    }
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
        /// Every other path the run wrote besides the lock file.
        companions: Vec<Companion>,
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
            Self::AllWithheldByCooldown => {
                "every fix resolved to a version inside the freshness cooldown window and was withheld"
            }
        })
    }
}

impl fmt::Display for UnsupportedReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WorkspaceMemberLockfile => {
                f.write_str(
                    "the manifest may belong to a workspace (the lockfile is in an ancestor directory, an \
ancestor declares a workspace, or the workspace directory is set through the environment)",
                )
            }
            Self::LockfileOwnershipMismatch => {
                f.write_str("the lockfile is not the one the tool would update")
            }
            Self::CooldownFallbackTarget => {
                f.write_str("a cooldown-fallback target cannot be pinned by range resolution")
            }
            Self::LockfileSymlink => f.write_str("the lockfile is a symlink or not a regular file"),
            Self::YarnClassic => f.write_str(
                "Yarn Classic (1.x) has no lockfile-only mode; only Yarn 2+ is supported",
            ),
            Self::SavedVirtualenv => f.write_str(
                "the project directory has a .venv file or symlink that would select an interpreter to run",
            ),
            Self::LockfileOutsideRepository => {
                f.write_str("the lockfile or a file the tool writes is outside the repository")
            }
            Self::LegacyLockLayout(LegacyLayoutConflict::BesideUnifiedLock) => f.write_str(
                "the project has both a gradle.lockfile and a legacy gradle/dependency-locks directory; Gradle reads gradle.lockfile and ignores the directory, so delete gradle/dependency-locks to continue",
            ),
            Self::LegacyLockLayout(LegacyLayoutConflict::SettingsLock) => f.write_str(
                "the legacy gradle/dependency-locks directory holds a settings lock file, which is not migrated automatically",
            ),
            Self::LegacyLockLayout(LegacyLayoutConflict::EditedPinLockedAtSeveralVersions) => f
                .write_str(
                    "an edited dependency is locked at several versions in gradle/dependency-locks, so migrating the lock layout would move it; migrate the layout once with `gradle :<project>:dependencies --update-locks <group:module>`, commit the result, then rerun",
                ),
            Self::LegacyLockLayout(LegacyLayoutConflict::EditedPinWithoutSingleDeclaration) => f
                .write_str(
                    "an edited dependency has no single declaration with a version that can be held fixed during the lock layout migration; migrate the layout once with `gradle :<project>:dependencies --update-locks <group:module>`, commit the result, then rerun",
                ),
            Self::CentralPackageVersions => f.write_str(
                "package versions are centralized in Directory.Packages.props, which is not the edited manifest",
            ),
            Self::LockfileSetTooLarge => {
                f.write_str("the project has more lock files than one run handles")
            }
            Self::LockfileOnlyUpdateUnsupported(program) => write!(
                f,
                "{program} has no lockfile-only update mode that leaves unrelated pins alone"
            ),
            Self::ToolTooOld(program) => {
                write!(f, "the installed {program} is too old for lockfile regeneration")
            }
            Self::OtherFloatingRequirements => f.write_str(
                "other dependencies have floating or range requirements the restore would re-resolve",
            ),
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
    Pypi,
    Bundler,
    Deno,
    Composer,
    Dart,
    NuGet,
    Gradle,
    Swift,
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
        EcosystemId::Pypi => Strategy::Pypi,
        EcosystemId::Bundler => Strategy::Bundler,
        EcosystemId::Deno => Strategy::Deno,
        EcosystemId::Composer => Strategy::Composer,
        EcosystemId::Dart => Strategy::Dart,
        EcosystemId::Gradle => Strategy::Gradle,
        EcosystemId::Swift => Strategy::Swift,
        EcosystemId::NuGet => Strategy::NuGet,
    }
}

/// Whether regeneration is implemented for an ecosystem, decided from its identity alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockfileSupport {
    /// A tool regenerates the lock file.
    Regenerates,
    /// The ecosystem has no lock file format, so there is nothing to regenerate.
    NoLockfileFormat,
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
/// assert_eq!(lockfile_support(EcosystemId::Pypi), LockfileSupport::Regenerates);
/// assert_eq!(lockfile_support(EcosystemId::Maven), LockfileSupport::NoLockfileFormat);
/// ```
#[must_use]
pub const fn lockfile_support(id: EcosystemId) -> LockfileSupport {
    match strategy(id) {
        Strategy::Cargo
        | Strategy::NpmFamily
        | Strategy::Go
        | Strategy::Pypi
        | Strategy::Bundler
        | Strategy::Deno
        | Strategy::Composer
        | Strategy::Dart
        | Strategy::NuGet
        | Strategy::Gradle
        | Strategy::Swift => LockfileSupport::Regenerates,
        Strategy::NoLockfileFormat => LockfileSupport::NoLockfileFormat,
    }
}

/// The regeneration tools of a strategy as `(name shown to the user, program)`.
const fn strategy_tools(strategy: Strategy) -> &'static [(&'static str, Program)] {
    match strategy {
        Strategy::Cargo => &[("Cargo", Program::Cargo)],
        Strategy::NpmFamily => &[
            ("npm", Program::Npm),
            ("pnpm", Program::Pnpm),
            ("Yarn 2+", Program::Yarn),
            ("Bun", Program::Bun),
        ],
        Strategy::Go => &[("Go", Program::Go)],
        Strategy::Pypi => &[
            ("uv", Program::Uv),
            ("Poetry", Program::Poetry),
            ("PDM", Program::Pdm),
            ("Pipenv", Program::Pipenv),
        ],
        Strategy::Bundler => &[("Bundler", Program::Bundle)],
        Strategy::Deno => &[("Deno", Program::Deno)],
        Strategy::Composer => &[("Composer", Program::Composer)],
        Strategy::Dart => &[("Dart", Program::Dart), ("Flutter", Program::Flutter)],
        Strategy::NuGet => &[("NuGet", Program::Dotnet)],
        Strategy::Gradle => &[("Gradle", Program::Gradle)],
        Strategy::Swift => &[("SwiftPM", Program::Swift)],
        Strategy::NoLockfileFormat => &[],
    }
}

/// The tools of `id`'s ecosystem that can move a lock file without a planned manifest edit, as prose
/// (`npm, pnpm, Yarn 2+ and Bun`), derived from [`strategy`] so it cannot drift from the tools
/// the strategy runs; `None` for an ecosystem without a lock file format.
pub(super) fn lockfile_only_tools_text(id: EcosystemId) -> Option<String> {
    let mut tools: Vec<&str> = strategy_tools(strategy(id))
        .iter()
        .map(|(label, _)| *label)
        .collect();
    let last = tools.pop()?;
    Some(if tools.is_empty() {
        last.to_owned()
    } else {
        format!("{} and {last}", tools.join(", "))
    })
}

/// How a pin is proven against the regenerated lockfile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PinCheck {
    /// The lockfile holds exactly the target (cargo, go).
    ExactInLock,
    /// The lockfile holds a version that satisfies the edited requirement and is at least the
    /// target (npm, pnpm).
    SatisfiesInLock,
    /// The lockfile holds the target or a newer version by the ecosystem's own ordering, for
    /// ecosystems whose matcher grammar has no `>=target` (Gradle). Only a lock-file-only pin may
    /// land on a newer version; an edited or cooldown-fallback pin must hold the exact target.
    AtLeastTarget,
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
#[derive(Clone)]
struct LockPin {
    package: PackageName,
    normalized: NormalizedName,
    target: ConcreteVersion,
    cooldown_fallback: bool,
    /// Versions inside the freshness cooldown window that the lock file must not end up on.
    cooldown_held: Vec<ConcreteVersion>,
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

    fn is_held_at(&self, formatter: &dyn EcosystemFormatter, version: &ConcreteVersion) -> bool {
        self.cooldown_held
            .iter()
            .any(|held| same_release(formatter, held, version))
    }
}

fn collect_pins(plan: &UpdatePlan, formatter: &dyn EcosystemFormatter) -> Vec<LockPin> {
    let mut pins: Vec<LockPin> = Vec::new();
    for item in &plan.items {
        let (target, origin) = match &item.outcome {
            Outcome::Applied { target, .. } => (target, PinOrigin::ManifestEdit),
            Outcome::RequiresLockfileUpdate { target, .. } => (
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
            existing
                .cooldown_held
                .extend_from_slice(&item.lockfile_fix.cooldown_held);
            continue;
        }
        pins.push(LockPin {
            package,
            normalized,
            target: target.clone(),
            cooldown_fallback: matches!(
                item.cooldown_fallback,
                Some(CooldownFallbackNote::AppliedInsteadOf(..))
            ),
            cooldown_held: item.lockfile_fix.cooldown_held.clone(),
            origin,
        });
    }
    pins
}

/// Regenerates the lockfile for the manifest `plan` was applied to, using the inherited `PATH`,
/// and settles every `RequiresLockfileUpdate` item the regenerated lockfile now satisfies into
/// `AppliedViaLockfile`.
///
/// Never panics; writes only the snapshot restore and, for #2077, a temporary exact-pin
/// manifest. A failure is a [`LockfileOutcome`] variant.
pub async fn regenerate_lockfile(
    plan: UpdatePlan,
    target: &ManifestTarget<'_>,
    gate: RegenerationGate,
) -> UpdateRun {
    let interrupt = interrupt_listener(&plan, target, gate);
    regenerate_with_interrupt(plan, target, gate, LockfileScope::Unrestricted, interrupt).await
}

/// Like [`regenerate_lockfile`], but installs no signal listener of its own.
///
/// For a caller that already drops this future on SIGINT/SIGTERM (`--open-pr`'s
/// [`PrSignals`](super::pr::PrSignals)): two competing listeners would make an interrupt end
/// either as a dropped phase or as a `failed` lock file outcome, depending on which fired first.
/// The dropped future still terminates the tool's process tree through the child guards.
///
/// `repo_root` is the work-tree root: no lock file or companion path may resolve outside it, or
/// the run ends `Unsupported(LockfileOutsideRepository)` before anything is spawned. Workspace
/// members are allowed; their lock file is published from wherever it lives inside the root.
pub async fn regenerate_lockfile_unlistened(
    plan: UpdatePlan,
    target: &ManifestTarget<'_>,
    gate: RegenerationGate,
    repo_root: &Path,
) -> UpdateRun {
    regenerate_with_interrupt(
        plan,
        target,
        gate,
        LockfileScope::Within(repo_root),
        std::future::pending(),
    )
    .await
}

async fn regenerate_with_interrupt(
    plan: UpdatePlan,
    target: &ManifestTarget<'_>,
    gate: RegenerationGate,
    scope: LockfileScope<'_>,
    interrupt: impl Future<Output = ()>,
) -> UpdateRun {
    let runner = ToolRunner {
        deadline: TOOL_BUDGET,
        search_path: SearchPath::Inherit,
        group: ProcessGroup::detect(),
    };
    regenerate_planned(plan, target, gate, &runner, scope, interrupt).await
}

/// Regenerates, settles and marks the cooldown-held items of `plan` with `runner`.
async fn regenerate_planned(
    plan: UpdatePlan,
    target: &ManifestTarget<'_>,
    gate: RegenerationGate,
    runner: &ToolRunner,
    scope: LockfileScope<'_>,
    interrupt: impl Future<Output = ()>,
) -> UpdateRun {
    let RegenerationRun { lockfile, retried } =
        regenerate_until(&plan, target, gate, runner, scope, interrupt).await;
    let formatter = target.ecosystem.formatter();
    let mut plan = plan;
    settle_lockfile_only(&mut plan, &lockfile, formatter);
    withhold(&mut plan, &retried, formatter);
    if let LockfileOutcome::Failed(RegenerationError::CooldownHeldVersion { first, rest }) =
        &lockfile
    {
        let refused: Vec<HeldVersion> = std::iter::once(first).chain(rest).cloned().collect();
        mark_held(&mut plan, &refused, formatter);
    }
    UpdateRun { plan, lockfile }
}

/// Withholds every fix `held` names: an `Applied` item becomes `Unfixable(ResolvesWithinCooldown)`
/// (`--security-only`) or `Skipped(WithinFreshnessCooldown)` (default mode), per its
/// [`HeldEdit`], and its edit is written back out of the manifest; a lock-file-only item stays as
/// it is; both record the version the tool resolved.
fn withhold(plan: &mut UpdatePlan, held: &[HeldVersion], formatter: &dyn EcosystemFormatter) {
    for item in &mut plan.items {
        let Outcome::Applied { target, .. } = &item.outcome else {
            continue;
        };
        if let Some(entry) = held_entry(held, formatter, item.name.as_str(), target) {
            item.lockfile_fix.lockfile = LockfileState::HeldByCooldown(entry.version.clone());
            item.outcome = match item.lockfile_fix.held_edit {
                HeldEdit::Unfixable => {
                    Outcome::Unfixable(UnfixableReason::ResolvesWithinCooldown {
                        target: target.clone(),
                        resolved: entry.version.clone(),
                    })
                }
                HeldEdit::Skip => Outcome::Skipped {
                    reason: SkipReason::WithinFreshnessCooldown,
                    target: Some(target.clone()),
                },
            };
        }
    }
    mark_held(plan, held, formatter);
}

/// Records on each still-unsettled `RequiresLockfileUpdate` item named in `held` that the tool
/// resolved it to a version inside the cooldown window.
fn mark_held(plan: &mut UpdatePlan, held: &[HeldVersion], formatter: &dyn EcosystemFormatter) {
    for item in &mut plan.items {
        let Outcome::RequiresLockfileUpdate { target, .. } = &item.outcome else {
            continue;
        };
        if let Some(entry) = held_entry(held, formatter, item.name.as_str(), target) {
            item.lockfile_fix.lockfile = LockfileState::HeldByCooldown(entry.version.clone());
        }
    }
}

/// The entry of `held` for the pin of package `name` with fix target `target`.
fn held_entry<'a>(
    held: &'a [HeldVersion],
    formatter: &dyn EcosystemFormatter,
    name: &str,
    target: &ConcreteVersion,
) -> Option<&'a HeldVersion> {
    let name = formatter.normalize_package_name(&PackageName::new(name));
    held.iter().find(|entry| {
        entry.target == *target && formatter.normalize_package_name(&entry.package) == name
    })
}

/// Installs the signal handlers right before the first spawn, when the gate is `Run` and there
/// is at least one pin.
///
/// This is decided before the strategy is known, so handlers are also installed for runs that
/// end up spawning nothing (an ecosystem without a lock file format, a missing lock file); the
/// signals are then swallowed for the rest of the short-lived process. Under `--open-pr`,
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
/// lock file now stands. A newer version inside the cooldown window never reaches this point:
/// verification fails the run with [`RegenerationError::CooldownHeldVersion`] and restores the
/// lock files.
fn settle_lockfile_only(
    plan: &mut UpdatePlan,
    lockfile: &LockfileOutcome,
    formatter: &dyn EcosystemFormatter,
) {
    let LockfileOutcome::Regenerated { pins, .. } = lockfile else {
        return;
    };
    for item in &mut plan.items {
        let Outcome::RequiresLockfileUpdate { target, .. } = &item.outcome else {
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
    regenerate_until(
        plan,
        target,
        gate,
        runner,
        LockfileScope::Unrestricted,
        std::future::pending(),
    )
    .await
    .lockfile
}

#[cfg(all(test, unix))]
async fn regenerate_run_with(
    plan: UpdatePlan,
    target: &ManifestTarget<'_>,
    gate: RegenerationGate,
    runner: &ToolRunner,
) -> UpdateRun {
    regenerate_planned(
        plan,
        target,
        gate,
        runner,
        LockfileScope::Unrestricted,
        std::future::pending(),
    )
    .await
}

/// The outcome of [`regenerate_until`], with the pins it left out of a retry.
struct RegenerationRun {
    lockfile: LockfileOutcome,
    /// Pins left out of the manifest or lock file because a tool resolved them inside the
    /// cooldown window: the lock-file-only ones and the edits of the first attempt, which the
    /// retry regenerated without, and the edits the retry held again.
    retried: Vec<HeldVersion>,
}

impl RegenerationRun {
    const fn plain(lockfile: LockfileOutcome) -> Self {
        Self {
            lockfile,
            retried: Vec::new(),
        }
    }
}

/// Regenerates like [`regenerate_lockfile`], but abandons the run when `interrupt` resolves:
/// dropping the session fires every child guard, so the tool's process tree is killed.
async fn regenerate_until(
    plan: &UpdatePlan,
    target: &ManifestTarget<'_>,
    gate: RegenerationGate,
    runner: &ToolRunner,
    scope: LockfileScope<'_>,
    interrupt: impl Future<Output = ()>,
) -> RegenerationRun {
    let formatter = target.ecosystem.formatter();
    let pins = collect_pins(plan, formatter);
    if pins.is_empty() {
        return RegenerationRun::plain(LockfileOutcome::NotApplicable(
            NotApplicableReason::NothingApplied,
        ));
    }
    if let RegenerationGate::Skip(cause) = gate {
        return RegenerationRun::plain(LockfileOutcome::Skipped(cause));
    }
    let deadline = Instant::now() + runner.deadline;
    tokio::pin!(interrupt);
    let first = run_attempt(target, runner, deadline, scope, &pins, interrupt.as_mut()).await;
    let LockfileOutcome::Failed(RegenerationError::CooldownHeldVersion { first: held, rest }) =
        &first
    else {
        return RegenerationRun::plain(first);
    };
    let held: Vec<HeldVersion> = std::iter::once(held).chain(rest).cloned().collect();
    let is_held = |pin: &LockPin| names_pin(&held, formatter, pin);
    let mut retry_plan = plan.clone();
    withhold(&mut retry_plan, &held, formatter);
    if pins
        .iter()
        .any(|pin| is_held(pin) && !pin.is_lockfile_only())
        && !rewrite_without_held_edits(target, plan, &retry_plan)
    {
        return RegenerationRun::plain(first);
    }
    let remaining: Vec<LockPin> = collect_pins(&retry_plan, formatter)
        .into_iter()
        .filter(|pin| !(pin.is_lockfile_only() && is_held(pin)))
        .collect();
    if remaining.is_empty() {
        return RegenerationRun {
            lockfile: LockfileOutcome::NotApplicable(NotApplicableReason::AllWithheldByCooldown),
            retried: held,
        };
    }
    let second = run_attempt(
        target,
        runner,
        deadline,
        scope,
        &remaining,
        interrupt.as_mut(),
    )
    .await;
    let mut withheld = held;
    withheld.extend(retry_held_edits(
        &second,
        &remaining,
        target,
        &retry_plan,
        formatter,
    ));
    RegenerationRun {
        lockfile: second,
        retried: withheld,
    }
}

/// Whether `held` names the pin's package at the pin's fix target.
fn names_pin(held: &[HeldVersion], formatter: &dyn EcosystemFormatter, pin: &LockPin) -> bool {
    held.iter().any(|entry| {
        entry.target == pin.target
            && formatter.normalize_package_name(&entry.package) == pin.normalized
    })
}

/// The manifest edits the retry held again, written back out of the manifest like the first
/// attempt's; empty when the retry did not hold an edit or the manifest could not be rewritten.
fn retry_held_edits(
    second: &LockfileOutcome,
    remaining: &[LockPin],
    target: &ManifestTarget<'_>,
    retry_plan: &UpdatePlan,
    formatter: &dyn EcosystemFormatter,
) -> Vec<HeldVersion> {
    let LockfileOutcome::Failed(RegenerationError::CooldownHeldVersion { first, rest }) = second
    else {
        return Vec::new();
    };
    let edits: Vec<HeldVersion> = std::iter::once(first)
        .chain(rest)
        .filter(|entry| {
            let held = std::slice::from_ref(*entry);
            remaining
                .iter()
                .any(|pin| !pin.is_lockfile_only() && names_pin(held, formatter, pin))
        })
        .cloned()
        .collect();
    if edits.is_empty() {
        return edits;
    }
    let mut final_plan = retry_plan.clone();
    withhold(&mut final_plan, &edits, formatter);
    if rewrite_without_held_edits(target, retry_plan, &final_plan) {
        edits
    } else {
        Vec::new()
    }
}

/// Writes the manifest back as the original text plus the edits `after` still applies, so a held
/// edit disappears from it. `false` when the file no longer holds what `before` wrote (it was
/// changed during the run) or the write fails.
fn rewrite_without_held_edits(
    target: &ManifestTarget<'_>,
    before: &UpdatePlan,
    after: &UpdatePlan,
) -> bool {
    let original = target.original.0;
    let current = deps_core::fs_probe::read_to_string_capped(
        target.manifest_path,
        crate::MAX_MANIFEST_FILE_SIZE,
    )
    .ok()
    .flatten();
    current.as_deref() == Some(super::planned_manifest(before, original).as_str())
        && deps_core::fs_probe::write_atomic(
            target.manifest_path,
            &super::planned_manifest(after, original),
        )
        .is_ok()
}

/// One regeneration of `pins` under a fresh snapshot, restored when it fails or `interrupt`
/// resolves.
async fn run_attempt(
    target: &ManifestTarget<'_>,
    runner: &ToolRunner,
    deadline: Instant,
    scope: LockfileScope<'_>,
    pins: &[LockPin],
    interrupt: std::pin::Pin<&mut impl Future<Output = ()>>,
) -> LockfileOutcome {
    let snapshot = OnceLock::new();
    let session = Session {
        target,
        runner,
        deadline,
        pins,
        manifest_dir: target
            .manifest_path
            .parent()
            .unwrap_or_else(|| Path::new("")),
        snapshot: &snapshot,
        scope,
    };
    let outcome = tokio::select! {
        result = session.execute() => result.unwrap_or_else(LockfileOutcome::Failed),
        () = interrupt => LockfileOutcome::Failed(RegenerationError::Interrupted),
    };
    match outcome {
        LockfileOutcome::Failed(error) => {
            LockfileOutcome::Failed(restore_snapshot(error, &snapshot))
        }
        other => other,
    }
}

/// Lock files as they were before the first writing spawn.
struct LockSnapshot {
    files: Vec<SnapshotFile>,
}

struct SnapshotFile {
    path: PathBuf,
    display: PathBuf,
    state: SnapshotState,
}

/// What a snapshotted path held: a file to put back, or nothing (the run may create it).
enum SnapshotState {
    Present(Vec<u8>),
    Absent,
}

/// Whether a failure leaves lock files that may need putting back.
///
/// Off unix a timed-out or interrupted `.cmd`/`.bat` shim is killed without waiting for its
/// child, which may still write, so no restore is attempted there.
const fn restore_after(error: &RegenerationError) -> bool {
    match error {
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
        RegenerationError::SnapshotFailed { .. } | RegenerationError::RestoreFailed { .. } => false,
    }
}

/// Puts every snapshotted file back after `error`, rewriting only files whose bytes differ.
///
/// Runs after the session future was dropped, so the tool's process tree is already gone.
fn restore_snapshot(
    error: RegenerationError,
    snapshot: &OnceLock<LockSnapshot>,
) -> RegenerationError {
    let Some(snapshot) = snapshot.get().filter(|_| restore_after(&error)) else {
        return error;
    };
    for file in &snapshot.files {
        let restored = match &file.state {
            SnapshotState::Present(bytes) => {
                let unchanged = matches!(
                    deps_core::fs_probe::read_capped_no_follow(
                        &file.path,
                        deps_core::lockfile::MAX_LOCKFILE_BYTES
                    ),
                    Ok(Some(current)) if current == *bytes
                );
                if unchanged {
                    continue;
                }
                deps_core::fs_probe::write_atomic_bytes(&file.path, bytes)
            }
            SnapshotState::Absent => match std::fs::remove_file(&file.path) {
                Err(source) if source.kind() != std::io::ErrorKind::NotFound => Err(source),
                Ok(()) | Err(_) => Ok(()),
            },
        };
        if let Err(source) = restored {
            return RegenerationError::RestoreFailed {
                cause: Box::new(error),
                path: file.display.clone(),
                source,
            };
        }
    }
    error
}

/// Where a regeneration may write: anywhere the tool puts its lock file, or only inside the
/// work tree `--open-pr` publishes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LockfileScope<'a> {
    Unrestricted,
    Within(&'a Path),
}

/// The state of one regeneration: the target, the shared deadline and the pins to verify.
struct Session<'a> {
    target: &'a ManifestTarget<'a>,
    runner: &'a ToolRunner,
    deadline: Instant,
    pins: &'a [LockPin],
    manifest_dir: &'a Path,
    snapshot: &'a OnceLock<LockSnapshot>,
    scope: LockfileScope<'a>,
}

impl Session<'_> {
    async fn execute(&self) -> Result<LockfileOutcome, RegenerationError> {
        let id = self.target.ecosystem.ecosystem_id();
        match strategy(id) {
            Strategy::NoLockfileFormat => Ok(LockfileOutcome::NotApplicable(
                NotApplicableReason::NoLockfileFormat,
            )),
            Strategy::Cargo => self.cargo().await,
            Strategy::NpmFamily => self.npm_family().await,
            Strategy::Go => self.go().await,
            Strategy::Pypi => self.pypi().await,
            Strategy::Bundler => self.bundler().await,
            Strategy::Deno => self.deno().await,
            Strategy::Composer => self.composer().await,
            Strategy::Dart => self.dart().await,
            Strategy::NuGet => self.nuget().await,
            Strategy::Gradle => self.gradle().await,
            Strategy::Swift => self.swift().await,
        }
    }

    /// Records `paths` before the first spawn that writes them, once per run.
    ///
    /// # Errors
    ///
    /// [`RegenerationError::SnapshotFailed`] when a file is unreadable, a symlink, or over the
    /// lock file size cap; nothing has been spawned yet.
    fn capture(&self, paths: &[&Path]) -> Result<(), RegenerationError> {
        self.capture_creating(paths, &[])
    }

    /// Like [`Self::capture`], also recording `created`: paths that must not exist yet and are
    /// removed again on restore.
    ///
    /// # Errors
    ///
    /// [`RegenerationError::SnapshotFailed`] as for `capture`, or when a `created` path exists.
    fn capture_creating(
        &self,
        present: &[&Path],
        created: &[&Path],
    ) -> Result<(), RegenerationError> {
        let mut files = present
            .iter()
            .map(|path| {
                let display = self.display_lock_path(path).shown;
                deps_core::fs_probe::read_capped_no_follow(
                    path,
                    deps_core::lockfile::MAX_LOCKFILE_BYTES,
                )
                .ok()
                .flatten()
                .map(|bytes| SnapshotFile {
                    path: (*path).to_path_buf(),
                    display: display.clone(),
                    state: SnapshotState::Present(bytes),
                })
                .ok_or(RegenerationError::SnapshotFailed { path: display })
            })
            .collect::<Result<Vec<_>, _>>()?;
        for path in created {
            let display = self.display_lock_path(path).shown;
            let missing = matches!(
                std::fs::symlink_metadata(path),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound
            );
            if !missing {
                return Err(RegenerationError::SnapshotFailed { path: display });
            }
            files.push(SnapshotFile {
                path: (*path).to_path_buf(),
                display,
                state: SnapshotState::Absent,
            });
        }
        // A second capture in one run keeps the first: the earliest state is the one to restore.
        let _ = self.snapshot.set(LockSnapshot { files });
        Ok(())
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

    /// `Some(Unsupported)` when a pin's target came from the cooldown fallback: range
    /// resolution cannot pin it.
    fn cooldown_refusal(&self, lockfile: &Path) -> Option<LockfileOutcome> {
        self.pins.iter().any(|pin| pin.cooldown_fallback).then(|| {
            unsupported(
                Some(self.display_lock_path(lockfile)),
                UnsupportedReason::CooldownFallbackTarget,
            )
        })
    }

    /// Each lockfile-only pin's package name, validated by `parse`.
    fn lockfile_only_args<T>(
        &self,
        parse: impl Fn(&str) -> Result<T, command::UnsafeArgument>,
    ) -> Result<Vec<T>, RegenerationError> {
        self.pins
            .iter()
            .filter(|pin| pin.is_lockfile_only())
            .map(|pin| parse(pin.package.as_str()).map_err(|_| unsafe_argument(pin)))
            .collect()
    }

    /// `Some(Unsupported)` unless the provider's lockfile is the one the tool owns and is a
    /// plain file.
    async fn ownership_refusal(
        &self,
        owned: &Path,
    ) -> Result<Option<LockfileOutcome>, RegenerationError> {
        let located = self.locate().await?;
        if same_file(located.as_deref(), Some(owned)) {
            return Ok(self.placement_refusal(owned));
        }
        let display = located.as_deref().map(|path| self.display_lock_path(path));
        Ok(Some(unsupported(
            display,
            UnsupportedReason::LockfileOwnershipMismatch,
        )))
    }

    /// Whether `path` resolves inside the scope; an uncanonicalizable path is outside.
    fn within_scope(&self, path: &Path) -> bool {
        match self.scope {
            LockfileScope::Unrestricted => true,
            LockfileScope::Within(root) => std::fs::canonicalize(root)
                .ok()
                .zip(std::fs::canonicalize(path).ok())
                .is_some_and(|(root, path)| path.starts_with(root)),
        }
    }

    /// Refuses a lockfile that is a symlink or not a regular file (the tool would rewrite the
    /// link's target, or replace the link, elsewhere) or that resolves outside the scope.
    fn placement_refusal(&self, lockfile: &Path) -> Option<LockfileOutcome> {
        let plain = std::fs::symlink_metadata(lockfile)
            .is_ok_and(|metadata| metadata.file_type().is_file());
        let reason = if !plain {
            UnsupportedReason::LockfileSymlink
        } else if !self.within_scope(lockfile) {
            UnsupportedReason::LockfileOutsideRepository
        } else {
            return None;
        };
        Some(unsupported(Some(self.display_lock_path(lockfile)), reason))
    }

    /// Verifies every pin against a freshly read lockfile and builds the final outcome.
    async fn verified(
        &self,
        tool: Program,
        lockfile: &Path,
        check: PinCheck,
    ) -> Result<LockfileOutcome, RegenerationError> {
        self.verified_with(tool, lockfile, Vec::new(), check).await
    }

    /// Like [`Self::verified`], recording the other paths the run wrote.
    async fn verified_with(
        &self,
        tool: Program,
        lockfile: &Path,
        companions: Vec<Companion>,
        check: PinCheck,
    ) -> Result<LockfileOutcome, RegenerationError> {
        let lockfile = self.display_lock_path(lockfile);
        let pins = self.verify_pins(check, &lockfile).await?;
        Ok(LockfileOutcome::Regenerated {
            lockfile,
            tool,
            pins,
            companions,
        })
    }

    fn reparse_failed(&self) -> RegenerationError {
        RegenerationError::ManifestReparseFailed {
            path: self.target.display_path.to_path_buf(),
        }
    }

    /// Reads the manifest with the size cap and without following symlinks.
    fn read_manifest_text(&self) -> Result<String, RegenerationError> {
        deps_core::fs_probe::read_to_string_capped_no_follow(
            self.target.manifest_path,
            crate::MAX_MANIFEST_FILE_SIZE,
        )
        .ok()
        .flatten()
        .ok_or_else(|| self.reparse_failed())
    }

    /// Parses manifest `text` with the target's ecosystem.
    fn parse_manifest_text(
        &self,
        text: &str,
    ) -> Result<Box<dyn deps_core::ParsedManifest>, RegenerationError> {
        deps_core::ecosystem::parse_manifest_now(self.target.ecosystem, text, self.target.uri)
            .ok_or_else(|| self.reparse_failed())
    }

    /// Reads and parses the manifest as it is on disk now.
    fn reparse_manifest(&self) -> Result<Box<dyn deps_core::ParsedManifest>, RegenerationError> {
        self.parse_manifest_text(&self.read_manifest_text()?)
    }

    async fn verify_pins(
        &self,
        check: PinCheck,
        lockfile: &DisplayLockPath,
    ) -> Result<Vec<PinReport>, RegenerationError> {
        let parsed = self.reparse_manifest()?;

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
                path: lockfile.shown.clone(),
            });
        };

        let formatter = self.target.ecosystem.formatter();
        let reports =
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
                    let exact = || {
                        evidence
                            .contains(&&pin.target)
                            .then_some(PinResolution::Exact)
                    };
                    let resolution = match check {
                        PinCheck::ExactInLock => exact(),
                        PinCheck::AtLeastTarget if pin.cooldown_fallback => exact(),
                        PinCheck::AtLeastTarget if !pin.is_lockfile_only() => exact(),
                        PinCheck::AtLeastTarget => exact()
                            .or_else(|| not_older_resolution(formatter, &evidence, &pin.target)),
                        // A cooldown-fallback target is deliberately below the newest release, so a
                        // newer satisfying version would be the very release the cooldown excludes.
                        PinCheck::SatisfiesInLock if pin.cooldown_fallback => exact(),
                        PinCheck::SatisfiesInLock => {
                            let requirements: Vec<&VersionReq> = parsed
                                .dependencies()
                                .into_iter()
                                .filter(|dep| {
                                    formatter.normalize_package_name(dep.name()) == pin.normalized
                                })
                                .filter_map(|dep| dep.version_requirement())
                                .collect();
                            satisfying_version(formatter, &requirements, &evidence, &pin.target)
                                .map(|version| {
                                    if version == pin.target {
                                        PinResolution::Exact
                                    } else {
                                        PinResolution::Newer(version)
                                    }
                                })
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
                .collect::<Result<Vec<_>, _>>()?;
        let mut held =
            self.pins
                .iter()
                .zip(&reports)
                .filter_map(|(pin, report)| match &report.resolution {
                    PinResolution::Newer(version) if pin.is_held_at(formatter, version) => {
                        Some(HeldVersion {
                            package: pin.package.clone(),
                            version: version.clone(),
                            target: pin.target.clone(),
                        })
                    }
                    PinResolution::Newer(_) | PinResolution::Exact => None,
                });
        match held.next() {
            Some(first) => Err(RegenerationError::CooldownHeldVersion {
                first,
                rest: held.collect(),
            }),
            None => Ok(reports),
        }
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
        DisplayLockPath {
            shown: lexically_normalized(&display_dir.join(relative_route(&from, &to))),
            real: to,
        }
    }
}

/// Whether `a` and `b` name the same release under the ecosystem's own version ordering, so
/// spellings the registry and the lock file normalize differently (PEP 440 `2.31.1` and
/// `2.31.1.0`) still compare equal. Unparsable versions are equal only when spelled identically.
fn same_release(
    formatter: &dyn EcosystemFormatter,
    a: &ConcreteVersion,
    b: &ConcreteVersion,
) -> bool {
    let at_least = |version: &ConcreteVersion| {
        formatter.compile_requirement(&VersionReq::new(format!(">={version}")))
    };
    a == b
        || at_least(a)
            .zip(at_least(b))
            .is_some_and(|(at_least_a, at_least_b)| {
                at_least_a.matches(b) == Some(true) && at_least_b.matches(a) == Some(true)
            })
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

/// The first of `evidence` that equals or exceeds `target` by the ecosystem's own ordering.
///
/// An unordered pair (`None`) fails closed.
fn not_older_resolution(
    formatter: &dyn EcosystemFormatter,
    evidence: &[&ConcreteVersion],
    target: &ConcreteVersion,
) -> Option<PinResolution> {
    evidence.iter().find_map(
        |version| match formatter.compare_versions(version, target)? {
            std::cmp::Ordering::Equal => Some(PinResolution::Exact),
            std::cmp::Ordering::Greater => Some(PinResolution::Newer((*version).clone())),
            std::cmp::Ordering::Less => None,
        },
    )
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

/// `path` with `.` dropped and every `x/..` pair collapsed, without touching the filesystem.
///
/// A `..` with no normal component before it (leading, or right after the root) is kept.
fn lexically_normalized(path: &Path) -> PathBuf {
    use std::path::Component;
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir
                if matches!(out.components().next_back(), Some(Component::Normal(_))) =>
            {
                out.pop();
            }
            other => out.push(other),
        }
    }
    out
}

/// Whether pnpm's workspace directory is set in the environment (read through `env_var`).
fn workspace_dir_env_set(
    client: NpmClient,
    env_var: impl Fn(&str) -> Option<std::ffi::OsString>,
) -> bool {
    client == NpmClient::Pnpm
        && ["NPM_CONFIG_WORKSPACE_DIR", "npm_config_workspace_dir"]
            .iter()
            .any(|name| env_var(name).is_some())
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
    if workspace_dir_env_set(client, env_var) {
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
