//! Regeneration for Gradle dependency-lock files (#2085).
//!
//! Gradle runs from the build root, so one run may rewrite the lock file of every project of the
//! build. The whole lock set is snapshotted before the first spawn and reported as companions.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use deps_core::NormalizeName;
use deps_core::edit::{ManifestEdit, apply_edits};

mod lock_state;

#[cfg(test)]
mod legacy_tests;

pub use lock_state::{LockConfiguration, LockStateChange, LockedCoordinate};
use lock_state::{LockScope, LockState, first_drift, parse_legacy, parse_unified, without_modules};

use super::command::NonEmpty;
use super::command::gradle::{GradleCoordArg, GradleProjectPath};
use super::fallback::{CapturedManifest, ManifestGuard, is_version_char};
use super::{
    Companion, Invocation, IoOperation, LegacyLayoutConflict, LockfileOutcome, NotApplicableReason,
    PinCheck, Program, RegenerationError, Removal, Session, UnsupportedReason, same_file,
    unsafe_argument, unsupported,
};

const SETTINGS_FILES: [&str; 2] = ["settings.gradle", "settings.gradle.kts"];
const LOCK_FILES: [&str; 2] = ["gradle.lockfile", "buildscript-gradle.lockfile"];

/// Most lock files one run snapshots, stages and restores.
const MAX_LOCK_FILES: usize = 512;
/// Most bytes of absolute lock paths one run puts on a git command line (Windows allows 32,767).
const MAX_LOCK_PATH_BYTES: usize = 24_000;
/// Most directory entries the lock-set walk examines.
const MAX_WALK_ENTRIES: usize = 100_000;

/// Why the lock set of a build could not be collected.
#[derive(Debug)]
enum LockSetError {
    /// The set is refused for the stated reason; nothing was spawned.
    Refused(UnsupportedReason),
    /// A legacy layout cannot be migrated; `path` is the offending legacy or settings lock file.
    Conflict {
        /// What conflicts.
        conflict: LegacyLayoutConflict,
        /// The file that conflicts.
        path: PathBuf,
    },
    /// A directory could not be listed.
    Unreadable,
}

impl From<UnsupportedReason> for LockSetError {
    fn from(reason: UnsupportedReason) -> Self {
        Self::Refused(reason)
    }
}

/// The lock files of a build, split by layout.
#[derive(Debug)]
struct LockSet {
    /// Unified `gradle.lockfile` and `buildscript-gradle.lockfile` files, sorted.
    unified: Vec<PathBuf>,
    /// Projects that still use the legacy `gradle/dependency-locks` layout, sorted by directory.
    legacy: Vec<LegacyProject>,
}

/// The legacy lock files of one project.
#[derive(Debug)]
struct LegacyProject {
    /// The project directory, the parent of `gradle/`.
    dir: PathBuf,
    /// Its `gradle/dependency-locks/*.lockfile` files, sorted.
    files: Vec<PathBuf>,
}

/// Accumulates the lock set of one walk against the shared bounds.
#[derive(Default)]
struct Collector {
    unified: Vec<PathBuf>,
    legacy: Vec<LegacyProject>,
    files: usize,
    path_bytes: usize,
    visited: usize,
}

impl Collector {
    fn visit(&mut self) -> Result<(), LockSetError> {
        self.visited += 1;
        if self.visited > MAX_WALK_ENTRIES {
            return Err(UnsupportedReason::LockfileSetTooLarge.into());
        }
        Ok(())
    }

    fn admit(&mut self, path: &Path) -> Result<(), LockSetError> {
        self.files += 1;
        self.path_bytes += path.as_os_str().len();
        if self.files > MAX_LOCK_FILES || self.path_bytes > MAX_LOCK_PATH_BYTES {
            return Err(UnsupportedReason::LockfileSetTooLarge.into());
        }
        Ok(())
    }

    /// Collects the `*.lockfile` files of `dir` (a `gradle/dependency-locks` directory) as the
    /// legacy locks of `project`; a directory without any is not a layout.
    fn collect_legacy(&mut self, project: &Path, dir: &Path) -> Result<(), LockSetError> {
        let mut files = Vec::new();
        for entry in std::fs::read_dir(dir).map_err(|_| LockSetError::Unreadable)? {
            let entry = entry.map_err(|_| LockSetError::Unreadable)?;
            self.visit()?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if !name.ends_with(".lockfile") {
                continue;
            }
            let kind = entry.file_type().map_err(|_| LockSetError::Unreadable)?;
            if kind.is_symlink() {
                return Err(UnsupportedReason::LockfileSymlink.into());
            }
            if !kind.is_file() {
                continue;
            }
            if name.starts_with("settings-") {
                return Err(LockSetError::Conflict {
                    conflict: LegacyLayoutConflict::SettingsLock,
                    path: entry.path(),
                });
            }
            let path = entry.path();
            self.admit(&path)?;
            files.push(path);
        }
        if !files.is_empty() {
            files.sort();
            self.legacy.push(LegacyProject {
                dir: project.to_path_buf(),
                files,
            });
        }
        Ok(())
    }
}

/// Every Gradle lock file under `root`, split into unified and legacy layouts.
///
/// The walk never follows symlinks and skips `build/`, `.gradle/` and other hidden directories.
/// A legacy directory beside a unified lock of the same project, a settings lock in it, or a walk
/// or set over the bounds above refuses the build.
fn lock_set(root: &Path) -> Result<LockSet, LockSetError> {
    let mut collector = Collector::default();
    let mut pending = vec![(root.to_path_buf(), 0_usize)];
    while let Some((dir, depth)) = pending.pop() {
        let entries = std::fs::read_dir(&dir).map_err(|_| LockSetError::Unreadable)?;
        for entry in entries {
            let entry = entry.map_err(|_| LockSetError::Unreadable)?;
            collector.visit()?;
            let kind = entry.file_type().map_err(|_| LockSetError::Unreadable)?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if kind.is_dir() {
                let project = (name == "dependency-locks"
                    && dir.file_name().is_some_and(|parent| parent == "gradle"))
                .then(|| dir.parent().filter(|project| project.starts_with(root)))
                .flatten();
                if let Some(project) = project {
                    collector.collect_legacy(project, &entry.path())?;
                    continue;
                }
                if name == "build" || name.starts_with('.') {
                    continue;
                }
                if depth + 1 >= deps_core::fs_probe::MAX_CONFIG_ANCESTOR_DEPTH {
                    return Err(UnsupportedReason::LockfileSetTooLarge.into());
                }
                pending.push((entry.path(), depth + 1));
            } else if LOCK_FILES.contains(&&*name) {
                let path = entry.path();
                collector.admit(&path)?;
                collector.unified.push(path);
            }
        }
    }
    let Collector {
        mut unified,
        mut legacy,
        ..
    } = collector;
    unified.sort();
    legacy.sort_by(|a, b| a.dir.cmp(&b.dir));
    let beside = legacy.iter().find(|project| {
        unified
            .iter()
            .any(|lock| lock.parent() == Some(&project.dir))
    });
    if let Some(path) = beside.and_then(|project| project.files.first()) {
        return Err(LockSetError::Conflict {
            conflict: LegacyLayoutConflict::BesideUnifiedLock,
            path: path.clone(),
        });
    }
    Ok(LockSet { unified, legacy })
}

/// Whether `lock` belongs to a build nested below `root` (`buildSrc/` or an included build with
/// its own settings file). Gradle applies `--update-locks` to `buildSrc` too and rewrites its lock
/// only for the configurations that build resolves, so the set cannot be updated consistently.
fn in_nested_build(root: &Path, lock: &Path) -> bool {
    lock.parent()
        .into_iter()
        .flat_map(Path::ancestors)
        .take_while(|dir| *dir != root && dir.starts_with(root))
        .any(|dir| {
            dir.file_name().is_some_and(|name| name == "buildSrc")
                || SETTINGS_FILES.iter().any(|name| dir.join(name).is_file())
        })
}

/// The distinct projects owning the lock directories `dirs`, one per directory below `root`.
///
/// # Errors
///
/// [`RegenerationError::UnsafeArgument`] when a lock directory cannot be a safe project path;
/// nothing has been spawned yet.
fn lock_projects(
    root: &Path,
    dirs: &[&Path],
) -> Result<NonEmpty<GradleProjectPath>, RegenerationError> {
    let mut projects: Vec<GradleProjectPath> = Vec::new();
    for dir in dirs {
        let relative = dir.strip_prefix(root).unwrap_or(dir);
        let project =
            GradleProjectPath::of(relative).map_err(|_| RegenerationError::UnsafeArgument {
                package: crate::sanitize::sanitize_message_for_display(
                    &relative.display().to_string(),
                ),
            })?;
        if !projects.contains(&project) {
            projects.push(project);
        }
    }
    NonEmpty::new(projects).ok_or(RegenerationError::SnapshotFailed {
        path: root.to_path_buf(),
    })
}

/// The outcome of reading one lock file.
enum LockRead {
    /// The file does not exist.
    Missing,
    /// The file's UTF-8 text.
    Text(String),
    /// The file is a symlink or not a regular file, over the size cap, not UTF-8, or unreadable.
    Unreadable,
}

/// What the migration spawn needs done to the edited manifest first.
enum Neutral {
    /// No edit pin is held by a relevant legacy lock.
    Unneeded,
    /// The manifest with every held edit pin at its locked version.
    Text(String),
    /// A held edit pin cannot be held fixed.
    Refused(LegacyLayoutConflict),
}

/// A legacy lock file with what it stood for before the migration.
struct LegacyFile {
    path: PathBuf,
    key: (LockScope, LockConfiguration),
    held_nothing: bool,
}

/// The unified lock files a spawn in `dirs` may create: those of each directory not in `existing`.
fn missing_unified_locks(dirs: &[&Path], existing: &[PathBuf]) -> Vec<PathBuf> {
    dirs.iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .flat_map(|dir| LockScope::ALL.map(|scope| dir.join(scope.unified_file_name())))
        .filter(|path| !existing.contains(path))
        .collect()
}

/// The parsed state of one unified lock file.
struct UnifiedLock {
    path: PathBuf,
    state: LockState,
}

/// The legacy lock state of one project, read before the first spawn.
struct LegacyState {
    state: LockState,
    files: Vec<LegacyFile>,
}

impl Session<'_> {
    /// The directory Gradle runs in, canonical: the nearest ancestor with a settings file, else
    /// the project directory (the parent of `gradle/` for a version catalog).
    fn gradle_build_root(&self) -> Option<PathBuf> {
        let physical = std::fs::canonicalize(self.manifest_dir).ok()?;
        let settings_dir = deps_core::fs_probe::config_ancestors(&physical)
            .find(|dir| SETTINGS_FILES.iter().any(|name| dir.join(name).is_file()));
        let catalog_in_gradle_dir = self.target.manifest_path.file_name()
            == Some(std::ffi::OsStr::new("libs.versions.toml"))
            && physical.file_name() == Some(std::ffi::OsStr::new("gradle"));
        Some(match settings_dir {
            Some(dir) => dir.to_path_buf(),
            None if catalog_in_gradle_dir => physical.parent()?.to_path_buf(),
            None => physical,
        })
    }

    /// `gradle dependencies --update-locks <g:a,...>` at the build root, for edit and lock-only
    /// pins alike.
    ///
    /// Uses `gradle` from `PATH` only, never a project wrapper (it would run a distribution
    /// the manifest chooses). A project still on the legacy `gradle/dependency-locks` layout is
    /// first migrated to the unified lock files by a spawn that moves no dependency, and the
    /// migrated state must equal the legacy one before the pins are applied.
    pub(super) async fn gradle(&self) -> Result<LockfileOutcome, RegenerationError> {
        let Some(located) = self.locate().await? else {
            return Ok(LockfileOutcome::NotApplicable(
                NotApplicableReason::NoLockfilePresent,
            ));
        };
        let display = self.display_lock_path(&located);
        if let Some(outcome) = self.cooldown_refusal(&located) {
            return Ok(outcome);
        }
        // A settings file above the repository makes that outer build the one Gradle runs.
        let Some(root) = self
            .gradle_build_root()
            .filter(|root| self.within_scope(root))
        else {
            return Ok(unsupported(
                Some(display),
                UnsupportedReason::LockfileOutsideRepository,
            ));
        };
        let set = match lock_set(&root) {
            Ok(set) => set,
            Err(LockSetError::Refused(reason)) => return Ok(unsupported(Some(display), reason)),
            Err(LockSetError::Conflict { conflict, path }) => {
                return Ok(unsupported(
                    Some(self.display_lock_path(&path)),
                    UnsupportedReason::LegacyLockLayout(conflict),
                ));
            }
            Err(LockSetError::Unreadable) => {
                return Err(RegenerationError::SnapshotFailed {
                    path: self.target.display_path.to_path_buf(),
                });
            }
        };
        let locks: Vec<&Path> = set
            .unified
            .iter()
            .chain(set.legacy.iter().flat_map(|project| &project.files))
            .map(PathBuf::as_path)
            .collect();
        if !locks
            .iter()
            .any(|lock| same_file(Some(lock), Some(&located)))
            || locks.iter().any(|lock| in_nested_build(&root, lock))
        {
            return Ok(unsupported(
                Some(display),
                UnsupportedReason::LockfileOwnershipMismatch,
            ));
        }
        for lock in &locks {
            if let Some(outcome) = self.placement_refusal(lock) {
                return Ok(outcome);
            }
        }

        let coordinates = self
            .pins
            .iter()
            .map(|pin| {
                GradleCoordArg::parse(pin.package.as_str()).map_err(|_| unsafe_argument(pin))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let Some(coordinates) = NonEmpty::new(coordinates) else {
            return Ok(LockfileOutcome::NotApplicable(
                NotApplicableReason::NothingApplied,
            ));
        };

        if set.legacy.is_empty() {
            self.gradle_unified(&root, &located, &set.unified, &coordinates)
                .await
        } else {
            self.gradle_migrating(&root, &located, &set, &coordinates)
                .await
        }
    }

    async fn gradle_unified(
        &self,
        root: &Path,
        located: &Path,
        unified: &[PathBuf],
        coordinates: &NonEmpty<GradleCoordArg>,
    ) -> Result<LockfileOutcome, RegenerationError> {
        let dirs: Vec<&Path> = unified.iter().filter_map(|lock| lock.parent()).collect();
        let projects = lock_projects(root, &dirs)?;

        let created = missing_unified_locks(&dirs, unified);
        let present: Vec<&Path> = unified.iter().map(PathBuf::as_path).collect();
        let created_refs: Vec<&Path> = created.iter().map(PathBuf::as_path).collect();
        self.capture_creating(&present, &created_refs)?;
        let guarded: Vec<PathBuf> = unified.iter().chain(&created).cloned().collect();
        let before = self.read_unified_states(&guarded)?;
        self.runner
            .run(
                &Invocation::gradle_update_locks(root, &projects, coordinates),
                self.deadline,
            )
            .await?;
        self.ensure_only_pins_moved(&before, &guarded)?;
        let mut companions: Vec<Companion> = unified
            .iter()
            .filter(|lock| !same_file(Some(lock), Some(located)))
            .map(|lock| self.companion_file(lock))
            .collect();
        companions.extend(self.created_companions(&created)?);
        self.verified_with(
            Program::Gradle,
            located,
            companions,
            PinCheck::AtLeastTarget,
        )
        .await
    }

    /// A [`Companion::Created`] for each of `created` that the run wrote as a regular file.
    fn created_companions(&self, created: &[PathBuf]) -> Result<Vec<Companion>, RegenerationError> {
        let mut companions = Vec::new();
        for path in created {
            match std::fs::symlink_metadata(path) {
                Ok(metadata) if metadata.file_type().is_file() => {
                    companions.push(Companion::Created(self.companion_path(path)));
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Ok(_) | Err(_) => {
                    return Err(RegenerationError::LockfileUnreadable {
                        path: self.display_lock_path(path).shown,
                    });
                }
            }
        }
        Ok(companions)
    }

    fn companion_file(&self, lock: &Path) -> Companion {
        Companion::File(self.display_lock_path(lock).real_path().to_path_buf())
    }

    /// Migrates the legacy projects of `set`, proves the migrated state equal to the legacy one,
    /// removes the legacy files and only then applies the pins.
    async fn gradle_migrating(
        &self,
        root: &Path,
        located: &Path,
        set: &LockSet,
        coordinates: &NonEmpty<GradleCoordArg>,
    ) -> Result<LockfileOutcome, RegenerationError> {
        let before = set
            .legacy
            .iter()
            .map(|project| self.read_legacy_state(project))
            .collect::<Result<Vec<_>, _>>()?;
        let verified = Self::migrated_lock_of(located, set);
        let manifest = (self.pins.iter().any(|pin| !pin.is_lockfile_only()))
            .then(|| self.read_manifest(self.target.manifest_path))
            .transpose()?;
        let neutral = match &manifest {
            Some(manifest) => {
                let relevant = self.relevant_legacy_states(set, &before);
                match self.neutral_manifest_text(manifest.bytes(), &relevant)? {
                    Neutral::Unneeded => None,
                    Neutral::Text(text) => Some(text),
                    Neutral::Refused(conflict) => {
                        return Ok(unsupported(
                            Some(self.display_lock_path(self.target.manifest_path)),
                            UnsupportedReason::LegacyLockLayout(conflict),
                        ));
                    }
                }
            }
            None => None,
        };
        let project_dirs: Vec<&Path> = set
            .unified
            .iter()
            .filter_map(|lock| lock.parent())
            .chain(set.legacy.iter().map(|project| project.dir.as_path()))
            .collect();
        let created = missing_unified_locks(&project_dirs, &set.unified);
        let present: Vec<&Path> = set
            .unified
            .iter()
            .chain(set.legacy.iter().flat_map(|project| &project.files))
            .map(PathBuf::as_path)
            .chain(manifest.as_ref().map(CapturedManifest::path))
            .collect();
        let created_refs: Vec<&Path> = created.iter().map(PathBuf::as_path).collect();
        self.capture_creating(&present, &created_refs)?;

        let legacy_dirs: Vec<&Path> = set
            .legacy
            .iter()
            .map(|project| project.dir.as_path())
            .collect();
        let locks_to_guard: Vec<PathBuf> = set.unified.iter().chain(&created).cloned().collect();
        // The migration spawn may rewrite locks of other projects too, so their baseline is read
        // before it; a legacy project's own locks are proven equal to the legacy state instead.
        let (in_legacy_dirs, outside_legacy_dirs): (Vec<PathBuf>, Vec<PathBuf>) = locks_to_guard
            .iter()
            .cloned()
            .partition(|lock| lock.parent().is_some_and(|dir| legacy_dirs.contains(&dir)));
        let mut baseline = self.read_unified_states(&outside_legacy_dirs)?;
        let mut guard = manifest
            .as_ref()
            .filter(|_| neutral.is_some())
            .map(ManifestGuard::new);
        if let (Some(manifest), Some(text)) = (&manifest, &neutral) {
            self.write_manifest(
                manifest,
                text.as_bytes(),
                IoOperation::WriteExactPinManifest,
            )?;
        }
        self.runner
            .run(
                &Invocation::gradle_migrate_locks(root, &lock_projects(root, &legacy_dirs)?),
                self.deadline,
            )
            .await?;
        if let (Some(manifest), Some(guard)) = (&manifest, &mut guard) {
            self.write_manifest(manifest, manifest.bytes(), IoOperation::WriteBackManifest)?;
            guard.disarm();
        }

        let mut removals: Vec<(PathBuf, Removal)> = Vec::new();
        for (project, legacy) in set.legacy.iter().zip(&before) {
            let migrated = self.read_migrated_state(project)?;
            if let Some((scope, configuration, change)) = first_drift(&legacy.state, &migrated) {
                return Err(RegenerationError::LockStateDrift {
                    path: self
                        .display_lock_path(&project.dir.join(scope.unified_file_name()))
                        .shown,
                    configuration,
                    change,
                });
            }
            for file in &legacy.files {
                let removal = if migrated.contains_key(&file.key) {
                    Removal::Migrated
                } else if file.held_nothing {
                    Removal::StaleEmpty
                } else {
                    Removal::StaleDropped
                };
                removals.push((file.path.clone(), removal));
            }
        }
        for (path, _) in &removals {
            self.remove_legacy_file(path)?;
        }

        let dirs: Vec<&Path> = set
            .unified
            .iter()
            .filter_map(|lock| lock.parent())
            .chain(legacy_dirs.iter().copied())
            .collect();
        baseline.extend(self.read_unified_states(&in_legacy_dirs)?);
        self.runner
            .run(
                &Invocation::gradle_update_locks(root, &lock_projects(root, &dirs)?, coordinates),
                self.deadline,
            )
            .await?;
        self.ensure_only_pins_moved(&baseline, &locks_to_guard)?;

        let mut companions: Vec<Companion> = set
            .unified
            .iter()
            .filter(|lock| !same_file(Some(lock), Some(&verified)))
            .map(|lock| self.companion_file(lock))
            .collect();
        companions.extend(self.created_companions(&created)?);
        companions.extend(
            removals
                .into_iter()
                .map(|(path, removal)| Companion::Removed {
                    path: self.companion_path(&path),
                    removal,
                }),
        );
        self.verified_with(
            Program::Gradle,
            &verified,
            companions,
            PinCheck::AtLeastTarget,
        )
        .await
    }

    /// The parsed state of every existing unified lock file among `paths`.
    fn read_unified_states(
        &self,
        paths: &[PathBuf],
    ) -> Result<Vec<UnifiedLock>, RegenerationError> {
        let mut locks = Vec::new();
        for path in paths {
            let scope = path
                .file_name()
                .and_then(|name| name.to_str())
                .and_then(LockScope::of_unified_file_name)
                .ok_or_else(|| self.unrecognized(path))?;
            let text = match Self::read_lock_text(path) {
                LockRead::Text(text) => text,
                LockRead::Missing => continue,
                LockRead::Unreadable => {
                    return Err(RegenerationError::LockfileUnreadable {
                        path: self.display_lock_path(path).shown,
                    });
                }
            };
            let state = parse_unified(scope, &text).ok_or_else(|| self.unrecognized(path))?;
            locks.push(UnifiedLock {
                path: path.clone(),
                state,
            });
        }
        Ok(locks)
    }

    /// Refuses a run that moved a coordinate no pin names, in a configuration the lock already
    /// held or one it was missing (which Gradle resolves fresh, past the cooldown).
    ///
    /// The caller's snapshot restores the files on the returned error.
    fn ensure_only_pins_moved(
        &self,
        before: &[UnifiedLock],
        paths: &[PathBuf],
    ) -> Result<(), RegenerationError> {
        let modules: Vec<&str> = self.pins.iter().map(|pin| pin.package.as_str()).collect();
        let empty = LockState::new();
        for after in self.read_unified_states(paths)? {
            let prior = before
                .iter()
                .find(|lock| lock.path == after.path)
                .map_or(&empty, |lock| &lock.state);
            if let Some((_, configuration, change)) = first_drift(
                &without_modules(prior, &modules),
                &without_modules(&after.state, &modules),
            ) {
                return Err(RegenerationError::LockStateDrift {
                    path: self.display_lock_path(&after.path).shown,
                    configuration,
                    change,
                });
            }
        }
        Ok(())
    }

    fn write_manifest(
        &self,
        manifest: &CapturedManifest,
        bytes: &[u8],
        operation: IoOperation,
    ) -> Result<(), RegenerationError> {
        deps_core::fs_probe::write_atomic_bytes(manifest.path(), bytes).map_err(|source| {
            RegenerationError::Io {
                operation,
                path: manifest.display().to_path_buf(),
                source,
            }
        })
    }

    /// The legacy states an edit pin's lock entries can come from: the manifest project's own
    /// for a build script, every legacy project's for a version catalog.
    fn relevant_legacy_states<'a>(
        &self,
        set: &LockSet,
        states: &'a [LegacyState],
    ) -> Vec<&'a LegacyState> {
        let catalog = self.target.manifest_path.file_name()
            == Some(std::ffi::OsStr::new("libs.versions.toml"));
        let own_dir = std::fs::canonicalize(self.manifest_dir).ok();
        set.legacy
            .iter()
            .zip(states)
            .filter(|(project, _)| catalog || own_dir.as_deref() == Some(project.dir.as_path()))
            .map(|(_, state)| state)
            .collect()
    }

    /// The manifest text with every edit pin that the legacy locks hold set to its one locked
    /// version, so the migration spawn resolves exactly the legacy state.
    ///
    /// A pin no relevant legacy state holds stays as edited: it cannot change the migrated
    /// state, and the drift check still guards it.
    fn neutral_manifest_text(
        &self,
        bytes: &[u8],
        relevant: &[&LegacyState],
    ) -> Result<Neutral, RegenerationError> {
        let content = std::str::from_utf8(bytes).map_err(|_| self.reparse_failed())?;
        let parsed = self.parse_manifest_text(content)?;
        let formatter = self.target.ecosystem.formatter();
        let locked_versions = |pin: &super::LockPin, scope: Option<LockScope>| -> BTreeSet<&str> {
            let prefix = format!("{}:", pin.package.as_str());
            relevant
                .iter()
                .flat_map(|project| &project.state)
                .filter(|((key_scope, _), _)| scope.is_none_or(|scope| scope == *key_scope))
                .flat_map(|(_, coordinates)| coordinates)
                .filter_map(|coordinate| coordinate.as_str().strip_prefix(prefix.as_str()))
                .collect()
        };
        let mut edits = Vec::new();
        for pin in self.pins.iter().filter(|pin| !pin.is_lockfile_only()) {
            let declarations: Vec<_> = parsed
                .dependencies()
                .into_iter()
                .filter(|dep| formatter.normalize_package_name(dep.name()) == pin.normalized)
                .collect();
            let [declaration] = declarations.as_slice() else {
                if locked_versions(pin, None).is_empty() {
                    continue;
                }
                return Ok(Neutral::Refused(
                    LegacyLayoutConflict::EditedPinWithoutSingleDeclaration,
                ));
            };
            let scope = match declaration.lock_scope() {
                deps_core::LockScope::Project => LockScope::Project,
                deps_core::LockScope::BuildScript => LockScope::Buildscript,
            };
            let locked = locked_versions(pin, Some(scope));
            let mut versions = locked.iter();
            let version = match (versions.next(), versions.next()) {
                (None, _) => continue,
                (Some(_), Some(_)) => {
                    return Ok(Neutral::Refused(
                        LegacyLayoutConflict::EditedPinLockedAtSeveralVersions,
                    ));
                }
                (Some(version), None) => *version,
            };
            let Some(range) = declaration
                .version_range()
                .filter(|_| version.chars().all(is_version_char))
            else {
                return Ok(Neutral::Refused(
                    LegacyLayoutConflict::EditedPinWithoutSingleDeclaration,
                ));
            };
            edits.push(ManifestEdit {
                range,
                new_text: version.to_owned(),
            });
        }
        Ok(if edits.is_empty() {
            Neutral::Unneeded
        } else {
            Neutral::Text(apply_edits(content, &edits))
        })
    }

    /// The lock file the run reports and verifies: the project-scope unified file of the
    /// legacy project that owns `located` (its buildscript one when that project has no
    /// project-scope legacy file), else `located` itself (a unified file).
    ///
    /// Taken before the first spawn, while `located` still exists; the provider's choice among
    /// the legacy files says nothing about the scope the pins land in.
    fn migrated_lock_of(located: &Path, set: &LockSet) -> PathBuf {
        set.legacy
            .iter()
            .find(|project| {
                project
                    .files
                    .iter()
                    .any(|file| same_file(Some(file), Some(located)))
            })
            .map_or_else(
                || located.to_path_buf(),
                |project| {
                    let has_project_scope = project.files.iter().any(|file| {
                        file.file_name()
                            .and_then(|name| name.to_str())
                            .and_then(LockScope::of_legacy_file_name)
                            .is_some_and(|(scope, _)| scope == LockScope::Project)
                    });
                    let scope = if has_project_scope {
                        LockScope::Project
                    } else {
                        LockScope::Buildscript
                    };
                    project.dir.join(scope.unified_file_name())
                },
            )
    }

    /// `path` for a companion: its canonical parent and its own name, so a symlink at `path` is
    /// never followed by the publishing git commands.
    fn companion_path(&self, path: &Path) -> PathBuf {
        path.parent()
            .and_then(|parent| std::fs::canonicalize(parent).ok())
            .zip(path.file_name())
            .map_or_else(|| path.to_path_buf(), |(parent, name)| parent.join(name))
    }

    /// What reading one lock file found.
    fn read_lock_text(path: &Path) -> LockRead {
        match deps_core::fs_probe::read_capped_no_follow(
            path,
            deps_core::lockfile::MAX_LOCKFILE_BYTES,
        ) {
            Ok(Some(bytes)) => {
                String::from_utf8(bytes).map_or(LockRead::Unreadable, LockRead::Text)
            }
            Ok(None) => LockRead::Unreadable,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => LockRead::Missing,
            Err(_) => LockRead::Unreadable,
        }
    }

    fn unrecognized(&self, path: &Path) -> RegenerationError {
        RegenerationError::UnrecognizedLockfile {
            path: self.display_lock_path(path).shown,
        }
    }

    /// Reads and parses the legacy files of `project` before anything is spawned.
    fn read_legacy_state(&self, project: &LegacyProject) -> Result<LegacyState, RegenerationError> {
        let mut state = LockState::new();
        let mut files = Vec::new();
        for path in &project.files {
            let LockRead::Text(text) = Self::read_lock_text(path) else {
                return Err(RegenerationError::SnapshotFailed {
                    path: self.display_lock_path(path).shown,
                });
            };
            let key = path
                .file_name()
                .and_then(|name| name.to_str())
                .and_then(LockScope::of_legacy_file_name)
                .ok_or_else(|| self.unrecognized(path))?;
            let coordinates = parse_legacy(&text).ok_or_else(|| self.unrecognized(path))?;
            files.push(LegacyFile {
                path: path.clone(),
                held_nothing: coordinates.is_empty(),
                key: key.clone(),
            });
            state.insert(key, coordinates);
        }
        Ok(LegacyState { state, files })
    }

    /// The state of the unified files Gradle created for `project`; a missing file is empty.
    fn read_migrated_state(&self, project: &LegacyProject) -> Result<LockState, RegenerationError> {
        let mut state = LockState::new();
        for scope in LockScope::ALL {
            let path = project.dir.join(scope.unified_file_name());
            let text = match Self::read_lock_text(&path) {
                LockRead::Text(text) => text,
                LockRead::Missing => continue,
                LockRead::Unreadable => {
                    return Err(RegenerationError::LockfileUnreadable {
                        path: self.display_lock_path(&path).shown,
                    });
                }
            };
            let parsed = parse_unified(scope, &text).ok_or_else(|| self.unrecognized(&path))?;
            state.extend(parsed);
        }
        Ok(state)
    }

    /// Deletes a legacy lock file after re-checking, now that a spawn has run, that it is still
    /// a regular file in the directory the walk found it in.
    fn remove_legacy_file(&self, path: &Path) -> Result<(), RegenerationError> {
        let unchanged = path
            .parent()
            .is_some_and(|parent| std::fs::canonicalize(parent).is_ok_and(|real| real == parent));
        let regular = match std::fs::symlink_metadata(path) {
            Ok(metadata) => metadata.file_type().is_file(),
            Err(error) => error.kind() == std::io::ErrorKind::NotFound,
        };
        if !unchanged || !regular {
            return Err(RegenerationError::LockfileUnreadable {
                path: self.display_lock_path(path).shown,
            });
        }
        match std::fs::remove_file(path) {
            Err(source) if source.kind() != std::io::ErrorKind::NotFound => {
                Err(RegenerationError::Io {
                    operation: IoOperation::RemoveLegacyLockfile,
                    path: self.display_lock_path(path).shown,
                    source,
                })
            }
            Ok(()) | Err(_) => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::assert_matches;

    use super::*;

    fn touch(root: &Path, rel: &str) {
        let path = root.join(rel);
        std::fs::create_dir_all(path.parent().expect("parent")).expect("dirs");
        std::fs::write(path, b"").expect("write");
    }

    fn names(root: &Path, set: &[PathBuf]) -> Vec<String> {
        set.iter()
            .map(|path| {
                path.strip_prefix(root)
                    .expect("under root")
                    .to_string_lossy()
                    .replace('\\', "/")
            })
            .collect()
    }

    #[test]
    fn nested_builds_are_buildsrc_and_directories_with_their_own_settings() {
        let dir = tempfile::tempdir().expect("dir");
        let root = dir.path();
        touch(root, "settings.gradle");
        touch(root, "gradle.lockfile");
        touch(root, "app/gradle.lockfile");
        touch(root, "buildSrc/gradle.lockfile");
        touch(root, "included/settings.gradle.kts");
        touch(root, "included/gradle.lockfile");
        touch(root, "included/sub/gradle.lockfile");

        let nested = |rel: &str| in_nested_build(root, &root.join(rel));

        assert!(!nested("gradle.lockfile"));
        assert!(!nested("app/gradle.lockfile"));
        assert!(nested("buildSrc/gradle.lockfile"));
        assert!(nested("included/gradle.lockfile"));
        assert!(nested("included/sub/gradle.lockfile"));
    }

    #[test]
    fn lock_set_collects_both_lock_names_in_every_project() {
        let dir = tempfile::tempdir().expect("dir");
        for rel in [
            "gradle.lockfile",
            "buildscript-gradle.lockfile",
            "app/gradle.lockfile",
            "libs/core/gradle.lockfile",
            "app/other.lockfile",
        ] {
            touch(dir.path(), rel);
        }

        let set = lock_set(dir.path()).expect("lock set").unified;

        assert_eq!(
            names(dir.path(), &set),
            [
                "app/gradle.lockfile",
                "buildscript-gradle.lockfile",
                "gradle.lockfile",
                "libs/core/gradle.lockfile"
            ]
        );
    }

    #[test]
    fn lock_set_skips_build_and_hidden_directories() {
        let dir = tempfile::tempdir().expect("dir");
        for rel in [
            "gradle.lockfile",
            "build/gradle.lockfile",
            ".gradle/gradle.lockfile",
            ".hidden/sub/gradle.lockfile",
        ] {
            touch(dir.path(), rel);
        }

        let set = lock_set(dir.path()).expect("lock set").unified;

        assert_eq!(names(dir.path(), &set), ["gradle.lockfile"]);
    }

    #[test]
    fn lock_set_ignores_a_dependency_locks_dir_outside_gradle() {
        let dir = tempfile::tempdir().expect("dir");
        touch(dir.path(), "other/dependency-locks/x.lockfile");

        assert!(lock_set(dir.path()).expect("lock set").unified.is_empty());
    }

    #[test]
    fn lock_set_refuses_more_than_the_file_cap() {
        let dir = tempfile::tempdir().expect("dir");
        for index in 0..=MAX_LOCK_FILES {
            touch(dir.path(), &format!("p{index}/gradle.lockfile"));
        }

        assert_matches!(
            lock_set(dir.path()),
            Err(LockSetError::Refused(
                UnsupportedReason::LockfileSetTooLarge
            ))
        );
    }

    #[test]
    fn lock_set_refuses_paths_over_the_byte_cap() {
        let dir = tempfile::tempdir().expect("dir");
        let long = "d".repeat(200);
        for index in 0..150 {
            touch(dir.path(), &format!("{long}{index}/gradle.lockfile"));
        }

        assert_matches!(
            lock_set(dir.path()),
            Err(LockSetError::Refused(
                UnsupportedReason::LockfileSetTooLarge
            ))
        );
    }

    #[cfg(unix)]
    #[test]
    fn lock_set_does_not_follow_symlinked_directories() {
        let dir = tempfile::tempdir().expect("dir");
        let outside = tempfile::tempdir().expect("outside");
        touch(outside.path(), "gradle.lockfile");
        std::os::unix::fs::symlink(outside.path(), dir.path().join("link")).expect("symlink");

        assert!(lock_set(dir.path()).expect("lock set").unified.is_empty());
    }
}
