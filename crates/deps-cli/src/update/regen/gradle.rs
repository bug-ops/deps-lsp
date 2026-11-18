//! Regeneration for Gradle dependency-lock files (#2085).
//!
//! Gradle runs from the build root, so one run may rewrite the lock file of every project of the
//! build. The whole lock set is snapshotted before the first spawn and reported as companions.

use std::path::{Path, PathBuf};

use super::command::NonEmpty;
use super::command::gradle::{GradleCoordArg, GradleProjectPath};
use super::{
    Companion, Invocation, LockfileOutcome, NotApplicableReason, PinCheck, Program,
    RegenerationError, Session, UnsupportedReason, same_file, unsafe_argument, unsupported,
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
    /// A directory could not be listed.
    Unreadable,
}

impl From<UnsupportedReason> for LockSetError {
    fn from(reason: UnsupportedReason) -> Self {
        Self::Refused(reason)
    }
}

/// Every Gradle lock file under `root`, sorted.
///
/// The walk never follows symlinks and skips `build/`, `.gradle/` and other hidden directories.
/// A `gradle/dependency-locks` directory (the legacy layout) refuses the build; so does a walk
/// or a set over the bounds above.
fn lock_set(root: &Path) -> Result<Vec<PathBuf>, LockSetError> {
    let mut pending = vec![(root.to_path_buf(), 0_usize)];
    let mut files: Vec<PathBuf> = Vec::new();
    let mut path_bytes = 0_usize;
    let mut visited = 0_usize;
    while let Some((dir, depth)) = pending.pop() {
        let entries = std::fs::read_dir(&dir).map_err(|_| LockSetError::Unreadable)?;
        for entry in entries {
            let entry = entry.map_err(|_| LockSetError::Unreadable)?;
            visited += 1;
            if visited > MAX_WALK_ENTRIES {
                return Err(UnsupportedReason::LockfileSetTooLarge.into());
            }
            let kind = entry.file_type().map_err(|_| LockSetError::Unreadable)?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if kind.is_dir() {
                let legacy = name == "dependency-locks"
                    && dir.file_name().is_some_and(|parent| parent == "gradle");
                if legacy {
                    return Err(UnsupportedReason::LegacyLockLayout.into());
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
                path_bytes += path.as_os_str().len();
                if files.len() >= MAX_LOCK_FILES || path_bytes > MAX_LOCK_PATH_BYTES {
                    return Err(UnsupportedReason::LockfileSetTooLarge.into());
                }
                files.push(path);
            }
        }
    }
    files.sort();
    Ok(files)
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

/// The distinct projects owning the lock files of `set`, one per lock directory below `root`.
///
/// # Errors
///
/// [`RegenerationError::UnsafeArgument`] when a lock directory cannot be a safe project path;
/// nothing has been spawned yet.
fn lock_projects(
    root: &Path,
    set: &[PathBuf],
) -> Result<NonEmpty<GradleProjectPath>, RegenerationError> {
    let mut projects: Vec<GradleProjectPath> = Vec::new();
    for lock in set {
        let relative = lock
            .parent()
            .and_then(|dir| dir.strip_prefix(root).ok())
            .unwrap_or(lock);
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
    /// the manifest chooses). The legacy `gradle/dependency-locks` layout is refused.
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
            Err(LockSetError::Unreadable) => {
                return Err(RegenerationError::SnapshotFailed {
                    path: self.target.display_path.to_path_buf(),
                });
            }
        };
        if !set.iter().any(|lock| same_file(Some(lock), Some(&located))) {
            return Ok(unsupported(
                Some(display),
                UnsupportedReason::LockfileOwnershipMismatch,
            ));
        }
        if set.iter().any(|lock| in_nested_build(&root, lock)) {
            return Ok(unsupported(
                Some(display),
                UnsupportedReason::LockfileOwnershipMismatch,
            ));
        }
        for lock in &set {
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

        let projects = lock_projects(&root, &set)?;

        let to_capture: Vec<&Path> = set.iter().map(PathBuf::as_path).collect();
        self.capture(&to_capture)?;
        self.runner
            .run(
                &Invocation::gradle_update_locks(&root, &projects, &coordinates),
                self.deadline,
            )
            .await?;
        let companions = set
            .iter()
            .filter(|lock| !same_file(Some(lock), Some(&located)))
            .map(|lock| Companion::File(self.display_lock_path(lock).real_path().to_path_buf()))
            .collect();
        // Exact, not satisfying: the Gradle grammar has no `>=target` matcher for `SatisfiesInLock`.
        self.verified_with(Program::Gradle, &located, companions, PinCheck::ExactInLock)
            .await
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

        let set = lock_set(dir.path()).expect("lock set");

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

        let set = lock_set(dir.path()).expect("lock set");

        assert_eq!(names(dir.path(), &set), ["gradle.lockfile"]);
    }

    #[test]
    fn lock_set_refuses_the_legacy_layout_anywhere() {
        let dir = tempfile::tempdir().expect("dir");
        touch(dir.path(), "gradle.lockfile");
        touch(
            dir.path(),
            "sub/gradle/dependency-locks/compileClasspath.lockfile",
        );

        assert_matches!(
            lock_set(dir.path()),
            Err(LockSetError::Refused(UnsupportedReason::LegacyLockLayout))
        );
    }

    #[test]
    fn lock_set_ignores_a_dependency_locks_dir_outside_gradle() {
        let dir = tempfile::tempdir().expect("dir");
        touch(dir.path(), "other/dependency-locks/x.lockfile");

        assert!(lock_set(dir.path()).expect("lock set").is_empty());
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

        assert!(lock_set(dir.path()).expect("lock set").is_empty());
    }
}
