//! `gradle.lockfile` provider: resolves in-use versions from Gradle dependency locking.
//!
//! Only the lock files in the manifest's own directory are read (a catalog in
//! `<project>/gradle/` also consults the project root): `gradle.lockfile` for the project's
//! dependencies and `buildscript-gradle.lockfile` for `buildscript { }` classpath dependencies,
//! kept apart by [`LockScope`]. When neither exists, the legacy
//! `<project>/gradle/dependency-locks/<configuration>.lockfile` layout supplies the lock set
//! (one file per configuration, merged); it is never read next to a unified file.

use std::collections::{BTreeSet, HashSet};
use std::path::{Path, PathBuf};
use std::pin::Pin;

use deps_core::LockScope;
use deps_core::lockfile::{
    LockFileProvider, MAX_LOCKFILE_BYTES, ResolvedPackage, ResolvedPackages, ResolvedSource,
    locate_lockfile_for_manifest_with_max_depth, read_and_parse_lockfile, read_lockfile_content,
    resolve_manifest_file_path,
};
use url::Url;

/// File name of Gradle's dependency-locking lock file.
pub const LOCKFILE_NAME: &str = "gradle.lockfile";

/// File name of the lock file Gradle writes for `buildscript { }` classpath dependencies.
pub const BUILDSCRIPT_LOCKFILE_NAME: &str = "buildscript-gradle.lockfile";

const CATALOG_FILE_NAME: &str = "libs.versions.toml";
const CATALOG_DIR_NAME: &str = "gradle";

const LEGACY_LOCKS_DIR_NAME: &str = "dependency-locks";
const LEGACY_LOCKFILE_SUFFIX: &str = ".lockfile";
const BUILDSCRIPT_PREFIX: &str = "buildscript-";
const SETTINGS_PREFIX: &str = "settings-";

/// Eligible legacy lock files considered per directory.
const MAX_LEGACY_DIR_ENTRIES: usize = 1024;

/// Directory entries examined per legacy `read_dir`, so a directory stuffed with files cannot
/// make one locate or companion call unbounded.
const MAX_LEGACY_SCAN_ENTRIES: usize = 16 * 1024;

/// Legacy lock files parsed per set besides the located one.
const MAX_LEGACY_COMPANIONS: usize = 128;

/// Which of Gradle's two on-disk lock layouts a lock file belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GradleLockLayout {
    /// `gradle.lockfile` and `buildscript-gradle.lockfile` next to the build script.
    Unified,
    /// `gradle/dependency-locks/<configuration>.lockfile`, one file per configuration.
    Legacy,
}

impl GradleLockLayout {
    fn of(path: &Path) -> Self {
        let unified_name = path
            .file_name()
            .is_some_and(|name| name == LOCKFILE_NAME || name == BUILDSCRIPT_LOCKFILE_NAME);
        let in_legacy_dir = path
            .parent()
            .and_then(Path::file_name)
            .is_some_and(|dir| dir == LEGACY_LOCKS_DIR_NAME);
        if !unified_name && in_legacy_dir {
            Self::Legacy
        } else {
            Self::Unified
        }
    }
}

/// Whether `name` is a legacy per-configuration lock file name Gradle reads for dependencies
/// (`settings-*` locks belong to settings classpath resolution and are skipped).
fn is_legacy_lock_name(name: &str) -> bool {
    name.ends_with(LEGACY_LOCKFILE_SUFFIX) && !name.starts_with(SETTINGS_PREFIX)
}

/// The first [`MAX_LEGACY_DIR_ENTRIES`] eligible lock files of a legacy lock directory by name,
/// chosen from at most [`MAX_LEGACY_SCAN_ENTRIES`] directory entries.
///
/// Eligibility is decided before the cap, so unrelated entries never crowd out lock files and
/// the located file is the name-first one whenever the directory is within the scan bound.
fn legacy_lock_files(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut files: Vec<PathBuf> = entries
        .take(MAX_LEGACY_SCAN_ENTRIES)
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name().to_str().is_some_and(is_legacy_lock_name))
        .map(|entry| entry.path())
        .collect();
    files.sort();
    files.truncate(MAX_LEGACY_DIR_ENTRIES);
    files.retain(|path| deps_core::fs_probe::is_file(path));
    files
}

/// Lock file provider for Gradle's `gradle.lockfile` (dependency locking).
///
/// Lines have the form `group:artifact:version=config1,config2`; each is keyed by the
/// Maven coordinate `group:artifact`, matching manifest dependency names.
///
/// # Examples
///
/// ```
/// use deps_gradle::GradleLockParser;
/// use deps_gradle::lockfile::parse_gradle_lockfile;
///
/// let packages = parse_gradle_lockfile("com.google.guava:guava:32.1.2-jre=compileClasspath\n");
/// assert_eq!(packages.version("com.google.guava:guava"), Some("32.1.2-jre"));
/// let _ = GradleLockParser;
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct GradleLockParser;

impl LockFileProvider for GradleLockParser {
    fn locate_lockfile(&self, manifest_uri: &Url) -> Option<PathBuf> {
        // Only the standard `<project>/gradle/libs.versions.toml` layout looks one level up;
        // Gradle locks per project, so any other catalog location must not borrow a
        // neighbouring project's lock file.
        let in_gradle_dir = resolve_manifest_file_path(manifest_uri).is_some_and(|path| {
            path.file_name()
                .is_some_and(|name| name == CATALOG_FILE_NAME)
                && path
                    .parent()
                    .and_then(Path::file_name)
                    .is_some_and(|dir| dir == CATALOG_DIR_NAME)
        });
        locate_lockfile_for_manifest_with_max_depth(
            manifest_uri,
            &[LOCKFILE_NAME, BUILDSCRIPT_LOCKFILE_NAME],
            usize::from(in_gradle_dir),
        )
        .or_else(|| {
            let manifest_dir = resolve_manifest_file_path(manifest_uri)?
                .parent()?
                .to_path_buf();
            let project_dir = if in_gradle_dir {
                manifest_dir.parent()?.to_path_buf()
            } else {
                manifest_dir
            };
            legacy_lock_files(
                &project_dir
                    .join(CATALOG_DIR_NAME)
                    .join(LEGACY_LOCKS_DIR_NAME),
            )
            .into_iter()
            .next()
        })
    }

    fn lock_set_root<'p>(&self, lockfile: &'p Path) -> Option<&'p Path> {
        match GradleLockLayout::of(lockfile) {
            GradleLockLayout::Unified => lockfile.parent(),
            // file -> dependency-locks -> gradle -> project
            GradleLockLayout::Legacy => lockfile.ancestors().nth(3),
        }
    }

    fn companion_lockfiles(&self, located: &Path) -> Vec<PathBuf> {
        if GradleLockLayout::of(located) == GradleLockLayout::Legacy {
            let Some(dir) = located.parent() else {
                return Vec::new();
            };
            // The directory is a companion so its mtime stamp catches files appearing or
            // vanishing; the per-file stamps catch edits.
            return std::iter::once(dir.to_path_buf())
                .chain(
                    legacy_lock_files(dir)
                        .into_iter()
                        .filter(|path| path != located)
                        .take(MAX_LEGACY_COMPANIONS),
                )
                .collect();
        }
        let other = match scope_of(located) {
            LockScope::Project => BUILDSCRIPT_LOCKFILE_NAME,
            LockScope::BuildScript => LOCKFILE_NAME,
        };
        located
            .parent()
            .map(|dir| dir.join(other))
            .into_iter()
            .collect()
    }

    fn parse_lockfile<'a>(
        &'a self,
        lockfile_path: &'a Path,
    ) -> Pin<Box<dyn std::future::Future<Output = deps_core::Result<ResolvedPackages>> + Send + 'a>>
    {
        Box::pin(async move {
            if GradleLockLayout::of(lockfile_path) == GradleLockLayout::Legacy {
                return parse_legacy_set(lockfile_path, self.companion_lockfiles(lockfile_path))
                    .await;
            }
            let mut packages = parse_scoped_file(lockfile_path).await?;
            for companion in self.companion_lockfiles(lockfile_path) {
                // Absence is normal (most projects have no buildscript locking). An unreadable
                // companion (symlink, oversized) degrades to the located file's data alone
                // rather than dropping the whole lock set.
                if deps_core::fs_probe::is_file(&companion) {
                    let scoped = match parse_scoped_file(&companion).await {
                        Ok(scoped) => scoped,
                        Err(e) => {
                            tracing::warn!(
                                path = %companion.display(),
                                "ignoring unreadable companion lock file: {e}"
                            );
                            continue;
                        }
                    };
                    for (_, entries) in scoped.iter_all() {
                        for entry in entries {
                            packages.insert(entry.clone());
                        }
                    }
                }
            }
            Ok(packages)
        })
    }
}

/// Reads the legacy lock set (the located file first, then its file companions), merging every
/// distinct `(scope, name, version)` once.
///
/// The total bytes read are capped at [`MAX_LOCKFILE_BYTES`]: a file that would exceed the
/// budget is dropped with a warning and what was read so far is kept.
async fn parse_legacy_set(
    located: &Path,
    companions: Vec<PathBuf>,
) -> deps_core::Result<ResolvedPackages> {
    let mut seen: HashSet<(LockScope, String, String)> = HashSet::new();
    let mut packages = ResolvedPackages::new();
    let mut budget = MAX_LOCKFILE_BYTES;
    let files = std::iter::once(located.to_path_buf())
        .chain(companions.into_iter().filter(|path| path.is_file()));
    for path in files {
        let content = match read_lockfile_content(&path, LOCKFILE_NAME).await {
            Ok(content) => content,
            Err(e) if path == located => return Err(e),
            Err(e) => {
                tracing::warn!(path = %path.display(), "ignoring unreadable legacy lock file: {e}");
                continue;
            }
        };
        let len = content.len() as u64;
        if len > budget {
            tracing::warn!(
                path = %path.display(),
                "legacy lock set exceeds the read budget; remaining files are ignored"
            );
            break;
        }
        budget -= len;
        let scope = scope_of(&path);
        for (name, version) in legacy_coordinates(&content) {
            if seen.insert((scope, name.clone(), version.clone())) {
                packages.insert(
                    ResolvedPackage::new(name, version, ResolvedSource::RegistryPin)
                        .with_lock_scope(scope),
                );
            }
        }
    }
    Ok(packages)
}

/// `(group:artifact, version)` of every coordinate line of a legacy lock file; the optional
/// `=config,...` suffix, comments, blank lines and malformed lines (including `empty=`) are
/// dropped.
fn legacy_coordinates(content: &str) -> impl Iterator<Item = (String, String)> + '_ {
    content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter_map(|line| {
            let coordinate = line
                .split_once('=')
                .map_or(line, |(coordinate, _)| coordinate);
            parse_coordinate(coordinate)
        })
}

/// The scope a Gradle lock file's entries belong to, by its file name.
fn scope_of(path: &Path) -> LockScope {
    if path
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.starts_with(BUILDSCRIPT_PREFIX))
    {
        LockScope::BuildScript
    } else {
        LockScope::Project
    }
}

async fn parse_scoped_file(path: &Path) -> deps_core::Result<ResolvedPackages> {
    let scope = scope_of(path);
    let file_type = match scope {
        LockScope::Project => LOCKFILE_NAME,
        LockScope::BuildScript => BUILDSCRIPT_LOCKFILE_NAME,
    };
    read_and_parse_lockfile(path, file_type, move |content| {
        Ok(parse_scoped_content(&content, scope))
    })
    .await
}

/// Parses `gradle.lockfile` content into resolved packages.
///
/// Comments, blank lines, the `empty=` marker and malformed lines are skipped; every
/// distinct version of a coordinate is kept.
#[must_use]
pub fn parse_gradle_lockfile(content: &str) -> ResolvedPackages {
    parse_scoped_content(content, LockScope::Project)
}

fn parse_scoped_content(content: &str, scope: LockScope) -> ResolvedPackages {
    let distinct: BTreeSet<(String, String)> = content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter_map(|line| {
            let parsed = parse_coordinate_line(line);
            if parsed.is_none() {
                tracing::debug!("skipping malformed gradle.lockfile line");
            }
            parsed
        })
        .collect();
    let mut packages = ResolvedPackages::new();
    for (name, version) in distinct {
        packages.insert(
            ResolvedPackage::new(name, version, ResolvedSource::RegistryPin).with_lock_scope(scope),
        );
    }
    packages
}

fn parse_coordinate_line(line: &str) -> Option<(String, String)> {
    let (coordinate, _configurations) = line.split_once('=')?;
    parse_coordinate(coordinate)
}

fn parse_coordinate(coordinate: &str) -> Option<(String, String)> {
    let mut parts = coordinate.split(':');
    let (group, artifact, version) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() || [group, artifact, version].iter().any(|s| s.is_empty()) {
        return None;
    }
    Some((format!("{group}:{artifact}"), version.to_owned()))
}

/// Fuzz-only entry point for the `gradle.lockfile` line parsers (unified and legacy grammars);
/// gated on the `fuzzing` feature so it stays out of the default public API.
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub fn fuzz_parse_gradle_lock(content: &str) {
    let _ = parse_gradle_lockfile(content);
    let _ = legacy_coordinates(content).count();
}
