//! `gradle.lockfile` provider: resolves in-use versions from Gradle dependency locking.
//!
//! Only the lock files in the manifest's own directory are read (a catalog in
//! `<project>/gradle/` also consults the project root): `gradle.lockfile` for the project's
//! dependencies and `buildscript-gradle.lockfile` for `buildscript { }` classpath dependencies,
//! kept apart by [`LockScope`]. The legacy `gradle/dependency-locks/` layout is not supported.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::pin::Pin;

use deps_core::LockScope;
use deps_core::lockfile::{
    LockFileProvider, ResolvedPackage, ResolvedPackages, ResolvedSource,
    locate_lockfile_for_manifest_with_max_depth, read_and_parse_lockfile,
    resolve_manifest_file_path,
};
use url::Url;

/// File name of Gradle's dependency-locking lock file.
pub const LOCKFILE_NAME: &str = "gradle.lockfile";

/// File name of the lock file Gradle writes for `buildscript { }` classpath dependencies.
pub const BUILDSCRIPT_LOCKFILE_NAME: &str = "buildscript-gradle.lockfile";

const CATALOG_FILE_NAME: &str = "libs.versions.toml";
const CATALOG_DIR_NAME: &str = "gradle";

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
    }

    fn companion_lockfiles(&self, located: &Path) -> Vec<PathBuf> {
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

/// The scope a Gradle lock file's entries belong to, by its file name.
fn scope_of(path: &Path) -> LockScope {
    if path
        .file_name()
        .is_some_and(|name| name == BUILDSCRIPT_LOCKFILE_NAME)
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
    let mut parts = coordinate.split(':');
    let (group, artifact, version) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() || [group, artifact, version].iter().any(|s| s.is_empty()) {
        return None;
    }
    Some((format!("{group}:{artifact}"), version.to_owned()))
}

/// Fuzz-only entry point for [`parse_gradle_lockfile`]; gated on the `fuzzing` feature so it
/// stays out of the default public API.
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub fn fuzz_parse_gradle_lock(content: &str) {
    let _ = parse_gradle_lockfile(content);
}
