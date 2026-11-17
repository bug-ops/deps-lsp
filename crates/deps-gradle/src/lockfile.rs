//! `gradle.lockfile` provider: resolves in-use versions from Gradle dependency locking.
//!
//! Only `gradle.lockfile` in the manifest's own directory is read (a catalog in
//! `<project>/gradle/` also consults the project root). `buildscript-gradle.lockfile` and
//! the legacy `gradle/dependency-locks/` layout are not supported.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::pin::Pin;

use deps_core::lockfile::{
    LockFileProvider, ResolvedPackage, ResolvedPackages, ResolvedSource,
    locate_lockfile_for_manifest_with_max_depth, read_and_parse_lockfile,
    resolve_manifest_file_path,
};
use url::Url;

/// File name of Gradle's dependency-locking lock file.
pub const LOCKFILE_NAME: &str = "gradle.lockfile";

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
            &[LOCKFILE_NAME],
            usize::from(in_gradle_dir),
        )
    }

    fn parse_lockfile<'a>(
        &'a self,
        lockfile_path: &'a Path,
    ) -> Pin<Box<dyn std::future::Future<Output = deps_core::Result<ResolvedPackages>> + Send + 'a>>
    {
        Box::pin(async move {
            read_and_parse_lockfile(lockfile_path, LOCKFILE_NAME, |content| {
                Ok(parse_gradle_lockfile(&content))
            })
            .await
        })
    }
}

/// Parses `gradle.lockfile` content into resolved packages.
///
/// Comments, blank lines, the `empty=` marker and malformed lines are skipped; every
/// distinct version of a coordinate is kept.
#[must_use]
pub fn parse_gradle_lockfile(content: &str) -> ResolvedPackages {
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
        packages.insert(ResolvedPackage::new(
            name,
            version,
            ResolvedSource::RegistryPin,
        ));
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
