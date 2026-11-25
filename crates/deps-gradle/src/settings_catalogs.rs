//! Version catalogs declared in `settings.gradle(.kts)` under names static routing misses (#2161).
//!
//! `versionCatalogs { create("x") { from(files("gradle/deps.toml")) } }` makes an arbitrary
//! `*.toml` a Gradle catalog. [`SettingsCatalogCache::declares`] answers whether the nearest
//! settings file declares a given candidate, reading settings through an mtime-gated cache.
//!
//! A settings file contributes at most [`MAX_DECLARED_CATALOGS`] declarations; later ones are
//! ignored (those catalogs stay unrecognized) and the cap is logged once per settings change.
//!
//! Limitations:
//! - a catalog outside the settings file's directory subtree is not recognized;
//! - the CLI walk skips hidden names, so a declared catalog with a hidden name is not walked;
//! - a document opened before its declaration exists stays untracked until reopened;
//! - settings are scanned line by line: only lines starting with `//` are skipped, so a
//!   declaration inside a `/* ... */` comment, or in a trailing `//` comment after code on the
//!   same line, is still claimed; a `from(` call split across lines is missed; and a brace
//!   inside a string literal in the block can end the block early.

use std::collections::HashSet;
use std::path::{Component, Path, PathBuf};

use deps_core::{DEFAULT_MAX_CACHED_FILES, MtimeFileCache, fs_probe};

const SETTINGS_FILE_NAMES: [&str; 2] = ["settings.gradle.kts", "settings.gradle"];

/// Most catalog declarations one settings file contributes, bounding both the memory kept per
/// cached settings file and the work an adversarial settings file can cause.
pub(crate) const MAX_DECLARED_CATALOGS: usize = 256;

/// A catalog path declared in a settings file: relative to the settings directory, made only
/// of normal components, with no `$` interpolation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DeclaredCatalogFile(PathBuf);

impl DeclaredCatalogFile {
    /// Validates a declared path; `None` for absolute, parent-traversing, empty or interpolated paths.
    pub(crate) fn parse(raw: &str) -> Option<Self> {
        if raw.contains('$') {
            return None;
        }
        let mut normalized = PathBuf::new();
        for component in Path::new(raw).components() {
            match component {
                Component::CurDir => {}
                Component::Normal(part) => normalized.push(part),
                Component::ParentDir | Component::RootDir | Component::Prefix(_) => return None,
            }
        }
        (!normalized.as_os_str().is_empty()).then_some(Self(normalized))
    }
}

/// The catalogs one settings file declares: a bounded set keyed by normalized relative path, so
/// a probe is one hash lookup however many declarations the file holds.
#[derive(Debug, Default)]
pub(crate) struct DeclaredCatalogs {
    files: HashSet<PathBuf>,
    truncated: bool,
}

impl DeclaredCatalogs {
    /// Adds a declaration; `false` once [`MAX_DECLARED_CATALOGS`] is reached, after which the
    /// set is marked truncated and the caller should stop scanning.
    pub(crate) fn insert(&mut self, file: DeclaredCatalogFile) -> bool {
        if self.files.len() >= MAX_DECLARED_CATALOGS && !self.files.contains(&file.0) {
            self.truncated = true;
            return false;
        }
        self.files.insert(file.0);
        true
    }

    /// Whether `relative` (a path below the settings directory) is declared.
    pub(crate) fn contains(&self, relative: &Path) -> bool {
        self.files.contains(relative)
    }

    /// Whether declarations beyond [`MAX_DECLARED_CATALOGS`] were dropped.
    pub(crate) const fn is_truncated(&self) -> bool {
        self.truncated
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.files.len()
    }
}

/// mtime-gated cache of the catalogs each settings file declares.
#[derive(Debug)]
pub(crate) struct SettingsCatalogCache(MtimeFileCache<DeclaredCatalogs>);

impl SettingsCatalogCache {
    pub(crate) fn new() -> Self {
        Self(MtimeFileCache::new(
            DEFAULT_MAX_CACHED_FILES,
            "gradle settings catalogs",
        ))
    }

    /// Whether the nearest settings file above `candidate` declares it as a version catalog.
    ///
    /// Makes no filesystem call unless `candidate` is an absolute `.toml` path; may block.
    pub(crate) fn declares(&self, candidate: &Path) -> bool {
        let is_toml = candidate
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .is_some_and(crate::is_catalog_file_name);
        if !candidate.is_absolute() || !is_toml {
            return false;
        }
        let Some(parent) = candidate.parent() else {
            return false;
        };
        for dir in fs_probe::config_ancestors(parent) {
            let settings: Vec<PathBuf> = SETTINGS_FILE_NAMES
                .iter()
                .map(|name| dir.join(name))
                .filter(|path| fs_probe::is_file(path))
                .collect();
            if settings.is_empty() {
                continue;
            }
            let Ok(relative) = candidate.strip_prefix(dir) else {
                return false;
            };
            return settings.iter().any(|path| {
                self.0
                    .get_or_parse(path, crate::parser::settings::declared_catalog_files)
                    .is_some_and(|declared| declared.contains(relative))
            });
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn declaration(index: usize) -> DeclaredCatalogFile {
        DeclaredCatalogFile::parse(&format!("gradle/c{index}.toml")).unwrap()
    }

    #[test]
    fn insert_stops_at_the_cap_and_marks_the_set_truncated() {
        let mut declared = DeclaredCatalogs::default();

        for index in 0..MAX_DECLARED_CATALOGS {
            assert!(declared.insert(declaration(index)));
        }
        assert!(!declared.is_truncated());
        assert!(
            declared.insert(declaration(0)),
            "a repeat of a kept entry is not an overflow"
        );
        assert!(!declared.insert(declaration(MAX_DECLARED_CATALOGS)));

        assert!(declared.is_truncated());
        assert_eq!(declared.len(), MAX_DECLARED_CATALOGS);
        assert!(declared.contains(Path::new("gradle/c255.toml")));
        assert!(!declared.contains(Path::new("gradle/c256.toml")));
    }

    #[test]
    fn a_settings_file_with_more_declarations_than_the_cap_keeps_only_the_first_ones() {
        let _guard = fs_probe::snapshot_guard();
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let mut settings = String::from("versionCatalogs {\n");
        for index in 0..=MAX_DECLARED_CATALOGS * 2 {
            settings.push_str(&format!("  from(files(\"gradle/c{index}.toml\"))\n"));
        }
        settings.push_str("}\n");
        let declared = crate::parser::settings::declared_catalog_files(&settings);
        std::fs::write(root.join("settings.gradle.kts"), settings).unwrap();
        let cache = SettingsCatalogCache::new();

        assert_eq!(declared.len(), MAX_DECLARED_CATALOGS);
        assert!(declared.is_truncated());
        assert!(cache.declares(&root.join("gradle/c0.toml")));
        assert!(cache.declares(&root.join(format!("gradle/c{}.toml", MAX_DECLARED_CATALOGS - 1))));
        assert!(!cache.declares(&root.join(format!("gradle/c{MAX_DECLARED_CATALOGS}.toml"))));
        assert!(!cache.declares(&root.join("other/u.toml")));
    }
}
