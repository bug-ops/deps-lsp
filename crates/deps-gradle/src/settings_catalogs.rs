//! Version catalogs declared in `settings.gradle(.kts)` under names static routing misses (#2161).
//!
//! `versionCatalogs { create("x") { from(files("gradle/deps.toml")) } }` makes an arbitrary
//! `*.toml` a Gradle catalog. [`SettingsCatalogCache::declares`] answers whether a settings
//! file in the candidate's ancestor directories declares it (the nearest
//! [`MAX_SETTINGS_ANCESTORS`] settings-bearing directories are consulted), reading settings
//! through an mtime-gated cache.
//!
//! A settings file contributes at most [`MAX_DECLARED_CATALOGS`] declarations; later ones are
//! ignored (those catalogs stay unrecognized) and the cap is logged once per settings change.
//! Settings text is tokenized with the shared Groovy/Kotlin code scanner, so comments and string
//! literals never count as code.
//!
//! Limitations:
//! - a catalog outside the settings file's directory subtree is not recognized;
//! - only the nearest [`MAX_SETTINGS_ANCESTORS`] (4) settings-bearing ancestor directories are
//!   consulted, so a declaration in a settings file further up is not seen;
//! - the CLI walk skips hidden names, so a declared catalog with a hidden name is not walked;
//! - recognition is decided once, when a document is opened: a document opened before its
//!   declaration exists stays untracked until reopened, and a tracked document whose declaring
//!   settings file later changes or drops the declaration stays tracked as a catalog.

use std::collections::HashSet;
use std::path::{Component, Path, PathBuf};

use deps_core::gradle_layout::{GradleSettingsFile, is_version_catalog_file};
use deps_core::{DEFAULT_MAX_CACHED_FILES, MtimeFileCache, fs_probe};

/// Most catalog declarations one settings file contributes, bounding both the memory kept per
/// cached settings file and the work an adversarial settings file can cause.
pub(crate) const MAX_DECLARED_CATALOGS: usize = 256;

/// Most settings-bearing ancestor directories one probe consults. Once the settings cache is
/// full it stops caching, so every consulted ancestor costs a fresh read and tokenize (up to
/// the 8 MiB read cap each); this bounds that amplification to a few parses per probe while
/// covering a root build with nested composite builds.
pub(crate) const MAX_SETTINGS_ANCESTORS: usize = 4;

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

    /// Whether a settings file above `candidate` declares it as a version catalog.
    ///
    /// Consults at most [`MAX_SETTINGS_ANCESTORS`] settings-bearing ancestor directories,
    /// nearest first. Makes no filesystem call unless `candidate` is an absolute `.toml` path;
    /// may block.
    pub(crate) fn declares(&self, candidate: &Path) -> bool {
        if !candidate.is_absolute() || !is_version_catalog_file(candidate) {
            return false;
        }
        let Some(parent) = candidate.parent() else {
            return false;
        };
        fs_probe::config_ancestors(parent)
            .filter_map(|dir| {
                let settings: Vec<PathBuf> = GradleSettingsFile::ALL
                    .iter()
                    .map(|settings| dir.join(settings.file_name()))
                    .filter(|path| fs_probe::is_file(path))
                    .collect();
                (!settings.is_empty()).then_some((dir, settings))
            })
            .take(MAX_SETTINGS_ANCESTORS)
            .any(|(dir, settings)| {
                let Ok(relative) = candidate.strip_prefix(dir) else {
                    return false;
                };
                settings.iter().any(|path| {
                    self.0
                        .get_or_parse(path, crate::parser::settings::declared_catalog_files)
                        .is_some_and(|declared| declared.contains(relative))
                })
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn declaration(index: usize) -> DeclaredCatalogFile {
        DeclaredCatalogFile::parse(&format!("gradle/c{index}.toml")).unwrap()
    }

    /// Builds `levels` nested directories, each holding a settings file; only the outermost
    /// declares the catalog at the innermost directory. Returns that catalog's path.
    fn nested_project(root: &Path, levels: usize) -> PathBuf {
        let mut dir = root.to_path_buf();
        let mut relative = PathBuf::new();
        for level in 0..levels {
            std::fs::create_dir_all(&dir).unwrap();
            let settings = if level == 0 {
                let target = PathBuf::from_iter((1..levels).map(|n| format!("n{n}")));
                format!(
                    "versionCatalogs {{ create(\"d\") {{ from(files(\"{}\")) }} }}",
                    target.join("x.toml").display()
                )
            } else {
                "rootProject.name = \"nested\"\n".to_owned()
            };
            std::fs::write(dir.join("settings.gradle.kts"), settings).unwrap();
            relative.push(format!("n{}", level + 1));
            dir = root.join(&relative);
        }
        let leaf = root.join(PathBuf::from_iter((1..levels).map(|n| format!("n{n}"))));
        leaf.join("x.toml")
    }

    #[test]
    fn only_the_nearest_settings_bearing_ancestors_are_consulted() {
        let _guard = fs_probe::snapshot_guard();
        let within = tempfile::tempdir().unwrap();
        let beyond = tempfile::tempdir().unwrap();
        let within_catalog = nested_project(
            &within.path().canonicalize().unwrap(),
            MAX_SETTINGS_ANCESTORS,
        );
        let beyond_catalog = nested_project(
            &beyond.path().canonicalize().unwrap(),
            MAX_SETTINGS_ANCESTORS + 1,
        );
        let cache = SettingsCatalogCache::new();

        assert!(cache.declares(&within_catalog));
        assert!(
            !cache.declares(&beyond_catalog),
            "the outermost settings file is past the ancestor cap"
        );
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
