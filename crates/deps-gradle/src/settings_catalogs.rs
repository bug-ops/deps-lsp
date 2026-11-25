//! Version catalogs declared in `settings.gradle(.kts)` under names static routing misses (#2161).
//!
//! `versionCatalogs { create("x") { from(files("gradle/deps.toml")) } }` makes an arbitrary
//! `*.toml` a Gradle catalog, possibly through `..` in a directory that is not below the settings
//! file. [`SettingsCatalogCache::declares`] answers whether some settings file declares a given
//! path, comparing absolute lexical forms (`.`/`..` folded, no `canonicalize`, no symlink
//! resolution):
//!
//! 1. **Backward:** the settings files in the candidate's ancestor directories (the nearest
//!    [`MAX_SETTINGS_ANCESTORS`] settings-bearing directories).
//! 2. **Forward:** settings files in child directories of the candidate's nearest
//!    [`MAX_FORWARD_ANCESTORS`] ancestors, for sibling layouts. Bounded above by the outermost of
//!    the nearest `.git` ancestor and the caller's [`ClaimBound`]; with neither there is no
//!    forward lookup, and nothing above that limit is ever listed.
//!
//! Both read settings through an mtime-gated cache. A settings file contributes at most
//! [`MAX_DECLARED_CATALOGS`] declarations; later ones are ignored (those catalogs stay
//! unrecognized) and the cap is logged once per settings change. Settings text is tokenized with
//! the shared Groovy/Kotlin code scanner, so comments and string literals never count as code.
//!
//! The forward lookup is further bounded per directory listing ([`MAX_FORWARD_ENTRIES`] entries,
//! [`MAX_FORWARD_CHILDREN`] child directories, hidden and symlinked directories skipped), and by
//! a parse budget of [`MAX_RUN_PARSES`] cache-miss parses per cache instance. Cached settings
//! files are always consulted; only a file that would need parsing after the budget is spent is
//! skipped (so its declarations do not claim). Listing results are memoized per ancestor (at most
//! [`MAX_FORWARD_MEMO`], cleared when full);
//! [`SettingsCatalogCache::reset_forward`] drops the memo and refills the budget.
//!
//! Limitations:
//! - a catalog outside both the git project and the caller's bound is not recognized by the
//!   forward lookup;
//! - forward settings files two or more levels below an ancestor are not found;
//! - only the nearest [`MAX_SETTINGS_ANCESTORS`] (4) settings-bearing ancestor directories are
//!   consulted backward, so a declaration in a settings file further up is not seen;
//! - a settings file created in an already listed child directory is seen after
//!   [`SettingsCatalogCache::reset_forward`] or by a new instance.

use std::collections::{HashMap, HashSet};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::SystemTime;

use deps_core::ecosystem::ClaimBound;
use deps_core::gradle_layout::{GradleSettingsFile, is_version_catalog_file};
use deps_core::{DEFAULT_MAX_CACHED_FILES, MtimeFileCache, fs_probe};

/// Most catalog declarations one settings file contributes, bounding both the memory kept per
/// cached settings file and the work an adversarial settings file can cause.
pub(crate) const MAX_DECLARED_CATALOGS: usize = 256;

/// Most settings-bearing ancestor directories one backward probe consults. Together with the
/// forward bounds below, it caps the settings files one probe can read: this covers a root build
/// with nested composite builds.
pub(crate) const MAX_SETTINGS_ANCESTORS: usize = 4;

/// Candidate ancestors whose child directories a forward probe lists.
pub(crate) const MAX_FORWARD_ANCESTORS: usize = 2;

/// Most directory entries one forward listing reads.
pub(crate) const MAX_FORWARD_ENTRIES: usize = 256;

/// Most child directories one forward listing consults.
pub(crate) const MAX_FORWARD_CHILDREN: usize = 64;

/// Most cache-miss settings parses one cache instance performs for forward probes.
pub(crate) const MAX_RUN_PARSES: usize = 256;

/// Most ancestors, and separately directories with a known `.git` ancestor, kept memoized.
pub(crate) const MAX_FORWARD_MEMO: usize = 256;

/// A catalog path declared in a settings file: relative to the settings directory, possibly
/// through `..`, with no `$` interpolation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DeclaredCatalogFile(PathBuf);

impl DeclaredCatalogFile {
    /// Validates a declared path; `None` for absolute, empty or interpolated paths, and for any
    /// path that does not name a `.toml` file (Gradle accepts only TOML catalogs).
    pub(crate) fn parse(raw: &str) -> Option<Self> {
        if raw.contains('$') {
            return None;
        }
        let mut normalized = PathBuf::new();
        for component in Path::new(raw).components() {
            match component {
                Component::CurDir => {}
                Component::Normal(part) => normalized.push(part),
                Component::ParentDir => normalized.push(".."),
                Component::RootDir | Component::Prefix(_) => return None,
            }
        }
        is_version_catalog_file(&normalized).then_some(Self(normalized))
    }
}

/// The catalogs one settings file declares: a bounded set of relative paths. Paths without `..`
/// are matched by one hash lookup however many declarations the file holds.
#[derive(Debug, Default)]
pub(crate) struct DeclaredCatalogs {
    inside: HashSet<PathBuf>,
    traversing: HashSet<PathBuf>,
    truncated: bool,
}

impl DeclaredCatalogs {
    /// Adds a declaration; `false` once [`MAX_DECLARED_CATALOGS`] is reached, after which the
    /// set is marked truncated and the caller should stop scanning.
    pub(crate) fn insert(&mut self, file: DeclaredCatalogFile) -> bool {
        let traverses = file.0.components().any(|c| c == Component::ParentDir);
        let set = if traverses {
            &mut self.traversing
        } else {
            &mut self.inside
        };
        if set.contains(&file.0) {
            return true;
        }
        if self.inside.len() + self.traversing.len() >= MAX_DECLARED_CATALOGS {
            self.truncated = true;
            return false;
        }
        if traverses {
            self.traversing.insert(file.0);
        } else {
            self.inside.insert(file.0);
        }
        true
    }

    /// Whether `candidate` (absolute lexical form) is declared by the settings file in
    /// `settings_dir`.
    pub(crate) fn declares_file(&self, settings_dir: &Path, candidate: &Path) -> bool {
        candidate
            .strip_prefix(settings_dir)
            .is_ok_and(|relative| self.inside.contains(relative))
            || self
                .traversing
                .iter()
                .any(|relative| resolve(settings_dir, relative).as_deref() == Some(candidate))
    }

    /// The declared catalogs as absolute lexical paths.
    pub(crate) fn resolved<'a>(
        &'a self,
        settings_dir: &'a Path,
    ) -> impl Iterator<Item = PathBuf> + 'a {
        self.inside
            .iter()
            .chain(&self.traversing)
            .filter_map(move |relative| resolve(settings_dir, relative))
    }

    /// Whether declarations beyond [`MAX_DECLARED_CATALOGS`] were dropped.
    pub(crate) const fn is_truncated(&self) -> bool {
        self.truncated
    }

    #[cfg(test)]
    pub(crate) fn contains(&self, relative: &Path) -> bool {
        self.inside.contains(relative) || self.traversing.contains(relative)
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.inside.len() + self.traversing.len()
    }
}

/// `None` only when `settings_dir` is relative.
fn resolve(settings_dir: &Path, relative: &Path) -> Option<PathBuf> {
    fs_probe::lexically_normalize(&settings_dir.join(relative))
}

/// The settings files directly inside `dir`.
fn settings_files(dir: &Path) -> impl Iterator<Item = PathBuf> + '_ {
    GradleSettingsFile::ALL
        .iter()
        .map(|settings| dir.join(settings.file_name()))
        .filter(|path| fs_probe::is_file(path))
}

fn modified(path: &Path) -> Option<SystemTime> {
    fs_probe::metadata(path).ok()?.modified().ok()
}

/// What the child directories of one ancestor declare.
#[derive(Debug)]
struct ForwardDeclarations {
    dir_mtime: Option<SystemTime>,
    settings: Vec<(PathBuf, Option<SystemTime>)>,
    declared: HashSet<PathBuf>,
}

impl ForwardDeclarations {
    fn is_current(&self, ancestor: &Path) -> bool {
        self.dir_mtime.is_some()
            && modified(ancestor) == self.dir_mtime
            && self
                .settings
                .iter()
                .all(|(path, mtime)| modified(path) == *mtime)
    }
}

#[derive(Debug, Default)]
struct ForwardState {
    listings: HashMap<PathBuf, Arc<ForwardDeclarations>>,
    git_dirs: HashMap<PathBuf, Option<PathBuf>>,
}

/// mtime-gated cache of the catalogs each settings file declares, plus the memo and budget of
/// the forward lookup.
#[derive(Debug)]
pub(crate) struct SettingsCatalogCache {
    files: MtimeFileCache<DeclaredCatalogs>,
    forward: Mutex<ForwardState>,
    parses_used: AtomicUsize,
    budget_reported: AtomicBool,
}

impl SettingsCatalogCache {
    pub(crate) fn new() -> Self {
        Self {
            files: MtimeFileCache::new(DEFAULT_MAX_CACHED_FILES, "gradle settings catalogs"),
            forward: Mutex::default(),
            parses_used: AtomicUsize::new(0),
            budget_reported: AtomicBool::new(false),
        }
    }

    /// Drops the forward memo and refills the parse budget, after a settings file changed.
    pub(crate) fn reset_forward(&self) {
        *self.state() = ForwardState::default();
        self.parses_used.store(0, Ordering::Relaxed);
        self.budget_reported.store(false, Ordering::Relaxed);
    }

    /// Whether a settings file declares `candidate` as a version catalog, looking backward over
    /// its ancestors and then forward into sibling directories (see the module docs).
    ///
    /// Makes no filesystem call unless `candidate` is an absolute `.toml` path; may block.
    pub(crate) fn declares(&self, candidate: &Path, bound: Option<&ClaimBound>) -> bool {
        if !is_version_catalog_file(candidate) {
            return false;
        }
        let Some(candidate) = fs_probe::lexically_normalize(candidate) else {
            return false;
        };
        let Some(parent) = candidate.parent() else {
            return false;
        };
        self.declared_by_ancestor(parent, &candidate)
            || self.declared_by_sibling(parent, &candidate, bound)
    }

    /// The catalogs the settings file at `manifest` declares, as absolute lexical paths (at most
    /// [`MAX_DECLARED_CATALOGS`]); empty for any other file. Existence is not checked.
    pub(crate) fn declared_by(&self, manifest: &Path) -> Vec<PathBuf> {
        let is_settings = manifest.file_name().is_some_and(|name| {
            GradleSettingsFile::ALL
                .iter()
                .any(|settings| name == settings.file_name())
        });
        if !is_settings {
            return Vec::new();
        }
        let Some(manifest) = fs_probe::lexically_normalize(manifest) else {
            return Vec::new();
        };
        let (Some(dir), Some(declared)) = (manifest.parent(), self.parsed(&manifest)) else {
            return Vec::new();
        };
        let mut resolved: Vec<PathBuf> = declared.resolved(dir).collect();
        resolved.sort_unstable();
        resolved
    }

    fn parsed(&self, settings: &Path) -> Option<Arc<DeclaredCatalogs>> {
        self.files
            .get_or_parse(settings, crate::parser::settings::declared_catalog_files)
    }

    fn state(&self) -> MutexGuard<'_, ForwardState> {
        self.forward.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn declared_by_ancestor(&self, parent: &Path, candidate: &Path) -> bool {
        fs_probe::config_ancestors(parent)
            .filter_map(|dir| {
                let settings: Vec<PathBuf> = settings_files(dir).collect();
                (!settings.is_empty()).then_some((dir, settings))
            })
            .take(MAX_SETTINGS_ANCESTORS)
            .any(|(dir, settings)| {
                settings.iter().any(|path| {
                    self.parsed(path)
                        .is_some_and(|declared| declared.declares_file(dir, candidate))
                })
            })
    }

    fn declared_by_sibling(
        &self,
        parent: &Path,
        candidate: &Path,
        bound: Option<&ClaimBound>,
    ) -> bool {
        let Some(limit) = self.forward_limit(parent, bound) else {
            return false;
        };
        fs_probe::config_ancestors(parent)
            .take_while(|ancestor| ancestor.starts_with(&limit))
            .take(MAX_FORWARD_ANCESTORS)
            .any(|ancestor| {
                self.forward_declarations(ancestor)
                    .declared
                    .contains(candidate)
            })
    }

    /// The outermost of the nearest `.git` ancestor of `parent` and `bound`, among those that
    /// contain `parent`.
    fn forward_limit(&self, parent: &Path, bound: Option<&ClaimBound>) -> Option<PathBuf> {
        let git = self.git_dir(parent);
        let bound = bound
            .map(ClaimBound::dir)
            .filter(|dir| parent.starts_with(dir))
            .map(Path::to_path_buf);
        [git, bound]
            .into_iter()
            .flatten()
            .min_by_key(|dir| dir.components().count())
    }

    /// The nearest ancestor of `parent` holding a `.git` directory or worktree file; `None` when
    /// that is a root or the home directory.
    fn git_dir(&self, parent: &Path) -> Option<PathBuf> {
        if let Some(known) = self.state().git_dirs.get(parent) {
            return known.clone();
        }
        let found = fs_probe::config_ancestors(parent)
            .find(|dir| fs_probe::exists(&dir.join(".git")))
            .and_then(ClaimBound::new)
            .map(|bound| bound.dir().to_path_buf());
        let mut state = self.state();
        if state.git_dirs.len() >= MAX_FORWARD_MEMO {
            state.git_dirs.clear();
        }
        state.git_dirs.insert(parent.to_path_buf(), found.clone());
        found
    }

    fn forward_declarations(&self, ancestor: &Path) -> Arc<ForwardDeclarations> {
        let known = self.state().listings.get(ancestor).map(Arc::clone);
        if let Some(known) = known
            && known.is_current(ancestor)
        {
            return known;
        }
        let (listing, complete) = self.list_children(ancestor);
        let listing = Arc::new(listing);
        if complete {
            let mut state = self.state();
            if state.listings.len() >= MAX_FORWARD_MEMO {
                state.listings.clear();
            }
            state
                .listings
                .insert(ancestor.to_path_buf(), Arc::clone(&listing));
        }
        listing
    }

    /// Reads `ancestor`'s child directories for settings files; the flag is `false` when the
    /// parse budget skipped a file, so the result must not be memoized.
    fn list_children(&self, ancestor: &Path) -> (ForwardDeclarations, bool) {
        let mut listing = ForwardDeclarations {
            dir_mtime: modified(ancestor),
            settings: Vec::new(),
            declared: HashSet::new(),
        };
        let mut complete = true;
        let Ok(entries) = std::fs::read_dir(ancestor) else {
            return (listing, complete);
        };
        let children = entries
            .take(MAX_FORWARD_ENTRIES)
            .filter_map(Result::ok)
            .filter(|entry| {
                entry.file_type().is_ok_and(|kind| kind.is_dir())
                    && !entry.file_name().to_string_lossy().starts_with('.')
            })
            .take(MAX_FORWARD_CHILDREN);
        for child in children {
            let child = child.path();
            for settings in settings_files(&child) {
                let mtime = modified(&settings);
                let declared = match self.files.get_if_fresh(&settings) {
                    Some(declared) => Some(declared),
                    None if self.parses_used.load(Ordering::Relaxed) >= MAX_RUN_PARSES => {
                        self.report_exhausted_budget();
                        complete = false;
                        continue;
                    }
                    None => self.files.get_or_parse(&settings, |content| {
                        self.parses_used.fetch_add(1, Ordering::Relaxed);
                        crate::parser::settings::declared_catalog_files(content)
                    }),
                };
                listing.settings.push((settings, mtime));
                if let Some(declared) = declared {
                    listing.declared.extend(declared.resolved(&child));
                }
            }
        }
        (listing, complete)
    }

    fn report_exhausted_budget(&self) {
        if !self.budget_reported.swap(true, Ordering::Relaxed) {
            tracing::warn!(
                per_run = MAX_RUN_PARSES,
                "settings.gradle parse budget exhausted; some sibling version catalogs may not \
                 be recognized"
            );
        }
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

        assert!(cache.declares(&within_catalog, None));
        assert!(
            !cache.declares(&beyond_catalog, None),
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
        assert!(cache.declares(&root.join("gradle/c0.toml"), None));
        assert!(cache.declares(
            &root.join(format!("gradle/c{}.toml", MAX_DECLARED_CATALOGS - 1)),
            None
        ));
        assert!(!cache.declares(
            &root.join(format!("gradle/c{MAX_DECLARED_CATALOGS}.toml")),
            None
        ));
        assert!(!cache.declares(&root.join("other/u.toml"), None));
    }

    fn write(path: &Path, content: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, content).unwrap();
    }

    fn declaring(relative: &str) -> String {
        format!("versionCatalogs {{ create(\"d\") {{ from(files(\"{relative}\")) }} }}\n")
    }

    fn bound(dir: &Path) -> ClaimBound {
        ClaimBound::new(dir).unwrap()
    }

    #[test]
    fn a_sibling_declaration_is_found_only_under_a_limit_that_contains_it() {
        let _guard = fs_probe::snapshot_guard();
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        write(
            &root.join("project/settings.gradle.kts"),
            &declaring("../shared/deps.toml"),
        );
        let catalog = root.join("shared/deps.toml");
        write(&catalog, "");

        let cache = SettingsCatalogCache::new();
        assert!(!cache.declares(&catalog, None), "no git root and no bound");
        assert!(!cache.declares(&catalog, Some(&bound(&root.join("shared")))));
        assert!(cache.declares(&catalog, Some(&bound(&root))));

        std::fs::create_dir(root.join(".git")).unwrap();
        assert!(SettingsCatalogCache::new().declares(&catalog, None));
    }

    #[test]
    fn a_new_settings_file_in_a_listed_child_is_seen_after_a_reset() {
        let _guard = fs_probe::snapshot_guard();
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let catalog = root.join("shared/deps.toml");
        write(&catalog, "");
        std::fs::create_dir(root.join("project")).unwrap();
        let cache = SettingsCatalogCache::new();
        let limit = bound(&root);
        assert!(!cache.declares(&catalog, Some(&limit)));

        write(
            &root.join("project/settings.gradle.kts"),
            &declaring("../shared/deps.toml"),
        );
        assert!(!cache.declares(&catalog, Some(&limit)), "memoized listing");
        cache.reset_forward();
        assert!(cache.declares(&catalog, Some(&limit)));
    }

    #[test]
    fn one_probe_finds_the_declaring_sibling_listed_last_among_many() {
        let _guard = fs_probe::snapshot_guard();
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let catalog = root.join("shared/deps.toml");
        write(&catalog, "");
        for index in 0..20 {
            write(
                &root.join(format!("p{index}/settings.gradle")),
                &declaring("other.toml"),
            );
        }
        // The declaring project is the one the listing reaches last, whatever the order is.
        let last = std::fs::read_dir(&root)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| path.join("settings.gradle").is_file())
            .last()
            .unwrap();
        write(
            &last.join("settings.gradle"),
            &declaring("../shared/deps.toml"),
        );

        assert!(SettingsCatalogCache::new().declares(&catalog, Some(&bound(&root))));
    }

    #[test]
    fn an_exhausted_budget_still_serves_cached_settings_and_skips_only_misses() {
        let _guard = fs_probe::snapshot_guard();
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let catalog = root.join("shared/deps.toml");
        write(&catalog, "");
        let settings = root.join("project/settings.gradle");
        write(&settings, &declaring("../shared/deps.toml"));
        let cache = SettingsCatalogCache::new();
        let limit = bound(&root);
        assert!(cache.declares(&catalog, Some(&limit)));

        cache.parses_used.store(MAX_RUN_PARSES, Ordering::Relaxed);
        cache.state().listings.clear();
        assert!(cache.declares(&catalog, Some(&limit)), "cached parse");

        // A file never parsed costs budget there is none of.
        let other = root.join("other/deps.toml");
        write(&other, "");
        write(
            &root.join("unparsed/settings.gradle"),
            &declaring("../other/deps.toml"),
        );
        cache.state().listings.clear();
        assert!(!cache.declares(&other, Some(&limit)));
        assert!(cache.declares(&catalog, Some(&limit)));
    }

    #[test]
    fn a_declared_path_that_is_not_toml_is_dropped() {
        for raw in [".env", "gradle/x.gradle", "../shared", "gradle"] {
            assert!(DeclaredCatalogFile::parse(raw).is_none(), "{raw}");
        }
        assert!(DeclaredCatalogFile::parse("../shared/Deps.TOML").is_some());
    }

    #[test]
    fn declared_by_resolves_the_declarations_of_a_settings_file_only() {
        let _guard = fs_probe::snapshot_guard();
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let settings = root.join("project/settings.gradle.kts");
        write(&settings, &declaring("../shared/.deps.toml"));
        let cache = SettingsCatalogCache::new();

        assert_eq!(
            cache.declared_by(&settings),
            [root.join("shared/.deps.toml")]
        );
        assert!(
            cache
                .declared_by(&root.join("project/build.gradle"))
                .is_empty()
        );
    }
}
