//! Repository-level config directory scope shared by the native-cooldown readers.

use std::path::{Path, PathBuf};

use crate::UserHome;
use crate::fs_probe::MAX_CONFIG_ANCESTOR_DEPTH;

/// The directories whose repository-level config applies to one manifest.
///
/// Walks from the manifest directory up to the repository root, root inclusive. The user's home
/// directory is never included, and the walk stops there: a repository cannot extend past the
/// home directory, so a config file of the home directory or of anything above it can never
/// change what an opened repository holds back.
///
/// # Examples
///
/// ```
/// use std::path::Path;
/// use deps_core::native_cooldown::RepositoryScope;
///
/// let scope = RepositoryScope::new(Path::new("/repo/app"), Path::new("/repo"), None);
/// assert_eq!(scope.config_dirs(), [Path::new("/repo/app"), Path::new("/repo")]);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepositoryScope {
    dirs: Vec<PathBuf>,
    home: Option<UserHome>,
}

impl RepositoryScope {
    /// Scope from `manifest_dir` up to `root` inclusive, never reaching `home`.
    ///
    /// A `root` that is not an ancestor of `manifest_dir` leaves the manifest directory alone.
    /// Resolves `home` once; callers that already hold a [`UserHome`] use
    /// [`Self::with_user_home`].
    #[must_use]
    pub fn new(manifest_dir: &Path, root: &Path, home: Option<&Path>) -> Self {
        let home = home.map(|home| UserHome::resolve(home.to_path_buf()));
        Self::with_user_home(manifest_dir, root, home.as_ref())
    }

    /// [`Self::new`] with an already resolved home directory.
    #[must_use]
    pub fn with_user_home(manifest_dir: &Path, root: &Path, home: Option<&UserHome>) -> Self {
        let boundary = if manifest_dir.starts_with(root) {
            root
        } else {
            manifest_dir
        };
        let mut dirs = Vec::new();
        for dir in manifest_dir.ancestors().take(MAX_CONFIG_ANCESTOR_DEPTH) {
            if home.is_some_and(|home| is_home(home, dir)) {
                break;
            }
            dirs.push(dir.to_path_buf());
            if dir == boundary {
                break;
            }
        }
        Self {
            dirs,
            home: home.cloned(),
        }
    }

    /// The config directories, closest to the manifest first.
    #[must_use]
    pub fn config_dirs(&self) -> Vec<PathBuf> {
        self.dirs.clone()
    }

    /// Whether `dir` is one of the scope's config directories.
    #[must_use]
    pub fn contains(&self, dir: &Path) -> bool {
        self.dirs.iter().any(|candidate| candidate == dir)
    }

    /// Whether the config file `config_file`, which sits at `home_relative` below its owning
    /// directory (for example `.cargo/config.toml` below the manifest directory), may change
    /// what the repository holds back: its directory is in scope and neither the file nor the
    /// directory is the home directory's own (a symlinked copy included).
    #[must_use]
    pub fn admits(&self, config_file: &Path, home_relative: &Path) -> bool {
        let Some(dir) = home_relative
            .components()
            .try_fold(config_file, |path, _| path.parent())
        else {
            return false;
        };
        if !self.contains(dir) {
            return false;
        }
        let Some(home) = &self.home else {
            return true;
        };
        let home_copy = home.path().join(home_relative);
        let same_file = std::fs::canonicalize(config_file)
            .and_then(|real| std::fs::canonicalize(&home_copy).map(|home_real| real == home_real))
            .unwrap_or(false);
        !same_file
    }
}

/// Raw or canonical equality, so a symlinked directory is still recognised as the home.
fn is_home(home: &UserHome, dir: &Path) -> bool {
    home.is(dir) || std::fs::canonicalize(dir).is_ok_and(|real| home.is(&real))
}
