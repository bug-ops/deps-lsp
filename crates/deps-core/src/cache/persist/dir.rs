//! Cache directory resolution, ownership checks and pruning (spec 051).
//!
//! Resolution is pure: it reads only injected environment variables and never touches the
//! filesystem. Opening (Unix) establishes the store directory without ever creating a
//! directory that another user could own or redirect: an existing cache root must be an
//! owned directory, a missing root is created only directly under an owned `$HOME`, and the
//! `deps-lsp/http/v1` components are created `0700` and verified without following symlinks.
//! On Windows the root is `%LOCALAPPDATA%`, never created, and trust rests on its per-user
//! ACL: components are verified as plain directories (no reparse points), without an owner check.
//! Pruning bounds the store by age, file count and total size.

use super::freshness::{DiskFreshness, ValidatedAt, classify};
use crate::net_policy::EnvSource;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};

/// Store directory components below the cache root.
const STORE_COMPONENTS: [&str; 3] = ["deps-lsp", "http", "v1"];

/// Permission bits that grant access to group or other users.
#[cfg(unix)]
const GROUP_OTHER_BITS: u32 = 0o077;

/// Extension of finished entry files.
const ENTRY_EXTENSION: &str = "entry";

/// Extension of in-flight write files.
const TMP_EXTENSION: &str = "tmp";

/// Age after which an in-flight write file is considered abandoned.
const STALE_TMP_AGE: Duration = Duration::from_hours(1);

/// Environment variables consulted for directory resolution.
#[derive(Debug, Clone, Copy)]
enum CacheDirEnvVar {
    XdgCacheHome,
    Home,
    LocalAppData,
}

impl CacheDirEnvVar {
    const fn name(self) -> &'static str {
        match self {
            Self::XdgCacheHome => "XDG_CACHE_HOME",
            Self::Home => "HOME",
            Self::LocalAppData => "LOCALAPPDATA",
        }
    }

    fn absolute_path(self, env: &impl EnvSource) -> Option<PathBuf> {
        env.var_os(self.name())
            .map(PathBuf::from)
            .filter(|path| path.is_absolute())
    }
}

/// Platform whose directory convention applies.
///
/// A parameter rather than a `cfg` inside the resolver so every platform's rules are
/// testable on any host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CachePlatform {
    /// XDG-style: `$XDG_CACHE_HOME` or `$HOME/.cache`.
    Unix,
    /// `$HOME/Library/Caches`.
    MacOs,
    /// `%LOCALAPPDATA%`.
    Windows,
}

impl CachePlatform {
    /// The platform this binary was built for.
    pub(super) const CURRENT: Self = if cfg!(target_os = "macos") {
        Self::MacOs
    } else if cfg!(windows) {
        Self::Windows
    } else {
        Self::Unix
    };
}

/// Why the disk tier cannot be used.
///
/// Every variant means "fall back to the memory tier"; none is fatal to the process.
#[derive(Debug, thiserror::Error)]
pub(super) enum DiskTierError {
    /// A required directory could not be created, or creation is not allowed here.
    #[error("cache directory cannot be created: {0}")]
    CreateFailed(#[source] std::io::Error),
    /// A directory is not owned by the current user, is a symlink, or is accessible to others.
    #[error("cache directory is not private to the current user")]
    InsecureDirectory,
    /// The effective user id could not be determined.
    #[error("effective user id could not be determined: {0}")]
    ProbeFailed(#[source] std::io::Error),
    /// An unexpected I/O failure.
    #[error("cache I/O failure: {0}")]
    Io(#[from] std::io::Error),
}

/// No absolute per-user cache directory could be determined.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("no absolute per-user cache directory is available")]
pub(super) struct NoCacheDir;

/// The absolute per-user cache root, for example `~/.cache`.
///
/// Only constructible through [`CacheDir::resolve`], so the path is always absolute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CacheDir(PathBuf);

impl CacheDir {
    /// Resolves the cache root for the platform this binary targets.
    ///
    /// # Errors
    ///
    /// [`NoCacheDir`] when the required variables are missing or relative.
    pub(super) fn user_default(env: &impl EnvSource) -> Result<Self, NoCacheDir> {
        Self::resolve(env, CachePlatform::CURRENT)
    }

    /// Resolves the cache root for `platform` from `env`, without filesystem access.
    ///
    /// Unix uses an absolute `XDG_CACHE_HOME` (a relative one is an error, not a fallback to
    /// `HOME`; an empty one counts as unset), else `$HOME/.cache`; macOS uses `$HOME/Library/Caches`; Windows uses
    /// `%LOCALAPPDATA%`.
    ///
    /// # Errors
    ///
    /// [`NoCacheDir`] when the required variables are missing or relative.
    pub(super) fn resolve(
        env: &impl EnvSource,
        platform: CachePlatform,
    ) -> Result<Self, NoCacheDir> {
        let path = match platform {
            CachePlatform::Unix => match env
                .var_os(CacheDirEnvVar::XdgCacheHome.name())
                .filter(|xdg| !xdg.is_empty())
            {
                Some(xdg) => Some(PathBuf::from(xdg)).filter(|path| path.is_absolute()),
                None => CacheDirEnvVar::Home
                    .absolute_path(env)
                    .map(|home| home.join(".cache")),
            },
            CachePlatform::MacOs => CacheDirEnvVar::Home
                .absolute_path(env)
                .map(|home| home.join("Library").join("Caches")),
            CachePlatform::Windows => CacheDirEnvVar::LocalAppData.absolute_path(env),
        };
        path.map(Self).ok_or(NoCacheDir)
    }

    /// The cache root path.
    #[must_use]
    pub(super) fn as_path(&self) -> &Path {
        &self.0
    }
}

/// The verified store directory `<root>/deps-lsp/http/v1`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct StoreDir(PathBuf);

impl StoreDir {
    /// The store directory path.
    #[must_use]
    pub(super) fn path(&self) -> &Path {
        &self.0
    }

    /// Prunes the store with [`PruneLimits::DEFAULT`].
    ///
    /// # Errors
    ///
    /// [`DiskTierError::Io`] when a file cannot be listed or removed for a reason other than
    /// having vanished.
    pub(super) fn prune(&self, now: SystemTime) -> Result<PruneReport, DiskTierError> {
        prune_dir(&self.0, now, PruneLimits::DEFAULT)
    }
}

/// Numeric id of the user that owns files this process creates.
///
/// Derived from the owner of a freshly created file, since `geteuid` is unavailable without
/// `unsafe`.
#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ProbeUid(u32);

#[cfg(unix)]
impl ProbeUid {
    /// Wraps a raw user id; test-only so production code can only obtain one by probing.
    #[cfg(test)]
    #[must_use]
    pub(super) const fn new(uid: u32) -> Self {
        Self(uid)
    }

    /// The raw user id.
    #[must_use]
    pub(super) const fn as_raw(self) -> u32 {
        self.0
    }

    /// Probes the user id via a file in the system temporary directory.
    ///
    /// # Errors
    ///
    /// [`DiskTierError::ProbeFailed`] when the probe file cannot be created, inspected or
    /// removed.
    pub(super) fn probe() -> Result<Self, DiskTierError> {
        Self::probe_in(&std::env::temp_dir())
    }

    /// Probes the user id by creating (`create_new`, `0600`) and deleting a file in `dir`.
    ///
    /// # Errors
    ///
    /// [`DiskTierError::ProbeFailed`] on any failure, including a probe file left behind.
    pub(super) fn probe_in(dir: &Path) -> Result<Self, DiskTierError> {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);

        let name = format!(
            ".deps-lsp-probe-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        );
        let path = dir.join(name);
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .map_err(DiskTierError::ProbeFailed)?;
        let owner = file.metadata().map(|meta| meta.uid());
        drop(file);
        let removed = std::fs::remove_file(&path);
        let uid = owner.map_err(DiskTierError::ProbeFailed)?;
        removed.map_err(DiskTierError::ProbeFailed)?;
        Ok(Self(uid))
    }
}

#[cfg(unix)]
impl CacheDir {
    /// Opens the store directory, probing the user id first.
    ///
    /// # Errors
    ///
    /// See [`CacheDir::open_with`]; additionally [`DiskTierError::ProbeFailed`].
    pub(super) fn open(&self, env: &impl EnvSource) -> Result<StoreDir, DiskTierError> {
        self.open_with(env, ProbeUid::probe()?)
    }

    /// Opens the store directory for an already-probed user id.
    ///
    /// An existing root must be a directory owned by `uid` (symlinks followed, mode not
    /// checked). A missing root is created with a single non-recursive `0700` `create_dir`,
    /// only when its parent is `$HOME` and `$HOME` is owned by `uid`. Each store component is
    /// created `0700` and verified with `symlink_metadata`.
    ///
    /// # Errors
    ///
    /// - [`DiskTierError::InsecureDirectory`]: a root, `$HOME` or component is not a directory
    ///   owned by `uid`, or a component is a symlink or has group/other permission bits.
    /// - [`DiskTierError::CreateFailed`]: creation is not permitted or the filesystem refused.
    /// - [`DiskTierError::Io`]: the root could not be inspected.
    pub(super) fn open_with(
        &self,
        env: &impl EnvSource,
        uid: ProbeUid,
    ) -> Result<StoreDir, DiskTierError> {
        self.ensure_root(env, uid)?;
        let mut dir = self.0.clone();
        for component in STORE_COMPONENTS {
            dir.push(component);
            create_private_dir(&dir)?;
            verify_private_dir(&dir, uid)?;
        }
        Ok(StoreDir(dir))
    }

    fn ensure_root(&self, env: &impl EnvSource, uid: ProbeUid) -> Result<(), DiskTierError> {
        match std::fs::metadata(&self.0) {
            Ok(meta) => return verify_owned_dir(&meta, uid),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(err.into()),
        }
        let home = CacheDirEnvVar::Home
            .absolute_path(env)
            .filter(|home| self.0.parent() == Some(home.as_path()))
            .ok_or_else(|| {
                DiskTierError::CreateFailed(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "cache root is not directly under an absolute HOME",
                ))
            })?;
        let home_meta = std::fs::metadata(&home).map_err(DiskTierError::CreateFailed)?;
        verify_owned_dir(&home_meta, uid)?;
        create_private_dir(&self.0)?;
        let meta = std::fs::metadata(&self.0)?;
        verify_owned_dir(&meta, uid)
    }
}

#[cfg(unix)]
fn create_private_dir(path: &Path) -> Result<(), DiskTierError> {
    match std::fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(err) => Err(DiskTierError::CreateFailed(err)),
    }
}

#[cfg(unix)]
fn verify_owned_dir(meta: &std::fs::Metadata, uid: ProbeUid) -> Result<(), DiskTierError> {
    if meta.is_dir() && meta.uid() == uid.as_raw() {
        Ok(())
    } else {
        Err(DiskTierError::InsecureDirectory)
    }
}

#[cfg(unix)]
fn verify_private_dir(path: &Path, uid: ProbeUid) -> Result<(), DiskTierError> {
    let meta = std::fs::symlink_metadata(path)?;
    verify_owned_dir(&meta, uid)?;
    if meta.permissions().mode() & GROUP_OTHER_BITS == 0 {
        Ok(())
    } else {
        Err(DiskTierError::InsecureDirectory)
    }
}

/// Whether an entry file may be read: a regular file (not a symlink) owned by `uid` that no
/// group or other user can write.
///
/// `meta` must come from the very handle the entry is read through (the metadata returned by
/// [`crate::fs_probe::read_capped_no_follow_with_metadata`]), not from a separate path `lstat`,
/// which would leave a check-then-open race. An untrusted file is treated as a cache miss.
#[cfg(unix)]
#[must_use]
pub(super) fn entry_file_trusted(meta: &std::fs::Metadata, uid: ProbeUid) -> bool {
    meta.file_type().is_file()
        && meta.uid() == uid.as_raw()
        && meta.permissions().mode() & 0o022 == 0
}

/// `FILE_ATTRIBUTE_REPARSE_POINT`, declared locally to avoid a `windows-sys` dependency.
#[cfg(windows)]
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;

#[cfg(windows)]
impl CacheDir {
    /// Opens the store directory under `%LOCALAPPDATA%`.
    ///
    /// Trust rests on the per-user ACL of `%LOCALAPPDATA%` (NFR-004): the root is never
    /// created, each store component is created with a plain `create_dir` (inheriting the
    /// profile ACL) and verified to be a directory that is not a reparse point. Owner and DACL
    /// verification is not performed. `env` is unused and kept for signature parity with the
    /// Unix `open`.
    ///
    /// # Errors
    ///
    /// - [`DiskTierError::CreateFailed`]: the root is missing (it is never created) or a
    ///   component could not be created.
    /// - [`DiskTierError::InsecureDirectory`]: the root is not a directory, or a component is not
    ///   a directory or is a reparse point.
    /// - [`DiskTierError::Io`]: the root or a component could not be inspected.
    pub(super) fn open(&self, _env: &impl EnvSource) -> Result<StoreDir, DiskTierError> {
        match std::fs::metadata(&self.0) {
            Ok(meta) if meta.is_dir() => {}
            Ok(_) => return Err(DiskTierError::InsecureDirectory),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                return Err(DiskTierError::CreateFailed(err));
            }
            Err(err) => return Err(err.into()),
        }
        let mut dir = self.0.clone();
        for component in STORE_COMPONENTS {
            dir.push(component);
            match std::fs::create_dir(&dir) {
                Ok(()) => {}
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(err) => return Err(DiskTierError::CreateFailed(err)),
            }
            verify_plain_dir(&dir)?;
        }
        Ok(StoreDir(dir))
    }
}

#[cfg(windows)]
fn verify_plain_dir(path: &Path) -> Result<(), DiskTierError> {
    use std::os::windows::fs::MetadataExt;

    let meta = std::fs::symlink_metadata(path)?;
    if meta.file_type().is_dir() && meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0 {
        Ok(())
    } else {
        Err(DiskTierError::InsecureDirectory)
    }
}

/// Whether an entry file may be read: a regular file.
///
/// The owner check is skipped per NFR-004 (trust rests on the per-user `%LOCALAPPDATA%` ACL);
/// owner/DACL verification is tracked in #2146. `meta` must come from the handle the entry is
/// read through, as on Unix. An untrusted file is treated as a cache miss.
#[cfg(windows)]
#[must_use]
pub(super) fn entry_file_trusted(meta: &std::fs::Metadata) -> bool {
    meta.file_type().is_file()
}

/// Bounds enforced by [`prune_dir`].
#[derive(Debug, Clone, Copy)]
#[expect(
    clippy::struct_field_names,
    reason = "each field is a distinct maximum; the prefix names the bound"
)]
pub(super) struct PruneLimits {
    /// Total size of retained entry files.
    pub(super) max_bytes: u64,
    /// Number of retained entry files.
    pub(super) max_files: usize,
    /// Directory entries examined per pass.
    pub(super) max_scan: usize,
}

impl PruneLimits {
    /// 64 MiB, 2048 files, 16384 scanned entries.
    pub(super) const DEFAULT: Self = Self {
        max_bytes: 64 * 1024 * 1024,
        max_files: 2048,
        max_scan: 16384,
    };
}

/// Outcome of a prune pass.
#[derive(Debug, Clone, Copy)]
pub(super) struct PruneReport {
    /// Directory entries examined.
    pub(super) scanned: usize,
    /// Files removed by this pass.
    pub(super) removed: usize,
    /// Files that should have been removed but could not be.
    pub(super) failed: usize,
}

impl PruneReport {
    fn remove(&mut self, path: &Path) {
        match std::fs::remove_file(path) {
            Ok(()) => self.removed += 1,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => self.failed += 1,
        }
    }
}

struct EntryFile {
    path: PathBuf,
    len: u64,
    validated_at: SystemTime,
}

/// Removes abandoned, expired and surplus files from `dir`.
///
/// Order: `*.tmp` older than one hour, then entries that are expired (or stamped in the
/// future), then least recently validated entries until the remainder fits
/// [`PruneLimits::max_bytes`] and [`PruneLimits::max_files`]. Fresh `*.tmp` files belong to
/// in-flight writers and are never touched. A missing directory or a file that vanished
/// concurrently is not an error. A file that cannot be removed is counted in
/// [`PruneReport::failed`] and the pass continues, so one stubborn file never leaves the rest
/// of the store over budget.
///
/// # Errors
///
/// [`DiskTierError::Io`] when the directory cannot be listed.
pub(super) fn prune_dir(
    dir: &Path,
    now: SystemTime,
    limits: PruneLimits,
) -> Result<PruneReport, DiskTierError> {
    let listing = match std::fs::read_dir(dir) {
        Ok(listing) => listing,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Ok(PruneReport {
                scanned: 0,
                removed: 0,
                failed: 0,
            });
        }
        Err(err) => return Err(err.into()),
    };

    let mut report = PruneReport {
        scanned: 0,
        removed: 0,
        failed: 0,
    };
    let mut entries = Vec::new();
    for item in listing.take(limits.max_scan) {
        report.scanned += 1;
        let item = item?;
        let Ok(meta) = item.metadata() else { continue };
        if !meta.is_file() {
            continue;
        }
        let Ok(validated_at) = meta.modified() else {
            continue;
        };
        let path = item.path();
        if has_extension(&path, TMP_EXTENSION) {
            let stale = now
                .duration_since(validated_at)
                .is_ok_and(|age| age > STALE_TMP_AGE);
            if stale {
                report.remove(&path);
            }
        } else if has_extension(&path, ENTRY_EXTENSION) {
            entries.push(EntryFile {
                path,
                len: meta.len(),
                validated_at,
            });
        }
    }

    let (discard, mut kept): (Vec<_>, Vec<_>) =
        entries.into_iter().partition(|entry| {
            match classify(ValidatedAt::new(entry.validated_at), now) {
                DiskFreshness::Expired | DiskFreshness::FromFuture => true,
                DiskFreshness::Fresh | DiskFreshness::Revalidate => false,
            }
        });
    for entry in discard {
        report.remove(&entry.path);
    }

    kept.sort_by_key(|entry| std::cmp::Reverse(entry.validated_at));
    let mut total_bytes: u64 = kept.iter().map(|entry| entry.len).sum();
    while total_bytes > limits.max_bytes || kept.len() > limits.max_files {
        let Some(oldest) = kept.pop() else { break };
        total_bytes -= oldest.len;
        report.remove(&oldest.path);
    }

    Ok(report)
}

fn has_extension(path: &Path, extension: &str) -> bool {
    path.extension() == Some(OsStr::new(extension))
}
