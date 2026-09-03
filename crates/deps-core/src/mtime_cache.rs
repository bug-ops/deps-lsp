//! Generic per-path, mtime-gated file cache shared by every ecosystem config-file cache
//! (`deps-cargo`'s `.cargo/config.toml`/`$CARGO_HOME/config.toml`, `deps-npm`'s `.npmrc`).
//!
//! [`MtimeFileCache<T>`] caches **raw, unvalidated** parse results, keyed by file path and
//! invalidated by mtime — validation, environment-variable expansion, and policy gating are
//! expected to run per call against the cached raw value, never cached themselves, so a
//! `didChangeConfiguration` policy change or an environment-variable change takes effect
//! immediately with no cache invalidation of its own. That split is the caller's
//! responsibility: this cache only knows how to keep one path's `T` fresh.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use crate::fs_probe;

/// Upper bound on a [`MtimeFileCache`]'s entry count.
///
/// Generous for any realistic project tree, since it is bounded by the number of *distinct*
/// config files a workspace's ancestor walk can find, not by the number of manifests sharing
/// them.
pub const DEFAULT_MAX_CACHED_FILES: usize = 256;

/// One cached file's mtime plus its parsed value. The mtime lives here, not on `T`, so `T`
/// stays exactly the caller's existing parsed-value type with no cache-specific field to
/// strip at every call site.
struct CacheEntry<T> {
    mtime: SystemTime,
    value: Arc<T>,
}

/// Per-path memoization of a file's parsed contents, invalidated by mtime.
///
/// Caches whatever `parse` produces for a file's raw content — validation, expansion, and
/// policy checks are expected to run per call on the returned value, never cached. Absence
/// is never cached: only a file that existed, was a regular file, and parsed successfully
/// gets an entry, so a file created after the cache first found nothing is picked up on the
/// very next call with no extra bookkeeping.
pub struct MtimeFileCache<T> {
    files: dashmap::DashMap<PathBuf, CacheEntry<T>>,
    capacity: usize,
    label: &'static str,
}

impl<T> std::fmt::Debug for MtimeFileCache<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MtimeFileCache")
            .field("label", &self.label)
            .field("capacity", &self.capacity)
            .field("len", &self.files.len())
            .finish()
    }
}

impl<T> MtimeFileCache<T> {
    /// Creates an empty cache holding at most `capacity` entries, labeled `label` for
    /// diagnostics (e.g. `"cargo config"`, `"npm config"`) when the capacity is reached.
    #[must_use]
    pub fn new(capacity: usize, label: &'static str) -> Self {
        Self {
            files: dashmap::DashMap::new(),
            capacity,
            label,
        }
    }

    /// Returns `path`'s parsed contents, from cache if `path`'s mtime is unchanged, else
    /// re-reading and re-parsing with `parse`. `None` if `path` does not exist, is not a
    /// regular file, or cannot be read.
    ///
    /// Rejects anything but a regular file (a FIFO, socket, character device, or directory)
    /// before ever attempting to read it — reading one of those can block the calling thread
    /// indefinitely, and [`std::fs::metadata`] follows symlinks, so a symlinked regular file
    /// still resolves.
    ///
    /// Always performs one `stat` (the mtime check) — that cost is unavoidable and paid on
    /// every call, cache hit or not — but reads and parses the file's *content* only on a
    /// miss. Compares mtime with `!=`, not `>`: a `git checkout` that restores an older file
    /// moves the mtime backwards, and `>` would then keep serving the stale cached entry.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::mtime_cache::{DEFAULT_MAX_CACHED_FILES, MtimeFileCache};
    /// use std::sync::Arc;
    ///
    /// let dir = tempfile::tempdir().unwrap();
    /// let path = dir.path().join("config.toml");
    /// std::fs::write(&path, "value = 1").unwrap();
    ///
    /// let cache: MtimeFileCache<String> = MtimeFileCache::new(DEFAULT_MAX_CACHED_FILES, "example");
    /// let first = cache.get_or_parse(&path, str::to_owned).unwrap();
    /// let second = cache.get_or_parse(&path, str::to_owned).unwrap();
    /// assert!(Arc::ptr_eq(&first, &second), "an unchanged file is served from cache");
    /// ```
    pub fn get_or_parse(&self, path: &Path, parse: impl FnOnce(&str) -> T) -> Option<Arc<T>> {
        let metadata = fs_probe::metadata(path).ok()?;
        if !metadata.is_file() {
            return None;
        }
        let mtime = metadata.modified().ok()?;

        if let Some(existing) = self.files.get(path)
            && existing.mtime == mtime
        {
            return Some(Arc::clone(&existing.value));
        }

        let content = fs_probe::read_to_string(path).ok()?;
        let value = Arc::new(parse(&content));

        if !self.files.contains_key(path) && self.files.len() >= self.capacity {
            tracing::warn!(
                path = %path.display(),
                label = self.label,
                cap = self.capacity,
                "mtime file cache capacity reached; not caching this file (still used for this parse)"
            );
            return Some(value);
        }
        self.files.insert(
            path.to_path_buf(),
            CacheEntry {
                mtime,
                value: Arc::clone(&value),
            },
        );
        Some(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, PartialEq, Eq)]
    struct Parsed(String);

    fn parse_upper(content: &str) -> Parsed {
        Parsed(content.trim().to_uppercase())
    }

    #[test]
    fn hit_reuses_same_arc_without_reparsing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("file.txt");
        std::fs::write(&path, "hello").unwrap();

        let cache: MtimeFileCache<Parsed> = MtimeFileCache::new(DEFAULT_MAX_CACHED_FILES, "test");
        let first = cache.get_or_parse(&path, parse_upper).unwrap();
        let second = cache.get_or_parse(&path, parse_upper).unwrap();

        assert!(
            Arc::ptr_eq(&first, &second),
            "a cache hit must return the same Arc, not re-parse"
        );
    }

    #[test]
    fn hit_does_zero_reads_and_exactly_one_stat() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("file.txt");
        std::fs::write(&path, "hello").unwrap();

        let cache: MtimeFileCache<Parsed> = MtimeFileCache::new(DEFAULT_MAX_CACHED_FILES, "test");
        cache.get_or_parse(&path, parse_upper).unwrap();

        let (stats_before, reads_before) = fs_probe::snapshot();
        let hit = cache.get_or_parse(&path, parse_upper).unwrap();
        let (stats_after, reads_after) = fs_probe::snapshot();

        assert_eq!(
            reads_after - reads_before,
            0,
            "a cache hit must perform zero content reads"
        );
        assert_eq!(
            stats_after - stats_before,
            1,
            "a cache hit still pays exactly one mtime stat"
        );
        assert_eq!(hit.0, "HELLO");
    }

    #[test]
    fn forward_mtime_bump_invalidates() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("file.txt");
        std::fs::write(&path, "one").unwrap();

        let cache: MtimeFileCache<Parsed> = MtimeFileCache::new(DEFAULT_MAX_CACHED_FILES, "test");
        let first = cache.get_or_parse(&path, parse_upper).unwrap();

        // Ensure a distinguishable mtime on filesystems with coarse timestamp resolution.
        let future = SystemTime::now() + std::time::Duration::from_secs(2);
        std::fs::write(&path, "two").unwrap();
        // `File::open` is read-only, which lacks `FILE_WRITE_ATTRIBUTES` on Windows and makes
        // `set_modified` fail with `PermissionDenied`; open for write instead.
        std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(future)
            .unwrap();

        let second = cache.get_or_parse(&path, parse_upper).unwrap();
        assert!(
            !Arc::ptr_eq(&first, &second),
            "an mtime bump must invalidate the cache entry"
        );
        assert_eq!(second.0, "TWO");
    }

    /// A `git checkout` restoring an older file moves the mtime *backwards* — invalidation
    /// must compare with `!=`, not `>`.
    #[test]
    fn backward_mtime_move_invalidates() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("file.txt");
        std::fs::write(&path, "one").unwrap();
        let future = SystemTime::now() + std::time::Duration::from_secs(10);
        std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(future)
            .unwrap();

        let cache: MtimeFileCache<Parsed> = MtimeFileCache::new(DEFAULT_MAX_CACHED_FILES, "test");
        let first = cache.get_or_parse(&path, parse_upper).unwrap();

        std::fs::write(&path, "two").unwrap();
        let past = SystemTime::now();
        std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(past)
            .unwrap();

        let second = cache.get_or_parse(&path, parse_upper).unwrap();
        assert!(
            !Arc::ptr_eq(&first, &second),
            "a backwards mtime move must still invalidate the cache entry"
        );
    }

    #[test]
    fn missing_path_returns_none() {
        let cache: MtimeFileCache<Parsed> = MtimeFileCache::new(DEFAULT_MAX_CACHED_FILES, "test");
        assert!(
            cache
                .get_or_parse(Path::new("/nonexistent/path/file.txt"), parse_upper)
                .is_none()
        );
    }

    /// Decision: a directory at the candidate path must never be treated as cacheable
    /// content — reading it would fail, but the `is_file` gate rejects it before that read is
    /// even attempted.
    #[test]
    fn directory_path_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let cache: MtimeFileCache<Parsed> = MtimeFileCache::new(DEFAULT_MAX_CACHED_FILES, "test");
        assert!(cache.get_or_parse(dir.path(), parse_upper).is_none());
    }

    /// At capacity, a freshly parsed value is still returned to the caller but not inserted
    /// into the map — the parse succeeds, only memoization is declined.
    #[test]
    fn capacity_cap_returns_value_without_inserting() {
        let dir = tempfile::tempdir().unwrap();
        let path_a = dir.path().join("a.txt");
        let path_b = dir.path().join("b.txt");
        std::fs::write(&path_a, "a").unwrap();
        std::fs::write(&path_b, "b").unwrap();

        let cache: MtimeFileCache<Parsed> = MtimeFileCache::new(1, "test");
        let first = cache.get_or_parse(&path_a, parse_upper).unwrap();
        assert_eq!(first.0, "A");

        let second = cache.get_or_parse(&path_b, parse_upper).unwrap();
        assert_eq!(second.0, "B", "the value is still returned despite the cap");

        // `b` was not cached (capacity already held `a`), so a repeat call re-parses it —
        // a fresh Arc, not the same one.
        let second_again = cache.get_or_parse(&path_b, parse_upper).unwrap();
        assert!(!Arc::ptr_eq(&second, &second_again));
    }
}
