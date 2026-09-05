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

/// Maximum file size [`MtimeFileCache::get_or_parse`] reads before parsing.
///
/// Enforced twice: a cheap [`std::fs::Metadata::len`] pre-filter rejects an obviously oversized
/// file before it is even opened, and [`crate::fs_probe::read_to_string_capped`] then bounds
/// the actual read itself, so an oversized file (e.g. a crafted `pnpm-workspace.yaml` in a
/// cloned repository) never reaches `YamlLoader` or any content-based guard like
/// [`crate::check_yaml_nesting_depth`]/[`crate::check_yaml_expansion`] — those guards run on
/// content already read into memory, so they cannot bound the read itself. The capped read is
/// what actually closes the gap: the `stat` pre-filter alone would leave a TOCTOU window where
/// a symlink swap or concurrent growth between the `stat` and the read could let an oversized
/// file's content through. 8 MiB matches [`crate::cache`]'s `MAX_CACHEABLE_ENTRY_BYTES` order
/// of magnitude and is generous for a real config file (`.cargo/config.toml`, `.npmrc`,
/// `pnpm-workspace.yaml`), which are typically a few KB.
pub const MAX_CACHED_FILE_BYTES: u64 = 8 * 1024 * 1024;

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
    /// Last mtime an oversized path was warned about, so [`Self::get_or_parse`] logs at most
    /// once per distinct file version rather than once per call — an oversized file is never
    /// cached in `files`, so without this every hover/completion/diagnostic pass touching it
    /// would otherwise re-emit the same warning (impl-critic S2). Bounded by `capacity`, same
    /// as `files`: once full, a repeat warning is simply not deduped rather than growing this
    /// map without limit.
    oversize_warned: dashmap::DashMap<PathBuf, SystemTime>,
    capacity: usize,
    label: &'static str,
}

impl<T> std::fmt::Debug for MtimeFileCache<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MtimeFileCache")
            .field("label", &self.label)
            .field("capacity", &self.capacity)
            .field("len", &self.files.len())
            .finish_non_exhaustive()
    }
}

impl<T> MtimeFileCache<T> {
    /// Creates an empty cache holding at most `capacity` entries, labeled `label` for
    /// diagnostics (e.g. `"cargo config"`, `"npm config"`) when the capacity is reached.
    #[must_use]
    pub fn new(capacity: usize, label: &'static str) -> Self {
        Self {
            files: dashmap::DashMap::new(),
            oversize_warned: dashmap::DashMap::new(),
            capacity,
            label,
        }
    }

    /// Logs the "oversized, not caching" warning at most once per distinct `mtime`, deduping
    /// via [`Self::oversize_warned`] exactly like the pre-existing stat-based rejection path.
    /// `len` is the known content length when available (the cheap stat pre-filter has it);
    /// the capped-read rejection path does not know the exact length without reading the
    /// whole oversized file, so it passes `None` and the length is simply omitted from the log.
    fn warn_oversized_once(&self, path: &Path, mtime: Option<SystemTime>, len: Option<u64>) {
        let already_warned = mtime.is_some_and(|mtime| {
            self.oversize_warned
                .get(path)
                .is_some_and(|warned| *warned == mtime)
        });
        if already_warned {
            return;
        }
        tracing::warn!(
            path = %path.display(),
            label = self.label,
            len,
            cap = MAX_CACHED_FILE_BYTES,
            "file exceeds mtime file cache size cap; not reading"
        );
        if let Some(mtime) = mtime
            && self.oversize_warned.len() < self.capacity
        {
            self.oversize_warned.insert(path.to_path_buf(), mtime);
        }
    }

    /// Returns `path`'s parsed contents, from cache if `path`'s mtime is unchanged, else
    /// re-reading and re-parsing with `parse`. `None` if `path` does not exist, is not a
    /// regular file, exceeds [`MAX_CACHED_FILE_BYTES`], or cannot be read.
    ///
    /// Rejects anything but a regular file (a FIFO, socket, character device, or directory) as
    /// observed at `stat` time — reading one of those can block the calling thread
    /// indefinitely, and [`std::fs::metadata`] follows symlinks, so a symlinked regular file
    /// still resolves. This check is necessarily a point-in-time observation, not a guarantee
    /// about what [`crate::fs_probe::read_to_string_capped`] will see: a symlink that resolved
    /// to a regular file at `stat` time can still be swapped to a FIFO before the subsequent
    /// `open` (the same TOCTOU class as the size check below), which would still block on
    /// open. Fixing that blocking-open race is out of scope here (it needs `O_NONBLOCK` or
    /// equivalent); this doc only avoids overclaiming that the gate rules it out.
    ///
    /// A file over [`MAX_CACHED_FILE_BYTES`] never reaches `parse` — every content-based
    /// safety guard (nesting-depth, expansion) only sees content already read into memory, so
    /// it cannot bound the read itself. This is enforced twice: the `stat` result is checked
    /// first as a cheap pre-filter (skips opening an obviously huge file), and
    /// [`crate::fs_probe::read_to_string_capped`] then bounds the read itself regardless of
    /// what the `stat` reported — so a symlink swap or concurrent growth between the `stat`
    /// and the read cannot let an oversized file's content slip through (CWE-367).
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
        if metadata.len() > MAX_CACHED_FILE_BYTES {
            self.warn_oversized_once(path, metadata.modified().ok(), Some(metadata.len()));
            return None;
        }
        let mtime = metadata.modified().ok()?;

        if let Some(existing) = self.files.get(path)
            && existing.mtime == mtime
        {
            return Some(Arc::clone(&existing.value));
        }

        let content = match fs_probe::read_to_string_capped(path, MAX_CACHED_FILE_BYTES).ok()? {
            Some(content) => content,
            None => {
                // The stat-based pre-filter above passed, but the read itself still hit the
                // cap — a symlink swap or concurrent growth between the two calls (CWE-367).
                // Same outward behavior as the stat-based rejection: not cached, warned once.
                self.warn_oversized_once(path, Some(mtime), None);
                return None;
            }
        };
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

    /// A file over [`MAX_CACHED_FILE_BYTES`] must never reach `parse` at all — rejected here by
    /// the cheap `stat` pre-filter. `fs_probe::tests::read_to_string_capped_rejects_content_over_cap`
    /// proves the same bound holds on the read itself, independent of any `stat` result —
    /// that is what closes the TOCTOU gap (CWE-367) a stat-only check would leave open.
    #[test]
    fn oversized_file_returns_none_without_reading_content() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("huge.txt");
        let file = std::fs::File::create(&path).unwrap();
        file.set_len(MAX_CACHED_FILE_BYTES + 1).unwrap();
        drop(file);

        let cache: MtimeFileCache<Parsed> = MtimeFileCache::new(DEFAULT_MAX_CACHED_FILES, "test");
        let parse_calls = std::cell::Cell::new(0);
        let result = cache.get_or_parse(&path, |content| {
            parse_calls.set(parse_calls.get() + 1);
            parse_upper(content)
        });

        assert!(result.is_none());
        assert_eq!(
            parse_calls.get(),
            0,
            "parse must not run on an oversized file"
        );
    }

    /// A file exactly at [`MAX_CACHED_FILE_BYTES`] must still be cached — the capped read
    /// reads one byte past the cap to detect an overage, and an off-by-one there would
    /// falsely reject a file that lands exactly on the boundary.
    #[test]
    fn file_exactly_at_cap_is_still_cached() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("exact.txt");
        let content = "a".repeat(MAX_CACHED_FILE_BYTES as usize);
        std::fs::write(&path, &content).unwrap();

        let cache: MtimeFileCache<Parsed> = MtimeFileCache::new(DEFAULT_MAX_CACHED_FILES, "test");
        let result = cache.get_or_parse(&path, parse_upper);

        assert!(result.is_some(), "a file exactly at the cap must be cached");
    }

    /// Impl-critic S2 regression: an oversized file must warn at most once per distinct
    /// mtime, not once per call — an oversized file is never memoized in `files`, so without
    /// this every hover/completion/diagnostic pass touching it would re-emit the warning.
    #[test]
    fn oversized_file_warns_once_per_mtime_not_once_per_call() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("huge.txt");
        let file = std::fs::File::create(&path).unwrap();
        file.set_len(MAX_CACHED_FILE_BYTES + 1).unwrap();
        drop(file);

        let cache: MtimeFileCache<Parsed> = MtimeFileCache::new(DEFAULT_MAX_CACHED_FILES, "test");

        let log = crate::test_util::capture_tracing_output(|| {
            assert!(cache.get_or_parse(&path, parse_upper).is_none());
            assert!(cache.get_or_parse(&path, parse_upper).is_none());
            assert!(cache.get_or_parse(&path, parse_upper).is_none());
        });

        assert_eq!(
            log.matches("file exceeds mtime file cache size cap")
                .count(),
            1,
            "expected exactly one warning across three calls with an unchanged mtime: {log}"
        );
    }

    /// A file that changes (still oversized) after already being warned about must warn
    /// again — the dedup is per file *version*, not a one-time-ever suppression.
    #[test]
    fn oversized_file_warns_again_after_mtime_changes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("huge.txt");
        let file = std::fs::File::create(&path).unwrap();
        file.set_len(MAX_CACHED_FILE_BYTES + 1).unwrap();
        drop(file);

        let cache: MtimeFileCache<Parsed> = MtimeFileCache::new(DEFAULT_MAX_CACHED_FILES, "test");

        let log = crate::test_util::capture_tracing_output(|| {
            assert!(cache.get_or_parse(&path, parse_upper).is_none());

            // Ensure a distinguishable mtime on filesystems with coarse timestamp resolution.
            let future = SystemTime::now() + std::time::Duration::from_secs(2);
            let file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
            file.set_len(MAX_CACHED_FILE_BYTES + 2).unwrap();
            file.set_modified(future).unwrap();
            drop(file);

            assert!(cache.get_or_parse(&path, parse_upper).is_none());
        });

        assert_eq!(
            log.matches("file exceeds mtime file cache size cap")
                .count(),
            2,
            "expected a fresh warning after the file's mtime changed: {log}"
        );
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
