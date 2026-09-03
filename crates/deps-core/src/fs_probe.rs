//! Counted filesystem probe funnel, shared by every ecosystem crate's config-file cache.
//!
//! [`crate::mtime_cache::MtimeFileCache`] claims "one stat, zero reads on a cache hit" — a
//! claim `Arc::ptr_eq` on the returned value cannot verify, since that only proves the
//! parsed *value* was reused, not that no syscall ran to get there. Counting actual
//! `stat`/`read` calls needs a single chokepoint every cache implementation routes through,
//! so the count is trustworthy across crate boundaries.
//!
//! Every wrapper below is a bare passthrough to its `std::fs` equivalent in a shipped build:
//! the counters are compiled out entirely unless this crate is built for its own tests or
//! with the `test-util` feature, so counting one function's calls costs nothing in
//! production. `cfg(test)` alone cannot gate the public [`snapshot`] function, because
//! `deps-core` is an ordinary (non-dev) dependency of `deps-cargo`/`deps-npm` — it is never
//! compiled with `cfg(test)` when a downstream crate's own tests build, so the `test-util`
//! feature is what those crates enable in their `dev-dependencies` instead.

use std::path::Path;

#[cfg(any(test, feature = "test-util"))]
use std::sync::atomic::{AtomicUsize, Ordering};

#[cfg(any(test, feature = "test-util"))]
static STAT_COUNT: AtomicUsize = AtomicUsize::new(0);
#[cfg(any(test, feature = "test-util"))]
static READ_COUNT: AtomicUsize = AtomicUsize::new(0);

/// Counted wrapper around [`std::fs::metadata`].
///
/// # Errors
///
/// Returns an error under the same conditions as [`std::fs::metadata`] — most commonly,
/// `path` does not exist or is not accessible.
pub fn metadata(path: &Path) -> std::io::Result<std::fs::Metadata> {
    #[cfg(any(test, feature = "test-util"))]
    STAT_COUNT.fetch_add(1, Ordering::Relaxed);
    std::fs::metadata(path)
}

/// Counted wrapper around [`std::fs::read_to_string`].
///
/// # Errors
///
/// Returns an error under the same conditions as [`std::fs::read_to_string`] — most
/// commonly, `path` does not exist, is not accessible, or is not valid UTF-8.
pub fn read_to_string(path: &Path) -> std::io::Result<String> {
    #[cfg(any(test, feature = "test-util"))]
    READ_COUNT.fetch_add(1, Ordering::Relaxed);
    std::fs::read_to_string(path)
}

/// Whether `path` exists and is a regular file — `false` on any error, including a missing
/// path.
///
/// Deliberately rejects a FIFO, socket, character device, or directory at `path`: unlike a
/// regular file, reading one of those can **block the calling thread indefinitely**, which
/// would stall the parse. [`std::fs::metadata`] follows symlinks, so a symlinked regular
/// file still resolves as a file here.
///
/// Callers that already hold a [`std::fs::Metadata`] from [`metadata`] (as
/// [`crate::mtime_cache::MtimeFileCache`] does) should call `.is_file()` on it directly
/// rather than re-probing through here.
///
/// # Examples
///
/// ```
/// use deps_core::fs_probe::is_file;
/// use std::path::Path;
///
/// assert!(!is_file(Path::new("/nonexistent/path/to/nowhere")));
/// ```
#[must_use]
pub fn is_file(path: &Path) -> bool {
    metadata(path).is_ok_and(|m| m.is_file())
}

/// Whether `path` exists — `false` on any error, including a missing path.
#[must_use]
pub fn exists(path: &Path) -> bool {
    metadata(path).is_ok()
}

/// The current `(stat_count, read_count)` totals.
///
/// For a test to snapshot before an operation and diff against afterward — never a global
/// "reset to zero", since `cargo nextest` gives each test its own process but a bare
/// count-from-zero would still race a hypothetical future multi-threaded runner.
#[cfg(feature = "test-util")]
#[must_use]
pub fn snapshot() -> (usize, usize) {
    (
        STAT_COUNT.load(Ordering::Relaxed),
        READ_COUNT.load(Ordering::Relaxed),
    )
}
