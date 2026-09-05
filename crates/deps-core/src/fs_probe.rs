//! Counted filesystem probe funnel, shared by every ecosystem crate's config-file cache.
//!
//! [`crate::mtime_cache::MtimeFileCache`] claims "one stat, zero reads on a cache hit" — a
//! claim `Arc::ptr_eq` on the returned value cannot verify, since that only proves the
//! parsed *value* was reused, not that no syscall ran to get there. Counting actual
//! `stat`/`read` calls needs a single chokepoint every cache implementation routes through,
//! so the count is trustworthy across crate boundaries.
//!
//! Most wrappers below are a bare passthrough to their `std::fs` equivalent in a shipped
//! build (the exception is [`read_to_string_capped`], which adds a real size bound on top of
//! `File::open`/`Read::take`); the counters are compiled out entirely unless this crate is
//! built for its own tests or with the `test-util` feature, so counting one function's calls
//! costs nothing in production. `cfg(test)` alone cannot gate the public `snapshot` function,
//! because
//! `deps-core` is an ordinary (non-dev) dependency of `deps-cargo`/`deps-npm` — it is never
//! compiled with `cfg(test)` when a downstream crate's own tests build, so the `test-util`
//! feature is what those crates enable in their `dev-dependencies` instead.

use std::io::Read;
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

/// Counted, size-bounded wrapper around [`std::fs::File::open`] + [`Read::take`].
///
/// Reads at most `max_bytes + 1` bytes and returns `Ok(None)` if that read produced more than
/// `max_bytes` — the one extra byte is what distinguishes "exactly `max_bytes` long" from
/// "longer than `max_bytes`" without reading the whole (potentially huge) file. Unlike a
/// `stat`-then-`read_to_string` sequence, this bound is enforced by the read call itself, so
/// it holds even if the file grows, or is swapped via a symlink, between a caller's earlier
/// `stat` and this call.
///
/// # Errors
///
/// Returns an error under the same conditions as [`std::fs::read_to_string`] — most commonly,
/// `path` does not exist, is not accessible, or the bounded content is not valid UTF-8.
pub fn read_to_string_capped(path: &Path, max_bytes: u64) -> std::io::Result<Option<String>> {
    #[cfg(any(test, feature = "test-util"))]
    READ_COUNT.fetch_add(1, Ordering::Relaxed);
    let file = std::fs::File::open(path)?;
    let mut buf = Vec::new();
    file.take(max_bytes.saturating_add(1))
        .read_to_end(&mut buf)?;
    if buf.len() as u64 > max_bytes {
        return Ok(None);
    }
    String::from_utf8(buf)
        .map(Some)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.utf8_error()))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_to_string_capped_returns_content_under_cap() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("small.txt");
        std::fs::write(&path, "hello").unwrap();

        assert_eq!(
            read_to_string_capped(&path, 1024).unwrap().as_deref(),
            Some("hello")
        );
    }

    /// A file exactly at the cap must be read in full, not rejected as one byte too many —
    /// an off-by-one here would falsely reject every file that happens to land exactly on
    /// the boundary.
    #[test]
    fn read_to_string_capped_accepts_content_exactly_at_cap() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("exact.txt");
        std::fs::write(&path, "abcde").unwrap();

        assert_eq!(
            read_to_string_capped(&path, 5).unwrap().as_deref(),
            Some("abcde")
        );
    }

    /// The read itself must reject content over the cap — this holds regardless of what any
    /// separate `stat` call reported for the same path, which is the property that closes the
    /// TOCTOU gap (CWE-367) between a size check and a subsequent unbounded read.
    #[test]
    fn read_to_string_capped_rejects_content_over_cap() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("over.txt");
        std::fs::write(&path, "abcdef").unwrap();

        assert_eq!(read_to_string_capped(&path, 5).unwrap(), None);
    }

    #[test]
    fn read_to_string_capped_missing_path_errors() {
        assert!(read_to_string_capped(Path::new("/nonexistent/path/file.txt"), 1024).is_err());
    }
}
