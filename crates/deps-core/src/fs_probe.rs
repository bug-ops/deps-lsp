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
//!
//! Any test in `deps-core`, `deps-gradle`, `deps-cargo`, `deps-npm`, `deps-nuget`, or
//! `deps-lsp` that touches `fs_probe` (directly, through [`crate::mtime_cache::MtimeFileCache`],
//! through an ecosystem's own config-file cache, or through `Ecosystem::parse_manifest`) must
//! hold [`snapshot_guard`]/[`snapshot_guard_async`] for the duration of that touch — see
//! [`snapshot_guard`]'s doc for why. Nothing enforces this at compile time; run
//! `scripts/check-fs-probe-race.sh` after adding a new fs_probe-touching test in one of those
//! six crates to catch a missing guard before it reaches CI's i686 cross-test leg (issue #806).

use std::io::Read;
use std::path::Path;

/// Shared upper bound on how many ancestor directories a config-file discovery walk
/// climbs, independent of whether the filesystem root has been reached.
///
/// `deps-gradle`, `deps-cargo`, `deps-npm`, and `deps-nuget` all import this canonical
/// definition directly for their own workspace-root / config-file ancestor walks, rather
/// than each declaring their own duplicate. 64 directories up is not a realistic project
/// layout — a pathologically deep or hostile tree hits this cap instead of doing unbounded
/// work per parse (CWE-400).
pub const MAX_CONFIG_ANCESTOR_DEPTH: usize = 64;

/// Ancestor directories of `start_dir`, inclusive, capped at [`MAX_CONFIG_ANCESTOR_DEPTH`].
///
/// Yields `start_dir` itself first, then each successive parent, stopping at whichever
/// comes first: the filesystem root, or [`MAX_CONFIG_ANCESTOR_DEPTH`] directories visited.
/// This is the single canonical replacement for the hand-written
/// `while let Some(dir) = current { if depth >= MAX_CONFIG_ANCESTOR_DEPTH { break; } ... }`
/// loop every ancestor-config-file walk in this workspace used to duplicate — the depth
/// bound is enforced by the iterator itself, so a caller cannot forget it.
///
/// # Examples
///
/// ```
/// use deps_core::fs_probe::config_ancestors;
/// use std::path::Path;
///
/// let dirs: Vec<_> = config_ancestors(Path::new("/a/b/c")).collect();
/// assert_eq!(
///     dirs,
///     vec![Path::new("/a/b/c"), Path::new("/a/b"), Path::new("/a"), Path::new("/")]
/// );
/// ```
pub fn config_ancestors(start_dir: &Path) -> impl Iterator<Item = &Path> {
    std::iter::successors(Some(start_dir), |d| d.parent()).take(MAX_CONFIG_ANCESTOR_DEPTH)
}

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

/// Backing lock for [`snapshot_guard`]/[`snapshot_guard_async`] — shared so a sync and an
/// async caller serialize against each other, not just against callers of the same function.
#[cfg(feature = "test-util")]
static SNAPSHOT_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Serializes a `snapshot`-before/operation/`snapshot`-after/assert section, run from a plain
/// (non-async) test, against every other test doing the same.
///
/// [`snapshot`] reads the process-global `STAT_COUNT`/`READ_COUNT` counters, so a
/// before/after diff is only race-free when nothing else touches `fs_probe` between the two
/// calls. `cargo nextest run` gives each test its own process, which happens to make that
/// true — but plain `cargo test` runs every test in one multi-threaded process, where a
/// concurrently running `fs_probe`-touching test can bump the same counters mid-section and
/// produce a spurious failure. Hold this guard for the whole section under measurement
/// (both `snapshot()` calls and everything between them), not just around the calls
/// themselves, so no other snapshot-based test can interleave.
///
/// This is not limited to tests that themselves diff a snapshot: **every** test in the same
/// binary that calls an `fs_probe`-touching function (directly or transitively, e.g. through
/// [`crate::mtime_cache::MtimeFileCache`] or an ecosystem's own config-file cache) must also
/// acquire this guard for the duration of that call — otherwise it can still bump the
/// counters mid-diff even though it never calls [`snapshot`] itself. Verified empirically:
/// guarding only the diffing test left `deps-gradle`'s and `deps-core`'s own snapshot-diff
/// tests flaky under plain `cargo test` (siblings in the same file that call the same
/// instrumented function without diffing were still free to interleave) until every
/// fs_probe-touching test in those files took the guard too.
///
/// Use [`snapshot_guard_async`] instead from an `async fn` test.
///
/// # Panics
///
/// Panics if called from inside an async execution context (e.g. from within a
/// `#[tokio::test] async fn` — use [`snapshot_guard_async`] there instead).
///
/// # Examples
///
/// ```
/// use deps_core::fs_probe::{snapshot, snapshot_guard};
///
/// let _guard = snapshot_guard();
/// let (stats_before, _) = snapshot();
/// // ... perform the operation under test ...
/// let (stats_after, _) = snapshot();
/// assert!(stats_after >= stats_before);
/// ```
#[cfg(feature = "test-util")]
#[must_use = "dropping the guard immediately releases it, guarding nothing — bind it to a \
              named variable (e.g. `let _guard = snapshot_guard();`) held for the whole \
              measured section"]
pub fn snapshot_guard() -> tokio::sync::MutexGuard<'static, ()> {
    SNAPSHOT_LOCK.blocking_lock()
}

/// Async counterpart of [`snapshot_guard`], for a test whose measured section spans an
/// `.await` point (e.g. an async `load_document_from_disk` call).
///
/// A `std::sync::MutexGuard` held across an `.await` would stall the runtime for the
/// duration of the wait — this returns a `tokio::sync::MutexGuard` instead, which is safe to
/// hold across `.await`.
///
/// # Panics
///
/// Never panics — unlike [`snapshot_guard`], this is always safe to call from an async
/// execution context, since it yields to the runtime instead of blocking the thread.
///
/// # Examples
///
/// ```
/// use deps_core::fs_probe::{snapshot, snapshot_guard_async};
///
/// # #[tokio::main]
/// # async fn main() {
/// let _guard = snapshot_guard_async().await;
/// let (stats_before, _) = snapshot();
/// // ... perform the async operation under test ...
/// let (stats_after, _) = snapshot();
/// assert!(stats_after >= stats_before);
/// # }
/// ```
#[cfg(feature = "test-util")]
#[must_use = "dropping the guard immediately releases it, guarding nothing — bind it to a \
              named variable (e.g. `let _guard = snapshot_guard_async().await;`) held for the \
              whole measured section"]
pub async fn snapshot_guard_async() -> tokio::sync::MutexGuard<'static, ()> {
    SNAPSHOT_LOCK.lock().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_to_string_capped_returns_content_under_cap() {
        // Held per `snapshot_guard`'s doc: this module's own tests call the very functions
        // instrumented for counting, and run in the same test binary as other modules'
        // (e.g. `mtime_cache`'s) diffing tests.
        let _guard = snapshot_guard();
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
        // See the comment in `read_to_string_capped_returns_content_under_cap` on why this
        // guard is needed here.
        let _guard = snapshot_guard();
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
        // See the comment in `read_to_string_capped_returns_content_under_cap` on why this
        // guard is needed here.
        let _guard = snapshot_guard();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("over.txt");
        std::fs::write(&path, "abcdef").unwrap();

        assert_eq!(read_to_string_capped(&path, 5).unwrap(), None);
    }

    #[test]
    fn read_to_string_capped_missing_path_errors() {
        // See the comment in `read_to_string_capped_returns_content_under_cap` on why this
        // guard is needed here.
        let _guard = snapshot_guard();
        assert!(read_to_string_capped(Path::new("/nonexistent/path/file.txt"), 1024).is_err());
    }
}
