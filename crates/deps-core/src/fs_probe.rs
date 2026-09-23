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

use std::io::{Read, Write};
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

/// Reads at most `max_bytes + 1` bytes from an already-open `file` and returns `Ok(None)` if
/// that read produced more than `max_bytes` — shared body for [`read_to_string_capped`] and
/// [`read_to_string_capped_no_follow`], which differ only in how they obtain `file`.
fn read_capped(file: std::fs::File, max_bytes: u64) -> std::io::Result<Option<String>> {
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

/// Counted, size-bounded wrapper around [`std::fs::File::open`] + [`Read::take`].
///
/// Reads at most `max_bytes + 1` bytes and returns `Ok(None)` if that read produced more than
/// `max_bytes` — the one extra byte is what distinguishes "exactly `max_bytes` long" from
/// "longer than `max_bytes`" without reading the whole (potentially huge) file. Unlike a
/// `stat`-then-`read_to_string` sequence, this bound is enforced by the read call itself, so
/// it holds even if the file grows, or is swapped via a symlink, between a caller's earlier
/// `stat` and this call.
///
/// This follows symlinks, matching [`std::fs::File::open`]'s own default — the right choice
/// for every existing caller (ecosystem config-file discovery, `deps-lsp`'s
/// `--follow-symlinks` mode), which read *through* an encountered symlink deliberately. A
/// caller that must instead refuse a symlinked path outright wants
/// [`read_to_string_capped_no_follow`].
///
/// # Errors
///
/// Returns an error under the same conditions as [`std::fs::read_to_string`] — most commonly,
/// `path` does not exist, is not accessible, or the bounded content is not valid UTF-8.
pub fn read_to_string_capped(path: &Path, max_bytes: u64) -> std::io::Result<Option<String>> {
    #[cfg(any(test, feature = "test-util"))]
    READ_COUNT.fetch_add(1, Ordering::Relaxed);
    let file = std::fs::File::open(path)?;
    read_capped(file, max_bytes)
}

/// Like [`read_to_string_capped`], but refuses to read through a symlinked `path`.
///
/// The single call that opens `path` is itself given the `O_NOFOLLOW` flag, so there is no
/// gap between checking for a symlink and reading through it (code review finding 2, #1329: a
/// separate `symlink_metadata` check followed by a plain, symlink-following open left a
/// check-then-open TOCTOU race — an attacker with write access to the manifest's directory
/// could swap in a symlink between the two calls).
///
/// On every Unix target (Linux on all architectures, macOS, and the BSDs), the kernel enforces
/// this atomically via `libc::O_NOFOLLOW` on the `open(2)` call — a symlinked `path` fails the
/// open outright, with no content ever read either way; this function then classifies that
/// failure into the distinct, well-worded error described below rather than a generic read
/// failure. On non-Unix platforms (Windows), std exposes no portable `O_NOFOLLOW` equivalent,
/// so this falls back to a `symlink_metadata` check immediately before the open — not atomic,
/// but narrows the window to the two syscalls happening back to back with no attacker-controlled
/// work between them, rather than leaving it open across this function's entire caller-side
/// read path.
///
/// # Errors
///
/// Returns an error under the same conditions as [`read_to_string_capped`], plus
/// [`std::io::ErrorKind::InvalidInput`] (matching [`write_atomic`]'s own symlink-refusal
/// error kind) when `path`'s final component is a symlink.
pub fn read_to_string_capped_no_follow(
    path: &Path,
    max_bytes: u64,
) -> std::io::Result<Option<String>> {
    #[cfg(any(test, feature = "test-util"))]
    READ_COUNT.fetch_add(1, Ordering::Relaxed);
    let file = open_no_follow(path)?;
    read_capped(file, max_bytes)
}

/// `std::io::ErrorKind::FilesystemLoop` (the semantically exact kind for this) is still an
/// unstable library feature (`io_error_more`, rust-lang/rust#86442) — `InvalidInput` is the
/// stable kind [`write_atomic`]'s own symlink refusal already uses, so this matches that
/// existing convention instead of introducing a second, inconsistent error shape.
fn symlink_refused_error(path: &Path) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        format!(
            "refusing to read through a symlinked path: {}",
            path.display()
        ),
    )
}

#[cfg(unix)]
fn open_no_follow(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;

    // The `O_NOFOLLOW` open itself is the atomic, race-free enforcement — it fails (ELOOP) if
    // `path`'s final component is a symlink, with no window between checking and opening. The
    // `symlink_metadata` call below runs only *after* that open already failed, purely to
    // classify the error into a specific, well-worded message; it is not security-load-bearing
    // (by this point nothing has been read either way) and cannot reintroduce the race this
    // function exists to close.
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| {
            if std::fs::symlink_metadata(path).is_ok_and(|meta| meta.file_type().is_symlink()) {
                symlink_refused_error(path)
            } else {
                error
            }
        })
}

#[cfg(not(unix))]
fn open_no_follow(path: &Path) -> std::io::Result<std::fs::File> {
    if std::fs::symlink_metadata(path).is_ok_and(|meta| meta.file_type().is_symlink()) {
        return Err(symlink_refused_error(path));
    }
    std::fs::File::open(path)
}

/// Atomically writes `content` to `path` (issue #1329, `deps-cli update`'s write path).
///
/// Refuses to write when `path`'s final path component is itself a symlink — checked via
/// [`std::fs::symlink_metadata`] before any temp file is created, so neither the symlink nor
/// its target is ever touched. Otherwise creates a temp file in `path`'s own directory via
/// `OpenOptions::create_new(true)` (`O_CREAT|O_EXCL`, closing the classic
/// symlink-pre-creation race by open-mode rather than by name unpredictability — anything,
/// including a dangling symlink, already at the temp path makes this call fail with
/// `AlreadyExists`). On Unix, the temp file is created directly at mode `0600` (via
/// `OpenOptionsExt::mode`), **not** the default `0644`-under-typical-umask a bare
/// `create_new` would produce — the temp path is a predictable, guessable name
/// (`{name}.deps-cli-{pid}-{nanos}.tmp`), and a window where it is world-readable under any
/// default mode would let another local user on the same host read the content before this
/// function ever gets to widen the permissions back. `path`'s original permissions are then
/// copied onto the **open temp handle** before writing any content, widening `0600` back to
/// the original's actual mode (e.g. `0644`) if that was ever narrower than the default. The
/// content is written and `sync_all`ed, then [`std::fs::rename`]d over `path`. On non-Unix
/// platforms the permission-copy step is skipped entirely (no Unix mode bits exist to copy)
/// — the destination directory's inherited ACL governs the renamed file instead. The temp
/// file is removed on every error path before returning.
///
/// **Accepted limitations**: `sync_all` covers only the temp file's own content durability,
/// not the `rename`'s directory-entry durability — that would additionally need the parent
/// directory itself fsynced, which this function does not do. This function alone does not
/// close the write-time TOCTOU window either: callers that need to detect a concurrent
/// modification between planning and writing must re-read and byte-compare the original
/// content themselves before calling this function (`rename(2)` has no compare-and-swap
/// primitive). `fs::rename`'s positive property — a target-side symlink is *replaced*, not
/// followed — is relied on deliberately here; do not "simplify" this to `fs::write`. A
/// pre-created file already sitting at the generated temp path makes `create_new` fail
/// outright (never silently overwritten) — this also means an attacker who can predict a
/// future invocation's `pid`/timestamp and pre-creates that exact path can wedge that one
/// `update` run; accepted, since the attacker already needs write access to the manifest's
/// own directory to do so, at which point tampering with the manifest directly is simpler.
///
/// # Errors
///
/// Returns an error if `path`'s final path component is a symlink, if the temp file cannot
/// be created (including because something already exists at the generated temp path) or
/// written, or if the rename fails.
pub fn write_atomic(path: &Path, content: &str) -> std::io::Result<()> {
    if std::fs::symlink_metadata(path).is_ok_and(|meta| meta.file_type().is_symlink()) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "refusing to write through a symlinked manifest path: {}",
                path.display()
            ),
        ));
    }

    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path.file_name().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "manifest path has no file name",
        )
    })?;
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    let tmp_path = dir.join(format!(
        "{}.deps-cli-{}-{nanos}.tmp",
        file_name.to_string_lossy(),
        std::process::id(),
    ));

    let mut open_options = std::fs::OpenOptions::new();
    open_options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // Created narrow (0600), then widened to the original file's actual mode below —
        // never briefly world-readable at the default `0644`-under-typical-umask a bare
        // `create_new` would produce.
        open_options.mode(0o600);
    }
    let mut file = open_options.open(&tmp_path)?;

    let write_result = write_atomic_content(&mut file, path, content);
    drop(file);

    match write_result {
        Ok(()) => {
            if let Err(error) = std::fs::rename(&tmp_path, path) {
                let _ = std::fs::remove_file(&tmp_path);
                Err(error)
            } else {
                Ok(())
            }
        }
        Err(error) => {
            let _ = std::fs::remove_file(&tmp_path);
            Err(error)
        }
    }
}

/// [`write_atomic`]'s permission-copy-then-write step, split out so the temp-handle
/// permission set always happens before any content byte is written.
fn write_atomic_content(
    file: &mut std::fs::File,
    original_path: &Path,
    content: &str,
) -> std::io::Result<()> {
    #[cfg(unix)]
    if let Ok(original_meta) = std::fs::metadata(original_path) {
        file.set_permissions(original_meta.permissions())?;
    }
    #[cfg(not(unix))]
    let _ = original_path;

    file.write_all(content.as_bytes())?;
    file.sync_all()
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
#[cfg(any(test, feature = "test-util"))]
#[must_use]
pub fn snapshot() -> (usize, usize) {
    (
        STAT_COUNT.load(Ordering::Relaxed),
        READ_COUNT.load(Ordering::Relaxed),
    )
}

/// Backing lock for [`snapshot_guard`]/[`snapshot_guard_async`] — shared so a sync and an
/// async caller serialize against each other, not just against callers of the same function.
#[cfg(any(test, feature = "test-util"))]
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
#[cfg(any(test, feature = "test-util"))]
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
#[cfg(any(test, feature = "test-util"))]
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

    #[test]
    fn write_atomic_replaces_content() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("Cargo.toml");
        std::fs::write(&path, "old content").unwrap();

        write_atomic(&path, "new content").unwrap();

        assert_eq!(std::fs::read_to_string(&path).unwrap(), "new content");
        // No stray temp file left behind after a successful write.
        let leftover: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name() != "Cargo.toml")
            .collect();
        assert!(
            leftover.is_empty(),
            "temp file must be renamed away, not left behind"
        );
    }

    #[test]
    fn write_atomic_creates_new_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("Cargo.toml");

        write_atomic(&path, "content").unwrap();

        assert_eq!(std::fs::read_to_string(&path).unwrap(), "content");
    }

    #[test]
    fn read_to_string_capped_no_follow_reads_a_plain_file() {
        // See the comment in `read_to_string_capped_returns_content_under_cap` on why this
        // guard is needed here — this function increments the same `READ_COUNT`.
        let _guard = snapshot_guard();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("Cargo.toml");
        std::fs::write(&path, "content").unwrap();

        assert_eq!(
            read_to_string_capped_no_follow(&path, 1000).unwrap(),
            Some("content".to_string())
        );
    }

    #[cfg(unix)]
    #[test]
    fn read_to_string_capped_no_follow_refuses_a_symlinked_path() {
        use std::os::unix::fs::symlink;

        let _guard = snapshot_guard();
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("real.toml");
        std::fs::write(&target, "real content").unwrap();
        let link = dir.path().join("Cargo.toml");
        symlink(&target, &link).unwrap();

        let result = read_to_string_capped_no_follow(&link, 1000);

        assert!(result.is_err(), "a symlinked path must be refused");
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::InvalidInput);
    }

    #[cfg(unix)]
    #[test]
    fn write_atomic_refuses_symlinked_manifest_path() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("real.toml");
        std::fs::write(&target, "real content").unwrap();
        let link = dir.path().join("Cargo.toml");
        symlink(&target, &link).unwrap();

        let result = write_atomic(&link, "attacker content");

        assert!(result.is_err(), "a symlinked manifest path must be refused");
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "real content");
        assert!(
            std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink(),
            "the symlink itself must be left untouched"
        );
        // No temp file created before the refusal.
        let leftover: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| {
                let name = entry.file_name();
                name != "real.toml" && name != "Cargo.toml"
            })
            .collect();
        assert!(
            leftover.is_empty(),
            "no temp file must be created before refusal"
        );
    }

    #[cfg(unix)]
    #[test]
    fn write_atomic_preserves_unix_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("Cargo.toml");
        std::fs::write(&path, "old content").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

        write_atomic(&path, "new content").unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "the original file's mode must survive the atomic rewrite"
        );
    }

    /// Security-S1 regression: the temp file must never be created at a mode wider than the
    /// original's — this test uses an original mode *wider* than the temp file's initial
    /// `0600` (`0644`) to prove the permission-copy step still widens back out correctly
    /// (not permanently stuck at `0600`), while the create-time mode itself (verified by
    /// inspection, not by this test — see the doc comment) is never `0644`-by-default.
    #[cfg(unix)]
    #[test]
    fn write_atomic_widens_permissions_when_original_is_wider_than_temp_default() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("Cargo.toml");
        std::fs::write(&path, "old content").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        write_atomic(&path, "new content").unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o644,
            "the original file's wider mode must be restored, not left at the temp file's \
             narrower creation-time mode"
        );
    }

    #[cfg(unix)]
    #[test]
    fn write_atomic_original_content_untouched_on_temp_create_failure() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("Cargo.toml");
        std::fs::write(&path, "original content").unwrap();
        // Make the directory read-only so `OpenOptions::create_new` cannot create the temp
        // file at all — a portable failure injection for "the temp file could not be
        // created", proving the original manifest is never touched in that case.
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o500)).unwrap();

        let result = write_atomic(&path, "new content");

        // Restore permissions so the tempdir can be cleaned up.
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();

        assert!(result.is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "original content");
    }

    /// FR-018: the positive property `write_atomic`'s write-time TOCTOU window relies on —
    /// `fs::rename`'s target-side symlink is *replaced*, not followed. Exercised directly
    /// against `std::fs::rename` (not through `write_atomic`, which refuses upfront whenever
    /// `path` is already a symlink at call time — see
    /// `write_atomic_refuses_symlinked_manifest_path`) since this is an OS-level guarantee
    /// the accepted TOCTOU window relies on, not a check this crate performs itself. A future
    /// "simplification" to `fs::write` would silently lose this property.
    #[cfg(unix)]
    #[test]
    fn fs_rename_replaces_a_target_side_symlink_rather_than_its_target() {
        let dir = tempfile::tempdir().unwrap();
        let real_target = dir.path().join("real_target.txt");
        std::fs::write(&real_target, "target content").unwrap();
        let symlink_path = dir.path().join("symlink.txt");
        std::os::unix::fs::symlink(&real_target, &symlink_path).unwrap();

        let new_path = dir.path().join("new_content.txt");
        std::fs::write(&new_path, "new content").unwrap();

        std::fs::rename(&new_path, &symlink_path).unwrap();

        assert!(
            !std::fs::symlink_metadata(&symlink_path)
                .unwrap()
                .file_type()
                .is_symlink(),
            "the symlink itself must be replaced by a regular file"
        );
        assert_eq!(
            std::fs::read_to_string(&symlink_path).unwrap(),
            "new content"
        );
        assert_eq!(
            std::fs::read_to_string(&real_target).unwrap(),
            "target content",
            "the symlink's original target must never be written through"
        );
    }
}
