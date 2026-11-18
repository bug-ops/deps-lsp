//! #2054 acceptance (track C): `LockFileCache::get_or_parse` lists a lock set once and hands that
//! listing to `LockFileProvider::parse_lock_set`; the directory that produced the listing is
//! stamped BEFORE the listing so a file created in between invalidates the entry (#359 rule).
//!
//! Written tests-first against plan revision 3 (`.local/handoff/2026-11-18T00-57-21-architect.md`);
//! the two defaulted trait methods `parse_lock_set` and `companion_listing_dir` do not exist yet.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime};

use deps_core::ResolvedPackages;
use deps_core::lockfile::{LockFileCache, LockFileProvider};
use url::Url;

type ParseFuture<'a> =
    Pin<Box<dyn std::future::Future<Output = deps_core::Result<ResolvedPackages>> + Send + 'a>>;

fn set_dir_modified(dir: &Path, time: SystemTime) {
    #[cfg(windows)]
    let handle = {
        use std::os::windows::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .access_mode(0x100)
            .custom_flags(0x0200_0000)
            .open(dir)
            .unwrap()
    };
    #[cfg(not(windows))]
    let handle = std::fs::File::open(dir).unwrap();
    handle.set_modified(time).unwrap();
}

fn in_the_past(dir: &Path) {
    set_dir_modified(dir, SystemTime::now() - Duration::from_secs(60));
}

/// Provider whose lock set is `main.lock` plus every other `*.lock` in its directory, with the
/// directory itself the first companion and the listing directory.
#[derive(Default)]
struct ListingProvider {
    listings: AtomicUsize,
    set_parses: AtomicUsize,
    single_parses: AtomicUsize,
    received: Mutex<Vec<Vec<PathBuf>>>,
    /// Creates this file in the listed directory while listing (after the directory stat).
    create_while_listing: Mutex<Option<PathBuf>>,
}

impl ListingProvider {
    fn listing(&self, located: &Path) -> Vec<PathBuf> {
        self.listings.fetch_add(1, Ordering::SeqCst);
        let dir = located.parent().unwrap();
        let late = self.create_while_listing.lock().unwrap().take();
        if let Some(path) = late {
            std::fs::write(path, "x").unwrap();
        }
        let mut files: Vec<PathBuf> = std::fs::read_dir(dir)
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| path.extension().is_some_and(|e| e == "lock") && path != located)
            .collect();
        files.sort();
        std::iter::once(dir.to_path_buf()).chain(files).collect()
    }
}

impl LockFileProvider for ListingProvider {
    fn locate_lockfile(&self, _manifest_uri: &Url) -> Option<PathBuf> {
        None
    }

    fn companion_lockfiles(&self, located: &Path) -> Vec<PathBuf> {
        self.listing(located)
    }

    fn companion_listing_dir(&self, located: &Path) -> Option<PathBuf> {
        located.parent().map(Path::to_path_buf)
    }

    fn parse_lockfile<'a>(&'a self, _lockfile_path: &'a Path) -> ParseFuture<'a> {
        self.single_parses.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok(ResolvedPackages::new()) })
    }

    fn parse_lock_set<'a>(
        &'a self,
        _located: &'a Path,
        companions: &'a [PathBuf],
    ) -> ParseFuture<'a> {
        self.set_parses.fetch_add(1, Ordering::SeqCst);
        self.received.lock().unwrap().push(companions.to_vec());
        Box::pin(async { Ok(ResolvedPackages::new()) })
    }
}

/// A provider that implements neither new method: the defaults must keep today's behaviour.
#[derive(Default)]
struct PlainProvider {
    single_parses: AtomicUsize,
}

impl LockFileProvider for PlainProvider {
    fn locate_lockfile(&self, _manifest_uri: &Url) -> Option<PathBuf> {
        None
    }

    fn parse_lockfile<'a>(&'a self, _lockfile_path: &'a Path) -> ParseFuture<'a> {
        self.single_parses.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok(ResolvedPackages::new()) })
    }
}

fn fixture() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let located = dir.path().canonicalize().unwrap().join("main.lock");
    std::fs::write(&located, "1").unwrap();
    in_the_past(located.parent().unwrap());
    (dir, located)
}

#[test]
fn companion_listing_dir_defaults_to_none() {
    assert_eq!(
        PlainProvider::default().companion_listing_dir(Path::new("/a/b.lock")),
        None
    );
}

#[tokio::test]
async fn parse_lock_set_default_delegates_to_parse_lockfile() {
    let provider = PlainProvider::default();
    let located = Path::new("/a/b.lock");

    provider.parse_lock_set(located, &[]).await.unwrap();

    assert_eq!(provider.single_parses.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn get_or_parse_with_default_methods_parses_through_parse_lockfile_once() {
    let (_dir, located) = fixture();
    let provider = PlainProvider::default();
    let cache = LockFileCache::new();

    cache.get_or_parse(&provider, &located).await.unwrap();
    cache.get_or_parse(&provider, &located).await.unwrap();

    assert_eq!(provider.single_parses.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn get_or_parse_lists_the_lock_set_once_and_passes_that_listing_to_parse_lock_set() {
    let (dir, located) = fixture();
    std::fs::write(dir.path().join("a.lock"), "a").unwrap();
    in_the_past(dir.path());
    let provider = ListingProvider::default();
    let cache = LockFileCache::new();

    cache.get_or_parse(&provider, &located).await.unwrap();

    assert_eq!(provider.listings.load(Ordering::SeqCst), 1, "listed once");
    assert_eq!(provider.set_parses.load(Ordering::SeqCst), 1);
    assert_eq!(
        provider.single_parses.load(Ordering::SeqCst),
        0,
        "the cache parses through parse_lock_set, never re-listing via parse_lockfile"
    );
    let received = provider.received.lock().unwrap();
    assert_eq!(
        received[0],
        vec![
            located.parent().unwrap().to_path_buf(),
            located.parent().unwrap().join("a.lock")
        ]
    );
}

#[tokio::test]
async fn cache_hit_neither_lists_nor_parses_again() {
    let (_dir, located) = fixture();
    let provider = ListingProvider::default();
    let cache = LockFileCache::new();

    cache.get_or_parse(&provider, &located).await.unwrap();
    cache.get_or_parse(&provider, &located).await.unwrap();

    assert_eq!(provider.listings.load(Ordering::SeqCst), 1);
    assert_eq!(provider.set_parses.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn file_created_while_listing_invalidates_the_entry_on_the_next_lookup() {
    let (dir, located) = fixture();
    let provider = ListingProvider::default();
    *provider.create_while_listing.lock().unwrap() = Some(dir.path().join("late.lock"));
    let cache = LockFileCache::new();

    cache.get_or_parse(&provider, &located).await.unwrap();
    assert_eq!(provider.set_parses.load(Ordering::SeqCst), 1);

    cache.get_or_parse(&provider, &located).await.unwrap();
    assert_eq!(
        provider.set_parses.load(Ordering::SeqCst),
        2,
        "the directory was stamped before the listing, so the creation is newer than the stamp"
    );
    cache.get_or_parse(&provider, &located).await.unwrap();
    assert_eq!(provider.set_parses.load(Ordering::SeqCst), 2, "now stable");
}

#[tokio::test]
async fn file_added_to_and_removed_from_the_listed_directory_still_invalidates() {
    let (dir, located) = fixture();
    let provider = ListingProvider::default();
    let cache = LockFileCache::new();

    cache.get_or_parse(&provider, &located).await.unwrap();
    let added = dir.path().join("b.lock");
    std::fs::write(&added, "b").unwrap();
    cache.get_or_parse(&provider, &located).await.unwrap();
    assert_eq!(provider.set_parses.load(Ordering::SeqCst), 2, "addition");

    std::fs::remove_file(&added).unwrap();
    // Forward bump so a coarse-grained clock cannot tie with the stamp taken at the last parse.
    set_dir_modified(dir.path(), SystemTime::now() + Duration::from_secs(5));
    cache.get_or_parse(&provider, &located).await.unwrap();
    assert_eq!(provider.set_parses.load(Ordering::SeqCst), 3, "removal");
}

#[tokio::test]
async fn edit_of_a_listed_companion_file_invalidates_the_entry() {
    let (dir, located) = fixture();
    let companion = dir.path().join("a.lock");
    std::fs::write(&companion, "a").unwrap();
    in_the_past(dir.path());
    let provider = ListingProvider::default();
    let cache = LockFileCache::new();

    cache.get_or_parse(&provider, &located).await.unwrap();
    std::fs::write(&companion, "changed").unwrap();
    std::fs::OpenOptions::new()
        .write(true)
        .open(&companion)
        .unwrap()
        .set_modified(SystemTime::now() + Duration::from_secs(5))
        .unwrap();
    cache.get_or_parse(&provider, &located).await.unwrap();

    assert_eq!(provider.set_parses.load(Ordering::SeqCst), 2);
}
