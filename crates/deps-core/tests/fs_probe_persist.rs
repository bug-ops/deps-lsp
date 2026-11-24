//! T004 (spec 051) acceptance: `fs_probe` primitives for the disk registry cache
//! (`AtomicWrite`, `FileMode`, `write_atomic_bytes_with`, `read_capped_no_follow_with_metadata`,
//! `open_for_restamp`). Written tests-first; none of these items exist yet.

#![expect(clippy::expect_used, reason = "test code")]

use std::io::{ErrorKind, Read};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use deps_core::fs_probe::{
    AtomicWrite, FileMode, open_for_restamp, read_capped_no_follow_with_metadata,
    write_atomic_bytes_with,
};

const NON_UTF8: &[u8] = &[0xff, 0xfe, 0x00, b'a', 0x80];

fn stamp() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_000_000_000)
}

fn owner_only(modified: Option<SystemTime>) -> AtomicWrite {
    AtomicWrite {
        mode: FileMode::OwnerOnly,
        modified,
    }
}

#[cfg(unix)]
fn mode_bits(path: &std::path::Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).expect("stat").permissions().mode() & 0o777
}

#[cfg(unix)]
fn set_mode(path: &std::path::Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("chmod");
}

fn set_mtime(path: &std::path::Path, time: SystemTime) {
    std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .expect("open")
        .set_modified(time)
        .expect("set_modified");
}

#[test]
fn write_atomic_bytes_with_replaces_content_exactly_and_leaves_no_temp_file() {
    let dir = tempfile::tempdir().expect("dir");
    let path = dir.path().join("entry");
    std::fs::write(&path, b"old").expect("seed");

    write_atomic_bytes_with(&path, NON_UTF8, owner_only(None)).expect("write");

    assert_eq!(std::fs::read(&path).expect("read"), NON_UTF8);
    let entries: Vec<_> = std::fs::read_dir(dir.path()).expect("list").collect();
    assert_eq!(entries.len(), 1, "no stray temp files: {entries:?}");
}

#[cfg(unix)]
#[test]
fn write_atomic_bytes_with_owner_only_creates_new_file_as_0600() {
    let dir = tempfile::tempdir().expect("dir");
    let path = dir.path().join("entry");

    write_atomic_bytes_with(&path, b"x", owner_only(None)).expect("write");

    assert_eq!(mode_bits(&path), 0o600);
}

#[cfg(unix)]
#[test]
fn write_atomic_bytes_with_owner_only_never_copies_target_permissions() {
    let dir = tempfile::tempdir().expect("dir");
    let path = dir.path().join("entry");
    std::fs::write(&path, b"old").expect("seed");
    set_mode(&path, 0o644);

    write_atomic_bytes_with(&path, b"new", owner_only(None)).expect("write");

    assert_eq!(mode_bits(&path), 0o600);
}

#[cfg(unix)]
#[test]
fn write_atomic_bytes_with_preserve_target_copies_target_permissions() {
    let dir = tempfile::tempdir().expect("dir");
    let path = dir.path().join("entry");
    std::fs::write(&path, b"old").expect("seed");
    set_mode(&path, 0o640);
    let options = AtomicWrite {
        mode: FileMode::PreserveTarget,
        modified: None,
    };

    write_atomic_bytes_with(&path, b"new", options).expect("write");

    assert_eq!(mode_bits(&path), 0o640);
}

#[cfg(unix)]
#[test]
fn write_atomic_bytes_with_refuses_a_symlink_and_leaves_its_target_alone() {
    let dir = tempfile::tempdir().expect("dir");
    let real = dir.path().join("real");
    std::fs::write(&real, b"keep").expect("write");
    let link = dir.path().join("link");
    std::os::unix::fs::symlink(&real, &link).expect("symlink");

    let error =
        write_atomic_bytes_with(&link, b"clobber", owner_only(Some(stamp()))).expect_err("symlink");

    assert_eq!(error.kind(), ErrorKind::InvalidInput);
    assert_eq!(std::fs::read(&real).expect("read"), b"keep");
    assert!(
        std::fs::symlink_metadata(&link)
            .expect("stat")
            .file_type()
            .is_symlink()
    );
}

#[test]
fn write_atomic_bytes_with_sets_the_requested_mtime() {
    let dir = tempfile::tempdir().expect("dir");
    let path = dir.path().join("entry");

    write_atomic_bytes_with(&path, b"x", owner_only(Some(stamp()))).expect("write");

    assert_eq!(
        std::fs::metadata(&path)
            .expect("stat")
            .modified()
            .expect("mtime"),
        stamp()
    );
}

#[test]
fn write_atomic_bytes_with_none_leaves_the_mtime_unstamped() {
    let dir = tempfile::tempdir().expect("dir");
    let path = dir.path().join("entry");

    write_atomic_bytes_with(&path, b"x", owner_only(None)).expect("write");

    let age = SystemTime::now()
        .duration_since(
            std::fs::metadata(&path)
                .expect("stat")
                .modified()
                .expect("mtime"),
        )
        .expect("mtime is not in the future");
    assert!(
        age < Duration::from_hours(1),
        "mtime must be current: {age:?}"
    );
}

/// The stamp lands on the temp handle, so the renamed-in file is never visible with a
/// different mtime.
#[test]
fn write_atomic_bytes_with_never_exposes_the_target_before_its_mtime_is_set() {
    let dir = tempfile::tempdir().expect("dir");
    for round in 0..30 {
        let path = dir.path().join(format!("entry-{round}"));
        let observer_path = path.clone();
        let observer = std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            loop {
                if let Ok(meta) = std::fs::metadata(&observer_path) {
                    return meta.modified().expect("mtime");
                }
                assert!(
                    std::time::Instant::now() < deadline,
                    "target never appeared"
                );
                std::thread::yield_now();
            }
        });

        write_atomic_bytes_with(&path, b"x", owner_only(Some(stamp()))).expect("write");

        assert_eq!(observer.join().expect("observer"), stamp());
    }
}

#[test]
fn read_capped_no_follow_with_metadata_returns_bytes_and_metadata_of_the_file() {
    let dir = tempfile::tempdir().expect("dir");
    let path = dir.path().join("entry");
    std::fs::write(&path, NON_UTF8).expect("write");
    set_mtime(&path, stamp());

    let (bytes, meta) = read_capped_no_follow_with_metadata(&path, 1024)
        .expect("read")
        .expect("under cap");

    assert_eq!(bytes, NON_UTF8);
    assert_eq!(meta.len(), NON_UTF8.len() as u64);
    assert_eq!(meta.modified().expect("mtime"), stamp());
}

#[test]
fn read_capped_no_follow_with_metadata_accepts_exactly_the_cap_and_rejects_one_byte_more() {
    let dir = tempfile::tempdir().expect("dir");
    let path = dir.path().join("entry");
    std::fs::write(&path, [b'x'; 16]).expect("write");

    assert!(
        read_capped_no_follow_with_metadata(&path, 16)
            .expect("at cap")
            .is_some()
    );
    assert!(
        read_capped_no_follow_with_metadata(&path, 15)
            .expect("over cap")
            .is_none()
    );
}

#[test]
fn read_capped_no_follow_with_metadata_reports_a_missing_file_as_not_found() {
    let dir = tempfile::tempdir().expect("dir");

    let error =
        read_capped_no_follow_with_metadata(&dir.path().join("absent"), 16).expect_err("missing");

    assert_eq!(error.kind(), ErrorKind::NotFound);
}

#[cfg(unix)]
#[test]
fn read_capped_no_follow_with_metadata_refuses_a_symlinked_final_component() {
    let dir = tempfile::tempdir().expect("dir");
    let real = dir.path().join("real");
    std::fs::write(&real, b"data").expect("write");
    let link = dir.path().join("link");
    std::os::unix::fs::symlink(&real, &link).expect("symlink");

    let error = read_capped_no_follow_with_metadata(&link, 16).expect_err("symlink");

    assert_eq!(error.kind(), ErrorKind::InvalidInput);
}

/// A FIFO with no writer blocks a plain `open(O_RDONLY)` forever; `O_NONBLOCK` plus the
/// regular-file check must turn it into an error instead.
#[cfg(unix)]
#[test]
fn read_capped_no_follow_with_metadata_rejects_a_fifo_without_blocking() {
    let dir = tempfile::tempdir().expect("dir");
    let fifo = dir.path().join("fifo");
    let status = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .expect("mkfifo");
    assert!(status.success());

    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(read_capped_no_follow_with_metadata(&fifo, 16));
    });

    let result = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("read of a FIFO must not block");
    assert!(result.is_err(), "non-regular file must be an error");
}

/// FR-014: restamping must refuse a FIFO planted at the entry path, promptly.
#[cfg(unix)]
#[test]
fn open_for_restamp_rejects_a_fifo_without_blocking() {
    let dir = tempfile::tempdir().expect("dir");
    let fifo = dir.path().join("fifo");
    let status = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .expect("mkfifo");
    assert!(status.success());

    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(open_for_restamp(&fifo).map(|_| ()));
    });

    let result = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("restamp open of a FIFO must not block");
    let error = result.expect_err("non-regular file must be an error");
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
}

#[test]
fn open_for_restamp_preserves_content_and_allows_reading_and_set_modified() {
    let dir = tempfile::tempdir().expect("dir");
    let path = dir.path().join("entry");
    std::fs::write(&path, NON_UTF8).expect("write");

    let mut handle = open_for_restamp(&path).expect("open");
    let mut read_back = Vec::new();
    handle.read_to_end(&mut read_back).expect("read via handle");
    handle.set_modified(stamp()).expect("set_modified");
    drop(handle);

    assert_eq!(read_back, NON_UTF8);
    assert_eq!(std::fs::read(&path).expect("read"), NON_UTF8, "no truncate");
    assert_eq!(
        std::fs::metadata(&path)
            .expect("stat")
            .modified()
            .expect("mtime"),
        stamp()
    );
}

#[test]
fn open_for_restamp_propagates_not_found() {
    let dir = tempfile::tempdir().expect("dir");

    let error = open_for_restamp(&dir.path().join("absent")).expect_err("missing");

    assert_eq!(error.kind(), ErrorKind::NotFound);
}

#[cfg(unix)]
#[test]
fn open_for_restamp_refuses_a_symlinked_final_component() {
    let dir = tempfile::tempdir().expect("dir");
    let real = dir.path().join("real");
    std::fs::write(&real, b"data").expect("write");
    set_mtime(&real, stamp());
    let link = dir.path().join("link");
    std::os::unix::fs::symlink(&real, &link).expect("symlink");

    assert!(open_for_restamp(&link).is_err());
    assert_eq!(
        std::fs::metadata(&real)
            .expect("stat")
            .modified()
            .expect("mtime"),
        stamp()
    );
}

/// Windows replaces a file that another reader still holds open (std opens with
/// `FILE_SHARE_DELETE`); the writer must not fail with a sharing violation.
#[cfg(windows)]
#[test]
fn write_atomic_bytes_with_replaces_a_target_held_open_by_a_reader() {
    let dir = tempfile::tempdir().expect("dir");
    let path = dir.path().join("entry");
    std::fs::write(&path, b"old").expect("seed");
    let reader = std::fs::File::open(&path).expect("hold open");

    write_atomic_bytes_with(&path, b"new", owner_only(Some(stamp()))).expect("replace");

    drop(reader);
    assert_eq!(std::fs::read(&path).expect("read"), b"new");
}
