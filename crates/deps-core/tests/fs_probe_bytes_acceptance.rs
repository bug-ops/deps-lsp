//! #2071 acceptance: byte-level lock snapshot primitives in `deps_core::fs_probe`
//! (`read_capped_no_follow`, `write_atomic_bytes`). Written tests-first; neither exists yet.

#![allow(clippy::expect_used)]

use std::io::ErrorKind;

use deps_core::fs_probe::{read_capped_no_follow, write_atomic_bytes};

const NON_UTF8: &[u8] = &[0xff, 0xfe, 0x00, b'a', 0x80];

#[test]
fn read_capped_no_follow_returns_non_utf8_bytes_unchanged() {
    let dir = tempfile::tempdir().expect("dir");
    let path = dir.path().join("lock");
    std::fs::write(&path, NON_UTF8).expect("write");

    let read = read_capped_no_follow(&path, 1024).expect("read");

    assert_eq!(read.as_deref(), Some(NON_UTF8));
}

#[test]
fn read_capped_no_follow_accepts_exactly_the_cap_and_rejects_one_byte_more() {
    let dir = tempfile::tempdir().expect("dir");
    let path = dir.path().join("lock");
    std::fs::write(&path, [b'x'; 16]).expect("write");

    assert_eq!(
        read_capped_no_follow(&path, 16)
            .expect("at cap")
            .map(|bytes| bytes.len()),
        Some(16)
    );
    assert_eq!(read_capped_no_follow(&path, 15).expect("over cap"), None);
}

#[test]
fn read_capped_no_follow_reports_a_missing_file_as_not_found() {
    let dir = tempfile::tempdir().expect("dir");

    let error = read_capped_no_follow(&dir.path().join("absent"), 16).expect_err("missing");

    assert_eq!(error.kind(), ErrorKind::NotFound);
}

#[cfg(unix)]
#[test]
fn read_capped_no_follow_refuses_a_symlinked_final_component() {
    let dir = tempfile::tempdir().expect("dir");
    let real = dir.path().join("real");
    std::fs::write(&real, b"data").expect("write");
    let link = dir.path().join("link");
    std::os::unix::fs::symlink(&real, &link).expect("symlink");

    let error = read_capped_no_follow(&link, 16).expect_err("symlink");

    assert_eq!(error.kind(), ErrorKind::InvalidInput);
}

#[test]
fn write_atomic_bytes_replaces_content_and_leaves_no_temp_file() {
    let dir = tempfile::tempdir().expect("dir");
    let path = dir.path().join("lock");
    std::fs::write(&path, b"old").expect("seed");

    write_atomic_bytes(&path, NON_UTF8).expect("write");

    assert_eq!(std::fs::read(&path).expect("read"), NON_UTF8);
    let entries: Vec<_> = std::fs::read_dir(dir.path()).expect("list").collect();
    assert_eq!(entries.len(), 1, "no stray temp files: {entries:?}");
}

#[cfg(unix)]
#[test]
fn write_atomic_bytes_refuses_a_symlink_and_leaves_its_target_alone() {
    let dir = tempfile::tempdir().expect("dir");
    let real = dir.path().join("real");
    std::fs::write(&real, b"keep").expect("write");
    let link = dir.path().join("link");
    std::os::unix::fs::symlink(&real, &link).expect("symlink");

    let error = write_atomic_bytes(&link, b"clobber").expect_err("symlink");

    assert_eq!(error.kind(), ErrorKind::InvalidInput);
    assert_eq!(std::fs::read(&real).expect("read"), b"keep");
}
