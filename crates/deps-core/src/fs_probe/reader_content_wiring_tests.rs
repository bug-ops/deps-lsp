//! #2173/#2186: which `ReadContent` each public no-follow reader passes to the completeness
//! check. The handle classification is forced to `Exact`, as a reparse point would give.

use super::{
    FORCE_EXACT_COMPLETENESS, read_capped_no_follow, read_capped_no_follow_with_metadata,
    read_to_string_capped_no_follow, snapshot_guard,
};
use std::io::ErrorKind;
use std::path::PathBuf;

/// A complete file ending in a NUL byte: the zero-filled tail of a partial rehydration.
fn zero_tailed(dir: &tempfile::TempDir) -> PathBuf {
    let path = dir.path().join("Cargo.toml");
    std::fs::write(&path, b"[a]\n\0").unwrap();
    path
}

fn with_exact_completeness(read: impl FnOnce()) {
    FORCE_EXACT_COMPLETENESS.with(|force| force.set(true));
    read();
    FORCE_EXACT_COMPLETENESS.with(|force| force.set(false));
}

#[test]
fn text_readers_refuse_a_zero_tailed_reparse_read() {
    let _guard = snapshot_guard();
    let dir = tempfile::tempdir().unwrap();
    let path = zero_tailed(&dir);

    with_exact_completeness(|| {
        let text = read_to_string_capped_no_follow(&path, 1024);
        assert_eq!(text.unwrap_err().kind(), ErrorKind::InvalidData);
        let bytes = read_capped_no_follow(&path, 1024);
        assert_eq!(bytes.unwrap_err().kind(), ErrorKind::InvalidData);
    });
}

#[test]
fn the_metadata_reader_accepts_a_zero_tailed_binary_read() {
    let _guard = snapshot_guard();
    let dir = tempfile::tempdir().unwrap();
    let path = zero_tailed(&dir);

    with_exact_completeness(|| {
        let (bytes, _) = read_capped_no_follow_with_metadata(&path, 1024)
            .unwrap()
            .expect("under the cap");
        assert_eq!(bytes, b"[a]\n\0");
    });
}
