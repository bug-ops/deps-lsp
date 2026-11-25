//! #2158: a no-follow read of a WOF-compressed file (a reparse point that is not a symlink) either
//! returns exactly the file's content or fails; it never returns other bytes as `Ok`.
//!
//! Windows only. When the host cannot produce the setup (no `compact.exe` WOF support, attribute
//! 0x400 missing afterwards) the test skips locally and panics on GitHub Actions, so CI cannot go
//! green without having run the check.

#![cfg(windows)]
#![expect(clippy::unwrap_used, reason = "test code")]

use std::os::windows::fs::MetadataExt;
use std::path::Path;

use deps_core::fs_probe::{read_to_string_capped_no_follow, snapshot_guard};

const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;

fn setup_unavailable(reason: &str) {
    assert!(
        std::env::var_os("GITHUB_ACTIONS").is_none(),
        "WOF setup failed on CI, the acceptance check did not run: {reason}"
    );
    eprintln!("skipping: WOF setup unavailable: {reason}");
}

fn compress_with_wof(path: &Path) -> Result<(), String> {
    let output = std::process::Command::new("compact.exe")
        .args(["/c", "/exe:xpress4k"])
        .arg(path)
        .output()
        .map_err(|error| format!("compact.exe did not start: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "compact.exe exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stdout)
        ));
    }
    let attributes = std::fs::symlink_metadata(path)
        .map_err(|error| format!("metadata after compact: {error}"))?
        .file_attributes();
    if attributes & FILE_ATTRIBUTE_REPARSE_POINT == 0 {
        return Err(format!(
            "attribute 0x400 absent after compact (attributes {attributes:#x})"
        ));
    }
    Ok(())
}

#[test]
fn no_follow_read_of_a_wof_compressed_file_returns_the_content_or_fails() {
    let _guard = snapshot_guard();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("Cargo.toml");
    let content: String = (0..2048)
        .map(|n| format!("# line {n:05} of a compressible manifest\n"))
        .collect();
    assert!(content.len() >= 64 * 1024);
    std::fs::write(&path, &content).unwrap();
    if let Err(reason) = compress_with_wof(&path) {
        setup_unavailable(&reason);
        return;
    }

    let outcome = read_to_string_capped_no_follow(&path, 1 << 20);

    match outcome {
        Ok(Some(read)) => assert_eq!(read, content, "Ok must carry the exact original content"),
        Ok(None) => panic!("the file is far below the cap"),
        Err(error) => eprintln!("refused with {:?}: {error}", error.kind()),
    }
}
