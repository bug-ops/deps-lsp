//! #2158: a no-follow read of a WOF-compressed file (a reparse point that is not a symlink) either
//! returns exactly the file's content or fails; it never returns other bytes as `Ok`.
//!
//! Windows only. When the host cannot produce the setup (no `compact.exe` WOF support, attribute
//! 0x400 missing afterwards) the test skips locally and panics on GitHub Actions, so CI cannot go
//! green without having run the check.

#![cfg(windows)]

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

const WOF_ALGORITHMS: [&str; 4] = ["xpress4k", "xpress8k", "xpress16k", "lzx"];

fn compress_with_wof(path: &Path) -> Result<(), String> {
    let mut attempts = Vec::new();
    for algorithm in WOF_ALGORITHMS {
        let output = std::process::Command::new("compact.exe")
            .args(["/c", &format!("/exe:{algorithm}")])
            .arg(path)
            .output()
            .map_err(|error| format!("compact.exe did not start: {error}"))?;
        let attributes = std::fs::symlink_metadata(path)
            .map_err(|error| format!("metadata after compact: {error}"))?
            .file_attributes();
        if output.status.success() && attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Ok(());
        }
        attempts.push(format!(
            "/exe:{algorithm}: exit {}, attributes {attributes:#x}, stdout {:?}, stderr {:?}",
            output.status,
            String::from_utf8_lossy(&output.stdout).trim(),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Err(format!(
        "no WOF compression took effect: {}",
        attempts.join(" | ")
    ))
}

#[test]
fn no_follow_read_of_a_wof_compressed_file_returns_the_content_or_fails() {
    let _guard = snapshot_guard();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("Cargo.toml");
    let content = "# a line of a compressible manifest\n".repeat(2048);
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
