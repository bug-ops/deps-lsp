//! #2170: `deps-cli check` surfaces an unreadable version-catalog `[libraries]` entry as a finding
//! instead of reporting "No findings" for a catalog whose entry was silently dropped.
#![cfg(feature = "gradle")]

#[test]
fn check_reports_an_unreadable_catalog_entry_as_a_finding() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().canonicalize().expect("canonical tempdir");
    std::fs::create_dir_all(root.join("gradle")).expect("gradle dir");
    std::fs::write(
        root.join("gradle/libs.versions.toml"),
        "[libraries]\nbad-short = \"not-a-coordinate\"\n",
    )
    .expect("catalog");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_deps-cli"))
        .args([
            "check",
            "--offline",
            "--format",
            "json",
            "gradle/libs.versions.toml",
        ])
        .current_dir(&root)
        .output()
        .expect("run the real deps-cli binary");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("bad-short"),
        "the unreadable entry must be reported by alias, got: {stdout}"
    );
}
