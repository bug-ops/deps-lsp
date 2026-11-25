//! Acceptance test (tester-owned) for #2178: `ClaimBound`, the upper limit of the forward
//! catalog lookup, refuses directories that would make the lookup unbounded.

use std::path::Path;

use deps_core::ecosystem::ClaimBound;

#[test]
fn claim_bound_new_refuses_relative_root_and_home_directories() {
    assert!(ClaimBound::new(Path::new("relative/dir")).is_none());
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().ancestors().last().expect("filesystem root");
    assert!(ClaimBound::new(root).is_none());
    if let Some(home) = std::env::home_dir() {
        assert!(ClaimBound::new(&home).is_none());
    }
    assert!(ClaimBound::new(dir.path()).is_some());
}
