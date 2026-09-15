//! `.gitignore`-aware directory walk and ecosystem routing (FR-001 through FR-004).

use deps_core::{Ecosystem, EcosystemRegistry};
use ignore::WalkBuilder;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Upper bound on the number of files a single `check` invocation inspects across every
/// walked root (FR-004).
///
/// Protects against an unbounded walk over a pathological directory tree (a huge
/// `node_modules`-style tree with `.gitignore` not excluding it, a symlink loop `ignore`
/// itself doesn't already guard against, ...). Once reached, the walk stops and
/// [`WalkOutcome::truncated`] is set so the caller can warn instead of silently
/// under-reporting.
pub const MAX_WALKED_FILES: usize = 50_000;

/// One manifest discovered by [`walk`], already routed to its owning ecosystem.
pub struct DiscoveredManifest {
    /// Absolute (or walk-root-relative, when the walked root itself was relative)
    /// filesystem path to the manifest.
    pub path: PathBuf,
    /// The manifest path as it should be displayed/reported — relative to the walked root
    /// when possible, matching [`crate::report::CheckFinding::manifest_path`].
    pub display_path: PathBuf,
    /// The ecosystem [`deps_core::EcosystemRegistry::for_uri`] routed this file to.
    pub ecosystem: Arc<dyn Ecosystem>,
}

/// The result of walking one or more roots.
#[derive(Default)]
pub struct WalkOutcome {
    /// Every manifest discovered and routed to an ecosystem.
    pub manifests: Vec<DiscoveredManifest>,
    /// Paths that `ignore` could not read (permission error, broken symlink, ...) — reported
    /// as warnings, never fatal (FR-002's "no ecosystem recognizes / cannot be read" edge
    /// case).
    pub walk_errors: Vec<String>,
    /// Whether [`MAX_WALKED_FILES`] was reached before the walk finished.
    pub truncated: bool,
    /// A `root` that was itself a single file (not a directory) but that no ecosystem's
    /// `manifest_filenames`/`manifest_patterns`/`manifest_extensions`/
    /// `manifest_directory_patterns` claimed (M4, spec 062 review) — spec §6 requires a
    /// warning line for exactly this case: an explicitly-given path, unlike an unmatched file
    /// encountered while walking a directory (the overwhelming majority of files in any real
    /// tree, never worth a warning each).
    pub unrecognized_explicit_paths: Vec<PathBuf>,
}

/// Walks every path in `roots` with `.gitignore` awareness.
///
/// Uses the `ignore` crate — respects `.gitignore`, `.git/info/exclude`, and the user's
/// global gitignore, same as `git` itself — routing every regular file through
/// `registry.for_uri` (FR-002) unchanged from the LSP's own routing.
///
/// A `root` that is itself a single file (not a directory) is checked directly against the
/// registry, bypassing the directory walk — this is what lets `deps-cli check Cargo.toml`
/// work without needing `.gitignore` semantics at all.
///
/// Every directory root is walked twice (spec 062 review, background code-review fix 1):
/// once with `ignore`'s default hidden-file filtering intact (so `.git` — a potentially huge
/// tree in a real checkout, and never a source of manifests — is never even descended into,
/// not merely filtered from the results), and once more per registered ecosystem's own
/// dot-prefixed [`deps_core::Ecosystem::manifest_directory_patterns`] entry (`.github`,
/// `.gitlab`, ...) with hidden-ness lifted for that one subtree specifically. This is derived
/// from the live registry rather than a hardcoded `[".github", ".gitlab"]` list, so a future
/// ecosystem introducing a new dot-directory pattern is picked up automatically.
#[must_use]
pub fn walk(roots: &[PathBuf], registry: &EcosystemRegistry) -> WalkOutcome {
    walk_with_limit(roots, registry, MAX_WALKED_FILES)
}

/// [`walk`]'s implementation, parameterized over the walked-entry cap so a test can exercise
/// truncation against a small fixture instead of needing a real `MAX_WALKED_FILES`-sized tree
/// (spec 062 review, tester gap 2).
///
/// The cap counts every entry the walk visits (S1, spec 062 review) — files, directories, and
/// unreadable entries alike — not just the subset that matched an ecosystem, so
/// [`WalkOutcome::truncated`] actually bounds the walk's own cost against a pathological tree
/// (a huge `node_modules` not excluded by `.gitignore`, a symlink loop) rather than only the
/// count of manifests found. Applies uniformly to the `root.is_file()` explicit-path branch
/// too (background code-review fix 2, spec 062 review) — that branch previously incremented
/// the counter but never checked it, so `WalkOutcome::truncated` could never be set from an
/// explicit path list.
fn walk_with_limit(roots: &[PathBuf], registry: &EcosystemRegistry, limit: usize) -> WalkOutcome {
    let mut outcome = WalkOutcome::default();
    let mut entries_walked: usize = 0;
    let hidden_ecosystem_dirs = hidden_ecosystem_directories(registry);

    'roots: for root in roots {
        if outcome.truncated {
            break;
        }
        if root.is_file() {
            if entries_walked >= limit {
                outcome.truncated = true;
                tracing::warn!(
                    limit,
                    "walk truncated: reached the maximum number of entries per run"
                );
                break;
            }
            entries_walked += 1;
            let matched_before = outcome.manifests.len();
            route_file(root, root, registry, &mut outcome);
            if outcome.manifests.len() == matched_before {
                outcome.unrecognized_explicit_paths.push(root.clone());
            }
            continue;
        }

        // Always hidden-filtered (`ignore`'s default): a `root` whose own basename happens
        // to start with `.` — e.g. a `tempfile`-generated directory on macOS, which is
        // exactly how this bit rotted once already during review — is not evidence the user
        // wants dot-directory contents un-hidden; `hidden(true)` only filters entries by
        // their *own* basename as the walk descends, so it never excludes `walk_root` itself
        // regardless of what `walk_root`'s name looks like.
        if !walk_directory(
            root,
            root,
            true,
            registry,
            limit,
            &mut entries_walked,
            &mut outcome,
        ) {
            break 'roots;
        }

        for dir_name in &hidden_ecosystem_dirs {
            let sub_root = root.join(dir_name);
            if !sub_root.is_dir() {
                continue;
            }
            if !walk_directory(
                &sub_root,
                root,
                false,
                registry,
                limit,
                &mut entries_walked,
                &mut outcome,
            ) {
                break 'roots;
            }
        }
    }

    outcome
}

/// Walks `walk_root` (a directory), routing every regular file relative to `display_root` —
/// the outer `root` [`walk_with_limit`] was given, so a file under a dot-directory sub-root
/// (e.g. `<repo>/.github`) still displays relative to the repository root, not to `.github`
/// itself. Returns `false` once `limit` is reached (the caller must stop the whole walk, not
/// just this directory); `true` otherwise.
fn walk_directory(
    walk_root: &Path,
    display_root: &Path,
    hidden: bool,
    registry: &EcosystemRegistry,
    limit: usize,
    entries_walked: &mut usize,
    outcome: &mut WalkOutcome,
) -> bool {
    let mut builder = WalkBuilder::new(walk_root);
    builder.standard_filters(true).hidden(hidden);
    for entry in builder.build() {
        if *entries_walked >= limit {
            outcome.truncated = true;
            tracing::warn!(
                limit,
                "walk truncated: reached the maximum number of entries per run"
            );
            return false;
        }
        *entries_walked += 1;
        match entry {
            Ok(entry) if entry.file_type().is_some_and(|t| t.is_file()) => {
                let path = entry.path();
                let display = path
                    .strip_prefix(display_root)
                    .unwrap_or(path)
                    .to_path_buf();
                route_file(path, &display, registry, outcome);
            }
            Ok(_) => {}
            Err(error) => outcome.walk_errors.push(error.to_string()),
        }
    }
    true
}

/// The set of top-level dot-directory names (`.github`, `.gitlab`, ...) that at least one
/// registered ecosystem's [`deps_core::Ecosystem::manifest_directory_patterns`] names — the
/// only dot-directories [`walk_with_limit`] walks with hidden-file filtering lifted. Derived
/// from the live registry (not a hardcoded list) so a future ecosystem's own dot-directory
/// pattern is picked up automatically; `.git` is never a match here, since no ecosystem's
/// directory pattern names it.
fn hidden_ecosystem_directories(registry: &EcosystemRegistry) -> BTreeSet<String> {
    let mut dirs = BTreeSet::new();
    for id in registry.ecosystem_ids() {
        let Some(ecosystem) = registry.get(id) else {
            continue;
        };
        for (dir_pattern, _suffix) in ecosystem.manifest_directory_patterns() {
            if let Some(first) = dir_pattern.split('/').next()
                && first.starts_with('.')
            {
                dirs.insert(first.to_string());
            }
        }
    }
    dirs
}

/// Routes one already-discovered file through `registry.for_uri`, pushing a
/// [`DiscoveredManifest`] onto `outcome` when an ecosystem claims it.
fn route_file(
    path: &Path,
    display_path: &Path,
    registry: &EcosystemRegistry,
    outcome: &mut WalkOutcome,
) {
    let Ok(uri) = url::Url::from_file_path(path) else {
        return;
    };
    if let Some(ecosystem) = registry.for_uri(&uri) {
        outcome.manifests.push(DiscoveredManifest {
            path: path.to_path_buf(),
            display_path: display_path.to_path_buf(),
            ecosystem,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn test_registry() -> EcosystemRegistry {
        let registry = EcosystemRegistry::new();
        let runtime = deps_engine::setup::EcosystemRuntime::from_policy(
            &deps_core::policy_config::PolicyConfig::default(),
        );
        deps_engine::setup::register_ecosystems(
            &registry,
            Arc::new(deps_core::HttpCache::new()),
            &runtime,
        );
        registry
    }

    #[test]
    fn test_walk_empty_directory_finds_nothing() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let outcome = walk(&[dir.path().to_path_buf()], &test_registry());
        assert!(outcome.manifests.is_empty());
        assert!(!outcome.truncated);
    }

    #[test]
    fn test_walk_finds_cargo_toml() {
        let dir = tempfile::tempdir().expect("create temp dir");
        fs::write(dir.path().join("Cargo.toml"), "[package]\nname = \"x\"\n")
            .expect("write manifest");
        let outcome = walk(&[dir.path().to_path_buf()], &test_registry());
        assert_eq!(outcome.manifests.len(), 1);
        assert_eq!(
            outcome.manifests[0].display_path,
            PathBuf::from("Cargo.toml")
        );
        assert_eq!(outcome.manifests[0].ecosystem.id(), "cargo");
    }

    #[test]
    fn test_walk_skips_gitignored_manifest() {
        let dir = tempfile::tempdir().expect("create temp dir");
        // `ignore`'s `.gitignore` support only activates inside a git repository by default
        // (`WalkBuilder::require_git`, true by default — matches real `git`'s own behavior);
        // an empty `.git` marker is enough for detection.
        fs::create_dir(dir.path().join(".git")).expect("create .git marker");
        fs::write(dir.path().join(".gitignore"), "ignored/\n").expect("write gitignore");
        fs::create_dir(dir.path().join("ignored")).expect("mkdir");
        fs::write(dir.path().join("ignored").join("Cargo.toml"), "[package]\n")
            .expect("write manifest");
        let outcome = walk(&[dir.path().to_path_buf()], &test_registry());
        assert!(outcome.manifests.is_empty());
    }

    #[test]
    fn test_walk_single_file_path_bypasses_gitignore() {
        let dir = tempfile::tempdir().expect("create temp dir");
        fs::write(dir.path().join(".gitignore"), "Cargo.toml\n").expect("write gitignore");
        let manifest = dir.path().join("Cargo.toml");
        fs::write(&manifest, "[package]\n").expect("write manifest");
        let outcome = walk(&[manifest], &test_registry());
        assert_eq!(outcome.manifests.len(), 1);
    }

    /// Regression test for S1 (spec 062 review): the cap must count every walked entry, not
    /// just matched manifests — a small fixture plus a small `limit` proves truncation fires
    /// without needing a real `MAX_WALKED_FILES`-sized tree.
    #[test]
    fn test_walk_with_limit_truncates_on_walked_entries_not_just_manifests() {
        let dir = tempfile::tempdir().expect("create temp dir");
        for i in 0..5 {
            fs::write(dir.path().join(format!("noise-{i}.txt")), "").expect("write noise file");
        }
        fs::write(dir.path().join("Cargo.toml"), "[package]\n").expect("write manifest");

        let outcome = walk_with_limit(&[dir.path().to_path_buf()], &test_registry(), 2);
        assert!(
            outcome.truncated,
            "a 2-entry limit against a 6-entry tree must truncate"
        );
    }

    #[test]
    fn test_walk_with_limit_does_not_truncate_when_under_the_cap() {
        let dir = tempfile::tempdir().expect("create temp dir");
        fs::write(dir.path().join("Cargo.toml"), "[package]\n").expect("write manifest");
        let outcome = walk_with_limit(&[dir.path().to_path_buf()], &test_registry(), 100);
        assert!(!outcome.truncated);
        assert_eq!(outcome.manifests.len(), 1);
    }

    /// Regression test for M4 (spec 062 review): an explicitly-given path no ecosystem
    /// recognizes must be reported, not silently dropped.
    #[test]
    fn test_walk_explicit_unrecognized_path_is_reported() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let unknown = dir.path().join("notes.txt");
        fs::write(&unknown, "not a manifest").expect("write file");
        let outcome = walk(std::slice::from_ref(&unknown), &test_registry());
        assert!(outcome.manifests.is_empty());
        assert_eq!(outcome.unrecognized_explicit_paths, vec![unknown]);
    }

    /// A file encountered while walking a directory (as opposed to given explicitly) must
    /// never be reported this way — nearly every file in a real tree doesn't match any
    /// ecosystem, and warning on each would be useless noise.
    #[test]
    fn test_walk_unrecognized_file_found_during_directory_walk_is_not_reported() {
        let dir = tempfile::tempdir().expect("create temp dir");
        fs::write(dir.path().join("notes.txt"), "not a manifest").expect("write file");
        let outcome = walk(&[dir.path().to_path_buf()], &test_registry());
        assert!(outcome.unrecognized_explicit_paths.is_empty());
    }

    #[test]
    fn test_walk_multiple_ecosystems_in_one_tree() {
        let dir = tempfile::tempdir().expect("create temp dir");
        fs::write(dir.path().join("Cargo.toml"), "[package]\n").expect("write cargo manifest");
        fs::write(dir.path().join("package.json"), "{}").expect("write npm manifest");
        let outcome = walk(&[dir.path().to_path_buf()], &test_registry());
        assert_eq!(outcome.manifests.len(), 2);
    }

    /// Regression test for background code-review fix 1 (spec 062 review): `.git`'s contents
    /// must never be walked, even though `.github`/`.gitlab` need hidden-ness lifted for the
    /// same tree. Deterministic regardless of directory-enumeration order: `.git` holds 100
    /// dummy files against a `limit` of 3 (comfortable margin over the handful of entries —
    /// the walk root, `.git`'s own directory entry, `Cargo.toml` — a correctly-hidden-filtered
    /// walk actually visits) — if `.git`'s contents were descended into at all, `entries_walked`
    /// would blow past 3 long before reaching `Cargo.toml`, truncating the walk.
    ///
    /// This test caught a real bug during review: an earlier version of this fix special-cased
    /// "the walk root's own basename starts with `.`" to mean "un-hide it, the user chose this
    /// dot-directory on purpose" — but `tempfile::tempdir()` itself creates dot-prefixed
    /// directories on macOS, so *every* test using a tempdir root silently hit that special
    /// case and disabled hidden-file filtering entirely, `.git` included. The fix removes that
    /// special-casing; `hidden(true)` never filters `walk_root` itself regardless of its name
    /// (only entries encountered *while descending*, by their own basename), so it was never
    /// needed in the first place.
    #[test]
    fn test_walk_never_descends_into_dot_git() {
        let dir = tempfile::tempdir().expect("create temp dir");
        fs::create_dir(dir.path().join(".git")).expect("create .git marker");
        for i in 0..100 {
            fs::write(dir.path().join(".git").join(format!("object-{i}")), "")
                .expect("write dummy git-internal file");
        }
        fs::write(dir.path().join("Cargo.toml"), "[package]\n").expect("write manifest");

        let outcome = walk_with_limit(&[dir.path().to_path_buf()], &test_registry(), 3);
        assert!(
            !outcome.truncated,
            ".git's 100 dummy files must never be walked, so a limit of 3 must suffice"
        );
        assert_eq!(outcome.manifests.len(), 1);
        assert_eq!(
            outcome.manifests[0].display_path,
            PathBuf::from("Cargo.toml")
        );
    }

    /// Companion test: `.github/workflows/*.yml` must still be found in the same tree that
    /// excludes `.git` — proves the fix distinguishes the two rather than just re-hiding
    /// everything dot-prefixed again.
    #[test]
    fn test_walk_still_finds_github_workflows_alongside_excluded_dot_git() {
        let dir = tempfile::tempdir().expect("create temp dir");
        fs::create_dir(dir.path().join(".git")).expect("create .git marker");
        fs::create_dir_all(dir.path().join(".github").join("workflows")).expect("mkdir");
        fs::write(
            dir.path().join(".github").join("workflows").join("ci.yml"),
            "on: push\njobs:\n  x:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n",
        )
        .expect("write workflow");

        let outcome = walk(&[dir.path().to_path_buf()], &test_registry());
        assert_eq!(outcome.manifests.len(), 1);
        assert_eq!(
            outcome.manifests[0].display_path,
            PathBuf::from(".github").join("workflows").join("ci.yml")
        );
        assert_eq!(outcome.manifests[0].ecosystem.id(), "github-actions");
    }

    /// Regression test for background code-review fix 2 (spec 062 review): the cap must be
    /// enforced for explicit file-path arguments too, not only for a directory walk — this
    /// was previously incrementing `entries_walked` without ever checking it in that branch.
    #[test]
    fn test_walk_with_limit_truncates_on_explicit_path_list() {
        let dir = tempfile::tempdir().expect("create temp dir");
        // Each manifest needs its own subdirectory — `Cargo.toml` is matched by exact
        // filename (`Ecosystem::manifest_filenames`), not a pattern, so five siblings named
        // `Cargo0.toml`..`Cargo4.toml` in one directory would never route to any ecosystem.
        let paths: Vec<PathBuf> = (0..5)
            .map(|i| {
                let subdir = dir.path().join(format!("pkg{i}"));
                fs::create_dir(&subdir).expect("mkdir");
                let path = subdir.join("Cargo.toml");
                fs::write(&path, "[package]\n").expect("write manifest");
                path
            })
            .collect();

        let outcome = walk_with_limit(&paths, &test_registry(), 2);
        assert!(
            outcome.truncated,
            "a 2-entry limit against 5 explicit paths must truncate"
        );
        assert_eq!(outcome.manifests.len(), 2);
    }
}
