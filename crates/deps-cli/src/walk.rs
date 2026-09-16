//! Directory walk and ecosystem routing (FR-001 through FR-004).
//!
//! Not `.gitignore`-aware by default (issue #1109): `check` is a CI security gate over
//! potentially untrusted input, so `.gitignore`/`.ignore` are only consulted when
//! [`crate::cli::CheckArgs::respect_gitignore`] opts back in. A compiled-in `PRUNED_DIRECTORIES`
//! denylist still keeps common dependency/build/VCS trees (`node_modules`, `target`, `vendor`,
//! ...) out of the scan either way — see [`walk`]'s doc.

use deps_core::{Ecosystem, EcosystemRegistry};
use ignore::WalkBuilder;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// Upper bound on the number of files a single `check` invocation inspects across every
/// walked root (FR-004).
///
/// Protects against an unbounded walk over a pathological directory tree — the internal
/// `PRUNED_DIRECTORIES` denylist keeps the common offenders (`node_modules`, `target`, ...)
/// out of the scan already, but this cap remains a backstop for anything else pathologically
/// large (a symlink loop `ignore` itself doesn't already guard against, an unusually large
/// tree of a kind not on that denylist, ...). Once reached, the walk stops and
/// [`WalkOutcome::truncated`] is set so the caller can warn instead of silently
/// under-reporting.
pub const MAX_WALKED_FILES: usize = 50_000;

/// Directory basenames pruned from every walk, before `.gitignore`/`.ignore` are ever
/// consulted (critic follow-up on issue #1109's default flip, S1/S2/S4). `.gitignore` was
/// doing double duty: attacker-controlled suppression *and* the only thing keeping
/// `node_modules/`, `target/`, `vendor/`, ... out of the scan; disabling it by default
/// (see [`walk`]'s doc) removed both. This denylist restores the pruning without
/// reintroducing attacker control — it is baked into the binary, so a scanned repository has
/// no way to influence it, unlike a `.gitignore`/`.ignore` file.
///
/// Not exhaustive; covers the common heavy dependency/build/VCS directories across this
/// crate's 14 supported ecosystems. Most VCS and tool-cache directories here (`.git`, `.venv`,
/// `.gradle`, `.dart_tool`, `.build`, `.bundle`, `.tox`, ...) are already dot-prefixed and
/// excluded by `hidden(true)` wherever that's active; they're listed again so pruning stays
/// uniform regardless of a given walk's own `hidden` setting (e.g. the ecosystem
/// dot-directory sub-walk, or [`detect_ignored_manifests`]'s unfiltered detection walk, both
/// of which run with `hidden` lifted for their own reasons).
const PRUNED_DIRECTORIES: &[&str] = &[
    // Version control
    ".git",
    ".hg",
    ".svn",
    ".bzr",
    // JavaScript / TypeScript / Deno
    "node_modules",
    "bower_components",
    // Rust
    "target",
    // Go / PHP (Composer) / Ruby (Bundler, vendor/bundle)
    "vendor",
    // Python
    ".venv",
    "venv",
    "__pycache__",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    // Ruby (Bundler)
    ".bundle",
    // Dart
    ".dart_tool",
    // Gradle
    ".gradle",
    // Swift
    ".build",
    "Pods",
    "DerivedData",
    // Generic build output, used by several ecosystems (Maven, Dart, npm builds, ...)
    "dist",
    "build",
];

/// Returns `false` for a directory entry [`ignore::WalkBuilder::filter_entry`] should prune —
/// its basename is in [`PRUNED_DIRECTORIES`]. Never prunes depth 0 (the walk root itself), so
/// an explicitly-walked root that happens to be named e.g. `vendor` still works, matching the
/// existing convention that an explicitly-given path is trusted.
fn is_not_pruned_directory(entry: &ignore::DirEntry) -> bool {
    entry.depth() == 0
        || !entry
            .file_type()
            .is_some_and(|file_type| file_type.is_dir())
        || !entry
            .file_name()
            .to_str()
            .is_some_and(|name| PRUNED_DIRECTORIES.contains(&name))
}

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
    /// Manifest-shaped files excluded from the scan without the caller asking for that
    /// exclusion — either an ignore rule while `respect_gitignore` was enabled (issue #1109),
    /// or a `PRUNED_DIRECTORIES` match in *any* mode (reviewer follow-up: an unusual monorepo
    /// layout can have a real subproject's manifest sitting directly inside a directory named
    /// `vendor`/`build`/`dist`/...). Unlike
    /// [`unrecognized_explicit_paths`](Self::unrecognized_explicit_paths), this is a warning
    /// about data loss (a real manifest silently skipped), not a benign non-match.
    pub ignored_manifests: Vec<PathBuf>,
}

/// Walks every path in `roots`.
///
/// Uses the `ignore` crate, routing every regular file through `registry.for_uri` (FR-002)
/// unchanged from the LSP's own routing.
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
///
/// **`respect_gitignore` (issue #1109)**: when `false` (the `check` subcommand's default —
/// see [`crate::cli::CheckArgs::respect_gitignore`]), `.gitignore` and `.ignore` files are
/// never consulted, because in a CI security-gate invocation (`git checkout && deps-cli check
/// .` against an untrusted fork PR) both are attacker-controlled input: a one-line addition
/// anywhere in the tree would otherwise silently remove a manifest from the scan. `.git`
/// itself is still never descended into (that is `hidden`-filtering, an unrelated concern —
/// see above), and `.git/info/exclude` / the user's global gitignore are always honored
/// regardless of this flag, since neither travels with a cloned/fetched PR and both are
/// operator-, not attacker-, controlled. When `true`, standard `.gitignore`/`.ignore`
/// awareness is restored (matching `git`'s own behavior), and any manifest-shaped file that
/// awareness excludes is additionally reported via [`WalkOutcome::ignored_manifests`].
/// The internal `PRUNED_DIRECTORIES` denylist is applied regardless of `respect_gitignore` —
/// it is compiled into the binary, not attacker-controlled input, so pruning
/// `node_modules`/`target`/`vendor`/... does not reopen the fail-open gap this flag closes. A
/// manifest sitting directly at the root of a pruned directory (an unusual but real monorepo
/// layout, e.g. a genuine subproject named `vendor`) is still reported via
/// [`WalkOutcome::ignored_manifests`] in every mode, so pruning stays visible rather than a
/// second, narrower silent-omission bug.
///
/// One asymmetry is deliberate rather than accidental: in the default (`respect_gitignore:
/// false`) mode, a manifest excluded only by the always-on `.git/info/exclude` or global
/// gitignore is never diffed against (that costly double-walk only runs under
/// `respect_gitignore`), so such a suppression is silent beyond [`WalkOutcome::manifests`]
/// coming back emptier than expected — acceptable because both sources are
/// operator-, not attacker-, controlled (see above).
#[must_use]
pub fn walk(
    roots: &[PathBuf],
    registry: &EcosystemRegistry,
    respect_gitignore: bool,
) -> WalkOutcome {
    walk_with_limit(roots, registry, MAX_WALKED_FILES, respect_gitignore)
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
fn walk_with_limit(
    roots: &[PathBuf],
    registry: &EcosystemRegistry,
    limit: usize,
    respect_gitignore: bool,
) -> WalkOutcome {
    let mut ctx = WalkCtx {
        registry,
        limit,
        entries_walked: 0,
        outcome: WalkOutcome::default(),
    };
    let hidden_ecosystem_dirs = hidden_ecosystem_directories(registry);

    'roots: for root in roots {
        if ctx.outcome.truncated {
            break;
        }
        // Absolutized (issue #1108): `url::Url::from_file_path` (in `route_file`) and
        // `ignore::WalkBuilder` both require an absolute root to produce absolute entries —
        // a relative root (e.g. `.`, the CLI's own default) otherwise made every discovered
        // file fail `from_file_path` silently, so `deps-cli check` with no arguments always
        // reported zero manifests. `display_path`s below are still derived relative to
        // `root` as given, so reported paths stay exactly as the caller typed them.
        let Ok(absolute_root) = std::path::absolute(root) else {
            ctx.outcome
                .walk_errors
                .push(format!("could not resolve path: {}", root.display()));
            continue;
        };

        if root.is_file() {
            if ctx.entries_walked >= ctx.limit {
                ctx.outcome.truncated = true;
                tracing::warn!(
                    limit,
                    "walk truncated: reached the maximum number of entries per run"
                );
                break;
            }
            ctx.entries_walked += 1;
            let matched_before = ctx.outcome.manifests.len();
            route_file(&absolute_root, root, registry, &mut ctx.outcome);
            if ctx.outcome.manifests.len() == matched_before {
                ctx.outcome.unrecognized_explicit_paths.push(root.clone());
            }
            continue;
        }

        // Always hidden-filtered: `hidden(true)` filters entries by their own basename as the
        // walk descends, so `walk_root` itself is never excluded even if its name starts with
        // `.` (e.g. a tempfile dir on macOS) — that previously caused a regression.
        if !walk_directory(
            &absolute_root,
            &absolute_root,
            true,
            respect_gitignore,
            &mut ctx,
        ) {
            break 'roots;
        }

        for dir_name in &hidden_ecosystem_dirs {
            let sub_root = absolute_root.join(dir_name);
            if !sub_root.is_dir() {
                continue;
            }
            if !walk_directory(
                &sub_root,
                &absolute_root,
                false,
                respect_gitignore,
                &mut ctx,
            ) {
                break 'roots;
            }
        }
    }

    ctx.outcome
}

/// Bundles the state threaded through every helper in a single walk run, so adding a new
/// piece of shared state doesn't grow each helper's own argument list
/// (`clippy::too_many_arguments`).
struct WalkCtx<'a> {
    registry: &'a EcosystemRegistry,
    limit: usize,
    entries_walked: usize,
    outcome: WalkOutcome,
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
    respect_gitignore: bool,
    ctx: &mut WalkCtx<'_>,
) -> bool {
    // `.gitignore`/`.ignore` toggle by `respect_gitignore` (issue #1109) — both are
    // attacker-controlled in a CI scan of untrusted input. `git_exclude` (`.git/info/exclude`)
    // and `git_global` (the user's global gitignore) stay on unconditionally: neither travels
    // with a cloned/fetched PR, so neither is part of the attack surface this flag closes.
    let pruned_dirs: Arc<Mutex<Vec<PathBuf>>> = Arc::new(Mutex::new(Vec::new()));
    let mut builder = WalkBuilder::new(walk_root);
    builder
        .hidden(hidden)
        .parents(true)
        .ignore(respect_gitignore)
        .git_ignore(respect_gitignore)
        .git_global(true)
        .git_exclude(true);
    {
        let pruned_dirs = Arc::clone(&pruned_dirs);
        builder.filter_entry(move |entry| {
            if is_not_pruned_directory(entry) {
                true
            } else {
                pruned_dirs
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(entry.path().to_path_buf());
                false
            }
        });
    }

    let mut visited: BTreeSet<PathBuf> = BTreeSet::new();
    for entry in builder.build() {
        if ctx.entries_walked >= ctx.limit {
            ctx.outcome.truncated = true;
            tracing::warn!(
                limit = ctx.limit,
                "walk truncated: reached the maximum number of entries per run"
            );
            return false;
        }
        ctx.entries_walked += 1;
        match entry {
            Ok(entry) if entry.file_type().is_some_and(|t| t.is_file()) => {
                let path = entry.path();
                let display = path
                    .strip_prefix(display_root)
                    .unwrap_or(path)
                    .to_path_buf();
                if respect_gitignore {
                    visited.insert(display.clone());
                }
                route_file(path, &display, ctx.registry, &mut ctx.outcome);
            }
            Ok(_) => {}
            Err(error) => ctx.outcome.walk_errors.push(error.to_string()),
        }
    }

    // Reviewer follow-up (#2): visible regardless of `respect_gitignore` — pruning is always
    // on, so its (rare) false positives must always be reported, not only under the opt-in
    // ignore-aware mode.
    for pruned_dir in pruned_dirs
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
    {
        warn_on_pruned_directory_manifest(pruned_dir, display_root, ctx);
    }

    if respect_gitignore {
        detect_ignored_manifests(walk_root, display_root, hidden, ctx, &visited);
    }
    true
}

/// Checks a directory [`is_not_pruned_directory`] excluded (its basename matched
/// [`PRUNED_DIRECTORIES`]) for a manifest sitting directly at its own root, and records any
/// found onto [`WalkOutcome::ignored_manifests`] (reviewer follow-up on issue #1109's
/// pruning fix: an unusual monorepo layout can have a *real* subproject's manifest directly
/// inside a directory named `vendor`/`build`/`dist`/...).
///
/// Deliberately one level deep only — a full recursive re-walk of the pruned directory would
/// reintroduce the exact cost [`PRUNED_DIRECTORIES`] exists to avoid for a large vendored tree
/// (a `node_modules` with hundreds of packages has no manifest directly at its own root, only
/// nested under each package directory, so this check costs one cheap `read_dir` per pruned
/// directory and stays silent for it). A manifest nested two or more levels inside a pruned
/// directory remains a known, accepted limitation of this check, not a regression — it was
/// never discovered before this fix either.
fn warn_on_pruned_directory_manifest(
    pruned_dir: &Path,
    display_root: &Path,
    ctx: &mut WalkCtx<'_>,
) {
    let Ok(read_dir) = std::fs::read_dir(pruned_dir) else {
        return;
    };
    for entry in read_dir.flatten() {
        if !entry.file_type().is_ok_and(|file_type| file_type.is_file()) {
            continue;
        }
        let path = entry.path();
        let display = path
            .strip_prefix(display_root)
            .unwrap_or(&path)
            .to_path_buf();
        let Ok(uri) = url::Url::from_file_path(&path) else {
            continue;
        };
        if ctx.registry.for_uri(&uri).is_some() {
            ctx.outcome.ignored_manifests.push(display);
        }
    }
}

/// Diffs an unfiltered (but still [`PRUNED_DIRECTORIES`]-pruned) walk of `walk_root` against
/// `visited` (the file set an ignore-aware walk already found) and records any
/// *manifest-shaped* file present only in the unfiltered walk onto
/// [`WalkOutcome::ignored_manifests`] (issue #1109) — reusing [`EcosystemRegistry::for_uri`]
/// (the same routing [`route_file`] uses) rather than reimplementing manifest matching, and
/// never warning on a non-manifest file so this stays silent for the overwhelming majority of
/// ordinary `.gitignore` entries. `git_global`/`git_exclude` are kept `true` here too — the
/// same as the filtered walk (critic S3) — so a file excluded only by the operator-controlled
/// `.git/info/exclude` or global gitignore (out of scope for `respect_gitignore`, see [`walk`]'s
/// doc) is present in *both* walks and never misattributed to `.gitignore`/`.ignore`.
///
/// Only invoked when `respect_gitignore` is `true` — the default (`respect_gitignore: false`)
/// already never consults `.gitignore`/`.ignore`, so there is nothing to diff against. Uses its
/// own entry budget, independent of `ctx.entries_walked`/`ctx.limit` (reviewer follow-up #3):
/// this is a best-effort diagnostic pass over a walk whose *primary* manifest list is already
/// complete by the time this runs, so exhausting its budget must never set
/// [`WalkOutcome::truncated`] (which would misleadingly claim the primary walk, not this
/// diagnostic one, is incomplete) or otherwise affect the primary walk's own truncation state.
fn detect_ignored_manifests(
    walk_root: &Path,
    display_root: &Path,
    hidden: bool,
    ctx: &mut WalkCtx<'_>,
    visited: &BTreeSet<PathBuf>,
) {
    let mut builder = WalkBuilder::new(walk_root);
    builder
        .hidden(hidden)
        .ignore(false)
        .git_ignore(false)
        .git_global(true)
        .git_exclude(true)
        .filter_entry(is_not_pruned_directory);
    for (detection_entries, entry) in builder.build().enumerate() {
        if detection_entries >= ctx.limit {
            tracing::warn!(
                limit = ctx.limit,
                "ignored-manifest detection walk truncated: reached the maximum number of \
                 entries per run; some .gitignore/.ignore exclusions may go unreported"
            );
            return;
        }
        // Reviewer follow-up (#4): both failure paths below now match their counterparts in
        // `walk_directory`/`route_file` — an unreadable entry or an unconvertible path is
        // recorded, not silently skipped, so two structurally identical failure points added
        // by the same change behave identically.
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                ctx.outcome.walk_errors.push(error.to_string());
                continue;
            }
        };
        if !entry.file_type().is_some_and(|t| t.is_file()) {
            continue;
        }
        let path = entry.path();
        let display = path
            .strip_prefix(display_root)
            .unwrap_or(path)
            .to_path_buf();
        if visited.contains(&display) {
            continue;
        }
        match url::Url::from_file_path(path) {
            Ok(uri) => {
                if ctx.registry.for_uri(&uri).is_some() {
                    ctx.outcome.ignored_manifests.push(display);
                }
            }
            Err(()) => {
                ctx.outcome.walk_errors.push(format!(
                    "could not convert to a file URI while checking for ignore-suppressed \
                     manifests, skipping: {}",
                    display.display()
                ));
            }
        }
    }
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
///
/// `path` is expected to already be absolute (every caller absolutizes its walk root first —
/// see [`walk_with_limit`]) so `url::Url::from_file_path` should never fail in practice; if it
/// somehow does (issue #1108), that is recorded as a warning rather than silently dropping the
/// file, so a future regression in the absolutization degrades loudly instead of quietly
/// reintroducing the "walk finds zero manifests" bug.
fn route_file(
    path: &Path,
    display_path: &Path,
    registry: &EcosystemRegistry,
    outcome: &mut WalkOutcome,
) {
    let Ok(uri) = url::Url::from_file_path(path) else {
        outcome.walk_errors.push(format!(
            "could not convert to a file URI, skipping: {}",
            display_path.display()
        ));
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
    use std::sync::Mutex;

    /// Serializes tests that call `std::env::set_current_dir` — the process CWD is global
    /// state shared across every test in this binary, which otherwise run concurrently.
    static CWD_LOCK: Mutex<()> = Mutex::new(());

    /// Chdirs into `dir` and restores the original cwd on drop — including on an early return
    /// via a panicking assertion mid-test (critic M3), which a plain "restore at the end of the
    /// function" cannot do. Holds `CWD_LOCK` for its own lifetime.
    struct CwdGuard {
        original: PathBuf,
        _lock: std::sync::MutexGuard<'static, ()>,
    }

    impl CwdGuard {
        fn chdir(dir: &Path) -> Self {
            let lock = CWD_LOCK
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let original = std::env::current_dir().expect("read cwd");
            std::env::set_current_dir(dir).expect("chdir");
            Self {
                original,
                _lock: lock,
            }
        }
    }

    impl Drop for CwdGuard {
        fn drop(&mut self) {
            let _ = std::env::set_current_dir(&self.original);
        }
    }

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
        let outcome = walk(&[dir.path().to_path_buf()], &test_registry(), false);
        assert!(outcome.manifests.is_empty());
        assert!(!outcome.truncated);
    }

    #[test]
    fn test_walk_finds_cargo_toml() {
        let dir = tempfile::tempdir().expect("create temp dir");
        fs::write(dir.path().join("Cargo.toml"), "[package]\nname = \"x\"\n")
            .expect("write manifest");
        let outcome = walk(&[dir.path().to_path_buf()], &test_registry(), false);
        assert_eq!(outcome.manifests.len(), 1);
        assert_eq!(
            outcome.manifests[0].display_path,
            PathBuf::from("Cargo.toml")
        );
        assert_eq!(outcome.manifests[0].ecosystem.id(), "cargo");
    }

    /// With `respect_gitignore: true` (the opt-in, pre-#1109-fix behavior), a `.gitignore`
    /// entry still suppresses a manifest — this is intentional for a caller who explicitly
    /// asked to restore `git`'s own semantics.
    #[test]
    fn test_walk_respect_gitignore_true_skips_gitignored_manifest() {
        let dir = tempfile::tempdir().expect("create temp dir");
        // `ignore`'s `.gitignore` support only activates inside a git repo by default
        // (`require_git`); an empty `.git` marker is enough for detection.
        fs::create_dir(dir.path().join(".git")).expect("create .git marker");
        fs::write(dir.path().join(".gitignore"), "ignored/\n").expect("write gitignore");
        fs::create_dir(dir.path().join("ignored")).expect("mkdir");
        fs::write(dir.path().join("ignored").join("Cargo.toml"), "[package]\n")
            .expect("write manifest");
        let outcome = walk(&[dir.path().to_path_buf()], &test_registry(), true);
        assert!(outcome.manifests.is_empty());
        assert_eq!(
            outcome.ignored_manifests,
            vec![PathBuf::from("ignored").join("Cargo.toml")]
        );
    }

    /// Issue #1109 repro 1: a `.gitignore` entry must NOT suppress a manifest under the
    /// default (`respect_gitignore: false`) `check` behavior — this is the fail-open gap the
    /// issue reports (attacker-controlled `.gitignore` silently defeating the CI gate).
    #[test]
    fn test_walk_default_does_not_respect_gitignore() {
        let dir = tempfile::tempdir().expect("create temp dir");
        fs::create_dir(dir.path().join(".git")).expect("create .git marker");
        fs::write(dir.path().join(".gitignore"), "Cargo.toml\n").expect("write gitignore");
        fs::write(dir.path().join("Cargo.toml"), "[package]\n").expect("write manifest");
        let outcome = walk(&[dir.path().to_path_buf()], &test_registry(), false);
        assert_eq!(outcome.manifests.len(), 1);
        assert!(outcome.ignored_manifests.is_empty());
    }

    /// Issue #1109 repro 2: a nested `sub/.gitignore` (not just a top-level one) must not
    /// suppress a manifest under the default behavior either.
    #[test]
    fn test_walk_default_ignores_nested_gitignore() {
        let dir = tempfile::tempdir().expect("create temp dir");
        fs::create_dir(dir.path().join(".git")).expect("create .git marker");
        fs::create_dir(dir.path().join("sub")).expect("mkdir sub");
        fs::write(dir.path().join("sub").join(".gitignore"), "Cargo.toml\n")
            .expect("write nested gitignore");
        fs::write(dir.path().join("sub").join("Cargo.toml"), "[package]\n")
            .expect("write manifest");
        let outcome = walk(&[dir.path().to_path_buf()], &test_registry(), false);
        assert_eq!(outcome.manifests.len(), 1);
    }

    /// Issue #1109 repro 3: an `.ignore` file (no `.git` directory at all) must not suppress a
    /// manifest under the default behavior.
    #[test]
    fn test_walk_default_ignores_dot_ignore_file_without_git_repo() {
        let dir = tempfile::tempdir().expect("create temp dir");
        fs::write(dir.path().join(".ignore"), "Cargo.toml\n").expect("write .ignore");
        fs::write(dir.path().join("Cargo.toml"), "[package]\n").expect("write manifest");
        let outcome = walk(&[dir.path().to_path_buf()], &test_registry(), false);
        assert_eq!(outcome.manifests.len(), 1);
    }

    /// Critic S1 (post-#1109 default-flip regression): disabling `.gitignore`/`.ignore` by
    /// default must not turn a vendored `node_modules/` tree back into hundreds of scanned
    /// manifests — the compiled-in [`PRUNED_DIRECTORIES`] denylist must prune it regardless.
    #[test]
    fn test_walk_default_prunes_node_modules() {
        let dir = tempfile::tempdir().expect("create temp dir");
        fs::write(dir.path().join("Cargo.toml"), "[package]\n").expect("write manifest");
        fs::create_dir_all(dir.path().join("node_modules").join("left-pad"))
            .expect("mkdir node_modules/left-pad");
        fs::write(
            dir.path()
                .join("node_modules")
                .join("left-pad")
                .join("package.json"),
            "{}",
        )
        .expect("write vendored manifest");

        let outcome = walk(&[dir.path().to_path_buf()], &test_registry(), false);

        assert_eq!(outcome.manifests.len(), 1);
        assert_eq!(
            outcome.manifests[0].display_path,
            PathBuf::from("Cargo.toml")
        );
    }

    /// Reviewer follow-up #2: an unusual monorepo layout can have a *real* subproject's
    /// manifest sitting directly under a directory named `vendor`/`build`/`dist`/... —
    /// `PRUNED_DIRECTORIES` still excludes it from the primary scan, but the omission must be
    /// visible via `WalkOutcome::ignored_manifests`, in every mode (not only under
    /// `--respect-gitignore`).
    #[test]
    fn test_walk_default_warns_on_manifest_directly_inside_pruned_directory() {
        let dir = tempfile::tempdir().expect("create temp dir");
        fs::create_dir(dir.path().join("vendor")).expect("mkdir vendor");
        fs::write(dir.path().join("vendor").join("Cargo.toml"), "[package]\n")
            .expect("write manifest directly under pruned dir");

        let outcome = walk(&[dir.path().to_path_buf()], &test_registry(), false);

        assert!(
            outcome.manifests.is_empty(),
            "still pruned from the primary scan"
        );
        assert_eq!(
            outcome.ignored_manifests,
            vec![PathBuf::from("vendor").join("Cargo.toml")]
        );
    }

    /// Companion to the above: a manifest nested two or more levels inside a pruned directory
    /// remains a documented, accepted limitation (checking only the pruned directory's own
    /// root avoids reintroducing the cost a full recursive re-walk would bring back for a
    /// large vendored tree) — not a regression, since it was never found before this fix.
    #[test]
    fn test_walk_manifest_nested_two_levels_inside_pruned_directory_remains_unreported() {
        let dir = tempfile::tempdir().expect("create temp dir");
        fs::create_dir_all(dir.path().join("vendor").join("sub")).expect("mkdir vendor/sub");
        fs::write(
            dir.path().join("vendor").join("sub").join("Cargo.toml"),
            "[package]\n",
        )
        .expect("write nested manifest");

        let outcome = walk(&[dir.path().to_path_buf()], &test_registry(), false);

        assert!(outcome.manifests.is_empty());
        assert!(outcome.ignored_manifests.is_empty());
    }

    /// Reviewer follow-up #3: `detect_ignored_manifests`'s diagnostic pass must use its own
    /// entry budget, independent of the primary walk's `ctx.entries_walked`/`ctx.limit` — a
    /// small limit that comfortably covers the primary (filtered) walk but not the
    /// diagnostic (unfiltered) pass over an ignored, non-manifest-shaped `noise/` directory
    /// must exhaust only the diagnostic pass, never set `WalkOutcome::truncated`, and never
    /// affect the primary walk's own (already-complete) manifest list.
    #[test]
    fn test_detect_ignored_manifests_uses_its_own_budget_and_does_not_set_truncated() {
        let dir = tempfile::tempdir().expect("create temp dir");
        fs::create_dir(dir.path().join(".git")).expect("create .git marker");
        fs::write(dir.path().join(".gitignore"), "noise/\n").expect("write gitignore");
        fs::write(dir.path().join("Cargo.toml"), "[package]\n").expect("write manifest");
        fs::create_dir(dir.path().join("noise")).expect("mkdir noise");
        for i in 0..20 {
            fs::write(dir.path().join("noise").join(format!("f{i}.txt")), "")
                .expect("write noise file");
        }

        // Comfortably covers the primary walk (root + .gitignore + Cargo.toml == 3 entries,
        // `noise/` itself is `.gitignore`-excluded there) but not the diagnostic pass, which
        // ignores `.gitignore` and must descend into `noise/`'s 20 files.
        let outcome = walk_with_limit(&[dir.path().to_path_buf()], &test_registry(), 5, true);

        assert!(
            !outcome.truncated,
            "the diagnostic pass' own budget exhaustion must not mark the primary walk truncated"
        );
        assert_eq!(
            outcome.manifests.len(),
            1,
            "primary walk result must still be complete"
        );
    }

    /// Critic S2: with `respect_gitignore: true`, a `node_modules/` excluded by an ordinary,
    /// non-security-relevant `.gitignore` entry must not be reported via
    /// [`WalkOutcome::ignored_manifests`] — [`PRUNED_DIRECTORIES`] removes it from both the
    /// filtered and unfiltered walk, so there is nothing to diff.
    #[test]
    fn test_walk_respect_gitignore_does_not_warn_on_pruned_directory() {
        let dir = tempfile::tempdir().expect("create temp dir");
        fs::create_dir(dir.path().join(".git")).expect("create .git marker");
        fs::write(dir.path().join(".gitignore"), "node_modules/\n").expect("write gitignore");
        fs::create_dir_all(dir.path().join("node_modules").join("left-pad"))
            .expect("mkdir node_modules/left-pad");
        fs::write(
            dir.path()
                .join("node_modules")
                .join("left-pad")
                .join("package.json"),
            "{}",
        )
        .expect("write vendored manifest");

        let outcome = walk(&[dir.path().to_path_buf()], &test_registry(), true);

        assert!(outcome.ignored_manifests.is_empty());
    }

    /// Critic S3: a manifest excluded only by the always-on, operator-controlled
    /// `.git/info/exclude` must not be misattributed to `.gitignore`/`.ignore` — both walks in
    /// [`detect_ignored_manifests`] must apply `git_exclude` identically, so such a file is
    /// absent from *both* and never diffed into [`WalkOutcome::ignored_manifests`].
    #[test]
    fn test_walk_git_info_exclude_suppression_not_misreported_as_ignored_manifest() {
        let dir = tempfile::tempdir().expect("create temp dir");
        fs::create_dir_all(dir.path().join(".git").join("info")).expect("mkdir .git/info");
        fs::write(
            dir.path().join(".git").join("info").join("exclude"),
            "Cargo.toml\n",
        )
        .expect("write git info/exclude");
        fs::write(dir.path().join("Cargo.toml"), "[package]\n").expect("write manifest");

        let outcome = walk(&[dir.path().to_path_buf()], &test_registry(), true);

        assert!(outcome.manifests.is_empty());
        assert!(
            outcome.ignored_manifests.is_empty(),
            ".git/info/exclude is operator-controlled, not a .gitignore/.ignore rule"
        );
    }

    #[test]
    fn test_walk_single_file_path_bypasses_gitignore() {
        let dir = tempfile::tempdir().expect("create temp dir");
        fs::write(dir.path().join(".gitignore"), "Cargo.toml\n").expect("write gitignore");
        let manifest = dir.path().join("Cargo.toml");
        fs::write(&manifest, "[package]\n").expect("write manifest");
        let outcome = walk(&[manifest], &test_registry(), true);
        assert_eq!(outcome.manifests.len(), 1);
    }

    /// Regression test for #1108: a *relative* walk root must still find manifests —
    /// `url::Url::from_file_path` (used to route a discovered file) rejects relative paths, so
    /// before the fix every file under a relative root was silently dropped, and `deps-cli
    /// check`'s own no-argument default (`.`) always reported zero findings.
    ///
    /// `std::env::set_current_dir` mutates process-global state, so this test (and any other
    /// test doing the same) is serialized via [`CwdGuard`]/[`CWD_LOCK`], which also restores
    /// the original cwd even if an assertion below panics.
    #[test]
    fn test_walk_relative_root_finds_manifest() {
        let dir = tempfile::tempdir().expect("create temp dir");
        fs::write(dir.path().join("Cargo.toml"), "[package]\n").expect("write manifest");
        let _guard = CwdGuard::chdir(dir.path());

        let outcome = walk(&[PathBuf::from(".")], &test_registry(), false);

        assert_eq!(outcome.manifests.len(), 1);
        assert!(outcome.walk_errors.is_empty());
        assert_eq!(
            outcome.manifests[0].display_path,
            PathBuf::from("Cargo.toml")
        );
    }

    /// Companion to [`test_walk_relative_root_finds_manifest`]: an explicitly-given *relative*
    /// file path must resolve to the real path-conversion issue being fixed, not report the
    /// file as unrecognized by any ecosystem (the previous, misleading failure mode).
    #[test]
    fn test_walk_relative_explicit_file_path_is_found() {
        let dir = tempfile::tempdir().expect("create temp dir");
        fs::write(dir.path().join("Cargo.toml"), "[package]\n").expect("write manifest");
        let _guard = CwdGuard::chdir(dir.path());

        let outcome = walk(&[PathBuf::from("Cargo.toml")], &test_registry(), false);

        assert_eq!(outcome.manifests.len(), 1);
        assert!(outcome.unrecognized_explicit_paths.is_empty());
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

        let outcome = walk_with_limit(&[dir.path().to_path_buf()], &test_registry(), 2, false);
        assert!(
            outcome.truncated,
            "a 2-entry limit against a 6-entry tree must truncate"
        );
    }

    #[test]
    fn test_walk_with_limit_does_not_truncate_when_under_the_cap() {
        let dir = tempfile::tempdir().expect("create temp dir");
        fs::write(dir.path().join("Cargo.toml"), "[package]\n").expect("write manifest");
        let outcome = walk_with_limit(&[dir.path().to_path_buf()], &test_registry(), 100, false);
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
        let outcome = walk(std::slice::from_ref(&unknown), &test_registry(), false);
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
        let outcome = walk(&[dir.path().to_path_buf()], &test_registry(), false);
        assert!(outcome.unrecognized_explicit_paths.is_empty());
    }

    #[test]
    fn test_walk_multiple_ecosystems_in_one_tree() {
        let dir = tempfile::tempdir().expect("create temp dir");
        fs::write(dir.path().join("Cargo.toml"), "[package]\n").expect("write cargo manifest");
        fs::write(dir.path().join("package.json"), "{}").expect("write npm manifest");
        let outcome = walk(&[dir.path().to_path_buf()], &test_registry(), false);
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

        let outcome = walk_with_limit(&[dir.path().to_path_buf()], &test_registry(), 3, false);
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

        let outcome = walk(&[dir.path().to_path_buf()], &test_registry(), false);
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
        // Each manifest needs its own subdirectory — matched by exact filename, not a
        // pattern, so `Cargo0.toml`..`Cargo4.toml` siblings would never route to any ecosystem.
        let paths: Vec<PathBuf> = (0..5)
            .map(|i| {
                let subdir = dir.path().join(format!("pkg{i}"));
                fs::create_dir(&subdir).expect("mkdir");
                let path = subdir.join("Cargo.toml");
                fs::write(&path, "[package]\n").expect("write manifest");
                path
            })
            .collect();

        let outcome = walk_with_limit(&paths, &test_registry(), 2, false);
        assert!(
            outcome.truncated,
            "a 2-entry limit against 5 explicit paths must truncate"
        );
        assert_eq!(outcome.manifests.len(), 2);
    }
}
