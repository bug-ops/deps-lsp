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

/// Returns `false` for a directory entry [`ignore::WalkBuilder::filter_entry`] should prune
/// *before descending into it* — its canonicalized real path falls outside `canonical_root`
/// under `follow_symlinks: true`. Never prunes depth 0 (the walk root itself; already
/// containment-checked by its own caller — see [`walk_with_limit`]'s sub-root check) or a
/// non-directory entry (the per-file [`canonicalize_within_root`] check in [`walk_directory`]'s
/// match loop already covers those).
///
/// Background code-review finding #2: without this, `follow_links(true)` lets `ignore` descend
/// into a symlinked directory that resolves entirely outside the walked root (e.g.
/// `evil -> /some/huge/external/tree`) before the per-file check rejects each descendant
/// individually — on a large enough external tree this can exhaust [`MAX_WALKED_FILES`] on
/// content outside the walked root, silently truncating the walk and dropping legitimate
/// manifests elsewhere in the real tree, reintroducing #1112's own fail-open class through this
/// fix's own new flag. Pruning at the directory level (mirroring [`is_not_pruned_directory`]'s
/// existing prune-before-descend pattern) bounds the cost to one `canonicalize` call per
/// directory rather than one per descendant file — deliberately *not* extended into the
/// existing pruned-directory one-level-deep manifest peek
/// ([`warn_on_pruned_directory_manifest`]), since that helper's `read_dir` is only safe because
/// a *pruned* directory is still inside the trusted walked root; an *escaping* one is not, and
/// must not have its contents listed at all.
///
/// Additive to, not a replacement for, the per-file [`canonicalize_within_root`] check: a leaf
/// file symlink that individually escapes the root without its parent directory itself being a
/// symlink is not a directory-level escape, so this check does not fire for it and the per-file
/// check remains the only guard for that case.
fn is_not_escaping_directory(
    entry: &ignore::DirEntry,
    follow_symlinks: bool,
    canonical_root: Option<&Path>,
) -> bool {
    if !follow_symlinks || entry.depth() == 0 {
        return true;
    }
    if !entry
        .file_type()
        .is_some_and(|file_type| file_type.is_dir())
    {
        return true;
    }
    let Some(canonical_root) = canonical_root else {
        return false;
    };
    let Ok(canonical_path) = std::fs::canonicalize(entry.path()) else {
        return false;
    };
    canonical_path.starts_with(canonical_root)
}

/// One manifest discovered by [`walk`], already routed to its owning ecosystem.
pub struct DiscoveredManifest {
    /// Absolute (or walk-root-relative, when the walked root itself was relative)
    /// filesystem path to read the manifest's content from — for a symlinked manifest under
    /// `--follow-symlinks`, this is the resolved, canonicalized real path (FR-007), never the
    /// symlink itself.
    pub path: PathBuf,
    /// Absolute filesystem path used to derive the manifest's URI for parsing and lockfile/
    /// in-use-version discovery (review finding M2). This must stay the manifest's *encountered*
    /// path — the symlink's own location, not its resolved target's — because lockfile lookup
    /// searches ancestor directories starting from this URI: a manifest symlinked into
    /// directory A, whose target lives in directory B, must find `A`'s adjacent lockfile, not
    /// `B`'s (or `B`'s absence of one), matching US-002's own shared-manifest scenario. Identical
    /// to [`path`](Self::path) for every non-symlinked (or `--follow-symlinks`-disabled)
    /// manifest.
    pub uri_path: PathBuf,
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
///
/// **`follow_symlinks` (issue #1112)**: a directory entry that is itself a symlink to a
/// manifest-shaped file is always detected, regardless of this flag — its path is reported via
/// [`WalkOutcome::ignored_manifests`], the same sink a pruned or `.gitignore`-excluded manifest
/// already uses, so a symlinked manifest can never silently vanish from the report. Detection
/// alone never reads the target's content. When `follow_symlinks` is `true`, such a symlink is
/// additionally resolved and routed like any other manifest (appearing in
/// [`WalkOutcome::manifests`] instead, with [`DiscoveredManifest::path`] set to the resolved
/// real path used for reading and [`DiscoveredManifest::display_path`] kept as the symlink's
/// own encountered path). Every routed entry under `follow_symlinks: true` — not only ones
/// where the leaf itself is a symlink, since an entry reached by descending into a followed
/// symlinked *directory* is otherwise indistinguishable from an ordinary one — is canonicalized
/// and checked against the walked root's own canonicalized absolute path; an entry that
/// resolves outside the root is never routed, and is reported via `ignored_manifests` only when
/// it is itself manifest-shaped (an arbitrary out-of-root symlink to a non-manifest file is
/// silently skipped, matching detection's own never-warn-on-non-manifests invariant). This
/// containment check applies to every registered ecosystem's own dot-directory sub-root (e.g.
/// `.github`) too, and — because `ignore`/`walkdir` always follows a walk's own *root* symlink
/// regardless of `follow_links` — that sub-root containment check runs in every mode, not only
/// under `follow_symlinks`. A symlink loop is detected by the underlying `ignore` crate and
/// surfaced via [`WalkOutcome::walk_errors`].
#[must_use]
pub fn walk(
    roots: &[PathBuf],
    registry: &EcosystemRegistry,
    respect_gitignore: bool,
    follow_symlinks: bool,
) -> WalkOutcome {
    walk_with_limit(
        roots,
        registry,
        MAX_WALKED_FILES,
        respect_gitignore,
        follow_symlinks,
    )
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
    follow_symlinks: bool,
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
            route_file(
                &absolute_root,
                &absolute_root,
                root,
                registry,
                &mut ctx.outcome,
            );
            if ctx.outcome.manifests.len() == matched_before {
                ctx.outcome.unrecognized_explicit_paths.push(root.clone());
            }
            continue;
        }

        // FR-004: the escape-prevention baseline, canonicalized once per root (not per entry).
        // Computed unconditionally, not only when `follow_symlinks` is set (critic finding S1):
        // `ignore`/`walkdir` always follows a *root* symlink when starting a walk, regardless
        // of `follow_links`, so a symlinked hidden-ecosystem sub-root (e.g. a repository's own
        // `.github` replaced by a symlink) can escape the walked root in every mode, not only
        // under `--follow-symlinks` — this baseline is reused below to close that gap too.
        // `canonicalize` failing here (a root that itself cannot be resolved) is not fatal to
        // the walk: it just means containment can never be proven for anything under this root,
        // so every symlink target falls back to `ignored_manifests` (or the sub-root is simply
        // not walked) rather than being routed.
        let canonical_root = std::fs::canonicalize(&absolute_root).ok();

        // Always hidden-filtered: `hidden(true)` filters entries by their own basename as the
        // walk descends, so `walk_root` itself is never excluded even if its name starts with
        // `.` (e.g. a tempfile dir on macOS) — that previously caused a regression.
        if !walk_directory(
            &absolute_root,
            &absolute_root,
            true,
            respect_gitignore,
            follow_symlinks,
            canonical_root.as_deref(),
            &mut ctx,
        ) {
            break 'roots;
        }

        for dir_name in &hidden_ecosystem_dirs {
            let sub_root = absolute_root.join(dir_name);
            if !sub_root.is_dir() {
                continue;
            }
            // S1: `sub_root` (e.g. `<root>/.github`) may itself be a symlink escaping the
            // walked root — `ignore`/`walkdir` always follows a walk's own root symlink, so
            // this containment check applies regardless of `follow_symlinks`. A root that
            // could not be canonicalized above means containment can never be proven, so the
            // sub-root is skipped entirely rather than walked unchecked.
            match (
                canonical_root.as_deref(),
                std::fs::canonicalize(&sub_root).ok(),
            ) {
                (Some(canonical_root), Some(canonical_sub_root))
                    if canonical_sub_root.starts_with(canonical_root) => {}
                _ => continue,
            }
            if !walk_directory(
                &sub_root,
                &absolute_root,
                false,
                respect_gitignore,
                follow_symlinks,
                canonical_root.as_deref(),
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
    follow_symlinks: bool,
    canonical_root: Option<&Path>,
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
        .git_exclude(true)
        .follow_links(follow_symlinks);
    {
        let pruned_dirs = Arc::clone(&pruned_dirs);
        let canonical_root_owned = canonical_root.map(Path::to_path_buf);
        builder.filter_entry(move |entry| {
            if !is_not_pruned_directory(entry) {
                pruned_dirs
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(entry.path().to_path_buf());
                return false;
            }
            is_not_escaping_directory(entry, follow_symlinks, canonical_root_owned.as_deref())
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
                if follow_symlinks {
                    // FR-004/FR-007 (critic finding C1): every entry is canonicalized and
                    // containment-checked here, not only ones where the leaf itself is a
                    // symlink — see `canonicalize_within_root`'s doc for why a leaf-only check
                    // misses an entry reached through a followed symlinked *directory*. The
                    // resolved path doubles as the real path routed for reading (FR-007).
                    match canonicalize_within_root(path, canonical_root) {
                        Some(canonical_path) => {
                            // Routing (basename/pattern matching) still goes through `path`
                            // (the encountered, possibly-symlinked path) — only the content
                            // read later uses the resolved `canonical_path` (FR-007).
                            route_file(
                                path,
                                &canonical_path,
                                &display,
                                ctx.registry,
                                &mut ctx.outcome,
                            );
                        }
                        None => {
                            // S4: only report as an excluded manifest when the escaping/
                            // unresolvable path is itself manifest-shaped — an arbitrary
                            // out-of-root symlink (e.g. `notes.txt -> /etc/hosts`) must not
                            // produce a false "looks like a manifest" warning.
                            if symlink_is_manifest_shaped(path, ctx.registry) {
                                ctx.outcome.ignored_manifests.push(display);
                            }
                        }
                    }
                } else {
                    route_file(path, path, &display, ctx.registry, &mut ctx.outcome);
                }
            }
            Ok(entry) => {
                // Issue #1112: `file_type()` reports the symlink's own type, not its target's,
                // so a manifest reachable only through a symlink otherwise falls through here
                // silently. Detection alone (this arm) is always on; actually resolving and
                // scanning the target is opt-in via `follow_symlinks` (handled by `ignore`'s
                // own `WalkBuilder::follow_links`, wired above).
                if entry.path_is_symlink() && symlink_is_manifest_shaped(entry.path(), ctx.registry)
                {
                    let path = entry.path();
                    let display = path
                        .strip_prefix(display_root)
                        .unwrap_or(path)
                        .to_path_buf();
                    // Background code-review finding #1: must mirror the `is_file()` arm's
                    // `visited` insert above — otherwise `detect_ignored_manifests`' separate
                    // unfiltered walk (run when `respect_gitignore` is true) finds this same
                    // symlink again, sees it missing from `visited`, and pushes a second,
                    // duplicate `ignored_manifests` entry for it.
                    if respect_gitignore {
                        visited.insert(display.clone());
                    }
                    ctx.outcome.ignored_manifests.push(display);
                }
            }
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
        let path = entry.path();
        if !symlink_is_manifest_shaped(&path, ctx.registry) {
            continue;
        }
        let display = path
            .strip_prefix(display_root)
            .unwrap_or(&path)
            .to_path_buf();
        ctx.outcome.ignored_manifests.push(display);
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
            // #1112/M5: a symlinked manifest excluded by `.gitignore`/`.ignore` never appears
            // in the primary (filtered) walk at all — `ignore` skips a gitignored entry before
            // yielding it, so it also never lands in `visited`. This unfiltered pass is the
            // only place that still sees it; without this branch it silently vanished from
            // both `manifests` and `ignored_manifests` under `--respect-gitignore`, the same
            // fail-open class `--respect-gitignore` closes for ordinary files.
            let path = entry.path();
            if entry.path_is_symlink() && symlink_is_manifest_shaped(path, ctx.registry) {
                let display = path
                    .strip_prefix(display_root)
                    .unwrap_or(path)
                    .to_path_buf();
                if !visited.contains(&display) {
                    ctx.outcome.ignored_manifests.push(display);
                }
            }
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

/// FR-004/FR-007: resolves `path` to its canonicalized real path and returns it only when that
/// path is contained within `canonical_root`. `canonical_root` being `None` (symlink-following
/// disabled, or the root itself failed to canonicalize) always yields `None` — a safe default,
/// never routing an entry whose containment cannot be proven. A `canonicalize` failure on `path`
/// itself (e.g. a race between the walk's stat and this check) is likewise treated as "outside
/// root", never as "inside".
///
/// Called for **every** routed file entry under `follow_symlinks: true`, not only ones where
/// the leaf itself is a symlink (critic finding C1): `ignore`/`walkdir` only sets
/// `DirEntry::path_is_symlink()` on the entry actually named as a symlink, so an entry reached
/// by *descending into* a followed symlinked directory reports `path_is_symlink() == false` for
/// its own leaf while still resolving to a real path outside the walked root — canonicalizing
/// unconditionally (rather than gating on `path_is_symlink()`) closes that gap for both leaf
/// symlinks and symlinked ancestors alike.
///
/// The returned path also satisfies FR-007: it is the resolved real path
/// [`DiscoveredManifest::path`] must use for reading, computed once here rather than a second
/// time at read-time, which would otherwise leave a TOCTOU window between this containment
/// check and the actual read.
fn canonicalize_within_root(path: &Path, canonical_root: Option<&Path>) -> Option<PathBuf> {
    let canonical_root = canonical_root?;
    let canonical_path = std::fs::canonicalize(path).ok()?;
    canonical_path
        .starts_with(canonical_root)
        .then_some(canonical_path)
}

/// Resolves `path` (which failed the regular `is_file()` check) as a possible symlink to a
/// manifest-shaped file, without reading its content. Returns `false` for anything that isn't
/// a symlink resolving to a manifest-shaped regular file — a broken symlink, a symlink to a
/// directory, or a target no ecosystem's `for_uri` claims (issue #1112, FR-001).
fn symlink_is_manifest_shaped(path: &Path, registry: &EcosystemRegistry) -> bool {
    let Ok(metadata) = std::fs::metadata(path) else {
        return false;
    };
    if !metadata.is_file() {
        return false;
    }
    let Ok(uri) = url::Url::from_file_path(path) else {
        return false;
    };
    registry.for_uri(&uri).is_some()
}

/// Routes one already-discovered file through `registry.for_uri`, pushing a
/// [`DiscoveredManifest`] onto `outcome` when an ecosystem claims it.
///
/// `route_path` and `read_path` are the same path for every caller except the
/// `follow_symlinks: true` branch of `walk_directory` (FR-007): ecosystem routing is a
/// basename/pattern match (`manifest_filenames`, `manifest_patterns`, ...), so it must always
/// go through the *encountered* path — a symlink named `Cargo.toml` routes as `Cargo.toml`
/// regardless of what its target is named — while [`DiscoveredManifest::path`] (used later to
/// read the manifest's content) must be the resolved real path a symlink was already
/// containment-checked against, not the symlink itself. `route_path` is also stored as
/// [`DiscoveredManifest::uri_path`] (review finding M2): lockfile/in-use-version discovery
/// must anchor its ancestor-directory search at the symlink's own location, not its target's.
///
/// `route_path` is expected to already be absolute (every caller absolutizes its walk root
/// first — see [`walk_with_limit`]) so `url::Url::from_file_path` should never fail in
/// practice; if it somehow does (issue #1108), that is recorded as a warning rather than
/// silently dropping the file, so a future regression in the absolutization degrades loudly
/// instead of quietly reintroducing the "walk finds zero manifests" bug.
fn route_file(
    route_path: &Path,
    read_path: &Path,
    display_path: &Path,
    registry: &EcosystemRegistry,
    outcome: &mut WalkOutcome,
) {
    let Ok(uri) = url::Url::from_file_path(route_path) else {
        outcome.walk_errors.push(format!(
            "could not convert to a file URI, skipping: {}",
            display_path.display()
        ));
        return;
    };
    if let Some(ecosystem) = registry.for_uri(&uri) {
        outcome.manifests.push(DiscoveredManifest {
            path: read_path.to_path_buf(),
            uri_path: route_path.to_path_buf(),
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
        let outcome = walk(&[dir.path().to_path_buf()], &test_registry(), false, false);
        assert!(outcome.manifests.is_empty());
        assert!(!outcome.truncated);
    }

    #[test]
    fn test_walk_finds_cargo_toml() {
        let dir = tempfile::tempdir().expect("create temp dir");
        fs::write(dir.path().join("Cargo.toml"), "[package]\nname = \"x\"\n")
            .expect("write manifest");
        let outcome = walk(&[dir.path().to_path_buf()], &test_registry(), false, false);
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
        let outcome = walk(&[dir.path().to_path_buf()], &test_registry(), true, false);
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
        let outcome = walk(&[dir.path().to_path_buf()], &test_registry(), false, false);
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
        let outcome = walk(&[dir.path().to_path_buf()], &test_registry(), false, false);
        assert_eq!(outcome.manifests.len(), 1);
    }

    /// Issue #1109 repro 3: an `.ignore` file (no `.git` directory at all) must not suppress a
    /// manifest under the default behavior.
    #[test]
    fn test_walk_default_ignores_dot_ignore_file_without_git_repo() {
        let dir = tempfile::tempdir().expect("create temp dir");
        fs::write(dir.path().join(".ignore"), "Cargo.toml\n").expect("write .ignore");
        fs::write(dir.path().join("Cargo.toml"), "[package]\n").expect("write manifest");
        let outcome = walk(&[dir.path().to_path_buf()], &test_registry(), false, false);
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

        let outcome = walk(&[dir.path().to_path_buf()], &test_registry(), false, false);

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

        let outcome = walk(&[dir.path().to_path_buf()], &test_registry(), false, false);

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

        let outcome = walk(&[dir.path().to_path_buf()], &test_registry(), false, false);

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
        let outcome = walk_with_limit(
            &[dir.path().to_path_buf()],
            &test_registry(),
            5,
            true,
            false,
        );

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

        let outcome = walk(&[dir.path().to_path_buf()], &test_registry(), true, false);

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

        let outcome = walk(&[dir.path().to_path_buf()], &test_registry(), true, false);

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
        let outcome = walk(&[manifest], &test_registry(), true, false);
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

        let outcome = walk(&[PathBuf::from(".")], &test_registry(), false, false);

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

        let outcome = walk(
            &[PathBuf::from("Cargo.toml")],
            &test_registry(),
            false,
            false,
        );

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

        let outcome = walk_with_limit(
            &[dir.path().to_path_buf()],
            &test_registry(),
            2,
            false,
            false,
        );
        assert!(
            outcome.truncated,
            "a 2-entry limit against a 6-entry tree must truncate"
        );
    }

    #[test]
    fn test_walk_with_limit_does_not_truncate_when_under_the_cap() {
        let dir = tempfile::tempdir().expect("create temp dir");
        fs::write(dir.path().join("Cargo.toml"), "[package]\n").expect("write manifest");
        let outcome = walk_with_limit(
            &[dir.path().to_path_buf()],
            &test_registry(),
            100,
            false,
            false,
        );
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
        let outcome = walk(
            std::slice::from_ref(&unknown),
            &test_registry(),
            false,
            false,
        );
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
        let outcome = walk(&[dir.path().to_path_buf()], &test_registry(), false, false);
        assert!(outcome.unrecognized_explicit_paths.is_empty());
    }

    #[test]
    fn test_walk_multiple_ecosystems_in_one_tree() {
        let dir = tempfile::tempdir().expect("create temp dir");
        fs::write(dir.path().join("Cargo.toml"), "[package]\n").expect("write cargo manifest");
        fs::write(dir.path().join("package.json"), "{}").expect("write npm manifest");
        let outcome = walk(&[dir.path().to_path_buf()], &test_registry(), false, false);
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

        let outcome = walk_with_limit(
            &[dir.path().to_path_buf()],
            &test_registry(),
            3,
            false,
            false,
        );
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

        let outcome = walk(&[dir.path().to_path_buf()], &test_registry(), false, false);
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

        let outcome = walk_with_limit(&paths, &test_registry(), 2, false, false);
        assert!(
            outcome.truncated,
            "a 2-entry limit against 5 explicit paths must truncate"
        );
        assert_eq!(outcome.manifests.len(), 2);
    }

    /// Issue #1112, US-001: a symlinked manifest must never silently vanish from the scan
    /// under the default (`follow_symlinks: false`) mode — it is reported via
    /// `ignored_manifests`, not `manifests`.
    #[cfg(unix)]
    #[test]
    fn test_walk_default_detects_symlinked_manifest_without_following() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let real = dir.path().join("real").join("manifest-data");
        fs::create_dir(dir.path().join("real")).expect("mkdir real");
        fs::write(&real, "[package]\n").expect("write real manifest");
        std::os::unix::fs::symlink(&real, dir.path().join("Cargo.toml")).expect("create symlink");

        let outcome = walk(&[dir.path().to_path_buf()], &test_registry(), false, false);

        assert!(outcome.manifests.is_empty());
        assert_eq!(outcome.ignored_manifests, vec![PathBuf::from("Cargo.toml")]);
    }

    /// A broken symlink is not manifest-shaped by definition — no `ignored_manifests` entry.
    #[cfg(unix)]
    #[test]
    fn test_walk_broken_symlink_is_not_reported_as_manifest() {
        let dir = tempfile::tempdir().expect("create temp dir");
        std::os::unix::fs::symlink(
            dir.path().join("does-not-exist"),
            dir.path().join("Cargo.toml"),
        )
        .expect("create broken symlink");

        let outcome = walk(&[dir.path().to_path_buf()], &test_registry(), false, false);

        assert!(outcome.manifests.is_empty());
        assert!(outcome.ignored_manifests.is_empty());
    }

    /// A symlink to a directory is not manifest-shaped either.
    #[cfg(unix)]
    #[test]
    fn test_walk_symlink_to_directory_is_not_reported_as_manifest() {
        let dir = tempfile::tempdir().expect("create temp dir");
        fs::create_dir(dir.path().join("real_dir")).expect("mkdir real_dir");
        std::os::unix::fs::symlink(dir.path().join("real_dir"), dir.path().join("link_dir"))
            .expect("create symlink to directory");

        let outcome = walk(&[dir.path().to_path_buf()], &test_registry(), false, false);

        assert!(outcome.manifests.is_empty());
        assert!(outcome.ignored_manifests.is_empty());
    }

    /// Spec §6 edge case: a symlink to a manifest-shaped file sitting directly at a
    /// `PRUNED_DIRECTORIES`-excluded directory's own root is reported via `ignored_manifests`,
    /// mirroring the existing regular-file case
    /// (`test_walk_default_warns_on_manifest_directly_inside_pruned_directory`).
    #[cfg(unix)]
    #[test]
    fn test_walk_pruned_directory_symlinked_manifest_is_still_warned() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let real = dir.path().join("real-cargo.toml");
        fs::write(&real, "[package]\n").expect("write real manifest");
        fs::create_dir(dir.path().join("vendor")).expect("mkdir vendor");
        std::os::unix::fs::symlink(&real, dir.path().join("vendor").join("Cargo.toml"))
            .expect("create symlink inside pruned directory");

        let outcome = walk(&[dir.path().to_path_buf()], &test_registry(), false, false);

        assert!(
            outcome.manifests.is_empty(),
            "still pruned from the primary scan"
        );
        assert_eq!(
            outcome.ignored_manifests,
            vec![PathBuf::from("vendor").join("Cargo.toml")]
        );
    }

    /// Issue #1112, US-002 (FR-003): with `follow_symlinks: true`, a symlinked manifest inside
    /// the walked root is resolved and routed, appearing in `manifests` rather than only
    /// `ignored_manifests`.
    #[cfg(unix)]
    #[test]
    fn test_walk_follow_symlinks_resolves_and_routes_manifest() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let real = dir.path().join("real").join("manifest-data");
        fs::create_dir(dir.path().join("real")).expect("mkdir real");
        fs::write(&real, "[package]\n").expect("write real manifest");
        std::os::unix::fs::symlink(&real, dir.path().join("Cargo.toml")).expect("create symlink");

        let outcome = walk(&[dir.path().to_path_buf()], &test_registry(), false, true);

        assert_eq!(outcome.manifests.len(), 1);
        assert!(outcome.ignored_manifests.is_empty());
        assert_eq!(outcome.manifests[0].ecosystem.id(), "cargo");
        // S3/FR-007: `path` (used for reading) is the resolved real path, not the symlink.
        assert_eq!(
            outcome.manifests[0]
                .path
                .canonicalize()
                .expect("canonicalize actual path"),
            real.canonicalize()
                .expect("canonicalize expected real path")
        );
        // Review finding M3: canonicalizing both sides above can't actually distinguish
        // "symlink path" from "real path" on its own (both would resolve to the same real
        // file) — assert the *raw*, non-canonicalized paths differ too, proving `path` is
        // genuinely the resolved target, not the symlink verbatim.
        assert_ne!(
            outcome.manifests[0].path,
            dir.path().join("Cargo.toml"),
            "path must be the resolved real path, not the symlink's own raw path"
        );
    }

    /// FR-002/US-001: the same symlinked-manifest fixture behaves oppositely depending on the
    /// flag — `follow_symlinks: false` never reads the target (empty `manifests`, populated
    /// `ignored_manifests`), `follow_symlinks: true` resolves and routes it (populated
    /// `manifests`, empty `ignored_manifests`) — proving the flag actually gates reading, not
    /// just two independently-plausible outcomes.
    #[cfg(unix)]
    #[test]
    fn test_walk_follow_symlinks_toggles_between_ignored_and_routed() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let real = dir.path().join("real").join("manifest-data");
        fs::create_dir(dir.path().join("real")).expect("mkdir real");
        fs::write(&real, "[package]\n").expect("write real manifest");
        std::os::unix::fs::symlink(&real, dir.path().join("Cargo.toml")).expect("create symlink");

        let disabled = walk(&[dir.path().to_path_buf()], &test_registry(), false, false);
        assert!(disabled.manifests.is_empty());
        assert_eq!(
            disabled.ignored_manifests,
            vec![PathBuf::from("Cargo.toml")]
        );

        let enabled = walk(&[dir.path().to_path_buf()], &test_registry(), false, true);
        assert_eq!(enabled.manifests.len(), 1);
        assert!(enabled.ignored_manifests.is_empty());
    }

    /// FR-007: `display_path` reflects the symlink's own encountered path, not the resolved
    /// target's real path.
    #[cfg(unix)]
    #[test]
    fn test_walk_follow_symlinks_display_path_is_symlink_path_not_target() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let real = dir.path().join("real").join("manifest-data");
        fs::create_dir(dir.path().join("real")).expect("mkdir real");
        fs::write(&real, "[package]\n").expect("write real manifest");
        std::os::unix::fs::symlink(&real, dir.path().join("Cargo.toml")).expect("create symlink");

        let outcome = walk(&[dir.path().to_path_buf()], &test_registry(), false, true);

        assert_eq!(outcome.manifests.len(), 1);
        assert_eq!(
            outcome.manifests[0].display_path,
            PathBuf::from("Cargo.toml")
        );
    }

    /// FR-006: `follow_symlinks: true` does not defeat `PRUNED_DIRECTORIES` pruning, even when
    /// the manifest inside the pruned directory is itself reachable through a symlink.
    #[cfg(unix)]
    #[test]
    fn test_walk_follow_symlinks_still_prunes_node_modules() {
        let dir = tempfile::tempdir().expect("create temp dir");
        fs::write(dir.path().join("Cargo.toml"), "[package]\n").expect("write manifest");
        let real_vendored = dir.path().join("real-vendored-manifest");
        fs::write(&real_vendored, "{}").expect("write real vendored manifest");
        fs::create_dir_all(dir.path().join("node_modules").join("left-pad"))
            .expect("mkdir node_modules/left-pad");
        std::os::unix::fs::symlink(
            &real_vendored,
            dir.path()
                .join("node_modules")
                .join("left-pad")
                .join("package.json"),
        )
        .expect("symlink vendored manifest inside pruned directory");

        let outcome = walk(&[dir.path().to_path_buf()], &test_registry(), false, true);

        assert_eq!(
            outcome.manifests.len(),
            1,
            "a symlinked manifest inside a pruned directory must still be pruned, not routed"
        );
        assert_eq!(
            outcome.manifests[0].display_path,
            PathBuf::from("Cargo.toml")
        );
    }

    /// FR-006: `follow_symlinks: true` still respects `walk_with_limit`'s cap when a symlinked
    /// directory inflates the number of entries the walk must visit.
    #[cfg(unix)]
    #[test]
    fn test_walk_follow_symlinks_still_enforces_max_walked_files() {
        let dir = tempfile::tempdir().expect("create temp dir");
        // Review finding M4: the noise source is a *hidden* (dot-prefixed) directory, so the
        // default `hidden(true)` filter excludes it from ever being walked directly by its own
        // name — the only way to reach its 5 files is by following `noise-link`, making the
        // symlink genuinely load-bearing for this test. `limit` is chosen to comfortably cover
        // the baseline tree (walk root + `Cargo.toml` + the `noise-link` entry itself = 3
        // entries, `.noise-source` never yielded at all) but not baseline-plus-5-noise-files —
        // with `follow_symlinks: false` this same fixture and limit does *not* truncate,
        // proving the symlink (not just the raw entry count) is what pushes the walk over.
        let noise_target = dir.path().join(".noise-source");
        fs::create_dir(&noise_target).expect("mkdir .noise-source");
        for i in 0..5 {
            fs::write(noise_target.join(format!("noise-{i}.txt")), "").expect("write noise file");
        }
        std::os::unix::fs::symlink(&noise_target, dir.path().join("noise-link"))
            .expect("symlink noise directory");
        fs::write(dir.path().join("Cargo.toml"), "[package]\n").expect("write manifest");

        let outcome = walk_with_limit(
            &[dir.path().to_path_buf()],
            &test_registry(),
            4,
            false,
            true,
        );
        assert!(
            outcome.truncated,
            "a 4-entry limit against a tree inflated by a symlinked directory must truncate"
        );
    }

    /// FR-004, US-003: a symlink inside the walked root pointing to a manifest-shaped file
    /// *outside* the walked root is never routed, even with `follow_symlinks: true`.
    #[cfg(unix)]
    #[test]
    fn test_walk_follow_symlinks_rejects_target_outside_root() {
        let outside = tempfile::tempdir().expect("create outside temp dir");
        let outside_manifest = outside.path().join("Cargo.toml");
        fs::write(&outside_manifest, "[package]\n").expect("write outside manifest");

        let root = tempfile::tempdir().expect("create walked root");
        std::os::unix::fs::symlink(&outside_manifest, root.path().join("Cargo.toml"))
            .expect("create symlink escaping the walked root");

        let outcome = walk(&[root.path().to_path_buf()], &test_registry(), false, true);

        assert!(
            outcome.manifests.is_empty(),
            "must never route a symlink target outside the walked root"
        );
        assert_eq!(outcome.ignored_manifests, vec![PathBuf::from("Cargo.toml")]);
    }

    /// FR-005, US-003: a symlink loop must not hang or crash the walk; it is reported via
    /// `walk_errors` and the run's other manifests are still found.
    #[cfg(unix)]
    #[test]
    fn test_walk_follow_symlinks_reports_symlink_loop_via_walk_errors() {
        let dir = tempfile::tempdir().expect("create temp dir");
        fs::create_dir_all(dir.path().join("a")).expect("mkdir a");
        fs::create_dir_all(dir.path().join("b")).expect("mkdir b");
        std::os::unix::fs::symlink(dir.path().join("b"), dir.path().join("a").join("loop"))
            .expect("create a/loop -> b");
        std::os::unix::fs::symlink(dir.path().join("a"), dir.path().join("b").join("loop"))
            .expect("create b/loop -> a");
        fs::write(dir.path().join("Cargo.toml"), "[package]\n").expect("write manifest");

        let outcome = walk(&[dir.path().to_path_buf()], &test_registry(), false, true);

        assert!(
            outcome
                .walk_errors
                .iter()
                .any(|error| error.to_lowercase().contains("loop")),
            "a symlink loop must be reported via walk_errors naming the loop, not just any \
             error, and must not hang or crash: {:?}",
            outcome.walk_errors
        );
        assert!(
            outcome
                .manifests
                .iter()
                .any(|m| m.display_path == Path::new("Cargo.toml")),
            "other manifests in the same tree must still be found"
        );
    }

    /// Spec §6 edge case: `--follow-symlinks` and `--respect-gitignore` are independent flags —
    /// a symlinked manifest excluded by `.gitignore` is still reported via the existing
    /// `.gitignore`-suppression path once resolved, exactly as a non-symlinked manifest would
    /// be, rather than `follow_symlinks` bypassing the ignore rule.
    #[cfg(unix)]
    #[test]
    fn test_walk_follow_symlinks_and_respect_gitignore_together_still_honors_gitignore() {
        let dir = tempfile::tempdir().expect("create temp dir");
        fs::create_dir(dir.path().join(".git")).expect("create .git marker");
        fs::write(dir.path().join(".gitignore"), "Cargo.toml\n").expect("write gitignore");
        let real = dir.path().join("real").join("manifest-data");
        fs::create_dir(dir.path().join("real")).expect("mkdir real");
        fs::write(&real, "[package]\n").expect("write real manifest");
        std::os::unix::fs::symlink(&real, dir.path().join("Cargo.toml")).expect("create symlink");

        let outcome = walk(&[dir.path().to_path_buf()], &test_registry(), true, true);

        assert!(
            outcome.manifests.is_empty(),
            "a .gitignore-excluded symlinked manifest must not be routed even under \
             --follow-symlinks"
        );
        assert_eq!(outcome.ignored_manifests, vec![PathBuf::from("Cargo.toml")]);
    }

    /// Critic finding C1 regression: a symlinked *directory* (not a symlinked leaf file) must
    /// not let `--follow-symlinks` escape the walked root — the leaf entry inside it
    /// (`evil/Cargo.toml`) is not itself a symlink, so a containment check keyed only on
    /// `path_is_symlink()` would miss it.
    #[cfg(unix)]
    #[test]
    fn test_walk_follow_symlinks_rejects_directory_symlink_escaping_root() {
        let outside = tempfile::tempdir().expect("create outside temp dir");
        fs::write(outside.path().join("Cargo.toml"), "[package]\n")
            .expect("write outside manifest");

        let root = tempfile::tempdir().expect("create walked root");
        fs::write(root.path().join("Cargo.toml"), "[package]\n").expect("write root manifest");
        std::os::unix::fs::symlink(outside.path(), root.path().join("evil"))
            .expect("symlink a directory escaping the walked root");

        let outcome = walk(&[root.path().to_path_buf()], &test_registry(), false, true);

        assert!(
            outcome
                .manifests
                .iter()
                .all(|m| m.display_path != PathBuf::from("evil").join("Cargo.toml")),
            "a manifest reached only by descending into a symlinked directory outside the \
             walked root must never be routed: {:?}",
            outcome
                .manifests
                .iter()
                .map(|m| &m.display_path)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            outcome.manifests.len(),
            1,
            "the root's own, non-escaping Cargo.toml must still be found"
        );
    }

    /// Background code-review finding #2: an escaping symlinked directory must be pruned
    /// *before* `ignore`/`walkdir` descends into it, not walked entry-by-entry and rejected
    /// individually — otherwise a large external tree behind the symlink can exhaust
    /// `MAX_WALKED_FILES` on content outside the walked root, silently truncating the walk and
    /// dropping legitimate manifests elsewhere in the real tree (the exact #1112 fail-open
    /// class, reopened through this fix's own flag). Proven by pointing the escaping symlink at
    /// a directory with far more entries than a deliberately tiny `limit`, and asserting the
    /// walk still finds the root's own manifest without truncating.
    #[cfg(unix)]
    #[test]
    fn test_walk_follow_symlinks_escaping_directory_does_not_exhaust_the_budget() {
        let outside = tempfile::tempdir().expect("create outside temp dir");
        for i in 0..50 {
            fs::write(outside.path().join(format!("noise-{i}.txt")), "")
                .expect("write outside noise file");
        }

        let root = tempfile::tempdir().expect("create walked root");
        fs::write(root.path().join("Cargo.toml"), "[package]\n").expect("write root manifest");
        std::os::unix::fs::symlink(outside.path(), root.path().join("evil"))
            .expect("symlink a directory escaping the walked root");

        // Comfortably covers the walked root's own 2 entries (root dir + Cargo.toml) plus the
        // pruned `evil` entry itself, but is far smaller than the 50 files behind it — if the
        // escaping directory were walked instead of pruned, this would truncate long before
        // `Cargo.toml` is guaranteed to be counted.
        let outcome = walk_with_limit(
            &[root.path().to_path_buf()],
            &test_registry(),
            5,
            false,
            true,
        );

        assert!(
            !outcome.truncated,
            "pruning the escaping directory before descent must keep the walk well under the \
             budget, not exhaust it on external content"
        );
        assert_eq!(
            outcome.manifests.len(),
            1,
            "the root's own manifest must still be found"
        );
    }

    /// Background code-review finding #1: a symlinked manifest that is not itself
    /// `.gitignore`-excluded must be reported exactly once in `ignored_manifests`, not twice.
    /// Root cause was the primary walk's symlink-detection arm never inserting into `visited`
    /// (only the `is_file()` arm did), so `detect_ignored_manifests`'s separate unfiltered walk
    /// (run because `respect_gitignore` is true) found the same symlink again and double-counted
    /// it.
    #[cfg(unix)]
    #[test]
    fn test_walk_respect_gitignore_does_not_duplicate_symlinked_manifest_warning() {
        let dir = tempfile::tempdir().expect("create temp dir");
        fs::create_dir(dir.path().join(".git")).expect("create .git marker");
        // Present but irrelevant to this symlink — proves the duplication wasn't specific to
        // an empty .gitignore file being absent.
        fs::write(dir.path().join(".gitignore"), "*.log\n").expect("write gitignore");
        let real = dir.path().join("real").join("manifest-data");
        fs::create_dir(dir.path().join("real")).expect("mkdir real");
        fs::write(&real, "[package]\n").expect("write real manifest");
        std::os::unix::fs::symlink(&real, dir.path().join("Cargo.toml")).expect("create symlink");

        let outcome = walk(&[dir.path().to_path_buf()], &test_registry(), true, false);

        assert_eq!(
            outcome.ignored_manifests,
            vec![PathBuf::from("Cargo.toml")],
            "a non-gitignored symlinked manifest must be reported exactly once"
        );
    }

    /// Critic finding S1 regression: a registered ecosystem's own hidden dot-directory (e.g.
    /// `.github`) escaping the walked root via a symlink must not be scanned, regardless of
    /// `follow_symlinks` — `ignore`/`walkdir` always follows a walk's own root symlink, so this
    /// containment check must apply in the default mode too.
    #[cfg(unix)]
    #[test]
    fn test_walk_default_rejects_symlinked_hidden_ecosystem_directory_escaping_root() {
        let outside = tempfile::tempdir().expect("create outside temp dir");
        fs::create_dir_all(outside.path().join("workflows")).expect("mkdir workflows");
        fs::write(
            outside.path().join("workflows").join("ci.yml"),
            "on: push\njobs:\n  x:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n",
        )
        .expect("write workflow");

        let root = tempfile::tempdir().expect("create walked root");
        std::os::unix::fs::symlink(outside.path(), root.path().join(".github"))
            .expect("symlink .github escaping the walked root");

        let outcome = walk(&[root.path().to_path_buf()], &test_registry(), false, false);

        assert!(
            outcome.manifests.is_empty(),
            "a symlinked .github escaping the walked root must never be scanned, even in the \
             default mode: {:?}",
            outcome
                .manifests
                .iter()
                .map(|m| &m.display_path)
                .collect::<Vec<_>>()
        );
    }
}
