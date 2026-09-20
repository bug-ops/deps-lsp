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
    /// exclusion — either an ignore rule while [`GitignorePolicy::Respect`] was in effect
    /// (issue #1109),
    /// or a `PRUNED_DIRECTORIES` match in *any* mode (reviewer follow-up: an unusual monorepo
    /// layout can have a real subproject's manifest sitting directly inside a directory named
    /// `vendor`/`build`/`dist`/...). Unlike
    /// [`unrecognized_explicit_paths`](Self::unrecognized_explicit_paths), this is a warning
    /// about data loss (a real manifest silently skipped), not a benign non-match.
    pub ignored_manifests: Vec<PathBuf>,
    /// A manifest-shaped symlink whose target is not a manifest — unresolvable (dangling,
    /// broken chain, unreadable) or resolves to a non-regular-file (issue #1124). Distinct from
    /// [`ignored_manifests`](Self::ignored_manifests): that means "a real file existed and we
    /// chose not to read it" (unfollowed symlink, `.gitignore`, pruned directory); this means
    /// the manifest-shaped path produced no manifest at all, a stronger tampering signal.
    /// Reported regardless of `--follow-symlinks`/`--respect-gitignore`, except a structural
    /// ancestor loop under `--follow-symlinks`, which surfaces via `walk_errors` instead (still
    /// a non-zero exit, just a generic message rather than this specific one).
    pub broken_manifest_symlinks: Vec<PathBuf>,
}

/// Whether `.gitignore`/`.ignore` rules exclude manifests from the walk (issue #1109).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GitignorePolicy {
    /// `.gitignore`/`.ignore` are consulted, matching `git`'s own behavior.
    Respect,
    /// `.gitignore`/`.ignore` are never consulted.
    Ignore,
}

/// Whether symlinked manifests and directories are resolved and walked into (issue #1112).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymlinkPolicy {
    /// Symlinks are resolved and walked into.
    Follow,
    /// Symlinks are detected but never resolved or descended into.
    Skip,
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
/// **`gitignore_policy` (issue #1109)**: when [`GitignorePolicy::Ignore`] (the `check`
/// subcommand's default — see [`crate::cli::CheckArgs::gitignore_policy`]), `.gitignore` and
/// `.ignore` files are never consulted, because in a CI security-gate invocation (`git
/// checkout && deps-cli check .` against an untrusted fork PR) both are attacker-controlled
/// input: a one-line addition anywhere in the tree would otherwise silently remove a manifest
/// from the scan. `.git` itself is still never descended into (that is `hidden`-filtering, an
/// unrelated concern — see above), and `.git/info/exclude` / the user's global gitignore are
/// always honored regardless of this policy, since neither travels with a cloned/fetched PR and
/// both are operator-, not attacker-, controlled. When [`GitignorePolicy::Respect`], standard
/// `.gitignore`/`.ignore` awareness is restored (matching `git`'s own behavior), and any
/// manifest-shaped file that awareness excludes is additionally reported via
/// [`WalkOutcome::ignored_manifests`]. The internal `PRUNED_DIRECTORIES` denylist is applied
/// regardless of `gitignore_policy` — it is compiled into the binary, not attacker-controlled
/// input, so pruning `node_modules`/`target`/`vendor`/... does not reopen the fail-open gap
/// this policy closes. A manifest sitting directly at the root of a pruned directory (an
/// unusual but real monorepo layout, e.g. a genuine subproject named `vendor`) is still
/// reported via [`WalkOutcome::ignored_manifests`] in every mode, so pruning stays visible
/// rather than a second, narrower silent-omission bug.
///
/// One asymmetry is deliberate rather than accidental: in the default
/// ([`GitignorePolicy::Ignore`]) mode, a manifest excluded only by the always-on
/// `.git/info/exclude` or global gitignore is never diffed against (that costly double-walk
/// only runs under [`GitignorePolicy::Respect`]), so such a suppression is silent beyond
/// [`WalkOutcome::manifests`] coming back emptier than expected — acceptable because both
/// sources are operator-, not attacker-, controlled (see above).
///
/// **`symlink_policy` (issue #1112)**: a directory entry that is itself a symlink to a
/// manifest-shaped file is always detected, regardless of this policy — its path is reported
/// via [`WalkOutcome::ignored_manifests`], the same sink a pruned or `.gitignore`-excluded
/// manifest already uses, so a symlinked manifest can never silently vanish from the report.
/// Detection alone never reads the target's content. When `symlink_policy` is
/// [`SymlinkPolicy::Follow`], such a symlink is additionally resolved and routed like any other
/// manifest (appearing in [`WalkOutcome::manifests`] instead, with [`DiscoveredManifest::path`]
/// set to the resolved real path used for reading and [`DiscoveredManifest::display_path`] kept
/// as the symlink's own encountered path). Every routed entry under [`SymlinkPolicy::Follow`] —
/// not only ones where the leaf itself is a symlink, since an entry reached by descending into
/// a followed symlinked *directory* is otherwise indistinguishable from an ordinary one — is
/// canonicalized and checked against the walked root's own canonicalized absolute path; an
/// entry that resolves outside the root is never routed, and is reported via
/// `ignored_manifests` only when it is itself manifest-shaped (an arbitrary out-of-root symlink
/// to a non-manifest file is silently skipped, matching detection's own never-warn-on-non-manifests
/// invariant). This containment check applies to every registered ecosystem's own dot-directory
/// sub-root (e.g. `.github`) too, and — because `ignore`/`walkdir` always follows a walk's own
/// *root* symlink regardless of `follow_links` — that sub-root containment check runs in every
/// mode, not only under [`SymlinkPolicy::Follow`]. A symlink loop is detected by the underlying
/// `ignore` crate and surfaced via [`WalkOutcome::walk_errors`].
///
/// **Broken symlinks (issue #1124)**: a symlink whose target is not a manifest (unresolvable,
/// or a non-regular-file such as a directory) is classified by its own filename, not its
/// target, and reported via [`WalkOutcome::broken_manifest_symlinks`] instead of
/// `ignored_manifests` — unconditional across every mode, same as the resolvable case, except a
/// structural ancestor loop under `--follow-symlinks`, which reports via `walk_errors` instead.
#[must_use]
pub fn walk(
    roots: &[PathBuf],
    registry: &EcosystemRegistry,
    gitignore_policy: GitignorePolicy,
    symlink_policy: SymlinkPolicy,
) -> WalkOutcome {
    walk_with_limit(
        roots,
        registry,
        MAX_WALKED_FILES,
        gitignore_policy,
        symlink_policy,
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
    gitignore_policy: GitignorePolicy,
    symlink_policy: SymlinkPolicy,
) -> WalkOutcome {
    let mut ctx = WalkCtx {
        registry,
        limit,
        entries_walked: 0,
        outcome: WalkOutcome::default(),
    };
    let hidden_ecosystem_dirs = hidden_ecosystem_directories(registry);
    let options = WalkOptions {
        respect_gitignore: matches!(gitignore_policy, GitignorePolicy::Respect),
        follow_symlinks: matches!(symlink_policy, SymlinkPolicy::Follow),
    };

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

        // Short-circuit a broken/non-file-target manifest-shaped symlink root via the same
        // `classify_symlink` the walk uses, so it can't both fall through as a directory walk
        // and get independently re-flagged as `Broken` at the root entry (S1/S3 contradiction).
        if is_symlink(root) {
            let sink = match classify_symlink(&absolute_root, registry) {
                SymlinkClassification::Broken => Some(&mut ctx.outcome.broken_manifest_symlinks),
                SymlinkClassification::Irrelevant if std::fs::metadata(root).is_err() => {
                    Some(&mut ctx.outcome.unrecognized_explicit_paths)
                }
                SymlinkClassification::Resolvable | SymlinkClassification::Irrelevant => None,
            };
            if let Some(sink) = sink {
                if ctx.entries_walked >= ctx.limit {
                    ctx.outcome.truncated = true;
                    tracing::warn!(
                        limit,
                        "walk truncated: reached the maximum number of entries per run"
                    );
                    break;
                }
                ctx.entries_walked += 1;
                sink.push(root.clone());
                continue;
            }
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
            DotDirs::Skip,
            options,
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
                DotDirs::Descend,
                options,
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

/// The `respect_gitignore`/`follow_symlinks` pair, bundled so the internal walk chain (issue
/// #1135) threads one named value instead of two positional bools whose order a call site can
/// silently transpose.
#[derive(Clone, Copy)]
struct WalkOptions {
    respect_gitignore: bool,
    follow_symlinks: bool,
}

/// Whether a walk skips or descends into dot-prefixed entries — replaces `walk_directory`'s
/// former positional `hidden: bool` parameter (issue #1135), whose meaning is the inverse of
/// what a reader expects: `ignore::WalkBuilder::hidden(true)` means "skip hidden entries".
#[derive(Clone, Copy)]
enum DotDirs {
    /// Dot-prefixed entries are filtered out of the walk.
    Skip,
    /// Dot-prefixed entries are walked normally.
    Descend,
}

impl DotDirs {
    /// The `ignore::WalkBuilder::hidden` argument this variant corresponds to — the single
    /// point where `DotDirs` is converted back to the crate's own inverted-bool convention.
    fn skip_hidden(self) -> bool {
        matches!(self, Self::Skip)
    }
}

/// Walks `walk_root` (a directory), routing every regular file relative to `display_root` —
/// the outer `root` [`walk_with_limit`] was given, so a file under a dot-directory sub-root
/// (e.g. `<repo>/.github`) still displays relative to the repository root, not to `.github`
/// itself. Returns `false` once `limit` is reached (the caller must stop the whole walk, not
/// just this directory); `true` otherwise.
fn walk_directory(
    walk_root: &Path,
    display_root: &Path,
    dot_dirs: DotDirs,
    options: WalkOptions,
    canonical_root: Option<&Path>,
    ctx: &mut WalkCtx<'_>,
) -> bool {
    // `.gitignore`/`.ignore` toggle by `respect_gitignore` (issue #1109) — both are
    // attacker-controlled in a CI scan of untrusted input. `git_exclude` (`.git/info/exclude`)
    // and `git_global` (the user's global gitignore) stay on unconditionally: neither travels
    // with a cloned/fetched PR, so neither is part of the attack surface this flag closes.
    let hidden = dot_dirs.skip_hidden();
    let pruned_dirs: Arc<Mutex<Vec<PathBuf>>> = Arc::new(Mutex::new(Vec::new()));
    let mut builder = WalkBuilder::new(walk_root);
    builder
        .hidden(hidden)
        .parents(true)
        .ignore(options.respect_gitignore)
        .git_ignore(options.respect_gitignore)
        .git_global(true)
        .git_exclude(true)
        .follow_links(options.follow_symlinks);
    {
        let pruned_dirs = Arc::clone(&pruned_dirs);
        let canonical_root_owned = canonical_root.map(Path::to_path_buf);
        let follow_symlinks = options.follow_symlinks;
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
                let display = display_relative_path(path, display_root);
                if options.respect_gitignore {
                    visited.insert(display.clone());
                }
                if options.follow_symlinks {
                    // FR-004/FR-007 (critic C1): canonicalize+containment-check every entry,
                    // not only leaf symlinks — a followed symlinked *directory* ancestor needs
                    // the same check. Resolved path doubles as the real read path (FR-007).
                    match canonicalize_within_root(path, canonical_root) {
                        Some(canonical_path) => {
                            route_file(
                                path,
                                &canonical_path,
                                &display,
                                ctx.registry,
                                &mut ctx.outcome,
                            );
                        }
                        // S4: reachable only via a rare TOCTOU race (metadata failed here after
                        // `is_file()` succeeded above); routed like any other unresolvable path.
                        None => {
                            classify_symlink(path, ctx.registry).record(&mut ctx.outcome, display);
                        }
                    }
                } else {
                    route_file(path, path, &display, ctx.registry, &mut ctx.outcome);
                }
            }
            // #1112/#1124: `file_type()` reports the symlink's own (unresolved) type under
            // `follow_symlinks: false`, or `None` under `follow_symlinks: true` when the
            // target can't be stat'd (a broken symlink) — either way this arm, not the one
            // above, is where detection happens.
            Ok(entry) => {
                if entry.path_is_symlink() {
                    let path = entry.path();
                    let classification = classify_symlink(path, ctx.registry);
                    if !matches!(classification, SymlinkClassification::Irrelevant) {
                        let display = display_relative_path(path, display_root);
                        // Mirrors the `is_file()` arm's `visited` insert — otherwise
                        // `detect_ignored_manifests`'s separate unfiltered walk double-reports.
                        if options.respect_gitignore {
                            visited.insert(display.clone());
                        }
                        classification.record(&mut ctx.outcome, display);
                    }
                }
            }
            Err(error) => {
                // #1124: under `follow_symlinks: true`, a broken symlink surfaces as an `Err`
                // (walkdir must stat to resolve type) instead of the arm above. `is_io()`
                // excludes a structurally different error sharing this path-carrying variant
                // (e.g. a symlink `Loop`); `is_symlink` (S2) excludes a non-symlink permission
                // error from being misreported as tampering.
                let classified_as_broken = if let ignore::Error::WithPath { path, err } = &error
                    && err.is_io()
                    && is_symlink(path)
                    && is_manifest_shaped_by_name(path, ctx.registry)
                {
                    let display = display_relative_path(path, display_root);
                    if options.respect_gitignore {
                        visited.insert(display.clone());
                    }
                    ctx.outcome.broken_manifest_symlinks.push(display);
                    true
                } else {
                    false
                };
                // Bug 3 (background review): don't also emit the generic IO error once the
                // specific broken-manifest warning already covers this path.
                if !classified_as_broken {
                    ctx.outcome.walk_errors.push(error.to_string());
                }
            }
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

    if options.respect_gitignore {
        detect_ignored_manifests(walk_root, display_root, hidden, ctx, &visited);
    }
    true
}

/// Checks a directory [`is_not_pruned_directory`] excluded (its basename matched
/// [`PRUNED_DIRECTORIES`]) for a manifest sitting directly at its own root, and records any
/// found onto [`WalkOutcome::ignored_manifests`] or [`WalkOutcome::broken_manifest_symlinks`]
/// (reviewer follow-up on issue #1109's pruning fix, extended for #1124: an unusual monorepo
/// layout can have a *real* subproject's manifest — or a manifest-shaped, possibly broken,
/// symlink — directly inside a directory named `vendor`/`build`/`dist`/...).
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
        let display = display_relative_path(&path, display_root);
        classify_symlink(&path, ctx.registry).record(&mut ctx.outcome, display);
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
            // #1112/M5/#1124: a gitignored symlinked (possibly broken) manifest never appears
            // in the primary filtered walk at all, so this unfiltered pass is the only place
            // that still sees it under `--respect-gitignore`.
            let path = entry.path();
            if entry.path_is_symlink() {
                let display = display_relative_path(path, display_root);
                if !visited.contains(&display) {
                    classify_symlink(path, ctx.registry).record(&mut ctx.outcome, display);
                }
            }
            continue;
        }
        let path = entry.path();
        let display = display_relative_path(path, display_root);
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

/// The result of [`classify_symlink`] (issue #1124).
enum SymlinkClassification {
    /// Target resolved to a manifest-shaped regular file — not followed by choice, or resolved
    /// but excluded for another reason (e.g. it falls outside the walked root, FR-004).
    Resolvable,
    /// Manifest-shaped by name, but the target is not a manifest: unresolvable (dangling,
    /// broken chain hop, unreadable), or resolves to a non-regular-file (directory, fifo,
    /// socket, ...) — the latter is just as much a substitute for the real manifest as a
    /// dangling target, so it is not treated as safe merely because it "resolves".
    Broken,
    /// Not manifest-shaped by name — never worth a warning.
    Irrelevant,
}

impl SymlinkClassification {
    /// Routes `display` to the matching `outcome` sink (no-op for `Irrelevant`) — the one place
    /// this Resolvable/Broken/Irrelevant → push/push/noop mapping lives.
    fn record(self, outcome: &mut WalkOutcome, display: PathBuf) {
        match self {
            Self::Resolvable => outcome.ignored_manifests.push(display),
            Self::Broken => outcome.broken_manifest_symlinks.push(display),
            Self::Irrelevant => {}
        }
    }
}

/// Classifies `path` without reading its content — gates `Broken` on `path` actually being a
/// symlink (lstat), not merely non-regular-file, so an ordinary permission-denied directory or
/// file that happens to share a manifest's name is never misreported as tampering.
fn classify_symlink(path: &Path, registry: &EcosystemRegistry) -> SymlinkClassification {
    if !is_manifest_shaped_by_name(path, registry) {
        return SymlinkClassification::Irrelevant;
    }
    match std::fs::metadata(path) {
        Ok(metadata) if metadata.is_file() => SymlinkClassification::Resolvable,
        _ if is_symlink(path) => SymlinkClassification::Broken,
        _ => SymlinkClassification::Irrelevant,
    }
}

/// `symlink_metadata` (lstat, never follows) reporting `path` itself as a symlink — succeeds
/// even for a dangling target, unlike [`std::fs::metadata`]/`Path::is_file`.
fn is_symlink(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_symlink())
}

/// `path` relative to `display_root`; falls back to `path` itself when `strip_prefix` fails or
/// succeeds empty (the latter whenever `path == display_root`, e.g. an explicitly-given root).
fn display_relative_path(path: &Path, display_root: &Path) -> PathBuf {
    let stripped = path.strip_prefix(display_root).unwrap_or(path);
    if stripped.as_os_str().is_empty() {
        path.to_path_buf()
    } else {
        stripped.to_path_buf()
    }
}

/// `EcosystemRegistry::for_uri` on `path`'s own name, never on a resolved target.
fn is_manifest_shaped_by_name(path: &Path, registry: &EcosystemRegistry) -> bool {
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
        let outcome = walk(
            &[dir.path().to_path_buf()],
            &test_registry(),
            GitignorePolicy::Ignore,
            SymlinkPolicy::Skip,
        );
        assert!(outcome.manifests.is_empty());
        assert!(!outcome.truncated);
    }

    #[test]
    fn test_walk_finds_cargo_toml() {
        let dir = tempfile::tempdir().expect("create temp dir");
        fs::write(dir.path().join("Cargo.toml"), "[package]\nname = \"x\"\n")
            .expect("write manifest");
        let outcome = walk(
            &[dir.path().to_path_buf()],
            &test_registry(),
            GitignorePolicy::Ignore,
            SymlinkPolicy::Skip,
        );
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
        let outcome = walk(
            &[dir.path().to_path_buf()],
            &test_registry(),
            GitignorePolicy::Respect,
            SymlinkPolicy::Skip,
        );
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
        let outcome = walk(
            &[dir.path().to_path_buf()],
            &test_registry(),
            GitignorePolicy::Ignore,
            SymlinkPolicy::Skip,
        );
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
        let outcome = walk(
            &[dir.path().to_path_buf()],
            &test_registry(),
            GitignorePolicy::Ignore,
            SymlinkPolicy::Skip,
        );
        assert_eq!(outcome.manifests.len(), 1);
    }

    /// Issue #1109 repro 3: an `.ignore` file (no `.git` directory at all) must not suppress a
    /// manifest under the default behavior.
    #[test]
    fn test_walk_default_ignores_dot_ignore_file_without_git_repo() {
        let dir = tempfile::tempdir().expect("create temp dir");
        fs::write(dir.path().join(".ignore"), "Cargo.toml\n").expect("write .ignore");
        fs::write(dir.path().join("Cargo.toml"), "[package]\n").expect("write manifest");
        let outcome = walk(
            &[dir.path().to_path_buf()],
            &test_registry(),
            GitignorePolicy::Ignore,
            SymlinkPolicy::Skip,
        );
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

        let outcome = walk(
            &[dir.path().to_path_buf()],
            &test_registry(),
            GitignorePolicy::Ignore,
            SymlinkPolicy::Skip,
        );

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

        let outcome = walk(
            &[dir.path().to_path_buf()],
            &test_registry(),
            GitignorePolicy::Ignore,
            SymlinkPolicy::Skip,
        );

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

        let outcome = walk(
            &[dir.path().to_path_buf()],
            &test_registry(),
            GitignorePolicy::Ignore,
            SymlinkPolicy::Skip,
        );

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
            GitignorePolicy::Respect,
            SymlinkPolicy::Skip,
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

        let outcome = walk(
            &[dir.path().to_path_buf()],
            &test_registry(),
            GitignorePolicy::Respect,
            SymlinkPolicy::Skip,
        );

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

        let outcome = walk(
            &[dir.path().to_path_buf()],
            &test_registry(),
            GitignorePolicy::Respect,
            SymlinkPolicy::Skip,
        );

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
        let outcome = walk(
            &[manifest],
            &test_registry(),
            GitignorePolicy::Respect,
            SymlinkPolicy::Skip,
        );
        assert_eq!(outcome.manifests.len(), 1);
    }

    /// Critic finding S3: issue #1124's own repro command shape is `deps-cli check
    /// path/to/Cargo.toml` where that path is itself a broken symlink — the natural
    /// single-manifest CI-gate invocation. Before the fix, `root.is_file()` (which follows
    /// symlinks and so is `false` here) let this fall into the directory-walk branch with
    /// `walk_root == display_root == root`, producing an empty `display_path` once
    /// `strip_prefix` trivially succeeded against itself. Must report the manifest's own given
    /// path, not an empty one.
    #[cfg(unix)]
    #[test]
    fn test_walk_explicit_broken_symlink_manifest_path_reports_the_given_path() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let manifest = dir.path().join("Cargo.toml");
        std::os::unix::fs::symlink(dir.path().join("does-not-exist"), &manifest)
            .expect("create broken symlink");

        let outcome = walk(
            std::slice::from_ref(&manifest),
            &test_registry(),
            GitignorePolicy::Ignore,
            SymlinkPolicy::Skip,
        );

        assert!(outcome.manifests.is_empty());
        assert!(outcome.ignored_manifests.is_empty());
        assert!(outcome.unrecognized_explicit_paths.is_empty());
        assert_eq!(outcome.broken_manifest_symlinks, vec![manifest]);
    }

    /// Companion to the above: an explicit root that is a symlink to a real *directory* must
    /// still be walked as a directory (existing, legitimate use), not intercepted by S3's fix —
    /// only a symlink whose target fails to resolve at all is a broken-manifest candidate.
    #[cfg(unix)]
    #[test]
    fn test_walk_explicit_symlink_to_directory_root_is_still_walked() {
        let real_dir = tempfile::tempdir().expect("create real dir");
        fs::write(real_dir.path().join("Cargo.toml"), "[package]\n").expect("write manifest");

        let link_parent = tempfile::tempdir().expect("create link parent");
        let link = link_parent.path().join("link-to-real");
        std::os::unix::fs::symlink(real_dir.path(), &link)
            .expect("create symlink to a real directory");

        let outcome = walk(
            std::slice::from_ref(&link),
            &test_registry(),
            GitignorePolicy::Ignore,
            SymlinkPolicy::Skip,
        );

        assert_eq!(outcome.manifests.len(), 1);
        assert!(outcome.broken_manifest_symlinks.is_empty());
    }

    /// Critic S4 + background-review Bug 1: a manifest-shaped symlink resolving to an existing
    /// *directory*, passed as an explicit root (`deps-cli check tree/Cargo.toml`), must be
    /// reported with a non-empty path — and, critically, must NOT also be walked as a
    /// directory: `real_dir` contains a real, findable manifest, so if the old fallthrough
    /// behavior regressed, `manifests` would be non-empty here at the same time
    /// `broken_manifest_symlinks` is populated — a self-contradictory report (found earlier by
    /// background code review: S1's widened policy and S3's directory-walk fallthrough used to
    /// fire simultaneously for this exact path).
    #[cfg(unix)]
    #[test]
    fn test_walk_explicit_manifest_shaped_symlink_to_directory_root_reports_a_non_empty_path() {
        let real_dir = tempfile::tempdir().expect("create real dir");
        fs::write(real_dir.path().join("package.json"), "{}").expect("write real manifest");

        let link_parent = tempfile::tempdir().expect("create link parent");
        let link = link_parent.path().join("Cargo.toml");
        std::os::unix::fs::symlink(real_dir.path(), &link)
            .expect("create manifest-shaped symlink to a real directory");

        let outcome = walk(
            std::slice::from_ref(&link),
            &test_registry(),
            GitignorePolicy::Ignore,
            SymlinkPolicy::Skip,
        );

        assert!(
            outcome.manifests.is_empty(),
            "must not also walk the target directory's contents: {:?}",
            outcome
                .manifests
                .iter()
                .map(|m| &m.display_path)
                .collect::<Vec<_>>()
        );
        assert!(outcome.ignored_manifests.is_empty());
        assert_eq!(outcome.broken_manifest_symlinks.len(), 1);
        assert!(
            !outcome.broken_manifest_symlinks[0].as_os_str().is_empty(),
            "must never report an empty display path"
        );
        assert_eq!(
            outcome.broken_manifest_symlinks[0].file_name(),
            Some(std::ffi::OsStr::new("Cargo.toml")),
            "reported path must still name the manifest: {:?}",
            outcome.broken_manifest_symlinks
        );
    }

    /// Explicit root that is a broken symlink whose own name is *not* manifest-shaped must be
    /// reported as unrecognized, not as tampering — mirrors the never-warn-on-non-manifests
    /// invariant `classify_symlink` already applies to a discovered (non-root) entry.
    #[cfg(unix)]
    #[test]
    fn test_walk_explicit_broken_symlink_non_manifest_path_is_unrecognized() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let notes = dir.path().join("notes.txt");
        std::os::unix::fs::symlink(dir.path().join("does-not-exist"), &notes)
            .expect("create broken, non-manifest-shaped symlink");

        let outcome = walk(
            std::slice::from_ref(&notes),
            &test_registry(),
            GitignorePolicy::Ignore,
            SymlinkPolicy::Skip,
        );

        assert!(outcome.broken_manifest_symlinks.is_empty());
        assert_eq!(outcome.unrecognized_explicit_paths, vec![notes]);
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

        let outcome = walk(
            &[PathBuf::from(".")],
            &test_registry(),
            GitignorePolicy::Ignore,
            SymlinkPolicy::Skip,
        );

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
            GitignorePolicy::Ignore,
            SymlinkPolicy::Skip,
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
            GitignorePolicy::Ignore,
            SymlinkPolicy::Skip,
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
            GitignorePolicy::Ignore,
            SymlinkPolicy::Skip,
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
            GitignorePolicy::Ignore,
            SymlinkPolicy::Skip,
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
        let outcome = walk(
            &[dir.path().to_path_buf()],
            &test_registry(),
            GitignorePolicy::Ignore,
            SymlinkPolicy::Skip,
        );
        assert!(outcome.unrecognized_explicit_paths.is_empty());
    }

    #[test]
    fn test_walk_multiple_ecosystems_in_one_tree() {
        let dir = tempfile::tempdir().expect("create temp dir");
        fs::write(dir.path().join("Cargo.toml"), "[package]\n").expect("write cargo manifest");
        fs::write(dir.path().join("package.json"), "{}").expect("write npm manifest");
        let outcome = walk(
            &[dir.path().to_path_buf()],
            &test_registry(),
            GitignorePolicy::Ignore,
            SymlinkPolicy::Skip,
        );
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
            GitignorePolicy::Ignore,
            SymlinkPolicy::Skip,
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

        let outcome = walk(
            &[dir.path().to_path_buf()],
            &test_registry(),
            GitignorePolicy::Ignore,
            SymlinkPolicy::Skip,
        );
        assert_eq!(outcome.manifests.len(), 1);
        assert_eq!(
            outcome.manifests[0].display_path,
            PathBuf::from(".github").join("workflows").join("ci.yml")
        );
        assert_eq!(outcome.manifests[0].ecosystem.id(), "github-actions");
    }

    /// Regression test for issue #1165: pins the `DotDirs::Descend` wiring at the
    /// hidden-ecosystem sub-root call site (e.g. `.github`) in [`walk_with_limit`].
    /// `hidden(true)` vs `hidden(false)` only differs on *nested* dot-prefixed entries — the
    /// sub-root itself is never filtered either way (depth 0) — so a manifest nested under a
    /// dot-prefixed directory inside `.github` is only discovered under `Descend`. If that call
    /// site were accidentally flipped to `DotDirs::Skip`, this manifest would be silently
    /// dropped and this test would fail.
    #[test]
    fn test_walk_descends_into_nested_dot_dir_under_github_sub_root() {
        let dir = tempfile::tempdir().expect("create temp dir");
        fs::create_dir_all(dir.path().join(".github").join(".hidden")).expect("mkdir");
        fs::write(
            dir.path()
                .join(".github")
                .join(".hidden")
                .join("Cargo.toml"),
            "[package]\n",
        )
        .expect("write nested manifest");

        let outcome = walk(
            &[dir.path().to_path_buf()],
            &test_registry(),
            GitignorePolicy::Ignore,
            SymlinkPolicy::Skip,
        );

        assert_eq!(outcome.manifests.len(), 1);
        assert_eq!(
            outcome.manifests[0].display_path,
            PathBuf::from(".github").join(".hidden").join("Cargo.toml")
        );
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

        let outcome = walk_with_limit(
            &paths,
            &test_registry(),
            2,
            GitignorePolicy::Ignore,
            SymlinkPolicy::Skip,
        );
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

        let outcome = walk(
            &[dir.path().to_path_buf()],
            &test_registry(),
            GitignorePolicy::Ignore,
            SymlinkPolicy::Skip,
        );

        assert!(outcome.manifests.is_empty());
        assert_eq!(outcome.ignored_manifests, vec![PathBuf::from("Cargo.toml")]);
    }

    /// Issue #1124's own repro: a manifest-shaped broken symlink is reported via the
    /// dedicated `broken_manifest_symlinks` sink, not `ignored_manifests` — the two carry
    /// different signal (see `WalkOutcome::broken_manifest_symlinks`'s doc).
    #[cfg(unix)]
    #[test]
    fn test_walk_default_detects_broken_symlinked_manifest() {
        let dir = tempfile::tempdir().expect("create temp dir");
        std::os::unix::fs::symlink(
            dir.path().join("does-not-exist"),
            dir.path().join("Cargo.toml"),
        )
        .expect("create broken symlink");

        let outcome = walk(
            &[dir.path().to_path_buf()],
            &test_registry(),
            GitignorePolicy::Ignore,
            SymlinkPolicy::Skip,
        );

        assert!(outcome.manifests.is_empty());
        assert!(outcome.ignored_manifests.is_empty());
        assert_eq!(
            outcome.broken_manifest_symlinks,
            vec![PathBuf::from("Cargo.toml")]
        );
    }

    /// A symlink whose own filename is not manifest-shaped stays silent even when broken —
    /// the never-warn-on-non-manifests invariant applies to `broken_manifest_symlinks` too.
    #[cfg(unix)]
    #[test]
    fn test_walk_broken_symlink_not_manifest_shaped_is_not_reported() {
        let dir = tempfile::tempdir().expect("create temp dir");
        std::os::unix::fs::symlink(
            dir.path().join("does-not-exist"),
            dir.path().join("notes.txt"),
        )
        .expect("create broken, non-manifest-shaped symlink");

        let outcome = walk(
            &[dir.path().to_path_buf()],
            &test_registry(),
            GitignorePolicy::Ignore,
            SymlinkPolicy::Skip,
        );

        assert!(outcome.manifests.is_empty());
        assert!(outcome.ignored_manifests.is_empty());
        assert!(outcome.broken_manifest_symlinks.is_empty());
    }

    /// `--follow-symlinks` does not defeat #1124's detection — a broken symlink still can't be
    /// resolved regardless of the flag, so it must still land in `broken_manifest_symlinks`,
    /// not silently vanish the way it did before this fix. Exercises a different code path
    /// than the default-mode test above: under `follow_symlinks: true`, `ignore`/`walkdir`
    /// must stat the entry to resolve its type and yields an `Err` for a broken target instead
    /// of an `Ok(entry)` with an unresolved type — see the `Err(error)` arm's own doc in
    /// `walk_directory`.
    #[cfg(unix)]
    #[test]
    fn test_walk_follow_symlinks_still_detects_broken_symlinked_manifest() {
        let dir = tempfile::tempdir().expect("create temp dir");
        std::os::unix::fs::symlink(
            dir.path().join("does-not-exist"),
            dir.path().join("Cargo.toml"),
        )
        .expect("create broken symlink");

        let outcome = walk(
            &[dir.path().to_path_buf()],
            &test_registry(),
            GitignorePolicy::Ignore,
            SymlinkPolicy::Follow,
        );

        assert!(outcome.manifests.is_empty());
        assert!(outcome.ignored_manifests.is_empty());
        assert_eq!(
            outcome.broken_manifest_symlinks,
            vec![PathBuf::from("Cargo.toml")]
        );
        assert!(
            outcome.walk_errors.is_empty(),
            "Bug 3 (background code review): a mid-walk broken symlink already classified must \
             not also emit a duplicate generic IO walk error: {:?}",
            outcome.walk_errors
        );
    }

    /// A broken hop partway through a symlink chain (`Cargo.toml -> intermediate -> nothing`)
    /// is detected the same way a directly-broken symlink is — `std::fs::metadata` follows the
    /// whole chain, so no separate per-hop handling is needed.
    #[cfg(unix)]
    #[test]
    fn test_walk_broken_symlink_chain_is_detected() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let missing = dir.path().join("does-not-exist");
        let intermediate = dir.path().join("intermediate-link");
        std::os::unix::fs::symlink(&missing, &intermediate)
            .expect("create intermediate broken symlink");
        std::os::unix::fs::symlink(&intermediate, dir.path().join("Cargo.toml"))
            .expect("create Cargo.toml -> intermediate-link -> does-not-exist");

        let outcome = walk(
            &[dir.path().to_path_buf()],
            &test_registry(),
            GitignorePolicy::Ignore,
            SymlinkPolicy::Skip,
        );

        assert!(outcome.manifests.is_empty());
        assert!(outcome.ignored_manifests.is_empty());
        assert_eq!(
            outcome.broken_manifest_symlinks,
            vec![PathBuf::from("Cargo.toml")]
        );
    }

    /// A symlink target unreadable because of an ancestor directory's permissions (`EACCES`,
    /// not `ENOENT`) is detected the same way a dangling symlink is — `std::fs::metadata`
    /// fails identically for both. Skips its own assertions (rather than failing) when running
    /// with a privilege that bypasses directory permission checks (e.g. root in some CI
    /// containers), since the permission-denied precondition this test needs doesn't hold there.
    #[cfg(unix)]
    #[test]
    fn test_walk_symlink_target_permission_denied_is_detected_as_broken() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("create temp dir");
        let blocked = dir.path().join("blocked");
        fs::create_dir(&blocked).expect("mkdir blocked");
        let target = blocked.join("manifest-data");
        fs::write(&target, "[package]\n").expect("write target");
        fs::set_permissions(&blocked, fs::Permissions::from_mode(0o000)).expect("chmod 000");
        std::os::unix::fs::symlink(&target, dir.path().join("Cargo.toml"))
            .expect("create symlink into a permission-denied directory");

        let outcome = walk(
            &[dir.path().to_path_buf()],
            &test_registry(),
            GitignorePolicy::Ignore,
            SymlinkPolicy::Skip,
        );
        let permission_check_effective = std::fs::metadata(&target).is_err();
        fs::set_permissions(&blocked, fs::Permissions::from_mode(0o755)).expect("restore perms");

        if !permission_check_effective {
            eprintln!(
                "skipping: directory permissions did not block metadata (likely running as root)"
            );
            return;
        }

        assert!(outcome.manifests.is_empty());
        assert!(outcome.ignored_manifests.is_empty());
        assert_eq!(
            outcome.broken_manifest_symlinks,
            vec![PathBuf::from("Cargo.toml")]
        );
    }

    /// Spec 065 §6 edge case, extended for #1124: a broken, manifest-shaped symlink directly
    /// at a `PRUNED_DIRECTORIES`-excluded directory's own root is reported via
    /// `broken_manifest_symlinks`, mirroring the existing resolvable-symlink case
    /// (`test_walk_pruned_directory_symlinked_manifest_is_still_warned`).
    #[cfg(unix)]
    #[test]
    fn test_walk_pruned_directory_broken_symlinked_manifest_is_reported_as_broken() {
        let dir = tempfile::tempdir().expect("create temp dir");
        fs::create_dir(dir.path().join("vendor")).expect("mkdir vendor");
        std::os::unix::fs::symlink(
            dir.path().join("vendor").join("does-not-exist"),
            dir.path().join("vendor").join("Cargo.toml"),
        )
        .expect("create broken symlink inside pruned directory");

        let outcome = walk(
            &[dir.path().to_path_buf()],
            &test_registry(),
            GitignorePolicy::Ignore,
            SymlinkPolicy::Skip,
        );

        assert!(
            outcome.manifests.is_empty(),
            "still pruned from the primary scan"
        );
        assert!(outcome.ignored_manifests.is_empty());
        assert_eq!(
            outcome.broken_manifest_symlinks,
            vec![PathBuf::from("vendor").join("Cargo.toml")]
        );
    }

    /// A broken symlink excluded by `.gitignore` under `--respect-gitignore` must still be
    /// detected — mirroring #1112/M5's own gitignored-resolvable-symlink case
    /// (`test_walk_respect_gitignore_does_not_duplicate_symlinked_manifest_warning`), this is
    /// only visible via `detect_ignored_manifests`'s unfiltered diff pass since the primary
    /// (filtered) walk never yields a gitignored entry at all.
    #[cfg(unix)]
    #[test]
    fn test_walk_respect_gitignore_detects_gitignored_broken_symlinked_manifest() {
        let dir = tempfile::tempdir().expect("create temp dir");
        fs::create_dir(dir.path().join(".git")).expect("create .git marker");
        fs::write(dir.path().join(".gitignore"), "Cargo.toml\n").expect("write gitignore");
        std::os::unix::fs::symlink(
            dir.path().join("does-not-exist"),
            dir.path().join("Cargo.toml"),
        )
        .expect("create broken symlink");

        let outcome = walk(
            &[dir.path().to_path_buf()],
            &test_registry(),
            GitignorePolicy::Respect,
            SymlinkPolicy::Skip,
        );

        assert!(outcome.manifests.is_empty());
        assert!(outcome.ignored_manifests.is_empty());
        assert_eq!(
            outcome.broken_manifest_symlinks,
            vec![PathBuf::from("Cargo.toml")]
        );
    }

    /// Companion to the above: a broken symlinked manifest that is *not* gitignored must be
    /// reported exactly once even when `--respect-gitignore`'s extra unfiltered diff pass also
    /// runs — mirrors the existing resolvable-symlink dedup test
    /// (`test_walk_respect_gitignore_does_not_duplicate_symlinked_manifest_warning`).
    #[cfg(unix)]
    #[test]
    fn test_walk_respect_gitignore_does_not_duplicate_broken_symlink_warning() {
        let dir = tempfile::tempdir().expect("create temp dir");
        fs::create_dir(dir.path().join(".git")).expect("create .git marker");
        fs::write(dir.path().join(".gitignore"), "*.log\n").expect("write gitignore");
        std::os::unix::fs::symlink(
            dir.path().join("does-not-exist"),
            dir.path().join("Cargo.toml"),
        )
        .expect("create broken symlink");

        let outcome = walk(
            &[dir.path().to_path_buf()],
            &test_registry(),
            GitignorePolicy::Respect,
            SymlinkPolicy::Skip,
        );

        assert_eq!(
            outcome.broken_manifest_symlinks,
            vec![PathBuf::from("Cargo.toml")],
            "a non-gitignored broken symlinked manifest must be reported exactly once"
        );
    }

    /// A symlink to a directory whose own name isn't manifest-shaped is silent — unaffected by
    /// critic finding S1, since the never-warn-on-non-manifests invariant is orthogonal to it.
    #[cfg(unix)]
    #[test]
    fn test_walk_symlink_to_directory_is_not_reported_as_manifest() {
        let dir = tempfile::tempdir().expect("create temp dir");
        fs::create_dir(dir.path().join("real_dir")).expect("mkdir real_dir");
        std::os::unix::fs::symlink(dir.path().join("real_dir"), dir.path().join("link_dir"))
            .expect("create symlink to directory");

        let outcome = walk(
            &[dir.path().to_path_buf()],
            &test_registry(),
            GitignorePolicy::Ignore,
            SymlinkPolicy::Skip,
        );

        assert!(outcome.manifests.is_empty());
        assert!(outcome.ignored_manifests.is_empty());
        assert!(outcome.broken_manifest_symlinks.is_empty());
    }

    /// Critic finding S1: a manifest-shaped symlink resolving to an existing *directory* is a
    /// zero-cost substitute for a dangling symlink from an attacker's perspective — both are
    /// "a manifest-shaped path that produces no manifest" — so it must land in
    /// `broken_manifest_symlinks`, not silently pass as `Irrelevant` just because the target
    /// technically resolves.
    #[cfg(unix)]
    #[test]
    fn test_walk_symlink_to_directory_with_manifest_shaped_name_is_reported_as_broken() {
        let dir = tempfile::tempdir().expect("create temp dir");
        fs::create_dir(dir.path().join("real_dir")).expect("mkdir real_dir");
        std::os::unix::fs::symlink(dir.path().join("real_dir"), dir.path().join("Cargo.toml"))
            .expect("create manifest-shaped symlink to a directory");

        let outcome = walk(
            &[dir.path().to_path_buf()],
            &test_registry(),
            GitignorePolicy::Ignore,
            SymlinkPolicy::Skip,
        );

        assert!(outcome.manifests.is_empty());
        assert!(outcome.ignored_manifests.is_empty());
        assert_eq!(
            outcome.broken_manifest_symlinks,
            vec![PathBuf::from("Cargo.toml")]
        );
    }

    /// Companion to the above: a manifest-shaped symlink resolving to a non-regular,
    /// non-directory target (a fifo) is the same class of substitution attack and must be
    /// reported identically. Uses the `mkfifo` binary rather than unsafe `libc::mkfifo` (this
    /// workspace forbids `unsafe_code`); skips gracefully if the binary isn't on `PATH`.
    #[cfg(unix)]
    #[test]
    fn test_walk_symlink_to_fifo_with_manifest_shaped_name_is_reported_as_broken() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let fifo = dir.path().join("a-fifo");
        let mkfifo_ok = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .is_ok_and(|status| status.success());
        if !mkfifo_ok {
            eprintln!("skipping: `mkfifo` binary not available on PATH");
            return;
        }
        std::os::unix::fs::symlink(&fifo, dir.path().join("Cargo.toml"))
            .expect("create manifest-shaped symlink to a fifo");

        let outcome = walk(
            &[dir.path().to_path_buf()],
            &test_registry(),
            GitignorePolicy::Ignore,
            SymlinkPolicy::Skip,
        );

        assert!(outcome.manifests.is_empty());
        assert!(outcome.ignored_manifests.is_empty());
        assert_eq!(
            outcome.broken_manifest_symlinks,
            vec![PathBuf::from("Cargo.toml")]
        );
    }

    /// Critic finding S2: an ordinary, non-symlink directory that merely shares a manifest's
    /// name, made unreadable by permissions, must never be reported as symlink tampering — the
    /// `is_symlink` gate in both `classify_symlink` and the walk's `Err(error)` arm must
    /// exclude it. Skips its own assertions when running with a privilege that bypasses
    /// directory permission checks (mirrors the existing EACCES symlink-target test).
    #[cfg(unix)]
    #[test]
    fn test_walk_permission_denied_non_symlink_manifest_named_directory_is_not_reported() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("create temp dir");
        let blocked = dir.path().join("app.csproj");
        fs::create_dir(&blocked).expect("mkdir app.csproj");
        fs::set_permissions(&blocked, fs::Permissions::from_mode(0o000)).expect("chmod 000");

        let outcome = walk(
            &[dir.path().to_path_buf()],
            &test_registry(),
            GitignorePolicy::Ignore,
            SymlinkPolicy::Skip,
        );
        // Background-review test-gap finding: `metadata()`/`stat()` on `blocked` needs only
        // execute permission on its *ancestors*, not on `blocked` itself, so it always succeeds
        // here regardless of the chmod above — checking it (as an earlier version of this test
        // did) made the self-skip fire unconditionally, giving this test zero real coverage.
        // `read_dir()` on `blocked` does need its own execute bit, matching the operation the
        // walker actually performs (and fails) when it tries to descend into this entry.
        let permission_check_effective = std::fs::read_dir(&blocked).is_err();
        fs::set_permissions(&blocked, fs::Permissions::from_mode(0o755)).expect("restore perms");

        if !permission_check_effective {
            eprintln!(
                "skipping: directory permissions did not block read_dir (likely running as root)"
            );
            return;
        }

        assert!(
            !outcome.walk_errors.is_empty(),
            "sanity check: the walker's own descent into `blocked` must have failed for this \
             test to exercise anything"
        );
        assert!(outcome.ignored_manifests.is_empty());
        assert!(
            outcome.broken_manifest_symlinks.is_empty(),
            "a non-symlink, permission-denied directory must never be reported as symlink \
             tampering: {:?}",
            outcome.broken_manifest_symlinks
        );
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

        let outcome = walk(
            &[dir.path().to_path_buf()],
            &test_registry(),
            GitignorePolicy::Ignore,
            SymlinkPolicy::Skip,
        );

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

        let outcome = walk(
            &[dir.path().to_path_buf()],
            &test_registry(),
            GitignorePolicy::Ignore,
            SymlinkPolicy::Follow,
        );

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

        let disabled = walk(
            &[dir.path().to_path_buf()],
            &test_registry(),
            GitignorePolicy::Ignore,
            SymlinkPolicy::Skip,
        );
        assert!(disabled.manifests.is_empty());
        assert_eq!(
            disabled.ignored_manifests,
            vec![PathBuf::from("Cargo.toml")]
        );

        let enabled = walk(
            &[dir.path().to_path_buf()],
            &test_registry(),
            GitignorePolicy::Ignore,
            SymlinkPolicy::Follow,
        );
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

        let outcome = walk(
            &[dir.path().to_path_buf()],
            &test_registry(),
            GitignorePolicy::Ignore,
            SymlinkPolicy::Follow,
        );

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

        let outcome = walk(
            &[dir.path().to_path_buf()],
            &test_registry(),
            GitignorePolicy::Ignore,
            SymlinkPolicy::Follow,
        );

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
            GitignorePolicy::Ignore,
            SymlinkPolicy::Follow,
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

        let outcome = walk(
            &[root.path().to_path_buf()],
            &test_registry(),
            GitignorePolicy::Ignore,
            SymlinkPolicy::Follow,
        );

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

        let outcome = walk(
            &[dir.path().to_path_buf()],
            &test_registry(),
            GitignorePolicy::Ignore,
            SymlinkPolicy::Follow,
        );

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

    /// M2 (critic follow-up): a self-referential manifest-shaped symlink (`Cargo.toml ->
    /// Cargo.toml`) resolves via a plain OS-level `ELOOP` (`io::Error`), distinct from the
    /// structural ancestor/descendant directory cycle `ignore`'s own `Error::Loop` variant
    /// detects during descent (`test_walk_follow_symlinks_reports_symlink_loop_via_walk_errors`
    /// above, whose names aren't manifest-shaped and whose `Error::Loop` isn't `is_io()`
    /// either way). Since this *is* an IO error on a manifest-shaped symlink, it lands in
    /// `broken_manifest_symlinks`, and — per Bug 3 (background code review) — the generic
    /// `walk_errors` push is skipped once that specific classification already fired, so no
    /// hang/crash but also no duplicate warning.
    #[cfg(unix)]
    #[test]
    fn test_walk_follow_symlinks_self_referential_manifest_symlink_is_reported_as_broken() {
        let dir = tempfile::tempdir().expect("create temp dir");
        std::os::unix::fs::symlink(dir.path().join("Cargo.toml"), dir.path().join("Cargo.toml"))
            .expect("create self-referential Cargo.toml -> Cargo.toml");

        let outcome = walk(
            &[dir.path().to_path_buf()],
            &test_registry(),
            GitignorePolicy::Ignore,
            SymlinkPolicy::Follow,
        );

        assert_eq!(
            outcome.broken_manifest_symlinks,
            vec![PathBuf::from("Cargo.toml")]
        );
        assert!(
            outcome.walk_errors.is_empty(),
            "must not duplicate the specific broken-manifest classification with a generic \
             IO walk error: {:?}",
            outcome.walk_errors
        );
    }

    /// M2 (critic follow-up): `--respect-gitignore` and `--follow-symlinks` combined must still
    /// detect a broken, gitignored manifest symlink — no untested interaction between the two
    /// opt-in flags for the broken case specifically (the resolvable case already has
    /// `test_walk_follow_symlinks_and_respect_gitignore_together_still_honors_gitignore`).
    #[cfg(unix)]
    #[test]
    fn test_walk_respect_gitignore_and_follow_symlinks_together_detect_broken_manifest() {
        let dir = tempfile::tempdir().expect("create temp dir");
        fs::create_dir(dir.path().join(".git")).expect("create .git marker");
        fs::write(dir.path().join(".gitignore"), "Cargo.toml\n").expect("write gitignore");
        std::os::unix::fs::symlink(
            dir.path().join("does-not-exist"),
            dir.path().join("Cargo.toml"),
        )
        .expect("create broken symlink");

        let outcome = walk(
            &[dir.path().to_path_buf()],
            &test_registry(),
            GitignorePolicy::Respect,
            SymlinkPolicy::Follow,
        );

        assert!(outcome.manifests.is_empty());
        assert!(outcome.ignored_manifests.is_empty());
        assert_eq!(
            outcome.broken_manifest_symlinks,
            vec![PathBuf::from("Cargo.toml")]
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

        let outcome = walk(
            &[dir.path().to_path_buf()],
            &test_registry(),
            GitignorePolicy::Respect,
            SymlinkPolicy::Follow,
        );

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

        let outcome = walk(
            &[root.path().to_path_buf()],
            &test_registry(),
            GitignorePolicy::Ignore,
            SymlinkPolicy::Follow,
        );

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
            GitignorePolicy::Ignore,
            SymlinkPolicy::Follow,
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

        let outcome = walk(
            &[dir.path().to_path_buf()],
            &test_registry(),
            GitignorePolicy::Respect,
            SymlinkPolicy::Skip,
        );

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

        let outcome = walk(
            &[root.path().to_path_buf()],
            &test_registry(),
            GitignorePolicy::Ignore,
            SymlinkPolicy::Skip,
        );

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
