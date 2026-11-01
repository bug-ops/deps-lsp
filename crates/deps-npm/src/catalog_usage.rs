//! "Used by N packages" index for pnpm catalog entries (#1878).
//!
//! [`CatalogUsageIndex::build`] walks the workspace members selected by the
//! `pnpm-workspace.yaml` `packages:` globs and counts, per catalog entry, how many distinct
//! member `package.json` files reference it through a `catalog:` specifier. The walk is bounded
//! (literal-prefix roots, a depth cap, an entry cap and a member cap) because the globs and the
//! tree are attacker-controlled; hitting a cap yields [`Completeness::Truncated`] so the hover
//! says "at least N" instead of under-reporting silently.
//!
//! Like pnpm, `.gitignore` is never applied. [`deps_core::fs_probe::PRUNED_WALK_DIRECTORIES`]
//! and dot directories are pruned even under `**`.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use deps_core::PackageName;
use deps_core::fs_probe::{PRUNED_WALK_DIRECTORIES, read_to_string_capped_no_follow};
use globset::{GlobSet, GlobSetBuilder};
use ignore::WalkBuilder;
use tokio::sync::watch;

use crate::catalog::CatalogSpecifier;
use crate::ecosystem::DEPENDENCY_KEYS;
use crate::types::CatalogId;
use crate::workspace_members::{PackageGlob, WorkspaceGlob, WorkspaceMembers};

/// Deepest directory level a recursive (`**`) member pattern is followed.
pub const MAX_MEMBER_WALK_DEPTH: usize = 8;
/// Directory entries visited across all walk roots before the index is marked truncated.
pub const MAX_WALK_ENTRIES: usize = 20_000;
/// Member `package.json` files read before the index is marked truncated.
pub const MAX_MEMBERS: usize = 1000;
/// Size cap for one member `package.json`.
const MAX_MEMBER_MANIFEST_BYTES: u64 = 1024 * 1024;
/// Wall-clock budget of one walk before the index is marked truncated.
pub const MAX_WALK_DURATION: Duration = Duration::from_secs(2);
/// How long a computed index is served before the workspace is walked again.
const INDEX_TTL: Duration = Duration::from_secs(30);
/// Distinct workspace roots kept in [`CatalogUsageCache`].
const MAX_CACHED_ROOTS: usize = 64;

/// Whether an index saw every workspace member.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Completeness {
    /// The whole member set was read; counts are exact.
    Complete,
    /// A walk cap was hit; counts are lower bounds.
    Truncated,
}

/// Caps applied by one [`CatalogUsageIndex::build_with_limits`] walk.
#[derive(Debug, Clone, Copy)]
struct WalkLimits {
    recursive_depth: usize,
    entries: usize,
    members: usize,
    duration: Duration,
}

impl WalkLimits {
    const DEFAULT: Self = Self {
        recursive_depth: MAX_MEMBER_WALK_DEPTH,
        entries: MAX_WALK_ENTRIES,
        members: MAX_MEMBERS,
        duration: MAX_WALK_DURATION,
    };
}

/// Per-catalog-entry count of workspace packages referencing it.
#[derive(Debug, Clone)]
pub struct CatalogUsageIndex {
    counts: HashMap<(CatalogId, PackageName), usize>,
    completeness: Completeness,
}

impl CatalogUsageIndex {
    /// Walks the workspace `members` selects and counts `catalog:` references.
    ///
    /// Blocking filesystem work: call from a blocking context.
    #[must_use]
    pub fn build(members: &WorkspaceMembers) -> Self {
        Self::build_with_limits(members, WalkLimits::DEFAULT)
    }

    fn build_with_limits(members: &WorkspaceMembers, limits: WalkLimits) -> Self {
        let Some(matcher) = MemberMatcher::new(members.globs()) else {
            return Self {
                counts: HashMap::new(),
                completeness: Completeness::Complete,
            };
        };
        let Ok(workspace_root) = std::fs::canonicalize(members.root()) else {
            return Self {
                counts: HashMap::new(),
                completeness: Completeness::Complete,
            };
        };
        let mut tally = Tally::default();
        if members.globs_truncated() {
            tally.completeness = Completeness::Truncated;
        }
        let mut visited = 0usize;
        let began = Instant::now();

        tally.add_manifest(&workspace_root.join("package.json"));

        'roots: for root in walk_roots(members.globs(), limits.recursive_depth) {
            // A symlinked prefix component must not lead the walk outside the workspace.
            let Ok(start) = std::fs::canonicalize(workspace_root.join(&root.prefix)) else {
                continue;
            };
            if !start.starts_with(&workspace_root) {
                continue;
            }
            let walker = WalkBuilder::new(&start)
                .standard_filters(false)
                .follow_links(false)
                .max_depth(Some(root.max_depth))
                .filter_entry(is_walkable)
                .build();
            for entry in walker.flatten() {
                visited += 1;
                if visited > limits.entries || began.elapsed() > limits.duration {
                    tally.completeness = Completeness::Truncated;
                    break 'roots;
                }
                if !entry.file_type().is_some_and(|t| t.is_file())
                    || entry.file_name() != "package.json"
                {
                    continue;
                }
                let Ok(relative) = entry.path().strip_prefix(&workspace_root) else {
                    continue;
                };
                if relative == Path::new("package.json") || !matcher.is_member(relative) {
                    continue;
                }
                if tally.manifests_read >= limits.members {
                    tally.completeness = Completeness::Truncated;
                    break 'roots;
                }
                tally.manifests_read += 1;
                tally.add_manifest(entry.path());
            }
        }
        Self {
            counts: tally.counts,
            completeness: tally.completeness,
        }
    }

    /// Number of distinct workspace packages referencing the `name` entry of catalog `id`.
    #[must_use]
    pub fn count(&self, id: &CatalogId, name: &PackageName) -> usize {
        self.counts
            .get(&(id.clone(), name.clone()))
            .copied()
            .unwrap_or(0)
    }

    /// Whether [`Self::count`] values are exact or lower bounds.
    #[must_use]
    pub const fn completeness(&self) -> Completeness {
        self.completeness
    }
}

/// Include/exclude matchers over a member's root-relative `package.json` path.
struct MemberMatcher {
    includes: GlobSet,
    excludes: GlobSet,
}

impl MemberMatcher {
    fn new(globs: &[PackageGlob]) -> Option<Self> {
        let mut includes = GlobSetBuilder::new();
        let mut excludes = GlobSetBuilder::new();
        for glob in globs {
            match glob {
                PackageGlob::Include(g) => includes.add(g.package_json_glob().clone()),
                PackageGlob::Exclude(g) => excludes.add(g.package_json_glob().clone()),
            };
        }
        Some(Self {
            includes: includes.build().ok()?,
            excludes: excludes.build().ok()?,
        })
    }

    fn is_member(&self, relative: &Path) -> bool {
        let text = relative.to_string_lossy().replace('\\', "/");
        self.includes.is_match(&text) && !self.excludes.is_match(&text)
    }
}

#[derive(Debug, PartialEq, Eq)]
struct WalkRoot {
    prefix: PathBuf,
    max_depth: usize,
}

/// One walk root per distinct literal prefix, nested prefixes folded into their ancestor, with
/// the depth needed to reach every include glob under it.
fn walk_roots(globs: &[PackageGlob], recursive_depth: usize) -> Vec<WalkRoot> {
    let includes: Vec<&WorkspaceGlob> = globs
        .iter()
        .filter_map(|glob| match glob {
            PackageGlob::Include(g) => Some(g),
            PackageGlob::Exclude(_) => None,
        })
        .collect();
    let mut prefixes: Vec<PathBuf> = includes.iter().map(|g| g.literal_prefix()).collect();
    prefixes.sort();
    prefixes.dedup();
    let top_level: Vec<PathBuf> = prefixes
        .iter()
        .filter(|prefix| {
            !prefixes
                .iter()
                .any(|other| other != *prefix && prefix.starts_with(other))
        })
        .cloned()
        .collect();
    top_level
        .into_iter()
        .map(|prefix| {
            let max_depth = includes
                .iter()
                .filter(|g| g.literal_prefix().starts_with(&prefix))
                .map(|g| {
                    if g.is_recursive() {
                        recursive_depth
                    } else {
                        let offset =
                            g.literal_prefix().components().count() - prefix.components().count();
                        offset + g.levels_below_prefix()
                    }
                })
                .max()
                .unwrap_or(1)
                .min(recursive_depth.max(1));
            WalkRoot { prefix, max_depth }
        })
        .collect()
}

/// Prunes dependency/build/VCS trees and dot directories; never prunes the walk root.
fn is_walkable(entry: &ignore::DirEntry) -> bool {
    if entry.depth() == 0 || !entry.file_type().is_some_and(|t| t.is_dir()) {
        return true;
    }
    entry
        .file_name()
        .to_str()
        .is_some_and(|name| !name.starts_with('.') && !PRUNED_WALK_DIRECTORIES.contains(&name))
}

#[derive(Debug)]
struct Tally {
    counts: HashMap<(CatalogId, PackageName), usize>,
    manifests_read: usize,
    completeness: Completeness,
}

impl Default for Tally {
    fn default() -> Self {
        Self {
            counts: HashMap::new(),
            manifests_read: 0,
            completeness: Completeness::Complete,
        }
    }
}

impl Tally {
    /// Counts each catalog entry `path`'s manifest references once, however many dependency
    /// sections name it. An unreadable or malformed manifest contributes nothing.
    fn add_manifest(&mut self, path: &Path) {
        // `symlink_metadata` first: opening a FIFO would block the walk.
        if !std::fs::symlink_metadata(path).is_ok_and(|meta| meta.is_file()) {
            return;
        }
        let Ok(Some(text)) = read_to_string_capped_no_follow(path, MAX_MEMBER_MANIFEST_BYTES)
        else {
            return;
        };
        let Ok(root) = deps_core::parse_json_checked::<serde_json::Value>(text.as_bytes()) else {
            return;
        };
        let mut referenced: HashSet<(CatalogId, PackageName)> = HashSet::new();
        for section in DEPENDENCY_KEYS {
            let Some(entries) = root.get(section).and_then(|v| v.as_object()) else {
                continue;
            };
            for (name, spec) in deps_core::json_helpers::string_valued_entries(entries) {
                if let Some(specifier) = CatalogSpecifier::parse(spec) {
                    referenced.insert((specifier.id(), PackageName::from(name)));
                }
            }
        }
        for key in referenced {
            *self.counts.entry(key).or_default() += 1;
        }
    }
}

type SharedIndex = Option<Arc<CatalogUsageIndex>>;

struct Slot {
    started: Instant,
    members: WorkspaceMembers,
    index: watch::Receiver<SharedIndex>,
}

/// Short-lived per-root cache of [`CatalogUsageIndex`] that never blocks a handler on the
/// walk: the walk runs on the blocking pool and callers wait only up to a budget.
#[derive(Default)]
pub(crate) struct CatalogUsageCache {
    slots: DashMap<PathBuf, Slot>,
}

impl CatalogUsageCache {
    /// The index for `members`, waiting at most `budget` for a walk still in flight; `None`
    /// when the walk has not finished in time (the walk keeps running and warms the cache).
    pub(crate) async fn usage(
        &self,
        members: &WorkspaceMembers,
        budget: Duration,
    ) -> Option<Arc<CatalogUsageIndex>> {
        let mut receiver = self.claim(members);
        let ready = tokio::time::timeout(budget, receiver.wait_for(Option::is_some))
            .await
            .ok()?
            .ok()?;
        (*ready).clone()
    }

    fn claim(&self, members: &WorkspaceMembers) -> watch::Receiver<SharedIndex> {
        if self.slots.len() >= MAX_CACHED_ROOTS {
            self.slots
                .retain(|_, slot| slot.started.elapsed() < INDEX_TTL);
            if self.slots.len() >= MAX_CACHED_ROOTS {
                self.slots.clear();
            }
        }
        let mut spawn_for = None;
        let receiver = {
            let mut slot = self
                .slots
                .entry(members.root().to_path_buf())
                .or_insert_with(|| {
                    let (sender, index) = watch::channel(None);
                    spawn_for = Some(sender);
                    Slot {
                        started: Instant::now(),
                        members: members.clone(),
                        index,
                    }
                });
            if spawn_for.is_none()
                && (slot.started.elapsed() >= INDEX_TTL || slot.members != *members)
            {
                // Same workspace shape: keep serving the previous index while the refresh runs.
                let stale = if slot.members == *members {
                    slot.index.borrow().clone()
                } else {
                    None
                };
                let (sender, index) = watch::channel(stale);
                spawn_for = Some(sender);
                *slot = Slot {
                    started: Instant::now(),
                    members: members.clone(),
                    index,
                };
            }
            slot.index.clone()
        };
        if let Some(sender) = spawn_for {
            let members = members.clone();
            tokio::task::spawn_blocking(move || {
                sender.send_replace(Some(Arc::new(CatalogUsageIndex::build(&members))));
            });
        }
        receiver
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn write(root: &Path, relative: &str, content: &str) {
        let path = root.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, content).unwrap();
    }

    fn pkg(deps: &str) -> String {
        format!(r#"{{"dependencies": {{{deps}}}}}"#)
    }

    fn members(root: &Path, globs: &[&str]) -> WorkspaceMembers {
        WorkspaceMembers::new(
            root.to_path_buf(),
            globs.iter().filter_map(|g| PackageGlob::parse(g)).collect(),
        )
    }

    fn count(index: &CatalogUsageIndex, id: &CatalogId, name: &str) -> usize {
        index.count(id, &PackageName::from(name))
    }

    const REACT: &str = r#""react": "catalog:""#;

    #[test]
    fn test_single_star_counts_direct_children_only() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "packages/a/package.json", &pkg(REACT));
        write(dir.path(), "packages/a/b/package.json", &pkg(REACT));
        let index = CatalogUsageIndex::build(&members(dir.path(), &["packages/*"]));
        assert_eq!(count(&index, &CatalogId::Default, "react"), 1);
        assert_eq!(index.completeness(), Completeness::Complete);
    }

    #[test]
    fn test_double_star_counts_nested_levels() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "apps/a/package.json", &pkg(REACT));
        write(dir.path(), "apps/a/b/package.json", &pkg(REACT));
        write(dir.path(), "other/c/package.json", &pkg(REACT));
        let index = CatalogUsageIndex::build(&members(dir.path(), &["apps/**"]));
        assert_eq!(count(&index, &CatalogId::Default, "react"), 2);
    }

    #[test]
    fn test_exclude_glob_removes_matching_members() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "packages/x/package.json", &pkg(REACT));
        write(dir.path(), "packages/test/package.json", &pkg(REACT));
        write(dir.path(), "packages/y/test/z/package.json", &pkg(REACT));
        let index = CatalogUsageIndex::build(&members(dir.path(), &["packages/**", "!**/test/**"]));
        assert_eq!(count(&index, &CatalogId::Default, "react"), 1);
    }

    #[test]
    fn test_root_package_always_counts() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "package.json", &pkg(REACT));
        write(dir.path(), "packages/a/package.json", &pkg(REACT));
        let index = CatalogUsageIndex::build(&members(dir.path(), &["packages/*"]));
        assert_eq!(count(&index, &CatalogId::Default, "react"), 2);
        let defaults = CatalogUsageIndex::build(&WorkspaceMembers::new(
            dir.path().to_path_buf(),
            PackageGlob::defaults(),
        ));
        assert_eq!(count(&defaults, &CatalogId::Default, "react"), 2);
    }

    #[test]
    fn test_named_and_default_catalog_specifiers_are_distinguished() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "packages/a/package.json",
            r#"{
                "dependencies": {"react": "catalog:default", "vue": "catalog:v2"},
                "devDependencies": {"react": "catalog:", "lodash": "^4"}
            }"#,
        );
        let index = CatalogUsageIndex::build(&members(dir.path(), &["packages/*"]));
        assert_eq!(count(&index, &CatalogId::Default, "react"), 1);
        assert_eq!(count(&index, &CatalogId::from_name("v2"), "vue"), 1);
        assert_eq!(count(&index, &CatalogId::Default, "vue"), 0);
        assert_eq!(count(&index, &CatalogId::Default, "lodash"), 0);
    }

    #[test]
    fn test_pruned_and_dot_directories_are_skipped_under_double_star() {
        let dir = tempfile::tempdir().unwrap();
        for pruned in ["node_modules", "target", "dist", ".hidden", "vendor"] {
            write(dir.path(), &format!("{pruned}/p/package.json"), &pkg(REACT));
        }
        write(dir.path(), "real/package.json", &pkg(REACT));
        let index = CatalogUsageIndex::build(&members(dir.path(), &["**"]));
        assert_eq!(count(&index, &CatalogId::Default, "react"), 1);
    }

    #[test]
    fn test_escaping_globs_are_dropped_and_walk_stays_inside_root() {
        let outer = tempfile::tempdir().unwrap();
        let root = outer.path().join("ws");
        write(&root, "packages/a/package.json", &pkg(REACT));
        write(outer.path(), "sibling/package.json", &pkg(REACT));
        let index = CatalogUsageIndex::build(&members(
            &root,
            &["../sibling", "../*", "/etc", "../../**", "packages/*"],
        ));
        assert_eq!(count(&index, &CatalogId::Default, "react"), 1);
    }

    #[test]
    fn test_entry_cap_marks_index_truncated() {
        let dir = tempfile::tempdir().unwrap();
        for i in 0..20 {
            write(
                dir.path(),
                &format!("packages/p{i}/package.json"),
                &pkg(REACT),
            );
        }
        let limits = WalkLimits {
            entries: 6,
            ..WalkLimits::DEFAULT
        };
        let index =
            CatalogUsageIndex::build_with_limits(&members(dir.path(), &["packages/*"]), limits);
        assert_eq!(index.completeness(), Completeness::Truncated);
        let counted = count(&index, &CatalogId::Default, "react");
        assert!((1..20).contains(&counted));
    }

    #[test]
    fn test_member_cap_marks_index_truncated() {
        let dir = tempfile::tempdir().unwrap();
        for i in 0..10 {
            write(
                dir.path(),
                &format!("packages/p{i}/package.json"),
                &pkg(REACT),
            );
        }
        let limits = WalkLimits {
            members: 4,
            ..WalkLimits::DEFAULT
        };
        let index =
            CatalogUsageIndex::build_with_limits(&members(dir.path(), &["packages/*"]), limits);
        assert_eq!(index.completeness(), Completeness::Truncated);
        assert_eq!(count(&index, &CatalogId::Default, "react"), 4);
    }

    #[test]
    fn test_recursive_depth_is_capped() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "a/b/c/d/package.json", &pkg(REACT));
        let limits = WalkLimits {
            recursive_depth: 3,
            ..WalkLimits::DEFAULT
        };
        let index = CatalogUsageIndex::build_with_limits(&members(dir.path(), &["**"]), limits);
        assert_eq!(count(&index, &CatalogId::Default, "react"), 0);
    }

    #[test]
    fn test_walk_roots_fold_nested_prefixes_and_bound_depth() {
        let parse = |globs: &[&str]| -> Vec<PackageGlob> {
            globs.iter().filter_map(|g| PackageGlob::parse(g)).collect()
        };
        let roots = walk_roots(&parse(&["packages/*", "packages/ui/*", "apps/web"]), 8);
        assert_eq!(
            roots,
            vec![
                WalkRoot {
                    prefix: PathBuf::from("apps/web"),
                    max_depth: 1
                },
                WalkRoot {
                    prefix: PathBuf::from("packages"),
                    max_depth: 3
                },
            ]
        );
        let recursive = walk_roots(&parse(&["**"]), 8);
        assert_eq!(recursive[0].prefix, PathBuf::new());
        assert_eq!(recursive[0].max_depth, 8);
    }

    #[test]
    fn test_malformed_member_manifest_is_ignored() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "packages/a/package.json", "{ not json");
        write(dir.path(), "packages/b/package.json", &pkg(REACT));
        let index = CatalogUsageIndex::build(&members(dir.path(), &["packages/*"]));
        assert_eq!(count(&index, &CatalogId::Default, "react"), 1);
    }

    #[tokio::test]
    async fn test_cache_serves_index_and_recomputes_on_changed_globs() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "packages/a/package.json", &pkg(REACT));
        write(dir.path(), "apps/b/package.json", &pkg(REACT));
        let cache = CatalogUsageCache::default();
        let budget = Duration::from_secs(10);

        let first = cache
            .usage(&members(dir.path(), &["packages/*"]), budget)
            .await
            .unwrap();
        assert_eq!(count(&first, &CatalogId::Default, "react"), 1);

        let second = cache
            .usage(&members(dir.path(), &["packages/*", "apps/*"]), budget)
            .await
            .unwrap();
        assert_eq!(count(&second, &CatalogId::Default, "react"), 2);
    }

    #[tokio::test]
    async fn test_cache_reuses_fresh_index_without_rewalking() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "packages/a/package.json", &pkg(REACT));
        let cache = CatalogUsageCache::default();
        let selected = members(dir.path(), &["packages/*"]);
        let first = cache
            .usage(&selected, Duration::from_secs(10))
            .await
            .unwrap();
        write(dir.path(), "packages/b/package.json", &pkg(REACT));
        let again = cache
            .usage(&selected, Duration::from_secs(10))
            .await
            .unwrap();
        assert!(Arc::ptr_eq(&first, &again));
    }

    #[cfg(unix)]
    #[test]
    fn test_symlinked_root_manifest_is_not_read() {
        let outer = tempfile::tempdir().unwrap();
        let root = outer.path().join("ws");
        fs::create_dir_all(&root).unwrap();
        write(outer.path(), "elsewhere.json", &pkg(REACT));
        std::os::unix::fs::symlink(
            outer.path().join("elsewhere.json"),
            root.join("package.json"),
        )
        .unwrap();
        let index = CatalogUsageIndex::build(&members(&root, &["packages/*"]));
        assert_eq!(count(&index, &CatalogId::Default, "react"), 0);
    }

    #[cfg(unix)]
    #[test]
    fn test_fifo_manifests_do_not_hang_the_walk() {
        let dir = tempfile::tempdir().unwrap();
        let fifo = |path: &Path| {
            std::process::Command::new("mkfifo")
                .arg(path)
                .status()
                .unwrap()
                .success()
        };
        assert!(fifo(&dir.path().join("package.json")));
        fs::create_dir_all(dir.path().join("packages/a")).unwrap();
        assert!(fifo(&dir.path().join("packages/a/package.json")));
        write(dir.path(), "packages/b/package.json", &pkg(REACT));
        let index = CatalogUsageIndex::build(&members(dir.path(), &["packages/*"]));
        assert_eq!(count(&index, &CatalogId::Default, "react"), 1);
    }

    #[cfg(unix)]
    #[test]
    fn test_symlinked_prefix_component_cannot_escape_the_root() {
        let outer = tempfile::tempdir().unwrap();
        let root = outer.path().join("ws");
        fs::create_dir_all(&root).unwrap();
        write(outer.path(), "outside/a/package.json", &pkg(REACT));
        std::os::unix::fs::symlink(outer.path().join("outside"), root.join("packages")).unwrap();
        let index = CatalogUsageIndex::build(&members(&root, &["packages/*"]));
        assert_eq!(count(&index, &CatalogId::Default, "react"), 0);
    }

    #[test]
    fn test_oversized_member_manifest_is_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let padding = " ".repeat(usize::try_from(MAX_MEMBER_MANIFEST_BYTES).unwrap());
        write(
            dir.path(),
            "packages/big/package.json",
            &format!("{}{padding}", pkg(REACT)),
        );
        write(dir.path(), "packages/ok/package.json", &pkg(REACT));
        let index = CatalogUsageIndex::build(&members(dir.path(), &["packages/*"]));
        assert_eq!(count(&index, &CatalogId::Default, "react"), 1);
    }

    #[test]
    fn test_expired_wall_clock_budget_marks_index_truncated() {
        let dir = tempfile::tempdir().unwrap();
        for i in 0..5 {
            write(
                dir.path(),
                &format!("packages/p{i}/package.json"),
                &pkg(REACT),
            );
        }
        let limits = WalkLimits {
            duration: Duration::ZERO,
            ..WalkLimits::DEFAULT
        };
        let index =
            CatalogUsageIndex::build_with_limits(&members(dir.path(), &["packages/*"]), limits);
        assert_eq!(index.completeness(), Completeness::Truncated);
    }

    #[tokio::test]
    async fn test_expired_slot_serves_the_stale_index_while_refreshing() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "packages/a/package.json", &pkg(REACT));
        let cache = CatalogUsageCache::default();
        let selected = members(dir.path(), &["packages/*"]);
        let first = cache
            .usage(&selected, Duration::from_secs(10))
            .await
            .unwrap();

        write(dir.path(), "packages/b/package.json", &pkg(REACT));
        cache.slots.get_mut(dir.path()).unwrap().started =
            Instant::now().checked_sub(INDEX_TTL * 2).unwrap();
        let stale = cache.usage(&selected, Duration::ZERO).await.unwrap();
        assert!(Arc::ptr_eq(&first, &stale));

        let refreshed = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let current = cache
                    .usage(&selected, Duration::from_secs(10))
                    .await
                    .unwrap();
                if !Arc::ptr_eq(&first, &current) {
                    break current;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(count(&refreshed, &CatalogId::Default, "react"), 2);
    }

    #[cfg(unix)]
    #[test]
    fn test_symlinked_members_and_directories_are_skipped() {
        let outer = tempfile::tempdir().unwrap();
        let root = outer.path().join("ws");
        write(&root, "packages/real/package.json", &pkg(REACT));
        write(outer.path(), "target-dir/package.json", &pkg(REACT));
        write(outer.path(), "target-file.json", &pkg(REACT));
        std::os::unix::fs::symlink(
            outer.path().join("target-dir"),
            root.join("packages/linked-dir"),
        )
        .unwrap();
        fs::create_dir_all(root.join("packages/linked-file")).unwrap();
        std::os::unix::fs::symlink(
            outer.path().join("target-file.json"),
            root.join("packages/linked-file/package.json"),
        )
        .unwrap();
        let index = CatalogUsageIndex::build(&members(&root, &["packages/*", "packages/**"]));
        assert_eq!(count(&index, &CatalogId::Default, "react"), 1);
    }
}
