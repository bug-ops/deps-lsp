//! Typed `packages:` globs of a `pnpm-workspace.yaml` (spec 078 follow-up, #1878).
//!
//! A glob that could leave the workspace root (absolute, `..`, backslash separators) is
//! unrepresentable as a [`WorkspaceGlob`]: [`WorkspaceGlob::parse`] rejects it, so the bounded
//! member walk in `catalog_usage` can never be steered outside the directory holding the
//! workspace file by a hostile `packages:` entry.

use std::path::{Path, PathBuf};

use globset::{Glob, GlobBuilder};

/// Characters that make a path component a pattern instead of a literal directory name.
const GLOB_META: &[char] = &['*', '?', '[', ']', '{', '}', '!'];

/// A validated, normalized `packages:` pattern naming workspace member directories.
///
/// The pattern is relative to the workspace root and has no `./` prefix, no trailing `/`, no
/// empty or `.` components, and no `..` component. The empty pattern is the root itself
/// (`.` in the YAML).
///
/// # Examples
///
/// ```
/// use deps_npm::workspace_members::WorkspaceGlob;
///
/// assert_eq!(WorkspaceGlob::parse("./packages/*/").unwrap().as_str(), "packages/*");
/// assert_eq!(WorkspaceGlob::parse(".").unwrap().as_str(), "");
/// assert!(WorkspaceGlob::parse("../outside").is_none());
/// assert!(WorkspaceGlob::parse("/etc").is_none());
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceGlob {
    pattern: String,
    package_json: Glob,
}

impl WorkspaceGlob {
    /// Parses and normalizes `raw`, or `None` when it is empty, absolute, contains a `..`
    /// component or a backslash, or is not a valid glob.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        let raw = raw.trim();
        if raw.is_empty() || raw.contains(['\\', ':']) || raw.starts_with('/') {
            return None;
        }
        let mut components = Vec::new();
        for component in raw.split('/') {
            match component {
                ".." => return None,
                "" | "." => {}
                other => components.push(other),
            }
        }
        let pattern = components.join("/");
        let member_file = if pattern.is_empty() {
            "package.json".to_string()
        } else {
            format!("{pattern}/package.json")
        };
        // `literal_separator` makes `*` stop at `/` while `**` still crosses it, like pnpm.
        let package_json = GlobBuilder::new(&member_file)
            .literal_separator(true)
            .build()
            .ok()?;
        Some(Self {
            pattern,
            package_json,
        })
    }

    /// The normalized pattern text (empty for the workspace root).
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.pattern
    }

    /// The compiled glob matching this pattern's `package.json` files, relative to the root.
    #[must_use]
    pub const fn package_json_glob(&self) -> &Glob {
        &self.package_json
    }

    /// Leading components free of glob metacharacters: the deepest directory every match is
    /// guaranteed to live under.
    #[must_use]
    pub fn literal_prefix(&self) -> PathBuf {
        self.pattern
            .split('/')
            .take_while(|component| !component.is_empty() && !component.contains(GLOB_META))
            .collect()
    }

    /// Whether the pattern can match at unbounded depth.
    #[must_use]
    pub fn is_recursive(&self) -> bool {
        self.pattern.contains("**")
    }

    /// Number of directory levels below [`Self::literal_prefix`] that can hold a matching
    /// `package.json` file, counting the file itself. Meaningless for a recursive pattern.
    #[must_use]
    pub fn levels_below_prefix(&self) -> usize {
        let total = self.pattern.split('/').filter(|c| !c.is_empty()).count();
        total - self.literal_prefix().components().count() + 1
    }
}

/// One `packages:` entry: a pattern selecting members or, with a leading `!`, removing them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PackageGlob {
    /// A pattern whose matches are workspace members.
    Include(WorkspaceGlob),
    /// A `!pattern` entry whose matches are not members even if an include selects them.
    Exclude(WorkspaceGlob),
}

impl PackageGlob {
    /// Parses one `packages:` entry; `None` when the pattern is rejected by
    /// [`WorkspaceGlob::parse`].
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_npm::workspace_members::PackageGlob;
    ///
    /// assert!(matches!(PackageGlob::parse("apps/*"), Some(PackageGlob::Include(_))));
    /// assert!(matches!(PackageGlob::parse("!**/test/**"), Some(PackageGlob::Exclude(_))));
    /// assert!(PackageGlob::parse("!../x").is_none());
    /// ```
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        let raw = raw.trim();
        match raw.strip_prefix('!') {
            Some(rest) => WorkspaceGlob::parse(rest).map(Self::Exclude),
            None => WorkspaceGlob::parse(raw).map(Self::Include),
        }
    }

    /// The pnpm default when `packages:` is absent: the root and every subdirectory.
    #[must_use]
    pub fn defaults() -> Vec<Self> {
        Self::parse("**").into_iter().collect()
    }
}

/// The member-selection half of a `pnpm-workspace.yaml`: where the workspace is rooted and
/// which directories hold its packages.
///
/// # Examples
///
/// ```
/// use deps_npm::workspace_members::{PackageGlob, WorkspaceMembers};
///
/// let members = WorkspaceMembers::new("/repo".into(), PackageGlob::defaults());
/// assert_eq!(members.root(), std::path::Path::new("/repo"));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceMembers {
    root: PathBuf,
    globs: Vec<PackageGlob>,
    globs_truncated: bool,
}

impl WorkspaceMembers {
    /// Builds the member selection for the workspace rooted at `root`.
    #[must_use]
    pub const fn new(root: PathBuf, globs: Vec<PackageGlob>) -> Self {
        Self {
            root,
            globs,
            globs_truncated: false,
        }
    }

    /// Marks the glob list as cut short, so counts derived from it are lower bounds.
    #[must_use]
    pub const fn with_truncated_globs(mut self) -> Self {
        self.globs_truncated = true;
        self
    }

    /// Whether `packages:` had more entries than were kept.
    #[must_use]
    pub const fn globs_truncated(&self) -> bool {
        self.globs_truncated
    }

    /// Directory containing the `pnpm-workspace.yaml`.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The `packages:` entries, in file order.
    #[must_use]
    pub fn globs(&self) -> &[PackageGlob] {
        &self.globs
    }
}

#[cfg(test)]
mod tests {
    use std::assert_matches;

    use super::*;

    #[test]
    fn test_parse_normalizes_dot_slash_and_trailing_slash() {
        assert_eq!(WorkspaceGlob::parse("./a//b/").unwrap().as_str(), "a/b");
        assert_eq!(WorkspaceGlob::parse("a/./b").unwrap().as_str(), "a/b");
        assert_eq!(WorkspaceGlob::parse("./").unwrap().as_str(), "");
        assert_eq!(WorkspaceGlob::parse(".").unwrap().as_str(), "");
    }

    #[test]
    fn test_parse_rejects_escaping_and_malformed_patterns() {
        for raw in [
            "",
            "   ",
            "..",
            "../x",
            "a/../b",
            "a/..",
            "/abs",
            "\\\\server\\share",
            "a\\b",
            "C:/x",
            "c:x",
            "a/b:c",
            "packages/C:",
            "[unclosed",
        ] {
            assert!(
                WorkspaceGlob::parse(raw).is_none(),
                "{raw:?} must be rejected"
            );
        }
    }

    #[test]
    fn test_package_glob_negation_requires_valid_remainder() {
        assert_matches!(
            PackageGlob::parse("!**/test/**"),
            Some(PackageGlob::Exclude(_))
        );
        assert!(PackageGlob::parse("!").is_none());
        assert!(PackageGlob::parse("!../a").is_none());
        assert!(PackageGlob::parse("!/a").is_none());
    }

    #[test]
    fn test_literal_prefix_stops_at_first_pattern_component() {
        let prefix = |raw: &str| WorkspaceGlob::parse(raw).unwrap().literal_prefix();
        assert_eq!(prefix("packages/*"), PathBuf::from("packages"));
        assert_eq!(prefix("a/b/c"), PathBuf::from("a/b/c"));
        assert_eq!(prefix("a/*/c"), PathBuf::from("a"));
        assert_eq!(prefix("**"), PathBuf::new());
        assert_eq!(prefix("."), PathBuf::new());
        assert_eq!(prefix("{a,b}/c"), PathBuf::new());
    }

    #[test]
    fn test_levels_below_prefix_counts_the_package_json_file() {
        let levels = |raw: &str| WorkspaceGlob::parse(raw).unwrap().levels_below_prefix();
        assert_eq!(levels("packages/*"), 2);
        assert_eq!(levels("a/b"), 1);
        assert_eq!(levels("a/*/c"), 3);
        assert_eq!(levels("."), 1);
    }

    #[test]
    fn test_recursive_detection() {
        assert!(WorkspaceGlob::parse("apps/**").unwrap().is_recursive());
        assert!(!WorkspaceGlob::parse("apps/*").unwrap().is_recursive());
    }

    #[test]
    fn test_defaults_select_everything_recursively() {
        let defaults = PackageGlob::defaults();
        assert_eq!(defaults.len(), 1);
        assert_matches!(&defaults[0], PackageGlob::Include(g) if g.is_recursive());
    }
}
