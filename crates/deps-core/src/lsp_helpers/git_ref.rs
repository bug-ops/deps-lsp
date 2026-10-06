//! Shared git-tags-datasource parser scaffolding, extracted from
//! `deps-github-actions`'s originally crate-private `parser.rs`/`formatter.rs` helpers so a
//! second git-tags-shaped ecosystem (GitLab CI) can reuse the same hardened span/text
//! plumbing instead of forking it. `deps-github-actions` now imports these instead of
//! defining them locally.

use super::{BoundedVersionReq, CommentTag, LineOffsetTable, RequirementStatus};
use crate::pagination::ListCoverage;
use crate::position::Range;
use yaml_rust2::parser::Tag;
use yaml_rust2::scanner::{Marker, TScalarStyle};

#[cfg(feature = "lsp-responses")]
use super::diagnostics::MAX_VERSION_DIAGNOSTIC_CHARS;
#[cfg(feature = "lsp-responses")]
use super::{EcosystemFormatter, markdown_code_span, single_file_edit};
#[cfg(feature = "lsp-responses")]
use crate::{Dependency, ParseResult};
#[cfg(feature = "lsp-responses")]
use tower_lsp_server::ls_types::{CodeAction, CodeActionKind, Position, TextEdit, WorkspaceEdit};

/// Length of a full, lowercase-or-not hex commit SHA (git's SHA-1 object id).
pub(super) const SHA_LEN: usize = 40;

/// The conventional 7-character display prefix of a commit SHA (the whole string when shorter).
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::short_sha;
///
/// assert_eq!(short_sha(&"a".repeat(40)), "aaaaaaa");
/// assert_eq!(short_sha("abc"), "abc");
/// ```
#[must_use]
pub fn short_sha(sha: &str) -> &str {
    sha.get(..7).unwrap_or(sha)
}

/// Whether `s` is a 40-character hex string — a git commit SHA shape, shared by every
/// ecosystem resolving refs against a git-tags-datasource API (GitHub, GitLab).
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::is_full_sha;
///
/// assert!(is_full_sha(&"a".repeat(40)));
/// assert!(!is_full_sha(&"a".repeat(39)));
/// assert!(!is_full_sha("not-a-sha"));
/// ```
#[must_use]
pub fn is_full_sha(s: &str) -> bool {
    s.len() == SHA_LEN && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// A validated, lowercase-canonical, full 40-hex-character git commit SHA.
///
/// Equality and hashing are therefore independent of the case a pin was written in:
/// registries report lowercase hex, while a manifest may spell the SHA in uppercase. The
/// only constructor is [`CommitSha::parse`], which routes every value through
/// [`is_full_sha`] — the shared allowlist gate for the one registry-controlled string in
/// each git-tags-datasource ecosystem (GitHub Actions, GitLab CI) that is later spliced
/// verbatim into a manifest text edit and a hover string with no other validation (security
/// S-3). Once constructed, a caller holding a `CommitSha` never needs to re-check it.
#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub struct CommitSha(String);

impl CommitSha {
    /// Validates `s` as a full 40-hex-character commit SHA via [`is_full_sha`].
    ///
    /// The text is stored lowercased: [`is_full_sha`] accepts uppercase hex, and registries
    /// report lowercase, so the canonical form is what makes `CommitSha` values comparable.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::lsp_helpers::CommitSha;
    ///
    /// assert!(CommitSha::parse(&"a".repeat(40)).is_some());
    /// assert!(CommitSha::parse("not-a-sha").is_none());
    /// assert_eq!(CommitSha::parse(&"A".repeat(40)), CommitSha::parse(&"a".repeat(40)));
    /// ```
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        is_full_sha(s).then(|| Self(s.to_ascii_lowercase()))
    }

    /// The validated SHA text, lowercase.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for CommitSha {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Per-repository/per-route tag/SHA cross-reference, shared by every git-tags-datasource
/// ecosystem (GitHub Actions, GitLab CI).
///
/// Populated on every successful tags/releases fetch (the response already carries the
/// commit SHA — zero extra requests). Read by each ecosystem's formatter to resolve a
/// SHA-pin edit's replacement text and by a hover override to resolve a tag or SHA's
/// counterpart for display.
///
/// Fields are `pub` (not `pub(crate)`) so a cross-crate integration test that exercises the
/// shared `deps_core::collect_update_all_edits`/hover machinery — which never itself drives
/// a live registry fetch — can seed a repository's entry directly.
///
/// No constructor beyond [`Default`] and [`Self::from_tags`] is provided: a caller may also
/// build one via `TagIndex::default()` and populate [`Self::tag_to_sha`] directly and the
/// SHA -> tag direction via [`Self::insert_sha_pin`].
#[non_exhaustive]
#[derive(Debug, Default)]
pub struct TagIndex {
    /// Tag/release text (as published) -> the commit SHA it points at.
    pub tag_to_sha: std::collections::HashMap<String, CommitSha>,
    /// Commit SHA -> the tag/release it corresponds to, classified at insertion time so a
    /// tag can never be read back without knowing whether it is a moving alias.
    sha_to_tag: std::collections::HashMap<CommitSha, ResolvedPin>,
    canonical_repo_name: Option<crate::github::CanonicalRepoName>,
    coverage: ListCoverage,
}

/// Other release tags sharing a commit with a [`ResolvedPin`]'s primary tag.
///
/// Each has the same specificity class as the primary (a full-semver release next to a
/// full-semver release, or a `major.minor` release that no other tag extends next to another),
/// so each is as valid a name for the commit as the primary. Pre-release and non-semver tags
/// are never siblings. The list is sorted deterministically (lowest version first) and
/// excludes the primary and spelling duplicates (`4.8.0` next to `v4.8.0`). It can only be
/// built inside `deps-core` from a [`TagIndex`]; a scan receives it only through
/// [`crate::lsp_helpers::InUseVersions`]. [`Default`] is the empty list.
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::{CommitSha, SiblingTags, TagIndex};
///
/// assert!(SiblingTags::default().is_empty());
///
/// let sha = CommitSha::parse(&"a".repeat(40)).unwrap();
/// let index = TagIndex::from_tags([("v4.8.0", &sha), ("v4.9.0", &sha), ("v4.9.1-rc1", &sha)]);
/// let pin = index.resolved_pin(&sha).unwrap();
/// let siblings: Vec<&str> = pin.siblings().iter().map(|t| t.as_str()).collect();
/// assert_eq!(siblings, ["v4.9.0"]);
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SiblingTags(Vec<crate::ConcreteVersion>);

impl SiblingTags {
    pub(crate) fn from_candidates<'a>(
        primary: &str,
        names: impl IntoIterator<Item = &'a str>,
    ) -> Self {
        let class = tag_specificity_rank(primary).0;
        let (kind, _, is_release) = class;
        if !is_release || !matches!(kind, FULL_SEMVER_KIND | PARTIAL_SEMVER_KIND) {
            return Self::default();
        }
        let primary_normalized = crate::github::normalize_tag(primary);
        let mut ranked: Vec<(TagRank<'a>, &'a str)> = names
            .into_iter()
            .map(|n| (tag_specificity_rank(n), n))
            .collect();
        let all: Vec<&str> = ranked.iter().map(|(_, n)| *n).collect();
        ranked.retain(|(rank, n)| {
            rank.0 == class
                && crate::github::normalize_tag(n) != primary_normalized
                && (kind == FULL_SEMVER_KIND
                    || (tag_components(n).all(|c| c.parse::<u64>().is_ok())
                        && !all.iter().any(|other| extends_tag(other, n))))
        });
        ranked.sort_by(|a, b| b.0.cmp(&a.0));
        ranked.dedup_by(|a, b| {
            crate::github::normalize_tag(a.1) == crate::github::normalize_tag(b.1)
        });
        Self(
            ranked
                .into_iter()
                .map(|(_, n)| crate::ConcreteVersion::new(n))
                .collect(),
        )
    }

    /// The sibling tags, lowest version first.
    pub fn iter(&self) -> std::slice::Iter<'_, crate::ConcreteVersion> {
        self.0.iter()
    }

    /// Whether the primary tag is the only release name on its commit.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The number of sibling tags.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.0.len()
    }
}

impl<'a> IntoIterator for &'a SiblingTags {
    type Item = &'a crate::ConcreteVersion;
    type IntoIter = std::slice::Iter<'a, crate::ConcreteVersion>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// A tag resolved from a commit SHA, classified by whether it names a release or is a
/// moving alias of a more specific tag on the same commit.
///
/// Produced by [`TagIndex::resolved_pin`]; consumed by
/// [`crate::lsp_helpers::resolve_in_use_version`], which is the only place that decides
/// whether the tag is precise enough to query a vulnerability database with. Both variants
/// carry the other release tags on the same commit ([`SiblingTags`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolvedPin {
    /// No other tag on the same commit extends this one, so it is the most specific name the
    /// repository published for the commit (`v2.9` next to `v2`, but also a lone `v2`).
    MostSpecific {
        /// The tag text, verbatim as published.
        tag: crate::ConcreteVersion,
        /// Other release tags on the same commit.
        siblings: SiblingTags,
    },
    /// Another tag on the same commit extends this one (`v2` next to `v2.9`): a moving alias.
    Alias {
        /// The tag text, verbatim as published.
        tag: crate::ConcreteVersion,
        /// Other release tags on the same commit.
        siblings: SiblingTags,
    },
}

impl ResolvedPin {
    /// A [`Self::MostSpecific`] pin without siblings.
    #[must_use]
    pub fn most_specific(tag: crate::ConcreteVersion) -> Self {
        Self::MostSpecific {
            tag,
            siblings: SiblingTags::default(),
        }
    }

    /// An [`Self::Alias`] pin without siblings.
    #[must_use]
    pub fn alias(tag: crate::ConcreteVersion) -> Self {
        Self::Alias {
            tag,
            siblings: SiblingTags::default(),
        }
    }

    /// The tag text, verbatim as published.
    #[must_use]
    pub const fn version(&self) -> &crate::ConcreteVersion {
        match self {
            Self::MostSpecific { tag, .. } | Self::Alias { tag, .. } => tag,
        }
    }

    /// Other release tags on the same commit as [`Self::version`].
    #[must_use]
    pub const fn siblings(&self) -> &SiblingTags {
        match self {
            Self::MostSpecific { siblings, .. } | Self::Alias { siblings, .. } => siblings,
        }
    }
}

/// [`tag_specificity_rank`] class kind of a full `major.minor.patch` semver name.
const FULL_SEMVER_KIND: u8 = 2;
/// [`tag_specificity_rank`] class kind of a partial numeric name (`v2`, `v2.9`).
const PARTIAL_SEMVER_KIND: u8 = 1;

/// Sort key of [`tag_specificity_rank`]: class, then numeric version order (lower wins), then name.
type TagRank<'a> = (
    (u8, usize, bool),
    std::cmp::Reverse<Option<semver::Version>>,
    std::cmp::Reverse<Vec<u64>>,
    std::cmp::Reverse<&'a str>,
);

/// Specificity rank of a tag name when several share one commit: a full semver name beats a
/// partial numeric one (more components wins), which beats any non-semver name; within a
/// rank a release beats a pre-release of it, the numerically lower version wins (`v4.9.0`
/// over `v4.10.0`), and the lexicographically smaller name breaks any remaining tie so the
/// choice never depends on fetch order.
///
/// The winner is the commit's primary tag; the other names of its class become its
/// [`SiblingTags`], which the OSV scan evaluates as well.
fn tag_specificity_rank(name: &str) -> TagRank<'_> {
    let normalized = crate::github::normalize_tag(name);
    let is_release = !normalized.contains(['-', '+']);
    let (class, semver, numeric) = if let Ok(v) = semver::Version::parse(normalized) {
        ((FULL_SEMVER_KIND, 0, is_release), Some(v), Vec::new())
    } else if is_partial_semver_shaped(name) {
        let numeric = normalized
            .split(['-', '+'])
            .next()
            .unwrap_or_default()
            .split('.')
            .map(|c| c.parse().unwrap_or(u64::MAX))
            .collect();
        (
            (
                PARTIAL_SEMVER_KIND,
                tag_components(name).count(),
                is_release,
            ),
            None,
            numeric,
        )
    } else {
        ((0, 0, false), None, Vec::new())
    };
    (
        class,
        std::cmp::Reverse(semver),
        std::cmp::Reverse(numeric),
        std::cmp::Reverse(name),
    )
}

fn tag_components(name: &str) -> impl Iterator<Item = &str> {
    crate::github::normalize_tag(name).split('.')
}

/// Whether `longer` extends `shorter` by at least one more dot-separated component.
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::extends_tag;
///
/// assert!(extends_tag("v4.2.2", "v4"));
/// assert!(!extends_tag("v5.0.0", "v4"));
/// assert!(!extends_tag("v4", "v4"));
/// ```
#[must_use]
pub fn extends_tag(longer: &str, shorter: &str) -> bool {
    let mut longer = tag_components(longer);
    tag_components(shorter).all(|c| longer.next() == Some(c)) && longer.next().is_some()
}

/// How a partial release tag (`v4`, `v4.2`) written in a manifest is judged against the newest
/// release by [`tag_pin_is_up_to_date`].
///
/// Exhaustive so each ecosystem states which reading its ref syntax has.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartialTagPolicy {
    /// A partial tag names a moving line that follows the newest release of that line
    /// (GitHub Actions `uses: owner/repo@v4`).
    MovingLine,
    /// A partial tag is just a literal tag name, current only when it is the newest tag.
    Exact,
}

/// Pre-release labels a partial release core may carry (`v2-beta`) and still be ordered.
const PRERELEASE_LABELS: [&str; 10] = [
    "alpha", "beta", "rc", "pre", "preview", "dev", "canary", "next", "nightly", "snapshot",
];

/// Whether `suffix` (starting at `-` or `+`) reads as a pre-release or build marker rather than
/// a variant name such as `-node20`.
fn is_prerelease_suffix(suffix: &str) -> bool {
    let Some(rest) = suffix.strip_prefix('-') else {
        return true;
    };
    let rest = rest.to_ascii_lowercase();
    let (label, tail) = rest.split_at(
        rest.find(|c: char| !c.is_ascii_alphabetic())
            .unwrap_or(rest.len()),
    );
    PRERELEASE_LABELS.contains(&label) && tail.chars().all(|c| c.is_ascii_digit() || c == '.')
}

/// Whether `tag` is a bare partial release: one or two all-digit components, no suffix. A
/// ref without a `v` prefix (`@4`) is one too, unlike a free-text comment token.
fn is_bare_partial_release(tag: &str) -> bool {
    tag_components(tag).count() < 3
        && tag_components(tag).all(|c| !c.is_empty() && c.bytes().all(|b| b.is_ascii_digit()))
}

/// A bare partial release zero-padded to a full version (`v4` -> `4.0.0`).
fn padded_release(tag: &str) -> Option<semver::Version> {
    if !is_bare_partial_release(tag) {
        return None;
    }
    let normalized = crate::github::normalize_tag(tag);
    let padding = ".0".repeat(3usize.checked_sub(tag_components(tag).count())?);
    semver::Version::parse(&format!("{normalized}{padding}")).ok()
}

/// Parses a full-semver `tag` (optional `v`/`V` prefix) with build metadata dropped.
fn comparable_version(tag: &str) -> Option<semver::Version> {
    let mut version = semver::Version::parse(crate::github::normalize_tag(tag)).ok()?;
    version.build = semver::BuildMetadata::EMPTY;
    Some(version)
}

/// Parses `tag` into a precedence-comparable semver version, build metadata dropped.
///
/// A partial release core with a recognized pre-release suffix (`v2-beta`, `v2.1-rc`) is padded
/// to three components (`2.0.0-beta`, `2.1.0-rc`); a bare partial release (`v4`) has no
/// precedence of its own and yields `None`, as does a variant suffix (`v3-node20`).
fn orderable_tag(tag: &str) -> Option<semver::Version> {
    let normalized = crate::github::normalize_tag(tag);
    let mut version = match semver::Version::parse(normalized) {
        Ok(version) => version,
        Err(_) if is_partial_semver_shaped(tag) => {
            let (core, suffix) = normalized.split_at(normalized.find(['-', '+'])?);
            if !is_prerelease_suffix(suffix) {
                return None;
            }
            let padding = ".0".repeat(3usize.checked_sub(core.split('.').count())?);
            semver::Version::parse(&format!("{core}{padding}{suffix}")).ok()?
        }
        Err(_) => return None,
    };
    version.build = semver::BuildMetadata::EMPTY;
    Some(version)
}

/// Whether [`tag_pin_is_up_to_date`] can place `tag` on the version line at all.
///
/// `false` for a tag-shaped ref that is no version (`v1.x`, a release-line branch) or carries a
/// variant suffix (`v3-node20`); an ecosystem whose refs may be branches treats those as
/// unknown rather than outdated.
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::tag_has_precedence;
///
/// assert!(tag_has_precedence("v4"));
/// assert!(tag_has_precedence("v2-beta"));
/// assert!(tag_has_precedence("v4.2.0"));
/// assert!(!tag_has_precedence("v1.x"));
/// assert!(!tag_has_precedence("v3-node20"));
/// ```
#[must_use]
pub fn tag_has_precedence(tag: &str) -> bool {
    is_bare_partial_release(tag) || orderable_tag(tag).is_some()
}

/// Where a version tag written in a manifest sits relative to the newest release `latest`, as
/// decided by [`tag_pin_position`].
///
/// Exhaustive so a consumer must decide what each position means: only [`Self::Behind`] is
/// outdated, and only [`Self::Ahead`] is a claim a complete tag index can disprove.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TagPinPosition {
    /// The same tag as `latest` (ignoring a `v` prefix), or the same version by precedence.
    Equal,
    /// A partial release (`v4`) that follows the line `latest` belongs to, or a tag extending a
    /// less precise `latest`.
    MovingLine,
    /// A version above `latest` by precedence: a pre-release of a newer line, or a bare partial
    /// release whose zero-padded version is strictly higher. Such a tag may not exist at all.
    Ahead,
    /// Below `latest`, or placed on no version line.
    Behind,
}

/// Positions a version tag written in a manifest relative to the newest release `latest`.
///
/// Rules, in order: the same tag (ignoring a `v` prefix) is [`TagPinPosition::Equal`]; under
/// [`PartialTagPolicy::MovingLine`] a partial release (`v4`, `v4.2`) that `latest` extends, and a
/// written tag that extends a less precise `latest`, are [`TagPinPosition::MovingLine`];
/// otherwise both tags are compared by semver precedence, so a pre-release of an older line
/// (`v2-beta` against `v7.0.0`) is [`TagPinPosition::Behind`] while a pin above `latest` is
/// [`TagPinPosition::Ahead`]. A bare partial release whose zero-padded version is strictly
/// ahead of `latest` (`v5` against `v4.9.0`) is `Ahead` too. Anything else without precedence
/// (`v4.x`, a bare partial release under [`PartialTagPolicy::Exact`]) is `Behind`.
#[must_use]
pub(crate) fn tag_pin_position(
    written: &str,
    latest: &str,
    policy: PartialTagPolicy,
) -> TagPinPosition {
    use crate::github::normalize_tag;

    if normalize_tag(written) == normalize_tag(latest) {
        return TagPinPosition::Equal;
    }
    if policy == PartialTagPolicy::MovingLine
        && ((is_bare_partial_release(written) && extends_tag(latest, written))
            || extends_tag(written, latest))
    {
        return TagPinPosition::MovingLine;
    }
    let latest_version = orderable_tag(latest);
    if matches!(
        (padded_release(written), &latest_version),
        (Some(written), Some(latest)) if written > *latest
    ) {
        return TagPinPosition::Ahead;
    }
    match (orderable_tag(written), latest_version) {
        (Some(written), Some(latest)) => match written.cmp(&latest) {
            std::cmp::Ordering::Greater => TagPinPosition::Ahead,
            std::cmp::Ordering::Equal => TagPinPosition::Equal,
            std::cmp::Ordering::Less => TagPinPosition::Behind,
        },
        _ => TagPinPosition::Behind,
    }
}

/// Whether a version tag written in a manifest is at least as new as the newest release `latest`.
///
/// `true` unless `written` is behind `latest`: the same tag, a moving line, or a pin ahead of
/// `latest` (which is not offered a downgrade).
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::{PartialTagPolicy, tag_pin_is_up_to_date};
///
/// assert!(tag_pin_is_up_to_date("v4", "v4.3.1", PartialTagPolicy::MovingLine));
/// assert!(!tag_pin_is_up_to_date("v4", "v4.3.1", PartialTagPolicy::Exact));
/// assert!(!tag_pin_is_up_to_date("v2-beta", "v7.0.0", PartialTagPolicy::MovingLine));
/// assert!(tag_pin_is_up_to_date("v5.0.0-rc.1", "v4.9.0", PartialTagPolicy::Exact));
/// ```
#[must_use]
pub fn tag_pin_is_up_to_date(written: &str, latest: &str, policy: PartialTagPolicy) -> bool {
    tag_pin_position(written, latest, policy) != TagPinPosition::Behind
}

impl TagIndex {
    /// Builds a `TagIndex` from `(name, sha)` pairs, preferring the most specific name when
    /// several entries share one SHA.
    ///
    /// A bare-major moving tag like `v3`/`v4` (or a non-semver release name) is a less
    /// specific name than the precise release the SHA was actually cut from, and the fetch
    /// API's ordering is undocumented, so "first in the response" is not a reliable proxy for
    /// "most specific". The SHA -> tag map therefore ranks the names sharing a SHA: a full
    /// semver name first, then a partial numeric one with more components (`v2.9` over `v2`),
    /// then anything else; a release beats a pre-release of it, and remaining ties resolve
    /// to the smaller name. The chosen name is stored as [`ResolvedPin::Alias`] when another
    /// name on the same SHA still extends it, else as [`ResolvedPin::MostSpecific`].
    /// [`Self::tag_to_sha`] has no such ambiguity (keyed by the caller's own literal ref
    /// text), so it stays a plain first-wins index over `entries`' order.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::lsp_helpers::{CommitSha, TagIndex};
    ///
    /// let sha = CommitSha::parse(&"a".repeat(40)).unwrap();
    /// // "v1" (a bare-major moving tag) is listed before "v0.1.0" (the precise release) —
    /// // the SHA -> tag map must still prefer the more specific name.
    /// let index = TagIndex::from_tags([("v1", &sha), ("v0.1.0", &sha)]);
    /// assert_eq!(index.tag_for_sha(&sha), Some("v0.1.0"));
    /// assert_eq!(index.tag_to_sha.get("v1"), Some(&sha));
    /// ```
    #[must_use]
    pub fn from_tags<'a, I>(entries: I) -> Self
    where
        I: IntoIterator<Item = (&'a str, &'a CommitSha)>,
    {
        let mut index = Self::default();
        let mut names_by_sha: std::collections::HashMap<&CommitSha, Vec<&str>> =
            std::collections::HashMap::new();
        for (name, sha) in entries {
            names_by_sha.entry(sha).or_default().push(name);
            index
                .tag_to_sha
                .entry(name.to_string())
                .or_insert_with(|| sha.clone());
        }
        for (sha, names) in names_by_sha {
            let Some(best) = names
                .iter()
                .copied()
                .max_by_key(|n| tag_specificity_rank(n))
            else {
                continue;
            };
            let siblings = SiblingTags::from_candidates(best, names.iter().copied());
            let tag = crate::ConcreteVersion::new(best);
            let pin = if names.iter().any(|other| extends_tag(other, best)) {
                ResolvedPin::Alias { tag, siblings }
            } else {
                ResolvedPin::MostSpecific { tag, siblings }
            };
            index.sha_to_tag.insert(sha.clone(), pin);
        }
        index
    }

    /// Resolves the exact tag `written` (`v4.8.0`) to a pin whose primary is that tag itself,
    /// with the other release tags of the same major line on its commit as siblings.
    ///
    /// Unlike [`Self::resolved_pin`] the primary is never re-picked: the user wrote that tag.
    /// Tags of other majors on the same commit are not siblings. `None` when `written` is not
    /// in the index.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::lsp_helpers::{CommitSha, TagIndex};
    ///
    /// let sha = CommitSha::parse(&"a".repeat(40)).unwrap();
    /// let index = TagIndex::from_tags([("v4.8.0", &sha), ("v4.9.0", &sha), ("v5.0.0", &sha)]);
    /// let pin = index.resolved_exact_tag("v4.8.0").unwrap();
    /// assert_eq!(pin.version().as_str(), "v4.8.0");
    /// assert_eq!(pin.siblings().len(), 1);
    /// assert!(index.resolved_exact_tag("v9.9.9").is_none());
    /// ```
    #[must_use]
    pub fn resolved_exact_tag(&self, written: &str) -> Option<ResolvedPin> {
        let sha = self.tag_to_sha.get(written)?;
        let major = tag_components(written).next();
        let names: Vec<&str> = self
            .tag_to_sha
            .iter()
            .filter(|(name, other)| *other == sha && tag_components(name).next() == major)
            .map(|(name, _)| name.as_str())
            .collect();
        let siblings = SiblingTags::from_candidates(written, names.iter().copied());
        let tag = crate::ConcreteVersion::new(written);
        Some(if names.iter().any(|other| extends_tag(other, written)) {
            ResolvedPin::Alias { tag, siblings }
        } else {
            ResolvedPin::MostSpecific { tag, siblings }
        })
    }

    /// Attaches the repository's canonical casing as reported by GitHub.
    #[must_use]
    pub fn with_canonical_repo_name(
        mut self,
        name: Option<crate::github::CanonicalRepoName>,
    ) -> Self {
        self.canonical_repo_name = name;
        self
    }

    /// Records whether the fetch that built this index reached the end of the tag list.
    ///
    /// [`Self::default`] and [`Self::from_tags`] start as [`ListCoverage::Complete`].
    #[must_use]
    pub const fn with_coverage(mut self, coverage: ListCoverage) -> Self {
        self.coverage = coverage;
        self
    }

    /// Whether the index covers every tag of the repository, so absence of a SHA is meaningful.
    #[must_use]
    pub const fn coverage(&self) -> ListCoverage {
        self.coverage
    }

    /// The repository's canonical `owner/repo` casing, `None` when no fetched tag confirmed it.
    #[must_use]
    pub const fn canonical_repo_name(&self) -> Option<&crate::github::CanonicalRepoName> {
        self.canonical_repo_name.as_ref()
    }

    /// Records `pin` as the tag resolved for `sha`, replacing any previous entry.
    ///
    /// For callers that build an index by hand (e.g. cross-crate tests) instead of via
    /// [`Self::from_tags`], and so must state the alias classification explicitly.
    pub fn insert_sha_pin(&mut self, sha: CommitSha, pin: ResolvedPin) {
        self.sha_to_tag.insert(sha, pin);
    }

    /// The tag published at `sha`, classified as a release name or a moving alias.
    ///
    /// `None` when no tag points at `sha`.
    #[must_use]
    pub fn resolved_pin(&self, sha: &CommitSha) -> Option<ResolvedPin> {
        self.sha_to_tag.get(sha).cloned()
    }

    /// The tag text published at `sha`, without its alias classification.
    #[must_use]
    pub fn tag_for_sha(&self, sha: &CommitSha) -> Option<&str> {
        self.sha_to_tag.get(sha).map(|pin| pin.version().as_str())
    }

    /// What the index proves about `sha`: the tag naming it, that no release tag names it, that
    /// the comment beside it names another commit, or nothing.
    ///
    /// [`PinResolution::Untagged`] requires a populated, [`ListCoverage::Complete`] index that
    /// lacks `sha`; an empty or truncated index is [`PinResolution::Unresolved`], except that a
    /// [`ListCoverage::Truncated`] index which lacks `sha` yet maps the full-version `comment`
    /// to a different commit is [`PinResolution::CommentContradicted`]. A moving-alias comment
    /// (`# v4`) is never contradicted, since such a tag legitimately drifts.
    ///
    /// A comment naming a full version the truncated index does not list at all (a forged
    /// `# v99.0.0`) is still [`PinResolution::Unresolved`].
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::lsp_helpers::{CommitSha, PinResolution, TagIndex};
    ///
    /// let sha = CommitSha::parse(&"a".repeat(40)).unwrap();
    /// let other = CommitSha::parse(&"b".repeat(40)).unwrap();
    /// let index = TagIndex::from_tags([("v1.0.0", &sha)]);
    /// assert!(matches!(index.pin_resolution(&sha, None), PinResolution::Resolved(_)));
    /// assert_eq!(index.pin_resolution(&other, None), PinResolution::Untagged);
    /// assert_eq!(TagIndex::default().pin_resolution(&other, None), PinResolution::Unresolved);
    /// ```
    #[must_use]
    pub fn pin_resolution(&self, sha: &CommitSha, comment: Option<&CommentTag>) -> PinResolution {
        // TODO(#1766): a truncated index with the SHA and a full-version comment both absent,
        // the comment ahead of latest, is still trusted for status and the GitHub Actions OSV query.
        if let Some(pin) = self.sha_to_tag.get(sha) {
            return PinResolution::Resolved(pin.clone());
        }
        match self.coverage {
            ListCoverage::Complete if !self.is_empty() => PinResolution::Untagged,
            ListCoverage::Complete => PinResolution::Unresolved,
            ListCoverage::Truncated if self.comment_names_other_commit(sha, comment) => {
                PinResolution::CommentContradicted
            }
            ListCoverage::Truncated => PinResolution::Unresolved,
        }
    }

    /// Whether `comment` is a full version that this index maps to a commit other than `sha`.
    ///
    /// Tags are matched by version (`v` prefix and build metadata ignored), so a spelling
    /// variant (`# 2.87.22`, `# V2.87.22`) cannot dodge the check. A comment is contradicted
    /// only when no tag of that version points at `sha`.
    fn comment_names_other_commit(&self, sha: &CommitSha, comment: Option<&CommentTag>) -> bool {
        let Some(wanted) = comment
            .filter(|tag| tag.is_full_version())
            .and_then(|tag| comparable_version(tag.as_str()))
        else {
            return false;
        };
        let mut named_elsewhere = false;
        for (name, commit) in &self.tag_to_sha {
            if comparable_version(name).as_ref() == Some(&wanted) {
                if commit == sha {
                    return false;
                }
                named_elsewhere = true;
            }
        }
        named_elsewhere
    }

    /// Whether the index proves no tag spelled `tag` (with or without a `v` prefix) exists.
    ///
    /// Requires a populated, [`ListCoverage::Complete`] index; an empty or truncated one proves
    /// nothing.
    #[must_use]
    pub(crate) fn proves_tag_absent(&self, tag: &str) -> bool {
        if self.coverage != ListCoverage::Complete || self.is_empty() {
            return false;
        }
        let bare = crate::github::normalize_tag(tag);
        ![tag, bare, &format!("v{bare}")]
            .iter()
            .any(|spelling| self.tag_to_sha.contains_key(*spelling))
    }

    /// Whether `written` sits ahead of `latest` by version and the index proves
    /// no such tag exists, so a mistyped or nonexistent pin (`@v40`) is not current.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::lsp_helpers::{CommitSha, PartialTagPolicy, TagIndex};
    ///
    /// let sha = CommitSha::parse(&"a".repeat(40)).unwrap();
    /// let index = TagIndex::from_tags([("v4.3.1", &sha), ("v5.0.0-rc.1", &sha)]);
    /// let proves = |written| index.proves_ahead_tag_absent(written, "v4.3.1", PartialTagPolicy::MovingLine);
    /// assert!(proves("v40"));
    /// assert!(!proves("v5.0.0-rc.1"));
    /// assert!(!proves("v4"));
    /// ```
    #[must_use]
    pub fn proves_ahead_tag_absent(
        &self,
        written: &str,
        latest: &str,
        policy: PartialTagPolicy,
    ) -> bool {
        tag_pin_position(written, latest, policy) == TagPinPosition::Ahead
            && self.proves_tag_absent(written)
    }

    /// Whether the index holds no tag in either direction.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.tag_to_sha.is_empty() && self.sha_to_tag.is_empty()
    }
}

/// What a repository's [`TagIndex`] proves about a pinned commit, as returned by
/// [`TagIndex::pin_resolution`].
///
/// The variants are exhaustive so a consumer must decide what each means for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinResolution {
    /// No out-of-band evidence (cold cache, truncated or empty index): manifest text may stand
    /// in for the pin's version.
    Unresolved,
    /// A truncated index lacks the commit but maps the comment's full-version tag to another
    /// commit, so the comment is provably wrong and must not stand in for the pin's version.
    CommentContradicted,
    /// A tag names the commit.
    Resolved(ResolvedPin),
    /// The index proves no release tag names the commit, so manifest text (a trailing
    /// comment) must not stand in for its version.
    Untagged,
}

/// Where a tag that names a pinned commit sits relative to the newest release, by version.
///
/// Decided by [`tag_pin_is_up_to_date`] under [`PartialTagPolicy::Exact`]: a commit tagged only
/// by a moving alias (`v1`, `1.1`) is not `latest`'s commit, so the alias counts as
/// [`Self::BelowLatest`] unless its zero-padded version is strictly ahead of `latest`
/// (`v1.10` over `v1.9.0`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TagPosition {
    /// The tag is at or above `latest`: a pre-release of a newer line (`v2.0.0-rc1` over
    /// `1.9.0`) counts, as semver orders it above the older release.
    AtOrAboveLatest,
    /// The tag is below `latest`, or has no version order (`cargo-deny`, `v3-node20`).
    BelowLatest,
}

impl TagPosition {
    /// Positions `tag` relative to `latest`.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::lsp_helpers::TagPosition;
    ///
    /// assert_eq!(TagPosition::of("v1", "v1.5.0"), TagPosition::BelowLatest);
    /// assert_eq!(TagPosition::of("v1.10", "v1.9.0"), TagPosition::AtOrAboveLatest);
    /// assert_eq!(TagPosition::of("cargo-deny", "v1.5.0"), TagPosition::BelowLatest);
    /// ```
    #[must_use]
    pub fn of(tag: &str, latest: &str) -> Self {
        if tag_pin_is_up_to_date(tag, latest, PartialTagPolicy::Exact) {
            Self::AtOrAboveLatest
        } else {
            Self::BelowLatest
        }
    }
}

/// Outcome of looking a full-SHA pin up in a repository's [`TagIndex`] against the newest
/// release, shared by every tags-datasource ecosystem (GitHub Actions, GitLab CI).
///
/// Callers map each variant to their own status policy; the variants are exhaustive so a
/// new outcome forces every consumer to decide.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShaPinLookup {
    /// The SHA is the commit of `latest`, whatever other tags name it.
    LatestCommit,
    /// A tag other than `latest` names the SHA.
    Indexed {
        /// The tag published at the SHA, verbatim.
        tag: crate::ConcreteVersion,
        /// Where `tag` sits relative to `latest` by version.
        position: TagPosition,
    },
    /// The repository's index is populated, [`ListCoverage::Complete`], and no tag points at
    /// the SHA.
    NotIndexed,
    /// The index cannot vouch for the SHA either way: no populated index yet (cold cache), or
    /// the SHA is absent from a [`ListCoverage::Truncated`] index.
    Unverifiable,
    /// A [`ListCoverage::Truncated`] index lacks the SHA but maps the comment's full-version
    /// tag to another commit: the comment is provably wrong, so neither it nor the SHA vouches
    /// for a status. Its [`Self::status`] is `Some(Unresolved)`, not `None` like
    /// [`Self::Unverifiable`], because the comment is provably wrong and so must not be used as
    /// the status fallback.
    CommentContradicted,
}

impl ShaPinLookup {
    /// Looks `sha` up in `index` relative to `latest`.
    ///
    /// A missing or empty `index`, or a SHA absent from a truncated one, yields
    /// [`Self::Unverifiable`], never [`Self::NotIndexed`], so a cold cache or a capped tag
    /// list is not mistaken for proof that the pin is stale. The one exception is a
    /// full-version `comment` that the truncated index maps to a different commit
    /// ([`Self::CommentContradicted`]).
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::ConcreteVersion;
    /// use deps_core::lsp_helpers::{CommitSha, ShaPinLookup, TagIndex};
    ///
    /// let sha = CommitSha::parse(&"A".repeat(40)).unwrap();
    /// let index = TagIndex::from_tags([("v1.0.0", &sha)]);
    /// let latest = ConcreteVersion::new("v1.0.0");
    /// assert_eq!(
    ///     ShaPinLookup::resolve(Some(&index), &sha, &latest, None),
    ///     ShaPinLookup::LatestCommit
    /// );
    /// assert_eq!(
    ///     ShaPinLookup::resolve(None, &sha, &latest, None),
    ///     ShaPinLookup::Unverifiable
    /// );
    /// ```
    #[must_use]
    pub fn resolve(
        index: Option<&TagIndex>,
        sha: &CommitSha,
        latest: &crate::ConcreteVersion,
        comment: Option<&CommentTag>,
    ) -> Self {
        let Some(index) = index.filter(|index| !index.is_empty()) else {
            return Self::Unverifiable;
        };
        if index.tag_to_sha.get(latest.as_str()) == Some(sha) {
            return Self::LatestCommit;
        }
        match index.pin_resolution(sha, comment) {
            PinResolution::Resolved(pin) => Self::Indexed {
                tag: pin.version().clone(),
                position: TagPosition::of(pin.version().as_str(), latest.as_str()),
            },
            PinResolution::Untagged => Self::NotIndexed,
            PinResolution::Unresolved => Self::Unverifiable,
            PinResolution::CommentContradicted => Self::CommentContradicted,
        }
    }

    /// Maps the lookup to a [`RequirementStatus`], or `None` when the caller should fall back
    /// to its own text-based classification (only for [`Self::Unverifiable`]).
    ///
    /// [`Self::LatestCommit`] is up to date. [`Self::Indexed`] is up to date only when its
    /// tag is [`TagPosition::AtOrAboveLatest`]: a commit named
    /// only by an outdated moving tag (`v1`) or by a non-version tag (`cargo-deny`) is not
    /// `latest`'s commit and never reads as current by text; an oversized tag is
    /// `Unresolved`. [`Self::NotIndexed`] is `Outdated`: `latest` comes from the same fetch,
    /// so the pin is provably not `latest`'s commit, whatever a trailing `# tag` comment
    /// claims. [`Self::CommentContradicted`] is `Unresolved`: the comment is wrong, so it must
    /// not be trusted, yet the pin's own age is unknown.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::ConcreteVersion;
    /// use deps_core::lsp_helpers::{CommitSha, RequirementStatus, ShaPinLookup, TagIndex};
    ///
    /// let old = CommitSha::parse(&"a".repeat(40)).unwrap();
    /// let new = CommitSha::parse(&"b".repeat(40)).unwrap();
    /// let index = TagIndex::from_tags([("v1", &old), ("v1.5.0", &new)]);
    /// let latest = ConcreteVersion::new("v1.5.0");
    /// let lookup = ShaPinLookup::resolve(Some(&index), &old, &latest, None);
    /// assert_eq!(lookup.status(), Some(RequirementStatus::Outdated));
    /// assert_eq!(ShaPinLookup::LatestCommit.status(), Some(RequirementStatus::UpToDate));
    /// assert_eq!(ShaPinLookup::Unverifiable.status(), None);
    /// assert_eq!(
    ///     ShaPinLookup::CommentContradicted.status(),
    ///     Some(RequirementStatus::Unresolved)
    /// );
    /// ```
    #[must_use]
    pub fn status(self) -> Option<RequirementStatus> {
        match self {
            Self::LatestCommit => Some(RequirementStatus::UpToDate),
            Self::Indexed { tag, position } => {
                let tag = crate::VersionReq::new(tag.as_str());
                Some(if BoundedVersionReq::new(&tag).is_none() {
                    RequirementStatus::Unresolved
                } else {
                    match position {
                        TagPosition::AtOrAboveLatest => RequirementStatus::UpToDate,
                        TagPosition::BelowLatest => RequirementStatus::Outdated,
                    }
                })
            }
            Self::NotIndexed => Some(RequirementStatus::Outdated),
            Self::CommentContradicted => Some(RequirementStatus::Unresolved),
            Self::Unverifiable => None,
        }
    }
}

/// Whether `s` has the shape of a tag ref: an optional leading `v`/`V` followed by a digit.
///
/// Anything else (that isn't an [`is_full_sha`] SHA) is treated as a branch name — the
/// "honest unknown" side, since a branch cannot be resolved to a concrete version without
/// registry access.
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::is_tag_shaped;
///
/// assert!(is_tag_shaped("v4"));
/// assert!(is_tag_shaped("4.2.0"));
/// assert!(!is_tag_shaped("main"));
/// assert!(!is_tag_shaped(&"a".repeat(40)));
/// ```
#[must_use]
pub fn is_tag_shaped(s: &str) -> bool {
    if is_full_sha(s) {
        return false;
    }
    let stripped = s.strip_prefix(['v', 'V']).unwrap_or(s);
    stripped.starts_with(|c: char| c.is_ascii_digit())
}

/// Whether `s` has the shape of a version safe to trust from free-text context.
///
/// Unlike [`is_tag_shaped`] (safe for a constrained git-ref domain GitHub itself
/// resolves), this is meant for text a human wrote by hand — e.g. a YAML comment.
///
/// An optional leading `v`/`V`, 1-3 dot-separated all-digit components, and an optional
/// `-`/`+` prerelease/build suffix (accepted, not itself validated) — but, unlike
/// `is_tag_shaped`, a bare all-digit token with **no** `v`/`V` prefix and **no** dot
/// (`1234`, `20240501`, `0`) is rejected: nothing in the shape alone distinguishes an
/// unprefixed integer from an arbitrary numeric annotation a human might write in a
/// comment (a ticket number, a date), whereas `owner/repo@1234` as an actual git *ref* has
/// no such ambiguity — GitHub either has a ref named `1234` or it doesn't (issue #907
/// review finding S1: `deps-github-actions`'s SHA-pin trailing-comment parser had used
/// `is_tag_shaped` and silently treated a genuine non-version annotation as a version).
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::is_partial_semver_shaped;
///
/// assert!(is_partial_semver_shaped("v4"));
/// assert!(is_partial_semver_shaped("v2.9"));
/// assert!(is_partial_semver_shaped("4.2.0"));
/// assert!(is_partial_semver_shaped("v4.2.0-beta.1"));
/// assert!(!is_partial_semver_shaped("1234"));
/// assert!(!is_partial_semver_shaped("20240501"));
/// assert!(!is_partial_semver_shaped("0"));
/// assert!(!is_partial_semver_shaped("2024-01-15"));
/// assert!(!is_partial_semver_shaped("main"));
/// ```
#[expect(
    clippy::string_slice,
    reason = "idx comes from str::find(['-', '+']), both ASCII bytes, so it is always a char \
              boundary; strip_prefix(['v', 'V']) likewise only ever removes a single ASCII byte"
)]
#[must_use]
pub fn is_partial_semver_shaped(s: &str) -> bool {
    let has_v_prefix = s.starts_with(['v', 'V']);
    let stripped = s.strip_prefix(['v', 'V']).unwrap_or(s);
    let core = match stripped.find(['-', '+']) {
        Some(idx) => &stripped[..idx],
        None => stripped,
    };
    let parts: Vec<&str> = core.split('.').collect();
    if parts.len() > 3 || (!has_v_prefix && parts.len() < 2) {
        return false;
    }
    parts
        .iter()
        .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
}

/// Rewrites `tag` to match `current`'s leading `v`/`V` prefix style (or lack of one).
///
/// A repository/project can change its tagging convention over time (`4.0.0` -> `v5.0.0`);
/// a formatted replacement should still read naturally against the user's existing pin
/// style rather than silently flipping it.
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::match_v_prefix_style;
///
/// assert_eq!(match_v_prefix_style("v4", "5.0.0"), "v5.0.0");
/// assert_eq!(match_v_prefix_style("4", "v5.0.0"), "5.0.0");
/// ```
#[expect(
    clippy::string_slice,
    reason = "tag[1..] only runs when tag_has_v (an ASCII 'v'/'V' prefix check), so index 1 \
              is always a char boundary"
)]
#[must_use]
pub fn match_v_prefix_style(current: &str, tag: &str) -> String {
    let current_has_v = current.starts_with(['v', 'V']);
    let tag_has_v = tag.starts_with(['v', 'V']);
    match (current_has_v, tag_has_v) {
        (true, false) => format!("v{tag}"),
        (false, true) => tag[1..].to_string(),
        _ => tag.to_string(),
    }
}

/// Whether a plain (unquoted) scalar's text denotes an absent value.
///
/// A completely empty plain scalar (`ref:` with nothing after the colon — the normal
/// mid-typing state in a live editor) is *always* absent, regardless of any tag: `!!str` on
/// no text still means no text was given, not the literal empty string (which needs an
/// actual quoted `""` to express — see the `style == Plain` guard below). For non-empty text
/// (`~`/`null`), an explicit tag matters: untagged or explicitly `tag:yaml.org,2002:null`
/// tagged text still resolves to absent, but any *other* explicit tag (e.g. `!!str`) forces
/// the scalar to that type instead — `!!str null` is the literal string `"null"`, not an
/// absent value.
///
/// The four spellings GitLab's Psych loader treats as null (verified against Ruby Psych
/// 5.3.1 — GitLab's own YAML loader and this function's binding oracle since
/// `deps-gitlab-ci`'s mapping-shaped container-anchor support (spec 058 FR-015) became this
/// function's second consumer): `~`, `null`, `Null`, `NULL`. This is a fixed enumeration, not
/// true case-insensitive matching — `nULL` or `nUll` do **not** match, mirroring Psych's own
/// behavior exactly. Gating on `"~" | "null"` alone (this function's original, `deps-dart`-only,
/// `yaml_rust2::YamlLoader`-mirroring behavior) let a merged-template `ref: NULL` resolve to
/// the literal version string `"NULL"` instead of absent — a plausible-looking wrong
/// version, worse than none (P0).
///
/// A *quoted* empty string (`ref: ""`) is a real, if unusual, explicit value and must not be
/// treated as absent — enforced by the `style == Plain` guard below, not by this list.
///
/// Promoted from `deps-dart/src/parser.rs` (originally private to that crate, and originally
/// scoped only to `yaml_rust2::YamlLoader`'s narrower `"" | "~" | "null"` rule) to
/// `deps-core` once `deps-gitlab-ci`'s mapping-shaped container-anchor support (spec 058
/// FR-015) became its second consumer; `deps-dart` now imports this shared version too,
/// rather than keeping its own duplicate.
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::is_plain_null;
/// use yaml_rust2::scanner::TScalarStyle;
///
/// assert!(is_plain_null(TScalarStyle::Plain, None, ""));
/// assert!(is_plain_null(TScalarStyle::Plain, None, "~"));
/// assert!(is_plain_null(TScalarStyle::Plain, None, "null"));
/// assert!(is_plain_null(TScalarStyle::Plain, None, "Null"));
/// assert!(is_plain_null(TScalarStyle::Plain, None, "NULL"));
/// assert!(!is_plain_null(TScalarStyle::DoubleQuoted, None, ""));
/// assert!(!is_plain_null(TScalarStyle::Plain, None, "v1.0.0"));
/// ```
#[must_use]
pub fn is_plain_null(style: TScalarStyle, tag: Option<&Tag>, value: &str) -> bool {
    if style != TScalarStyle::Plain {
        return false;
    }
    if value.is_empty() {
        return true;
    }
    match tag {
        None => matches!(value, "~" | "null" | "Null" | "NULL"),
        Some(tag) => is_null_tag(tag) && matches!(value, "~" | "null" | "Null" | "NULL"),
    }
}

/// Whether `tag` is YAML's `null` tag, in either form `yaml-rust2`'s scanner produces.
///
/// The `!!null` shorthand resolves to `Tag { handle: "tag:yaml.org,2002:", suffix: "null"
/// }`, but the equivalent verbatim form `!<tag:yaml.org,2002:null>` resolves to `Tag {
/// handle: "", suffix: "tag:yaml.org,2002:null" }` — the whole URI lands in `suffix` with an
/// empty `handle`, since verbatim tags bypass handle resolution entirely.
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::is_null_tag;
/// use yaml_rust2::parser::Tag;
///
/// assert!(is_null_tag(&Tag {
///     handle: "tag:yaml.org,2002:".to_string(),
///     suffix: "null".to_string(),
/// }));
/// assert!(!is_null_tag(&Tag {
///     handle: "tag:yaml.org,2002:".to_string(),
///     suffix: "str".to_string(),
/// }));
/// ```
#[must_use]
pub fn is_null_tag(tag: &Tag) -> bool {
    (tag.handle == "tag:yaml.org,2002:" && tag.suffix == "null")
        || (tag.handle.is_empty() && tag.suffix == "tag:yaml.org,2002:null")
}

/// Resolves a `yaml-rust2` scanner marker's `(line, col)` position into a byte offset in
/// `content`, via a shared, once-per-document [`LineOffsetTable`].
///
/// Deliberately does **not** use `yaml_rust2::scanner::Marker::index()` — despite its own
/// doc comment claiming a byte count, `Scanner::scan_block_scalar_content_line`
/// (`yaml-rust2` 0.12.0's `scanner.rs:1778-1779`) advances `mark.index` by the **byte**
/// length of each block-scalar (`|`/`>`) content line, not its char count, once the
/// scanner's internal 16-char lookahead buffer empties mid-line — which happens on
/// essentially every real content line. Every multi-byte UTF-8 character consumed this way
/// desyncs `index` permanently for the rest of the document (#879). `Marker::line()`/
/// `Marker::col()` are unaffected: `col` resets to `0` on every line break
/// (`Scanner::skip_nl`), so the corruption from one block-scalar content line never carries
/// into a later scalar's own `col` — safe for every value this crate resolves spans for
/// (`uses:`, `ref:`, `project:`, `include:`), none of which are themselves inside a block
/// scalar's own content.
///
/// This `line`/`col`-based resolver is a workaround for an upstream `yaml-rust2` 0.12.0 bug
/// (tracked in #880, not yet reported upstream). Do not simplify this back to
/// `Marker::index()`-based resolution without first checking whether the upstream bug has
/// been fixed.
///
/// `line` is 1-indexed and `col` a 0-indexed **char** count within that line, matching
/// `yaml-rust2`'s own `Marker::line()`/`Marker::col()` *behavior* — note that
/// `yaml_rust2::scanner::Marker::col()`'s own doc comment claims 1-indexed while its `Display`
/// impl prints `col + 1`, i.e. the doc is wrong the same way `index()`'s was; do not "fix" the
/// `col.min(...)`/`.nth(col)` arithmetic below to match that prose. Returns `content.len()` if
/// `line` is past the end of `content`. `line` must be `>= 1` (see `debug_assert!` below) —
/// every marker `yaml-rust2` actually emits satisfies this.
///
/// # Line-ending assumption
///
/// Like every other [`LineOffsetTable`] lookup, this counts only `\n` as a line break. A
/// document using bare `\r` (no `\n`) line endings is out of scope: `yaml-rust2` still
/// advances `mark.line` across such a break (`Scanner::skip_nl`), but `LineOffsetTable::new`
/// never splits on a lone `\r`, so `line` can run past the table's line count for any content
/// after the first line — this function then falls back to `content.len()`, and the caller's
/// [`locate_value_span`] fails to find the value, dropping the candidate (logged at `debug`
/// — see its own doc comment) the same way as any other fallback-scan miss.
/// Bare-`\r` YAML is not a realistic manifest shape; LF and CRLF, which `yaml-rust2` and this
/// crate both handle throughout, are unaffected.
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::{LineOffsetTable, marker_byte_offset};
///
/// let content = "a: b\nc: \u{2014}d\n";
/// let table = LineOffsetTable::new(content);
/// // Line 2 ("c: \u{2014}d"), char column 4 -> the 'd' right after the multi-byte em dash.
/// assert_eq!(marker_byte_offset(content, &table, 2, 4), content.find('d').unwrap());
/// ```
#[must_use]
pub fn marker_byte_offset(
    content: &str,
    table: &LineOffsetTable,
    line: usize,
    col: usize,
) -> usize {
    debug_assert!(line >= 1, "yaml-rust2 marker line is 1-indexed, got 0");
    let Some(line_start) = table.line_start(line.saturating_sub(1)) else {
        return content.len();
    };
    let line_end = table.line_start(line).unwrap_or(content.len());
    let line_text = content.get(line_start..line_end).unwrap_or_default();
    // #742-style fast path: an ASCII line has 1 byte per char, so `col` is already a byte
    // offset — skip the `char_indices()` walk, which made this O(line length) per call.
    let byte_in_line = if table
        .line_is_ascii
        .get(line.saturating_sub(1))
        .copied()
        .unwrap_or(false)
    {
        col.min(line_text.len())
    } else {
        // #882: a naive char_indices().nth(col) walk per call is O(line length); the
        // cached per-line index makes repeat lookups on the same line O(1).
        table.non_ascii_char_byte_offset(line.saturating_sub(1), line_text, col)
    };
    line_start + byte_in_line
}

/// Upper bound, in bytes past `search_from`, on how far [`locate_value_span`]'s fallback
/// scan will search.
///
/// The fallback exists only to correct for `yaml-rust2`'s marker-vs-value quoting offset —
/// a handful of bytes at most for any real manifest value. Leaving the scan unbounded made
/// it an `O(line_length x value_length)` scan over the *rest of the line* regardless of how
/// far away the real match could possibly be: a several-megabyte single-line manifest
/// (comfortably under the crate's YAML expansion-size gate) could cost whole minutes of
/// single-core CPU per `didOpen`/`didChange` (security S-2). Capping the window bounds the
/// fallback's cost independent of line length; a value that genuinely cannot be located
/// within this window is treated the same as any other unlocatable value — the candidate is
/// silently skipped, not an error.
pub const MAX_FALLBACK_SCAN_BYTES: usize = 1024;

/// Finds the byte offset in `content` (searching only within the line starting at
/// `search_from`) where the literal bytes of `value` occur.
///
/// The scanner-reported marker usually points exactly at the value's start for a plain
/// scalar, but may point at the opening quote for a quoted one — rather than
/// reverse-engineering `yaml-rust2`'s exact escaping/quoting byte accounting, this verifies
/// the direct-offset guess first and falls back to a bounded same-line search (see
/// [`MAX_FALLBACK_SCAN_BYTES`]), which is exact for the unescaped ASCII text most manifest
/// values are.
///
/// `is_quoted` disambiguates the empty-value case (see below) — pass
/// [`MarkedScalar::is_quoted`], or the equivalent for a hand-rolled scanner receiver.
///
/// Returns `None` if `search_from` is past the end of `content` (checked first, before the
/// `value.is_empty()` short-circuit below — #673 M2) or `value` cannot be located within
/// the bounded fallback scan — logged at `debug` (value length only, never the value text
/// itself, matching the `warn_rejected_value` convention) so a future resolver miss (e.g.
/// #879's class of bug, or [`marker_byte_offset`]'s documented bare-`\r` gap) is diagnosable
/// instead of vanishing the candidate with zero trace.
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::locate_value_span;
///
/// let content = "prefix xxxxx actions/checkout@v4 suffix";
/// let (start, end) = locate_value_span(content, 0, "actions/checkout@v4", false).unwrap();
/// assert_eq!(&content[start..end], "actions/checkout@v4");
/// ```
#[must_use]
pub fn locate_value_span(
    content: &str,
    search_from: usize,
    value: &str,
    is_quoted: bool,
) -> Option<(usize, usize)> {
    let bytes = content.as_bytes();
    // #673: reject an out-of-bounds search_from before the value.is_empty() check below
    // (#673 M2: otherwise an empty value would return Some((search_from, search_from))).
    if search_from > bytes.len() {
        tracing::debug!(
            search_from,
            content_len = bytes.len(),
            "locate_value_span: search_from past end of content"
        );
        return None;
    }
    if value.is_empty() {
        // #1184: a quoted empty scalar (`""`/`''`) has no content bytes for a fallback
        // scan to anchor on, so the marker's own opening-quote-or-not shape is the only
        // signal available — advance past the quote when the raw marker lands on one.
        // Gated on `is_quoted` (a non-heuristic discriminator from the scanner's own
        // reported style — true only for `SingleQuoted`/`DoubleQuoted`, critic M2), not on
        // the marker byte alone and not on `!is_plain`: a `Plain` empty scalar's marker
        // points at the *next token*, not the value itself, and a `Literal`/`Folded`
        // block scalar's empty body is neither plain nor quoted — both cases have an
        // unrelated next token that can itself happen to be a quote byte, which
        // inferring "quoted" from `!is_plain` alone would incorrectly shift into.
        let corrected = if is_quoted {
            match bytes.get(search_from) {
                Some(b'"' | b'\'') => search_from + 1,
                _ => search_from,
            }
        } else {
            search_from
        };
        return Some((corrected, corrected));
    }
    #[expect(
        clippy::indexing_slicing,
        reason = "every slice/index in this block is bounds-checked by the search_from <= \
                  bytes.len() guard above combined with each expression's own <=/.min(...) clamp"
    )]
    {
        if search_from + value.len() <= bytes.len()
            && &bytes[search_from..search_from + value.len()] == value.as_bytes()
        {
            return Some((search_from, search_from + value.len()));
        }
    }
    // #885: bound the window *before* searching for '\n', not after — searching the whole
    // remainder first reintroduces O(remaining-document-length) cost on one huge line even
    // though the resulting scan_end value is the same either way (min is order-independent).
    let window_end = bytes
        .len()
        .min(search_from.saturating_add(MAX_FALLBACK_SCAN_BYTES));
    #[expect(
        clippy::indexing_slicing,
        reason = "window_end = bytes.len().min(...), and search_from <= bytes.len() from the \
                  guard above, so bytes[search_from..window_end] is always in bounds"
    )]
    let scan_end = bytes[search_from..window_end]
        .iter()
        .position(|&b| b == b'\n')
        .map_or(window_end, |p| search_from + p);
    #[expect(
        clippy::indexing_slicing,
        reason = "scan_end is derived from window_end or a position found within \
                  bytes[search_from..window_end], so it stays within [search_from, window_end]"
    )]
    let haystack = &bytes[search_from..scan_end];
    let needle = value.as_bytes();
    let found = haystack
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|rel| (search_from + rel, search_from + rel + needle.len()));
    if found.is_none() {
        tracing::debug!(
            search_from,
            value_len = needle.len(),
            scan_bytes = scan_end - search_from,
            "locate_value_span: value not found within bounded fallback scan"
        );
    }
    found
}

/// Converts a byte span in `content` into an LSP [`Range`] via `table`.
///
/// `deps-gitlab-ci`'s `make_range` and `deps-github-actions`'s `make_range` closure each
/// defined this exact computation byte-for-byte identically before deps-lsp#908 extracted
/// it here. deps-lsp#927 later routed every other ecosystem crate's byte-span-to-`Range`
/// site through this same function: `deps-cargo`, `deps-pypi`, `deps-gradle`, and
/// `deps-nuget` each keep a thin local adapter for their own span shape (a
/// `toml_span::Span`, or a `(usize, usize)` tuple); `deps-swift` keeps its `make_range`
/// closure, which captures `content`/`line_table` to save two arguments across its ~15
/// call sites; `deps-bundler`, `deps-go`, `deps-maven`, `deps-deno`, and `deps-pypi`'s
/// `requirements.rs` call this directly at each bare inline site (`deps-deno` deleted its
/// own byte-identical `byte_range_to_lsp` rather than keep a pointless delegate); `deps-core`'s
/// own `json_ast` module calls it directly at two sites (`quoted_lsp_range`, plus
/// `dependency_position`'s `ObjectPropName::Word` arm). `deps-dart` is a full adopter as
/// well (see [`MarkedScalar::range`], added by deps-lsp#928) — it does not call this
/// function directly, but `MarkedScalar::range` does, on its behalf.
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::{LineOffsetTable, byte_span_to_range};
///
/// let content = "uses: actions/checkout@v4\n";
/// let table = LineOffsetTable::new(content);
/// let range = byte_span_to_range(content, &table, 6, 26);
/// assert_eq!(range.start.line, 0);
/// assert_eq!(range.start.character, 6);
/// ```
#[must_use]
pub fn byte_span_to_range(
    content: &str,
    table: &LineOffsetTable,
    start: usize,
    end: usize,
) -> Range {
    Range::new(
        table.byte_offset_to_position(content, start),
        table.byte_offset_to_position(content, end),
    )
}

/// A YAML scalar captured directly from `yaml-rust2`'s event stream.
///
/// Holds the scalar's resolved text, its scalar style, and the scanner's own
/// marker — the shape all three `MarkedEventReceiver`-based ecosystem parsers
/// (`deps-dart`, `deps-github-actions`, `deps-gitlab-ci`) build from an
/// `Event::Scalar` payload before resolving a byte span for it.
///
/// Always built via [`MarkedScalar::new`] from a real `&Marker`, never hand-assembled
/// from raw numbers: `line` is 1-indexed and `col` a 0-indexed **char** count, matching
/// `yaml-rust2`'s own `Marker::line()`/`Marker::col()` (see [`marker_byte_offset`]'s
/// docs for why — #879/#882 both trace back to conflating this with a byte count).
///
/// The marker does not always come from the same event as the text/style: `deps-dart`'s
/// `on_alias` (key position) builds a `MarkedScalar` whose marker is the *alias*
/// occurrence's own site but whose text and style are the *anchor* definition's — this is
/// deliberate (the anchor's style is what `is_plain_null` already checked to accept the
/// value), and safe because [`MarkedScalar::span`]/[`MarkedScalar::range`] never read
/// `style`, only `text`/`line`/`col`.
#[derive(Debug, Clone)]
pub struct MarkedScalar {
    text: String,
    style: TScalarStyle,
    line: usize,
    col: usize,
}

impl MarkedScalar {
    /// Builds a `MarkedScalar` from an `Event::Scalar`'s resolved value/style and the
    /// scanner marker it fired at.
    ///
    /// `yaml-rust2`'s `Marker` has no public constructor — a real one is only ever
    /// obtained from a live `MarkedEventReceiver::on_event` callback, as shown here.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::lsp_helpers::MarkedScalar;
    /// use yaml_rust2::parser::{Event, MarkedEventReceiver, Parser};
    /// use yaml_rust2::scanner::{Marker, TScalarStyle};
    ///
    /// struct Scalars(Vec<(String, TScalarStyle, Marker)>);
    /// impl MarkedEventReceiver for Scalars {
    ///     fn on_event(&mut self, event: Event, marker: Marker) {
    ///         if let Event::Scalar(value, style, ..) = event {
    ///             self.0.push((value, style, marker));
    ///         }
    ///     }
    /// }
    ///
    /// let mut receiver = Scalars(Vec::new());
    /// Parser::new_from_str("uses: v4\n")
    ///     .load(&mut receiver, false)
    ///     .unwrap();
    /// let (value, style, marker) = receiver.0[1].clone(); // the value scalar
    /// let scalar = MarkedScalar::new(value, style, &marker);
    /// assert_eq!(scalar.text(), "v4");
    /// assert!(scalar.is_plain());
    /// ```
    #[must_use]
    pub fn new(text: String, style: TScalarStyle, marker: &Marker) -> Self {
        Self {
            text,
            style,
            line: marker.line(),
            col: marker.col(),
        }
    }

    /// The scalar's resolved (dequoted) text.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Consumes the scalar, returning its resolved text.
    #[must_use]
    pub fn into_text(self) -> String {
        self.text
    }

    /// The YAML scalar style (`Plain`, single/double-quoted, literal/folded block).
    #[must_use]
    pub const fn style(&self) -> TScalarStyle {
        self.style
    }

    /// Whether the scalar was written unquoted.
    #[must_use]
    pub fn is_plain(&self) -> bool {
        self.style == TScalarStyle::Plain
    }

    /// Whether the scalar was written with an explicit quote style
    /// (`SingleQuoted`/`DoubleQuoted`).
    ///
    /// Deliberately not `!is_plain()` (critic M2 on #1184): a `Literal`/`Folded` block
    /// scalar (`ref: |`/`ref: >`) is neither plain nor quoted, and its marker has the
    /// same "points at the next token, not the value" shape as a `Plain` scalar's — so
    /// [`Self::span`]'s empty-value quote-correction must key on this method, not on the
    /// negation of [`Self::is_plain`].
    #[must_use]
    pub fn is_quoted(&self) -> bool {
        matches!(
            self.style,
            TScalarStyle::SingleQuoted | TScalarStyle::DoubleQuoted
        )
    }

    /// The scanner marker's 1-indexed line.
    #[must_use]
    pub const fn line(&self) -> usize {
        self.line
    }

    /// The scanner marker's 0-indexed char column.
    #[must_use]
    pub const fn col(&self) -> usize {
        self.col
    }

    /// Resolves this scalar's **raw, untrimmed** byte span within `content`, via
    /// [`marker_byte_offset`] + [`locate_value_span`].
    ///
    /// This is the load-bearing primitive every caller needing a *sub*-span builds
    /// on: `deps-github-actions` needs `owner/repo@ref`'s ref sub-span
    /// (`span_start + before_at_len + 1`) and `deps-gitlab-ci` needs
    /// `component@version`'s name/version sub-spans (`raw_start + prefix.len()`), and
    /// both derive those from *this* span's start, never from a value this function
    /// re-trims itself.
    ///
    /// Deliberately does **not** trim leading/trailing whitespace off the located
    /// span — a caller with its own trim-aware offset arithmetic (`deps-github-actions`'s
    /// UTF-8-boundary guard for a quoted value with non-ASCII padding is the concrete
    /// case) depends on receiving the untrimmed span and re-anchoring its own
    /// downstream offsets to it; trimming here would silently desync that arithmetic.
    /// Returns `None` on the same misses [`locate_value_span`] does (e.g. a folded or
    /// multiline scalar it cannot locate within its bounded fallback scan).
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::lsp_helpers::{LineOffsetTable, MarkedScalar};
    /// use yaml_rust2::parser::{Event, MarkedEventReceiver, Parser};
    /// use yaml_rust2::scanner::{Marker, TScalarStyle};
    ///
    /// struct Scalars(Vec<(String, TScalarStyle, Marker)>);
    /// impl MarkedEventReceiver for Scalars {
    ///     fn on_event(&mut self, event: Event, marker: Marker) {
    ///         if let Event::Scalar(value, style, ..) = event {
    ///             self.0.push((value, style, marker));
    ///         }
    ///     }
    /// }
    ///
    /// let content = "uses: actions/checkout@v4\n";
    /// let mut receiver = Scalars(Vec::new());
    /// Parser::new_from_str(content)
    ///     .load(&mut receiver, false)
    ///     .unwrap();
    /// let (value, style, marker) = receiver.0[1].clone(); // the value scalar
    /// let scalar = MarkedScalar::new(value, style, &marker);
    ///
    /// let table = LineOffsetTable::new(content);
    /// let (start, end) = scalar.span(content, &table).unwrap();
    /// assert_eq!(&content[start..end], "actions/checkout@v4");
    /// ```
    #[must_use]
    pub fn span(&self, content: &str, table: &LineOffsetTable) -> Option<(usize, usize)> {
        let start = marker_byte_offset(content, table, self.line, self.col);
        locate_value_span(content, start, &self.text, self.is_quoted())
    }

    /// Resolves this scalar's raw span (see [`MarkedScalar::span`]) into an LSP
    /// [`Range`] via [`byte_span_to_range`], or `None` on the same miss `span` can
    /// return.
    #[must_use]
    pub fn range(&self, content: &str, table: &LineOffsetTable) -> Option<Range> {
        self.span(content, table)
            .map(|(start, end)| byte_span_to_range(content, table, start, end))
    }
}

/// A successful static "pin to commit SHA" resolution: the dependency's display name, the
/// span of its current ref, and the commit-SHA replacement text for that span.
///
/// A named struct rather than a same-typed `(String, Range, String)` tuple (review finding
/// M3, #1138): `display_name` and `replacement` are both `String`, and a tuple return lets a
/// future [`ShaPinning`] implementor transpose them silently.
#[cfg(feature = "lsp-responses")]
#[derive(Clone, PartialEq, Eq, deps_core::redact_debug::RedactingDebug)]
pub struct ResolvedShaPin {
    /// The dependency's human-readable name, for the quickfix title ("Pin `{display_name}`
    /// to commit SHA").
    #[redact(key)]
    pub display_name: String,
    /// The span of the dependency's current ref — what the edit replaces.
    #[raw]
    pub version_range: Range,
    /// The commit-SHA text (plus any ecosystem-specific trailing comment, e.g. GitHub
    /// Actions' `{sha} # {tag}`) to splice into `version_range`.
    #[raw]
    pub replacement: String,
}

/// Resolves the *static* — warm-`TagIndex`-only, no live fetch — "pin a mutable ref to an
/// immutable commit SHA" quickfix shape.
///
/// Shared by every git-tags-datasource ecosystem (`deps-github-actions`'s `owner/repo@ref`,
/// `deps-gitlab-ci`'s `PinStyle::Tag` include) — see deps-lsp issue #1138. A resolution that
/// needs a live fetch instead of a warm tag index (e.g. GitLab's `component:`
/// `Latest`/`Partial` pin, resolved against a project's published releases) is out of this
/// trait's scope and stays ecosystem-specific.
#[cfg(feature = "lsp-responses")]
pub trait ShaPinning: Send + Sync {
    /// Attempts the static "pin to commit SHA" resolution for `dep`.
    ///
    /// Runs the eligibility check and `TagIndex` lookup in one step, since neither is
    /// meaningful without the other to this trait's callers.
    ///
    /// Returns a [`ResolvedShaPin`] on success. `None` if `dep` is not this ecosystem's own
    /// dependency type, is not a statically-pinnable occurrence (e.g. a mutable branch/SHA
    /// ref, or a non-editable alias token), has no ref span to anchor an edit on, or the
    /// `TagIndex` lookup misses (a registry fetch still in flight).
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::lsp_helpers::{ResolvedShaPin, ShaPinning};
    /// use deps_core::parser::DependencySource;
    /// use deps_core::position::Range;
    /// use deps_core::{Dependency, PackageName, VersionReq};
    /// use std::any::Any;
    ///
    /// struct MockDep {
    ///     name: PackageName,
    /// }
    ///
    /// impl Dependency for MockDep {
    ///     fn name(&self) -> &PackageName {
    ///         &self.name
    ///     }
    ///     fn name_range(&self) -> Range {
    ///         Range::default()
    ///     }
    ///     fn version_requirement(&self) -> Option<&VersionReq> {
    ///         None
    ///     }
    ///     fn version_range(&self) -> Option<Range> {
    ///         Some(Range::default())
    ///     }
    ///     fn source(&self) -> DependencySource {
    ///         DependencySource::Registry
    ///     }
    ///     fn as_any(&self) -> &dyn Any {
    ///         self
    ///     }
    /// }
    ///
    /// struct MockPinning;
    ///
    /// impl ShaPinning for MockPinning {
    ///     fn resolve_static_sha_pin(&self, dep: &dyn Dependency) -> Option<ResolvedShaPin> {
    ///         Some(ResolvedShaPin {
    ///             display_name: dep.name().as_str().to_string(),
    ///             version_range: dep.version_range()?,
    ///             replacement: "a".repeat(40),
    ///         })
    ///     }
    /// }
    ///
    /// let dep = MockDep { name: PackageName::new("owner/repo") };
    /// let resolved = MockPinning.resolve_static_sha_pin(&dep).unwrap();
    /// assert_eq!(resolved.display_name, "owner/repo");
    /// assert_eq!(resolved.replacement.len(), 40);
    /// ```
    fn resolve_static_sha_pin(&self, dep: &dyn Dependency) -> Option<ResolvedShaPin>;
}

/// Maximum character count of the dependency name interpolated into
/// [`build_sha_pin_action`]'s CodeAction title, before truncation with an ellipsis marker.
/// Mirrors `diagnostics::MAX_DIAGNOSTIC_NAME_CHARS`'s and
/// `deps_core::lsp_helpers::MAX_DIAGNOSTIC_VALUE_CHARS`'s numeric bound (#1252 critic
/// follow-up C1) — a separate `= 128` literal, not derived from either, out of #1278's
/// scope (that issue's nine-constant list did not include this one): this is the
/// *primary* `PinStyle::Tag` quickfix title, shared by both `deps-github-actions` and
/// `deps-gitlab-ci`, so it needs the same cap as the diagnostic sinks it sits next to.
#[cfg(feature = "lsp-responses")]
const MAX_SHA_PIN_TITLE_NAME_CHARS: usize = 128;

/// Builds the "Pin `{name}` to commit SHA" [`CodeAction`] for the dependency at `position`.
///
/// The boilerplate `deps-github-actions`'s and `deps-gitlab-ci`'s own `build_sha_pin_action`
/// functions each re-derived byte-for-byte before deps-lsp#1138 moved it here: locate the
/// dependency at `position` through `formatter`'s shared
/// [`PackageRendering::is_position_on_dependency`](super::PackageRendering::is_position_on_dependency)
/// lookup, resolve it via [`ShaPinning::resolve_static_sha_pin`], and wrap the resulting edit
/// into a `WorkspaceEdit`-carrying quickfix tagged with `diagnostic_code` so a client can
/// later associate this action back to its diagnostic.
///
/// Takes a single `formatter: &F` bound by both [`EcosystemFormatter`] and [`ShaPinning`]
/// (review finding M4, #1138) rather than two separate parameters for the same value — every
/// real implementor is one type that implements both traits, and a two-parameter signature
/// let a caller pass mismatched formatters at the two call sites with no compile error.
#[cfg(feature = "lsp-responses")]
#[must_use]
pub fn build_sha_pin_action<F: EcosystemFormatter + ShaPinning>(
    parse_result: &dyn ParseResult,
    position: Position,
    uri: &url::Url,
    formatter: &F,
    diagnostic_code: &'static str,
) -> Option<CodeAction> {
    let dep = parse_result
        .dependencies()
        .into_iter()
        .find(|d| formatter.is_position_on_dependency(*d, position.into()))?;
    let resolved = formatter.resolve_static_sha_pin(dep)?;
    let changes = single_file_edit(uri, resolved.version_range, resolved.replacement);
    let display_name = super::diagnostics::sanitize_and_truncate_for_diagnostic(
        &resolved.display_name,
        MAX_SHA_PIN_TITLE_NAME_CHARS,
    );
    Some(CodeAction {
        title: format!("Pin {display_name} to commit SHA"),
        kind: Some(CodeActionKind::QUICKFIX),
        edit: Some(WorkspaceEdit {
            changes: Some(changes),
            ..Default::default()
        }),
        data: Some(serde_json::json!({
            "diagnostic_codes": [diagnostic_code],
            "diagnostic_range": tower_lsp_server::ls_types::Range::from(resolved.version_range),
        })),
        ..Default::default()
    })
}

/// Builds the [`TextEdit`] for `dep` via [`ShaPinning::resolve_static_sha_pin`].
///
/// The single-dependency step `deps-github-actions`'s and `deps-gitlab-ci`'s own bulk "pin
/// all to SHA" collectors both build on, one dependency at a time, before their own
/// `dedup_overlapping_edits` pass.
#[cfg(feature = "lsp-responses")]
#[must_use]
pub fn sha_pin_text_edit(pinning: &impl ShaPinning, dep: &dyn Dependency) -> Option<TextEdit> {
    let resolved = pinning.resolve_static_sha_pin(dep)?;
    Some(TextEdit {
        range: resolved.version_range.into(),
        new_text: resolved.replacement,
    })
}

/// Inserts a `**Resolved**: `tag` (`sha…`)` line immediately after the shared hover's
/// `**Current**`/`**Requirement**` line (whichever is present), falling back to append.
///
/// Falls back to appending only if neither anchor is found — the byte-for-byte-identical
/// helper `deps-github-actions` and `deps-gitlab-ci` each defined locally, before
/// deps-lsp#1138 moved it here.
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::splice_resolved_line;
///
/// let markdown = "**Current**: `v3`\n\nSome body.";
/// let sha = deps_core::lsp_helpers::CommitSha::parse(&"a".repeat(40)).unwrap();
/// let out = splice_resolved_line(markdown, "v3.0.0", &sha);
/// assert!(out.contains("**Resolved**: `v3.0.0`"));
/// ```
#[cfg(feature = "lsp-responses")]
#[must_use]
pub fn splice_resolved_line(markdown: &str, resolved_tag: &str, sha: &CommitSha) -> String {
    let short_sha = short_sha(sha.as_str());
    // `resolved_tag` is tag-index/registry-controlled and unbounded (#1311), and — like
    // any git tag — has no legitimate use for an invisible/bidi character, so it gets
    // the same `sanitize_invisible`-then-truncate treatment `HoverMarkdown`'s
    // `Name`/`Version` field kinds apply (#1313), via the same combined helper
    // `build_sha_pin_action`'s `display_name` above already uses, at
    // `MAX_VERSION_DIAGNOSTIC_CHARS` (the version-shaped sibling cap).
    let line = format!(
        "**Resolved**: {} ({})",
        markdown_code_span(&super::diagnostics::sanitize_and_truncate_for_diagnostic(
            resolved_tag,
            MAX_VERSION_DIAGNOSTIC_CHARS
        )),
        markdown_code_span(&format!("{short_sha}…"))
    );
    splice_hover_line(markdown, &line)
}

/// Inserts one markdown `line` as its own paragraph after the last present hover anchor
/// (`**Resolved**`, else `**Current**`, else `**Requirement**`), falling back to append.
///
/// Anchoring on `**Resolved**` first keeps a warning line below a previously spliced
/// resolved-tag line. `line` must already be sanitized and contain no paragraph break.
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::splice_hover_line;
///
/// let out = splice_hover_line("**Current**: `v3`\n\nBody.", "**Warning**: careful");
/// assert_eq!(out, "**Current**: `v3`\n\n**Warning**: careful\n\nBody.");
/// ```
#[cfg(feature = "lsp-responses")]
#[expect(
    clippy::string_slice,
    reason = "pos/rel_end/insert_at derive only from find() of ASCII anchors, so every slice \
              below is a char boundary"
)]
#[must_use]
pub fn splice_hover_line(markdown: &str, line: &str) -> String {
    for anchor in ["**Resolved**: ", "**Current**: ", "**Requirement**: "] {
        if let Some(pos) = markdown.find(anchor)
            && let Some(rel_end) = markdown[pos..].find("\n\n")
        {
            let insert_at = pos + rel_end + 2;
            let mut out = String::with_capacity(markdown.len() + line.len() + 2);
            out.push_str(&markdown[..insert_at]);
            out.push_str(line);
            out.push_str("\n\n");
            out.push_str(&markdown[insert_at..]);
            return out;
        }
    }
    format!("{markdown}{line}\n\n")
}

#[cfg(test)]
#[expect(
    clippy::string_slice,
    reason = "fixtures are single-line ASCII literals with hand-computed byte offsets"
)]
mod tests {
    use super::*;
    use std::assert_matches;

    #[test]
    fn test_is_full_sha_accepts_and_rejects() {
        assert!(is_full_sha(&"a".repeat(40)));
        assert!(!is_full_sha(&"a".repeat(39)));
        assert!(!is_full_sha(&"g".repeat(40)));
    }

    #[test]
    fn test_tag_pin_position_table() {
        use PartialTagPolicy::{Exact, MovingLine};
        use TagPinPosition::{Ahead, Behind, Equal, MovingLine as Moving};
        for (written, latest, policy, expected) in [
            ("v4.3.1", "v4.3.1", MovingLine, Equal),
            ("4.3.1", "v4.3.1", Exact, Equal),
            ("v4", "v4.3.1", MovingLine, Moving),
            ("v4", "v4.3.1", Exact, Behind),
            ("v4.3.1.1", "v4.3.1", MovingLine, Moving),
            ("v40", "v4.3.1", MovingLine, Ahead),
            ("v5", "v4.9.0", Exact, Ahead),
            ("v5.0.0-rc.1", "v4.9.0", Exact, Ahead),
            ("v4.3.1+build", "v4.3.1", Exact, Equal),
            ("v2-beta", "v7.0.0", MovingLine, Behind),
            ("v1.x", "v4.3.1", MovingLine, Behind),
            ("v3", "v4.3.1", MovingLine, Behind),
        ] {
            assert_eq!(
                tag_pin_position(written, latest, policy),
                expected,
                "{written} vs {latest} ({policy:?})"
            );
            assert_eq!(
                tag_pin_is_up_to_date(written, latest, policy),
                expected != Behind,
                "{written} vs {latest} ({policy:?})"
            );
        }
    }

    #[test]
    fn test_proves_tag_absent_needs_a_populated_complete_index() {
        let sha = sha_of('a');
        let complete = TagIndex::from_tags([("v4.3.1", &sha)]);
        assert!(complete.proves_tag_absent("v40"));
        assert!(!complete.proves_tag_absent("v4.3.1"));
        assert!(
            !complete.proves_tag_absent("4.3.1"),
            "spelling variant is present"
        );
        let bare = TagIndex::from_tags([("4.3.1", &sha)]);
        assert!(!bare.proves_tag_absent("v4.3.1"));
        let truncated =
            TagIndex::from_tags([("v4.3.1", &sha)]).with_coverage(ListCoverage::Truncated);
        assert!(!truncated.proves_tag_absent("v40"));
        assert!(!TagIndex::default().proves_tag_absent("v40"));
    }

    #[test]
    fn test_proves_ahead_tag_absent_requires_ahead_position() {
        let sha = sha_of('a');
        let index = TagIndex::from_tags([("v4.3.1", &sha), ("v5.0.0", &sha)]);
        let proves = |written| {
            index.proves_ahead_tag_absent(written, "v4.3.1", PartialTagPolicy::MovingLine)
        };
        assert!(proves("v40"));
        assert!(!proves("v5.0.0"), "listed ahead tag");
        assert!(!proves("v4"), "moving line is never ahead");
        assert!(!proves("v3"), "behind is outdated, not absent-ahead");
        assert!(!proves("v4.3.1"));
    }

    fn comment_tag(text: &str) -> CommentTag {
        CommentTag::parse(text).unwrap()
    }

    #[test]
    fn test_pin_resolution_comment_contradicted_only_on_truncated_index() {
        let (pinned, latest) = (sha_of('a'), sha_of('b'));
        let tags = [("v1.1.0", &latest), ("v1", &latest)];
        let index = TagIndex::from_tags(tags);
        let truncated = TagIndex::from_tags(tags).with_coverage(ListCoverage::Truncated);
        let full = comment_tag("v1.1.0");
        assert_eq!(
            truncated.pin_resolution(&pinned, Some(&full)),
            PinResolution::CommentContradicted
        );
        assert_eq!(
            index.pin_resolution(&pinned, Some(&full)),
            PinResolution::Untagged
        );
        for benign in ["v1", "v1.2.0"] {
            assert_eq!(
                truncated.pin_resolution(&pinned, Some(&comment_tag(benign))),
                PinResolution::Unresolved,
                "{benign}"
            );
        }
        assert_eq!(
            truncated.pin_resolution(&pinned, None),
            PinResolution::Unresolved
        );
        assert_eq!(
            truncated.pin_resolution(&latest, Some(&full)),
            truncated.pin_resolution(&latest, None),
            "a pin the index can place is resolved whatever its comment says"
        );
    }

    #[test]
    fn test_pin_resolution_comment_match_ignores_spelling_unless_a_variant_names_the_pin() {
        let (pinned, latest) = (sha_of('a'), sha_of('b'));
        let mut truncated =
            TagIndex::from_tags([("v1.1.0", &latest)]).with_coverage(ListCoverage::Truncated);
        for spelling in ["1.1.0", "V1.1.0", "v1.1.0+meta"] {
            assert_eq!(
                truncated.pin_resolution(&pinned, Some(&comment_tag(spelling))),
                PinResolution::CommentContradicted,
                "{spelling}"
            );
        }
        truncated.tag_to_sha.insert("1.1.0".into(), pinned.clone());
        assert_eq!(
            truncated.pin_resolution(&pinned, Some(&comment_tag("v1.1.0"))),
            PinResolution::Unresolved,
            "a variant tag pointing at the pin means the comment is not contradicted"
        );
    }

    #[test]
    fn test_sha_pin_lookup_comment_contradicted_has_unresolved_status() {
        let (pinned, latest) = (sha_of('a'), sha_of('b'));
        let truncated =
            TagIndex::from_tags([("v1.1.0", &latest)]).with_coverage(ListCoverage::Truncated);
        let comment = comment_tag("1.1.0");
        let newest = crate::ConcreteVersion::new("v1.2.0");
        let lookup = ShaPinLookup::resolve(Some(&truncated), &pinned, &newest, Some(&comment));
        assert_eq!(lookup, ShaPinLookup::CommentContradicted);
        assert_eq!(lookup.status(), Some(RequirementStatus::Unresolved));
        assert_eq!(
            ShaPinLookup::resolve(Some(&truncated), &pinned, &newest, None),
            ShaPinLookup::Unverifiable
        );
    }

    #[test]
    fn test_commit_sha_parse_accepts_and_rejects() {
        assert!(CommitSha::parse(&"a".repeat(40)).is_some());
        assert!(CommitSha::parse("not-a-sha").is_none());
    }

    #[test]
    fn test_commit_sha_parse_canonicalizes_to_lowercase() {
        let upper = CommitSha::parse(&"ABCDEF0123".repeat(4)).unwrap();
        let lower = CommitSha::parse(&"abcdef0123".repeat(4)).unwrap();
        assert_eq!(upper, lower);
        assert_eq!(upper.as_str(), "abcdef0123".repeat(4));
        assert_eq!(upper.to_string(), "abcdef0123".repeat(4));
    }

    #[test]
    fn test_commit_sha_hash_lookup_is_case_independent() {
        let mut map = std::collections::HashMap::new();
        map.insert(CommitSha::parse(&"a".repeat(40)).unwrap(), "v1.0.0");
        let upper = CommitSha::parse(&"A".repeat(40)).unwrap();
        assert_eq!(map.get(&upper), Some(&"v1.0.0"));
    }

    #[test]
    fn test_pin_resolution_variants() {
        let sha = sha_of('a');
        let other = sha_of('b');
        let index = TagIndex::from_tags([("v1.0.0", &sha)]);
        assert_matches!(
            index.pin_resolution(&sha, None),
            PinResolution::Resolved(pin) if pin.version().as_str() == "v1.0.0"
        );
        assert_eq!(index.pin_resolution(&other, None), PinResolution::Untagged);

        let truncated =
            TagIndex::from_tags([("v1.0.0", &sha)]).with_coverage(ListCoverage::Truncated);
        assert_eq!(
            truncated.pin_resolution(&other, None),
            PinResolution::Unresolved
        );
        assert_matches!(
            truncated.pin_resolution(&sha, None),
            PinResolution::Resolved(_)
        );
        assert_eq!(
            TagIndex::default().pin_resolution(&other, None),
            PinResolution::Unresolved
        );
    }

    #[test]
    fn test_tag_has_precedence() {
        for tag in [
            "v4",
            "v4.2",
            "4.2.0",
            "v2-beta",
            "v2.1-rc.1",
            "v3.0.0-rc.1",
            "v2+b5",
        ] {
            assert!(tag_has_precedence(tag), "{tag}");
        }
        for tag in [
            "v1.x",
            "v1.*",
            "v1_2",
            "v3-node20",
            "v1.2-stable",
            "v2-beta.01",
            "main",
        ] {
            assert!(!tag_has_precedence(tag), "{tag}");
        }
    }

    #[test]
    fn test_tag_pin_is_up_to_date_table() {
        use PartialTagPolicy::{Exact, MovingLine};
        let cases = [
            ("v2-beta", "v7.0.0", MovingLine, false),
            ("v3.0.0-rc.1", "v7.0.0", MovingLine, false),
            ("v3.0.0-rc.1", "v3.0.0-rc.1", MovingLine, true),
            ("v4", "v4.3.1", MovingLine, true),
            ("v4", "v4.3.1", Exact, false),
            ("v4.2", "v4.2.5", MovingLine, true),
            ("v4.2", "v4.3.0", MovingLine, false),
            ("v5.0.0-rc.1", "v4.9.0", MovingLine, true),
            ("v5.0.0-rc.1", "v4.9.0", Exact, true),
            ("v8-beta", "v7.0.0", MovingLine, true),
            ("4.2.0", "v4.2.0", MovingLine, true),
            ("v4.x", "v4.3.1", MovingLine, false),
            ("v5", "v4.9.0", MovingLine, true),
            ("v5", "v4.9.0", Exact, true),
            ("v4.10", "v4.9.0", Exact, true),
            ("v4", "v4.0.0", Exact, false),
            ("v3-node20", "v7.0.0", MovingLine, false),
            ("v2-beta.01", "v7.0.0", MovingLine, false),
            ("v4.2.0", "v4", MovingLine, true),
            ("v4.2.0", "v4.2.0+build.5", Exact, true),
            ("v2.1-rc", "v2.1.0", Exact, false),
            ("v1", "v1.3.0", Exact, false),
            ("v4.1.0", "v4.2.0", MovingLine, false),
        ];
        for (written, latest, policy, expected) in cases {
            assert_eq!(
                tag_pin_is_up_to_date(written, latest, policy),
                expected,
                "{written} vs {latest} ({policy:?})"
            );
        }
    }

    #[test]
    fn test_tag_index_from_tags_dedupes_first_wins_for_tag_to_sha() {
        let sha_a = CommitSha::parse(&"a".repeat(40)).unwrap();
        let sha_b = CommitSha::parse(&"b".repeat(40)).unwrap();
        let index = TagIndex::from_tags([("v1.0.0", &sha_a), ("v1.0.0", &sha_b)]);
        assert_eq!(index.tag_to_sha.get("v1.0.0"), Some(&sha_a));
    }

    #[test]
    fn test_tag_index_from_tags_sha_to_tag_prefers_semver_over_bare_moving_tag() {
        let sha = CommitSha::parse(&"a".repeat(40)).unwrap();
        // The moving tag ("v1") listed before the precise release ("v0.1.15") — sha_to_tag
        // must still resolve to the semver-parseable one, regardless of iteration order.
        let index = TagIndex::from_tags([("v1", &sha), ("v0.1.15", &sha)]);
        assert_eq!(index.tag_for_sha(&sha), Some("v0.1.15"));
        assert_eq!(index.tag_to_sha.get("v1"), Some(&sha));
        assert_eq!(index.tag_to_sha.get("v0.1.15"), Some(&sha));
    }

    fn sha_of(c: char) -> CommitSha {
        CommitSha::parse(&c.to_string().repeat(40)).unwrap()
    }

    fn lookup(index: Option<&TagIndex>, sha: &str, latest: &str) -> Option<ShaPinLookup> {
        let sha = CommitSha::parse(sha)?;
        Some(ShaPinLookup::resolve(
            index,
            &sha,
            &crate::ConcreteVersion::new(latest),
            None,
        ))
    }

    #[test]
    fn test_sha_pin_lookup_rejects_non_full_sha() {
        let index = TagIndex::from_tags([("v1.0.0", &sha_of('a'))]);
        for bad in [
            "a".repeat(39),
            "a".repeat(41),
            "g".repeat(40),
            "v1.0.0".to_string(),
        ] {
            assert_eq!(lookup(Some(&index), &bad, "v1.0.0"), None, "{bad}");
        }
        assert_eq!(
            lookup(Some(&index), &"A".repeat(40), "v1.0.0"),
            Some(ShaPinLookup::LatestCommit)
        );
    }

    #[test]
    fn test_sha_pin_lookup_variants() {
        let index = TagIndex::from_tags([
            ("v1.0.0", &sha_of('a')),
            ("v1.1.0", &sha_of('b')),
            ("v1.1", &sha_of('b')),
        ]);
        assert_eq!(
            lookup(Some(&index), &"a".repeat(40), "v1.1.0"),
            Some(ShaPinLookup::Indexed {
                tag: crate::ConcreteVersion::new("v1.0.0"),
                position: TagPosition::BelowLatest,
            })
        );
        assert_eq!(
            lookup(Some(&index), &"c".repeat(40), "v1.1.0"),
            Some(ShaPinLookup::NotIndexed)
        );
        assert_eq!(
            lookup(Some(&TagIndex::default()), &"a".repeat(40), "v1.1.0"),
            Some(ShaPinLookup::Unverifiable)
        );
        assert_eq!(
            lookup(None, &"a".repeat(40), "v1.1.0"),
            Some(ShaPinLookup::Unverifiable)
        );
        assert_eq!(
            lookup(Some(&index), &"b".repeat(40), "v1.1.0"),
            Some(ShaPinLookup::LatestCommit)
        );
    }

    #[test]
    fn test_sha_pin_lookup_truncated_index_only_proves_presence() {
        let index = TagIndex::from_tags([("v1.0.0", &sha_of('a')), ("v1.1.0", &sha_of('b'))])
            .with_coverage(ListCoverage::Truncated);
        assert_eq!(
            lookup(Some(&index), &"c".repeat(40), "v1.1.0"),
            Some(ShaPinLookup::Unverifiable)
        );
        assert_eq!(
            lookup(Some(&index), &"a".repeat(40), "v1.1.0"),
            Some(ShaPinLookup::Indexed {
                tag: crate::ConcreteVersion::new("v1.0.0"),
                position: TagPosition::BelowLatest,
            })
        );
        assert_eq!(
            lookup(Some(&index), &"b".repeat(40), "v1.1.0"),
            Some(ShaPinLookup::LatestCommit)
        );
    }

    #[test]
    fn test_tag_position_table() {
        use TagPosition::{AtOrAboveLatest as At, BelowLatest as Below};
        let cases = [
            ("v1", "v1.5.0", Below),
            ("1.1", "1.1.3", Below),
            ("v1.10", "v1.9.0", At),
            ("v2.0.0-rc1", "1.9.0", At),
            ("v2", "1.9.0", At),
            ("v1", "v1.0.0", Below),
            ("v1.0.0", "1.0.0", At),
            ("v1.2.3-rc1", "v1.2.3", Below),
            ("v1.2.4", "v1.2.3", At),
            ("v1.9.0", "v1.10.0", Below),
            ("cargo-deny", "v1.5.0", Below),
            ("v1-rc1", "v1.5.0", Below),
            ("v1.5.0", "stable", Below),
            ("v99999999999999999999", "v1.5.0", Below),
            ("1.1", "1.1.0", Below),
            ("v1.2", "v1.1.9", At),
            ("v1.2.3+build5", "v1.2.3", At),
            ("v1+build5", "v1.5.0", Below),
            ("v01.2", "v1.1.0", Below),
            ("v01.2.3", "v1.2.3", Below),
            ("v1.2.3", "v01.2.3", Below),
        ];
        for (tag, latest, expected) in cases {
            assert_eq!(TagPosition::of(tag, latest), expected, "{tag} vs {latest}");
        }
    }

    #[test]
    fn test_sha_pin_lookup_indexed_by_outdated_moving_tag_is_outdated() {
        let index = TagIndex::from_tags([("v1", &sha_of('a')), ("v1.5.0", &sha_of('b'))]);
        let found = lookup(Some(&index), &"a".repeat(40), "v1.5.0").unwrap();
        assert_eq!(
            found,
            ShaPinLookup::Indexed {
                tag: crate::ConcreteVersion::new("v1"),
                position: TagPosition::BelowLatest,
            }
        );
        assert_eq!(found.status(), Some(RequirementStatus::Outdated));
    }

    #[test]
    fn test_sha_pin_lookup_indexed_by_prerelease_of_newer_line_is_up_to_date() {
        let index = TagIndex::from_tags([("v2.0.0-rc1", &sha_of('a')), ("1.9.0", &sha_of('b'))]);
        let found = lookup(Some(&index), &"a".repeat(40), "1.9.0").unwrap();
        assert_eq!(found.status(), Some(RequirementStatus::UpToDate));
    }

    #[test]
    fn test_sha_pin_lookup_status_branches() {
        let indexed = |tag: &str, position| ShaPinLookup::Indexed {
            tag: crate::ConcreteVersion::new(tag),
            position,
        };
        assert_eq!(
            indexed("v2.0.0", TagPosition::AtOrAboveLatest).status(),
            Some(RequirementStatus::UpToDate)
        );
        assert_eq!(
            indexed("cargo-deny", TagPosition::BelowLatest).status(),
            Some(RequirementStatus::Outdated)
        );
        let oversized = "v".repeat(super::super::MAX_REQUIREMENT_LEN + 1);
        assert_eq!(
            indexed(&oversized, TagPosition::AtOrAboveLatest).status(),
            Some(RequirementStatus::Unresolved)
        );
        assert_eq!(
            ShaPinLookup::LatestCommit.status(),
            Some(RequirementStatus::UpToDate)
        );
        assert_eq!(
            ShaPinLookup::NotIndexed.status(),
            Some(RequirementStatus::Outdated)
        );
        assert_eq!(ShaPinLookup::Unverifiable.status(), None);
    }

    fn resolved_pin_for(tags: &[&str]) -> Option<ResolvedPin> {
        let sha = CommitSha::parse(&"a".repeat(40)).unwrap();
        let index = TagIndex::from_tags(tags.iter().map(|t| (*t, &sha)));
        index.resolved_pin(&sha)
    }

    /// #1668: `v2.9` next to its moving alias `v2` is the most specific name, regardless of the
    /// order the fetch returned them in.
    #[test]
    fn test_tag_index_two_component_release_beats_moving_major_in_any_order() {
        for tags in [["v2.9", "v2"], ["v2", "v2.9"]] {
            assert_eq!(
                resolved_pin_for(&tags),
                Some(ResolvedPin::most_specific(crate::ConcreteVersion::new(
                    "v2.9"
                ))),
                "{tags:?}"
            );
        }
    }

    #[test]
    fn test_tag_index_full_semver_beats_two_component_and_major() {
        assert_eq!(
            resolved_pin_for(&["v2", "v2.9", "v2.9.1"]),
            Some(ResolvedPin::most_specific(crate::ConcreteVersion::new(
                "v2.9.1"
            )))
        );
    }

    #[test]
    fn test_tag_index_lone_major_is_most_specific_but_a_prefix_of_an_unranked_tag_is_alias() {
        assert_eq!(
            resolved_pin_for(&["v2"]),
            Some(ResolvedPin::most_specific(crate::ConcreteVersion::new(
                "v2"
            )))
        );
        // Four components rank below a partial-semver name but still extend it.
        assert_eq!(
            resolved_pin_for(&["v2.9", "v2.9.1.4"]),
            Some(ResolvedPin::alias(crate::ConcreteVersion::new("v2.9")))
        );
    }

    fn most_specific(tag: &str) -> Option<ResolvedPin> {
        Some(ResolvedPin::most_specific(crate::ConcreteVersion::new(tag)))
    }

    fn sibling_names(pin: &ResolvedPin) -> Vec<&str> {
        pin.siblings().iter().map(|t| t.as_str()).collect()
    }

    /// #1709: other release names on the commit become siblings of the primary, in any order.
    #[test]
    fn test_sibling_tags_collect_other_releases_in_any_order() {
        for tags in [["v4.8.0", "v4.9.0"], ["v4.9.0", "v4.8.0"]] {
            let pin = resolved_pin_for(&tags).unwrap();
            assert_eq!(pin.version().as_str(), "v4.8.0", "{tags:?}");
            assert_eq!(sibling_names(&pin), ["v4.9.0"], "{tags:?}");
        }
    }

    #[test]
    fn test_sibling_tags_are_sorted_lowest_first() {
        let pin = resolved_pin_for(&["v4.10.0", "v4.8.0", "v4.9.0", "v4.11.0"]).unwrap();
        assert_eq!(pin.version().as_str(), "v4.8.0");
        assert_eq!(sibling_names(&pin), ["v4.9.0", "v4.10.0", "v4.11.0"]);
    }

    /// #1709 (M4): aliases, pre-releases, other classes and spelling duplicates are never siblings.
    #[test]
    fn test_sibling_tags_exclude_aliases_prereleases_and_duplicates() {
        let pin = resolved_pin_for(&["v4", "v4.8", "v4.8.0", "v4.9.0-rc1", "4.8.0", "release-x"])
            .unwrap();
        assert_eq!(pin.version().as_str().trim_start_matches('v'), "4.8.0");
        assert!(pin.siblings().is_empty(), "{:?}", pin.siblings());
    }

    /// #1709: spelling duplicates among siblings collapse to one entry.
    #[test]
    fn test_sibling_tags_dedupe_spelling_variants_among_siblings() {
        let pin = resolved_pin_for(&["v4.8.0", "v4.9.0", "4.9.0"]).unwrap();
        assert_eq!(pin.version().as_str(), "v4.8.0");
        assert_eq!(pin.siblings().len(), 1);
    }

    /// #1709 (G7): two-component releases are siblings unless another tag extends them.
    #[test]
    fn test_sibling_tags_two_component_releases() {
        let pin = resolved_pin_for(&["v2.9", "v2.10"]).unwrap();
        assert_eq!(sibling_names(&pin), ["v2.10"]);
        let pin = resolved_pin_for(&["v2.9", "v2.10", "v2.10.0.1"]).unwrap();
        assert_eq!(pin.version().as_str(), "v2.9");
        assert!(pin.siblings().is_empty());
    }

    /// #1709: a prerelease primary has no siblings, not even other prereleases.
    #[test]
    fn test_sibling_tags_prerelease_primary_has_none() {
        let pin = resolved_pin_for(&["v4.9.0-rc1", "v4.9.0-rc2"]).unwrap();
        assert!(pin.siblings().is_empty());
    }

    /// #1709: an alias winner (extended by a non-semver 4-component name) keeps its siblings.
    #[test]
    fn test_sibling_tags_alias_winner_keeps_siblings() {
        let pin = resolved_pin_for(&["v1.2.3", "v1.2.4", "v1.2.3.1"]).unwrap();
        assert!(matches!(pin, ResolvedPin::Alias { .. }));
        assert_eq!(pin.version().as_str(), "v1.2.3");
        assert_eq!(sibling_names(&pin), ["v1.2.4"]);
    }

    /// #1709/#1719: the written exact tag stays primary; only its major line's releases on the
    /// same commit are siblings.
    #[test]
    fn test_resolved_exact_tag_keeps_written_primary_and_same_major_siblings() {
        let sha = CommitSha::parse(&"a".repeat(40)).unwrap();
        let other = CommitSha::parse(&"b".repeat(40)).unwrap();
        let index = TagIndex::from_tags([
            ("v4.9.0", &sha),
            ("v4.8.0", &sha),
            ("v5.0.0", &sha),
            ("v4.7.0", &other),
        ]);
        let pin = index.resolved_exact_tag("v4.9.0").unwrap();
        assert_eq!(pin.version().as_str(), "v4.9.0");
        assert_eq!(sibling_names(&pin), ["v4.8.0"]);
        assert_eq!(index.resolved_exact_tag("v9.9.9"), None);
    }

    /// #1709: an exact tag extended by another name on its commit is an alias primary; a
    /// differently spelled twin on the commit is not a sibling.
    #[test]
    fn test_resolved_exact_tag_alias_and_spelling_twin() {
        let sha = CommitSha::parse(&"a".repeat(40)).unwrap();
        let index = TagIndex::from_tags([("v4.8.0", &sha), ("v4.8.0.1", &sha), ("4.8.0", &sha)]);
        let pin = index.resolved_exact_tag("v4.8.0").unwrap();
        assert!(matches!(pin, ResolvedPin::Alias { .. }));
        assert!(pin.siblings().is_empty());
    }

    /// A pre-release never beats its own release, in either fetch order (#1668 critic).
    #[test]
    fn test_tag_index_release_beats_prerelease_in_any_order() {
        for tags in [["v2.9-rc1", "v2.9"], ["v2.9", "v2.9-rc1"]] {
            assert_eq!(resolved_pin_for(&tags), most_specific("v2.9"), "{tags:?}");
        }
        for tags in [["v2.9.1-rc1", "v2.9.1"], ["v2.9.1", "v2.9.1-rc1"]] {
            assert_eq!(resolved_pin_for(&tags), most_specific("v2.9.1"), "{tags:?}");
        }
    }

    /// #1703: equally specific releases on one commit resolve to the numerically lowest one,
    /// not to whichever name sorts first as text (`v4.10.0` < `v4.9.0` textually).
    #[test]
    fn test_tag_index_lowest_semver_release_wins_in_any_order() {
        for (tags, expected) in [
            (["v4.9.0", "v4.10.0"], "v4.9.0"),
            (["v4.10.0", "v4.9.0"], "v4.9.0"),
            (["v2.9", "v2.10"], "v2.9"),
            (["v2.10", "v2.9"], "v2.9"),
            (["v4.8.0", "v4.9.0"], "v4.8.0"),
            (["v4.9.0", "v4.8.0"], "v4.8.0"),
        ] {
            let pin = resolved_pin_for(&tags).unwrap();
            assert_eq!(pin.version().as_str(), expected, "{tags:?}");
            assert!(matches!(pin, ResolvedPin::MostSpecific { .. }), "{tags:?}");
        }
    }

    #[test]
    fn test_tag_index_prerelease_ordering_and_release_precedence() {
        for tags in [
            ["v1.0.0-rc.2", "v1.0.0-rc.10"],
            ["v1.0.0-rc.10", "v1.0.0-rc.2"],
        ] {
            assert_eq!(
                resolved_pin_for(&tags),
                most_specific("v1.0.0-rc.2"),
                "{tags:?}"
            );
        }
        assert_eq!(
            resolved_pin_for(&["v4.10.0-rc1", "v4.9.0"]),
            most_specific("v4.9.0")
        );
    }

    #[test]
    fn test_tag_index_non_semver_and_overflowing_components_stay_deterministic() {
        for tags in [["nightly", "edge"], ["edge", "nightly"]] {
            assert_eq!(resolved_pin_for(&tags), most_specific("edge"), "{tags:?}");
        }
        let huge = "v99999999999999999999999.1";
        for tags in [[huge, "v2.9"], ["v2.9", huge]] {
            assert_eq!(resolved_pin_for(&tags), most_specific("v2.9"), "{tags:?}");
        }
    }

    #[test]
    fn test_tag_index_full_semver_prerelease_beats_two_component() {
        assert_eq!(
            resolved_pin_for(&["v2.9", "v2.9.0-beta"]),
            most_specific("v2.9.0-beta")
        );
    }

    #[test]
    fn test_tag_index_unprefixed_tags_rank_like_prefixed() {
        for tags in [["2.9", "2"], ["2", "2.9"]] {
            assert_eq!(resolved_pin_for(&tags), most_specific("2.9"), "{tags:?}");
        }
        assert_eq!(resolved_pin_for(&["2"]), most_specific("2"));
    }

    #[test]
    fn test_tag_index_numeric_tag_beats_non_numeric_and_lone_non_numeric_wins() {
        assert_eq!(resolved_pin_for(&["cargo-deny", "v2"]), most_specific("v2"));
        assert_eq!(
            resolved_pin_for(&["nightly", "v2.9"]),
            most_specific("v2.9")
        );
        assert_eq!(resolved_pin_for(&["nightly"]), most_specific("nightly"));
    }

    #[test]
    fn test_tag_index_empty_input_yields_empty_index() {
        let index = TagIndex::from_tags(std::iter::empty());
        assert!(index.is_empty());
        assert_eq!(index.resolved_pin(&sha_of('a')), None);
    }

    #[test]
    fn test_tag_index_classifies_each_sha_independently() {
        let a = CommitSha::parse(&"a".repeat(40)).unwrap();
        let b = CommitSha::parse(&"b".repeat(40)).unwrap();
        let index = TagIndex::from_tags([("v2", &a), ("v2.9", &a), ("v3", &b)]);
        assert_eq!(index.resolved_pin(&a), most_specific("v2.9"));
        assert_eq!(index.resolved_pin(&b), most_specific("v3"));
    }

    #[test]
    fn test_tag_index_alias_is_classified_and_insert_sha_pin_overrides() {
        let sha = CommitSha::parse(&"a".repeat(40)).unwrap();
        let mut index = TagIndex::from_tags([("v2.9", &sha), ("v2.9.1.4", &sha)]);
        assert_eq!(
            index.resolved_pin(&sha),
            Some(ResolvedPin::alias(crate::ConcreteVersion::new("v2.9")))
        );
        assert_eq!(index.tag_for_sha(&sha), Some("v2.9"));
        index.insert_sha_pin(
            sha.clone(),
            ResolvedPin::most_specific(crate::ConcreteVersion::new("v3.0")),
        );
        assert_eq!(index.resolved_pin(&sha), most_specific("v3.0"));
    }

    #[test]
    fn test_extends_tag() {
        assert!(extends_tag("v2.9", "v2"));
        assert!(extends_tag("2.9.1", "v2.9"));
        assert!(!extends_tag("v2.10", "v2.1"));
        assert!(!extends_tag("v2", "v2"));
        assert!(!extends_tag("v2", "v2.9"));
        assert!(!extends_tag("v3.9", "v2"));
    }

    #[test]
    fn test_tag_index_resolved_pin_none_for_unknown_sha() {
        assert_eq!(TagIndex::default().resolved_pin(&sha_of('b')), None);
    }

    #[test]
    fn test_is_tag_shaped() {
        assert!(is_tag_shaped("v4"));
        assert!(is_tag_shaped("4.2.0"));
        assert!(!is_tag_shaped("main"));
        assert!(!is_tag_shaped(&"a".repeat(40)));
    }

    #[test]
    fn test_is_partial_semver_shaped_accepts_v_prefixed_at_any_precision() {
        assert!(is_partial_semver_shaped("v4"));
        assert!(is_partial_semver_shaped("v2.9"));
        assert!(is_partial_semver_shaped("v4.2.0"));
        assert!(is_partial_semver_shaped("v4.2.0-beta.1"));
        assert!(is_partial_semver_shaped("v4.2.0+build.5"));
        assert!(is_partial_semver_shaped("V4"));
    }

    #[test]
    fn test_is_partial_semver_shaped_accepts_dotted_without_v_prefix() {
        assert!(is_partial_semver_shaped("2.9"));
        assert!(is_partial_semver_shaped("4.2.0"));
    }

    #[test]
    fn test_is_partial_semver_shaped_rejects_bare_unprefixed_integer() {
        // #907 review S1: a bare all-digit token (ticket number, date) is indistinguishable
        // from a version, so it must be rejected here unlike `is_tag_shaped`.
        assert!(!is_partial_semver_shaped("1234"));
        assert!(!is_partial_semver_shaped("20240501"));
        assert!(!is_partial_semver_shaped("0"));
    }

    #[test]
    fn test_is_partial_semver_shaped_rejects_dash_separated_date_and_branch_names() {
        assert!(!is_partial_semver_shaped("2024-01-15"));
        assert!(!is_partial_semver_shaped("main"));
        assert!(!is_partial_semver_shaped(&"a".repeat(40)));
    }

    #[test]
    fn test_is_partial_semver_shaped_rejects_too_many_components() {
        assert!(!is_partial_semver_shaped("v1.2.3.4"));
    }

    #[test]
    fn test_match_v_prefix_style() {
        assert_eq!(match_v_prefix_style("v4", "5.0.0"), "v5.0.0");
        assert_eq!(match_v_prefix_style("4", "v5.0.0"), "5.0.0");
        assert_eq!(match_v_prefix_style("v4", "v5.0.0"), "v5.0.0");
        assert_eq!(match_v_prefix_style("4", "5.0.0"), "5.0.0");
    }

    #[test]
    fn test_locate_value_span_finds_value_within_fallback_bound() {
        let content = "prefix xxxxx actions/checkout@v4 suffix";
        let value = "actions/checkout@v4";
        let (start, end) = locate_value_span(content, 0, value, false).unwrap();
        assert_eq!(&content[start..end], value);
    }

    #[test]
    fn test_locate_value_span_out_of_bounds_search_from_rejected_even_with_empty_value() {
        // #673 M2: the `search_from > bytes.len()` guard must run before the
        // `value.is_empty()` early return, or this returned `Some((usize::MAX, usize::MAX))`.
        let content = "short";
        assert_eq!(locate_value_span(content, usize::MAX, "", false), None);
        assert_eq!(
            locate_value_span(content, content.len() + 1, "", false),
            None
        );
    }

    #[test]
    fn test_locate_value_span_empty_value_corrects_past_opening_double_quote() {
        // #1180: the raw marker for `pkg: ""` lands on the opening `"`, one byte before the
        // actual (empty) value slot between the quotes.
        let content = r#"pkg: """#;
        let quote_offset = content.find('"').unwrap();
        let (start, end) = locate_value_span(content, quote_offset, "", true).unwrap();
        assert_eq!(start, quote_offset + 1);
        assert_eq!(end, quote_offset + 1);
    }

    #[test]
    fn test_locate_value_span_empty_value_corrects_past_opening_single_quote() {
        let content = "ref: ''";
        let quote_offset = content.find('\'').unwrap();
        let (start, end) = locate_value_span(content, quote_offset, "", true).unwrap();
        assert_eq!(start, quote_offset + 1);
        assert_eq!(end, quote_offset + 1);
    }

    #[test]
    fn test_locate_value_span_empty_value_at_non_quote_position_is_unchanged() {
        // A plain (unquoted) empty value has no opening quote to correct past — the marker
        // already points at the right (empty) slot, e.g. `ref:` with nothing after it.
        let content = "ref: ";
        let end_offset = content.len();
        let (start, end) = locate_value_span(content, end_offset, "", false).unwrap();
        assert_eq!(start, end_offset);
        assert_eq!(end, end_offset);
    }

    #[test]
    fn test_locate_value_span_plain_empty_value_never_shifts_past_a_next_token_quote() {
        // #1184 Gap 1: for a Plain empty scalar the marker points at the *next token*,
        // not the value itself — if that next token happens to start with a quote byte,
        // `is_quoted: false` must still suppress the quote-correction, unlike the quoted
        // case above where the byte-at-marker really is the value's own opening quote.
        let content = "ref: \n\"next-token\"";
        let marker_offset = content.find('\n').unwrap() + 1;
        assert_eq!(content.as_bytes()[marker_offset], b'"');
        let (start, end) = locate_value_span(content, marker_offset, "", false).unwrap();
        assert_eq!(start, marker_offset);
        assert_eq!(end, marker_offset);
    }

    #[test]
    fn test_locate_value_span_literal_style_empty_value_never_shifts_past_a_next_token_quote() {
        // #1184 critic M2: a `Literal`/`Folded` block scalar's empty body is neither
        // `Plain` nor quoted — the old `!is_plain` gate would have wrongly performed the
        // quote-correction here (`is_plain()` is `false` for `Literal` too). `is_quoted`
        // must be keyed on the actual quote styles, not the negation of `is_plain`.
        let content = "ref: |\n\"next-token\"";
        let marker_offset = content.find('\n').unwrap() + 1;
        assert_eq!(content.as_bytes()[marker_offset], b'"');
        let (start, end) = locate_value_span(content, marker_offset, "", false).unwrap();
        assert_eq!(start, marker_offset);
        assert_eq!(end, marker_offset);
    }

    #[test]
    fn test_marked_scalar_span_quoted_empty_value_anchors_after_opening_quote() {
        // End-to-end regression for #1180: `MarkedScalar::span` (via `locate_value_span`)
        // must anchor a quoted empty scalar's span at the actual value slot, not the
        // opening quote one column early — reproduces deps-dart's `pkg: ""` and
        // deps-gitlab-ci's `ref: ""`.
        use yaml_rust2::parser::{Event, MarkedEventReceiver, Parser};

        struct Scalars(Vec<(String, TScalarStyle, Marker)>);
        impl MarkedEventReceiver for Scalars {
            fn on_event(&mut self, event: Event, marker: Marker) {
                if let Event::Scalar(value, style, ..) = event {
                    self.0.push((value, style, marker));
                }
            }
        }

        let content = "pkg: \"\"\n";
        let mut receiver = Scalars(Vec::new());
        Parser::new_from_str(content)
            .load(&mut receiver, false)
            .unwrap();
        // receiver.0[0] is the key scalar ("pkg"), receiver.0[1] is the value.
        let (value, style, marker) = receiver.0[1].clone();
        assert_eq!(value, "");
        let scalar = MarkedScalar::new(value, style, &marker);
        let table = LineOffsetTable::new(content);
        let (start, end) = scalar.span(content, &table).unwrap();
        let quote_offset = content.find("\"\"").unwrap();
        assert_eq!(
            (start, end),
            (quote_offset + 1, quote_offset + 1),
            "expected the empty value's span to anchor between the quotes, not on the \
             opening quote"
        );
    }

    #[test]
    fn test_marked_scalar_is_quoted_distinguishes_literal_from_plain_and_quoted() {
        // #1184 critic M2: `is_quoted()` must be `false` for `Literal`/`Folded`, same as
        // `Plain` — not the negation of `is_plain()`, which was `true` for `Literal` too.
        use yaml_rust2::parser::{Event, MarkedEventReceiver, Parser};

        struct Scalars(Vec<(String, TScalarStyle, Marker)>);
        impl MarkedEventReceiver for Scalars {
            fn on_event(&mut self, event: Event, marker: Marker) {
                if let Event::Scalar(value, style, ..) = event {
                    self.0.push((value, style, marker));
                }
            }
        }

        let content = "ref: |\n";
        let mut receiver = Scalars(Vec::new());
        Parser::new_from_str(content)
            .load(&mut receiver, false)
            .unwrap();
        let (value, style, marker) = receiver.0[1].clone();
        assert_eq!(style, TScalarStyle::Literal);
        let scalar = MarkedScalar::new(value, style, &marker);
        assert!(!scalar.is_plain());
        assert!(
            !scalar.is_quoted(),
            "a Literal block scalar is neither plain nor quoted"
        );
    }

    #[test]
    fn test_locate_value_span_gives_up_beyond_fallback_bound_instead_of_hanging() {
        let filler = "x".repeat(MAX_FALLBACK_SCAN_BYTES + 100);
        let value = "actions/checkout@v4";
        let content = format!("{filler}{value}");
        assert_eq!(locate_value_span(&content, 0, value, false), None);
    }

    #[test]
    fn test_locate_value_span_bounded_scan_stays_fast_on_a_huge_line() {
        // Regression guard (security S-2): a several-megabyte single-line haystack must
        // resolve in milliseconds, not minutes, once the scan is bounded.
        let filler = "y".repeat(6 * 1024 * 1024);
        let value = "not-present-in-filler@v4";
        let content = format!("{filler}\n");
        let start = std::time::Instant::now();
        let result = locate_value_span(&content, 0, value, false);
        assert!(
            start.elapsed() < std::time::Duration::from_secs(1),
            "locate_value_span took {:?}, expected a bounded scan to finish in well under 1s",
            start.elapsed()
        );
        assert_eq!(result, None);
    }

    #[test]
    fn test_locate_value_span_many_fallback_scans_on_one_huge_line_stay_bounded() {
        // Regression for #885 (S2): each fallback-triggering call on one huge physical line
        // used to cost O(remaining-document-length) despite the cap. Simulates many
        // fallback-forcing lookups on one multi-megabyte single-line manifest.
        let filler_segment = "z".repeat(64);
        let mut content = String::new();
        let mut offsets = Vec::new();
        for _ in 0..2000 {
            offsets.push(content.len());
            content.push_str(&filler_segment);
        }
        content.push_str(&"w".repeat(8 * 1024 * 1024));
        let value = "actions/checkout@v4";

        let start = std::time::Instant::now();
        for &offset in &offsets {
            let _ = locate_value_span(&content, offset, value, false);
        }
        let elapsed = start.elapsed();
        assert!(
            elapsed < std::time::Duration::from_secs(1),
            "{} locate_value_span fallback calls against an 8MB-tail single line took \
             {elapsed:?}; expected the pre-bound window to make each call's cost \
             independent of the trailing content size",
            offsets.len()
        );
    }

    #[test]
    fn test_marker_byte_offset_ascii() {
        let content = "hello\nworld";
        let table = LineOffsetTable::new(content);
        assert_eq!(marker_byte_offset(content, &table, 1, 0), 0);
        assert_eq!(marker_byte_offset(content, &table, 2, 3), 9);
    }

    #[test]
    fn test_marker_byte_offset_multibyte() {
        let content = "\u{3000}a\nb";
        let table = LineOffsetTable::new(content);
        // U+3000 is 3 bytes; the second char ('a') on line 1 starts at byte 3.
        assert_eq!(marker_byte_offset(content, &table, 1, 1), 3);
        // Line 2 ('b') starts right after the '\n'.
        assert_eq!(marker_byte_offset(content, &table, 2, 0), 5);
    }

    #[test]
    fn test_marker_byte_offset_block_scalar_drift_regression() {
        // #879: a non-ASCII char inside a `|` block scalar must not desync the byte offset
        // resolved for a later scalar — reproduces the yaml-rust2 Marker::index() drift.
        let content = "run: |\n  echo \u{2014} hi\nuses: actions/checkout@v4\n";
        let table = LineOffsetTable::new(content);
        // Line 3, col 6 is where "actions/checkout@v4" starts (after "uses: ").
        let expected = content.find("actions/checkout@v4").unwrap();
        assert_eq!(marker_byte_offset(content, &table, 3, 6), expected);
    }

    #[test]
    fn test_marker_byte_offset_line_past_end_returns_content_len() {
        let content = "hello";
        let table = LineOffsetTable::new(content);
        assert_eq!(marker_byte_offset(content, &table, 5, 0), content.len());
    }

    #[test]
    fn test_marker_byte_offset_multiple_multibyte_chars_before_target_col() {
        // Each multi-byte char before the target col must count as one *char*, not its byte
        // length, when walking to `col` (#879's failure mode, direct on the resolver).
        let content = "\u{2014}\u{2014}\u{3000}target";
        let table = LineOffsetTable::new(content);
        // 3 leading multi-byte chars (3 + 3 + 3 = 9 bytes), then "target" starts at char
        // column 3.
        assert_eq!(marker_byte_offset(content, &table, 1, 3), 9);
    }

    #[test]
    fn test_marker_byte_offset_col_past_end_of_line_clamps_to_line_end() {
        let content = "ab\ncd";
        let table = LineOffsetTable::new(content);
        // Line 1 ("ab") has only 2 chars; a col past that clamps to the line span's byte
        // end (`table.line_start(1)`, i.e. right after the '\n', where the next line
        // starts), rather than panicking or reading past that into line 2's content.
        assert_eq!(marker_byte_offset(content, &table, 1, 100), 3);
    }

    #[test]
    fn test_marker_byte_offset_ascii_fast_path_matches_char_indices_result() {
        // Differential test: the `line_is_ascii` fast path must agree with the pre-S1
        // general `char_indices().nth(col)` walk (reimplemented here) for every column on
        // an ASCII line, including overshoot — the desync class S1's fix could introduce.
        fn slow_path(content: &str, table: &LineOffsetTable, line: usize, col: usize) -> usize {
            let Some(line_start) = table.line_start(line.saturating_sub(1)) else {
                return content.len();
            };
            let line_end = table.line_start(line).unwrap_or(content.len());
            let line_text = content.get(line_start..line_end).unwrap_or_default();
            let byte_in_line = line_text
                .char_indices()
                .nth(col)
                .map_or(line_text.len(), |(b, _)| b);
            line_start + byte_in_line
        }

        let content = "uses: actions/checkout@v4\nref: v1.0.0\n";
        let table = LineOffsetTable::new(content);
        for col in 0..=35 {
            assert_eq!(
                marker_byte_offset(content, &table, 1, col),
                slow_path(content, &table, 1, col),
                "ascii fast path desynced from the general char_indices() walk at col {col}"
            );
        }
    }

    #[test]
    fn test_marker_byte_offset_ascii_fast_path_stays_linear_on_a_huge_single_line() {
        // Regression guard (S1, impl-critic, #879 follow-up): without `line_is_ascii`,
        // this was O(line length) per call, reintroducing the O(n^2) shape.
        let filler = "x".repeat(6 * 1024 * 1024);
        let table = LineOffsetTable::new(&filler);
        let start = std::time::Instant::now();
        for col in (0..filler.len()).step_by(filler.len() / 5000) {
            assert_eq!(marker_byte_offset(&filler, &table, 1, col), col);
        }
        assert!(
            start.elapsed() < std::time::Duration::from_secs(1),
            "marker_byte_offset took {:?} for 5000 lookups on a huge ASCII line, expected well \
             under 1s",
            start.elapsed()
        );
    }

    #[test]
    fn test_marker_byte_offset_non_ascii_line_cache_stays_fast_on_a_huge_single_line() {
        // Regression guard for #882: without the per-line char-boundary cache, N lookups on
        // the same non-ASCII line cost O(N x line length) — ~500ms for 5000 lookups on a
        // several-hundred-KB line in a release build.
        let filler = "x".repeat(200 * 1024);
        let content = format!("{filler}\u{2014}{filler}");
        let table = LineOffsetTable::new(&content);
        let char_count = content.chars().count();
        let start = std::time::Instant::now();
        for col in (0..char_count).step_by((char_count / 5000).max(1)) {
            let _ = marker_byte_offset(&content, &table, 1, col);
        }
        assert!(
            start.elapsed() < std::time::Duration::from_secs(1),
            "marker_byte_offset took {:?} for 5000 lookups on a huge non-ASCII line, expected \
             well under 1s",
            start.elapsed()
        );
    }

    #[test]
    fn test_marker_byte_offset_non_ascii_cache_matches_char_indices_result() {
        // Differential test: the cached char-boundary path must agree with a plain
        // reimplemented `char_indices().nth(col)` walk for every column on a non-ASCII line —
        // the exact class of desync a caching bug could silently introduce.
        fn slow_path(content: &str, table: &LineOffsetTable, line: usize, col: usize) -> usize {
            let Some(line_start) = table.line_start(line.saturating_sub(1)) else {
                return content.len();
            };
            let line_end = table.line_start(line).unwrap_or(content.len());
            let line_text = content.get(line_start..line_end).unwrap_or_default();
            let byte_in_line = line_text
                .char_indices()
                .nth(col)
                .map_or(line_text.len(), |(b, _)| b);
            line_start + byte_in_line
        }

        let content = "\u{1f680}rocket \u{2014} emoji then em dash \u{3000} and more";
        let table = LineOffsetTable::new(content);
        for col in 0..=(content.chars().count() + 5) {
            assert_eq!(
                marker_byte_offset(content, &table, 1, col),
                slow_path(content, &table, 1, col),
                "cached non-ASCII path desynced from the general char_indices() walk at col \
                 {col}"
            );
        }
    }

    #[test]
    fn test_marker_byte_offset_multiple_non_ascii_lines_cache_isolation() {
        // Coverage gap flagged by #882 review: the per-line cache must resolve two or more
        // non-ASCII lines independently regardless of query order, with no cross-line leak.
        fn slow_path(content: &str, table: &LineOffsetTable, line: usize, col: usize) -> usize {
            let Some(line_start) = table.line_start(line.saturating_sub(1)) else {
                return content.len();
            };
            let line_end = table.line_start(line).unwrap_or(content.len());
            let line_text = content.get(line_start..line_end).unwrap_or_default();
            let byte_in_line = line_text
                .char_indices()
                .nth(col)
                .map_or(line_text.len(), |(b, _)| b);
            line_start + byte_in_line
        }

        let content = "ascii only\n\u{2014}em dash line\n\u{1f680}rocket \u{3000}ideographic line\nascii again";
        let table = LineOffsetTable::new(content);

        // Query line 3 first, then line 2, then re-query line 3 and line 2 — deliberately out
        // of line order and with a repeat, to catch any cross-line contamination.
        let cases: &[(usize, usize)] = &[(3, 5), (2, 2), (3, 0), (2, 5), (3, 8), (2, 0)];
        for &(line, col) in cases {
            assert_eq!(
                marker_byte_offset(content, &table, line, col),
                slow_path(content, &table, line, col),
                "line {line} col {col} desynced after interleaved multi-line lookups"
            );
        }
    }

    #[test]
    fn test_marker_byte_offset_non_ascii_line_still_correct_without_fast_path() {
        // The fast path must only trigger for a genuinely ASCII line; a non-ASCII line still
        // takes the O(line) `char_indices()` walk, unchanged from before S1.
        let content = "\u{1f680}rocket \u{2014} emoji then em dash";
        let table = LineOffsetTable::new(content);
        let expected = content.char_indices().nth(3).unwrap().0;
        assert_eq!(marker_byte_offset(content, &table, 1, 3), expected);
    }

    #[test]
    fn test_marker_byte_offset_lone_cr_document_documented_limitation() {
        // S2 (impl-critic, #879 follow-up): a bare-`\r` document is out of scope per the
        // "Line-ending assumption" doc section, so this falls back to `content.len()`.
        // Locks in the documented behavior, not asserting it is desirable.
        let content = "on: push\rjobs:\r  build:\r    steps:\r      - uses: actions/checkout@v4\r";
        let table = LineOffsetTable::new(content);
        // yaml-rust2 would report line 5 for the `uses:` value here; only line 1 exists in
        // the table since it never splits on a lone `\r`.
        assert_eq!(marker_byte_offset(content, &table, 5, 14), content.len());
    }

    #[test]
    fn test_tag_index_coverage_defaults_to_complete() {
        assert_eq!(TagIndex::default().coverage(), ListCoverage::Complete);
        assert_eq!(
            TagIndex::from_tags(std::iter::empty()).coverage(),
            ListCoverage::Complete
        );
    }

    #[test]
    fn test_tag_index_with_coverage_records_truncation() {
        let index = TagIndex::default().with_coverage(ListCoverage::Truncated);
        assert_eq!(index.coverage(), ListCoverage::Truncated);
    }

    #[cfg(feature = "lsp-responses")]
    mod lsp_tests {
        use super::*;

        #[test]
        fn splice_hover_line_anchor_priority_resolved_then_current_then_requirement() {
            let with_resolved = "**Current**: `a`\n\n**Resolved**: `b`\n\nBody.";
            assert_eq!(
                splice_hover_line(with_resolved, "W"),
                "**Current**: `a`\n\n**Resolved**: `b`\n\nW\n\nBody."
            );
            assert_eq!(
                splice_hover_line("**Requirement**: `a`\n\nBody.", "W"),
                "**Requirement**: `a`\n\nW\n\nBody."
            );
            assert_eq!(splice_hover_line("Body.", "W"), "Body.W\n\n");
        }

        /// #1311: `resolved_tag` is tag-index/registry-controlled and unbounded — mirrors
        /// diagnostics.rs's `MAX_VERSION_DIAGNOSTIC_CHARS` truncation test pattern.
        #[test]
        fn splice_resolved_line_truncates_overlong_resolved_tag() {
            let long_tag = "9".repeat(5000);
            let sha = CommitSha::parse(&"a".repeat(40)).unwrap();
            let out = splice_resolved_line("", &long_tag, &sha);
            assert!(out.len() < long_tag.len(), "got: {out}");
            assert!(out.contains('…'));
        }

        /// #1310 critic M2: boundary case using `MAX_VERSION_DIAGNOSTIC_CHARS` specifically,
        /// not just the 5000-char extreme.
        #[test]
        fn splice_resolved_line_boundary_at_and_over_cap() {
            let cap = MAX_VERSION_DIAGNOSTIC_CHARS;
            let sha = CommitSha::parse(&"a".repeat(40)).unwrap();

            // `short_sha` always renders with a trailing `…` of its own (it's a fixed
            // 7-char prefix of a 40-char SHA), so a blanket "no ellipsis anywhere"
            // assertion would be wrong here — check the tag's own code span exactly instead.
            let at_cap = "9".repeat(cap);
            let out = splice_resolved_line("", &at_cap, &sha);
            assert!(out.contains(&format!("`{at_cap}`")), "got: {out}");

            let over_cap = "9".repeat(cap + 1);
            let out = splice_resolved_line("", &over_cap, &sha);
            assert!(
                out.contains(&format!("`{}…`", "9".repeat(cap))),
                "got: {out}"
            );
        }

        /// #1311/#1313: `resolved_tag` is a git tag (name/version-shaped), so it must strip
        /// a `sanitize_invisible`-only codepoint (U+0600 ARABIC NUMBER SIGN) that
        /// `is_markdown_unsafe` alone does not catch — deliberately exempt per #1248/#1323
        /// — the same treatment `HoverMarkdown`'s `Name`/`Version` field kinds now apply.
        #[test]
        fn splice_resolved_line_strips_u0600_from_resolved_tag() {
            let sha = CommitSha::parse(&"a".repeat(40)).unwrap();
            let out = splice_resolved_line("", &format!("v1.0{}0", '\u{0600}'), &sha);
            assert!(
                !out.contains('\u{0600}'),
                "U+0600 must be stripped from resolved_tag; got: {out}"
            );
        }

        // --- #1138 review M5: direct coverage for `build_sha_pin_action`/`sha_pin_text_edit`,
        // which previously had only indirect coverage via ecosystem-crate wrapper tests.

        use crate::lsp_helpers::test_support::MOCK_FORMATTER;

        use crate::position::Position as CorePosition;

        use crate::test_util::StubFormatter;

        use crate::{PackageName, VersionReq};

        /// Resolves a dependency named `"resolvable"` to a fixed SHA; declines everything else
        /// — the minimal [`ShaPinning`] fixture these tests need, layered onto the shared
        /// [`MOCK_FORMATTER`] fixture (already implements every [`EcosystemFormatter`] sub-trait)
        /// rather than hand-rolling a second formatter mock.
        impl ShaPinning for StubFormatter {
            fn resolve_static_sha_pin(&self, dep: &dyn Dependency) -> Option<ResolvedShaPin> {
                if dep.name().as_str() != "resolvable" {
                    return None;
                }
                Some(ResolvedShaPin {
                    display_name: dep.name().as_str().to_string(),
                    version_range: dep.version_range()?,
                    replacement: "a".repeat(40),
                })
            }
        }

        #[expect(
            clippy::cast_possible_truncation,
            reason = "fixed short ASCII test-fixture names never approach u32::MAX"
        )]
        fn sha_pin_test_dep(name: &str) -> crate::lsp_helpers::test_support::MockDep {
            let range = Range::new(
                CorePosition::new(0, 6),
                CorePosition::new(0, 6 + name.len() as u32),
            );
            crate::lsp_helpers::test_support::MockDep {
                name: PackageName::new(name),
                version_req: VersionReq::new("v1"),
                version_range: range,
                name_range: range,
            }
        }

        #[test]
        fn test_build_sha_pin_action_resolves_at_position() {
            let dep = sha_pin_test_dep("resolvable");
            let uri = crate::test_util::test_uri("/repo/manifest.yml");
            let parse_result = crate::lsp_helpers::test_support::MockParseResult {
                deps: vec![dep],
                uri: uri.clone(),
            };
            let position = Position {
                line: 0,
                character: 7,
            };

            let action = build_sha_pin_action(
                &parse_result,
                position,
                &uri,
                &MOCK_FORMATTER,
                "TEST_DIAGNOSTIC_CODE",
            )
            .expect("resolvable dependency at position must produce a quickfix");

            assert_eq!(action.title, "Pin resolvable to commit SHA");
            let edits = action
                .edit
                .expect("quickfix must carry a WorkspaceEdit")
                .changes
                .expect("WorkspaceEdit must carry changes");
            let text_edits = edits.values().next().expect("one file's edits");
            assert_eq!(text_edits.len(), 1);
            assert_eq!(text_edits[0].new_text, "a".repeat(40));
        }

        #[test]
        fn test_build_sha_pin_action_none_when_pinning_declines() {
            let dep = sha_pin_test_dep("not-resolvable");
            let uri = crate::test_util::test_uri("/repo/manifest.yml");
            let parse_result = crate::lsp_helpers::test_support::MockParseResult {
                deps: vec![dep],
                uri: uri.clone(),
            };
            let position = Position {
                line: 0,
                character: 7,
            };

            assert!(
                build_sha_pin_action(
                    &parse_result,
                    position,
                    &uri,
                    &MOCK_FORMATTER,
                    "TEST_DIAGNOSTIC_CODE",
                )
                .is_none()
            );
        }

        #[test]
        fn test_build_sha_pin_action_none_when_position_off_dependency() {
            let dep = sha_pin_test_dep("resolvable");
            let uri = crate::test_util::test_uri("/repo/manifest.yml");
            let parse_result = crate::lsp_helpers::test_support::MockParseResult {
                deps: vec![dep],
                uri: uri.clone(),
            };
            let position = Position {
                line: 5,
                character: 0,
            };

            assert!(
                build_sha_pin_action(
                    &parse_result,
                    position,
                    &uri,
                    &MOCK_FORMATTER,
                    "TEST_DIAGNOSTIC_CODE",
                )
                .is_none()
            );
        }

        #[test]
        fn test_sha_pin_text_edit_resolves() {
            let dep = sha_pin_test_dep("resolvable");
            let edit = sha_pin_text_edit(&MOCK_FORMATTER, &dep)
                .expect("resolvable dependency must resolve");
            assert_eq!(edit.new_text, "a".repeat(40));
            assert_eq!(edit.range, dep.version_range.into());
        }

        #[test]
        fn test_sha_pin_text_edit_none_when_pinning_declines() {
            let dep = sha_pin_test_dep("not-resolvable");
            assert!(sha_pin_text_edit(&MOCK_FORMATTER, &dep).is_none());
        }

        crate::debug_redaction_conformance!(
            test_resolved_sha_pin_debug_redacts_credentials,
            1,
            ResolvedShaPin {
                display_name: crate::conformance::CREDENTIAL_PROBE_KEY.to_string(),
                version_range: Range::default(),
                replacement: "a".repeat(40),
            },
        );
    }
}
