//! Pin-resolution rules shared by the git-tag ecosystems (GitHub Actions, GitLab CI).
//!
//! Each ecosystem projects its own pin style into a [`GitPinView`] and supplies its tag index
//! lookup; the decisions about what a cold, truncated or complete [`TagIndex`] proves, and
//! which tag spelling an update writes, live here so both platforms share them by construction.

use std::sync::Arc;

use super::candidate_tags::CandidateTagSource;
use super::git_ref::{CommitRewrite, CommitSha, PinResolution, TagIndex, match_v_prefix_style};
use super::in_use_version::concrete_pin_version;
use super::sha_comment::CommentTag;
use crate::{ConcreteVersion, EcosystemId};

/// How a dependency's ref is pinned, in the vocabulary the shared pin rules need.
///
/// Exhaustive so a new shape forces every `match` here to decide what it means.
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::{CommitSha, GitPinView};
///
/// let sha = CommitSha::parse(&"a".repeat(40)).unwrap();
/// let view = GitPinView::Sha { sha: &sha, comment: None };
/// assert_ne!(view, GitPinView::Tag { written: "v4.2.2" });
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GitPinView<'a> {
    /// A full commit SHA, with the tag named by its trailing comment, if any.
    Sha {
        /// The pinned commit.
        sha: &'a CommitSha,
        /// The trailing `# <tag>` comment.
        comment: Option<&'a CommentTag>,
    },
    /// A tag ref written as `written`.
    Tag {
        /// The ref text exactly as declared.
        written: &'a str,
    },
    /// Anything else (branch, `~latest`, partial component version, absent ref): the tag list
    /// proves nothing about it.
    Other,
}

/// What `index` proves about `pin`.
///
/// A cold or failed fetch (`index` is `None`) is [`PinResolution::NotYetIndexed`] for the pins
/// that have sibling release tags to miss (a SHA pin or a concrete tag pin) and
/// [`PinResolution::Unresolved`] for the rest.
///
/// # Examples
///
/// ```
/// use deps_core::EcosystemId;
/// use deps_core::lsp_helpers::{GitPinView, PinResolution, resolve_git_pin};
///
/// let cold = |written| {
///     resolve_git_pin(GitPinView::Tag { written }, None, EcosystemId::GithubActions)
/// };
/// assert_eq!(cold("v4.8.0"), PinResolution::NotYetIndexed);
/// assert_eq!(cold("v4"), PinResolution::Unresolved);
/// ```
#[must_use]
pub fn resolve_git_pin(
    pin: GitPinView<'_>,
    index: Option<&TagIndex>,
    ecosystem: EcosystemId,
) -> PinResolution {
    let Some(index) = index else {
        return cold_resolution(pin, ecosystem);
    };
    match pin {
        GitPinView::Sha { sha, comment } => index.pin_resolution(sha, comment),
        GitPinView::Tag { written } => index.tag_pin_resolution(written, ecosystem),
        GitPinView::Other => PinResolution::Unresolved,
    }
}

fn cold_resolution(pin: GitPinView<'_>, ecosystem: EcosystemId) -> PinResolution {
    match pin {
        GitPinView::Sha { .. } => PinResolution::NotYetIndexed,
        GitPinView::Tag { written } if concrete_pin_version(written, ecosystem).is_some() => {
            PinResolution::NotYetIndexed
        }
        GitPinView::Tag { .. } | GitPinView::Other => PinResolution::Unresolved,
    }
}

/// Whether a SHA pin can be rewritten to `version` using `index`.
///
/// [`CommitRewrite::NotACommitPin`] for every other pin shape; a missing index is
/// [`CommitRewrite::IndexUnavailable`].
///
/// # Examples
///
/// ```
/// use deps_core::ConcreteVersion;
/// use deps_core::lsp_helpers::{CommitRewrite, GitPinView, git_commit_rewrite};
///
/// let version = ConcreteVersion::new("v5.0.0");
/// assert_eq!(
///     git_commit_rewrite(GitPinView::Tag { written: "v4" }, None, &version),
///     CommitRewrite::NotACommitPin
/// );
/// ```
#[must_use]
pub fn git_commit_rewrite(
    pin: GitPinView<'_>,
    index: Option<&TagIndex>,
    version: &ConcreteVersion,
) -> CommitRewrite {
    match pin {
        GitPinView::Sha { .. } => index.map_or(CommitRewrite::IndexUnavailable, |index| {
            index.commit_rewrite_to(version.as_str())
        }),
        GitPinView::Tag { .. } | GitPinView::Other => CommitRewrite::NotACommitPin,
    }
}

/// Where the siblings of an advisory candidate for `pin` come from: a SHA pin names its whole
/// commit, any other pin keeps the same-major rule; a missing index is not yet fetched.
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::{CandidateTagSource, GitPinView, git_candidate_tag_source};
///
/// let source = git_candidate_tag_source(GitPinView::Other, None);
/// assert!(matches!(source, CandidateTagSource::NotYetIndexed));
/// ```
#[must_use]
pub fn git_candidate_tag_source(
    pin: GitPinView<'_>,
    index: Option<Arc<TagIndex>>,
) -> CandidateTagSource {
    let Some(index) = index else {
        return CandidateTagSource::NotYetIndexed;
    };
    match pin {
        GitPinView::Sha { .. } => CandidateTagSource::commit_pin(index),
        GitPinView::Tag { .. } | GitPinView::Other => CandidateTagSource::tag_pin(index),
    }
}

/// The ref text an update of a tag pin writes for `version`.
///
/// Preserves `current`'s `v`-prefix style when that spelling is a published tag, so a repository
/// that changed its tagging convention does not flip the user's style needlessly. When `index`
/// proves the style-matched spelling is not published (`7.0.1` where only `v7.0.1` exists), the
/// published spelling is written instead, so an update never creates an unknown ref. Without
/// such evidence the style-matched spelling is kept.
///
/// # Examples
///
/// ```
/// use deps_core::ConcreteVersion;
/// use deps_core::lsp_helpers::{CommitSha, TagIndex, git_tag_replacement};
///
/// let sha = CommitSha::parse(&"a".repeat(40)).unwrap();
/// let index = TagIndex::from_tags([("v7.0.1", &sha), ("v4.2.2", &sha)]);
/// let version = ConcreteVersion::new("v7.0.1");
/// assert_eq!(git_tag_replacement("4.2.2", &version, Some(&index)), "v7.0.1");
/// assert_eq!(git_tag_replacement("v4.2.2", &version, Some(&index)), "v7.0.1");
/// assert_eq!(git_tag_replacement("4.2.2", &version, None), "7.0.1");
/// ```
#[must_use]
pub fn git_tag_replacement(
    current: &str,
    version: &ConcreteVersion,
    index: Option<&TagIndex>,
) -> String {
    let styled = match_v_prefix_style(current, version.as_str());
    let Some(index) = index else {
        return styled;
    };
    let published = |tag: &str| index.tag_to_sha.contains_key(tag);
    if published(&styled) {
        return styled;
    }
    if published(version.as_str()) {
        return version.as_str().to_string();
    }
    index
        .release_tag(version.as_str())
        .map_or(styled, str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lsp_helpers::SiblingScope;
    use crate::pagination::ListCoverage;
    use std::assert_matches;

    fn sha(c: char) -> CommitSha {
        CommitSha::parse(&c.to_string().repeat(40)).unwrap()
    }

    fn index(tags: &[&str]) -> TagIndex {
        let commit = sha('a');
        TagIndex::from_tags(tags.iter().map(|tag| (*tag, &commit)))
    }

    #[test]
    fn test_cold_resolution_table() {
        let commit = sha('b');
        let eco = EcosystemId::GitlabCi;
        let cold = |pin| resolve_git_pin(pin, None, eco);
        assert_eq!(
            cold(GitPinView::Sha {
                sha: &commit,
                comment: None
            }),
            PinResolution::NotYetIndexed
        );
        assert_eq!(
            cold(GitPinView::Tag { written: "v4.8.0" }),
            PinResolution::NotYetIndexed
        );
        assert_eq!(
            cold(GitPinView::Tag { written: "v4" }),
            PinResolution::Unresolved
        );
        assert_eq!(cold(GitPinView::Other), PinResolution::Unresolved);
    }

    #[test]
    fn test_warm_tag_resolution_matches_tag_index() {
        let idx = index(&["v4.2.2"]);
        let eco = EcosystemId::GithubActions;
        let resolve = |written| resolve_git_pin(GitPinView::Tag { written }, Some(&idx), eco);
        assert_eq!(resolve("4.2.2"), PinResolution::Unpublished);
        assert_eq!(resolve("v4.2.2"), idx.tag_pin_resolution("v4.2.2", eco));
        assert_eq!(
            resolve_git_pin(GitPinView::Other, Some(&idx), eco),
            PinResolution::Unresolved
        );
    }

    #[test]
    fn test_commit_rewrite_only_for_sha_pins() {
        let commit = sha('a');
        let idx = index(&["v4.1.3"]);
        let version = ConcreteVersion::new("4.1.3");
        let sha_pin = GitPinView::Sha {
            sha: &commit,
            comment: None,
        };
        assert_eq!(
            git_commit_rewrite(sha_pin, Some(&idx), &version),
            CommitRewrite::Resolved
        );
        assert_eq!(
            git_commit_rewrite(sha_pin, None, &version),
            CommitRewrite::IndexUnavailable
        );
        assert_eq!(
            git_commit_rewrite(GitPinView::Other, Some(&idx), &version),
            CommitRewrite::NotACommitPin
        );
    }

    #[test]
    fn test_candidate_tag_source_scope_by_pin() {
        let commit = sha('a');
        let idx = Arc::new(index(&["v4.1.3"]));
        let sha_pin = GitPinView::Sha {
            sha: &commit,
            comment: None,
        };
        assert_matches!(
            git_candidate_tag_source(sha_pin, None),
            CandidateTagSource::NotYetIndexed
        );
        assert_matches!(
            git_candidate_tag_source(sha_pin, Some(Arc::clone(&idx))),
            CandidateTagSource::Indexed {
                scope: SiblingScope::WholeCommit,
                ..
            }
        );
        assert_matches!(
            git_candidate_tag_source(GitPinView::Tag { written: "v4" }, Some(idx)),
            CandidateTagSource::Indexed {
                scope: SiblingScope::SameMajor,
                ..
            }
        );
    }

    #[test]
    fn test_tag_replacement_writes_published_spelling_for_unpublished_ref() {
        let idx = index(&["v7.0.1", "v4.2.2"]);
        let version = ConcreteVersion::new("v7.0.1");
        assert_eq!(git_tag_replacement("4.2.2", &version, Some(&idx)), "v7.0.1");
        assert_eq!(git_tag_replacement("4", &version, Some(&idx)), "v7.0.1");
    }

    #[test]
    fn test_tag_replacement_normalizes_unprefixed_version_to_published_key() {
        let idx = index(&["v7.0.1"]);
        let version = ConcreteVersion::new("7.0.1");
        assert_eq!(git_tag_replacement("4.2.2", &version, Some(&idx)), "v7.0.1");
    }

    #[test]
    fn test_tag_replacement_keeps_style_when_that_spelling_is_published() {
        let idx = index(&["4.2.2", "7.0.1", "v7.0.1"]);
        let version = ConcreteVersion::new("v7.0.1");
        assert_eq!(git_tag_replacement("4.2.2", &version, Some(&idx)), "7.0.1");
        assert_eq!(git_tag_replacement("v4", &version, Some(&idx)), "v7.0.1");
    }

    #[test]
    fn test_tag_replacement_partial_pin_writes_published_release() {
        let idx = index(&["v7.0.1", "v40"]);
        let version = ConcreteVersion::new("v7.0.1");
        assert_eq!(git_tag_replacement("v40", &version, Some(&idx)), "v7.0.1");
        assert_eq!(git_tag_replacement("40", &version, Some(&idx)), "v7.0.1");
    }

    #[test]
    fn test_tag_replacement_monorepo_prefixed_tags_are_kept_verbatim() {
        let idx = index(&["pkg-v1.0.0", "pkg-v2.0.0", "other-v9.0.0"]);
        let version = ConcreteVersion::new("pkg-v2.0.0");
        assert_eq!(
            git_tag_replacement("pkg-v1.0.0", &version, Some(&idx)),
            "pkg-v2.0.0"
        );
        assert_eq!(
            git_tag_replacement("pkg-v1.0.0", &version, None),
            "pkg-v2.0.0"
        );
    }

    #[test]
    fn test_tag_replacement_path_style_tags_resolve_to_the_published_key() {
        let idx = index(&["release/1.0.0", "release/2.0.0"]);
        let version = ConcreteVersion::new("release/2.0.0");
        assert_eq!(
            git_tag_replacement("release/1.0.0", &version, Some(&idx)),
            "release/2.0.0"
        );
    }

    #[test]
    fn test_tag_replacement_without_evidence_keeps_style() {
        let version = ConcreteVersion::new("v7.0.1");
        assert_eq!(git_tag_replacement("4.2.2", &version, None), "7.0.1");
        let empty = TagIndex::default();
        assert_eq!(
            git_tag_replacement("4.2.2", &version, Some(&empty)),
            "7.0.1"
        );
    }

    #[test]
    fn test_tag_replacement_truncated_index_without_the_release_keeps_style() {
        let idx = index(&["v4.2.2"]).with_coverage(ListCoverage::Truncated);
        let version = ConcreteVersion::new("v7.0.1");
        assert_eq!(git_tag_replacement("4.2.2", &version, Some(&idx)), "7.0.1");
    }
}
