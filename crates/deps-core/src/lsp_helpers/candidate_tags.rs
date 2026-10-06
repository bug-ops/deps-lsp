//! Sibling release tags of a *candidate* version (a registry `latest`, an upgrade candidate or a
//! recommended fix target), the candidate-side counterpart of [`super::InUseVersions`].
//!
//! A tag-based ecosystem (GitHub Actions) names one commit with several release tags, and an
//! advisory affecting any of them affects the commit. Phase A already evaluates the in-use
//! version's siblings; this module lets phase B's candidate checks do the same without ever
//! guessing: when the siblings of a candidate cannot be established, the caller gets
//! [`CandidateSiblingsUnknown`] and must report the candidate unverified rather than clean.

use std::sync::Arc;

use super::in_use_version::queryable_siblings;
use super::{InUseVersions, SiblingScope, TagIndex};
use crate::{ConcreteVersion, EcosystemId};

mod private {
    pub trait Sealed {}
}

/// A set of release tags naming one commit that [`crate::osv::ScanTarget::with_siblings`] may
/// attach to a scan target.
///
/// Sealed: only [`InUseVersions`] (phase A) and [`CandidateSiblings`] (phase B) implement it, so
/// arbitrary tags can never be attached to a target.
pub trait TaggedVersions: private::Sealed {
    /// The sibling tags, lowest version first. Never includes the target's own version.
    fn siblings(&self) -> &[ConcreteVersion];
}

impl private::Sealed for InUseVersions {}

impl TaggedVersions for InUseVersions {
    fn siblings(&self) -> &[ConcreteVersion] {
        Self::siblings(self)
    }
}

/// Queryable sibling release tags of a candidate version.
///
/// Has no primary: the candidate's own version stays the scan target's `version`. Obtainable
/// only through [`CandidateTagSource::siblings_of`].
///
/// # Examples
///
/// ```
/// use deps_core::EcosystemId;
/// use deps_core::lsp_helpers::{CandidateTagSource, TaggedVersions};
/// use deps_core::ConcreteVersion;
///
/// let siblings = CandidateTagSource::NotTagBased
///     .siblings_of(&ConcreteVersion::new("1.2.3"), EcosystemId::Cargo)
///     .unwrap();
/// assert!(siblings.siblings().is_empty());
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateSiblings(Vec<ConcreteVersion>);

impl CandidateSiblings {
    /// Builds a value without a tag index, for tests of consumers in other crates.
    #[cfg(any(test, feature = "test-util"))]
    #[must_use]
    pub const fn for_test(siblings: Vec<ConcreteVersion>) -> Self {
        Self(siblings)
    }
}

impl private::Sealed for CandidateSiblings {}

impl TaggedVersions for CandidateSiblings {
    fn siblings(&self) -> &[ConcreteVersion] {
        &self.0
    }
}

/// The sibling release tags of a candidate could not be established, so a clean OSV answer for
/// the candidate alone would not be trustworthy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("sibling release tags of the candidate version are unknown")]
pub struct CandidateSiblingsUnknown;

/// Where a dependency's candidate versions get their sibling release tags from.
///
/// Returned by [`super::RequirementResolution::candidate_tag_source`].
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::CandidateTagSource;
///
/// assert!(!CandidateTagSource::NotTagBased.is_tag_based());
/// assert!(CandidateTagSource::NotYetIndexed.is_tag_based());
/// ```
#[derive(Debug, Clone)]
pub enum CandidateTagSource {
    /// Versions of this dependency are not git tags; a candidate has no siblings.
    NotTagBased,
    /// A populated tag index resolves a candidate's siblings.
    Indexed {
        /// The repository's tag index.
        index: Arc<TagIndex>,
        /// Which tags on a candidate's commit count as its siblings.
        scope: SiblingScope,
    },
    /// Versions are git tags but the tag index is not available yet (cold cache).
    NotYetIndexed,
}

// TODO(#1769): decide phase A and phase B together whether a truncated index must fail closed.
impl CandidateTagSource {
    /// A source for a dependency pinned to a commit: every release tag on the candidate's
    /// commit is a sibling, across majors.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::sync::Arc;
    /// use deps_core::lsp_helpers::{CandidateTagSource, SiblingScope, TagIndex};
    ///
    /// let source = CandidateTagSource::commit_pin(Arc::new(TagIndex::default()));
    /// assert!(matches!(
    ///     source,
    ///     CandidateTagSource::Indexed { scope: SiblingScope::WholeCommit, .. }
    /// ));
    /// ```
    #[must_use]
    pub const fn commit_pin(index: Arc<TagIndex>) -> Self {
        Self::Indexed {
            index,
            scope: SiblingScope::WholeCommit,
        }
    }

    /// A source for a dependency pinned to a tag or branch: only the candidate's own major
    /// line counts, as for an exact-tag pin.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::sync::Arc;
    /// use deps_core::lsp_helpers::{CandidateTagSource, SiblingScope, TagIndex};
    ///
    /// let source = CandidateTagSource::tag_pin(Arc::new(TagIndex::default()));
    /// assert!(matches!(
    ///     source,
    ///     CandidateTagSource::Indexed { scope: SiblingScope::SameMajor, .. }
    /// ));
    /// ```
    #[must_use]
    pub const fn tag_pin(index: Arc<TagIndex>) -> Self {
        Self::Indexed {
            index,
            scope: SiblingScope::SameMajor,
        }
    }

    /// The queryable sibling tags of `candidate` under this source.
    ///
    /// A tag absent from the index is unverifiable whatever the index coverage, so it is an
    /// error, not an empty list. Each sibling passes the same queryability gate as an in-use
    /// version for `ecosystem`.
    ///
    /// A candidate found in a [`crate::pagination::ListCoverage::Truncated`] index gets the
    /// siblings that were listed, which may be incomplete; phase A's pin resolution has the same
    /// limitation (#1769).
    ///
    /// # Errors
    ///
    /// [`CandidateSiblingsUnknown`] for [`Self::NotYetIndexed`], and for [`Self::Indexed`] when
    /// `candidate` does not resolve to a single tag of the index.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::sync::Arc;
    /// use deps_core::lsp_helpers::{
    ///     CandidateTagSource, CommitSha, SiblingScope, TagIndex, TaggedVersions,
    /// };
    /// use deps_core::{ConcreteVersion, EcosystemId};
    ///
    /// let sha = CommitSha::parse(&"a".repeat(40)).unwrap();
    /// let index = TagIndex::from_tags([("v4.8.0", &sha), ("v4.9.0", &sha)]);
    /// let source = CandidateTagSource::Indexed {
    ///     index: Arc::new(index),
    ///     scope: SiblingScope::SameMajor,
    /// };
    /// let siblings = source
    ///     .siblings_of(&ConcreteVersion::new("v4.8.0"), EcosystemId::GithubActions)
    ///     .unwrap();
    /// assert_eq!(siblings.siblings()[0].as_str(), "v4.9.0");
    /// assert!(
    ///     source
    ///         .siblings_of(&ConcreteVersion::new("v9.9.9"), EcosystemId::GithubActions)
    ///         .is_err()
    /// );
    /// ```
    pub fn siblings_of(
        &self,
        candidate: &ConcreteVersion,
        ecosystem: EcosystemId,
    ) -> Result<CandidateSiblings, CandidateSiblingsUnknown> {
        match self {
            Self::NotTagBased => Ok(CandidateSiblings(Vec::new())),
            Self::NotYetIndexed => Err(CandidateSiblingsUnknown),
            Self::Indexed { index, scope } => {
                let tag = index
                    .release_tag(candidate.as_str())
                    .ok_or(CandidateSiblingsUnknown)?;
                let pin = index
                    .resolved_release(tag, *scope)
                    .ok_or(CandidateSiblingsUnknown)?;
                Ok(CandidateSiblings(queryable_siblings(&pin, ecosystem)))
            }
        }
    }

    /// Whether candidates of this dependency are git tags, whatever the index state.
    #[must_use]
    pub const fn is_tag_based(&self) -> bool {
        !matches!(self, Self::NotTagBased)
    }

    /// Combines the readings of two dependencies sharing one scan key.
    ///
    /// Any [`Self::NotYetIndexed`] wins, else [`Self::Indexed`] with the wider scope (and the
    /// first index), else [`Self::NotTagBased`].
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::lsp_helpers::CandidateTagSource;
    ///
    /// let merged = CandidateTagSource::NotTagBased.merge(CandidateTagSource::NotYetIndexed);
    /// assert!(matches!(merged, CandidateTagSource::NotYetIndexed));
    /// ```
    #[must_use]
    pub fn merge(self, other: Self) -> Self {
        match (self, other) {
            (Self::NotYetIndexed, _) | (_, Self::NotYetIndexed) => Self::NotYetIndexed,
            (Self::NotTagBased, tagged) | (tagged, Self::NotTagBased) => tagged,
            (
                Self::Indexed { index, scope },
                Self::Indexed {
                    scope: other_scope, ..
                },
            ) => Self::Indexed {
                index,
                scope: scope.max(other_scope),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lsp_helpers::CommitSha;

    fn sha(c: char) -> CommitSha {
        CommitSha::parse(&c.to_string().repeat(40)).unwrap()
    }

    fn names(siblings: &CandidateSiblings) -> Vec<&str> {
        siblings
            .siblings()
            .iter()
            .map(ConcreteVersion::as_str)
            .collect()
    }

    fn indexed(tags: &[(&str, char)], scope: SiblingScope) -> CandidateTagSource {
        let shas: Vec<(&str, CommitSha)> = tags.iter().map(|(t, c)| (*t, sha(*c))).collect();
        let index = TagIndex::from_tags(shas.iter().map(|(t, s)| (*t, s)));
        CandidateTagSource::Indexed {
            index: Arc::new(index),
            scope,
        }
    }

    fn gha(source: &CandidateTagSource, candidate: &str) -> Result<Vec<String>, ()> {
        source
            .siblings_of(&ConcreteVersion::new(candidate), EcosystemId::GithubActions)
            .map(|s| names(&s).into_iter().map(str::to_string).collect())
            .map_err(|_| ())
    }

    #[test]
    fn not_tag_based_has_no_siblings() {
        assert_eq!(gha(&CandidateTagSource::NotTagBased, "1.0.0"), Ok(vec![]));
    }

    #[test]
    fn not_yet_indexed_is_unknown() {
        assert_eq!(gha(&CandidateTagSource::NotYetIndexed, "v1.0.0"), Err(()));
    }

    #[test]
    fn scope_decides_which_tags_are_siblings() {
        let tags = [("v4.8.0", 'a'), ("v4.9.0", 'a'), ("v5.0.0", 'a')];
        let same = indexed(&tags, SiblingScope::SameMajor);
        let whole = indexed(&tags, SiblingScope::WholeCommit);
        assert_eq!(gha(&same, "v4.8.0"), Ok(vec!["v4.9.0".to_string()]));
        assert_eq!(
            gha(&whole, "v4.8.0"),
            Ok(vec!["v4.9.0".to_string(), "v5.0.0".to_string()])
        );
    }

    #[test]
    fn candidate_absent_from_index_is_unknown_on_complete_and_truncated_index() {
        for coverage in [
            crate::pagination::ListCoverage::Complete,
            crate::pagination::ListCoverage::Truncated,
        ] {
            let a = sha('a');
            let index = TagIndex::from_tags([("v1.0.0", &a)]).with_coverage(coverage);
            let source = CandidateTagSource::Indexed {
                index: Arc::new(index),
                scope: SiblingScope::SameMajor,
            };
            assert_eq!(gha(&source, "v9.9.9"), Err(()), "{coverage:?}");
        }
    }

    #[test]
    fn unprefixed_candidate_resolves_through_normalized_tag() {
        let source = indexed(&[("v4.1.3", 'a'), ("v4.1.4", 'a')], SiblingScope::SameMajor);
        assert_eq!(gha(&source, "4.1.3"), Ok(vec!["v4.1.4".to_string()]));
    }

    #[test]
    fn conflicting_spellings_are_unknown_even_for_an_exact_key() {
        let source = indexed(&[("v4.1.3", 'a'), ("4.1.3", 'b')], SiblingScope::SameMajor);
        for candidate in ["V4.1.3", "4.1.3", "v4.1.3"] {
            assert_eq!(gha(&source, candidate), Err(()), "{candidate}");
        }
    }

    #[test]
    fn non_queryable_sibling_is_dropped() {
        let source = indexed(&[("v3", 'a'), ("v4", 'a')], SiblingScope::WholeCommit);
        assert_eq!(gha(&source, "v3"), Ok(vec![]));
    }

    #[test]
    fn merge_prefers_not_yet_indexed_then_wider_scope() {
        let tags = [("v1.0.0", 'a')];
        let same = indexed(&tags, SiblingScope::SameMajor);
        let whole = indexed(&tags, SiblingScope::WholeCommit);
        assert!(matches!(
            same.clone().merge(CandidateTagSource::NotYetIndexed),
            CandidateTagSource::NotYetIndexed
        ));
        assert!(matches!(
            same.clone().merge(whole),
            CandidateTagSource::Indexed {
                scope: SiblingScope::WholeCommit,
                ..
            }
        ));
        assert!(matches!(
            CandidateTagSource::NotTagBased.merge(same),
            CandidateTagSource::Indexed { .. }
        ));
        assert!(
            !CandidateTagSource::NotTagBased
                .merge(CandidateTagSource::NotTagBased)
                .is_tag_based()
        );
    }
}
