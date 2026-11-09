//! Cross-checks of an ecosystem's requirement matching, for the formatter test suites.

use crate::lsp_helpers::{BoundedVersionReq, RequirementMatcher, RequirementResolution};
use crate::{ConcreteVersion, VersionReq};

fn versions_of(versions: &[&str]) -> Vec<ConcreteVersion> {
    versions.iter().map(|v| ConcreteVersion::new(*v)).collect()
}

/// Asserts that a formatter's candidate set agrees with its compiled matcher.
///
/// For every requirement, [`candidate_set`](RequirementResolution::candidate_set) answers exactly
/// as [`compile_bounded_requirement`](RequirementResolution::compile_bounded_requirement) does
/// over `versions`: a requirement that does not compile is `None` in both, and a candidate is
/// flagged exactly when `matches` is `Some(true)`.
///
/// # Panics
///
/// When the formatter has no candidate set, or any requirement or version disagrees.
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::{
///     BoundedVersionReq, RequirementMatcher, RequirementResolution, SemverGrammar,
///     CandidateSet, grammar_candidates, grammar_matcher,
/// };
/// use deps_core::test_util::assert_candidate_set_consistent;
/// use deps_core::ConcreteVersion;
///
/// struct Semver;
/// impl RequirementResolution for Semver {
///     fn compile_bounded_requirement(
///         &self,
///         requirement: BoundedVersionReq<'_>,
///     ) -> Option<Box<dyn RequirementMatcher>> {
///         grammar_matcher(SemverGrammar, requirement)
///     }
///
///     fn candidate_set(&self, candidates: &[ConcreteVersion]) -> Option<Box<dyn CandidateSet>> {
///         Some(grammar_candidates(SemverGrammar, candidates))
///     }
/// }
///
/// assert_candidate_set_consistent(&Semver, &["^1.0", "oops"], &["1.2.0", "2.0.0", "x"]);
/// ```
pub fn assert_candidate_set_consistent<F: RequirementResolution + ?Sized>(
    formatter: &F,
    requirements: &[&str],
    versions: &[&str],
) {
    let candidates = versions_of(versions);
    let set = formatter
        .candidate_set(&candidates)
        .expect("the formatter provides a candidate set");
    for requirement in requirements {
        let requirement_text = VersionReq::new(*requirement);
        let bounded =
            BoundedVersionReq::new(&requirement_text).expect("corpus requirement within the cap");
        let matcher = formatter.compile_bounded_requirement(bounded);
        let mask = set.satisfying(bounded);
        assert_eq!(
            matcher.is_some(),
            mask.is_some(),
            "compile and candidate set disagree on whether `{requirement}` is modellable"
        );
        if let (Some(matcher), Some(mask)) = (matcher, mask) {
            for (version, flagged) in candidates.iter().zip(mask) {
                assert_eq!(
                    matcher.matches(version) == Some(true),
                    flagged,
                    "`{requirement}` vs `{version}`"
                );
            }
        }
    }
}

/// Asserts that a formatter's compiled matcher is observably identical to a `legacy` one.
///
/// Compared over every pair of `requirements` and `versions`: modellability, `matches` (including
/// `None` for an unparseable candidate), `strict_prerelease_exclusion` and `explicitly_excludes`.
///
/// Used while an ecosystem's matcher is re-expressed as a
/// [`VersionGrammar`](crate::lsp_helpers::VersionGrammar), with the previous implementation as the
/// oracle.
///
/// # Panics
///
/// On the first observable difference.
pub fn assert_matchers_equivalent<F: RequirementResolution + ?Sized>(
    formatter: &F,
    legacy: &dyn Fn(BoundedVersionReq<'_>) -> Option<Box<dyn RequirementMatcher>>,
    requirements: &[&str],
    versions: &[&str],
) {
    let candidates = versions_of(versions);
    for requirement in requirements {
        let requirement_text = VersionReq::new(*requirement);
        let bounded =
            BoundedVersionReq::new(&requirement_text).expect("corpus requirement within the cap");
        match (
            legacy(bounded),
            formatter.compile_bounded_requirement(bounded),
        ) {
            (None, None) => {}
            (Some(old), Some(new)) => {
                assert_eq!(
                    old.strict_prerelease_exclusion(),
                    new.strict_prerelease_exclusion(),
                    "strict_prerelease_exclusion of `{requirement}`"
                );
                for version in &candidates {
                    assert_eq!(
                        old.matches(version),
                        new.matches(version),
                        "matches of `{requirement}` vs `{version}`"
                    );
                    assert_eq!(
                        old.explicitly_excludes(version),
                        new.explicitly_excludes(version),
                        "explicitly_excludes of `{requirement}` vs `{version}`"
                    );
                }
            }
            (old, new) => panic!(
                "modellability of `{requirement}` differs: legacy {}, grammar {}",
                old.is_some(),
                new.is_some()
            ),
        }
    }
}
