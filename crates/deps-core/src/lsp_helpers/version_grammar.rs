//! Parse-once version matching: one ecosystem grammar feeds both a per-requirement
//! [`RequirementMatcher`] and a per-candidate-list [`CandidateSet`].
//!
//! [`RequirementMatcher::matches`] reparses the candidate on every call, which makes selecting a
//! lock entry for many distinct requirements quadratic in parsing work. A [`VersionGrammar`]
//! separates the three steps (parse a version, compile a requirement, compare the two), so
//! [`grammar_candidates`] parses each candidate once and [`CandidateSet::satisfying`] only
//! compares. [`grammar_matcher`] builds the single-requirement matcher from the same grammar, so
//! the two views cannot drift apart.

use super::{BoundedVersionReq, RequirementMatcher};
use crate::ConcreteVersion;

/// The version and requirement semantics of one ecosystem, split into parse, compile and compare.
///
/// Implementors are small `Copy` values (usually unit structs). [`Self::compile`] owns every
/// "this requirement cannot be modelled" decision, so a requirement the grammar rejects is
/// rejected identically by [`grammar_matcher`] and by [`CandidateSet::satisfying`].
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::{BoundedVersionReq, VersionGrammar, grammar_matcher};
/// use deps_core::{ConcreteVersion, VersionReq};
///
/// #[derive(Clone, Copy)]
/// struct MajorGrammar;
///
/// impl VersionGrammar for MajorGrammar {
///     type Version = u64;
///     type Compiled = u64;
///
///     fn parse_version(&self, version: &ConcreteVersion) -> Option<u64> {
///         version.as_str().split('.').next()?.parse().ok()
///     }
///
///     fn compile(&self, requirement: BoundedVersionReq<'_>) -> Option<u64> {
///         requirement.as_str().parse().ok()
///     }
///
///     fn satisfies(&self, compiled: &u64, version: &u64) -> bool {
///         compiled == version
///     }
///
///     fn strict_prerelease_exclusion(&self, _: &u64) -> bool {
///         false
///     }
/// }
///
/// let requirement = VersionReq::new("2");
/// let bounded = BoundedVersionReq::new(&requirement).unwrap();
/// let matcher = grammar_matcher(MajorGrammar, bounded).unwrap();
/// assert_eq!(matcher.matches(&ConcreteVersion::new("2.7.1")), Some(true));
/// assert_eq!(matcher.matches(&ConcreteVersion::new("3.0.0")), Some(false));
/// assert_eq!(matcher.matches(&ConcreteVersion::new("x")), None);
/// ```
pub trait VersionGrammar: Clone + Send + Sync + 'static {
    /// A candidate version after parsing.
    type Version: Send + Sync;
    /// A requirement after compiling.
    type Compiled: Send + Sync;

    /// Parses `version`; `None` when this ecosystem's version format cannot read it.
    fn parse_version(&self, version: &ConcreteVersion) -> Option<Self::Version>;

    /// Compiles `requirement`; `None` when it is unmodellable (does not parse, is a placeholder,
    /// or otherwise cannot be decided), exactly the contract of
    /// [`RequirementResolution::compile_bounded_requirement`](super::RequirementResolution::compile_bounded_requirement).
    fn compile(&self, requirement: BoundedVersionReq<'_>) -> Option<Self::Compiled>;

    /// Whether `version` satisfies `compiled`.
    fn satisfies(&self, compiled: &Self::Compiled, version: &Self::Version) -> bool;

    /// See [`RequirementMatcher::strict_prerelease_exclusion`].
    fn strict_prerelease_exclusion(&self, compiled: &Self::Compiled) -> bool;

    /// See [`RequirementMatcher::explicitly_excludes`]; `false` unless the grammar can ban a
    /// single value inside an otherwise admitted range.
    fn explicitly_excludes(&self, compiled: &Self::Compiled, version: &Self::Version) -> bool {
        let _ = (compiled, version);
        false
    }
}

/// A candidate list parsed once, answering which candidates satisfy a requirement.
///
/// Built by [`grammar_candidates`] through
/// [`RequirementResolution::candidate_set`](super::RequirementResolution::candidate_set) and shared
/// across every requirement selected from the same list.
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::{BoundedVersionReq, CandidateSet, SemverGrammar, grammar_candidates};
/// use deps_core::{ConcreteVersion, VersionReq};
///
/// let versions = [ConcreteVersion::new("1.2.0"), ConcreteVersion::new("2.0.0")];
/// let set = grammar_candidates(SemverGrammar, &versions);
/// let requirement = VersionReq::new("^1.0");
/// let bounded = BoundedVersionReq::new(&requirement).unwrap();
/// assert_eq!(set.satisfying(bounded), Some(vec![true, false]));
/// ```
pub trait CandidateSet: Send + Sync {
    /// One flag per candidate, in order: whether it provably satisfies `requirement`. An
    /// unparseable candidate is `false`. `None` when `requirement` is unmodellable, so the caller
    /// falls back to its heuristic exactly as it does for a failed compile.
    fn satisfying(&self, requirement: BoundedVersionReq<'_>) -> Option<Vec<bool>>;
}

/// Plain [`semver`] grammar: the range syntax of Cargo's registry and Swift Package Manager's
/// version requirements, with strict SemVer 2.0.0 pre-release exclusion.
///
/// It compiles every requirement `semver::VersionReq` parses and applies no placeholder guard;
/// a formatter wraps it with its own `bounded_requirement_is_unresolved` check, because those
/// guards differ per ecosystem.
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::{BoundedVersionReq, SemverGrammar, grammar_matcher};
/// use deps_core::{ConcreteVersion, VersionReq};
///
/// let requirement = VersionReq::new("^1.0.0");
/// let bounded = BoundedVersionReq::new(&requirement).unwrap();
/// let matcher = grammar_matcher(SemverGrammar, bounded).unwrap();
/// assert_eq!(matcher.matches(&ConcreteVersion::new("1.5.0")), Some(true));
/// assert_eq!(matcher.matches(&ConcreteVersion::new("2.0.0")), Some(false));
/// assert!(matcher.strict_prerelease_exclusion());
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct SemverGrammar;

impl VersionGrammar for SemverGrammar {
    type Version = semver::Version;
    type Compiled = semver::VersionReq;

    fn parse_version(&self, version: &ConcreteVersion) -> Option<semver::Version> {
        version.as_str().parse().ok()
    }

    fn compile(&self, requirement: BoundedVersionReq<'_>) -> Option<semver::VersionReq> {
        requirement.as_str().parse().ok()
    }

    fn satisfies(&self, compiled: &semver::VersionReq, version: &semver::Version) -> bool {
        compiled.matches(version)
    }

    /// `semver::VersionReq::matches` excludes pre-releases unless the requirement itself pins the
    /// same `X.Y.Z` tuple with a pre-release tag: strict SemVer 2.0.0 semantics (#299).
    fn strict_prerelease_exclusion(&self, _: &semver::VersionReq) -> bool {
        true
    }
}

struct GrammarMatcher<G: VersionGrammar> {
    grammar: G,
    compiled: G::Compiled,
}

impl<G: VersionGrammar> RequirementMatcher for GrammarMatcher<G> {
    fn matches(&self, version: &ConcreteVersion) -> Option<bool> {
        let parsed = self.grammar.parse_version(version)?;
        Some(self.grammar.satisfies(&self.compiled, &parsed))
    }

    fn strict_prerelease_exclusion(&self) -> bool {
        self.grammar.strict_prerelease_exclusion(&self.compiled)
    }

    fn explicitly_excludes(&self, version: &ConcreteVersion) -> bool {
        self.grammar
            .parse_version(version)
            .is_some_and(|parsed| self.grammar.explicitly_excludes(&self.compiled, &parsed))
    }
}

struct ParsedCandidates<G: VersionGrammar> {
    grammar: G,
    parsed: Vec<Option<G::Version>>,
}

impl<G: VersionGrammar> CandidateSet for ParsedCandidates<G> {
    fn satisfying(&self, requirement: BoundedVersionReq<'_>) -> Option<Vec<bool>> {
        let compiled = self.grammar.compile(requirement)?;
        Some(
            self.parsed
                .iter()
                .map(|version| {
                    version
                        .as_ref()
                        .is_some_and(|version| self.grammar.satisfies(&compiled, version))
                })
                .collect(),
        )
    }
}

/// Compiles `requirement` under `grammar` into a [`RequirementMatcher`], `None` when the grammar
/// rejects it.
#[must_use]
pub fn grammar_matcher<G: VersionGrammar>(
    grammar: G,
    requirement: BoundedVersionReq<'_>,
) -> Option<Box<dyn RequirementMatcher>> {
    let compiled = grammar.compile(requirement)?;
    Some(matcher_of(grammar, compiled))
}

/// The matcher of an already compiled requirement, for callers that compile without a
/// [`BoundedVersionReq`].
pub(crate) fn matcher_of<G: VersionGrammar>(
    grammar: G,
    compiled: G::Compiled,
) -> Box<dyn RequirementMatcher> {
    Box::new(GrammarMatcher { grammar, compiled })
}

/// Parses `candidates` once under `grammar`.
#[must_use]
pub fn grammar_candidates<G: VersionGrammar>(
    grammar: G,
    candidates: &[ConcreteVersion],
) -> Box<dyn CandidateSet> {
    let parsed = candidates
        .iter()
        .map(|version| grammar.parse_version(version))
        .collect();
    Box::new(ParsedCandidates { grammar, parsed })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::VersionReq;

    #[derive(Clone)]
    struct CountingGrammar {
        parses: Arc<AtomicUsize>,
        compiles: Arc<AtomicUsize>,
    }

    impl VersionGrammar for CountingGrammar {
        type Version = u64;
        type Compiled = u64;

        fn parse_version(&self, version: &ConcreteVersion) -> Option<u64> {
            self.parses.fetch_add(1, Ordering::SeqCst);
            version.as_str().parse().ok()
        }

        fn compile(&self, requirement: BoundedVersionReq<'_>) -> Option<u64> {
            self.compiles.fetch_add(1, Ordering::SeqCst);
            requirement.as_str().parse().ok()
        }

        fn satisfies(&self, compiled: &u64, version: &u64) -> bool {
            version >= compiled
        }

        fn strict_prerelease_exclusion(&self, _: &u64) -> bool {
            false
        }
    }

    fn bounded(requirement: &VersionReq) -> BoundedVersionReq<'_> {
        BoundedVersionReq::new(requirement).unwrap()
    }

    #[test]
    fn every_candidate_is_parsed_once_however_many_requirements_are_selected() {
        let grammar = CountingGrammar {
            parses: Arc::default(),
            compiles: Arc::default(),
        };
        let candidates: Vec<_> = (1..=5)
            .map(|n| ConcreteVersion::new(n.to_string()))
            .collect();
        let set = grammar_candidates(grammar.clone(), &candidates);
        let requirements: Vec<_> = (1..=4).map(|n| VersionReq::new(n.to_string())).collect();

        for requirement in &requirements {
            assert!(set.satisfying(bounded(requirement)).is_some());
        }

        assert_eq!(grammar.parses.load(Ordering::SeqCst), candidates.len());
        assert_eq!(grammar.compiles.load(Ordering::SeqCst), requirements.len());
    }

    #[test]
    fn the_candidate_set_and_the_matcher_agree_and_skip_unparseable_candidates() {
        let grammar = CountingGrammar {
            parses: Arc::default(),
            compiles: Arc::default(),
        };
        let candidates: Vec<_> = ["1", "x", "3"].map(ConcreteVersion::new).into();
        let requirement = VersionReq::new("2");

        let mask = grammar_candidates(grammar.clone(), &candidates)
            .satisfying(bounded(&requirement))
            .unwrap();
        let matcher = grammar_matcher(grammar, bounded(&requirement)).unwrap();
        let by_matcher: Vec<bool> = candidates
            .iter()
            .map(|version| matcher.matches(version) == Some(true))
            .collect();

        assert_eq!(mask, [false, false, true]);
        assert_eq!(mask, by_matcher);
    }

    #[test]
    fn an_unmodellable_requirement_is_none_for_both_views() {
        let grammar = CountingGrammar {
            parses: Arc::default(),
            compiles: Arc::default(),
        };
        let requirement = VersionReq::new("not a number");
        assert!(grammar_matcher(grammar.clone(), bounded(&requirement)).is_none());
        assert!(
            grammar_candidates(grammar, &[ConcreteVersion::new("1")])
                .satisfying(bounded(&requirement))
                .is_none()
        );
    }
}
