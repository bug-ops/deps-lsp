//! Per-package diagnostic suppression (#1927, spec 094).
//!
//! A [`SuppressionSet`] is the typed, validated form of `diagnostics.suppress` in the shared
//! policy config. It is compiled against an ecosystem's name normalization once per diagnostics
//! run ([`SuppressionSet::resolve`]) and applied inside
//! [`generate_diagnostics_from_cache`](super::generate_diagnostics_from_cache), so every
//! ecosystem honors a rule identically.
//!
//! Only the closed [`SuppressionKind`] set is suppressible. Vulnerability advisories are never
//! suppressible: workspace settings can be controlled by the repository being opened, so a
//! repo-supplied rule must not be able to hide a security finding. The single exception is an
//! advisory classified as unmaintained, which is hidden together with the deprecation it
//! duplicates (FR-008).

use serde::Deserialize;

use super::{EcosystemFormatter, NormalizeName};
use crate::PackageName;
use crate::diagnostic::DiagnosticKind;
use crate::osv::{DependencyVulnerabilities, VulnSeverity};
use crate::package::NormalizedName;

/// A diagnostic kind a user may suppress for a package.
///
/// Deliberately narrower than [`DiagnosticKind`]; the mapping is the exhaustive match in
/// `SuppressedKinds::hides`.
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::SuppressionKind;
///
/// let kind: SuppressionKind = serde_json::from_str("\"deprecated\"").unwrap();
/// assert_eq!(kind, SuppressionKind::Deprecated);
/// assert!(serde_json::from_str::<SuppressionKind>("\"vulnerability\"").is_err());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SuppressionKind {
    /// The package is deprecated, including its unmaintained advisories.
    Deprecated,
    /// A newer version is available.
    Outdated,
    /// The in-use or only-matching version is yanked.
    Yanked,
    /// The declared license violates the configured license policy.
    License,
}

/// A set of [`SuppressionKind`]s.
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::{SuppressedKinds, SuppressionKind};
///
/// let kinds = SuppressedKinds::default().with(SuppressionKind::Yanked);
/// assert!(kinds.contains(SuppressionKind::Yanked));
/// assert!(!kinds.contains(SuppressionKind::Outdated));
/// ```
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SuppressedKinds(u8);

impl SuppressedKinds {
    const fn bit(kind: SuppressionKind) -> u8 {
        match kind {
            SuppressionKind::Deprecated => 1,
            SuppressionKind::Outdated => 2,
            SuppressionKind::Yanked => 4,
            SuppressionKind::License => 8,
        }
    }

    /// This set plus `kind`.
    #[must_use]
    pub const fn with(self, kind: SuppressionKind) -> Self {
        Self(self.0 | Self::bit(kind))
    }

    /// Every kind in either set.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Whether `kind` is in the set.
    #[must_use]
    pub const fn contains(self, kind: SuppressionKind) -> bool {
        self.0 & Self::bit(kind) != 0
    }

    /// Whether no kind is in the set.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Whether a diagnostic of `kind` for a package with this suppression set must be dropped.
    ///
    /// `vulnerabilities` is that package's resolved OSV finding; an advisory is hidden only when
    /// the deprecated kind is suppressed and the advisory is typed
    /// [`VulnSeverity::Informational`], which only the unmaintained allowlist produces. Neither
    /// `Diagnostic::severity` nor message text is consulted.
    pub(crate) fn hides(
        self,
        kind: &DiagnosticKind,
        vulnerabilities: Option<&DependencyVulnerabilities>,
    ) -> bool {
        match kind {
            DiagnosticKind::Outdated => self.contains(SuppressionKind::Outdated),
            DiagnosticKind::Yanked => self.contains(SuppressionKind::Yanked),
            DiagnosticKind::LicensePolicy => self.contains(SuppressionKind::License),
            DiagnosticKind::Deprecated => self.contains(SuppressionKind::Deprecated),
            DiagnosticKind::Advisory(id) => {
                self.contains(SuppressionKind::Deprecated)
                    && vulnerabilities.is_some_and(|dv| {
                        dv.advisories
                            .items()
                            .iter()
                            .any(|a| a.id() == id && a.severity == VulnSeverity::Informational)
                    })
            }
            DiagnosticKind::FlaggedLatest
            | DiagnosticKind::UnverifiedLatest
            | DiagnosticKind::AdvisoryOverflow
            | DiagnosticKind::Unsatisfiable
            | DiagnosticKind::Typosquat
            | DiagnosticKind::MutableRefPin(_)
            | DiagnosticKind::ShaCommentMismatch
            | DiagnosticKind::UnknownRef
            | DiagnosticKind::UnresolvedGitlabHost
            | DiagnosticKind::DuplicateDefaultCatalog
            | DiagnosticKind::Notice => false,
        }
    }
}

/// Why a package pattern was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PatternError {
    /// The pattern is the empty string.
    #[error("package pattern must not be empty")]
    Empty,
    /// The pattern is a bare `*`, which would match every package.
    #[error("a bare `*` package pattern is not allowed")]
    BareWildcard,
    /// A `*` that is not the only leading or only trailing character.
    #[error("`*` is only supported as a single leading or trailing wildcard")]
    UnsupportedWildcard,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PatternShape {
    Exact(String),
    Prefix(String),
    Suffix(String),
}

/// A validated package name or single-wildcard glob (`name`, `prefix*`, `*suffix`).
///
/// Matching is linear-time string comparison, never a regex.
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::PackagePattern;
///
/// assert!(PackagePattern::parse("@types/*").is_ok());
/// assert!(PackagePattern::parse("*").is_err());
/// assert!(PackagePattern::parse("a*b").is_err());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub struct PackagePattern(PatternShape);

impl PackagePattern {
    /// Parses `raw` into a pattern.
    ///
    /// # Errors
    ///
    /// [`PatternError`] when `raw` is empty, a bare `*`, or has a `*` anywhere but as the single
    /// leading or trailing character.
    pub fn parse(raw: &str) -> Result<Self, PatternError> {
        if raw.is_empty() {
            return Err(PatternError::Empty);
        }
        if raw == "*" {
            return Err(PatternError::BareWildcard);
        }
        let stars = raw.matches('*').count();
        let shape = match (stars, raw.strip_suffix('*'), raw.strip_prefix('*')) {
            (0, _, _) => PatternShape::Exact(raw.to_owned()),
            (1, Some(prefix), _) => PatternShape::Prefix(prefix.to_owned()),
            (1, None, Some(suffix)) => PatternShape::Suffix(suffix.to_owned()),
            _ => return Err(PatternError::UnsupportedWildcard),
        };
        Ok(Self(shape))
    }

    fn resolve(&self, formatter: &dyn EcosystemFormatter) -> ResolvedPattern {
        let normalize = |literal: &str| {
            formatter
                .normalize_package_name(&PackageName::new(literal))
                .into_string()
        };
        ResolvedPattern(match &self.0 {
            PatternShape::Exact(s) => PatternShape::Exact(normalize(s)),
            PatternShape::Prefix(s) => PatternShape::Prefix(normalize(s)),
            PatternShape::Suffix(s) => PatternShape::Suffix(normalize(s)),
        })
    }
}

impl TryFrom<String> for PackagePattern {
    type Error = PatternError;

    fn try_from(raw: String) -> Result<Self, Self::Error> {
        Self::parse(&raw)
    }
}

/// A [`PackagePattern`] whose literal parts went through one ecosystem's name normalization.
#[derive(Debug, Clone)]
struct ResolvedPattern(PatternShape);

impl ResolvedPattern {
    fn matches(&self, name: &NormalizedName) -> bool {
        let name = name.as_str();
        match &self.0 {
            PatternShape::Exact(s) => name == s,
            PatternShape::Prefix(s) => name.starts_with(s.as_str()),
            PatternShape::Suffix(s) => name.ends_with(s.as_str()),
        }
    }
}

/// Why a suppression rule was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RuleError {
    /// `kinds` was an empty list.
    #[error("suppression rule must list at least one kind")]
    NoKinds,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRule {
    package: PackagePattern,
    kinds: Vec<SuppressionKind>,
}

/// One user-declared exemption: a package pattern and the kinds it silences.
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::{SuppressionKind, SuppressionRule};
///
/// let rule: SuppressionRule =
///     serde_json::from_str(r#"{"package":"request","kinds":["deprecated"]}"#).unwrap();
/// assert!(rule.kinds().contains(SuppressionKind::Deprecated));
/// assert!(serde_json::from_str::<SuppressionRule>(r#"{"package":"x","kinds":[]}"#).is_err());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "RawRule")]
pub struct SuppressionRule {
    package: PackagePattern,
    kinds: SuppressedKinds,
}

impl SuppressionRule {
    /// The kinds this rule silences; never empty.
    #[must_use]
    pub const fn kinds(&self) -> SuppressedKinds {
        self.kinds
    }
}

impl TryFrom<RawRule> for SuppressionRule {
    type Error = RuleError;

    fn try_from(raw: RawRule) -> Result<Self, Self::Error> {
        if raw.kinds.is_empty() {
            return Err(RuleError::NoKinds);
        }
        let kinds = raw
            .kinds
            .into_iter()
            .fold(SuppressedKinds::default(), SuppressedKinds::with);
        Ok(Self {
            package: raw.package,
            kinds,
        })
    }
}

/// The compiled `diagnostics.suppress` rule list, in declaration order.
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::SuppressionSet;
///
/// let set: SuppressionSet =
///     serde_json::from_str(r#"[{"package":"@types/*","kinds":["outdated"]}]"#).unwrap();
/// assert!(!set.is_empty());
/// assert!(SuppressionSet::default().is_empty());
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(transparent)]
pub struct SuppressionSet {
    rules: Vec<SuppressionRule>,
}

impl SuppressionSet {
    /// Builds a set from already-validated rules.
    #[must_use]
    pub const fn new(rules: Vec<SuppressionRule>) -> Self {
        Self { rules }
    }

    /// Whether no rule is configured.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Normalizes every pattern through `formatter` once, for repeated per-dependency lookups.
    #[must_use]
    pub fn resolve(&self, formatter: &dyn EcosystemFormatter) -> ResolvedSuppression {
        ResolvedSuppression {
            rules: self
                .rules
                .iter()
                .map(|rule| (rule.package.resolve(formatter), rule.kinds))
                .collect(),
        }
    }
}

/// A [`SuppressionSet`] normalized for one ecosystem.
#[derive(Debug, Clone, Default)]
pub struct ResolvedSuppression {
    rules: Vec<(ResolvedPattern, SuppressedKinds)>,
}

impl ResolvedSuppression {
    /// The union of the kinds of every rule matching `name`.
    #[must_use]
    pub fn kinds_for(&self, name: &NormalizedName) -> SuppressedKinds {
        self.rules
            .iter()
            .filter(|(pattern, _)| pattern.matches(name))
            .fold(SuppressedKinds::default(), |acc, (_, kinds)| {
                acc.union(*kinds)
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::StubFormatter;

    const FORMATTER: StubFormatter = StubFormatter::new().with_package_url_prefix("");

    fn set(json: &str) -> SuppressionSet {
        serde_json::from_str(json).unwrap()
    }

    fn kinds(set: &SuppressionSet, name: &str) -> SuppressedKinds {
        set.resolve(&FORMATTER)
            .kinds_for(&NormalizedName::for_test(name))
    }

    #[test]
    fn pattern_shapes_are_validated() {
        assert_eq!(PackagePattern::parse(""), Err(PatternError::Empty));
        assert_eq!(PackagePattern::parse("*"), Err(PatternError::BareWildcard));
        assert_eq!(
            PackagePattern::parse("a*b"),
            Err(PatternError::UnsupportedWildcard)
        );
        assert_eq!(
            PackagePattern::parse("**"),
            Err(PatternError::UnsupportedWildcard)
        );
        assert_eq!(
            PackagePattern::parse("*a*"),
            Err(PatternError::UnsupportedWildcard)
        );
        assert!(PackagePattern::parse("*-sys").is_ok());
    }

    #[test]
    fn exact_prefix_and_suffix_match() {
        let s = set(r#"[
                {"package":"request","kinds":["deprecated"]},
                {"package":"@types/*","kinds":["outdated"]},
                {"package":"*-sys","kinds":["yanked"]}
            ]"#);
        assert!(kinds(&s, "request").contains(SuppressionKind::Deprecated));
        assert!(kinds(&s, "requests").is_empty());
        assert!(kinds(&s, "@types/node").contains(SuppressionKind::Outdated));
        assert!(kinds(&s, "types-extra").is_empty());
        assert!(kinds(&s, "openssl-sys").contains(SuppressionKind::Yanked));
    }

    #[test]
    fn overlapping_rules_union_their_kinds() {
        let s = set(r#"[
                {"package":"left-pad","kinds":["outdated"]},
                {"package":"left-*","kinds":["yanked"]}
            ]"#);
        let k = kinds(&s, "left-pad");
        assert!(k.contains(SuppressionKind::Outdated));
        assert!(k.contains(SuppressionKind::Yanked));
        assert!(!k.contains(SuppressionKind::Deprecated));
    }

    #[test]
    fn invalid_rules_are_rejected() {
        for bad in [
            r#"[{"package":"x","kinds":[]}]"#,
            r#"[{"package":"x","kinds":["vulnerability"]}]"#,
            r#"[{"package":"*","kinds":["outdated"]}]"#,
            r#"[{"package":"x","kinds":["outdated"],"extra":1}]"#,
            r#"[{"kinds":["outdated"]}]"#,
        ] {
            assert!(
                serde_json::from_str::<SuppressionSet>(bad).is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn hides_maps_every_suppressible_kind_and_nothing_else() {
        let all = [
            SuppressionKind::Deprecated,
            SuppressionKind::Outdated,
            SuppressionKind::Yanked,
            SuppressionKind::License,
        ]
        .into_iter()
        .fold(SuppressedKinds::default(), SuppressedKinds::with);
        for (kind, hidden) in [
            (DiagnosticKind::Outdated, true),
            (DiagnosticKind::Yanked, true),
            (DiagnosticKind::LicensePolicy, true),
            (DiagnosticKind::Deprecated, true),
            (DiagnosticKind::FlaggedLatest, false),
            (DiagnosticKind::UnverifiedLatest, false),
            (DiagnosticKind::AdvisoryOverflow, false),
            (DiagnosticKind::Unsatisfiable, false),
            (DiagnosticKind::Typosquat, false),
            (DiagnosticKind::Notice, false),
        ] {
            assert_eq!(all.hides(&kind, None), hidden, "{kind:?}");
            assert!(!SuppressedKinds::default().hides(&kind, None), "{kind:?}");
        }
    }
}
