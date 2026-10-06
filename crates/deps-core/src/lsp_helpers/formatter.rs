//! Ecosystem-specific formatting and comparison logic, split into concern-scoped traits.
//!
//! [`EcosystemFormatter`] is kept as a single object-safe marker bound so every existing
//! `&dyn EcosystemFormatter` call site is untouched; it is automatically implemented for any
//! type implementing all seven concern traits below via a blanket impl, so implementors never
//! write `impl EcosystemFormatter for X` themselves. The seven traits are independent siblings
//! — none of them has a default method that calls a method living in a different trait — so
//! implementing a subset of them (e.g. in a test mock that only needs [`PackageRendering`]) is
//! always sufficient for calling that subset's methods directly, without pulling in the rest.

use crate::package::strip_build_metadata;
use crate::position::Position;

use super::{
    BoundedVersionReq, RequirementMatcher, RequirementStatus, is_same_major_minor,
    position_in_range,
};
use crate::{
    ConcreteVersion, Dependency, EcosystemId, InvalidPackageName, PackageName, VersionReq,
};

/// Ecosystem-specific package name normalization and validation.
///
/// Implementors guarantee that [`normalize_package_name`](Self::normalize_package_name)
/// produces a stable lookup key for the same logical package regardless of how its name is
/// spelled in a manifest, and that [`validate_package_name`](Self::validate_package_name) is a
/// diagnostic lint only — never a construction-time gate. Callers may assume both methods are
/// cheap, side-effect-free, and safe to call on unvalidated, manifest-sourced input.
pub trait PackageNaming: Send + Sync {
    /// Normalize package name for lookup (default: identity).
    fn normalize_package_name(&self, name: &PackageName) -> String {
        name.as_str().to_string()
    }

    /// Lints `name` against ecosystem-specific naming rules.
    ///
    /// Default: permissive, always `Ok(())`. This is a diagnostic lint, not a
    /// construction-time gate — [`PackageName::new`](crate::PackageName::new)
    /// stays infallible regardless of what this returns. Override only to warn
    /// on names an ecosystem's own tooling would never accept; err on the side
    /// of accepting anything ambiguous, since a false positive here is a
    /// warning on a manifest the user's actual package manager treats as fine.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidPackageName`] carrying the reason `name` fails this
    /// ecosystem's naming rules. The default implementation never errs.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::lsp_helpers::PackageNaming;
    ///
    /// struct PermissiveFormatter;
    ///
    /// impl PackageNaming for PermissiveFormatter {}
    ///
    /// // The default is permissive: any name, including one that would fail an
    /// // ecosystem-specific override, is accepted.
    /// assert!(PermissiveFormatter.validate_package_name("../not/a/real/rule").is_ok());
    /// ```
    fn validate_package_name(&self, _name: &str) -> Result<(), InvalidPackageName> {
        Ok(())
    }
}

/// How a package/version renders into manifest text edits and hover content.
///
/// Implementors guarantee that [`format_version_for_text_edit`](Self::format_version_for_text_edit)
/// and [`package_url`](Self::package_url) — the trait's only two required methods — produce
/// text safe to embed directly in a manifest or hover response for any version/name that has
/// already passed the workspace's shared safety gates
/// ([`crate::is_safe_version_string`], [`crate::is_safe_package_name`]). Callers may assume the
/// replacement-preserving methods ([`format_version_replacing`](Self::format_version_replacing),
/// [`format_version_replacing_for`](Self::format_version_replacing_for)) never change a
/// requirement's semantics unless the ecosystem has explicitly opted in to that transformation.
///
/// Since #1391, implementors of [`format_version_replacing`](Self::format_version_replacing)/
/// [`format_version_replacing_for`](Self::format_version_replacing_for) need not guard against
/// an unexpanded placeholder themselves: [`crate::edit::replacement_text`] is the only
/// production path that calls into either method, and it never does so once
/// [`RequirementResolution::bounded_requirement_is_placeholder`](super::RequirementResolution::bounded_requirement_is_placeholder)
/// says `true` for the requirement being replaced.
pub trait PackageRendering: Send + Sync {
    /// Format version string for code action text edit.
    fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String;

    /// Format `version` as a replacement for the existing requirement text
    /// `current`, preserving `current`'s operator/pin style where the
    /// ecosystem supports more than one.
    ///
    /// Default: ignores `current`, delegating to
    /// [`format_version_for_text_edit`](Self::format_version_for_text_edit).
    /// Override when a bare `format_version_for_text_edit` replacement would
    /// silently change the requirement's semantics — e.g. PyPI's `==1.0.1`
    /// pin becoming `>=1.0.1,<2` on "update version" would defeat the point
    /// of pinning.
    fn format_version_replacing(&self, version: &ConcreteVersion, _current: &str) -> String {
        self.format_version_for_text_edit(version)
    }

    /// Like [`format_version_replacing`](Self::format_version_replacing), but also
    /// carries the dependency identity `version`/`current` apply to.
    ///
    /// Default: ignores `dep`, delegating to
    /// [`format_version_replacing`](Self::format_version_replacing). Override when the
    /// replacement text cannot be derived from `version`/`current` alone — e.g.
    /// `deps-github-actions`'s SHA-pinned `uses: owner/repo@<sha> # vX.Y.Z` form, where
    /// the new SHA for a given tag is looked up per `dep.name()` (a tag's commit SHA is
    /// per-repository, unknowable from the tag string alone) in a registry-populated
    /// index the formatter holds a shared handle to.
    ///
    /// Every shared call site that builds a version-update edit (the vulnerability and
    /// unsatisfiable-requirement quickfixes, the REFACTOR-loop "update to X" actions, and
    /// the "Update N outdated dependencies" code lens) already has `dep` in scope and
    /// calls this method instead of [`format_version_replacing`](Self::format_version_replacing)
    /// directly, so an override here is picked up on every edit path at once.
    fn format_version_replacing_for(
        &self,
        _dep: &dyn Dependency,
        version: &ConcreteVersion,
        current: &str,
    ) -> String {
        self.format_version_replacing(version, current)
    }

    /// Adjusts a candidate version's presentation before a completion item's
    /// `insert_text`/`text_edit` splices it into the manifest, given `typed_prefix` — the
    /// text already typed before the cursor (possibly empty).
    ///
    /// Default: identity (`version.to_string()`) — completion has always inserted the
    /// registry's version string verbatim, and this default keeps that behavior unchanged
    /// for every ecosystem with no completion-time presentation concern of its own.
    ///
    /// Deliberately **not** [`format_version_replacing`](Self::format_version_replacing):
    /// that method's `current` parameter means "the full existing declared requirement
    /// text" (needed to reconstruct e.g. PyPI's `==X`-preserving rewrite from a complete
    /// pin) — `typed_prefix` is only the partially-typed text before the cursor, never a
    /// complete requirement, so an override reusing `format_version_replacing`'s contract
    /// here would corrupt a PyPI-style completion (issue #1435 S3: this was tried and
    /// reverted after it broke exactly that case). Override this method directly instead,
    /// for a narrower concern — e.g. `deps-composer`'s `ComposerFormatter` overrides it to
    /// preserve the typed prefix's `v`-style against Packagist's raw, unstripped tag text.
    fn format_version_for_completion(
        &self,
        version: &ConcreteVersion,
        typed_prefix: &str,
    ) -> String {
        let _ = typed_prefix;
        version.to_string()
    }

    /// Get package URL for hover markdown.
    fn package_url(&self, name: &PackageName) -> String;

    /// Whether hover should omit [`Self::package_url`]'s heading link for a dependency
    /// resolved against `source`.
    ///
    /// [`Self::package_url`] always names the ecosystem's *default* public registry (e.g.
    /// crates.io) — correct for a plain [`DependencySource::Registry`](crate::parser::DependencySource::Registry)
    /// dependency, but wrong for one resolved against a different registry entirely (e.g.
    /// `deps-cargo`'s resolved `AlternateRegistry`): once live version data from that other
    /// registry renders alongside the link, an unrelated crates.io link reads as
    /// confirmation the link is real, which is worse than showing no link at all.
    ///
    /// Default: suppressed whenever `source` is not exactly
    /// [`DependencySource::Registry`](crate::parser::DependencySource::Registry) — safe for
    /// any ecosystem with only one registry concept, including one that has not yet
    /// classified any non-`Registry` source (the link only hides once a dependency is
    /// actually classified as `Git`/`Path`/`Url`/... elsewhere). Only `deps-cargo`'s
    /// `CargoFormatter` still overrides this directly, because it also overrides
    /// [`SourcePolicy::source_is_public_registry_content`](crate::lsp_helpers::SourcePolicy::source_is_public_registry_content)
    /// to treat a crates.io-mirroring `AlternateRegistry` as linkable content too — a
    /// distinction this default cannot express without `SourcePolicy` as a supertrait of
    /// this trait, which would force every isolated `PackageRendering`-only implementor
    /// (e.g. test mocks) to also implement it.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::lsp_helpers::PackageRendering;
    /// use deps_core::parser::DependencySource;
    /// use deps_core::{ConcreteVersion, PackageName};
    ///
    /// struct DefaultFormatter;
    /// impl PackageRendering for DefaultFormatter {
    ///     fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
    ///         version.to_string()
    ///     }
    ///     fn package_url(&self, name: &PackageName) -> String {
    ///         name.as_str().to_string()
    ///     }
    /// }
    ///
    /// assert!(!DefaultFormatter.suppress_package_url(&DependencySource::Registry));
    /// assert!(DefaultFormatter.suppress_package_url(&DependencySource::Path {
    ///     path: "../local".into(),
    /// }));
    /// ```
    fn suppress_package_url(&self, source: &crate::parser::DependencySource) -> bool {
        !matches!(source, crate::parser::DependencySource::Registry)
    }

    /// Detect if cursor position is on a dependency for code actions.
    fn is_position_on_dependency(&self, dep: &dyn Dependency, position: Position) -> bool {
        dep.version_range()
            .is_some_and(|r| position_in_range(position, r))
    }
}

/// Whether a "no operator" (bare) version-requirement string means an auto-following range or
/// an exact pin.
///
/// This is the axis [`format_version_replacing_by_shape`] needs to decide whether a
/// bounded/compound/wildcard requirement can be safely collapsed to a bare version. It is NOT
/// the same question as [`RequirementRewriteShape`] answers: that type classifies
/// a requirement's own *syntax* (does it have an operator, is it a range); this type answers
/// what the *absence* of an operator means for a given ecosystem, which is not universal — the
/// #1576/impl-critic finding that motivated this type was exactly the bug of assuming Cargo's
/// bare-means-caret convention held for npm/Dart too, when their bare-means-exact-pin
/// convention makes every "collapse to bare" rewrite a narrowing, never a widening.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BareMeaning {
    /// A bare version auto-follows compatible future releases (Cargo's implicit `^`) — so
    /// replacing a bounded requirement ([`RequirementRewriteShape::SingleBound`],
    /// [`RequirementRewriteShape::PartialWildcard`], [`RequirementRewriteShape::Compound`])
    /// with a bare version WIDENS what it accepts, and must be refused.
    Caret,
    /// A bare version means exactly that version and nothing else (npm/node-semver, Dart's pub
    /// constraint grammar, RubyGems) — so replacing any bounded requirement with a bare
    /// version NARROWS (or leaves identical) what it accepts, and is always safe.
    ExactPin,
    /// A bare version is a minimum-only floor with no upper bound (NuGet's `Version="1.0.0"`,
    /// Maven's "soft" recommended version, Gradle's `require` constraint) — so, like
    /// [`Caret`](Self::Caret), replacing a bounded requirement with a bare version WIDENS what
    /// it accepts (the upper bound is dropped) and must be refused. #1602: distinct from
    /// `Caret` because these ecosystems have no auto-following range semantics at all (no `^`),
    /// only a floor — but the rewrite-safety consequence for a bounded range is identical, so
    /// [`format_version_replacing_by_shape`] treats both the same way for
    /// [`RequirementRewriteShape::Compound`], [`RequirementRewriteShape::PartialWildcard`], and
    /// [`RequirementRewriteShape::SingleBound`].
    Floor,
}

/// Whether an ecosystem's version comparison distinguishes versions that differ only by their
/// `+build` suffix.
///
/// SemVer 2.0.0 gives build metadata no precedence, so most ecosystems treat `1.2.3+a` and
/// `1.2.3+b` as the same release. Pub does not: `+N` build revisions are distinct, ordered
/// releases (#1687), so a pin at `0.8.13+1` is outdated against `0.8.13+23`.
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::BuildMetadataPolicy;
///
/// assert!(BuildMetadataPolicy::Ignored.versions_equal("1.2.3+1", "1.2.3+23"));
/// assert!(!BuildMetadataPolicy::Significant.versions_equal("1.2.3+1", "1.2.3+23"));
/// assert!(!BuildMetadataPolicy::Ignored.versions_equal("1.2.3", "1.2.4+1"));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuildMetadataPolicy {
    /// SemVer 2.0.0 precedence: build metadata is discarded before comparing.
    Ignored,
    /// Build metadata is part of the version's identity (Dart/pub).
    Significant,
}

impl BuildMetadataPolicy {
    /// Whether `a` and `b` name the same version under this policy.
    #[must_use]
    pub fn versions_equal(self, a: &str, b: &str) -> bool {
        match self {
            Self::Ignored => strip_build_metadata(a) == strip_build_metadata(b),
            Self::Significant => a == b,
        }
    }
}

/// The [`BareMeaning`] a bare (no-operator) version requirement carries under `ecosystem`.
///
/// The single, exhaustive source [`format_version_replacing_by_shape`] callers should derive
/// their `bare_meaning` argument from.
///
/// This answers a *different* question from `lsp_helpers::in_use_version`'s private
/// `bare_requirement_policy`: that function asks "can a bare requirement's text alone be
/// treated as a single concrete version for in-use-version/OSV-target resolution", this asks
/// "does rewriting a bounded range to bare change what the requirement accepts" — the #1602 bug
/// class was exactly these two being conflated for Maven and Gradle, which
/// `bare_requirement_policy` groups under its `Concrete` variant (a bare version is a usable
/// resolution pin) even though their bare meaning for *rewrite* purposes is
/// [`BareMeaning::Floor`], not [`BareMeaning::ExactPin`]. `in_use_version`'s own test module
/// cross-checks the two functions stay logically consistent for the one invariant they do
/// share: an ecosystem is [`BareMeaning::Caret`] here if and only if it is
/// `BareRequirementPolicy::AlwaysRange` there.
///
/// # Examples
///
/// ```
/// use deps_core::EcosystemId;
/// use deps_core::lsp_helpers::{BareMeaning, bare_meaning};
///
/// assert_eq!(bare_meaning(EcosystemId::Cargo), BareMeaning::Caret);
/// assert_eq!(bare_meaning(EcosystemId::Dart), BareMeaning::ExactPin);
/// assert_eq!(bare_meaning(EcosystemId::NuGet), BareMeaning::Floor);
/// assert_eq!(bare_meaning(EcosystemId::Maven), BareMeaning::Floor);
/// assert_eq!(bare_meaning(EcosystemId::Gradle), BareMeaning::Floor);
/// ```
#[must_use]
pub const fn bare_meaning(ecosystem: EcosystemId) -> BareMeaning {
    match ecosystem {
        EcosystemId::Cargo => BareMeaning::Caret,
        EcosystemId::Maven | EcosystemId::Gradle | EcosystemId::NuGet => BareMeaning::Floor,
        EcosystemId::Npm
        | EcosystemId::Pypi
        | EcosystemId::Go
        | EcosystemId::Bundler
        | EcosystemId::Dart
        | EcosystemId::Composer
        | EcosystemId::Swift
        | EcosystemId::Deno
        | EcosystemId::GithubActions
        | EcosystemId::GitlabCi => BareMeaning::ExactPin,
    }
}

/// Structural shape of a version-requirement string, classified for
/// [`format_version_replacing_by_shape`]'s decision on whether replacing it with a single
/// concrete version preserves what it accepts.
///
/// Whether [`Compound`](Self::Compound), [`PartialWildcard`](Self::PartialWildcard), and
/// [`SingleBound`](Self::SingleBound) have a safe rewrite depends on [`BareMeaning`] — see that
/// type's docs. [`AnyVersion`](Self::AnyVersion), [`Bare`](Self::Bare),
/// [`ExactPin`](Self::ExactPin), and [`Tilde`](Self::Tilde) always have one, regardless of
/// `BareMeaning`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequirementRewriteShape {
    /// No operator at all (a plain version number) — the ecosystem's own `bare` rewrite
    /// closure decides the replacement text, since what "no operator" should render as on
    /// rewrite differs per ecosystem (a plain version string for Cargo/npm/Dart's own bare
    /// constraint — never a `^`-prefixed one, even for an ecosystem whose *new-dependency*
    /// insertion convention is caret-prefixed, e.g. Dart's `pub add`).
    Bare,
    /// An explicit `^` caret operator. Under [`BareMeaning::Caret`] this is redundant with
    /// [`Bare`](Self::Bare) (bare already means caret), so the rewrite may drop it and call
    /// `bare` like any other no-special-operator shape; under [`BareMeaning::ExactPin`] this is
    /// a genuinely wider range than bare, so the rewrite must keep the `^` prefix.
    ExplicitCaret,
    /// A leading `=` exact-pin operator — the rewrite must keep the `=` prefix.
    ExactPin,
    /// A bracket-wrapped exact pin with no internal comma (NuGet/Maven/Gradle's `[1.0.0]`) —
    /// the bracket-interval grammars' spelling of "exactly this version, nothing else". Always
    /// preserved with its bracket wrap, regardless of [`BareMeaning`]: unlike
    /// [`ExplicitCaret`](Self::ExplicitCaret), no ecosystem using this bracket syntax also uses
    /// [`BareMeaning::Caret`], so there is no meaning under which collapsing it to bare would be
    /// safe. A bracket-interval *range* (`[1.0,2.0)`) always has an internal comma and is
    /// therefore already [`Compound`](Self::Compound) before this variant is ever considered.
    BracketExactPin,
    /// A leading tilde-family operator (Cargo's `~`, RubyGems' `~>`) — the rewrite must keep
    /// the tilde spelling.
    Tilde,
    /// A bare existence wildcard (`*`, empty, or Dart's `any`) that matches every version —
    /// collapsing it to one concrete version is always a narrowing, regardless of
    /// [`BareMeaning`], since "anything" can only ever shrink.
    AnyVersion,
    /// A version with a `*`/`x`/`X` core segment (e.g. `1.2.*`, `1.x`) — no single concrete
    /// version re-expresses "any patch/minor", so under [`BareMeaning::Caret`] there is no safe
    /// rewrite (see [`BareMeaning::Caret`]'s docs).
    PartialWildcard,
    /// A single asymmetric bound (`<`, `<=`, `>`, `>=`) — under [`BareMeaning::Caret`],
    /// collapsing to a bare version would silently turn an open-ended bound into an
    /// auto-following range (see [`BareMeaning::Caret`]'s docs).
    SingleBound,
    /// More than one comparator, joined by a comma (Cargo, RubyGems: `">=1.2, <1.5"`) or
    /// whitespace (npm/Dart AND-ranges: `">=1.2.0 <2.0.0"`, a hyphen range), or an npm `||`
    /// OR-set — no single comparator's rewrite represents the whole set, so under
    /// [`BareMeaning::Caret`] there is no safe rewrite (see [`BareMeaning::Caret`]'s docs).
    Compound,
}

/// Single-operator prefixes this module recognizes, longest-first so `~>` is never mistaken
/// for bare `~`, `<=`/`>=` are never mistaken for bare `<`/`>`, and `!=` is never mistaken for
/// bare `=` (only RubyGems has `!=`, but recognizing it keeps [`requirement_is_compound`]
/// correct for it too).
const REWRITE_OPERATOR_PREFIXES: [&str; 9] = ["~>", "!=", "<=", ">=", "=", "~", "^", "<", ">"];

/// Strips a single leading operator (see [`REWRITE_OPERATOR_PREFIXES`]) and any whitespace
/// immediately following it, leaving only the operand — e.g. `"= 1.6.13"` -> `"1.6.13"`,
/// `"~> 1.2.3"` -> `"1.2.3"`, `"^ 1.2.3"` -> `"1.2.3"`. Returns `trimmed` unchanged when no
/// recognized operator prefixes it (a bare version).
fn strip_requirement_operator(trimmed: &str) -> &str {
    REWRITE_OPERATOR_PREFIXES
        .iter()
        .find_map(|op| trimmed.strip_prefix(op))
        .map_or(trimmed, str::trim_start)
}

/// Whether `requirement` is built from more than one comparator.
///
/// Comma-joined (Cargo, RubyGems: `">=1.2, <1.5"`), `||`-joined (npm OR-sets, spaced or not:
/// `"^1||^2"`), or whitespace-joined once a single leading operator and its own adjacent
/// spacing are stripped via `strip_requirement_operator` (npm/Dart AND-ranges, hyphen
/// ranges). Stripping only the operator's own spacing — not every occurrence of a comparator
/// symbol — means a single bound written with a space after its operator (`"> 1.0"`,
/// `"= 1.6.13"`) is not mistaken for a two-comparator requirement.
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::requirement_is_compound;
///
/// assert!(requirement_is_compound(">=1.2, <1.5"));
/// assert!(requirement_is_compound(">=1.2.0 <2.0.0"));
/// assert!(requirement_is_compound("^1||^2"));
/// assert!(!requirement_is_compound("<1.5"));
/// assert!(!requirement_is_compound("> 1.0"));
/// assert!(!requirement_is_compound("= 1.6.13"));
/// assert!(!requirement_is_compound("^ 1.2.3"));
/// assert!(!requirement_is_compound("^1.2.3"));
/// ```
#[must_use]
pub fn requirement_is_compound(requirement: &str) -> bool {
    let trimmed = requirement.trim();
    trimmed.contains(',')
        || trimmed.contains("||")
        || strip_requirement_operator(trimmed).contains(char::is_whitespace)
}

/// Whether `requirement` — assumed already checked via [`requirement_is_compound`] and found
/// not compound, and not already recognized as an operator-prefixed shape — is a bare
/// existence wildcard that matches every version (see
/// [`RequirementRewriteShape::AnyVersion`]).
fn requirement_is_any_version_wildcard(requirement: &str) -> bool {
    crate::is_existence_wildcard_str(requirement) || requirement.eq_ignore_ascii_case("any")
}

/// Whether `requirement` — assumed already checked via [`requirement_is_any_version_wildcard`]
/// and found not a bare wildcard — has a `*` wildcard anywhere (including in a prerelease
/// float like NuGet's `1.2.0-rc.*`), an `x`/`X` wildcard segment in its version core, or
/// Gradle's trailing `+` dynamic-version marker (e.g. `1.0.+`, `2.5.+`) (see
/// [`RequirementRewriteShape::PartialWildcard`]).
///
/// #1602 impl-critic S2: `*` is checked against the *whole* string, not just the version core
/// — unlike `x`/`X`, a literal `*` is never a legitimate prerelease identifier in any
/// supported ecosystem's grammar, so there is no equivalent false-positive risk to guard
/// against by restricting it to the core (a `1.2.0-rc.*` float pinned to the `1.2.0` line
/// must not fall through to [`RequirementRewriteShape::Bare`], which would silently turn it
/// into an unbounded floor/caret range on rewrite). The `x`/`X` check stays restricted to the
/// segments before the first `-`/`+` (the version core, before any prerelease/build-metadata
/// part) so a prerelease identifier that happens to be a single letter `x` (e.g.
/// `1.0.0-alpha.x`) is not mistaken for a wildcard segment. The trailing-`+` check runs first
/// and independently of that split: Gradle's dynamic marker is the version core's own trailing
/// character, not a build-metadata separator, so `1.0.+` must not be routed through the
/// `split(['-', '+'])` core-isolation logic at all (`"1.0.+".split('+').next()` would silently
/// discard the marker as if it were spurious build metadata).
///
/// Deliberately not scoped to Gradle alone: this classifier is shared across every ecosystem
/// that calls [`format_version_replacing_by_shape`] (Cargo, Dart, NuGet, Maven, Gradle), and no
/// other ecosystem's requirement grammar produces a bare, unmarked trailing `+` today — a real
/// semver build-metadata suffix always has content after the `+` (`1.0.0+build`), so it never
/// reaches this check with an empty tail. Threading an `EcosystemId`/bool parameter through
/// this shared classifier to narrow the check to Gradle alone was considered and rejected as
/// unwarranted complexity for a check with no current false-positive case; revisit if a future
/// ecosystem's grammar ever legitimately produces a bare trailing `+`.
fn requirement_is_partial_wildcard_shape(requirement: &str) -> bool {
    if requirement.len() > 1 && requirement.ends_with('+') {
        return true;
    }
    if requirement.contains('*') {
        return true;
    }
    let core = requirement.split(['-', '+']).next().unwrap_or(requirement);
    core.split('.').any(|segment| matches!(segment, "x" | "X"))
}

/// Whether `requirement` is a bracket-wrapped exact pin — `[` ... `]` with no internal comma
/// (NuGet/Maven/Gradle's `[1.0.0]`) — as opposed to a bracket-interval *range* (`[1.0,2.0)`),
/// which always contains a comma and is therefore classified [`RequirementRewriteShape::Compound`]
/// by [`requirement_is_compound`] before this function is ever consulted. Only square brackets
/// are recognized: an unpaired `(`/`)` alone (without a comma) is not valid interval syntax in
/// any of these ecosystems' grammars, so treating it as an exact pin here would be a guess this
/// function is not meant to make.
fn requirement_is_bracket_exact_pin(requirement: &str) -> bool {
    requirement.len() > 2
        && requirement.starts_with('[')
        && requirement.ends_with(']')
        && !requirement.contains(',')
}

/// Classifies `requirement`'s structural shape for
/// [`format_version_replacing_by_shape`].
///
/// Known limitation: `!=` is one of `REWRITE_OPERATOR_PREFIXES` (so
/// [`requirement_is_compound`] strips it correctly), but this function has no dedicated shape
/// variant for it — a requirement like `"!=1.0.0"` falls through to
/// [`RequirementRewriteShape::Bare`]. Harmless today: no ecosystem that calls this function
/// (Cargo, npm, Dart) has a `!=` operator in its grammar; only RubyGems does, and Bundler
/// doesn't call this function (see its `format_version_replacing_for`'s own docs).
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::{RequirementRewriteShape, classify_requirement_rewrite_shape};
///
/// assert_eq!(classify_requirement_rewrite_shape("1.2.3"), RequirementRewriteShape::Bare);
/// assert_eq!(
///     classify_requirement_rewrite_shape("^1.2.3"),
///     RequirementRewriteShape::ExplicitCaret
/// );
/// assert_eq!(classify_requirement_rewrite_shape("=1.2.3"), RequirementRewriteShape::ExactPin);
/// assert_eq!(classify_requirement_rewrite_shape("~1.2.3"), RequirementRewriteShape::Tilde);
/// assert_eq!(classify_requirement_rewrite_shape("~>1.2.3"), RequirementRewriteShape::Tilde);
/// assert_eq!(classify_requirement_rewrite_shape("*"), RequirementRewriteShape::AnyVersion);
/// assert_eq!(
///     classify_requirement_rewrite_shape("1.2.*"),
///     RequirementRewriteShape::PartialWildcard
/// );
/// assert_eq!(classify_requirement_rewrite_shape("<1.5"), RequirementRewriteShape::SingleBound);
/// assert_eq!(
///     classify_requirement_rewrite_shape(">=1.2, <1.5"),
///     RequirementRewriteShape::Compound
/// );
/// assert_eq!(
///     classify_requirement_rewrite_shape("[1.0.0]"),
///     RequirementRewriteShape::BracketExactPin
/// );
/// // A bracket-interval range always has an internal comma, so it classifies as Compound,
/// // not BracketExactPin.
/// assert_eq!(
///     classify_requirement_rewrite_shape("[1.0,2.0)"),
///     RequirementRewriteShape::Compound
/// );
/// // Gradle's dynamic-version marker has no single-version rewrite either.
/// assert_eq!(
///     classify_requirement_rewrite_shape("1.0.+"),
///     RequirementRewriteShape::PartialWildcard
/// );
/// ```
#[must_use]
pub fn classify_requirement_rewrite_shape(requirement: &str) -> RequirementRewriteShape {
    let trimmed = requirement.trim();
    if requirement_is_compound(trimmed) {
        return RequirementRewriteShape::Compound;
    }
    if trimmed.starts_with('=') {
        return RequirementRewriteShape::ExactPin;
    }
    if requirement_is_bracket_exact_pin(trimmed) {
        return RequirementRewriteShape::BracketExactPin;
    }
    if trimmed.starts_with("~>") || trimmed.starts_with('~') {
        return RequirementRewriteShape::Tilde;
    }
    if trimmed.starts_with('^') {
        return RequirementRewriteShape::ExplicitCaret;
    }
    if requirement_is_any_version_wildcard(trimmed) {
        return RequirementRewriteShape::AnyVersion;
    }
    if requirement_is_partial_wildcard_shape(trimmed) {
        return RequirementRewriteShape::PartialWildcard;
    }
    if ["<=", "<", ">=", ">"]
        .iter()
        .any(|op| trimmed.starts_with(op))
    {
        return RequirementRewriteShape::SingleBound;
    }
    RequirementRewriteShape::Bare
}

/// Default requirement-rewrite policy driven by [`classify_requirement_rewrite_shape`] and
/// `bare_meaning`.
///
/// Always preserves an [`ExactPin`](RequirementRewriteShape::ExactPin),
/// [`BracketExactPin`](RequirementRewriteShape::BracketExactPin), or
/// [`Tilde`](RequirementRewriteShape::Tilde) operator, and always calls `bare` for
/// [`AnyVersion`](RequirementRewriteShape::AnyVersion) or
/// [`Bare`](RequirementRewriteShape::Bare) (collapsing either is always safe, regardless of
/// `bare_meaning` — see those variants' docs). For
/// [`ExplicitCaret`](RequirementRewriteShape::ExplicitCaret),
/// [`PartialWildcard`](RequirementRewriteShape::PartialWildcard),
/// [`SingleBound`](RequirementRewriteShape::SingleBound), and
/// [`Compound`](RequirementRewriteShape::Compound), the answer depends on `bare_meaning`: under
/// [`BareMeaning::Caret`] or [`BareMeaning::Floor`] the requirement is echoed back unchanged (no
/// safe single-value rewrite — `ExplicitCaret` collapses via `bare` instead only under `Caret`,
/// since under that `bare_meaning` alone a bare version already means caret); under
/// [`BareMeaning::ExactPin`] every one of them collapses safely (`ExplicitCaret` keeping its
/// `^` prefix, since bare would narrow it to something other than a range).
///
/// # Examples
///
/// ```
/// use deps_core::ConcreteVersion;
/// use deps_core::lsp_helpers::{BareMeaning, format_version_replacing_by_shape};
///
/// let new_version = ConcreteVersion::new("2.0.0");
/// assert_eq!(
///     format_version_replacing_by_shape(&new_version, "=1.5.0", BareMeaning::Caret, || {
///         new_version.to_string()
///     }),
///     "=2.0.0"
/// );
/// assert_eq!(
///     format_version_replacing_by_shape(
///         &new_version,
///         ">=1.2, <1.5",
///         BareMeaning::Caret,
///         || new_version.to_string()
///     ),
///     ">=1.2, <1.5"
/// );
/// assert_eq!(
///     format_version_replacing_by_shape(
///         &new_version,
///         ">=1.2.0 <1.5.0",
///         BareMeaning::ExactPin,
///         || new_version.to_string()
///     ),
///     "2.0.0"
/// );
/// ```
#[must_use]
pub fn format_version_replacing_by_shape(
    version: &ConcreteVersion,
    current: &str,
    bare_meaning: BareMeaning,
    bare: impl FnOnce() -> String,
) -> String {
    match classify_requirement_rewrite_shape(current) {
        RequirementRewriteShape::Compound
        | RequirementRewriteShape::PartialWildcard
        | RequirementRewriteShape::SingleBound => match bare_meaning {
            BareMeaning::Caret | BareMeaning::Floor => current.to_string(),
            BareMeaning::ExactPin => bare(),
        },
        // No ecosystem with `BareMeaning::Floor` has an explicit `^` caret operator in its
        // grammar, so this arm is unreachable in practice — echoed back unchanged, mirroring
        // `Caret`'s own refusal on every other unsafe shape above, since there is no known-safe
        // rewrite to fall back on.
        RequirementRewriteShape::ExplicitCaret => match bare_meaning {
            BareMeaning::Caret => bare(),
            BareMeaning::Floor => current.to_string(),
            BareMeaning::ExactPin => format!("^{}", version.as_str()),
        },
        RequirementRewriteShape::AnyVersion | RequirementRewriteShape::Bare => bare(),
        RequirementRewriteShape::ExactPin => format!("={}", version.as_str()),
        RequirementRewriteShape::BracketExactPin => format!("[{}]", version.as_str()),
        RequirementRewriteShape::Tilde => {
            // Reconstructs whichever tilde spelling `current` actually used, rather than
            // hardcoding `~` — `~>` is RubyGems' spelling (Bundler doesn't call this function
            // today, but nothing here should silently mangle it if that ever changes).
            let prefix = if current.trim_start().starts_with("~>") {
                "~>"
            } else {
                "~"
            };
            format!("{prefix}{}", version.as_str())
        }
    }
}

/// Splits `component` (a single dot-component, or a whole version string) at its first `-`/`+`
/// marker, returning the core before it and whether that marker was `-` (a prerelease suffix,
/// which sorts below the bare numeric value — unlike `+` build metadata, which doesn't affect
/// ordering).
fn split_patch_component(component: &str) -> (&str, bool) {
    component
        .char_indices()
        .find(|&(_, c)| c == '-' || c == '+')
        .map_or((component, false), |(idx, marker)| {
            (component.split_at(idx).0, marker == '-')
        })
}

/// Whether `version` satisfies a tilde requirement whose text (already stripped of its `~`
/// prefix) is `req` — patch-level changes only: `~X.Y.Z` -> `[X.Y.Z, X.(Y+1).0)`, `~X.Y` ->
/// `[X.Y.0, X.(Y+1).0)`, `~X` -> `[X.0.0, (X+1).0.0)`.
///
/// [`is_same_major_minor`] already enforces the major/minor upper bound (and the
/// shorter-requirement floor defaults for `~X`/`~X.Y`); this adds the explicit patch floor a
/// 3-component `~X.Y.Z` requirement needs on top of it, including a suffixed patch on either
/// side and a missing candidate patch (treated as `0`). Falls back to permissive
/// (`is_same_major_minor`'s own verdict) whenever either side's patch component isn't a plain,
/// in-range `u64` once its suffix is stripped — a wildcard (`x`/`X`/`*`), other non-numeric text,
/// or a component too large to fit `u64`.
fn tilde_admits_version(req: &str, version: &str) -> bool {
    if !is_same_major_minor(req, version) {
        return false;
    }

    let Some(required_component) = req.split('.').nth(2) else {
        return true;
    };
    let (required_core, required_is_prerelease) = split_patch_component(required_component);
    let Ok(required_patch) = required_core.parse::<u64>() else {
        return true;
    };

    let candidate_component = version.split('.').nth(2).unwrap_or("0");
    let (candidate_core, candidate_is_prerelease) = split_patch_component(candidate_component);
    let Ok(candidate_patch) = candidate_core.parse::<u64>() else {
        return true;
    };

    match candidate_patch.cmp(&required_patch) {
        std::cmp::Ordering::Less => false,
        std::cmp::Ordering::Greater => true,
        // ~1.5.3-beta.1 admits any prerelease at that patch — short of full semver precedence
        std::cmp::Ordering::Equal => !candidate_is_prerelease || required_is_prerelease,
    }
}

/// Parses up to the first 3 dot-separated `parts` as `u64`, padding any components beyond
/// `parts.len()` with `0`. Returns `None` if any of the first 3 parts fails to parse as a
/// non-negative integer.
fn parse_caret_components(parts: &[&str]) -> Option<[u64; 3]> {
    let mut out = [0u64; 3];
    for (slot, part) in out.iter_mut().zip(parts.iter()) {
        *slot = part.parse().ok()?;
    }
    Some(out)
}

/// Whether `part` is npm's wildcard-range component token (`x`, `X`, or `*`) — used in both
/// partial-version requirements (`1.x`, `1.2.x`, `1.2.*`) and caret requirements (`^1.5.x`,
/// `^1.5.*`) to mean "matches any value in this position", npm's own interpretation of the
/// syntax (#1641, #1637).
fn is_wildcard_component(part: &str) -> bool {
    matches!(part, "x" | "X" | "*")
}

/// The requirement components to use for matching, truncated at the first wildcard token
/// (`x`/`X`/`*`) and everything after it — npm's own semantics treat a wildcard component as
/// "not specified", which also silently wildcards every component after it (node-semver's
/// `replaceXRange` sets `xp = xm || isX(p)`): `1.x.5` behaves identically to `1.x`, and
/// `^1.5.x` behaves identically to `^1.5`. Shared by both the plain/partial-version wildcard
/// check ([`matches_wildcard_components`], #1641) and caret bounding
/// ([`RequirementResolution::version_satisfies_bounded_requirement`]'s `^` branch and
/// [`caret_admits_up_to_date`], #1637), so neither has to understand wildcards itself — both
/// just consume a possibly-shorter, wildcard-free `req_parts` slice.
///
/// Callers must check for an empty result themselves: an empty slice means the *first*
/// component was already a wildcard (`^x`, `*`), which is "matches any value" — treating it as
/// zero given components (`^` with nothing after it, i.e. `[0, 0, 0]`) would wrongly bound the
/// match to major version `0` only, contradicting the "any value" meaning.
fn truncate_at_wildcard<'a>(req_parts: &'a [&'a str]) -> &'a [&'a str] {
    let Some(idx) = req_parts
        .iter()
        .position(|part| is_wildcard_component(part))
    else {
        return req_parts;
    };
    req_parts.get(..idx).unwrap_or(req_parts)
}

/// Whether every component of `req_parts` up to its first wildcard token (`x`/`X`/`*`) equals
/// the same-position component of `version_parts` — a wildcard component and everything after it
/// match any value (see [`truncate_at_wildcard`]). Requires `req_parts` to actually contain a
/// wildcard — otherwise this is not the right check, since plain-equality/partial-prefix matching
/// already covers a non-wildcard requirement — and `version_parts` to have at least as many
/// components as the truncated prefix, since a wildcard requirement is still a partial/floor
/// match rather than an exact-length one (#1641).
fn matches_wildcard_components(req_parts: &[&str], version_parts: &[&str]) -> bool {
    if !req_parts.iter().any(|part| is_wildcard_component(part)) {
        return false;
    }
    let effective = truncate_at_wildcard(req_parts);
    version_parts.len() >= effective.len()
        && effective
            .iter()
            .zip(version_parts.iter())
            .all(|(req, ver)| req == ver)
}

/// The exclusive upper bound of a `^`-requirement whose lower bound is `lower`
/// (`parse_caret_components`'s output) and whose requirement text had `req_parts` given
/// components: increments the left-most non-zero component among those given, zeroing
/// everything after it — or, if every given component is `0`, increments the last given
/// component instead (`^0.0` -> `<0.1.0`, `^0.0.0` -> `<0.0.1`).
///
/// Returns `None` when that increment would overflow `u64` (an unrealistic version component,
/// but not something a caller can rule out) — the caller then treats the caret requirement as
/// having no upper bound at all, rather than panicking (debug) or silently wrapping to `0`
/// (release), the same overflow class #1619 already fixed in `deps-composer`'s own
/// `increment_last_segment`.
fn caret_upper_bound(lower: [u64; 3], req_parts: &[&str]) -> Option<[u64; 3]> {
    let given_len = req_parts.len().min(3);
    let bump_index = lower
        .iter()
        .take(given_len)
        .position(|&component| component != 0)
        .unwrap_or_else(|| given_len.saturating_sub(1));

    let [major, minor, patch] = lower;
    Some(match bump_index {
        0 => [major.checked_add(1)?, 0, 0],
        1 => [major, minor.checked_add(1)?, 0],
        _ => [major, minor, patch.checked_add(1)?],
    })
}

/// Truncates `version` at its first `-` (prerelease) or `+` (build metadata) marker, so the
/// numeric `major.minor.patch` core can still be split and parsed by
/// [`parse_caret_components`] even when the candidate carries a suffix that component-wise
/// `u64` parsing can't handle directly (#1622 S3: without this, a suffixed candidate like
/// `1.4.9-beta` silently defeated the caret lower-bound floor by falling through to the
/// pre-#1622, major-only fallback). Also applied to the *requirement* text's own floor component
/// since #1637, to collapse a prerelease/build-suffixed requirement (`^1.5.0-beta.1`) down to
/// its numeric floor `1.5.0` — a deliberate simplification that drops semver prerelease
/// precedence, not full prerelease-range semantics. Wildcard requirement components (`x`/`X`/
/// `*`) are a separate concern handled by [`truncate_at_wildcard`], not by this function.
#[expect(
    clippy::string_slice,
    reason = "cut is either a `find(['-', '+'])` match index (both ASCII, so always a char \
              boundary) or version.len() itself, so the slice bound is always a char boundary"
)]
fn strip_version_suffix(version: &str) -> &str {
    let cut = version.find(['-', '+']).unwrap_or(version.len());
    &version[..cut]
}

/// `requirement` with every simple `^X.Y.Z` token replaced by its major-wide range
/// (`>=X.0.0 <A.B.C`, the caret's exclusive upper bound), or `None` when no token was replaced.
///
/// Extends #1622 S2 (a caret's lower-bound floor must not make `latest` look outdated) to
/// compound requirements: `^1.5 <1.9` -> `>=1.0.0 <2.0.0 <1.9`.
/// Tokens are delimited by whitespace, `|`, and `,`; wildcard-led or unparseable carets are
/// left untouched. `bound_sep` joins the two bounds of a replaced caret (`" "` for npm-style
/// grammars, `", "` for Cargo's comma-separated one, whose parser rejects a bare space).
fn relax_caret_floors(requirement: &str, bound_sep: &str) -> Option<String> {
    let is_sep = |c: char| c.is_whitespace() || matches!(c, '|' | ',');
    let mut out = String::with_capacity(requirement.len());
    let mut replaced = false;
    let mut rest = requirement;
    while !rest.is_empty() {
        let (token, tail) = rest.split_at(rest.find(is_sep).unwrap_or(rest.len()));
        let (sep, next) = tail.split_at(tail.find(|c: char| !is_sep(c)).unwrap_or(tail.len()));
        let bound = token.strip_prefix('^').and_then(|body| {
            let parts: Vec<&str> = strip_version_suffix(body).split('.').collect();
            let effective = truncate_at_wildcard(&parts);
            if effective.is_empty() {
                return None;
            }
            let lower = parse_caret_components(effective)?;
            Some((lower[0], caret_upper_bound(lower, effective)?))
        });
        match bound {
            Some((floor_major, [major, minor, patch])) => {
                replaced = true;
                out.push_str(&format!(
                    ">={floor_major}.0.0{bound_sep}<{major}.{minor}.{patch}"
                ));
            }
            None => out.push_str(token),
        }
        out.push_str(sep);
        rest = next;
    }
    replaced.then_some(out)
}

/// Whether `latest` is still within a `^`-requirement's exclusive *upper* bound (the
/// auto-following range's ceiling) — ignoring the requirement's own minor/patch lower-bound
/// floor #1622 added to [`RequirementResolution::version_satisfies_bounded_requirement`]'s `^` branch.
///
/// [`RequirementResolution::is_bounded_requirement_up_to_date`]'s default asks "is `latest` still
/// within what this requirement would resolve to", not "does `latest` satisfy every clause of
/// the requirement" — `latest` is the newest *available* version (already excluding
/// yanked/prerelease/cooldown-held releases upstream), so it can legitimately sit below a
/// caret's own lower-bound floor (every `>=1.5` release of a `^1.5` dependency yanked, `latest`
/// still `1.4.9`) without the dependency being outdated in any actionable sense — a manifest
/// edit here would plan a downgrade, not an upgrade. #1622's lower-bound enforcement must stay
/// scoped to `version_satisfies_requirement`'s own general-purpose membership question (e.g.
/// lock-file in-use-version checks), not leak into this one.
///
/// Returns `None` when `requirement` doesn't start with `^`, or what follows the `^` is not a
/// single simple token (whitespace, `|`, or another comparator character: `^3 || ^4`,
/// `^4.5 <4.7`) so the caller falls back to its own general-purpose check for every other shape.
fn caret_admits_up_to_date(latest: &str, requirement: &str) -> Option<bool> {
    let req = requirement.strip_prefix('^')?;
    if req.contains(|c: char| {
        c.is_whitespace() || matches!(c, '|' | '<' | '>' | '=' | '~' | '^' | ',')
    }) {
        return None;
    }
    let req = strip_version_suffix(req);
    let req_parts: Vec<&str> = req.split('.').collect();
    let ver_parts: Vec<&str> = strip_version_suffix(latest).split('.').collect();

    match (req_parts.first(), ver_parts.first()) {
        (Some(r), Some(v)) if is_wildcard_component(r) || r == v => {}
        _ => return Some(false),
    }

    let effective_req_parts = truncate_at_wildcard(&req_parts);
    if effective_req_parts.is_empty() {
        // The requirement's first component was itself a wildcard (`^x`, `^*`) — npm treats
        // this as "any version", not as a caret with zero given components (which would
        // wrongly bound the match to major version `0` only, per `truncate_at_wildcard`'s doc).
        return Some(true);
    }
    let (Some(lower), Some(candidate)) = (
        parse_caret_components(effective_req_parts),
        parse_caret_components(&ver_parts),
    ) else {
        return Some(true);
    };

    Some(caret_upper_bound(lower, effective_req_parts).is_none_or(|upper| candidate < upper))
}

/// The shared default verdict behind [`RequirementResolution::is_requirement_up_to_date`].
fn up_to_date_via_heuristic<F: RequirementResolution + ?Sized>(
    formatter: &F,
    requirement: BoundedVersionReq<'_>,
    latest: &ConcreteVersion,
) -> bool {
    caret_admits_up_to_date(latest.as_str(), requirement.as_str()).unwrap_or_else(|| {
        formatter.version_satisfies_bounded_requirement(latest, requirement)
            || relax_caret_floors(requirement.as_str(), " ").is_some_and(|relaxed| {
                let relaxed = VersionReq::new(relaxed);
                BoundedVersionReq::new(&relaxed).is_some_and(|relaxed| {
                    formatter.version_satisfies_bounded_requirement(latest, relaxed)
                })
            })
    })
}

/// Whether `requirement`'s shape needs real range semantics: compound requirements, `=` pins,
/// and single `<`/`<=`/`>`/`>=` bounds — the shapes the default string heuristic has no branch
/// for. A wildcard version behind a leading operator (`>=1.*`) counts too; every other shape
/// keeps the heuristic.
fn requirement_needs_range_semantics(requirement: &str) -> bool {
    match classify_requirement_rewrite_shape(requirement) {
        RequirementRewriteShape::Compound
        | RequirementRewriteShape::ExactPin
        | RequirementRewriteShape::SingleBound => true,
        RequirementRewriteShape::PartialWildcard => {
            let trimmed = requirement.trim();
            strip_requirement_operator(trimmed) != trimmed
        }
        RequirementRewriteShape::Bare
        | RequirementRewriteShape::ExplicitCaret
        | RequirementRewriteShape::BracketExactPin
        | RequirementRewriteShape::Tilde
        | RequirementRewriteShape::AnyVersion => false,
    }
}

/// Up-to-date verdict that asks the compiled requirement matcher about comparator-style
/// requirements only, keeping the shared default heuristic for everything else.
///
/// For Cargo-style ecosystems where a bare version (`1.0.228`) is deliberately judged by the
/// pin heuristic (an exact bump is "outdated"), yet `=1.2.3`, `<2` and `>=1.2, <2` need real
/// range semantics instead of the default's string comparison (#1660). Meant to back an
/// [`RequirementResolution::is_bounded_requirement_up_to_date`] override; comparator shapes get
/// the semantics of [`up_to_date_via_compiled_matcher`].
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::{
///     BoundedVersionReq, RequirementMatcher, RequirementResolution,
///     up_to_date_for_comparators_via_compiled_matcher,
/// };
/// use deps_core::{ConcreteVersion, VersionReq};
///
/// struct MajorOne;
/// impl RequirementMatcher for MajorOne {
///     fn matches(&self, version: &ConcreteVersion) -> Option<bool> {
///         Some(version.as_str().starts_with("1."))
///     }
///     fn strict_prerelease_exclusion(&self) -> bool {
///         true
///     }
/// }
///
/// struct Formatter;
/// impl RequirementResolution for Formatter {
///     fn compile_bounded_requirement(
///         &self,
///         _: BoundedVersionReq<'_>,
///     ) -> Option<Box<dyn RequirementMatcher>> {
///         Some(Box::new(MajorOne))
///     }
/// }
///
/// let latest = ConcreteVersion::new("1.5.0");
/// let up_to_date = |req: &str| {
///     let requirement = VersionReq::new(req);
///     let bounded = BoundedVersionReq::new(&requirement).unwrap();
///     up_to_date_for_comparators_via_compiled_matcher(&Formatter, bounded, &latest)
/// };
/// assert!(up_to_date("<2"));
/// // A bare version keeps the default pin heuristic.
/// assert!(!up_to_date("1.4.0"));
/// ```
pub fn up_to_date_for_comparators_via_compiled_matcher<F: RequirementResolution + ?Sized>(
    formatter: &F,
    requirement: BoundedVersionReq<'_>,
    latest: &ConcreteVersion,
) -> bool {
    if requirement_needs_range_semantics(requirement.as_str()) {
        up_to_date_via_compiled_matcher(formatter, requirement, latest)
    } else {
        up_to_date_via_heuristic(formatter, requirement, latest)
    }
}

/// Up-to-date verdict backed by the compiled requirement matcher.
///
/// For ecosystems whose [`RequirementResolution::compile_bounded_requirement`] matcher models
/// the full requirement grammar (comparators, `||`, hyphen ranges, wildcards); meant to back a
/// [`RequirementResolution::is_bounded_requirement_up_to_date`] override.
///
/// A single simple `^` requirement keeps the default's upper-bound-only semantics (#1622 S2);
/// everything else is asked of the compiled matcher, also retried with caret floors relaxed to
/// their upper bounds (S2 for compound requirements) and against `latest`'s numeric core (a
/// prerelease `latest` is judged by its `X.Y.Z`, but only when the matcher opts into
/// [`RequirementMatcher::strict_prerelease_exclusion`], the same gate `diagnostics.rs` applies
/// to its numeric-core retry, #1661). Falls back to
/// [`RequirementResolution::version_satisfies_bounded_requirement`] when the requirement does
/// not compile or the matcher cannot judge `latest`.
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::{
///     BoundedVersionReq, RequirementMatcher, RequirementResolution, up_to_date_via_compiled_matcher,
/// };
/// use deps_core::{ConcreteVersion, VersionReq};
///
/// struct AtLeastOne;
/// impl RequirementMatcher for AtLeastOne {
///     fn matches(&self, version: &ConcreteVersion) -> Option<bool> {
///         Some(version.as_str().starts_with("1."))
///     }
///     fn strict_prerelease_exclusion(&self) -> bool {
///         false
///     }
/// }
///
/// struct Formatter;
/// impl RequirementResolution for Formatter {
///     fn compile_bounded_requirement(
///         &self,
///         _: BoundedVersionReq<'_>,
///     ) -> Option<Box<dyn RequirementMatcher>> {
///         Some(Box::new(AtLeastOne))
///     }
/// }
///
/// let latest = ConcreteVersion::new("1.4.0");
/// let requirement = VersionReq::new(">=1 <2");
/// let bounded = BoundedVersionReq::new(&requirement).unwrap();
/// assert!(up_to_date_via_compiled_matcher(&Formatter, bounded, &latest));
/// ```
pub fn up_to_date_via_compiled_matcher<F: RequirementResolution + ?Sized>(
    formatter: &F,
    requirement: BoundedVersionReq<'_>,
    latest: &ConcreteVersion,
) -> bool {
    if let Some(admitted) = caret_admits_up_to_date(latest.as_str(), requirement.as_str()) {
        return admitted;
    }
    let Some(matcher) = formatter.compile_bounded_requirement(requirement) else {
        return formatter.version_satisfies_bounded_requirement(latest, requirement);
    };
    let core = ConcreteVersion::new(strip_version_suffix(latest.as_str()));
    let admits = |m: &dyn RequirementMatcher| {
        m.matches(latest) == Some(true)
            || (m.strict_prerelease_exclusion() && m.matches(&core) == Some(true))
    };
    let bound_sep = if requirement.as_str().contains(',') {
        ", "
    } else {
        " "
    };
    let relaxed = relax_caret_floors(requirement.as_str(), bound_sep)
        .map(VersionReq::new)
        .and_then(|relaxed| {
            BoundedVersionReq::new(&relaxed)
                .and_then(|bounded| formatter.compile_bounded_requirement(bounded))
        });
    if admits(&*matcher) || relaxed.as_deref().is_some_and(admits) {
        true
    } else if matcher.matches(latest).is_none() {
        formatter.version_satisfies_bounded_requirement(latest, requirement)
    } else {
        false
    }
}

/// Requirement parsing, matching, and up-to-date status.
///
/// Implementors guarantee every method here is a pure function of its arguments — no network
/// or filesystem access — since these run on the hot hover/diagnostic path. The default
/// [`classify_requirement_status`](Self::classify_requirement_status) maps
/// [`bounded_requirement_is_unresolved`](Self::bounded_requirement_is_unresolved) to its `Unresolved` variant
/// and otherwise defers to [`is_bounded_requirement_up_to_date`](Self::is_bounded_requirement_up_to_date). Most
/// ecosystems whose requirement syntax can be unresolved (Maven, Gradle, NuGet, Cargo, npm, ...)
/// need only override [`bounded_requirement_is_placeholder`](Self::bounded_requirement_is_placeholder) —
/// `requirement_is_unresolved` defaults to delegating to it. Only `deps-github-actions` and
/// `deps-gitlab-ci` override `requirement_is_unresolved` directly, since their two predicates
/// answer genuinely different questions there (see `requirement_is_placeholder`'s doc). Callers
/// needing the tri-state distinction use
/// [`RequirementGate::requirement_status`], not the boolean method.
pub trait RequirementResolution: Send + Sync {
    /// Whether `+build` suffixes distinguish versions in this ecosystem's comparisons.
    ///
    /// Default: [`BuildMetadataPolicy::Ignored`] (SemVer 2.0.0). `deps-dart` overrides it with
    /// [`BuildMetadataPolicy::Significant`], since pub orders `+N` build revisions (#1687).
    /// Consulted by the shared pin equality in [`Self::version_satisfies_bounded_requirement`] (the
    /// path behind every requirement-vs-latest verdict: diagnostics, code lenses, code
    /// actions, `deps-cli`) and by the inlay-hint resolved-vs-latest check. Any new
    /// ecosystem-blind equality between an in-use or pinned version and a candidate must go
    /// through it rather than drop build metadata itself.
    fn build_metadata_policy(&self) -> BuildMetadataPolicy {
        BuildMetadataPolicy::Ignored
    }

    /// Check if a version satisfies a requirement string.
    ///
    /// General constraint check (e.g. for completion/candidate filtering) — not the
    /// "is this dependency up to date" hook. That is `is_bounded_requirement_up_to_date` below,
    /// which has its own default and its own override points; an ecosystem whose bare
    /// requirement is a floor rather than an auto-following range (see `deps-nuget`)
    /// overrides that method, not this one.
    ///
    /// Takes a [`BoundedVersionReq`]: [`RequirementGate::version_satisfies_requirement`] — the
    /// entry point callers use — reports an oversized requirement `false` before this hook is
    /// ever called.
    fn version_satisfies_bounded_requirement(
        &self,
        version: &ConcreteVersion,
        requirement: BoundedVersionReq<'_>,
    ) -> bool {
        let requirement = requirement.as_str();
        let version = version.as_str();
        // Caret allows changes that don't modify the left-most non-zero component, but never
        // below the requirement's own minor/patch floor: ^1.5 -> [1.5.0, 2.0.0), ^0.2 ->
        // [0.2.0, 0.3.0), ^0.0.3 -> [0.0.3, 0.0.4) (#1622, mirroring #1619's fix for
        // `deps-composer`'s own `satisfies_caret`).
        if let Some(req) = requirement.strip_prefix('^') {
            // Collapses a prerelease/build-suffixed requirement floor (`^1.5.0-beta.1`) to its
            // numeric core, same simplification `strip_version_suffix` already applies to
            // candidates (#1637).
            let req = strip_version_suffix(req);
            let req_parts: Vec<&str> = req.split('.').collect();
            let ver_parts: Vec<&str> = strip_version_suffix(version).split('.').collect();

            // Must have same major version — an `x`/`X`/`*` major component (e.g. `^x.5.0`,
            // vanishingly rare in practice) matches any candidate major.
            match (req_parts.first(), ver_parts.first()) {
                (Some(r), Some(v)) if is_wildcard_component(r) || r == v => {}
                _ => return false,
            }

            // A wildcard component (`^1.5.x`, `^1.5.*`) is treated as "not specified", the same
            // as a shorter `^1.5` requirement (#1637) — see `truncate_at_wildcard`.
            let effective_req_parts = truncate_at_wildcard(&req_parts);
            if effective_req_parts.is_empty() {
                // The requirement's first component was itself a wildcard (`^x`, `^*`,
                // `^x.5.0`) — npm treats this as "any version", not as a caret with zero given
                // components (which would wrongly bound the match to major version `0` only).
                return true;
            }
            let (Some(lower), Some(candidate)) = (
                parse_caret_components(effective_req_parts),
                parse_caret_components(&ver_parts),
            ) else {
                // A non-numeric, non-wildcard component is unusual for a bare `^X.Y[.Z]`
                // requirement — fall back to the major-only check already confirmed above.
                return true;
            };

            return candidate >= lower
                && caret_upper_bound(lower, effective_req_parts)
                    .is_none_or(|upper| candidate < upper);
        }

        // Tilde allows patch-level changes: ~2.0 -> 2.0.x, ~2.0.1 -> 2.0.x where x >= 1
        if let Some(req) = requirement.strip_prefix('~') {
            return tilde_admits_version(req, version);
        }

        // Plain version, partial version, or npm's `x`/`X`/`*` wildcard-range requirement
        // (`1.x`, `1.2.x`, `1.2.*`) — the wildcard form can have up to 3 components, so it is
        // checked independently of `is_partial_version` rather than folded into it (#1641). The
        // raw `version.starts_with(requirement)` string check #1636 removed here wrongly
        // admitted e.g. `1.20.0` for a `1.2` requirement; `is_same_major_minor` against the
        // suffix-stripped `version_core` is the correct component-wise replacement, shared with
        // the wildcard check below.
        let req_parts: Vec<&str> = requirement.split('.').collect();
        let is_partial_version = req_parts.len() <= 2;
        let version_core = split_patch_component(version).0;
        let ver_parts: Vec<&str> = version_core.split('.').collect();

        self.build_metadata_policy().versions_equal(
            version,
            requirement.strip_prefix('=').unwrap_or(requirement),
        ) || (is_partial_version && is_same_major_minor(requirement, version_core))
            || matches_wildcard_components(&req_parts, &ver_parts)
    }

    /// Whether an unresolved dependency (no lock-file version) should be reported as
    /// up to date against `latest`, given its declared `requirement`.
    ///
    /// Default: for a `^`-requirement, whether `latest` sits below its exclusive upper bound
    /// only — `caret_admits_up_to_date`, ignoring the requirement's own minor/patch
    /// lower-bound floor (#1622 S2): `latest` is the newest *available* version, so it can
    /// legitimately sit below that floor (every `>=1.5` release of a `^1.5` dependency yanked,
    /// `latest` still `1.4.9`) without the dependency being outdated in any actionable sense —
    /// treating it as outdated here would have a caller plan a downgrade, not an upgrade. Every
    /// other requirement shape falls back to `latest` satisfies `requirement` — correct for
    /// range-based ecosystems (Cargo's `^1.2`, npm's `~1.2`, ...) where the declared requirement
    /// already expresses forward compatibility, so a `latest` it accepts is not "newer" in any
    /// actionable sense. Ecosystems where a bare requirement is a minimum floor rather than an
    /// auto-following range (NuGet's bare `Version="1.0.0"`) must override this, since "does the
    /// floor accept `latest`" and "is the pin already `latest`" are different questions there.
    ///
    /// Takes a [`BoundedVersionReq`]: an oversized requirement is unmodellable, and
    /// [`RequirementGate::is_requirement_up_to_date`] — the entry point callers use — reports it
    /// `true` (not outdated) before this hook is ever called, so an override has no oversized
    /// value it could mishandle.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::lsp_helpers::{BoundedVersionReq, RequirementResolution};
    /// use deps_core::{ConcreteVersion, VersionReq};
    ///
    /// struct DefaultFormatter;
    /// impl RequirementResolution for DefaultFormatter {}
    ///
    /// let requirement = VersionReq::new("^1.2");
    /// let bounded = BoundedVersionReq::new(&requirement).unwrap();
    /// assert!(DefaultFormatter.is_bounded_requirement_up_to_date(bounded, &ConcreteVersion::new("1.5.0")));
    /// assert!(!DefaultFormatter.is_bounded_requirement_up_to_date(bounded, &ConcreteVersion::new("2.0.0")));
    /// ```
    fn is_bounded_requirement_up_to_date(
        &self,
        requirement: BoundedVersionReq<'_>,
        latest: &ConcreteVersion,
    ) -> bool {
        up_to_date_via_heuristic(self, requirement, latest)
    }

    /// Whether `requirement` could not be resolved to a concrete version constraint (e.g. an
    /// unexpanded property/variable placeholder rather than a real version or range).
    ///
    /// Default: delegates to [`bounded_requirement_is_placeholder`](Self::bounded_requirement_is_placeholder),
    /// which is correct for every ecosystem except `deps-github-actions` and `deps-gitlab-ci`
    /// (see that method's doc for why their two predicates genuinely differ). Overriding
    /// `requirement_is_placeholder` alone therefore keeps both predicates in sync; only those
    /// two ecosystems need their own `requirement_is_unresolved` override.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::lsp_helpers::{BoundedVersionReq, RequirementResolution};
    /// use deps_core::VersionReq;
    ///
    /// struct DefaultFormatter;
    /// impl RequirementResolution for DefaultFormatter {}
    ///
    /// let requirement = VersionReq::new("^1.2");
    /// let bounded = BoundedVersionReq::new(&requirement).unwrap();
    /// assert!(!DefaultFormatter.bounded_requirement_is_unresolved(bounded));
    /// ```
    fn bounded_requirement_is_unresolved(&self, requirement: BoundedVersionReq<'_>) -> bool {
        self.bounded_requirement_is_placeholder(requirement)
    }

    /// Whether `requirement` is an unexpanded placeholder/interpolation (Maven's
    /// `${property}`, Gradle's `$var`, NuGet's `$(Property)`/`%(Metadata)`/`@(ItemList)`,
    /// Bundler's `#{...}`/`#@ivar`, Swift's `\(...)`, GitLab CI's `$VAR`/`${VAR}`/`%VAR%`)
    /// that must never be overwritten by a manifest rewrite, no matter what other requirement
    /// resolution predicate happens to say about it.
    ///
    /// Distinct from [`bounded_requirement_is_unresolved`](Self::bounded_requirement_is_unresolved): that
    /// predicate also covers a *concrete but undecidable* ref (a `deps-github-actions`/
    /// `deps-gitlab-ci` SHA or branch pin) which is safe, and sometimes intentional, to
    /// rewrite — a vulnerability-fix quickfix pinning a SHA forward is exactly that. This
    /// predicate answers only "is there literally no concrete version text here to
    /// replace", which is why the central edit-planning gates in
    /// [`crate::edit::plan_verified_fix`], [`crate::edit::collect_update_candidates`],
    /// `crate::lsp_helpers::code_actions`'s unsatisfiable-requirement fix builder, and the
    /// REFACTOR "Update to X" action loop consult this method, not `requirement_is_unresolved`,
    /// before ever calling into an ecosystem's rewrite/compile logic.
    ///
    /// For most ecosystems `requirement_is_placeholder` implies `requirement_is_unresolved`
    /// (both key off the same underlying detector) — but this is not a general subset
    /// guarantee an implementor must uphold: `deps-gitlab-ci`'s `requirement_is_unresolved`
    /// classifies purely from `PinStyle` (`Sha`/`Branch`), so a variable embedded in an
    /// otherwise `Tag`- or `Partial`-shaped ref (`v1.2-$BUILD`) is `requirement_is_placeholder`
    /// `true` but `requirement_is_unresolved` `false` there. The two predicates answer
    /// genuinely different questions — "never has concrete version text to rewrite" vs.
    /// "concrete but undecidably outdated" — and callers needing either guarantee must consult
    /// the specific predicate they need, not assume one implies the other.
    ///
    /// Default: the shared [`super::requirement_contains_template_placeholder`] detector —
    /// every ecosystem starts out recognizing the generic `{{ }}`/`<%= %>`/`@VAR@`/`%VAR%`/
    /// `${VAR}`/`$VAR` forms (#1391), not "never a placeholder". An override must always be
    /// `shared || native` — i.e. call the shared detector and OR it with any
    /// ecosystem-specific grammar (Maven's `${property}`, Gradle's `$var`, NuGet's
    /// `$(Property)`/`%(Metadata)`/`@(ItemList)`, ...) — never replace the shared check with a
    /// native-only one, or a generic form this ecosystem's manifest also accepts would stop
    /// being guarded. [`crate::conformance::assert_generic_template_placeholders_guarded`]
    /// (called unconditionally from every crate's `formatter_conformance!` invocation, and
    /// from `deps-engine`'s universal-invariants loop over every *registered* ecosystem) is
    /// the mandatory, non-opt-out gate that catches a native-only override. Ecosystems whose
    /// requirement syntax can contain an unexpanded placeholder override this single predicate
    /// instead of hand-rolling the same check separately inside
    /// [`format_version_replacing`](PackageRendering::format_version_replacing),
    /// [`compile_bounded_requirement`](Self::compile_bounded_requirement), and
    /// [`version_satisfies_bounded_requirement`](Self::version_satisfies_bounded_requirement) — and, since
    /// #1391, need not guard [`format_version_replacing`](PackageRendering::format_version_replacing)/
    /// [`format_version_replacing_for`](PackageRendering::format_version_replacing_for) at all:
    /// [`crate::edit::replacement_text`] is the only production path that ever calls into
    /// those methods, and it never does so once this predicate says `true`.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::lsp_helpers::{BoundedVersionReq, RequirementResolution};
    /// use deps_core::VersionReq;
    ///
    /// struct DefaultFormatter;
    /// impl RequirementResolution for DefaultFormatter {}
    ///
    /// let concrete = VersionReq::new("^1.2");
    /// let templated = VersionReq::new("{{ version }}");
    /// let concrete = BoundedVersionReq::new(&concrete).unwrap();
    /// let templated = BoundedVersionReq::new(&templated).unwrap();
    /// assert!(!DefaultFormatter.bounded_requirement_is_placeholder(concrete));
    /// assert!(DefaultFormatter.bounded_requirement_is_placeholder(templated));
    /// ```
    fn bounded_requirement_is_placeholder(&self, requirement: BoundedVersionReq<'_>) -> bool {
        super::requirement_contains_template_placeholder(requirement.as_str())
    }

    /// Tri-state variant of `is_bounded_requirement_up_to_date` that distinguishes "confirmed up to
    /// date" from "could not be resolved, so we don't know."
    ///
    /// Default: `Unresolved` when `requirement_is_unresolved` says so, otherwise maps the
    /// boolean result of `is_bounded_requirement_up_to_date` to `UpToDate`/`Outdated`. Callers
    /// needing the distinction — inlay hints, in particular — use
    /// [`RequirementGate::requirement_status`] so they can tell "verified up to date"
    /// apart from "resolution failed."
    ///
    /// Takes a [`BoundedVersionReq`] rather than `&VersionReq`: an oversized requirement is
    /// unmodellable, not verified up to date or outdated, and
    /// [`RequirementGate::requirement_status`] — the only production entry point —
    /// already rejects one before this hook is ever called, so an override has no oversized
    /// value it could mishandle.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::lsp_helpers::{BoundedVersionReq, RequirementResolution, RequirementStatus};
    /// use deps_core::{ConcreteVersion, VersionReq};
    ///
    /// struct DefaultFormatter;
    /// impl RequirementResolution for DefaultFormatter {}
    ///
    /// let requirement = VersionReq::new("^1.2");
    /// let bounded = BoundedVersionReq::new(&requirement).unwrap();
    /// assert_eq!(
    ///     DefaultFormatter.classify_requirement_status(bounded, &ConcreteVersion::new("1.5.0")),
    ///     RequirementStatus::UpToDate
    /// );
    /// assert_eq!(
    ///     DefaultFormatter.classify_requirement_status(bounded, &ConcreteVersion::new("2.0.0")),
    ///     RequirementStatus::Outdated
    /// );
    /// ```
    fn classify_requirement_status(
        &self,
        requirement: BoundedVersionReq<'_>,
        latest: &ConcreteVersion,
    ) -> RequirementStatus {
        if self.bounded_requirement_is_unresolved(requirement) {
            return RequirementStatus::Unresolved;
        }
        if self.is_bounded_requirement_up_to_date(requirement, latest) {
            RequirementStatus::UpToDate
        } else {
            RequirementStatus::Outdated
        }
    }

    /// Like [`classify_requirement_status`](Self::classify_requirement_status), but also hands
    /// the ecosystem the dependency itself — for an ecosystem whose requirement *text* alone is
    /// ambiguous between two shapes with different resolution rules, and which already computed
    /// the disambiguating classification once, at parse time, onto the dependency
    /// (`deps-gitlab-ci`'s `PinStyle`, #466 review M-c: a bare `"1.2"` is `Partial` under its
    /// `component:` pin grammar but `Branch` under its simpler `project:` ref grammar —
    /// indistinguishable from the text alone).
    ///
    /// Default: forwards to [`classify_requirement_status`](Self::classify_requirement_status),
    /// ignoring `dep` — every other ecosystem's requirement text alone is unambiguous, so this
    /// is a no-op for them. Callers that already have `dep` in hand (the diagnostic pipeline's
    /// outdated rule) call [`RequirementGate::requirement_status_for`] instead of
    /// [`RequirementGate::requirement_status`] directly, mirroring
    /// `Registry::select_latest_matching`'s identical additive-default pattern for its own
    /// `selection_context` parameter.
    fn classify_requirement_status_for(
        &self,
        dep: &dyn Dependency,
        requirement: BoundedVersionReq<'_>,
        latest: &ConcreteVersion,
    ) -> RequirementStatus {
        let _ = dep;
        self.classify_requirement_status(requirement, latest)
    }

    /// Compiles `requirement` into a matcher for precise membership testing against a list
    /// of candidate version strings, or `None` when this ecosystem cannot parse or cannot
    /// model this requirement form — in which case no unsatisfiable-requirement diagnostic
    /// is produced for it.
    ///
    /// Distinct from `version_satisfies_requirement`, which answers the looser "treat as up
    /// to date" question and is deliberately permissive (see that method's docs). This one
    /// gates a WARNING diagnostic claiming "no published version satisfies this
    /// requirement", so it must never guess: an ecosystem that has not opted in by
    /// overriding this method emits no such diagnostic at all, rather than one derived from
    /// a loose heuristic.
    ///
    /// `None` has two distinct causes, both correct to suppress the diagnostic for: the
    /// requirement string fails to parse under this ecosystem's own comparator (`deps-cargo`,
    /// `deps-npm`, `deps-pypi`, `deps-swift` — `.ok()` on a fallible parse), or the
    /// requirement parses fine but names a version-space region the fetched `available` list
    /// structurally cannot contain regardless — a Go pseudo-version, a Composer
    /// dev-branch/`@dev` flag, a RubyGems exact pin indistinguishable from one that matches
    /// only a yanked release, a malformed Maven/Gradle/NuGet range. Scanning either case would
    /// always decide `Some(false)` for every candidate, producing a false "no published
    /// version satisfies" verdict instead of correctly suppressing the check. Implementors of
    /// the second (predicate-guard) shape should use
    /// [`crate::lsp_helpers::compile_requirement_unless`], which
    /// centralizes this contract instead of re-deriving it per ecosystem. `deps-dart` is the
    /// only ecosystem with neither cause: every requirement string is a valid Dart constraint
    /// by construction, so its override is always `Some`.
    ///
    /// Default: `None` — an ecosystem that has not opted in emits no unsatisfiable-requirement
    /// diagnostics.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::lsp_helpers::{BoundedVersionReq, RequirementResolution};
    /// use deps_core::VersionReq;
    ///
    /// struct DefaultFormatter;
    /// impl RequirementResolution for DefaultFormatter {}
    ///
    /// let requirement = VersionReq::new("^1.2");
    /// let bounded = BoundedVersionReq::new(&requirement).unwrap();
    /// assert!(DefaultFormatter.compile_bounded_requirement(bounded).is_none());
    /// ```
    fn compile_bounded_requirement(
        &self,
        _requirement: BoundedVersionReq<'_>,
    ) -> Option<Box<dyn RequirementMatcher>> {
        None
    }

    /// Whether `requirement`, left unedited, already resolves forward to a version at or
    /// above `target` under this ecosystem's own resolution rules — the gate
    /// [`crate::edit::plan_vulnerability_fix`] (#1344) consults before deciding a
    /// vulnerability-fix manifest rewrite is unnecessary.
    ///
    /// Distinct from `compile_bounded_requirement(requirement).matches(target)` alone, which only
    /// answers "is `target` a member of `requirement`'s accepted set" — true both for an
    /// auto-following range (Cargo's `^1`, a Maven bracket range), where membership genuinely
    /// means "no edit needed, re-resolving already gets there", *and* for a floor a resolver
    /// instead pins to its lowest admissible member (NuGet's bare `Version="1.0.0"`, mirroring
    /// [`Self::is_bounded_requirement_up_to_date`]'s own floor carve-out), where it does not: leaving
    /// the manifest unedited keeps resolving to the floor itself, never to `target`.
    ///
    /// Default: delegates straight to `compile_bounded_requirement(requirement).matches(target)`,
    /// collapsing `None` (uncompilable requirement) and `Some(false)` to `false` — correct for
    /// every ecosystem whose resolution prefers the newest admissible member of a requirement's
    /// accepted set. Override only when some requirement shape in this ecosystem instead
    /// resolves to something other than that newest member.
    ///
    /// Takes a [`BoundedVersionReq`]: [`RequirementGate::requirement_already_resolves_to`] collapses
    /// an oversized requirement to `false` (fail-closed: an edit may still be needed) before this
    /// hook is ever called.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::lsp_helpers::{BoundedVersionReq, RequirementResolution};
    /// use deps_core::{ConcreteVersion, VersionReq};
    ///
    /// struct DefaultFormatter;
    /// impl RequirementResolution for DefaultFormatter {}
    ///
    /// // No `compile_bounded_requirement` override, so this is always `false` — matches that
    /// // method's own default.
    /// let requirement = VersionReq::new("^1.2");
    /// let bounded = BoundedVersionReq::new(&requirement).unwrap();
    /// assert!(!DefaultFormatter.bounded_requirement_already_resolves_to(
    ///     bounded,
    ///     &ConcreteVersion::new("1.5.0")
    /// ));
    /// ```
    fn bounded_requirement_already_resolves_to(
        &self,
        requirement: BoundedVersionReq<'_>,
        target: &ConcreteVersion,
    ) -> bool {
        self.compile_bounded_requirement(requirement)
            .is_some_and(|matcher| matcher.matches(target) == Some(true))
    }

    /// Whether this ecosystem's registry can silently omit a *published* version from
    /// `available` in a way indistinguishable from "never published" — and, if so, whether
    /// `requirement` names a version-space region that specific omission could explain, given
    /// the versions actually observed in `available`.
    ///
    /// Called by [`crate::lsp_helpers::requirement_is_unsatisfiable`] before compiling `requirement`; returning
    /// `true` suppresses the "no published version satisfies this requirement" diagnostic for
    /// this dependency, the same as [`Self::compile_bounded_requirement`] returning `None` — but,
    /// unlike that method, this one sees `available` and can therefore narrow the suppression
    /// instead of disabling it for every requirement of a given shape.
    ///
    /// Default `false` — no ecosystem has this problem unless it opts in. `deps-bundler`
    /// overrides it (see `BundlerFormatter::requirement_is_undecidable_given_available` and
    /// its helper for the RubyGems-specific rationale and heuristic).
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::lsp_helpers::{BoundedVersionReq, RequirementResolution};
    /// use deps_core::{ConcreteVersion, VersionReq};
    ///
    /// struct DefaultFormatter;
    /// impl RequirementResolution for DefaultFormatter {}
    ///
    /// let requirement = VersionReq::new("1.6.13");
    /// assert!(!DefaultFormatter.bounded_requirement_is_undecidable_given_available(
    ///     BoundedVersionReq::new(&requirement).unwrap(),
    ///     &[ConcreteVersion::new("1.6.9"), ConcreteVersion::new("1.6.14")],
    /// ));
    /// ```
    fn bounded_requirement_is_undecidable_given_available(
        &self,
        _requirement: BoundedVersionReq<'_>,
        _available: &[ConcreteVersion],
    ) -> bool {
        false
    }

    /// Whether `dep`'s manifest version-requirement line is itself the exact
    /// version already selected — never a range.
    ///
    /// True only for a Go `require`-directive dependency: `go.mod`'s
    /// `require` line already holds the module version selected by Go's
    /// MVS, unlike Cargo/npm where the manifest holds a range and the lock
    /// file holds the pin. When true, hover and inlay hints prefer
    /// [`Dependency::version_requirement`] over the lock-file-derived entry
    /// in [`crate::lsp_helpers::VersionData::resolved`], because `go.sum` is a checksum ledger
    /// that `go get`/`go build` only ever append to (only `go mod tidy`
    /// prunes it) — a stale, no-longer-selected higher version can remain
    /// recorded there after a downgrade and, since go.sum is written sorted
    /// ascending by semver, always sorts last and wins naive
    /// last-occurrence-wins parsing (overridden in `deps-go`; see `#235`).
    ///
    /// Takes `dep` (precedent: [`OsvNaming::osv_package_name`]) because Go's
    /// `exclude`/`replace` directives are also surfaced as dependencies
    /// whose `version_requirement()` is *not* an in-use version (the
    /// excluded version, or the replaced-from version) — the `deps-go`
    /// override inspects the directive kind and returns `true` only for
    /// `require`.
    fn manifest_requirement_is_resolved_version(&self, dep: &dyn Dependency) -> bool {
        let _ = dep;
        false
    }

    /// An ecosystem-resolved concrete version for `dep`, sourced from out-of-band
    /// resolution data this ecosystem already holds elsewhere — rather than reconstructed
    /// from the manifest requirement text alone the way
    /// [`crate::lsp_helpers::concrete_pin_version`] must.
    ///
    /// GitHub Actions is the motivating case (#1556): a SHA-pinned `uses:` step's exact
    /// version is knowable from [`crate::lsp_helpers::TagIndex::resolved_pin`] — resolved via
    /// the same live tags fetch that already backs hover's `**Resolved**` line and the "Pin
    /// to commit SHA" quickfix — even when the pin's trailing `# comment` fails
    /// `concrete_pin_version`'s text-shape check (a moving-major-tag comment, a literal
    /// tool-name comment, or no comment at all). Overriding this lets such a dependency
    /// still reach a real OSV vulnerability scan, hover, and inlay hints instead of being
    /// skipped as unresolvable.
    ///
    /// Consulted by [`crate::lsp_helpers::resolve_in_use_version`] between its lock-file
    /// step and its final `concrete_pin_version` text fallback: a lock-file-resolved
    /// version, when one exists, still wins over this hook (impl-critic M2 — an
    /// ecosystem's own out-of-band resolution must only fill a gap the lock file leaves
    /// open, never silently supersede a stronger existing resolution source), but a `Some`
    /// here wins over the blind manifest-text guess below it, since it is still strictly
    /// more trustworthy than text alone. Its own output is not trusted verbatim either: the
    /// caller re-applies a shape gate (`concrete_pin_version`, plus a two-component allowance
    /// for a [`crate::lsp_helpers::ResolvedPin::MostSpecific`] tag), since this hook can itself
    /// resolve to a moving/partial name (#1556 impl-critic S1, #1668).
    ///
    /// The result has four values ([`crate::lsp_helpers::PinResolution`]): a
    /// [`Resolved`](crate::lsp_helpers::PinResolution::Resolved) pin is authoritative (an
    /// unqueryable one yields no version, never the manifest text), an
    /// [`Untagged`](crate::lsp_helpers::PinResolution::Untagged) pin is proven to name no
    /// release (its trailing comment must not stand in), a
    /// [`CommentContradicted`](crate::lsp_helpers::PinResolution::CommentContradicted) pin has
    /// a comment that is provably wrong and must not stand in either (an implementor must not
    /// map it to `Unresolved`), and only
    /// [`Unresolved`](crate::lsp_helpers::PinResolution::Unresolved) lets the manifest text
    /// stand in.
    ///
    /// Default: [`Unresolved`](crate::lsp_helpers::PinResolution::Unresolved) — every
    /// ecosystem's manifest requirement text is authoritative until it opts in.
    fn resolved_pin_version(&self, dep: &dyn Dependency) -> crate::lsp_helpers::PinResolution {
        let _ = dep;
        crate::lsp_helpers::PinResolution::Unresolved
    }

    /// Whether [`Self::resolved_pin_version`] may only start returning a non-`Unresolved` value
    /// for a given dependency once this ecosystem's own registry fetch completes (e.g. GitHub Actions'/
    /// GitLab CI's `TagIndex`, populated as a side effect of `Registry::get_versions` — not
    /// present yet at document-open/edit time).
    ///
    /// Default: `false` — every ecosystem whose `resolved_pin_version` stays `Unresolved`
    /// unconditionally, or is already sourced from data available before any fetch, has
    /// nothing to wait for. An ecosystem overriding `resolved_pin_version` with a value
    /// sourced from its own registry fetch MUST override this to `true`, or `deps-lsp`'s OSV
    /// phase A scan — spawned concurrently with, not after, that fetch — can run on a cold
    /// first open/edit, skip a dependency as unresolvable, and never re-check it once the
    /// fetch actually lands (#1556 critic S2): `deps-lsp` uses this flag to know when it must
    /// re-run the OSV scan pipeline after that fetch completes.
    fn resolved_pin_version_depends_on_registry_fetch(&self) -> bool {
        false
    }
}

/// The un-overridable entry point for requirement resolution questions.
///
/// Rust cannot mark a trait method non-overridable, so this trait supplies the guarantee
/// structurally instead: it is implemented, via the blanket impl below, for every
/// `T: RequirementResolution + ?Sized` — including `dyn EcosystemFormatter` — so any
/// `impl RequirementGate for X` an ecosystem crate might write is a duplicate-impl
/// error (E0119), the same "sealed by blanket impl" mechanism [`EcosystemFormatter`] itself
/// already uses. Its methods are therefore the only place [`super::requirement_is_oversized`]
/// is ever checked for these questions: they construct a [`BoundedVersionReq`] and, only on
/// success, call through to the overridable `*_bounded_*`/`classify_*` hooks of
/// [`RequirementResolution`], which receive the proof newtype and so have no oversized value
/// left to mishandle. An oversized requirement never reaches an override, regardless of what
/// that override does.
///
/// The oversized result is defined once, here, and is consistent across methods:
/// [`Self::requirement_status`] is `Unresolved`, `is_requirement_up_to_date` is `true`,
/// `compile_requirement` is `None`, `requirement_already_resolves_to` is `false`,
/// `requirement_is_unresolved`, `requirement_is_placeholder` and
/// `requirement_is_undecidable_given_available` are `true` (never rewrite or diagnose
/// unmodellable text), and `version_satisfies_requirement` is `false`.
///
/// Call sites only need to bring this trait into scope (`use
/// deps_core::lsp_helpers::RequirementGate;`) to keep using method syntax — it covers
/// `&dyn EcosystemFormatter` the same way `RequirementResolution` itself does.
pub trait RequirementGate: RequirementResolution {
    /// Whether `requirement` could not be resolved to a concrete version constraint
    /// ([`RequirementResolution::bounded_requirement_is_unresolved`]). An oversized requirement
    /// is unmodellable and reported `true`.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::lsp_helpers::{MAX_REQUIREMENT_LEN, RequirementGate, RequirementResolution};
    /// use deps_core::VersionReq;
    ///
    /// struct DefaultFormatter;
    /// impl RequirementResolution for DefaultFormatter {}
    ///
    /// assert!(!DefaultFormatter.requirement_is_unresolved(&VersionReq::new("^1.2")));
    /// let oversized = VersionReq::new(&"1".repeat(MAX_REQUIREMENT_LEN + 1));
    /// assert!(DefaultFormatter.requirement_is_unresolved(&oversized));
    /// ```
    fn requirement_is_unresolved(&self, requirement: &VersionReq) -> bool;

    /// Whether `requirement` is an unexpanded placeholder that must never be overwritten
    /// ([`RequirementResolution::bounded_requirement_is_placeholder`]). An oversized requirement
    /// is reported `true`: unmodellable text is never rewritten.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::lsp_helpers::{MAX_REQUIREMENT_LEN, RequirementGate, RequirementResolution};
    /// use deps_core::VersionReq;
    ///
    /// struct DefaultFormatter;
    /// impl RequirementResolution for DefaultFormatter {}
    ///
    /// assert!(DefaultFormatter.requirement_is_placeholder(&VersionReq::new("{{ version }}")));
    /// let oversized = VersionReq::new(&"1".repeat(MAX_REQUIREMENT_LEN + 1));
    /// assert!(DefaultFormatter.requirement_is_placeholder(&oversized));
    /// ```
    fn requirement_is_placeholder(&self, requirement: &VersionReq) -> bool;

    /// Whether `requirement` names a region of version space a hidden published version could
    /// explain ([`RequirementResolution::bounded_requirement_is_undecidable_given_available`]).
    /// An oversized requirement is reported `true` (diagnostic suppressed).
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::lsp_helpers::{MAX_REQUIREMENT_LEN, RequirementGate, RequirementResolution};
    /// use deps_core::{ConcreteVersion, VersionReq};
    ///
    /// struct DefaultFormatter;
    /// impl RequirementResolution for DefaultFormatter {}
    ///
    /// let available = [ConcreteVersion::new("1.0.0")];
    /// assert!(!DefaultFormatter.requirement_is_undecidable_given_available(&VersionReq::new("1.0.0"), &available));
    /// let oversized = VersionReq::new(&"1".repeat(MAX_REQUIREMENT_LEN + 1));
    /// assert!(DefaultFormatter.requirement_is_undecidable_given_available(&oversized, &available));
    /// ```
    fn requirement_is_undecidable_given_available(
        &self,
        requirement: &VersionReq,
        available: &[ConcreteVersion],
    ) -> bool;

    /// General constraint check ([`RequirementResolution::version_satisfies_bounded_requirement`]).
    /// An oversized requirement is unmodellable and reported `false`.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::lsp_helpers::{MAX_REQUIREMENT_LEN, RequirementGate, RequirementResolution};
    /// use deps_core::{ConcreteVersion, VersionReq};
    ///
    /// struct DefaultFormatter;
    /// impl RequirementResolution for DefaultFormatter {}
    ///
    /// let version = ConcreteVersion::new("1.5.0");
    /// assert!(DefaultFormatter.version_satisfies_requirement(&version, &VersionReq::new("^1.2")));
    /// let oversized = VersionReq::new(&"1".repeat(MAX_REQUIREMENT_LEN + 1));
    /// assert!(!DefaultFormatter.version_satisfies_requirement(&version, &oversized));
    /// ```
    fn version_satisfies_requirement(
        &self,
        version: &ConcreteVersion,
        requirement: &VersionReq,
    ) -> bool;

    /// Whether `latest` is already covered by `requirement` under this ecosystem's rules
    /// ([`RequirementResolution::is_bounded_requirement_up_to_date`]). An oversized requirement
    /// is unmodellable and reported `true` (not outdated), matching `Unresolved` from
    /// [`Self::requirement_status`].
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::lsp_helpers::{MAX_REQUIREMENT_LEN, RequirementGate, RequirementResolution};
    /// use deps_core::{ConcreteVersion, VersionReq};
    ///
    /// struct DefaultFormatter;
    /// impl RequirementResolution for DefaultFormatter {}
    ///
    /// let oversized = VersionReq::new(&"1".repeat(MAX_REQUIREMENT_LEN + 1));
    /// assert!(DefaultFormatter.is_requirement_up_to_date(&oversized, &ConcreteVersion::new("1.0.0")));
    /// ```
    fn is_requirement_up_to_date(&self, requirement: &VersionReq, latest: &ConcreteVersion)
    -> bool;

    /// Compiles `requirement` into a matcher ([`RequirementResolution::compile_bounded_requirement`]).
    /// An oversized requirement is unmodellable and yields `None`.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::lsp_helpers::{MAX_REQUIREMENT_LEN, RequirementGate, RequirementResolution};
    /// use deps_core::VersionReq;
    ///
    /// struct DefaultFormatter;
    /// impl RequirementResolution for DefaultFormatter {}
    ///
    /// assert!(DefaultFormatter.compile_requirement(&VersionReq::new("^1.2")).is_none());
    /// let oversized = VersionReq::new(&"1".repeat(MAX_REQUIREMENT_LEN + 1));
    /// assert!(DefaultFormatter.compile_requirement(&oversized).is_none());
    /// ```
    fn compile_requirement(&self, requirement: &VersionReq) -> Option<Box<dyn RequirementMatcher>>;

    /// Whether `requirement`, left unedited, already resolves to a version at or above `target`
    /// ([`RequirementResolution::bounded_requirement_already_resolves_to`]). An oversized
    /// requirement collapses to `false`, the fail-closed "an edit may still be needed" result.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::lsp_helpers::{MAX_REQUIREMENT_LEN, RequirementGate, RequirementResolution};
    /// use deps_core::{ConcreteVersion, VersionReq};
    ///
    /// struct DefaultFormatter;
    /// impl RequirementResolution for DefaultFormatter {}
    ///
    /// let oversized = VersionReq::new(&"1".repeat(MAX_REQUIREMENT_LEN + 1));
    /// assert!(!DefaultFormatter.requirement_already_resolves_to(&oversized, &ConcreteVersion::new("1.5.0")));
    /// ```
    fn requirement_already_resolves_to(
        &self,
        requirement: &VersionReq,
        target: &ConcreteVersion,
    ) -> bool;

    /// Tri-state variant of [`Self::is_requirement_up_to_date`] that distinguishes "confirmed up to
    /// date" from "could not be resolved, so we don't know" — including an oversized
    /// requirement, which is unmodellable rather than verified up to date or outdated (#1472
    /// defense-in-depth).
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::lsp_helpers::{RequirementResolution, RequirementStatus, RequirementGate};
    /// use deps_core::{ConcreteVersion, VersionReq};
    ///
    /// struct DefaultFormatter;
    /// impl RequirementResolution for DefaultFormatter {}
    ///
    /// assert_eq!(
    ///     DefaultFormatter.requirement_status(&VersionReq::new("^1.2"), &ConcreteVersion::new("1.5.0")),
    ///     RequirementStatus::UpToDate
    /// );
    /// assert_eq!(
    ///     DefaultFormatter.requirement_status(&VersionReq::new("^1.2"), &ConcreteVersion::new("2.0.0")),
    ///     RequirementStatus::Outdated
    /// );
    /// ```
    fn requirement_status(
        &self,
        requirement: &VersionReq,
        latest: &ConcreteVersion,
    ) -> RequirementStatus;

    /// Dependency-aware variant of [`Self::requirement_status`] — see
    /// [`RequirementResolution::classify_requirement_status_for`] for why some ecosystems need
    /// `dep` in hand.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::lsp_helpers::{RequirementResolution, RequirementStatus, RequirementGate};
    /// use deps_core::{ConcreteVersion, Dependency, PackageName, VersionReq};
    ///
    /// struct DefaultFormatter;
    /// impl RequirementResolution for DefaultFormatter {}
    ///
    /// # struct FakeDep(PackageName);
    /// # impl Dependency for FakeDep {
    /// #     fn name(&self) -> &PackageName {
    /// #         &self.0
    /// #     }
    /// #     fn name_range(&self) -> deps_core::position::Range {
    /// #         deps_core::position::Range::default()
    /// #     }
    /// #     fn version_requirement(&self) -> Option<&VersionReq> {
    /// #         None
    /// #     }
    /// #     fn version_range(&self) -> Option<deps_core::position::Range> {
    /// #         None
    /// #     }
    /// #     fn source(&self) -> deps_core::parser::DependencySource {
    /// #         deps_core::parser::DependencySource::Registry
    /// #     }
    /// #     fn as_any(&self) -> &dyn std::any::Any {
    /// #         self
    /// #     }
    /// # }
    /// #
    /// let dep = FakeDep(PackageName::new("example"));
    /// assert_eq!(
    ///     DefaultFormatter.requirement_status_for(
    ///         &dep,
    ///         &VersionReq::new("^1.2"),
    ///         &ConcreteVersion::new("1.5.0")
    ///     ),
    ///     RequirementStatus::UpToDate
    /// );
    /// ```
    fn requirement_status_for(
        &self,
        dep: &dyn Dependency,
        requirement: &VersionReq,
        latest: &ConcreteVersion,
    ) -> RequirementStatus;
}

impl<T: RequirementResolution + ?Sized> RequirementGate for T {
    fn requirement_is_unresolved(&self, requirement: &VersionReq) -> bool {
        BoundedVersionReq::new(requirement)
            .is_none_or(|requirement| self.bounded_requirement_is_unresolved(requirement))
    }

    fn requirement_is_placeholder(&self, requirement: &VersionReq) -> bool {
        BoundedVersionReq::new(requirement)
            .is_none_or(|requirement| self.bounded_requirement_is_placeholder(requirement))
    }

    fn requirement_is_undecidable_given_available(
        &self,
        requirement: &VersionReq,
        available: &[ConcreteVersion],
    ) -> bool {
        BoundedVersionReq::new(requirement).is_none_or(|requirement| {
            self.bounded_requirement_is_undecidable_given_available(requirement, available)
        })
    }

    fn version_satisfies_requirement(
        &self,
        version: &ConcreteVersion,
        requirement: &VersionReq,
    ) -> bool {
        BoundedVersionReq::new(requirement).is_some_and(|requirement| {
            self.version_satisfies_bounded_requirement(version, requirement)
        })
    }

    fn is_requirement_up_to_date(
        &self,
        requirement: &VersionReq,
        latest: &ConcreteVersion,
    ) -> bool {
        BoundedVersionReq::new(requirement)
            .is_none_or(|requirement| self.is_bounded_requirement_up_to_date(requirement, latest))
    }

    fn compile_requirement(&self, requirement: &VersionReq) -> Option<Box<dyn RequirementMatcher>> {
        BoundedVersionReq::new(requirement)
            .and_then(|requirement| self.compile_bounded_requirement(requirement))
    }

    fn requirement_already_resolves_to(
        &self,
        requirement: &VersionReq,
        target: &ConcreteVersion,
    ) -> bool {
        BoundedVersionReq::new(requirement).is_some_and(|requirement| {
            self.bounded_requirement_already_resolves_to(requirement, target)
        })
    }

    fn requirement_status(
        &self,
        requirement: &VersionReq,
        latest: &ConcreteVersion,
    ) -> RequirementStatus {
        BoundedVersionReq::new(requirement).map_or(RequirementStatus::Unresolved, |requirement| {
            self.classify_requirement_status(requirement, latest)
        })
    }

    fn requirement_status_for(
        &self,
        dep: &dyn Dependency,
        requirement: &VersionReq,
        latest: &ConcreteVersion,
    ) -> RequirementStatus {
        BoundedVersionReq::new(requirement).map_or(RequirementStatus::Unresolved, |requirement| {
            self.classify_requirement_status_for(dep, requirement, latest)
        })
    }
}

/// Static wording for diagnostics and hover about yanked/deprecated package state.
///
/// Implementors guarantee every method here returns a `'static` string with no per-call
/// computation — this is display copy, not logic — so callers may cache or repeat these
/// values freely across an entire diagnostics pass without re-invoking the formatter.
pub trait DiagnosticMessages: Send + Sync {
    /// Message for yanked/deprecated versions in diagnostics.
    fn yanked_message(&self) -> &'static str {
        "This version has been yanked"
    }

    /// Label for yanked versions in hover.
    fn yanked_label(&self) -> &'static str {
        "*(yanked)*"
    }

    /// Message for a package-level deprecation/abandonment diagnostic (issue #205).
    ///
    /// Distinct from [`Self::yanked_message`]: that one describes a single flagged
    /// *version*, this one describes the *package* being deprecated/abandoned/archived.
    /// Default wording is generic; `ComposerFormatter` overrides both this and
    /// [`Self::deprecated_label`] to "abandoned", matching Packagist's own vocabulary —
    /// the same pattern it already applies to the yanked pair.
    fn deprecated_message(&self) -> &'static str {
        "This package is deprecated"
    }

    /// Label preceding the sibling release tag(s) an advisory matched instead of the scanned
    /// primary version, e.g. `matched tag v4.9.0` (#1718).
    fn sibling_match_label(&self) -> &'static str {
        "matched tag"
    }

    /// Label for a deprecated package in hover.
    fn deprecated_label(&self) -> &'static str {
        "*(deprecated)*"
    }
}

/// Per-ecosystem opt-outs for which diagnostics apply to which dependency/requirement shapes.
///
/// Implementors guarantee these hooks only ever narrow or disable a diagnostic a shared,
/// ecosystem-agnostic pass would otherwise emit unconditionally — never widen or fabricate one.
/// An override does not always mean "this ecosystem is broken": `NpmFormatter` returns `false`
/// from [`yanked_diagnostic_applies_to`](Self::yanked_diagnostic_applies_to) unconditionally not
/// because the underlying signal is wrong, but to avoid duplicating the separate #205
/// package-level deprecation diagnostic that would otherwise fire alongside it.
pub trait DiagnosticPolicy: Send + Sync {
    /// Whether this ecosystem's deprecation payload ([`crate::Deprecation::replacement`])
    /// is safe to offer as a "Replace with X" rename quickfix.
    ///
    /// Default `false`. Only an ecosystem whose replacement name comes from a
    /// **structured, registry-validated** field may override this to `true` — never one
    /// synthesized by parsing free text, which is a typosquatting vector (npm's
    /// `deprecated` message names a successor only in prose). `ComposerFormatter`
    /// overrides this to `true`: Packagist's `abandoned` replacement is a real package
    /// name field, not extracted text.
    fn supports_package_rename(&self) -> bool {
        false
    }

    /// Whether the "requirement satisfiable only by a yanked version" diagnostic
    /// (`crate::lsp_helpers::requirement_matches_only_yanked`) should evaluate `requirement`
    /// at all for this ecosystem.
    ///
    /// Default `true` — no restriction, every requirement shape is checked. Override to
    /// `false` for a requirement shape (or, returning `false` unconditionally, for every
    /// requirement) where this diagnostic would duplicate a more specific one, or where this
    /// ecosystem's `Version::removal_status()` is not a reliable enough per-version signal.
    /// This is independent of
    /// [`Registry::reports_yanked`](crate::Registry::reports_yanked): that flag gates whether
    /// `removal_status()` data is trusted at all (and thus whether the separate #263
    /// in-use-version yanked check runs), while this hook only narrows *this* diagnostic.
    ///
    /// `dep` is passed alongside `requirement` (rather than `requirement` alone) so an
    /// implementor can key its decision off the dependency's package name — needed by
    /// `DenoFormatter` (#448) to tell its `jsr:`- and `npm:`-scheme specifiers apart, since
    /// the scheme lives in the name, not in the requirement text. At the sole call site
    /// (`crate::lsp_helpers::diagnostics::generate_diagnostics_from_cache`), `requirement`
    /// is always `dep.version_requirement().unwrap()` for the same `dep` — the two are
    /// never independent, though an implementor is free to key off either or both.
    ///
    /// `DenoFormatter` returns `false` unconditionally for `npm:` specifiers, mirroring
    /// `NpmFormatter` (#448), and applies unconditionally (`true`, the same as leaving this
    /// hook at its default) for `jsr:` specifiers, for any requirement shape (#454): unlike
    /// npm's `deprecated`, JSR's `yanked` flag is a genuine per-version signal with no
    /// package-level deprecation diagnostic to conflate with, so `jsr:` needs no restriction
    /// here at all — see that formatter's docs. `NpmFormatter` returns `false`
    /// unconditionally (#436): npm's `AdvisoryDeprecated` is genuinely per-version but
    /// commonly applied package-wide, so even an exact pin would often just duplicate the
    /// dedicated package-level deprecation diagnostic ([`DiagnosticMessages::deprecated_message`],
    /// issue #205); npm keeps `reports_yanked() == true`; so the #263 in-use-version check
    /// stays live. `ComposerFormatter` does not override this hook at all — it opts out at
    /// the registry level instead
    /// ([`Registry::reports_yanked`](crate::Registry::reports_yanked) `== false`, pre-dating
    /// #436, independently justified by #233 R2): Packagist's `abandoned` is package-level via
    /// p2 minified inheritance, so its yanked map is never populated and this hook has nothing
    /// to restrict.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::lsp_helpers::DiagnosticPolicy;
    /// use deps_core::{Dependency, PackageName, VersionReq};
    ///
    /// struct DefaultFormatter;
    /// impl DiagnosticPolicy for DefaultFormatter {}
    ///
    /// # struct FakeDep(PackageName);
    /// # impl Dependency for FakeDep {
    /// #     fn name(&self) -> &PackageName {
    /// #         &self.0
    /// #     }
    /// #     fn name_range(&self) -> deps_core::position::Range {
    /// #         deps_core::position::Range::default()
    /// #     }
    /// #     fn version_requirement(&self) -> Option<&VersionReq> {
    /// #         None
    /// #     }
    /// #     fn version_range(&self) -> Option<deps_core::position::Range> {
    /// #         None
    /// #     }
    /// #     fn source(&self) -> deps_core::parser::DependencySource {
    /// #         deps_core::parser::DependencySource::Registry
    /// #     }
    /// #     fn as_any(&self) -> &dyn std::any::Any {
    /// #         self
    /// #     }
    /// # }
    /// #
    /// let dep = FakeDep(PackageName::new("example"));
    /// assert!(DefaultFormatter.yanked_diagnostic_applies_to(&dep, &VersionReq::new("^1.2")));
    /// ```
    fn yanked_diagnostic_applies_to(
        &self,
        _dep: &dyn Dependency,
        _requirement: &VersionReq,
    ) -> bool {
        true
    }
}

/// What a [`DependencySource`](crate::parser::DependencySource) may be used for: resolution,
/// vulnerability scanning, and cache-key/link trust.
///
/// Implementors guarantee [`can_resolve_source`](Self::can_resolve_source) and
/// [`source_is_public_registry_content`](Self::source_is_public_registry_content) answer
/// independent questions — a source can be resolvable without being public-registry content
/// (e.g. a non-mirroring alternate registry), so callers must not assume one implies the
/// other.
pub trait SourcePolicy: Send + Sync {
    /// Whether this ecosystem's registry can resolve version data for `source`.
    ///
    /// Hover, diagnostics, and code actions gate every registry lookup on this instead of
    /// [`crate::parser::DependencySource::is_version_resolvable`] directly, so an ecosystem
    /// whose `Registry` implementation routes *more* sources than the generic
    /// crates.io-shaped default (e.g. `deps-cargo`'s `CargoRegistry`, which additionally
    /// resolves a `DependencySource::AlternateRegistry` against a private sparse index) can
    /// opt those sources in without widening the `Registry` trait itself or touching any of
    /// this hook's call sites.
    ///
    /// Default: delegates to
    /// [`DependencySource::is_version_resolvable`](crate::parser::DependencySource::is_version_resolvable),
    /// so every ecosystem that does not override this method keeps its exact pre-existing
    /// resolvability answer.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::lsp_helpers::SourcePolicy;
    /// use deps_core::parser::DependencySource;
    ///
    /// struct DefaultFormatter;
    /// impl SourcePolicy for DefaultFormatter {}
    ///
    /// assert!(DefaultFormatter.can_resolve_source(&DependencySource::Registry));
    /// assert!(!DefaultFormatter.can_resolve_source(&DependencySource::AlternateRegistry {
    ///     index: "https://index.mycorp.dev".into(),
    ///     mirrors_crates_io: false,
    /// }));
    /// ```
    fn can_resolve_source(&self, source: &crate::parser::DependencySource) -> bool {
        source.is_version_resolvable()
            || (self.resolves_alternate_registry()
                && matches!(
                    source,
                    crate::parser::DependencySource::AlternateRegistry { .. }
                ))
    }

    /// Whether this ecosystem's registry resolves version data for *any*
    /// [`DependencySource::AlternateRegistry`](crate::parser::DependencySource::AlternateRegistry)
    /// source, regardless of `mirrors_crates_io` or any other field.
    ///
    /// A single opt-in flag [`can_resolve_source`](Self::can_resolve_source) derives its
    /// widened answer from, replacing what five ecosystems (`deps-cargo`, `deps-go`,
    /// `deps-npm`, `deps-nuget`, `deps-pypi`) previously each spelled out as an identical
    /// full override of `can_resolve_source` itself (issue #1203). An ecosystem whose
    /// `AlternateRegistry` resolvability depends on more than "is it an
    /// `AlternateRegistry` at all" (e.g. `deps-gitlab-ci`, which resolves it but never
    /// plain `Registry`) still overrides [`can_resolve_source`](Self::can_resolve_source)
    /// directly instead of this flag.
    ///
    /// **This flag alone only widens the gate — it does not make fetching actually work**
    /// (#1227). Overriding it to `true` without a matching source-aware `Registry`
    /// implementation regresses silently: dependencies that were previously dropped from the
    /// fetch queue entirely now reach it, but `Registry::get_versions_from`/
    /// `get_latest_matching_from`'s *default* implementation ignores `source` and forwards to
    /// the plain public-registry path — so an `AlternateRegistry` dependency would fetch
    /// under its private package name against the wrong (public/default) registry instead of
    /// its resolved alternate host, the exact #248-class name leak this whole `SourcePolicy`
    /// design exists to prevent. Before flipping this flag, the ecosystem's `Registry` impl
    /// must also: (1) override `get_versions_from`/`get_latest_matching_from` to dispatch an
    /// `AlternateRegistry` source to a client for its `index`, and (2) register that client
    /// (e.g. an `NpmRegistry::register_alternate`-shaped call) from `Ecosystem::parse_manifest`
    /// over the parse result's own resolved-registries list — see `deps-npm`'s
    /// `NpmEcosystem::parse_manifest`/`NpmRegistry::{register_alternate,get_versions_from}` for
    /// the reference shape, and `deps-deno`'s `DenoEcosystem::parse_manifest`/
    /// `DenoRegistry::{register_alternate_npm,get_versions_from}` for a facade ecosystem that
    /// delegates its alternate-capable scheme to another crate's registry.
    ///
    /// Default `false`.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::lsp_helpers::SourcePolicy;
    ///
    /// struct DefaultFormatter;
    /// impl SourcePolicy for DefaultFormatter {}
    ///
    /// assert!(!DefaultFormatter.resolves_alternate_registry());
    /// ```
    fn resolves_alternate_registry(&self) -> bool {
        false
    }

    /// Whether `source`'s content is exactly the default public registry's — safe to treat
    /// as such for OSV vulnerability scanning, cache-key signature construction, and hover
    /// heading links.
    ///
    /// Default `matches!(source, DependencySource::Registry)` — every ecosystem with only
    /// one registry concept keeps its existing behavior. `deps-cargo`'s `CargoFormatter`
    /// overrides this to also accept `AlternateRegistry { mirrors_crates_io: true, .. }`:
    /// Cargo verifies per-version checksum equality against crates.io for a
    /// `[source.crates-io] replace-with` mirror, so its content is exactly as trustworthy as
    /// crates.io's own, even though the fetch itself goes to the mirror's index, not to
    /// crates.io (plan `.local/specs/023-cargo-custom-registries/plan-1b.md` §1.3, F1/F1b/F2).
    ///
    /// Deliberately distinct from [`Self::can_resolve_source`]: an `AlternateRegistry` that
    /// is *not* a crates.io mirror is resolvable (this LSP can fetch its version data) but is
    /// not public-registry content (its data must not be treated as crates.io's own for
    /// vulnerability-advisory or link purposes) — the two questions are orthogonal, and a
    /// single hook conflating them would force every non-Cargo ecosystem to answer a
    /// mirror-specific question it has no concept of.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::lsp_helpers::SourcePolicy;
    /// use deps_core::parser::DependencySource;
    ///
    /// struct DefaultFormatter;
    /// impl SourcePolicy for DefaultFormatter {}
    ///
    /// assert!(DefaultFormatter.source_is_public_registry_content(&DependencySource::Registry));
    /// assert!(!DefaultFormatter.source_is_public_registry_content(&DependencySource::AlternateRegistry {
    ///     index: "https://index.mycorp.dev".into(),
    ///     mirrors_crates_io: true,
    /// }));
    /// ```
    fn source_is_public_registry_content(&self, source: &crate::parser::DependencySource) -> bool {
        matches!(source, crate::parser::DependencySource::Registry)
    }
}

/// Whether a dependency's OSV package name can be produced yet, as reported by
/// [`OsvNaming::osv_name_availability`].
///
/// Separates a transient gap (registry data the name depends on has not landed) from a
/// structural one (`osv_package_name` returning `None` for good), so the former is never
/// recorded as permanently unmappable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OsvNameAvailability {
    /// [`OsvNaming::osv_package_name`]'s answer is final for the data currently held.
    Ready,
    /// The name depends on registry data that has not been fetched yet; retry after it lands.
    AwaitingRegistryData {
        /// The name as written in the manifest, when it is a valid OSV name: queried as a
        /// provisional name (positive results only) until the confirmed one is available.
        /// `None` keeps the dependency skipped.
        written_fallback: Option<crate::osv::OsvPackageName>,
    },
}

/// Native <-> OSV.dev namespace bridging for package names and version strings.
///
/// Implementors guarantee every method is the identity transform unless this ecosystem's
/// native naming/versioning genuinely diverges from OSV.dev's own convention for it — callers
/// (the OSV scan-target builder and advisory matcher) rely on the defaults being safe no-ops
/// for the common case of an ecosystem with no such divergence.
pub trait OsvNaming: Send + Sync {
    /// OSV.dev's canonical spelling for `dep`'s package name, or `None` if
    /// this dependency cannot be mapped (e.g. a non-GitHub Swift package).
    ///
    /// Deliberately **not** routed through [`PackageNaming::normalize_package_name`]:
    /// that method produces this project's internal lookup key, while this
    /// one produces the name sent on the wire to OSV. They coincide for most
    /// ecosystems and diverge for NuGet (case-preserving; normalizing would
    /// lowercase it and zero out results), Composer (OSV wants lowercase,
    /// overridden in `deps-composer`), and Swift (prefixed to
    /// `github.com/{owner}/{repo}`, overridden in `deps-swift`). Takes
    /// `&dyn Dependency` rather than `&str` because the Swift override needs
    /// to downcast to inspect the dependency's source URL host — see
    /// `architecture.md` §2.
    ///
    /// The default implementation is the identity: for Cargo, npm, Go, Maven,
    /// Gradle, Dart, Bundler, and NuGet the manifest's raw name already matches
    /// OSV's canonical spelling. PyPI (PEP 503 normalization) and Composer
    /// (lowercase) override it.
    fn osv_package_name(&self, dep: &dyn Dependency) -> Option<crate::osv::OsvPackageName> {
        crate::osv::OsvPackageName::new_or_skip(dep.name().as_str())
    }

    /// Whether [`Self::osv_package_name`] can already answer for `dep`.
    ///
    /// Callers check this first: [`OsvNameAvailability::AwaitingRegistryData`] is a transient
    /// skip, not an unmappable name. Default: always [`OsvNameAvailability::Ready`]; override
    /// only when the OSV name is derived from registry data (GitHub Actions' canonical casing).
    fn osv_name_availability(&self, dep: &dyn Dependency) -> OsvNameAvailability {
        let _ = dep;
        OsvNameAvailability::Ready
    }

    /// Converts a version string as it appears in an OSV advisory record
    /// (e.g. [`crate::osv::Advisory::fixed_versions`]) into this ecosystem's
    /// own version namespace, as used in manifests and by the registry.
    ///
    /// Default: identity — correct for ecosystems whose OSV records carry
    /// the native version string verbatim. Override when OSV's namespace
    /// diverges from the native one (Go module versions carry a `v` prefix
    /// that OSV's SEMVER ranges never use).
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::ConcreteVersion;
    /// use deps_core::lsp_helpers::OsvNaming;
    /// use deps_core::osv::OsvVersion;
    ///
    /// struct DefaultFormatter;
    /// impl OsvNaming for DefaultFormatter {}
    ///
    /// assert_eq!(
    ///     DefaultFormatter.osv_version_to_native(&OsvVersion::new("1.2.3")),
    ///     ConcreteVersion::new("1.2.3")
    /// );
    /// ```
    fn osv_version_to_native(&self, version: &crate::osv::OsvVersion) -> ConcreteVersion {
        ConcreteVersion::new(version.as_str())
    }

    /// Rewrites a native-ecosystem version string into the spelling OSV.dev's
    /// SEMVER range matching expects.
    ///
    /// Deliberately the inverse of [`Self::osv_package_name`] rather than a
    /// field on [`crate::osv::ScanTarget`] itself: the caller (`deps-lsp`'s
    /// scan-target builder) has only the native version string at hand, so
    /// each ecosystem's formatter is the natural place to own the transform.
    ///
    /// The default strips a single leading `v`/`V` via
    /// [`crate::github::normalize_tag`]: OSV's SEMVER range matching never
    /// carries that prefix, while a native version can legitimately carry
    /// one — either because an ecosystem's own tagging convention always
    /// does (GitHub Actions/GitLab CI tags), or because a bare full-version
    /// requirement's optional `v`/`V` prefix (accepted by
    /// `is_full_semver_shape`) is returned verbatim as the resolved in-use
    /// version (npm, Deno — see `BareRequirementPolicy::ConcreteIfFullVersion`).
    /// A no-op when the native spelling never carries the prefix, so this is
    /// safe as a blanket default. Only Go needs a genuinely different
    /// transform — its version namespace *requires* the prefix, so
    /// `deps-go` overrides both this and [`Self::osv_version_to_native`] to
    /// add it back rather than strip it once.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::ConcreteVersion;
    /// use deps_core::lsp_helpers::OsvNaming;
    ///
    /// struct DefaultFormatter;
    /// impl OsvNaming for DefaultFormatter {}
    ///
    /// assert_eq!(
    ///     DefaultFormatter.osv_version(&ConcreteVersion::new("1.2.3")),
    ///     "1.2.3"
    /// );
    /// assert_eq!(
    ///     DefaultFormatter.osv_version(&ConcreteVersion::new("v1.2.3")),
    ///     "1.2.3"
    /// );
    /// ```
    fn osv_version(&self, version: &ConcreteVersion) -> crate::osv::OsvVersion {
        crate::osv::OsvVersion::new(crate::github::normalize_tag(version.as_str()))
    }
}

/// Umbrella marker for a complete ecosystem formatter.
///
/// This trait is intentionally empty: it exists only so `&dyn EcosystemFormatter` keeps
/// working as a single trait-object type at every existing call site
/// (`Ecosystem::formatter`, hover, diagnostics, code actions, code lenses, inlay hints,
/// in-use-version resolution, and OSV scan-target construction). Implementors never write
/// `impl EcosystemFormatter for X` directly — the blanket impl below supplies it
/// automatically for any type implementing all seven concern traits
/// ([`PackageNaming`], [`PackageRendering`], [`RequirementResolution`],
/// [`DiagnosticMessages`], [`DiagnosticPolicy`], [`SourcePolicy`], [`OsvNaming`]). To add a
/// new ecosystem formatter, implement those seven traits; to call one specific behavior
/// (e.g. in a test mock), implement only the trait that owns it.
pub trait EcosystemFormatter:
    PackageNaming
    + PackageRendering
    + RequirementResolution
    + DiagnosticMessages
    + DiagnosticPolicy
    + SourcePolicy
    + OsvNaming
{
}

impl<
    T: PackageNaming
        + PackageRendering
        + RequirementResolution
        + DiagnosticMessages
        + DiagnosticPolicy
        + SourcePolicy
        + OsvNaming,
> EcosystemFormatter for T
{
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lsp_helpers::test_support::MOCK_FORMATTER;

    /// #1472 defense-in-depth: an oversized requirement must not reach `is_requirement_up_to_date`
    /// at all — the default `requirement_status` suppresses it as `Unresolved`, same as an
    /// unresolved placeholder, rather than compiling/comparing it.
    #[test]
    fn test_requirement_status_oversized_requirement_is_unresolved() {
        let oversized = VersionReq::new("1".repeat(300));
        let latest = ConcreteVersion::new("1.0.0");
        assert_eq!(
            MOCK_FORMATTER.requirement_status(&oversized, &latest),
            RequirementStatus::Unresolved
        );
    }

    #[test]
    fn test_requirement_status_ordinary_requirement_unaffected() {
        let requirement = VersionReq::new("1.0.0");
        let latest = ConcreteVersion::new("1.0.0");
        assert_eq!(
            MOCK_FORMATTER.requirement_status(&requirement, &latest),
            RequirementStatus::UpToDate
        );
    }

    /// #1648: proves an override cannot bypass the oversized gate even if it tries to —
    /// `AlwaysOutdatedFormatter`'s `classify_requirement_status_for` unconditionally reports
    /// `Outdated`, yet [`RequirementGate::requirement_status_for`] still reports
    /// `Unresolved` for an oversized requirement, because it never reaches the override at
    /// all: the [`BoundedVersionReq::new`] construction fails first. The within-cap positive
    /// control below is load-bearing, not decorative (impl-critic M2): without it, this test
    /// would still pass for a gate that always returns `Unresolved` regardless of size, or one
    /// that silently dispatches to `classify_requirement_status` instead of `_for` — the
    /// positive control proves a bounded requirement really does reach the override and its
    /// `Outdated` verdict really does flow back out.
    #[test]
    fn test_requirement_status_for_oversized_requirement_bypasses_misbehaving_override() {
        struct AlwaysOutdatedFormatter;
        impl PackageNaming for AlwaysOutdatedFormatter {}
        impl PackageRendering for AlwaysOutdatedFormatter {
            fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
                version.to_string()
            }
            fn package_url(&self, name: &PackageName) -> String {
                name.as_str().to_string()
            }
        }
        impl RequirementResolution for AlwaysOutdatedFormatter {
            fn classify_requirement_status_for(
                &self,
                _dep: &dyn Dependency,
                _requirement: BoundedVersionReq<'_>,
                _latest: &ConcreteVersion,
            ) -> RequirementStatus {
                RequirementStatus::Outdated
            }
        }
        impl DiagnosticMessages for AlwaysOutdatedFormatter {}
        impl DiagnosticPolicy for AlwaysOutdatedFormatter {}
        impl SourcePolicy for AlwaysOutdatedFormatter {}
        impl OsvNaming for AlwaysOutdatedFormatter {}

        let oversized = VersionReq::new("1".repeat(300));
        let within_cap = VersionReq::new("^1.0");
        let latest = ConcreteVersion::new("1.0.0");
        let range = crate::position::Range::new(
            crate::position::Position::new(0, 0),
            crate::position::Position::new(0, 1),
        );
        let dep = |requirement: &VersionReq| crate::lsp_helpers::test_support::MockDep {
            name: PackageName::new("pkg"),
            version_req: requirement.clone(),
            version_range: range,
            name_range: range,
        };

        // Positive control: a bounded requirement must reach the override and surface its
        // actual `Outdated` verdict — proves the gate lets bounded requirements through
        // rather than always short-circuiting to `Unresolved`.
        assert_eq!(
            AlwaysOutdatedFormatter.requirement_status_for(&dep(&within_cap), &within_cap, &latest),
            RequirementStatus::Outdated
        );
        // The actual proof: the same override, given an oversized requirement, never gets a
        // chance to report `Outdated` — the gate reports `Unresolved` itself.
        assert_eq!(
            AlwaysOutdatedFormatter.requirement_status_for(&dep(&oversized), &oversized, &latest),
            RequirementStatus::Unresolved
        );
    }

    /// #1652: the three hooks cannot be bypassed either — `MisbehavingFormatter` answers every
    /// hook with the opposite of the gate's oversized result (a matcher, `false`, `true`), yet
    /// the gated entry points still report `None`/`true`/`false` for an oversized requirement
    /// because construction of the [`BoundedVersionReq`] fails before any hook runs. The
    /// within-cap positive controls are load-bearing: they prove a gate that always returned
    /// the oversized result, or never dispatched to the hooks, would fail here.
    #[test]
    fn test_oversized_requirement_bypasses_misbehaving_hook_overrides() {
        struct AcceptAllMatcher;
        impl RequirementMatcher for AcceptAllMatcher {
            fn matches(&self, _version: &ConcreteVersion) -> Option<bool> {
                Some(true)
            }

            fn strict_prerelease_exclusion(&self) -> bool {
                false
            }
        }

        struct MisbehavingFormatter;
        impl PackageNaming for MisbehavingFormatter {}
        impl PackageRendering for MisbehavingFormatter {
            fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
                version.to_string()
            }
            fn package_url(&self, name: &PackageName) -> String {
                name.as_str().to_string()
            }
        }
        impl RequirementResolution for MisbehavingFormatter {
            fn compile_bounded_requirement(
                &self,
                _requirement: BoundedVersionReq<'_>,
            ) -> Option<Box<dyn RequirementMatcher>> {
                Some(Box::new(AcceptAllMatcher))
            }

            fn is_bounded_requirement_up_to_date(
                &self,
                _requirement: BoundedVersionReq<'_>,
                _latest: &ConcreteVersion,
            ) -> bool {
                false
            }

            fn bounded_requirement_already_resolves_to(
                &self,
                _requirement: BoundedVersionReq<'_>,
                _target: &ConcreteVersion,
            ) -> bool {
                true
            }
        }
        impl DiagnosticMessages for MisbehavingFormatter {}
        impl DiagnosticPolicy for MisbehavingFormatter {}
        impl SourcePolicy for MisbehavingFormatter {}
        impl OsvNaming for MisbehavingFormatter {}

        let oversized = VersionReq::new("1".repeat(crate::lsp_helpers::MAX_REQUIREMENT_LEN + 1));
        let at_cap = VersionReq::new("1".repeat(crate::lsp_helpers::MAX_REQUIREMENT_LEN));
        let within_cap = VersionReq::new("^1.0");
        let latest = ConcreteVersion::new("1.0.0");

        for requirement in [&within_cap, &at_cap] {
            assert!(
                MisbehavingFormatter
                    .compile_requirement(requirement)
                    .is_some()
            );
            assert!(!MisbehavingFormatter.is_requirement_up_to_date(requirement, &latest));
            assert!(MisbehavingFormatter.requirement_already_resolves_to(requirement, &latest));
        }

        assert!(
            MisbehavingFormatter
                .compile_requirement(&oversized)
                .is_none()
        );
        assert!(MisbehavingFormatter.is_requirement_up_to_date(&oversized, &latest));
        assert!(!MisbehavingFormatter.requirement_already_resolves_to(&oversized, &latest));

        let dyn_formatter: &dyn RequirementResolution = &MisbehavingFormatter;
        assert!(dyn_formatter.compile_requirement(&within_cap).is_some());
        assert!(!dyn_formatter.is_requirement_up_to_date(&within_cap, &latest));
        assert!(dyn_formatter.requirement_already_resolves_to(&within_cap, &latest));
        assert!(dyn_formatter.compile_requirement(&oversized).is_none());
        assert!(dyn_formatter.is_requirement_up_to_date(&oversized, &latest));
        assert!(!dyn_formatter.requirement_already_resolves_to(&oversized, &latest));
    }

    /// #1665: the four raw-text predicates are gated too — `MisbehavingPredicates` answers each
    /// with the opposite of the gate's oversized result (`false`/`false`/`false`/`true`), yet the
    /// gated entry points still report `true`/`true`/`true`/`false` for an oversized requirement.
    /// The within-cap and at-cap controls prove the gate still dispatches to the hooks.
    #[test]
    fn test_oversized_requirement_bypasses_misbehaving_predicate_overrides() {
        struct MisbehavingPredicates;
        impl PackageNaming for MisbehavingPredicates {}
        impl PackageRendering for MisbehavingPredicates {
            fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
                version.to_string()
            }
            fn package_url(&self, name: &PackageName) -> String {
                name.as_str().to_string()
            }
        }
        impl RequirementResolution for MisbehavingPredicates {
            fn bounded_requirement_is_unresolved(
                &self,
                _requirement: BoundedVersionReq<'_>,
            ) -> bool {
                false
            }

            fn bounded_requirement_is_placeholder(
                &self,
                _requirement: BoundedVersionReq<'_>,
            ) -> bool {
                false
            }

            fn bounded_requirement_is_undecidable_given_available(
                &self,
                _requirement: BoundedVersionReq<'_>,
                _available: &[ConcreteVersion],
            ) -> bool {
                false
            }

            fn version_satisfies_bounded_requirement(
                &self,
                _version: &ConcreteVersion,
                _requirement: BoundedVersionReq<'_>,
            ) -> bool {
                true
            }
        }
        impl DiagnosticMessages for MisbehavingPredicates {}
        impl DiagnosticPolicy for MisbehavingPredicates {}
        impl SourcePolicy for MisbehavingPredicates {}
        impl OsvNaming for MisbehavingPredicates {}

        let oversized = VersionReq::new("1".repeat(crate::lsp_helpers::MAX_REQUIREMENT_LEN + 1));
        let at_cap = VersionReq::new("1".repeat(crate::lsp_helpers::MAX_REQUIREMENT_LEN));
        let within_cap = VersionReq::new("^1.0");
        let version = ConcreteVersion::new("1.0.0");
        let available = [ConcreteVersion::new("1.0.0")];

        for requirement in [&within_cap, &at_cap] {
            assert!(!MisbehavingPredicates.requirement_is_unresolved(requirement));
            assert!(!MisbehavingPredicates.requirement_is_placeholder(requirement));
            assert!(
                !MisbehavingPredicates
                    .requirement_is_undecidable_given_available(requirement, &available)
            );
            assert!(MisbehavingPredicates.version_satisfies_requirement(&version, requirement));
        }

        assert!(MisbehavingPredicates.requirement_is_unresolved(&oversized));
        assert!(MisbehavingPredicates.requirement_is_placeholder(&oversized));
        assert!(
            MisbehavingPredicates
                .requirement_is_undecidable_given_available(&oversized, &available)
        );
        assert!(!MisbehavingPredicates.version_satisfies_requirement(&version, &oversized));

        let dyn_formatter: &dyn RequirementResolution = &MisbehavingPredicates;
        assert!(!dyn_formatter.requirement_is_placeholder(&within_cap));
        assert!(dyn_formatter.requirement_is_placeholder(&oversized));
        assert!(dyn_formatter.version_satisfies_requirement(&version, &within_cap));
        assert!(!dyn_formatter.version_satisfies_requirement(&version, &oversized));
    }

    /// #1636: `~1.5.3`'s own patch floor must be enforced, not just major/minor equality —
    /// `1.5.0` is same major.minor but below the requirement's explicit `.3` floor.
    #[test]
    fn test_version_satisfies_requirement_tilde_enforces_patch_floor() {
        assert!(!MOCK_FORMATTER.version_satisfies_requirement(
            &ConcreteVersion::new("1.5.0"),
            &VersionReq::new("~1.5.3")
        ));
        assert!(MOCK_FORMATTER.version_satisfies_requirement(
            &ConcreteVersion::new("1.5.3"),
            &VersionReq::new("~1.5.3")
        ));
        assert!(MOCK_FORMATTER.version_satisfies_requirement(
            &ConcreteVersion::new("1.5.9"),
            &VersionReq::new("~1.5.3")
        ));
    }

    /// A tilde requirement without its own patch component (`~1.5`) keeps the pre-#1636
    /// major/minor-only floor — every patch is admitted.
    #[test]
    fn test_version_satisfies_requirement_tilde_without_patch_admits_any_patch() {
        assert!(MOCK_FORMATTER.version_satisfies_requirement(
            &ConcreteVersion::new("1.5.0"),
            &VersionReq::new("~1.5")
        ));
        assert!(MOCK_FORMATTER.version_satisfies_requirement(
            &ConcreteVersion::new("1.5.9"),
            &VersionReq::new("~1.5")
        ));
        assert!(!MOCK_FORMATTER.version_satisfies_requirement(
            &ConcreteVersion::new("1.6.0"),
            &VersionReq::new("~1.5")
        ));
    }

    /// impl-critic round 1, S1: a suffixed patch component on either side must not bypass the
    /// floor check via the non-numeric fallback — the suffix is stripped before parsing, not
    /// treated as unparseable.
    #[test]
    fn test_version_satisfies_requirement_tilde_suffixed_patch_still_enforces_floor() {
        assert!(!MOCK_FORMATTER.version_satisfies_requirement(
            &ConcreteVersion::new("1.5.0-beta.1"),
            &VersionReq::new("~1.5.3")
        ));
        assert!(!MOCK_FORMATTER.version_satisfies_requirement(
            &ConcreteVersion::new("1.5.0"),
            &VersionReq::new("~1.5.3-beta.1")
        ));
        assert!(!MOCK_FORMATTER.version_satisfies_requirement(
            &ConcreteVersion::new("1.5.0"),
            &VersionReq::new("~1.5.3+build")
        ));
    }

    /// impl-critic round 1, S1: a prerelease candidate at the requirement's exact numeric patch
    /// still sorts below it in semver precedence (`1.5.3-beta < 1.5.3`), so it must be rejected
    /// even though the numeric component matches.
    #[test]
    fn test_version_satisfies_requirement_tilde_prerelease_at_exact_patch_is_rejected() {
        assert!(!MOCK_FORMATTER.version_satisfies_requirement(
            &ConcreteVersion::new("1.5.3-beta"),
            &VersionReq::new("~1.5.3")
        ));
    }

    /// impl-critic round 2, S2: the S1 rejection above must not fire when the requirement
    /// itself is a prerelease at that exact patch — `~1.5.3-beta.1` admitting its own exact
    /// version, and admitting another prerelease at the same patch, are both correct; only a
    /// non-prerelease requirement (the test above) should reject an equal-patch prerelease
    /// candidate.
    #[test]
    fn test_version_satisfies_requirement_tilde_prerelease_requirement_admits_same_patch_prerelease()
     {
        assert!(MOCK_FORMATTER.version_satisfies_requirement(
            &ConcreteVersion::new("1.5.3-beta.1"),
            &VersionReq::new("~1.5.3-beta.1")
        ));
        assert!(MOCK_FORMATTER.version_satisfies_requirement(
            &ConcreteVersion::new("1.5.3-rc.1"),
            &VersionReq::new("~1.5.3-beta.1")
        ));
    }

    /// Same S1 fix, exercised through `requirement_status` (the real production entry point
    /// Cargo/npm/Deno's outdated diagnostic goes through), for consistency with the other
    /// `requirement_status`-level tests in this block.
    #[test]
    fn test_requirement_status_tilde_suffixed_candidate_is_outdated() {
        let requirement = VersionReq::new("~1.5.3");
        assert_eq!(
            MOCK_FORMATTER.requirement_status(&requirement, &ConcreteVersion::new("1.5.0-beta.1")),
            RequirementStatus::Outdated
        );
    }

    /// Unlike a prerelease suffix, build metadata (`+build`) doesn't affect semver precedence —
    /// an equal numeric patch with only a `+` suffix must still be admitted, not rejected the
    /// way `1.5.3-beta` is.
    #[test]
    fn test_version_satisfies_requirement_tilde_build_metadata_at_exact_patch_is_admitted() {
        assert!(MOCK_FORMATTER.version_satisfies_requirement(
            &ConcreteVersion::new("1.5.3+build"),
            &VersionReq::new("~1.5.3")
        ));
    }

    /// A wildcard (`x`/`X`/`*`) patch component in the requirement itself is documented as
    /// falling back to the permissive major/minor-only check, not as a rejection — this is the
    /// one case `tilde_admits_version`'s non-numeric fallback is still meant to cover after S1.
    #[test]
    fn test_version_satisfies_requirement_tilde_wildcard_patch_is_permissive() {
        for requirement in ["~1.5.x", "~1.5.X", "~1.5.*"] {
            assert!(MOCK_FORMATTER.version_satisfies_requirement(
                &ConcreteVersion::new("1.5.0"),
                &VersionReq::new(requirement)
            ));
            assert!(MOCK_FORMATTER.version_satisfies_requirement(
                &ConcreteVersion::new("1.5.9"),
                &VersionReq::new(requirement)
            ));
        }
    }

    /// impl-critic round 1, M1: a candidate missing its patch component entirely is treated as
    /// patch `0`, not as automatically satisfying a `~X.Y.Z` requirement's own patch floor.
    #[test]
    fn test_version_satisfies_requirement_tilde_missing_candidate_patch_treated_as_zero() {
        assert!(!MOCK_FORMATTER.version_satisfies_requirement(
            &ConcreteVersion::new("1.5"),
            &VersionReq::new("~1.5.3")
        ));
    }

    /// A tilde requirement is enforced through the real production entry point too:
    /// `requirement_status` (via the default `is_requirement_up_to_date`), the sole caller
    /// `Cargo`/`npm`/`Deno`'s outdated diagnostic goes through since none of them override
    /// `version_satisfies_requirement` or `is_requirement_up_to_date`.
    #[test]
    fn test_requirement_status_tilde_below_patch_floor_is_outdated() {
        let requirement = VersionReq::new("~1.5.3");
        assert_eq!(
            MOCK_FORMATTER.requirement_status(&requirement, &ConcreteVersion::new("1.5.0")),
            RequirementStatus::Outdated
        );
        assert_eq!(
            MOCK_FORMATTER.requirement_status(&requirement, &ConcreteVersion::new("1.5.3")),
            RequirementStatus::UpToDate
        );
    }

    /// #1636: a bare partial requirement (`1.2`) must not admit a version merely because it
    /// shares a numeric string prefix — `1.20.0` is a different minor (`20`), not `2.x`.
    #[test]
    fn test_version_satisfies_requirement_partial_version_rejects_string_prefix_match() {
        assert!(!MOCK_FORMATTER.version_satisfies_requirement(
            &ConcreteVersion::new("1.20.0"),
            &VersionReq::new("1.2")
        ));
        assert!(MOCK_FORMATTER.version_satisfies_requirement(
            &ConcreteVersion::new("1.2.5"),
            &VersionReq::new("1.2")
        ));
    }

    /// Same #1636 fix, exercised through the real production entry point.
    #[test]
    fn test_requirement_status_partial_version_string_prefix_is_outdated() {
        let requirement = VersionReq::new("1.2");
        assert_eq!(
            MOCK_FORMATTER.requirement_status(&requirement, &ConcreteVersion::new("1.20.0")),
            RequirementStatus::Outdated
        );
        assert_eq!(
            MOCK_FORMATTER.requirement_status(&requirement, &ConcreteVersion::new("1.2.5")),
            RequirementStatus::UpToDate
        );
    }

    /// #1622 impl-critic S1: incrementing an already-`u64::MAX` component must not panic
    /// (debug) or silently wrap to `0` (release) — mirrors #1619's `checked_add` fix for
    /// `deps-composer`'s `increment_last_segment`. An overflowing upper bound is `None`
    /// ("unbounded"), not a wrapped, wrong value.
    #[test]
    fn test_caret_upper_bound_overflow_returns_none_instead_of_panicking() {
        let max = u64::MAX.to_string();
        assert_eq!(caret_upper_bound([u64::MAX, 0, 0], &[max.as_str()]), None);
        assert_eq!(
            caret_upper_bound([0, u64::MAX, 0], &["0", max.as_str()]),
            None
        );
        assert_eq!(
            caret_upper_bound([0, 0, u64::MAX], &["0", "0", max.as_str()]),
            None
        );
    }

    /// A caret requirement whose upper bound overflows is treated as unbounded above — the
    /// lower bound is still enforced, and the candidate must not panic against a `u64::MAX`
    /// component either.
    #[test]
    fn test_version_satisfies_requirement_caret_overflow_treated_as_unbounded_above() {
        let max = u64::MAX.to_string();
        let requirement = format!("^{max}");
        assert!(MOCK_FORMATTER.version_satisfies_requirement(
            &ConcreteVersion::new(format!("{max}.0.0")),
            &VersionReq::new(&requirement)
        ));
        assert!(!MOCK_FORMATTER.version_satisfies_requirement(
            &ConcreteVersion::new("0.0.0"),
            &VersionReq::new(&requirement)
        ));
    }

    /// #1622 impl-critic S2: `is_requirement_up_to_date`'s default must not proxy through
    /// `version_satisfies_requirement`'s lower-bound-enforcing `^` check. `latest` is the
    /// newest *available* version (yanked/prerelease/cooldown-held releases already excluded
    /// upstream), so it can legitimately sit below a caret's own minor/patch floor without the
    /// dependency being outdated in any actionable sense — reporting `Outdated` here would have
    /// a caller (e.g. `deps-cli update`) plan an actual downgrade (`^1.5` -> `^1.4.9`).
    #[test]
    fn test_requirement_status_caret_latest_below_lower_bound_floor_stays_up_to_date() {
        let requirement = VersionReq::new("^1.5");
        let latest = ConcreteVersion::new("1.4.9");
        assert_eq!(
            MOCK_FORMATTER.requirement_status(&requirement, &latest),
            RequirementStatus::UpToDate
        );
    }

    /// The major-version check is unaffected by the S2 carve-out above: `latest` still below a
    /// caret's *major* component stays `Outdated`, same as before #1622.
    #[test]
    fn test_requirement_status_caret_latest_below_major_is_outdated() {
        let requirement = VersionReq::new("^2.0");
        let latest = ConcreteVersion::new("1.9.0");
        assert_eq!(
            MOCK_FORMATTER.requirement_status(&requirement, &latest),
            RequirementStatus::Outdated
        );
    }

    /// #1622 impl-critic S3: a prerelease/build-metadata suffix on the *candidate* version must
    /// not defeat the lower-bound floor by tripping `parse_caret_components`'s non-numeric
    /// fallback — `strip_version_suffix` truncates it first. Reachable in production via
    /// `in_use_version.rs`'s lock-file-resolved candidate filtering for Cargo/npm/Deno.
    #[test]
    fn test_version_satisfies_requirement_caret_candidate_suffix_still_enforces_lower_bound() {
        assert!(!MOCK_FORMATTER.version_satisfies_requirement(
            &ConcreteVersion::new("1.4.9-beta"),
            &VersionReq::new("^1.5")
        ));
        assert!(!MOCK_FORMATTER.version_satisfies_requirement(
            &ConcreteVersion::new("1.4.9+build"),
            &VersionReq::new("^1.5")
        ));
        // The stripped core `1.5.0` meets the floor — accepted as the approximation this
        // heuristic already makes elsewhere (no full semver prerelease-ordering).
        assert!(MOCK_FORMATTER.version_satisfies_requirement(
            &ConcreteVersion::new("1.5.0-beta"),
            &VersionReq::new("^1.5")
        ));
    }

    /// Same S3 fix, exercised through `caret_admits_up_to_date`/`requirement_status` with a
    /// suffixed `latest`. Unlike `version_satisfies_requirement` above, this path only checks
    /// the caret's *upper* bound (S2), so a suffix below the lower-bound floor alone doesn't
    /// flip the answer (that's the zero-major case below: `0.5.5-beta` sits at neither
    /// boundary, `0.6.0-beta` sits exactly at the upper bound) — a non-zero-major requirement
    /// like `^1.5` can't demonstrate this, since its ceiling is far enough away that the
    /// pre-#1622 non-numeric fallback (`Some(true)`) already happened to agree.
    #[test]
    fn test_requirement_status_caret_suffixed_latest_at_upper_bound_is_outdated() {
        let requirement = VersionReq::new("^0.5");
        assert_eq!(
            MOCK_FORMATTER.requirement_status(&requirement, &ConcreteVersion::new("0.5.5-beta")),
            RequirementStatus::UpToDate
        );
        assert_eq!(
            MOCK_FORMATTER.requirement_status(&requirement, &ConcreteVersion::new("0.6.0-beta")),
            RequirementStatus::Outdated
        );
    }

    /// #1641: npm's `x`/`X`/`*` wildcard-range syntax (`1.x`, `1.2.x`, `1.2.*`) must match a
    /// candidate whose non-wildcard components agree, regardless of the requirement's component
    /// count — the pre-fix code only ever matched a 3-component requirement via exact string
    /// equality, so `1.2.x`/`1.2.*` always rejected every candidate.
    #[test]
    fn test_version_satisfies_requirement_wildcard_matches() {
        assert!(MOCK_FORMATTER.version_satisfies_requirement(
            &ConcreteVersion::new("1.3.0"),
            &VersionReq::new("1.x")
        ));
        assert!(MOCK_FORMATTER.version_satisfies_requirement(
            &ConcreteVersion::new("1.2.0"),
            &VersionReq::new("1.2.x")
        ));
        assert!(MOCK_FORMATTER.version_satisfies_requirement(
            &ConcreteVersion::new("1.2.5"),
            &VersionReq::new("1.2.*")
        ));
    }

    /// #1641: a wildcard requirement component must still reject a candidate that disagrees on a
    /// non-wildcard component — the fix must not turn wildcard matching into blanket admission.
    #[test]
    fn test_version_satisfies_requirement_wildcard_rejects_mismatched_component() {
        assert!(!MOCK_FORMATTER.version_satisfies_requirement(
            &ConcreteVersion::new("2.0.0"),
            &VersionReq::new("1.x")
        ));
        assert!(!MOCK_FORMATTER.version_satisfies_requirement(
            &ConcreteVersion::new("1.3.0"),
            &VersionReq::new("1.2.x")
        ));
    }

    /// #1637: `^1.5.x` and `^1.5.*` must bound like `^1.5` (`[1.5.0, 2.0.0)`), not fail open and
    /// admit every candidate past the major-version check — the pre-fix code returned `true`
    /// unconditionally once `parse_caret_components` failed to parse the wildcard component.
    #[test]
    fn test_version_satisfies_requirement_caret_wildcard_bounds_correctly() {
        for requirement in ["^1.5.x", "^1.5.*"] {
            assert!(
                !MOCK_FORMATTER.version_satisfies_requirement(
                    &ConcreteVersion::new("1.4.9"),
                    &VersionReq::new(requirement)
                ),
                "{requirement} must reject a candidate below the effective lower bound"
            );
            assert!(
                MOCK_FORMATTER.version_satisfies_requirement(
                    &ConcreteVersion::new("1.5.0"),
                    &VersionReq::new(requirement)
                ),
                "{requirement} must accept a candidate at the lower bound"
            );
            assert!(
                MOCK_FORMATTER.version_satisfies_requirement(
                    &ConcreteVersion::new("1.9.9"),
                    &VersionReq::new(requirement)
                ),
                "{requirement} must accept a candidate within range"
            );
            assert!(
                !MOCK_FORMATTER.version_satisfies_requirement(
                    &ConcreteVersion::new("2.0.0"),
                    &VersionReq::new(requirement)
                ),
                "{requirement} must reject a candidate at/above the upper bound"
            );
            assert!(
                !MOCK_FORMATTER.version_satisfies_requirement(
                    &ConcreteVersion::new("0.9.0"),
                    &VersionReq::new(requirement)
                ),
                "{requirement} must reject a candidate with a lower major version"
            );
        }
    }

    /// #1637: a prerelease/build-suffixed requirement floor (`^1.5.0-beta.1`) is collapsed to
    /// its numeric core `1.5.0` and bounded the same as `^1.5.0`, rather than fail-opening on the
    /// non-numeric `0-beta` component — a deliberate simplification that drops semver prerelease
    /// precedence (see `strip_version_suffix`'s doc).
    #[test]
    fn test_version_satisfies_requirement_caret_requirement_suffix_still_bounds() {
        let requirement = "^1.5.0-beta.1";
        assert!(!MOCK_FORMATTER.version_satisfies_requirement(
            &ConcreteVersion::new("1.4.9"),
            &VersionReq::new(requirement)
        ));
        assert!(MOCK_FORMATTER.version_satisfies_requirement(
            &ConcreteVersion::new("1.5.0"),
            &VersionReq::new(requirement)
        ));
        assert!(!MOCK_FORMATTER.version_satisfies_requirement(
            &ConcreteVersion::new("2.0.0"),
            &VersionReq::new(requirement)
        ));
    }

    /// #1637 impl-critic S1: a wildcard *major* component (`^x`, `^*`, `^x.5.0`) means "any
    /// version" per npm — `truncate_at_wildcard` returning an empty slice for these must not be
    /// treated as "zero given components" (which would wrongly bound the match to major version
    /// `0` only, contradicting the "any value" meaning of a leading wildcard).
    #[test]
    fn test_version_satisfies_requirement_caret_wildcard_major_matches_any_version() {
        for requirement in ["^x", "^*", "^x.5.0"] {
            assert!(
                MOCK_FORMATTER.version_satisfies_requirement(
                    &ConcreteVersion::new("2.3.4"),
                    &VersionReq::new(requirement)
                ),
                "{requirement} must admit a high-major candidate"
            );
            assert!(
                MOCK_FORMATTER.version_satisfies_requirement(
                    &ConcreteVersion::new("0.5.0"),
                    &VersionReq::new(requirement)
                ),
                "{requirement} must admit a zero-major candidate too"
            );
        }
    }

    /// Same S1 fix, exercised through `caret_admits_up_to_date`/`requirement_status` — the sole
    /// production caller of `caret_admits_up_to_date` (#1637).
    #[test]
    fn test_requirement_status_caret_wildcard_major_matches_any_version() {
        let requirement = VersionReq::new("^*");
        assert_eq!(
            MOCK_FORMATTER.requirement_status(&requirement, &ConcreteVersion::new("3.0.0")),
            RequirementStatus::UpToDate
        );
    }

    /// #1637 impl-critic M2: `caret_admits_up_to_date`'s wildcard fix, exercised via its only
    /// production entry point (`is_requirement_up_to_date`), not just `version_satisfies_requirement`
    /// directly. A `latest` past the effective upper bound must now report outdated instead of
    /// fail-open admitting it; a `latest` below the caret's own lower-bound floor must stay up to
    /// date, confirming the #1622 S2 floor-ignoring contract is unaffected by this fix (no
    /// `candidate >= lower` check was added to `caret_admits_up_to_date`).
    #[test]
    fn test_is_requirement_up_to_date_caret_wildcard_no_fail_open() {
        let requirement = VersionReq::new("^1.5.x");
        assert!(
            !MOCK_FORMATTER.is_requirement_up_to_date(&requirement, &ConcreteVersion::new("2.0.0")),
            "latest past the effective upper bound must be reported outdated, not fail-open admitted"
        );
        assert!(
            MOCK_FORMATTER.is_requirement_up_to_date(&requirement, &ConcreteVersion::new("1.4.9")),
            "latest below the caret's own lower-bound floor stays up to date (#1622 S2)"
        );
    }

    #[test]
    fn test_build_metadata_policy_defaults_to_ignored() {
        assert_eq!(
            MOCK_FORMATTER.build_metadata_policy(),
            BuildMetadataPolicy::Ignored
        );
    }

    #[test]
    fn test_pin_build_metadata_significant_policy_distinguishes_revisions() {
        struct BuildAware;
        impl RequirementResolution for BuildAware {
            fn build_metadata_policy(&self) -> BuildMetadataPolicy {
                BuildMetadataPolicy::Significant
            }
        }
        for (pin, latest, expected) in [
            ("1.2.3+1", "1.2.3+23", false),
            ("1.2.3+23", "1.2.3+23", true),
            ("=1.2.3+1", "1.2.3+23", false),
        ] {
            assert_eq!(
                BuildAware.is_requirement_up_to_date(
                    &VersionReq::new(pin),
                    &ConcreteVersion::new(latest)
                ),
                expected,
                "pin {pin} vs latest {latest}"
            );
        }
    }

    #[test]
    fn test_is_requirement_up_to_date_pin_ignores_build_metadata() {
        for (pin, latest, expected) in [
            ("1.2.3", "1.2.3+build.7", true),
            ("1.2.3+build.1", "1.2.3", true),
            ("1.2.3+build.1", "1.2.3+build.7", true),
            ("1.2.3", "1.2.4+build.7", false),
            ("1.2.3-beta.1", "1.2.3+build.7", false),
            ("=1.2.3", "1.2.3", true),
            ("=1.2.3", "1.2.3+build.7", true),
            ("=300.3.1+3.3.1", "300.3.1+3.3.2", true),
            ("=1.2.3", "1.2.4", false),
        ] {
            assert_eq!(
                MOCK_FORMATTER.is_requirement_up_to_date(
                    &VersionReq::new(pin),
                    &ConcreteVersion::new(latest)
                ),
                expected,
                "pin {pin} vs latest {latest}"
            );
        }
    }

    /// Same M2 fix, exercised through the `requirement_status` wrapper end to end, mirroring
    /// `test_requirement_status_caret_latest_below_major_is_outdated`'s existing pattern.
    #[test]
    fn test_requirement_status_caret_wildcard_latest_past_upper_bound_is_outdated() {
        let requirement = VersionReq::new("^1.5.x");
        let latest = ConcreteVersion::new("3.0.0");
        assert_eq!(
            MOCK_FORMATTER.requirement_status(&requirement, &latest),
            RequirementStatus::Outdated
        );
    }

    /// #1637 impl-critic M1: a wildcard component makes every component after it a wildcard too
    /// (node-semver's `replaceXRange` semantics: `xp = xm || isX(p)`) — `1.x.5` behaves
    /// identically to `1.x`, not "match any minor but require patch `5`".
    #[test]
    fn test_version_satisfies_requirement_wildcard_mid_position_truncates_trailing_components() {
        assert!(
            MOCK_FORMATTER.version_satisfies_requirement(
                &ConcreteVersion::new("1.3.4"),
                &VersionReq::new("1.x.5")
            ),
            "the trailing `.5` after a wildcard must not be enforced"
        );
        assert!(MOCK_FORMATTER.version_satisfies_requirement(
            &ConcreteVersion::new("1.3.5"),
            &VersionReq::new("1.x.5")
        ));
    }

    /// #1637/#1641 impl-critic M3: the uppercase `X` wildcard token, in both the plain/partial
    /// branch and the caret branch — `is_wildcard_component`'s `"X"` arm was previously
    /// unexercised.
    #[test]
    fn test_version_satisfies_requirement_wildcard_uppercase_x() {
        assert!(MOCK_FORMATTER.version_satisfies_requirement(
            &ConcreteVersion::new("1.2.0"),
            &VersionReq::new("1.2.X")
        ));
        assert!(MOCK_FORMATTER.version_satisfies_requirement(
            &ConcreteVersion::new("1.6.0"),
            &VersionReq::new("^1.5.X")
        ));
    }

    /// #1637 impl-critic M3: a zero-major caret requirement routes through the same truncated
    /// `effective_req_parts` path — `caret_upper_bound`'s existing zero-major bump logic (#1622)
    /// must still produce the correct boundary once the wildcard component is dropped (`^0.x` ->
    /// `<1.0.0`, `^0.0.x` -> `<0.1.0`, matching npm).
    #[test]
    fn test_version_satisfies_requirement_caret_zero_major_wildcard_bounds() {
        assert!(MOCK_FORMATTER.version_satisfies_requirement(
            &ConcreteVersion::new("0.5.0"),
            &VersionReq::new("^0.x")
        ));
        assert!(!MOCK_FORMATTER.version_satisfies_requirement(
            &ConcreteVersion::new("1.0.0"),
            &VersionReq::new("^0.x")
        ));

        assert!(MOCK_FORMATTER.version_satisfies_requirement(
            &ConcreteVersion::new("0.0.5"),
            &VersionReq::new("^0.0.x")
        ));
        assert!(!MOCK_FORMATTER.version_satisfies_requirement(
            &ConcreteVersion::new("0.1.0"),
            &VersionReq::new("^0.0.x")
        ));
    }

    /// #1641 impl-critic M4: a bare `*`/`x`/`X` requirement (no dot at all) now matches every
    /// candidate — a real, npm-correct behavior change from before this fix (previously always
    /// `false`, since a single-token wildcard requirement fell through every pre-existing
    /// plain/partial arm without matching).
    #[test]
    fn test_version_satisfies_requirement_bare_wildcard_matches_any_version() {
        for requirement in ["*", "x", "X"] {
            assert!(
                MOCK_FORMATTER.version_satisfies_requirement(
                    &ConcreteVersion::new("9.9.9"),
                    &VersionReq::new(requirement)
                ),
                "{requirement} must match any candidate"
            );
        }
    }

    #[test]
    fn test_classify_requirement_rewrite_shape_bare() {
        assert_eq!(
            classify_requirement_rewrite_shape("1.2.3"),
            RequirementRewriteShape::Bare
        );
    }

    /// Split from [`RequirementRewriteShape::Bare`] (impl-critic S3): an explicit `^` means
    /// something genuinely different from "no operator" on a `BareMeaning::ExactPin`
    /// ecosystem, so the two must classify separately even though they used to share a bucket.
    #[test]
    fn test_classify_requirement_rewrite_shape_explicit_caret() {
        assert_eq!(
            classify_requirement_rewrite_shape("^1.2.3"),
            RequirementRewriteShape::ExplicitCaret
        );
    }

    /// impl-critic M4: a space after `^` (valid in both Cargo's and node-semver's grammar)
    /// must not be mistaken for a second comparator.
    #[test]
    fn test_classify_requirement_rewrite_shape_explicit_caret_with_space() {
        assert_eq!(
            classify_requirement_rewrite_shape("^ 1.2.3"),
            RequirementRewriteShape::ExplicitCaret
        );
    }

    #[test]
    fn test_classify_requirement_rewrite_shape_exact_pin() {
        assert_eq!(
            classify_requirement_rewrite_shape("=1.2.3"),
            RequirementRewriteShape::ExactPin
        );
    }

    #[test]
    fn test_classify_requirement_rewrite_shape_tilde_both_spellings() {
        assert_eq!(
            classify_requirement_rewrite_shape("~1.2.3"),
            RequirementRewriteShape::Tilde
        );
        assert_eq!(
            classify_requirement_rewrite_shape("~>1.2.3"),
            RequirementRewriteShape::Tilde
        );
    }

    /// impl-critic S2: a bare existence wildcard (`*`, empty, Dart's `any`) matches every
    /// version, so collapsing it to one concrete version always narrows — split from
    /// [`RequirementRewriteShape::PartialWildcard`], which has no such guarantee.
    #[test]
    fn test_classify_requirement_rewrite_shape_any_version() {
        for requirement in ["*", "", "any", "ANY"] {
            assert_eq!(
                classify_requirement_rewrite_shape(requirement),
                RequirementRewriteShape::AnyVersion,
                "expected {requirement:?} to classify as AnyVersion"
            );
        }
    }

    /// #1577: a partial wildcard requirement (`1.2.*`, `1.x`) has no single-version rewrite
    /// that preserves "any patch/minor" semantics.
    #[test]
    fn test_classify_requirement_rewrite_shape_partial_wildcard() {
        assert_eq!(
            classify_requirement_rewrite_shape("1.2.*"),
            RequirementRewriteShape::PartialWildcard
        );
        assert_eq!(
            classify_requirement_rewrite_shape("1.x"),
            RequirementRewriteShape::PartialWildcard
        );
    }

    /// impl-critic M6: a prerelease identifier that happens to be a single letter `x` must not
    /// be mistaken for a wildcard segment — only the version core (before `-`/`+`) is checked.
    #[test]
    fn test_classify_requirement_rewrite_shape_prerelease_x_not_wildcard() {
        assert_eq!(
            classify_requirement_rewrite_shape("1.0.0-alpha.x"),
            RequirementRewriteShape::Bare
        );
    }

    /// #1602 impl-critic S2 (CONFIRMED): unlike `x`/`X`, a literal `*` is never a legitimate
    /// prerelease identifier — NuGet's prerelease-label float `1.2.0-rc.*` must classify as
    /// `PartialWildcard`, not fall through to `Bare` (which would silently widen it into an
    /// unbounded floor/caret range on rewrite, the same bug class the fix otherwise refuses).
    #[test]
    fn test_classify_requirement_rewrite_shape_wildcard_in_prerelease_part() {
        assert_eq!(
            classify_requirement_rewrite_shape("1.2.0-rc.*"),
            RequirementRewriteShape::PartialWildcard
        );
    }

    /// Same root cause as the prerelease case above, for build metadata instead: a `+build.x`
    /// segment must not be mistaken for a wildcard component either — `split(['-', '+'])`
    /// isolates the version core before either separator.
    #[test]
    fn test_classify_requirement_rewrite_shape_build_metadata_x_not_wildcard() {
        assert_eq!(
            classify_requirement_rewrite_shape("1.2.3+build.x"),
            RequirementRewriteShape::Bare
        );
    }

    /// Same "always safe to collapse" treatment as bare `*` (impl-critic S2) — an empty
    /// requirement string also matches [`crate::is_existence_wildcard_str`] and must not be
    /// refused as an ordinary partial wildcard.
    #[test]
    fn test_format_version_replacing_by_shape_empty_requirement_always_collapses() {
        let new_version = ConcreteVersion::new("2.0.0");
        for bare_meaning in [
            BareMeaning::Caret,
            BareMeaning::ExactPin,
            BareMeaning::Floor,
        ] {
            assert_eq!(
                format_version_replacing_by_shape(&new_version, "", bare_meaning, || {
                    new_version.to_string()
                }),
                "2.0.0"
            );
        }
    }

    /// #1577: a single asymmetric bound in either direction has no safe single-version
    /// rewrite — collapsing to bare would silently turn it into an auto-following range.
    #[test]
    fn test_classify_requirement_rewrite_shape_single_bound_both_directions() {
        for requirement in ["<1.5", "<=1.5.0", ">1.0", ">=1.2"] {
            assert_eq!(
                classify_requirement_rewrite_shape(requirement),
                RequirementRewriteShape::SingleBound,
                "expected {requirement:?} to classify as SingleBound"
            );
        }
    }

    #[test]
    fn test_classify_requirement_rewrite_shape_compound_comma_and_whitespace() {
        assert_eq!(
            classify_requirement_rewrite_shape(">=1.2, <1.5"),
            RequirementRewriteShape::Compound
        );
        assert_eq!(
            classify_requirement_rewrite_shape(">=1.2.0 <2.0.0"),
            RequirementRewriteShape::Compound
        );
    }

    /// impl-critic M5: an unspaced npm OR-set must classify as compound identically to a
    /// spaced one.
    #[test]
    fn test_classify_requirement_rewrite_shape_or_set_spaced_and_unspaced() {
        assert_eq!(
            classify_requirement_rewrite_shape("^1||^2"),
            RequirementRewriteShape::Compound
        );
        assert_eq!(
            classify_requirement_rewrite_shape("^1 || ^2"),
            RequirementRewriteShape::Compound
        );
    }

    #[test]
    fn test_requirement_is_compound_ignores_operator_adjacent_whitespace() {
        assert!(!requirement_is_compound("> 1.0"));
        assert!(!requirement_is_compound("<= 1.5.0"));
        assert!(requirement_is_compound(">=1.2.0 <2.0.0"));
        assert!(requirement_is_compound(">=1.2, <1.5"));
    }

    #[test]
    fn test_requirement_is_compound_ignores_spacing_after_non_angle_operators() {
        assert!(!requirement_is_compound("= 1.6.13"));
        assert!(!requirement_is_compound("~ 1.2.3"));
        assert!(!requirement_is_compound("~> 1.2.3"));
        assert!(!requirement_is_compound("^ 1.2.3"));
        assert!(!requirement_is_compound("!= 1.0.0"));
    }

    #[test]
    fn test_format_version_replacing_by_shape_preserves_exact_pin_and_tilde() {
        let new_version = ConcreteVersion::new("2.0.0");
        assert_eq!(
            format_version_replacing_by_shape(&new_version, "=1.5.0", BareMeaning::Caret, || {
                new_version.to_string()
            }),
            "=2.0.0"
        );
        assert_eq!(
            format_version_replacing_by_shape(
                &new_version,
                "~1.5.0",
                BareMeaning::ExactPin,
                || { new_version.to_string() }
            ),
            "~2.0.0"
        );
    }

    /// N2: the rewrite must reconstruct whichever tilde spelling `current` actually used, not
    /// hardcode `~` — a RubyGems-spelled `~>` requirement must stay `~>` on rewrite, matching
    /// this variant's own doc promise to "keep the tilde spelling".
    #[test]
    fn test_format_version_replacing_by_shape_preserves_rubygems_tilde_spelling() {
        let new_version = ConcreteVersion::new("2.0.0");
        assert_eq!(
            format_version_replacing_by_shape(
                &new_version,
                "~>1.5.0",
                BareMeaning::ExactPin,
                || { new_version.to_string() }
            ),
            "~>2.0.0"
        );
    }

    /// impl-critic S1: under `BareMeaning::Caret`, a bounded/compound requirement has no safe
    /// single-value rewrite and must be echoed back unchanged.
    #[test]
    fn test_format_version_replacing_by_shape_caret_meaning_refuses_unsafe_shapes() {
        let new_version = ConcreteVersion::new("2.0.0");
        for requirement in ["1.2.*", "<1.5", ">=1.2, <1.5", ">=1.2.0 <2.0.0"] {
            assert_eq!(
                format_version_replacing_by_shape(
                    &new_version,
                    requirement,
                    BareMeaning::Caret,
                    || new_version.to_string()
                ),
                requirement,
                "expected {requirement:?} to be echoed back unchanged under BareMeaning::Caret"
            );
        }
    }

    /// impl-critic S1: under `BareMeaning::ExactPin`, the same shapes collapse safely instead —
    /// a bare version there is a narrower single point, never a widening.
    #[test]
    fn test_format_version_replacing_by_shape_exact_pin_meaning_collapses_unsafe_shapes() {
        let new_version = ConcreteVersion::new("2.0.0");
        for requirement in ["1.2.*", "<1.5", ">=1.2, <1.5", ">=1.2.0 <2.0.0"] {
            assert_eq!(
                format_version_replacing_by_shape(
                    &new_version,
                    requirement,
                    BareMeaning::ExactPin,
                    || new_version.to_string()
                ),
                "2.0.0",
                "expected {requirement:?} to collapse to bare under BareMeaning::ExactPin"
            );
        }
    }

    /// impl-critic S2: a bare existence wildcard always collapses, regardless of
    /// `BareMeaning` — matching *anything* can only narrow when replaced with one version.
    #[test]
    fn test_format_version_replacing_by_shape_any_version_always_collapses() {
        let new_version = ConcreteVersion::new("2.0.0");
        for bare_meaning in [
            BareMeaning::Caret,
            BareMeaning::ExactPin,
            BareMeaning::Floor,
        ] {
            assert_eq!(
                format_version_replacing_by_shape(&new_version, "*", bare_meaning, || {
                    new_version.to_string()
                }),
                "2.0.0"
            );
        }
    }

    #[test]
    fn test_format_version_replacing_by_shape_bare_calls_bare_closure() {
        let new_version = ConcreteVersion::new("2.0.0");
        assert_eq!(
            format_version_replacing_by_shape(&new_version, "1.5.0", BareMeaning::ExactPin, || {
                new_version.as_str().to_string()
            }),
            "2.0.0"
        );
    }

    /// impl-critic S3: under `BareMeaning::Caret`, an explicit `^` is redundant with bare (both
    /// mean caret), so it may collapse via the `bare` closure just like a no-operator shape.
    #[test]
    fn test_format_version_replacing_by_shape_explicit_caret_collapses_under_caret_meaning() {
        let new_version = ConcreteVersion::new("2.0.0");
        assert_eq!(
            format_version_replacing_by_shape(&new_version, "^1.5.0", BareMeaning::Caret, || {
                new_version.to_string()
            }),
            "2.0.0"
        );
    }

    /// impl-critic S3: under `BareMeaning::ExactPin`, an explicit `^` is a genuinely wider
    /// range than bare — the rewrite must keep the `^` prefix, or it silently narrows a
    /// compatible-range requirement into an exact pin.
    #[test]
    fn test_format_version_replacing_by_shape_explicit_caret_preserved_under_exact_pin_meaning() {
        let new_version = ConcreteVersion::new("2.0.0");
        assert_eq!(
            format_version_replacing_by_shape(
                &new_version,
                "^1.5.0",
                BareMeaning::ExactPin,
                || { new_version.to_string() }
            ),
            "^2.0.0"
        );
    }

    /// #1602: a bracket-wrapped exact pin always keeps its bracket wrap, regardless of
    /// `BareMeaning` — this shape has no ecosystem whose bare form would make collapsing it safe.
    #[test]
    fn test_classify_requirement_rewrite_shape_bracket_exact_pin() {
        assert_eq!(
            classify_requirement_rewrite_shape("[1.0.0]"),
            RequirementRewriteShape::BracketExactPin
        );
    }

    /// #1602: a bracket-interval *range* always has an internal comma, so it must classify as
    /// Compound rather than BracketExactPin, even with an open-ended side (`[1.0,)`).
    #[test]
    fn test_classify_requirement_rewrite_shape_bracket_range_is_compound_not_exact_pin() {
        for requirement in ["[1.0,2.0)", "(1.0,2.0]", "[1.0,)", "(,1.0]"] {
            assert_eq!(
                classify_requirement_rewrite_shape(requirement),
                RequirementRewriteShape::Compound,
                "expected {requirement:?} to classify as Compound"
            );
        }
    }

    /// #1602: Gradle's trailing `+` dynamic-version marker (`1.0.+`, `2.5.+`) has no
    /// single-version rewrite that preserves "any matching patch/minor" semantics, exactly like
    /// a `*`/`x`/`X` partial wildcard.
    #[test]
    fn test_classify_requirement_rewrite_shape_gradle_dynamic_plus_suffix() {
        for requirement in ["1.0.+", "2.+", "1.2.3.+"] {
            assert_eq!(
                classify_requirement_rewrite_shape(requirement),
                RequirementRewriteShape::PartialWildcard,
                "expected {requirement:?} to classify as PartialWildcard"
            );
        }
    }

    /// #1602: under `BareMeaning::Floor`, a bounded/compound/wildcard requirement WIDENS if
    /// collapsed to bare (the upper bound is dropped), so it must be refused, mirroring
    /// `BareMeaning::Caret`'s own refusal.
    #[test]
    fn test_format_version_replacing_by_shape_floor_meaning_refuses_unsafe_shapes() {
        let new_version = ConcreteVersion::new("13.0.4");
        for requirement in ["[12.0.1,13.0.0)", "1.0.+", ">=1.0.0"] {
            assert_eq!(
                format_version_replacing_by_shape(
                    &new_version,
                    requirement,
                    BareMeaning::Floor,
                    || new_version.to_string()
                ),
                requirement,
                "expected {requirement:?} to be echoed back unchanged under BareMeaning::Floor"
            );
        }
    }

    /// #1602: a bracket-wrapped exact pin is preserved under `BareMeaning::Floor` too — the
    /// rewrite keeps the bracket wrap rather than collapsing to an unbounded floor.
    #[test]
    fn test_format_version_replacing_by_shape_floor_meaning_preserves_bracket_exact_pin() {
        let new_version = ConcreteVersion::new("13.0.4");
        assert_eq!(
            format_version_replacing_by_shape(&new_version, "[12.0.1]", BareMeaning::Floor, || {
                new_version.to_string()
            }),
            "[13.0.4]"
        );
    }

    /// #1602: a bare (no-marker) requirement still collapses under `BareMeaning::Floor` — only
    /// a *bounded* shape must be refused, not every non-exact one.
    #[test]
    fn test_format_version_replacing_by_shape_floor_meaning_bare_still_collapses() {
        let new_version = ConcreteVersion::new("13.0.4");
        assert_eq!(
            format_version_replacing_by_shape(&new_version, "12.0.1", BareMeaning::Floor, || {
                new_version.to_string()
            }),
            "13.0.4"
        );
    }

    /// #1602: no ecosystem with `BareMeaning::Floor` has an explicit `^` caret operator, so
    /// this arm is unreachable from any real ecosystem call site today — this test only proves
    /// the exhaustive match's own documented fallback (echo back unchanged, like every other
    /// unsafe shape under `Floor`) holds, in case a future `Floor` ecosystem ever gains one.
    #[test]
    fn test_format_version_replacing_by_shape_floor_meaning_refuses_explicit_caret() {
        let new_version = ConcreteVersion::new("13.0.4");
        assert_eq!(
            format_version_replacing_by_shape(&new_version, "^1.2.3", BareMeaning::Floor, || {
                new_version.to_string()
            }),
            "^1.2.3"
        );
    }

    /// #1602: `bare_meaning` is an exhaustive, per-ecosystem source of truth — every
    /// `EcosystemId::ALL` variant must resolve to some value without panicking (the match itself
    /// enforces exhaustiveness at compile time; this proves the const fn is actually callable
    /// for every variant at once).
    #[test]
    fn test_bare_meaning_covers_every_ecosystem() {
        for &eco in EcosystemId::ALL {
            let _ = bare_meaning(eco);
        }
    }

    /// #1656: `^`-prefixed compound requirements are not single carets and must not be
    /// mis-parsed by `caret_admits_up_to_date`.
    #[test]
    fn test_caret_admits_up_to_date_rejects_compound_shapes() {
        for requirement in ["^3 || ^4", "^4.5 <4.7", "^1 ^2", "^1, <2"] {
            assert_eq!(
                caret_admits_up_to_date("4.1.0", requirement),
                None,
                "{requirement}"
            );
        }
        assert_eq!(caret_admits_up_to_date("4.1.0", "^4.0"), Some(true));
    }

    #[test]
    fn test_up_to_date_via_compiled_matcher_falls_back_without_matcher() {
        let latest = ConcreteVersion::new("1.2.3");
        let requirement = VersionReq::new("1.2.3");
        assert!(up_to_date_via_compiled_matcher(
            &MOCK_FORMATTER,
            BoundedVersionReq::new(&requirement).unwrap(),
            &latest
        ));
    }

    struct MajorOneMatcher {
        strict: bool,
    }

    impl RequirementMatcher for MajorOneMatcher {
        fn matches(&self, version: &ConcreteVersion) -> Option<bool> {
            Some(version.as_str().starts_with("1.") && !version.as_str().contains('-'))
        }

        fn strict_prerelease_exclusion(&self) -> bool {
            self.strict
        }
    }

    struct MajorOneFormatter {
        strict: bool,
    }

    impl RequirementResolution for MajorOneFormatter {
        fn compile_bounded_requirement(
            &self,
            _: BoundedVersionReq<'_>,
        ) -> Option<Box<dyn RequirementMatcher>> {
            Some(Box::new(MajorOneMatcher {
                strict: self.strict,
            }))
        }
    }

    /// #1661: the numeric-core retry applies only to strict-prerelease matchers.
    #[test]
    fn test_up_to_date_via_compiled_matcher_core_retry_needs_strict_matcher() {
        let requirement = VersionReq::new(">=1 <2");
        let bounded = BoundedVersionReq::new(&requirement).unwrap();
        let latest = ConcreteVersion::new("1.5.0-beta.1");
        assert!(up_to_date_via_compiled_matcher(
            &MajorOneFormatter { strict: true },
            bounded,
            &latest
        ));
        assert!(!up_to_date_via_compiled_matcher(
            &MajorOneFormatter { strict: false },
            bounded,
            &latest
        ));
    }

    #[test]
    fn test_requirement_needs_range_semantics() {
        for requirement in [
            "=1.2.3",
            "<2",
            ">=1.2, <2",
            " > 1",
            "^1 || ^2",
            "^1.5 <1.9",
            ">=1.*",
            "=1.2.*",
        ] {
            assert!(
                requirement_needs_range_semantics(requirement),
                "{requirement}"
            );
        }
        for requirement in [
            "1.0.228", "^1.5", "~1.2", "1.*", "1.2.*", "*", "1.0.+", "[1.0.0]",
        ] {
            assert!(
                !requirement_needs_range_semantics(requirement),
                "{requirement}"
            );
        }
    }

    /// #1660 S1: a `^` floor in a comma-joined compound stays relaxed under a comma grammar.
    #[test]
    fn test_up_to_date_via_compiled_matcher_relaxes_caret_floor_with_comma_grammar() {
        struct CommaGrammarFormatter;
        impl RequirementResolution for CommaGrammarFormatter {
            fn compile_bounded_requirement(
                &self,
                requirement: BoundedVersionReq<'_>,
            ) -> Option<Box<dyn RequirementMatcher>> {
                crate::lsp_helpers::compile_semver_requirement(requirement.get())
            }
        }
        let up_to_date = |requirement: &str, latest: &str| {
            let requirement = VersionReq::new(requirement);
            up_to_date_via_compiled_matcher(
                &CommaGrammarFormatter,
                BoundedVersionReq::new(&requirement).unwrap(),
                &ConcreteVersion::new(latest),
            )
        };
        assert!(up_to_date("^1.5, <1.9", "1.4.9"));
        assert!(!up_to_date("^1.5, <1.9", "1.9.5"));
    }

    #[test]
    fn test_relax_caret_floors() {
        assert_eq!(
            relax_caret_floors("^1.5 <1.9", " ").as_deref(),
            Some(">=1.0.0 <2.0.0 <1.9")
        );
        assert_eq!(
            relax_caret_floors("^1.5,<1.9 || ^0.2", " ").as_deref(),
            Some(">=1.0.0 <2.0.0,<1.9 || >=0.0.0 <0.3.0")
        );
        assert_eq!(
            relax_caret_floors("^1.5, <1.9", ", ").as_deref(),
            Some(">=1.0.0, <2.0.0, <1.9")
        );
        assert_eq!(relax_caret_floors("^x", " "), None);
        assert_eq!(relax_caret_floors(">=1 <2", " "), None);
    }

    #[test]
    fn test_default_osv_package_name_skips_empty_name() {
        use crate::lsp_helpers::test_support::MockDep;
        use crate::position::Range;

        let dep = |name: &str| MockDep {
            name: name.into(),
            version_req: "1.0".into(),
            version_range: Range::default(),
            name_range: Range::default(),
        };
        assert_eq!(MOCK_FORMATTER.osv_package_name(&dep("")), None);
        assert!(MOCK_FORMATTER.osv_package_name(&dep("serde")).is_some());
    }
}
