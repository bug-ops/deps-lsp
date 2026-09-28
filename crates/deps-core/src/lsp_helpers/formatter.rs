//! Ecosystem-specific formatting and comparison logic, split into concern-scoped traits.
//!
//! [`EcosystemFormatter`] is kept as a single object-safe marker bound so every existing
//! `&dyn EcosystemFormatter` call site is untouched; it is automatically implemented for any
//! type implementing all seven concern traits below via a blanket impl, so implementors never
//! write `impl EcosystemFormatter for X` themselves. The seven traits are independent siblings
//! — none of them has a default method that calls a method living in a different trait — so
//! implementing a subset of them (e.g. in a test mock that only needs [`PackageRendering`]) is
//! always sufficient for calling that subset's methods directly, without pulling in the rest.

use crate::position::Position;

use super::{RequirementMatcher, RequirementStatus, is_same_major_minor, position_in_range};
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
/// [`RequirementResolution::requirement_is_placeholder`](super::RequirementResolution::requirement_is_placeholder)
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

/// Requirement parsing, matching, and up-to-date status.
///
/// Implementors guarantee every method here is a pure function of its arguments — no network
/// or filesystem access — since these run on the hot hover/diagnostic path. The default
/// [`requirement_status`](Self::requirement_status) maps
/// [`requirement_is_unresolved`](Self::requirement_is_unresolved) to its `Unresolved` variant
/// and otherwise defers to [`is_requirement_up_to_date`](Self::is_requirement_up_to_date). Most
/// ecosystems whose requirement syntax can be unresolved (Maven, Gradle, NuGet, Cargo, npm, ...)
/// need only override [`requirement_is_placeholder`](Self::requirement_is_placeholder) —
/// `requirement_is_unresolved` defaults to delegating to it. Only `deps-github-actions` and
/// `deps-gitlab-ci` override `requirement_is_unresolved` directly, since their two predicates
/// answer genuinely different questions there (see `requirement_is_placeholder`'s doc). Callers
/// needing the tri-state distinction use `requirement_status`, not the boolean method.
pub trait RequirementResolution: Send + Sync {
    /// Check if a version satisfies a requirement string.
    ///
    /// General constraint check (e.g. for completion/candidate filtering) — not the
    /// "is this dependency up to date" hook. That is `is_requirement_up_to_date` below,
    /// which has its own default and its own override points; an ecosystem whose bare
    /// requirement is a floor rather than an auto-following range (see `deps-nuget`)
    /// overrides that method, not this one.
    fn version_satisfies_requirement(&self, version: &ConcreteVersion, requirement: &str) -> bool {
        let version = version.as_str();
        // Caret allows changes that don't modify the left-most non-zero component:
        // ^2.0 -> 2.x.x, ^0.2 -> 0.2.x, ^0.0.3 -> only 0.0.3
        if let Some(req) = requirement.strip_prefix('^') {
            let req_parts: Vec<&str> = req.split('.').collect();
            let ver_parts: Vec<&str> = version.split('.').collect();

            // Must have same major version
            if req_parts.first() != ver_parts.first() {
                return false;
            }

            // For ^X.Y where X > 0, any X.*.* is allowed
            if req_parts.first().is_some_and(|m| *m != "0") {
                return true;
            }

            #[expect(
                clippy::indexing_slicing,
                reason = "for ^0.Y, must have same minor (length checked on the same line)"
            )]
            if req_parts.len() >= 2 && ver_parts.len() >= 2 {
                return req_parts[1] == ver_parts[1];
            }

            return true;
        }

        // Tilde allows patch-level changes: ~2.0 -> 2.0.x, ~2.0.1 -> 2.0.x where x >= 1
        if let Some(req) = requirement.strip_prefix('~') {
            return is_same_major_minor(req, version);
        }

        // Plain version or partial version
        let req_parts: Vec<&str> = requirement.split('.').collect();
        let is_partial_version = req_parts.len() <= 2;

        version == requirement
            || (is_partial_version && is_same_major_minor(requirement, version))
            || (is_partial_version && version.starts_with(requirement))
    }

    /// Whether an unresolved dependency (no lock-file version) should be reported as
    /// up to date against `latest`, given its declared `requirement`.
    ///
    /// Default: `latest` satisfies `requirement` — correct for range-based ecosystems
    /// (Cargo's `^1.2`, npm's `~1.2`, ...) where the declared requirement already
    /// expresses forward compatibility, so a `latest` it accepts is not "newer" in any
    /// actionable sense. Ecosystems where a bare requirement is a minimum floor rather
    /// than an auto-following range (NuGet's bare `Version="1.0.0"`) must override this,
    /// since "does the floor accept `latest`" and "is the pin already `latest`" are
    /// different questions there.
    fn is_requirement_up_to_date(
        &self,
        requirement: &VersionReq,
        latest: &ConcreteVersion,
    ) -> bool {
        self.version_satisfies_requirement(latest, requirement.as_str())
    }

    /// Whether `requirement` could not be resolved to a concrete version constraint (e.g. an
    /// unexpanded property/variable placeholder rather than a real version or range).
    ///
    /// Default: delegates to [`requirement_is_placeholder`](Self::requirement_is_placeholder),
    /// which is correct for every ecosystem except `deps-github-actions` and `deps-gitlab-ci`
    /// (see that method's doc for why their two predicates genuinely differ). Overriding
    /// `requirement_is_placeholder` alone therefore keeps both predicates in sync; only those
    /// two ecosystems need their own `requirement_is_unresolved` override.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::lsp_helpers::RequirementResolution;
    /// use deps_core::VersionReq;
    ///
    /// struct DefaultFormatter;
    /// impl RequirementResolution for DefaultFormatter {}
    ///
    /// assert!(!DefaultFormatter.requirement_is_unresolved(&VersionReq::new("^1.2")));
    /// ```
    fn requirement_is_unresolved(&self, requirement: &VersionReq) -> bool {
        self.requirement_is_placeholder(requirement)
    }

    /// Whether `requirement` is an unexpanded placeholder/interpolation (Maven's
    /// `${property}`, Gradle's `$var`, NuGet's `$(Property)`/`%(Metadata)`/`@(ItemList)`,
    /// Bundler's `#{...}`/`#@ivar`, Swift's `\(...)`, GitLab CI's `$VAR`/`${VAR}`/`%VAR%`)
    /// that must never be overwritten by a manifest rewrite, no matter what other requirement
    /// resolution predicate happens to say about it.
    ///
    /// Distinct from [`requirement_is_unresolved`](Self::requirement_is_unresolved): that
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
    /// [`compile_requirement`](Self::compile_requirement), and
    /// [`version_satisfies_requirement`](Self::version_satisfies_requirement) — and, since
    /// #1391, need not guard [`format_version_replacing`](PackageRendering::format_version_replacing)/
    /// [`format_version_replacing_for`](PackageRendering::format_version_replacing_for) at all:
    /// [`crate::edit::replacement_text`] is the only production path that ever calls into
    /// those methods, and it never does so once this predicate says `true`.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::lsp_helpers::RequirementResolution;
    /// use deps_core::VersionReq;
    ///
    /// struct DefaultFormatter;
    /// impl RequirementResolution for DefaultFormatter {}
    ///
    /// assert!(!DefaultFormatter.requirement_is_placeholder(&VersionReq::new("^1.2")));
    /// assert!(DefaultFormatter.requirement_is_placeholder(&VersionReq::new("{{ version }}")));
    /// ```
    fn requirement_is_placeholder(&self, requirement: &VersionReq) -> bool {
        super::requirement_contains_template_placeholder(requirement.as_str())
    }

    /// Tri-state variant of `is_requirement_up_to_date` that distinguishes "confirmed up to
    /// date" from "could not be resolved, so we don't know."
    ///
    /// Default: `Unresolved` when `requirement_is_unresolved` says so, otherwise maps the
    /// boolean result of `is_requirement_up_to_date` to `UpToDate`/`Outdated`. Callers
    /// needing the distinction — inlay hints, in particular — use this instead of
    /// `is_requirement_up_to_date` so they can tell "verified up to date" apart from
    /// "resolution failed."
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::lsp_helpers::{RequirementResolution, RequirementStatus};
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
    ) -> RequirementStatus {
        if self.requirement_is_unresolved(requirement) {
            return RequirementStatus::Unresolved;
        }
        // #1472 defense-in-depth: an oversized requirement is unmodellable, not verified
        // up to date or outdated — same suppression semantics as the unsatisfiable-diagnostic
        // gate. This is the sole production caller of `is_requirement_up_to_date`, so gating
        // here also covers callers of `requirement_status_for`'s default (which forwards to
        // this method).
        if super::requirement_is_oversized(requirement) {
            return RequirementStatus::Unresolved;
        }
        if self.is_requirement_up_to_date(requirement, latest) {
            RequirementStatus::UpToDate
        } else {
            RequirementStatus::Outdated
        }
    }

    /// Like [`requirement_status`](Self::requirement_status), but also hands the ecosystem
    /// the dependency itself — for an ecosystem whose requirement *text* alone is ambiguous
    /// between two shapes with different resolution rules, and which already computed the
    /// disambiguating classification once, at parse time, onto the dependency (`deps-gitlab-ci`'s
    /// `PinStyle`, #466 review M-c: a bare `"1.2"` is `Partial` under its `component:` pin
    /// grammar but `Branch` under its simpler `project:` ref grammar — indistinguishable from
    /// the text alone).
    ///
    /// Default: forwards to [`requirement_status`](Self::requirement_status), ignoring `dep`
    /// — every other ecosystem's requirement text alone is unambiguous, so this is a no-op
    /// for them. Callers that already have `dep` in hand (the diagnostic pipeline's outdated
    /// rule) call this instead of `requirement_status` directly, mirroring
    /// `Registry::select_latest_matching`'s identical additive-default pattern for its own
    /// `selection_context` parameter.
    fn requirement_status_for(
        &self,
        dep: &dyn Dependency,
        requirement: &VersionReq,
        latest: &ConcreteVersion,
    ) -> RequirementStatus {
        let _ = dep;
        self.requirement_status(requirement, latest)
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
    /// use deps_core::lsp_helpers::RequirementResolution;
    /// use deps_core::VersionReq;
    ///
    /// struct DefaultFormatter;
    /// impl RequirementResolution for DefaultFormatter {}
    ///
    /// assert!(
    ///     DefaultFormatter
    ///         .compile_requirement(&VersionReq::new("^1.2"))
    ///         .is_none()
    /// );
    /// ```
    fn compile_requirement(
        &self,
        _requirement: &VersionReq,
    ) -> Option<Box<dyn RequirementMatcher>> {
        None
    }

    /// Whether `requirement`, left unedited, already resolves forward to a version at or
    /// above `target` under this ecosystem's own resolution rules — the gate
    /// [`crate::edit::plan_vulnerability_fix`] (#1344) consults before deciding a
    /// vulnerability-fix manifest rewrite is unnecessary.
    ///
    /// Distinct from `compile_requirement(requirement).matches(target)` alone, which only
    /// answers "is `target` a member of `requirement`'s accepted set" — true both for an
    /// auto-following range (Cargo's `^1`, a Maven bracket range), where membership genuinely
    /// means "no edit needed, re-resolving already gets there", *and* for a floor a resolver
    /// instead pins to its lowest admissible member (NuGet's bare `Version="1.0.0"`, mirroring
    /// [`Self::is_requirement_up_to_date`]'s own floor carve-out), where it does not: leaving
    /// the manifest unedited keeps resolving to the floor itself, never to `target`.
    ///
    /// Default: delegates straight to `compile_requirement(requirement).matches(target)`,
    /// collapsing `None` (uncompilable requirement) and `Some(false)` to `false` — correct for
    /// every ecosystem whose resolution prefers the newest admissible member of a requirement's
    /// accepted set. Override only when some requirement shape in this ecosystem instead
    /// resolves to something other than that newest member.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::lsp_helpers::RequirementResolution;
    /// use deps_core::{ConcreteVersion, VersionReq};
    ///
    /// struct DefaultFormatter;
    /// impl RequirementResolution for DefaultFormatter {}
    ///
    /// // No `compile_requirement` override, so this is always `false` — matches that
    /// // method's own default.
    /// assert!(!DefaultFormatter.requirement_already_resolves_to(
    ///     &VersionReq::new("^1.2"),
    ///     &ConcreteVersion::new("1.5.0")
    /// ));
    /// ```
    fn requirement_already_resolves_to(
        &self,
        requirement: &VersionReq,
        target: &ConcreteVersion,
    ) -> bool {
        self.compile_requirement(requirement)
            .is_some_and(|matcher| matcher.matches(target) == Some(true))
    }

    /// Whether this ecosystem's registry can silently omit a *published* version from
    /// `available` in a way indistinguishable from "never published" — and, if so, whether
    /// `requirement` names a version-space region that specific omission could explain, given
    /// the versions actually observed in `available`.
    ///
    /// Called by [`crate::lsp_helpers::requirement_is_unsatisfiable`] before compiling `requirement`; returning
    /// `true` suppresses the "no published version satisfies this requirement" diagnostic for
    /// this dependency, the same as [`Self::compile_requirement`] returning `None` — but,
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
    /// use deps_core::lsp_helpers::RequirementResolution;
    /// use deps_core::{ConcreteVersion, VersionReq};
    ///
    /// struct DefaultFormatter;
    /// impl RequirementResolution for DefaultFormatter {}
    ///
    /// assert!(!DefaultFormatter.requirement_is_undecidable_given_available(
    ///     &VersionReq::new("1.6.13"),
    ///     &[ConcreteVersion::new("1.6.9"), ConcreteVersion::new("1.6.14")],
    /// ));
    /// ```
    fn requirement_is_undecidable_given_available(
        &self,
        _requirement: &VersionReq,
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
    /// version is knowable from [`crate::lsp_helpers::TagIndex::sha_to_tag`] — resolved via
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
    /// caller re-applies the identical full-version shape gate manifest text goes through
    /// (`concrete_pin_version`), since this hook can itself resolve to a
    /// moving/partial name (#1556 impl-critic S1).
    ///
    /// Default: `None` — every ecosystem's manifest requirement text is authoritative until
    /// it opts in.
    fn resolved_pin_version(&self, dep: &dyn Dependency) -> Option<ConcreteVersion> {
        let _ = dep;
        None
    }

    /// Whether [`Self::resolved_pin_version`] may only start returning `Some` for a given
    /// dependency once this ecosystem's own registry fetch completes (e.g. GitHub Actions'/
    /// GitLab CI's `TagIndex`, populated as a side effect of `Registry::get_versions` — not
    /// present yet at document-open/edit time).
    ///
    /// Default: `false` — every ecosystem whose `resolved_pin_version` stays `None`
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
    /// The default implementation is the identity: OSV is case-sensitive in
    /// every ecosystem this project supports except PyPI, and for Cargo, npm,
    /// Go, Maven, Gradle, Dart, Bundler, NuGet, and PyPI the manifest's raw
    /// name already matches OSV's canonical spelling.
    fn osv_package_name(&self, dep: &dyn Dependency) -> Option<String> {
        Some(dep.name().as_str().to_string())
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
}
