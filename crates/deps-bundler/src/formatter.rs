//! Version formatting for Bundler ecosystem.

use crate::version::{compare_versions, is_valid_rubygems_version, version_matches_requirement};
use deps_core::ConcreteVersion;
use deps_core::Dependency;
use deps_core::InvalidPackageName;
use deps_core::PackageName;
use deps_core::VersionReq;
use deps_core::lsp_helpers::{
    DiagnosticMessages, DiagnosticPolicy, OsvNaming, PackageNaming, PackageRendering,
    RequirementMatcher, RequirementResolution, SourcePolicy, compile_requirement_unless,
};

/// Whether every character of `name` is in RubyGems' gem-name charset
/// (`Gem::Specification::VALID_NAME_PATTERN`): ASCII letters, digits, `.`, `-`, `_`.
fn is_rubygems_name_charset(name: &str) -> bool {
    name.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
}

/// Extracts the version operand of `requirement` for the operators whose
/// [`version_matches_requirement`] branch evaluates `false` against every candidate on a
/// malformed operand ("fails closed") rather than `true` against every candidate ("fails
/// open"): `~>`, `<`, `<=`, `=`, and the bare/no-operator pin. Mirrors
/// `version_matches_requirement`'s own operator dispatch order (`<=` checked before `<`) so
/// a requirement is classified identically in both places.
///
/// Returns `None` for `>`, `>=`, `!=`, and `*` — confirmed live against RubyGems (#332
/// critique) that a malformed operand for these instead makes every candidate match except,
/// for `!=` since #345's switch to canonical comparison, one candidate that happens to
/// canonicalize identically to the operand's non-garbage prefix (e.g. `!= 1.0.0!!!` no longer
/// matches `1.0.0` itself). Either way this never triggers the "no version satisfies
/// requirement" false positive this gates — a single excluded candidate among the rest still
/// leaves the requirement satisfiable — so none of these four need validation here.
fn fail_closed_operand(requirement: &str) -> Option<&str> {
    let req = requirement.trim();
    if req == "*" || req.starts_with(">=") || req.starts_with('>') || req.starts_with("!=") {
        return None;
    }
    if let Some(rest) = req.strip_prefix("~>") {
        return Some(rest.trim());
    }
    if let Some(rest) = req.strip_prefix("<=") {
        return Some(rest.trim());
    }
    if let Some(rest) = req.strip_prefix('<') {
        return Some(rest.trim());
    }
    if let Some(rest) = req.strip_prefix('=') {
        return Some(rest.trim());
    }
    Some(req)
}

/// True when any comma-separated constraint of a (possibly multi-constraint, #1366) requirement
/// has a [`fail_closed_operand`] whose operand is not a valid RubyGems version — applied
/// per-constraint since `fail_closed_operand` itself only looks at a single leading operator, and
/// a multi-constraint requirement like `">= 1.0, < 2.0"` composes several independently.
fn any_constraint_fails_closed_and_invalid(requirement: &str) -> bool {
    requirement.split(',').any(|constraint| {
        fail_closed_operand(constraint).is_some_and(|operand| !is_valid_rubygems_version(operand))
    })
}

/// Rubygems requirement matcher, compiled once per dependency by
/// [`BundlerFormatter::compile_requirement`]. `version_matches_requirement` is a hand-rolled
/// comparator with no external parser to fail on, so this always decides (`Some`).
struct RubygemsMatcher(String);

impl RequirementMatcher for RubygemsMatcher {
    fn matches(&self, version: &ConcreteVersion) -> Option<bool> {
        let version = version.as_str();
        Some(version_matches_requirement(version, &self.0))
    }
}

/// Whether `requirement` contains an unresolved Ruby string-interpolation placeholder —
/// either the general `#{...}` form or one of Ruby's shorthand forms for a bare instance
/// (`#@ivar`), class (`#@@cvar`), or global (`#$GVAR`) variable reference, e.g. `gem 'rails',
/// "~> #{RAILS_VERSION}"` or `gem 'rails', "~> #@rails_version"`. Bundler's parser does not
/// degrade any of these shapes to `version_requirement: None` (unlike NuGet's `$(Property)`),
/// so they reach [`RequirementResolution`] and [`PackageRendering`] directly — issue #1354
/// security audit: `compile_requirement` previously returned `None` for `"~> #{V}"` only by
/// coincidence (its operand fails `is_valid_rubygems_version`), while `">= #{V}"` compiled to
/// `Some(true)` for every candidate (`fail_closed_operand` excludes `>=`), and neither path
/// stopped `format_version_replacing` from planning a destructive `"9.9.9"`-literal rewrite
/// over the interpolation. #1354 critic S4: the shorthand forms (`#@`/`#@@`/`#$`) were
/// initially missed by a `#{`-only check, leaving `"~> #@v"` rewritable. Mirrors
/// `NuGetFormatter`'s `$(Property)` guard (#1352).
fn requirement_contains_unresolved_interpolation(requirement: &str) -> bool {
    requirement
        .as_bytes()
        .array_windows::<2>()
        .any(|&[c, next]| c == b'#' && matches!(next, b'{' | b'@' | b'$'))
}

/// True when `literal` — a raw multi-constraint span (see
/// [`crate::types::BundlerDependency::version_literal`], #1366) spanning from the first
/// constraint's content through the last's — was written with inconsistent quote characters
/// across its constraints, e.g. `gem "x", '>= 5.0', "< 6.0"`.
///
/// [`VERSION_PATTERN`](crate::parser)'s capture group excludes quote characters from a
/// constraint's own text (`[^'"]*`), so the *only* quote characters that can appear inside this
/// span are the boundary quotes between constraints (a closing quote immediately followed by an
/// opening one) — a same-quote-style multi-constraint call therefore has exactly one quote
/// character repeated throughout the span, while a mixed-style one has both.
///
/// Why this matters: `version_range` spans from just after the first constraint's opening quote
/// to just before the last constraint's closing quote (#1366 impl-critic S1's `version_literal`
/// fix) — those two *outer* quote characters are never part of the replaced range, only
/// preserved verbatim on either side of it. Splicing a bare replacement version into that range
/// unconditionally is safe when every constraint used the same quote character (the two
/// preserved outer quotes match), but produces invalid Ruby when they differ — e.g. replacing
/// the whole span in `'>= 5.0', "< 6.0"` with `6.1.0` leaves `'6.1.0"` (mismatched open/close
/// quotes). Impl-critic S2: `deps-cli`'s `plan_verified_fix` has no separate guard against the
/// live document text (unlike the LSP's `literal_span_matches`), so this must be caught before a
/// replacement is ever produced, not after.
fn literal_span_has_mixed_quote_styles(literal: &str) -> bool {
    literal.contains('\'') && literal.contains('"')
}

/// A Bundler requirement written as `= X` or bare `X` (no operator) pins a single exact
/// version. Returns the pinned version string, or `None` when `requirement` is a wildcard,
/// empty, or a range/comparison operator (`~>`, `>=`, `>`, `<=`, `<`, `!=`) rather than a pin.
fn exact_pin_version(requirement: &str) -> Option<&str> {
    let req = requirement.trim();
    // A multi-constraint requirement (#1366, e.g. `"1.0.0, < 2.0"`) is never a single exact
    // pin, even when its first constraint looks like one — without this guard, a bare-pin
    // first constraint followed by another fell through to the `is_range_op` check below,
    // which only inspects the leading operator, and returned the whole comma-joined string as
    // if it were one version.
    if req.is_empty() || req == "*" || req.contains(',') {
        return None;
    }
    if let Some(rest) = req.strip_prefix('=') {
        let rest = rest.trim();
        return (!rest.is_empty()).then_some(rest);
    }
    let is_range_op = ["~>", ">=", ">", "<=", "<", "!="]
        .iter()
        .any(|op| req.starts_with(op));
    (!is_range_op).then_some(req)
}

/// RubyGems' `versions.json` endpoint omits yanked entries from the result entirely rather
/// than flagging them — verified live: `rest-client` lists `1.6.9`/`1.6.14` but not the
/// yanked `1.6.10`-`1.6.13`. Yanking is not confined to interior gaps, though: live
/// verification against real yank records found gems (`puppetlabs-syntax`,
/// `keeper_secrets_manager`, `tingee_ruby_sdk`) with every version *below* the current
/// minimum yanked — e.g. `puppetlabs-syntax` yanked `6.0.0` and `7.2.0`, leaving `7.2.1` as
/// the sole published version, so a pin on `7.2.0` sorts *below* `available`'s only entry.
/// The top of the range is the only usable boundary, and only an accepted approximation of
/// one: `available`'s observed maximum is ordinarily the newest real release, but if the
/// newest release itself was later yanked with nothing published after it, a pin on it would
/// sort *above* the new (lower) maximum — `available` alone cannot tell that case apart from a
/// pin that was simply mistyped too high, and flagging the latter is the whole point of #252.
/// This risk is accepted as an empirically rare residual (0/30 in the live sample that found
/// the below-minimum counterexamples below) rather than modeled, since there is no signal in
/// `available` to distinguish the two. So an exact pin (see [`exact_pin_version`]) is treated
/// as possibly-yanked — and the unsatisfiable check suppressed — whenever it does not exceed
/// `available`'s observed maximum, regardless of how far below the minimum it sorts; only a
/// pin above the maximum is still flagged as unsatisfiable. This deliberately over-suppresses
/// relative to the narrower "interior gap" theory this replaced (a below-minimum pin that
/// really was never published now also goes unflagged), but under-suppression was the actual
/// bug (#252) and the direction this errs in is the same one the whole mechanism exists to
/// guarantee: never a false "unsatisfiable". Wider requirement shapes (`~>`, `>=`, ranges) are
/// left alone: they typically span many versions, so a match existing only among yanked ones
/// is a rare edge case rather than the common one exact pins hit.
///
/// Note on the boundary case (pin equal to the maximum): this gate compares via
/// [`compare_versions`], and since #345 the actual scan in [`RubygemsMatcher`]
/// (`version_matches_requirement`) does too for both the explicit `=` and bare-pin forms —
/// both now agree that a pin of `"1.6"` canonically equals a published `"1.6.0"`. (Before
/// #345, the string/prefix matcher used there disagreed with this gate at that boundary; the
/// two no longer can.) A prerelease-tagged pin like `"2.0.0.rc1"` against a published
/// `"2.0.0"` does not reach this path either: `compare_versions` correctly orders it below
/// the stable release instead of tying, since #323's fix.
///
/// #1366 impl-critic M2: applied per comma-separated constraint, not just to `requirement` as a
/// whole — `exact_pin_version` itself rejects a whole multi-constraint string outright (it is
/// never itself a single pin), so without this a requirement like `'1.6.13', '< 2'` lost the
/// yanked-pin suppression entirely for its exact-pin half, reintroducing #252's false positive
/// for the specific case of an exact pin now written alongside a second, unrelated bound.
///
/// #1366 team-lead review: a candidate constraint's pin must also satisfy every *other*
/// constraint in `requirement` (checked via [`version_matches_requirement`] against the whole
/// original string, which already ANDs every comma-separated part) before this suppresses the
/// unsatisfiable diagnostic — otherwise a requirement that is genuinely, unconditionally
/// impossible for a reason unrelated to yanking (e.g. `"5.0.0", ">= 6.0"`, a bad merge/typo
/// with no version that could ever satisfy both) gets silently waved through just because its
/// exact-pin half happens to sit below the observed maximum: `5.0.0` not exceeding a `6.5.0`
/// max says nothing about whether `5.0.0` was ever a candidate for this requirement's *other*
/// half. Without this check, `exact_pin_could_be_yanked` only asked "could this one constraint's
/// pin be a yanked, unlisted version" — the right question for a single-constraint requirement,
/// but not sufficient once `requirement_is_undecidable_given_available` suppresses the diagnostic
/// for the *whole* multi-constraint requirement on this constraint's say-so alone.
fn exact_pin_could_be_yanked(requirement: &str, available: &[ConcreteVersion]) -> bool {
    let Some(max) = available
        .iter()
        .max_by(|a, b| compare_versions(a.as_str(), b.as_str()))
    else {
        return false;
    };
    requirement.split(',').any(|constraint| {
        exact_pin_version(constraint).is_some_and(|pin| {
            !compare_versions(pin, max.as_str()).is_gt()
                && version_matches_requirement(pin, requirement)
        })
    })
}

/// Formatter for Bundler/Ruby gem versions.
pub struct BundlerFormatter;

impl PackageNaming for BundlerFormatter {
    /// Lints `name` against RubyGems' own gem-name rule (see `is_rubygems_name_charset` plus
    /// its "must include at least one letter" check), so a structurally invalid gem name is
    /// reported as "Invalid package name" instead of falling through to a registry lookup and
    /// rendering the generic "Registry lookup failed" diagnostic (#402).
    ///
    /// # Errors
    ///
    /// Returns [`InvalidPackageName`] if `name` is empty, contains a character outside
    /// RubyGems' `[a-zA-Z0-9.\-_]` charset, or contains no letter. The charset check runs
    /// before the letter check (#402 critique M4) so a name that fails both — e.g. a
    /// non-ASCII name with no ASCII letter at all — reports the charset violation rather than
    /// the less specific "no letter" message.
    fn validate_package_name(&self, name: &str) -> Result<(), InvalidPackageName> {
        if name.is_empty() {
            return Err(InvalidPackageName::new("name cannot be empty"));
        }
        if !is_rubygems_name_charset(name) {
            return Err(InvalidPackageName::new(
                "name must contain only ASCII letters, digits, '.', '-', or '_'",
            ));
        }
        if !name.chars().any(|c| c.is_ascii_alphabetic()) {
            return Err(InvalidPackageName::new(
                "name must include at least one letter",
            ));
        }
        Ok(())
    }
}

impl PackageRendering for BundlerFormatter {
    fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
        let version = version.as_str();
        version.to_string()
    }

    fn package_url(&self, name: &PackageName) -> String {
        crate::registry::gem_url(name.as_str())
    }

    /// #1354 hardening: an unresolved Ruby interpolation (see
    /// `requirement_contains_unresolved_interpolation`) in `current` leaves `current`
    /// unchanged instead of substituting `version`, so a vulnerability-fix or "update to
    /// latest" edit can never hardcode a literal version over `#{...}` — mirrors
    /// `NuGetFormatter::format_version_replacing`'s `$(Property)` guard.
    fn format_version_replacing(&self, version: &ConcreteVersion, current: &str) -> String {
        if requirement_contains_unresolved_interpolation(current) {
            return current.to_string();
        }
        self.format_version_for_text_edit(version)
    }

    /// #1366 impl-critic S2: a multi-constraint requirement whose constraints were written
    /// with inconsistent quote characters (see `literal_span_has_mixed_quote_styles`) echoes
    /// [`Dependency::version_literal`] back unchanged instead of collapsing to a bare
    /// replacement version, mirroring [`Self::format_version_replacing`]'s `#{...}` guard.
    ///
    /// **Must** echo `literal_target` (`dep.version_literal()`, falling back to `current`) —
    /// not `current` — on every no-op path here, unlike [`Self::format_version_replacing`]
    /// itself (which has no `dep` and echoes `current`, its only option): both
    /// `deps_core::edit::plan_verified_fix`'s and `generate_code_actions`'s no-op check compare
    /// the text this returns against that exact `literal_target`, not `current`. For a
    /// multi-constraint dependency the two differ (`current` is the `", "`-joined comparator,
    /// e.g. `">= 5.0, < 6.0"`, with no quote characters at all regardless of how the source
    /// `Gemfile` quoted each constraint; `literal_target` is the raw source span, quotes and
    /// comma included) — echoing `current` there would fail the no-op comparison and still
    /// produce a corrupting replacement despite the interpolation/mixed-quote guard firing.
    fn format_version_replacing_for(
        &self,
        dep: &dyn Dependency,
        version: &ConcreteVersion,
        current: &str,
    ) -> String {
        let literal_target = dep.version_literal().unwrap_or(current);
        if requirement_contains_unresolved_interpolation(current)
            || literal_span_has_mixed_quote_styles(literal_target)
        {
            return literal_target.to_string();
        }
        self.format_version_for_text_edit(version)
    }
}

impl RequirementResolution for BundlerFormatter {
    /// #1354 hardening: an unresolved requirement (see
    /// [`Self::requirement_is_unresolved`]) returns `true` (treated as satisfied) rather than
    /// falling into `version_matches_requirement`, which would otherwise compare the raw
    /// `#{...}` text against every candidate — mirrors `NuGetFormatter`'s identical guard.
    fn version_satisfies_requirement(&self, version: &ConcreteVersion, requirement: &str) -> bool {
        if self.requirement_is_unresolved(&VersionReq::new(requirement)) {
            return true;
        }
        let version = version.as_str();
        version_matches_requirement(version, requirement)
    }

    /// Compiles `requirement` into a `RubygemsMatcher` using the same
    /// `version_matches_requirement` comparator as `version_satisfies_requirement` — Bundler
    /// requirements have no separate "loose" vs. "precise" form to distinguish, and
    /// `version_matches_requirement` never fails to parse, so this always decides (`Some`),
    /// except when `any_constraint_fails_closed_and_invalid` identifies one of `requirement`'s
    /// comma-separated constraints (#1366) as one of the operator shapes (`~>`, `<`, `<=`, `=`,
    /// bare) whose malformed-operand behavior fails closed (matches no candidate) rather than
    /// open: with no up-front validation, that would produce a misleading "no version satisfies
    /// requirement" diagnostic instead of flagging the requirement itself as invalid, so this
    /// returns `None` for it instead, matching the `is_valid_range`/`is_valid_requirement`
    /// precedent in Maven/Gradle/NuGet's `compile_requirement` (#332). The "could this
    /// requirement be satisfied by a version
    /// RubyGems hid" ambiguity is handled separately in
    /// [`Self::requirement_is_undecidable_given_available`], which sees `available` and can
    /// therefore decide it precisely instead of this method having to guess from
    /// `requirement` alone.
    fn compile_requirement(&self, requirement: &VersionReq) -> Option<Box<dyn RequirementMatcher>> {
        if self.requirement_is_unresolved(requirement) {
            return None;
        }
        compile_requirement_unless(
            requirement.as_str(),
            any_constraint_fails_closed_and_invalid,
            RubygemsMatcher,
        )
    }

    /// See `exact_pin_could_be_yanked` for the RubyGems-specific rationale and heuristic.
    fn requirement_is_undecidable_given_available(
        &self,
        requirement: &VersionReq,
        available: &[ConcreteVersion],
    ) -> bool {
        exact_pin_could_be_yanked(requirement.as_str(), available)
    }

    /// #1354: an unexpanded Ruby string-interpolation placeholder (`#{...}`) inside a
    /// requirement — see `requirement_contains_unresolved_interpolation`. Previously, only
    /// the fail-closed operator shapes (`~>`, `<`, `<=`, `=`, bare) happened to make
    /// `compile_requirement` undecidable for it; a fail-open operator (`>=`, `>`, `!=`)
    /// compiled to a matcher that accepted every candidate instead. This explicit predicate
    /// makes every operator shape decide identically, mirroring Maven/Gradle/NuGet's
    /// unresolved-variable precedent.
    fn requirement_is_unresolved(&self, requirement: &VersionReq) -> bool {
        requirement_contains_unresolved_interpolation(requirement.as_str())
    }

    /// #1370: Bundler has no separate "concrete but undecidable ref" case
    /// [`Self::requirement_is_unresolved`] would need to stay broader than this — an
    /// unresolved Ruby interpolation is the only unresolved shape Bundler has, so both
    /// predicates key off the same `requirement_contains_unresolved_interpolation` detector.
    fn requirement_is_placeholder(&self, requirement: &VersionReq) -> bool {
        requirement_contains_unresolved_interpolation(requirement.as_str())
    }
}

impl DiagnosticMessages for BundlerFormatter {}

impl DiagnosticPolicy for BundlerFormatter {}

impl SourcePolicy for BundlerFormatter {}

impl OsvNaming for BundlerFormatter {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_version() {
        let formatter = BundlerFormatter;
        assert_eq!(
            formatter.format_version_for_text_edit(&ConcreteVersion::new("7.0.8")),
            "7.0.8"
        );
        assert_eq!(
            formatter.format_version_for_text_edit(&ConcreteVersion::new("1.0.0")),
            "1.0.0"
        );
    }

    // #758: exact-value `EcosystemFormatter` conformance, replacing test_package_url,
    // test_validate_package_name_accepts_valid_names, test_validate_package_name_rejects_invalid_names,
    // test_pessimistic_operator, test_comparison_operators, and test_exact_match.
    deps_core::formatter_conformance! {
        mod bundler_formatter_conformance;
        build: BundlerFormatter;
        package_url: {
            "rails" => "https://rubygems.org/gems/rails",
            "nokogiri" => "https://rubygems.org/gems/nokogiri",
        };
        accepts: ["rails", "rspec-rails", "nokogiri", "activesupport.rb"];
        rejects: ["", "123", "rails util", "rails/util", "日本語"];
        version_roundtrip: [
            "7.0.8", "~> 7.0" => true,
            "7.0.0", "~> 7.0" => true,
            "7.9.9", "~> 7.0" => true,
            "8.0.0", "~> 7.0" => false,
            "6.9.9", "~> 7.0" => false,
            "1.0.5", "~> 1.0.5" => true,
            "1.0.9", "~> 1.0.5" => true,
            "1.1.0", "~> 1.0.5" => false,
            "1.0.4", "~> 1.0.5" => false,
            "1.5.0", ">= 1.1" => true,
            "1.1.0", ">= 1.1" => true,
            "1.0.0", ">= 1.1" => false,
            "2.0.0", "> 1.0" => true,
            "1.0.0", "> 1.0" => false,
            "1.0.0", "<= 1.0" => true,
            "1.1.0", "<= 1.0" => false,
            "0.9.0", "< 1.0" => true,
            "1.0.0", "< 1.0" => false,
            "1.0.0", "= 1.0.0" => true,
            "1.0.1", "= 1.0.0" => false,
            "1.0.1", "!= 1.0.0" => true,
            "1.0.0", "!= 1.0.0" => false
        ];
    }

    #[test]
    fn test_suppress_package_url() {
        let formatter = BundlerFormatter;
        assert!(!formatter.suppress_package_url(&deps_core::DependencySource::Registry));
        assert!(
            formatter.suppress_package_url(&deps_core::DependencySource::CustomRegistry {
                url: "https://gems.mycorp.com".into(),
            })
        );
        assert!(
            formatter.suppress_package_url(&deps_core::DependencySource::Git {
                url: "https://github.com/rails/rails".into(),
                rev: None,
            })
        );
    }

    #[test]
    fn test_default_normalize_is_identity() {
        let formatter = BundlerFormatter;
        assert_eq!(
            formatter.normalize_package_name(&PackageName::new("rails")),
            "rails"
        );
        assert_eq!(
            formatter.normalize_package_name(&PackageName::new("rspec-rails")),
            "rspec-rails"
        );
    }

    #[test]
    fn test_compile_requirement_satisfiable() {
        let formatter = BundlerFormatter;
        let matcher = formatter
            .compile_requirement(&VersionReq::new("~> 7.0"))
            .expect("Bundler requirement always compiles");
        assert_eq!(matcher.matches(&ConcreteVersion::new("7.0.8")), Some(true));
        assert_eq!(matcher.matches(&ConcreteVersion::new("8.0.0")), Some(false));
    }

    #[test]
    fn test_compile_requirement_bare_exact_pin_still_compiles() {
        let formatter = BundlerFormatter;
        let matcher = formatter
            .compile_requirement(&VersionReq::new("1.6.13"))
            .expect("Bundler requirement always compiles");
        assert_eq!(matcher.matches(&ConcreteVersion::new("1.6.13")), Some(true));
        assert_eq!(
            matcher.matches(&ConcreteVersion::new("1.6.14")),
            Some(false)
        );
    }

    #[test]
    fn test_compile_requirement_equals_prefix_pin_still_compiles() {
        let formatter = BundlerFormatter;
        assert!(
            formatter
                .compile_requirement(&VersionReq::new("= 1.6.13"))
                .is_some()
        );
    }

    #[test]
    fn test_compile_requirement_wildcard_still_compiles() {
        let formatter = BundlerFormatter;
        assert!(
            formatter
                .compile_requirement(&VersionReq::new("*"))
                .is_some()
        );
    }

    /// #332 regression: a syntactically malformed `~>` requirement must not compile into a
    /// matcher — that would compare `false` against every candidate version and trigger a
    /// misleading "no version satisfies requirement" diagnostic instead of one flagging the
    /// requirement itself as invalid.
    #[test]
    fn test_compile_requirement_malformed_pessimistic_suppressed() {
        let formatter = BundlerFormatter;
        assert!(
            formatter
                .compile_requirement(&VersionReq::new("~> abc"))
                .is_none()
        );
        assert!(
            formatter
                .compile_requirement(&VersionReq::new("~>"))
                .is_none()
        );
        assert!(
            formatter
                .compile_requirement(&VersionReq::new("~> "))
                .is_none()
        );
    }

    /// #332/S2 regression: `<`, `<=`, `=`, and a bare (no-operator) pin fail closed on a
    /// malformed operand identically to `~>` — confirmed live against RubyGems (critic
    /// finding S2), so the same suppression must apply to all four, not just `~>`.
    #[test]
    fn test_compile_requirement_malformed_other_fail_closed_operators_suppressed() {
        let formatter = BundlerFormatter;
        assert!(
            formatter
                .compile_requirement(&VersionReq::new("< abc"))
                .is_none()
        );
        assert!(
            formatter
                .compile_requirement(&VersionReq::new("<= abc"))
                .is_none()
        );
        assert!(
            formatter
                .compile_requirement(&VersionReq::new("= abc"))
                .is_none()
        );
        assert!(
            formatter
                .compile_requirement(&VersionReq::new("abc"))
                .is_none()
        );
    }

    /// #332/S2: `>`, `>=`, and `!=` fail *open* on a malformed operand (every candidate
    /// matches), which never triggers the unsatisfiable false positive #332 exists to
    /// prevent — so these must still compile, unlike the fail-closed operators above.
    #[test]
    fn test_compile_requirement_malformed_fail_open_operators_still_compile() {
        let formatter = BundlerFormatter;
        assert!(
            formatter
                .compile_requirement(&VersionReq::new("> abc"))
                .is_some()
        );
        assert!(
            formatter
                .compile_requirement(&VersionReq::new(">= abc"))
                .is_some()
        );
        assert!(
            formatter
                .compile_requirement(&VersionReq::new("!= abc"))
                .is_some()
        );
    }

    #[test]
    fn test_compile_requirement_range_forms_still_compile() {
        let formatter = BundlerFormatter;
        assert!(
            formatter
                .compile_requirement(&VersionReq::new(">= 1.1"))
                .is_some()
        );
        assert!(
            formatter
                .compile_requirement(&VersionReq::new("!= 1.0.0"))
                .is_some()
        );
    }

    #[test]
    fn test_exact_pin_version() {
        assert_eq!(exact_pin_version("1.6.13"), Some("1.6.13"));
        assert_eq!(exact_pin_version("= 1.6.13"), Some("1.6.13"));
        assert_eq!(exact_pin_version("*"), None);
        assert_eq!(exact_pin_version(""), None);
        assert_eq!(exact_pin_version("~> 7.0"), None);
        assert_eq!(exact_pin_version(">= 1.1"), None);
        assert_eq!(exact_pin_version("!= 1.0.0"), None);
    }

    /// #1366: a multi-constraint requirement is never a single exact pin, even when its first
    /// constraint has no operator prefix and would otherwise look like one.
    #[test]
    fn test_exact_pin_version_multi_constraint_not_a_pin() {
        assert_eq!(exact_pin_version("1.0.0, < 2.0"), None);
        assert_eq!(exact_pin_version("= 1.0.0, < 2.0"), None);
        assert_eq!(exact_pin_version(">= 1.0, < 2.0"), None);
    }

    /// #252 regression: rest-client's yanked `1.6.10`-`1.6.13` sit between the published
    /// `1.6.9` and `1.6.14`, so a pin on any of them must be suppressed rather than flagged
    /// unsatisfiable.
    #[test]
    fn test_exact_pin_could_be_yanked_interior_pin_suppressed() {
        let available = ["1.6.14".into(), "1.6.9".into()];
        assert!(exact_pin_could_be_yanked("1.6.13", &available));
        assert!(exact_pin_could_be_yanked("= 1.6.10", &available));
    }

    #[test]
    fn test_exact_pin_could_be_yanked_boundary_pin_suppressed() {
        let available = ["1.6.14".into(), "1.6.9".into()];
        assert!(exact_pin_could_be_yanked("1.6.9", &available));
        assert!(exact_pin_could_be_yanked("1.6.14", &available));
    }

    /// Live-verified counterexample (`puppetlabs-syntax`): every version below the current
    /// minimum can be yanked, not just interior ones — `6.0.0` and `7.2.0` were yanked,
    /// leaving `7.2.1` as the only published version, so a pin below that sole entry must
    /// still be suppressed rather than flagged unsatisfiable.
    #[test]
    fn test_exact_pin_could_be_yanked_below_minimum_pin_suppressed() {
        let available = ["7.2.1".into()];
        assert!(exact_pin_could_be_yanked("7.2.0", &available));
        assert!(exact_pin_could_be_yanked("6.0.0", &available));
    }

    /// A pin above the observed maximum is still flagged as unsatisfiable — accepting the rare,
    /// unmodelled risk of a yanked-newest-release false positive (see the doc comment above)
    /// in exchange for catching #252's motivating false negative (e.g. `gem "foo", "99.0.0"`
    /// when `foo` only publishes up to `2.0`).
    #[test]
    fn test_exact_pin_could_be_yanked_above_maximum_pin_not_suppressed() {
        let available = ["1.6.14".into(), "1.6.9".into()];
        assert!(!exact_pin_could_be_yanked("99.0.0", &available));
    }

    #[test]
    fn test_exact_pin_could_be_yanked_non_exact_pin_not_suppressed() {
        let available = ["1.6.14".into(), "1.6.9".into()];
        assert!(!exact_pin_could_be_yanked("~> 1.6", &available));
        assert!(!exact_pin_could_be_yanked("*", &available));
    }

    #[test]
    fn test_exact_pin_could_be_yanked_empty_available_not_suppressed() {
        assert!(!exact_pin_could_be_yanked("1.6.13", &[]));
    }

    /// #1366 impl-critic M2: a multi-constraint requirement combining a yanked-range exact
    /// pin with an unrelated second constraint (`gem "rest-client", "1.6.13", "< 2"`) must
    /// still suppress the yanked-pin false positive for its exact-pin half — before this fix,
    /// `exact_pin_version` rejected the whole comma-joined string outright (never a single
    /// pin), so the suppression this test pins never applied to a multi-constraint requirement
    /// at all, reintroducing #252's false positive whenever an exact pin was combined with a
    /// second bound.
    #[test]
    fn test_exact_pin_could_be_yanked_multi_constraint_exact_pin_suppressed() {
        let available = ["1.6.14".into(), "1.6.9".into()];
        assert!(exact_pin_could_be_yanked("1.6.13, < 2", &available));
        assert!(exact_pin_could_be_yanked("< 2, 1.6.13", &available));
    }

    /// A multi-constraint requirement whose exact-pin half is genuinely mistyped (above the
    /// observed maximum) must still be flagged — the per-constraint suppression must not
    /// blanket-suppress every multi-constraint requirement regardless of the pin's value.
    #[test]
    fn test_exact_pin_could_be_yanked_multi_constraint_mistyped_pin_not_suppressed() {
        let available = ["1.6.14".into(), "1.6.9".into()];
        assert!(!exact_pin_could_be_yanked("99.0.0, < 100", &available));
    }

    /// #1366 team-lead review: a multi-constraint requirement that is genuinely,
    /// unconditionally impossible (no version can ever satisfy both halves — e.g. a bad
    /// merge/typo) must not be suppressed just because its exact-pin half happens to sit below
    /// the observed maximum. `5.0.0` not exceeding a `6.5.0` max says nothing about whether
    /// `5.0.0` could ever satisfy the requirement's other half, `>= 6.0`.
    #[test]
    fn test_exact_pin_could_be_yanked_multi_constraint_contradictory_not_suppressed() {
        let available = ["6.5.0".into(), "6.0.0".into()];
        assert!(!exact_pin_could_be_yanked("5.0.0, >= 6.0", &available));
        assert!(!exact_pin_could_be_yanked(">= 6.0, 5.0.0", &available));
    }

    /// End-to-end companion to the unit test above, through the same
    /// `deps_core::lsp_helpers::requirement_is_unsatisfiable` entry point
    /// `test_requirement_is_unsatisfiable_mistyped_exact_pin_still_flagged` already exercises
    /// for the single-constraint case — pins that the diagnostic actually fires for the
    /// contradictory multi-constraint shape, not just that the internal heuristic returns the
    /// right boolean in isolation.
    #[test]
    fn test_requirement_is_unsatisfiable_multi_constraint_contradictory_still_flagged() {
        use deps_core::lsp_helpers::requirement_is_unsatisfiable;

        let formatter = BundlerFormatter;
        let available = vec!["6.5.0".into(), "6.0.0".into()];
        assert!(requirement_is_unsatisfiable(
            &formatter,
            &VersionReq::new("5.0.0, >= 6.0"),
            &available,
        ));
    }

    /// Boundary case the doc comment above [`exact_pin_could_be_yanked`] guarantees: a
    /// shorter pin like `1.6` zero-pads to `1.6.0` under the gate's numeric comparator and
    /// sorts below the observed maximum `1.6.14`, so it is suppressed here even though the
    /// actual string-based `RubygemsMatcher` would never treat `1.6` and `1.6.0` as equal.
    #[test]
    fn test_exact_pin_could_be_yanked_short_pin_numeric_boundary_suppressed() {
        let available = ["1.6.14".into(), "1.6.9".into()];
        assert!(exact_pin_could_be_yanked("1.6", &available));
    }

    /// End-to-end via the shared `deps-core` unsatisfiable check: a mistyped exact pin with
    /// nothing to do with yanked versions must still be flagged, even though the suppression
    /// exists — this is the false-negative #252 warns the blanket suppression caused.
    #[test]
    fn test_requirement_is_unsatisfiable_mistyped_exact_pin_still_flagged() {
        use deps_core::lsp_helpers::requirement_is_unsatisfiable;

        let formatter = BundlerFormatter;
        let available = vec!["2.0.0".into(), "1.0.0".into()];
        assert!(requirement_is_unsatisfiable(
            &formatter,
            &VersionReq::new("99.0.0"),
            &available,
        ));
    }

    /// End-to-end: a pin landing in the interior gap is suppressed, not flagged.
    #[test]
    fn test_requirement_is_unsatisfiable_yanked_gap_pin_suppressed() {
        use deps_core::lsp_helpers::requirement_is_unsatisfiable;

        let formatter = BundlerFormatter;
        let available = vec!["1.6.14".into(), "1.6.9".into()];
        assert!(!requirement_is_unsatisfiable(
            &formatter,
            &VersionReq::new("1.6.13"),
            &available,
        ));
    }

    /// End-to-end regression for the `puppetlabs-syntax` counterexample: a pin below the sole
    /// observed version must be suppressed, not flagged, since RubyGems can yank every version
    /// below the current minimum.
    #[test]
    fn test_requirement_is_unsatisfiable_below_minimum_pin_suppressed() {
        use deps_core::lsp_helpers::requirement_is_unsatisfiable;

        let formatter = BundlerFormatter;
        let available = vec!["7.2.1".into()];
        assert!(!requirement_is_unsatisfiable(
            &formatter,
            &VersionReq::new("7.2.0"),
            &available,
        ));
    }

    /// #402 critique M4: a name that fails both checks (no ASCII letter at all, and a
    /// character outside the charset) must report the charset violation, since that is the
    /// more specific and actionable diagnosis of the two.
    #[test]
    fn test_validate_package_name_prefers_charset_message_over_letter_message() {
        let formatter = BundlerFormatter;
        let err = formatter.validate_package_name("日本語").unwrap_err();
        assert!(err.reason().contains("must contain only ASCII"));
        assert!(!err.reason().contains("must include at least one letter"));
    }

    /// A name with valid charset but no letter (e.g. all digits) still reports the "must
    /// include at least one letter" message — unaffected by the M4 check-order swap.
    #[test]
    fn test_validate_package_name_rejects_all_digits_with_letter_message() {
        let formatter = BundlerFormatter;
        let err = formatter.validate_package_name("123").unwrap_err();
        assert!(err.reason().contains("letter"));
    }

    // --- #1354: unresolved Ruby interpolation (`#{...}`) must never be rewritten ---

    #[test]
    fn test_requirement_is_unresolved_ruby_interpolation() {
        let formatter = BundlerFormatter;
        assert!(formatter.requirement_is_unresolved(&VersionReq::new("~> #{RAILS_VERSION}")));
        assert!(formatter.requirement_is_unresolved(&VersionReq::new(">= #{RAILS_VERSION}")));
        assert!(!formatter.requirement_is_unresolved(&VersionReq::new("~> 7.0")));
    }

    /// #1354 critic S4: the shorthand interpolation forms (`#@ivar`, `#@@cvar`, `#$GVAR`) must
    /// be detected too, not just the general `#{...}` form — a `#{`-only check previously left
    /// `"~> #@v"` classified as an ordinary (resolvable) requirement.
    #[test]
    fn test_requirement_is_unresolved_ruby_shorthand_interpolation() {
        let formatter = BundlerFormatter;
        assert!(formatter.requirement_is_unresolved(&VersionReq::new("~> #@ivar")));
        assert!(formatter.requirement_is_unresolved(&VersionReq::new("~> #@@cvar")));
        assert!(formatter.requirement_is_unresolved(&VersionReq::new("~> #$GVAR")));
        assert!(formatter.requirement_is_unresolved(&VersionReq::new(">= #@ivar")));
        // A bare '#' not followed by {, @, or $ is not interpolation syntax.
        assert!(!formatter.requirement_is_unresolved(&VersionReq::new("~> 7.0 # comment")));
    }

    #[test]
    fn test_compile_requirement_none_for_unresolved_interpolation_any_operator() {
        let formatter = BundlerFormatter;
        // Previously only the fail-closed operators (~>, <, <=, =, bare) happened to be
        // undecidable; >= failed open and compiled to a matcher accepting every candidate.
        for requirement in [
            "~> #{V}", "< #{V}", "<= #{V}", "= #{V}", "#{V}", ">= #{V}", "> #{V}", "!= #{V}",
        ] {
            assert!(
                formatter
                    .compile_requirement(&VersionReq::new(requirement))
                    .is_none(),
                "expected {requirement:?} to be undecidable"
            );
        }
    }

    #[test]
    fn test_version_satisfies_requirement_unresolved_interpolation_returns_true() {
        let formatter = BundlerFormatter;
        assert!(
            formatter.version_satisfies_requirement(
                &ConcreteVersion::new("7.0.8"),
                "~> #{RAILS_VERSION}"
            )
        );
    }

    #[test]
    fn test_format_version_replacing_guards_unresolved_interpolation() {
        let formatter = BundlerFormatter;
        assert_eq!(
            formatter.format_version_replacing(&ConcreteVersion::new("9.9.9"), "~> #{V}"),
            "~> #{V}"
        );
        assert_eq!(
            formatter.format_version_replacing(&ConcreteVersion::new("9.9.9"), "~> 7.0"),
            "9.9.9"
        );
    }

    /// #1354 critic S4: the shorthand form must be guarded identically to `#{...}`.
    #[test]
    fn test_format_version_replacing_guards_ruby_shorthand_interpolation() {
        let formatter = BundlerFormatter;
        assert_eq!(
            formatter.format_version_replacing(&ConcreteVersion::new("9.9.9"), "~> #@v"),
            "~> #@v"
        );
        assert_eq!(
            formatter.format_version_replacing(&ConcreteVersion::new("0.0.1"), "~> #$GVAR"),
            "~> #$GVAR"
        );
    }

    /// #1354 security audit: exercises `deps_core::edit::plan_vulnerability_fix` with the
    /// *real* `BundlerFormatter` (not a hand-rolled mock) and a `BundlerDependency` obtained
    /// from the real `crate::parser::parse_gemfile` path, on a vulnerable gem whose declared
    /// requirement is an unexpanded Ruby interpolation — mirrors `deps-nuget`'s
    /// `test_plan_vulnerability_fix_with_real_formatter_and_parsed_dependency` (#1352).
    ///
    /// Unlike NuGet, Bundler's own parser does *not* degrade `#{...}` to
    /// `version_requirement: None` — this scenario is reachable through the real
    /// `generate_code_actions`/`deps-cli` call graph, not defense-in-depth only.
    #[test]
    fn test_plan_vulnerability_fix_unresolved_interpolation_is_not_rewritten() {
        use deps_core::ParseResult;
        use deps_core::edit::plan_vulnerability_fix;
        use deps_core::osv::{
            Advisory, Capped, DependencyVulnerabilities, UpgradeStatus, VulnSeverity,
        };

        let gemfile = r#"gem "rails", "~> #{RAILS_VERSION}""#;
        let uri = deps_core::test_util::test_uri("/test/Gemfile");
        let result = crate::parser::parse_gemfile(gemfile, &uri).expect("valid gemfile");
        let deps = result.dependencies();
        let dep = deps.first().expect("one dependency parsed");
        let current = dep
            .version_requirement()
            .expect("parser preserves the raw interpolated requirement text")
            .as_str();
        assert_eq!(current, "~> #{RAILS_VERSION}");

        let advisory = std::sync::Arc::new(
            Advisory::new(
                "GHSA-test-0002".to_string(),
                "2024-01-01T00:00:00Z".to_string(),
                VulnSeverity::High,
            )
            .expect("valid osv id")
            .with_fixed_versions(vec!["7.0.8".to_string()]),
        );
        let dv = DependencyVulnerabilities::new(Capped::new(vec![advisory], 1))
            .with_fix_target_status(UpgradeStatus::CandidateClean {
                version: "7.0.8".to_string(),
            });

        let planned = plan_vulnerability_fix(
            *dep,
            deps_core::position::Range::default(),
            current,
            &dv,
            &BundlerFormatter,
        );

        // #1370: `plan_verified_fix`'s central placeholder gate
        // (`BundlerFormatter::requirement_is_placeholder`) fires first now. Before that gate
        // existed: `compile_requirement` is `None` here (undecidable), so
        // `requirement_already_resolves_to`'s default gate never short-circuited —
        // `format_version_replacing`'s own `#{`-guard, echoing `current` back unchanged, made
        // the planner's textual no-op check fire instead (`NoOpRewrite`), and still does, as
        // defense-in-depth.
        assert_eq!(
            planned,
            Err(deps_core::edit::VulnFixSkip::UnresolvedPlaceholder),
            "the real BundlerFormatter must suppress the fix for an unresolved interpolation, \
             got {planned:?}"
        );
    }

    // --- #1366: multi-constraint requirements must round-trip or safely no-op ---

    /// A multi-constraint requirement with no unresolved interpolation is a normal
    /// vulnerability-fix target — the whole comma-joined requirement collapses to a single new
    /// version literal, and applying the resulting edit to the original text must leave a
    /// syntactically valid, single-argument `gem` call behind (not a stray second literal).
    #[test]
    fn test_plan_vulnerability_fix_multi_constraint_collapses_to_single_pin() {
        use deps_core::ParseResult;
        use deps_core::edit::plan_vulnerability_fix;
        use deps_core::osv::{
            Advisory, Capped, DependencyVulnerabilities, UpgradeStatus, VulnSeverity,
        };

        let gemfile = "gem \"rails\", \">= 5.0\", \"< 6.0\"";
        let uri = deps_core::test_util::test_uri("/test/Gemfile");
        let result = crate::parser::parse_gemfile(gemfile, &uri).expect("valid gemfile");
        let deps = result.dependencies();
        let dep = deps.first().expect("one dependency parsed");
        let current = dep
            .version_requirement()
            .expect("multi-constraint requirement preserved")
            .as_str();
        assert_eq!(current, ">= 5.0, < 6.0");
        let version_range = dep.version_range().expect("multi-constraint has a range");

        let advisory = std::sync::Arc::new(
            Advisory::new(
                "GHSA-test-0003".to_string(),
                "2024-01-01T00:00:00Z".to_string(),
                VulnSeverity::High,
            )
            .expect("valid osv id")
            .with_fixed_versions(vec!["6.1.0".to_string()]),
        );
        let dv = DependencyVulnerabilities::new(Capped::new(vec![advisory], 1))
            .with_fix_target_status(UpgradeStatus::CandidateClean {
                version: "6.1.0".to_string(),
            });

        let planned = plan_vulnerability_fix(*dep, version_range, current, &dv, &BundlerFormatter)
            .expect("a non-interpolated multi-constraint requirement must be rewritable");

        assert_eq!(planned.edit.new_text, "6.1.0");

        let start = usize::try_from(planned.edit.range.start.character).unwrap();
        let end = usize::try_from(planned.edit.range.end.character).unwrap();
        let mut rewritten = gemfile.to_string();
        rewritten.replace_range(start..end, &planned.edit.new_text);
        assert_eq!(rewritten, "gem \"rails\", \"6.1.0\"");
    }

    /// #1366: a later constraint's unresolved interpolation must suppress the rewrite for the
    /// *whole* multi-constraint requirement, not just leave the first constraint alone — mirrors
    /// `test_plan_vulnerability_fix_unresolved_interpolation_is_not_rewritten` above, but
    /// with the interpolation in the second constraint rather than the only one.
    #[test]
    fn test_plan_vulnerability_fix_multi_constraint_later_unresolved_interpolation_is_not_rewritten()
     {
        use deps_core::ParseResult;
        use deps_core::edit::plan_vulnerability_fix;
        use deps_core::osv::{
            Advisory, Capped, DependencyVulnerabilities, UpgradeStatus, VulnSeverity,
        };

        let gemfile = "gem \"rails\", \"~> 1.0\", \"< #{RAILS_MAX}\"";
        let uri = deps_core::test_util::test_uri("/test/Gemfile");
        let result = crate::parser::parse_gemfile(gemfile, &uri).expect("valid gemfile");
        let deps = result.dependencies();
        let dep = deps.first().expect("one dependency parsed");
        let current = dep
            .version_requirement()
            .expect("multi-constraint requirement preserved, interpolation included")
            .as_str();
        assert_eq!(current, "~> 1.0, < #{RAILS_MAX}");

        let advisory = std::sync::Arc::new(
            Advisory::new(
                "GHSA-test-0004".to_string(),
                "2024-01-01T00:00:00Z".to_string(),
                VulnSeverity::High,
            )
            .expect("valid osv id")
            .with_fixed_versions(vec!["7.0.8".to_string()]),
        );
        let dv = DependencyVulnerabilities::new(Capped::new(vec![advisory], 1))
            .with_fix_target_status(UpgradeStatus::CandidateClean {
                version: "7.0.8".to_string(),
            });

        let planned = plan_vulnerability_fix(
            *dep,
            deps_core::position::Range::default(),
            current,
            &dv,
            &BundlerFormatter,
        );

        assert_eq!(
            planned,
            Err(deps_core::edit::VulnFixSkip::UnresolvedPlaceholder),
            "an unresolved interpolation in ANY constraint must suppress the whole \
             multi-constraint rewrite, got {planned:?}"
        );
    }

    /// #1366: `compile_requirement` must reject a multi-constraint requirement when *any* of its
    /// constraints has an invalid operand for a fail-closed operator, not just the first.
    #[test]
    fn test_compile_requirement_multi_constraint_invalid_later_constraint_suppressed() {
        let formatter = BundlerFormatter;
        assert!(
            formatter
                .compile_requirement(&VersionReq::new(">= 1.0, < abc"))
                .is_none()
        );
        assert!(
            formatter
                .compile_requirement(&VersionReq::new(">= 1.0, < 2.0"))
                .is_some()
        );
    }
}
