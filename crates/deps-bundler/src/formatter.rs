//! Version formatting for Bundler ecosystem.

use crate::version::{compare_versions, is_valid_rubygems_version, version_matches_requirement};
use deps_core::ConcreteVersion;
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

/// A Bundler requirement written as `= X` or bare `X` (no operator) pins a single exact
/// version. Returns the pinned version string, or `None` when `requirement` is a wildcard,
/// empty, or a range/comparison operator (`~>`, `>=`, `>`, `<=`, `<`, `!=`) rather than a pin.
fn exact_pin_version(requirement: &str) -> Option<&str> {
    let req = requirement.trim();
    if req.is_empty() || req == "*" {
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
fn exact_pin_could_be_yanked(requirement: &str, available: &[ConcreteVersion]) -> bool {
    let Some(pin) = exact_pin_version(requirement) else {
        return false;
    };
    let Some(max) = available
        .iter()
        .max_by(|a, b| compare_versions(a.as_str(), b.as_str()))
    else {
        return false;
    };
    !compare_versions(pin, max.as_str()).is_gt()
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
}

impl RequirementResolution for BundlerFormatter {
    fn version_satisfies_requirement(&self, version: &ConcreteVersion, requirement: &str) -> bool {
        let version = version.as_str();
        version_matches_requirement(version, requirement)
    }

    /// Compiles `requirement` into a `RubygemsMatcher` using the same
    /// `version_matches_requirement` comparator as `version_satisfies_requirement` — Bundler
    /// requirements have no separate "loose" vs. "precise" form to distinguish, and
    /// `version_matches_requirement` never fails to parse, so this always decides (`Some`),
    /// except when `fail_closed_operand` identifies `requirement` as one of the operator
    /// shapes (`~>`, `<`, `<=`, `=`, bare) whose malformed-operand behavior fails closed
    /// (matches no candidate) rather than open: with no up-front validation, that would
    /// produce a misleading "no version satisfies requirement" diagnostic instead of
    /// flagging the requirement itself as invalid, so this returns `None` for it instead,
    /// matching the `is_valid_range`/`is_valid_requirement` precedent in Maven/Gradle/NuGet's
    /// `compile_requirement` (#332). The "could this requirement be satisfied by a version
    /// RubyGems hid" ambiguity is handled separately in
    /// [`Self::requirement_is_undecidable_given_available`], which sees `available` and can
    /// therefore decide it precisely instead of this method having to guess from
    /// `requirement` alone.
    fn compile_requirement(&self, requirement: &VersionReq) -> Option<Box<dyn RequirementMatcher>> {
        compile_requirement_unless(
            requirement.as_str(),
            |r| fail_closed_operand(r).is_some_and(|operand| !is_valid_rubygems_version(operand)),
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

    #[test]
    fn test_package_url() {
        let formatter = BundlerFormatter;
        assert_eq!(
            formatter.package_url(&PackageName::new("rails")),
            "https://rubygems.org/gems/rails"
        );
        assert_eq!(
            formatter.package_url(&PackageName::new("nokogiri")),
            "https://rubygems.org/gems/nokogiri"
        );
    }

    #[test]
    fn test_pessimistic_operator() {
        let formatter = BundlerFormatter;

        // ~> 7.0 means >= 7.0, < 8.0
        assert!(formatter.version_satisfies_requirement(&ConcreteVersion::new("7.0.8"), "~> 7.0"));
        assert!(formatter.version_satisfies_requirement(&ConcreteVersion::new("7.0.0"), "~> 7.0"));
        assert!(formatter.version_satisfies_requirement(&ConcreteVersion::new("7.9.9"), "~> 7.0"));
        assert!(!formatter.version_satisfies_requirement(&ConcreteVersion::new("8.0.0"), "~> 7.0"));
        assert!(!formatter.version_satisfies_requirement(&ConcreteVersion::new("6.9.9"), "~> 7.0"));

        // ~> 1.0.5 means >= 1.0.5, < 1.1.0
        assert!(
            formatter.version_satisfies_requirement(&ConcreteVersion::new("1.0.5"), "~> 1.0.5")
        );
        assert!(
            formatter.version_satisfies_requirement(&ConcreteVersion::new("1.0.9"), "~> 1.0.5")
        );
        assert!(
            !formatter.version_satisfies_requirement(&ConcreteVersion::new("1.1.0"), "~> 1.0.5")
        );
        assert!(
            !formatter.version_satisfies_requirement(&ConcreteVersion::new("1.0.4"), "~> 1.0.5")
        );
    }

    #[test]
    fn test_comparison_operators() {
        let formatter = BundlerFormatter;

        // >= operator
        assert!(formatter.version_satisfies_requirement(&ConcreteVersion::new("1.5.0"), ">= 1.1"));
        assert!(formatter.version_satisfies_requirement(&ConcreteVersion::new("1.1.0"), ">= 1.1"));
        assert!(!formatter.version_satisfies_requirement(&ConcreteVersion::new("1.0.0"), ">= 1.1"));

        // > operator
        assert!(formatter.version_satisfies_requirement(&ConcreteVersion::new("2.0.0"), "> 1.0"));
        assert!(!formatter.version_satisfies_requirement(&ConcreteVersion::new("1.0.0"), "> 1.0"));

        // <= operator
        assert!(formatter.version_satisfies_requirement(&ConcreteVersion::new("1.0.0"), "<= 1.0"));
        assert!(!formatter.version_satisfies_requirement(&ConcreteVersion::new("1.1.0"), "<= 1.0"));

        // < operator
        assert!(formatter.version_satisfies_requirement(&ConcreteVersion::new("0.9.0"), "< 1.0"));
        assert!(!formatter.version_satisfies_requirement(&ConcreteVersion::new("1.0.0"), "< 1.0"));
    }

    #[test]
    fn test_exact_match() {
        let formatter = BundlerFormatter;

        assert!(formatter.version_satisfies_requirement(&ConcreteVersion::new("1.0.0"), "= 1.0.0"));
        assert!(
            !formatter.version_satisfies_requirement(&ConcreteVersion::new("1.0.1"), "= 1.0.0")
        );

        assert!(
            formatter.version_satisfies_requirement(&ConcreteVersion::new("1.0.1"), "!= 1.0.0")
        );
        assert!(
            !formatter.version_satisfies_requirement(&ConcreteVersion::new("1.0.0"), "!= 1.0.0")
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

    #[test]
    fn test_validate_package_name_accepts_valid_names() {
        let formatter = BundlerFormatter;
        for name in ["rails", "rspec-rails", "nokogiri", "activesupport.rb"] {
            assert!(
                formatter.validate_package_name(name).is_ok(),
                "expected {name:?} to be accepted"
            );
        }
    }

    /// #402: a structurally invalid gem name must be reported as an invalid package name, not
    /// forwarded to the registry lookup that produces the misleading generic diagnostic.
    #[test]
    fn test_validate_package_name_rejects_invalid_names() {
        let formatter = BundlerFormatter;
        for name in ["", "123", "rails util", "rails/util", "日本語"] {
            assert!(
                formatter.validate_package_name(name).is_err(),
                "expected {name:?} to be rejected"
            );
        }
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
}
