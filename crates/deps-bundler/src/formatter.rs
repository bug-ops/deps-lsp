//! Version formatting for Bundler ecosystem.

use crate::version::{compare_versions, version_matches_requirement};
use deps_core::PackageName;
use deps_core::VersionReq;
use deps_core::lsp_helpers::{EcosystemFormatter, RequirementMatcher};

/// Rubygems requirement matcher, compiled once per dependency by
/// [`BundlerFormatter::compile_requirement`]. `version_matches_requirement` is a hand-rolled
/// comparator with no external parser to fail on, so this always decides (`Some`).
struct RubygemsMatcher(String);

impl RequirementMatcher for RubygemsMatcher {
    fn matches(&self, version: &str) -> Option<bool> {
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
/// Note on the boundary case (pin equal to the maximum): this gate compares numerically via
/// [`compare_versions`], which zero-pads missing components, while the actual scan in
/// [`RubygemsMatcher`] compares by string equality/prefix (see `version_matches_requirement`).
/// The two can disagree at the boundary — a pin of `"1.6"` vs. a published `"1.6.0"` compares
/// `Equal` here (numeric zero-padding) but would not string-match there. (A prerelease-tagged
/// pin like `"2.0.0.rc1"` against a published `"2.0.0"` no longer reaches this path:
/// `compare_versions` correctly orders it below the stable release instead of tying, since
/// #323's fix.) That disagreement only ever makes this gate suppress a diagnostic the string
/// matcher would otherwise have flagged — over-suppression, the safe direction — never the
/// reverse.
fn exact_pin_could_be_yanked(requirement: &str, available: &[String]) -> bool {
    let Some(pin) = exact_pin_version(requirement) else {
        return false;
    };
    let Some(max) = available.iter().max_by(|a, b| compare_versions(a, b)) else {
        return false;
    };
    !compare_versions(pin, max).is_gt()
}

/// Formatter for Bundler/Ruby gem versions.
pub struct BundlerFormatter;

impl EcosystemFormatter for BundlerFormatter {
    fn format_version_for_text_edit(&self, version: &str) -> String {
        version.to_string()
    }

    fn package_url(&self, name: &PackageName) -> String {
        crate::registry::gem_url(name.as_str())
    }

    fn version_satisfies_requirement(&self, version: &str, requirement: &str) -> bool {
        version_matches_requirement(version, requirement)
    }

    /// Compiles `requirement` into a `RubygemsMatcher` using the same
    /// `version_matches_requirement` comparator as `version_satisfies_requirement` — Bundler
    /// requirements have no separate "loose" vs. "precise" form to distinguish, and
    /// `version_matches_requirement` never fails to parse, so this always decides (`Some`).
    /// The "could this requirement be satisfied by a version RubyGems hid" ambiguity is
    /// handled separately in [`Self::requirement_is_undecidable_given_available`], which sees
    /// `available` and can therefore decide it precisely instead of this method having to
    /// guess from `requirement` alone.
    fn compile_requirement(&self, requirement: &VersionReq) -> Option<Box<dyn RequirementMatcher>> {
        Some(Box::new(RubygemsMatcher(requirement.as_str().to_string())))
    }

    /// See `exact_pin_could_be_yanked` for the RubyGems-specific rationale and heuristic.
    fn requirement_is_undecidable_given_available(
        &self,
        requirement: &VersionReq,
        available: &[String],
    ) -> bool {
        exact_pin_could_be_yanked(requirement.as_str(), available)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_version() {
        let formatter = BundlerFormatter;
        assert_eq!(formatter.format_version_for_text_edit("7.0.8"), "7.0.8");
        assert_eq!(formatter.format_version_for_text_edit("1.0.0"), "1.0.0");
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
        assert!(formatter.version_satisfies_requirement("7.0.8", "~> 7.0"));
        assert!(formatter.version_satisfies_requirement("7.0.0", "~> 7.0"));
        assert!(formatter.version_satisfies_requirement("7.9.9", "~> 7.0"));
        assert!(!formatter.version_satisfies_requirement("8.0.0", "~> 7.0"));
        assert!(!formatter.version_satisfies_requirement("6.9.9", "~> 7.0"));

        // ~> 1.0.5 means >= 1.0.5, < 1.1.0
        assert!(formatter.version_satisfies_requirement("1.0.5", "~> 1.0.5"));
        assert!(formatter.version_satisfies_requirement("1.0.9", "~> 1.0.5"));
        assert!(!formatter.version_satisfies_requirement("1.1.0", "~> 1.0.5"));
        assert!(!formatter.version_satisfies_requirement("1.0.4", "~> 1.0.5"));
    }

    #[test]
    fn test_comparison_operators() {
        let formatter = BundlerFormatter;

        // >= operator
        assert!(formatter.version_satisfies_requirement("1.5.0", ">= 1.1"));
        assert!(formatter.version_satisfies_requirement("1.1.0", ">= 1.1"));
        assert!(!formatter.version_satisfies_requirement("1.0.0", ">= 1.1"));

        // > operator
        assert!(formatter.version_satisfies_requirement("2.0.0", "> 1.0"));
        assert!(!formatter.version_satisfies_requirement("1.0.0", "> 1.0"));

        // <= operator
        assert!(formatter.version_satisfies_requirement("1.0.0", "<= 1.0"));
        assert!(!formatter.version_satisfies_requirement("1.1.0", "<= 1.0"));

        // < operator
        assert!(formatter.version_satisfies_requirement("0.9.0", "< 1.0"));
        assert!(!formatter.version_satisfies_requirement("1.0.0", "< 1.0"));
    }

    #[test]
    fn test_exact_match() {
        let formatter = BundlerFormatter;

        assert!(formatter.version_satisfies_requirement("1.0.0", "= 1.0.0"));
        assert!(!formatter.version_satisfies_requirement("1.0.1", "= 1.0.0"));

        assert!(formatter.version_satisfies_requirement("1.0.1", "!= 1.0.0"));
        assert!(!formatter.version_satisfies_requirement("1.0.0", "!= 1.0.0"));
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
        assert_eq!(matcher.matches("7.0.8"), Some(true));
        assert_eq!(matcher.matches("8.0.0"), Some(false));
    }

    #[test]
    fn test_compile_requirement_bare_exact_pin_still_compiles() {
        let formatter = BundlerFormatter;
        let matcher = formatter
            .compile_requirement(&VersionReq::new("1.6.13"))
            .expect("Bundler requirement always compiles");
        assert_eq!(matcher.matches("1.6.13"), Some(true));
        assert_eq!(matcher.matches("1.6.14"), Some(false));
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
        let available = ["1.6.14".to_string(), "1.6.9".to_string()];
        assert!(exact_pin_could_be_yanked("1.6.13", &available));
        assert!(exact_pin_could_be_yanked("= 1.6.10", &available));
    }

    #[test]
    fn test_exact_pin_could_be_yanked_boundary_pin_suppressed() {
        let available = ["1.6.14".to_string(), "1.6.9".to_string()];
        assert!(exact_pin_could_be_yanked("1.6.9", &available));
        assert!(exact_pin_could_be_yanked("1.6.14", &available));
    }

    /// Live-verified counterexample (`puppetlabs-syntax`): every version below the current
    /// minimum can be yanked, not just interior ones — `6.0.0` and `7.2.0` were yanked,
    /// leaving `7.2.1` as the only published version, so a pin below that sole entry must
    /// still be suppressed rather than flagged unsatisfiable.
    #[test]
    fn test_exact_pin_could_be_yanked_below_minimum_pin_suppressed() {
        let available = ["7.2.1".to_string()];
        assert!(exact_pin_could_be_yanked("7.2.0", &available));
        assert!(exact_pin_could_be_yanked("6.0.0", &available));
    }

    /// A pin above the observed maximum is still flagged as unsatisfiable — accepting the rare,
    /// unmodelled risk of a yanked-newest-release false positive (see the doc comment above)
    /// in exchange for catching #252's motivating false negative (e.g. `gem "foo", "99.0.0"`
    /// when `foo` only publishes up to `2.0`).
    #[test]
    fn test_exact_pin_could_be_yanked_above_maximum_pin_not_suppressed() {
        let available = ["1.6.14".to_string(), "1.6.9".to_string()];
        assert!(!exact_pin_could_be_yanked("99.0.0", &available));
    }

    #[test]
    fn test_exact_pin_could_be_yanked_non_exact_pin_not_suppressed() {
        let available = ["1.6.14".to_string(), "1.6.9".to_string()];
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
        let available = ["1.6.14".to_string(), "1.6.9".to_string()];
        assert!(exact_pin_could_be_yanked("1.6", &available));
    }

    /// End-to-end via the shared `deps-core` unsatisfiable check: a mistyped exact pin with
    /// nothing to do with yanked versions must still be flagged, even though the suppression
    /// exists — this is the false-negative #252 warns the blanket suppression caused.
    #[test]
    fn test_requirement_is_unsatisfiable_mistyped_exact_pin_still_flagged() {
        use deps_core::lsp_helpers::requirement_is_unsatisfiable;

        let formatter = BundlerFormatter;
        let available = vec!["2.0.0".to_string(), "1.0.0".to_string()];
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
        let available = vec!["1.6.14".to_string(), "1.6.9".to_string()];
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
        let available = vec!["7.2.1".to_string()];
        assert!(!requirement_is_unsatisfiable(
            &formatter,
            &VersionReq::new("7.2.0"),
            &available,
        ));
    }
}
