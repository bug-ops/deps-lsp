use deps_core::VersionReq;
use deps_core::lsp_helpers::{EcosystemFormatter, RequirementMatcher, compile_requirement_unless};
use deps_core::{Dependency, PackageName};

use crate::types::{GoDependency, GoDirective};

/// Exact/pseudo-version comparison shared by `version_satisfies_requirement` and
/// [`GoFormatter::compile_requirement`]'s matcher — Go module requirements are exact pins
/// or MVS-selected versions, not ranges, so both call sites need identical semantics:
///
/// 1. Exact match: v1.2.3 == v1.2.3
/// 2. Prefix match for pseudo-versions: v0.0.0-20191109021931-daa7c04131f5 starts with v0.0.0
/// 3. Prefix match for +incompatible: v2.0.0+incompatible starts with v2.0.0
fn go_version_matches(version: &str, requirement: &str) -> bool {
    if version == requirement {
        return true;
    }

    // Handle pseudo-versions and +incompatible suffix
    // Check if version starts with requirement followed by a dot, hyphen, plus, or end
    // This prevents false positives like v1.2.30 matching v1.2.3
    if let Some(suffix) = version.strip_prefix(requirement) {
        return suffix.is_empty()
            || suffix.starts_with('.')
            || suffix.starts_with('-')
            || suffix.starts_with('+');
    }

    false
}

/// Exact/pseudo-version matcher, compiled once per dependency by
/// [`GoFormatter::compile_requirement`]. Always decidable (`Some`) — Go module version
/// strings need no external parser, just [`go_version_matches`]'s string comparison — so
/// this never skips a candidate the way ecosystems with a real version parser can.
struct ExactMatcher(String);

impl RequirementMatcher for ExactMatcher {
    fn matches(&self, version: &str) -> Option<bool> {
        Some(go_version_matches(version, &self.0))
    }
}

/// Formatter for Go module version strings and package URLs.
///
/// Handles Go-specific version formatting:
/// - Versions are unquoted in go.mod (v1.2.3)
/// - Pseudo-versions (v0.0.0-20191109021931-daa7c04131f5)
/// - +incompatible suffix for v2+ modules without /v2 path
pub struct GoFormatter;

impl EcosystemFormatter for GoFormatter {
    fn format_version_for_text_edit(&self, version: &str) -> String {
        // Go versions in go.mod are unquoted: v1.2.3
        // Return version as-is since it should already have "v" prefix from registry
        version.to_string()
    }

    fn package_url(&self, name: &PackageName) -> String {
        crate::registry::package_url(name.as_str())
    }

    fn version_satisfies_requirement(&self, version: &str, requirement: &str) -> bool {
        go_version_matches(version, requirement)
    }

    /// Compiles `requirement` into an `ExactMatcher` using the same exact/pseudo-version
    /// comparison `version_satisfies_requirement` uses — Go's requirement syntax has no
    /// separate "loose" vs. "precise" distinction, so both share `go_version_matches`. Uses
    /// [`compile_requirement_unless`] (see that function and
    /// [`EcosystemFormatter::compile_requirement`] for the shared "undecidable" contract).
    ///
    /// The undecidable predicate is `crate::version::is_pseudo_version`:
    /// `proxy.golang.org/<mod>/@v/list` — the source of `available` — never lists
    /// pseudo-versions (they're derived per-commit, not enumerable), so a pseudo-version pin
    /// can never be found in `available` even when the exact commit it names is real. A
    /// `+incompatible`-suffixed *tag* (not a pseudo-version) is a real entry `/@v/list` does
    /// return, so it needs no such guard.
    fn compile_requirement(&self, requirement: &VersionReq) -> Option<Box<dyn RequirementMatcher>> {
        compile_requirement_unless(
            requirement.as_str(),
            crate::version::is_pseudo_version,
            ExactMatcher,
        )
    }

    fn osv_version_to_native(&self, version: &str) -> String {
        // OSV's `fixed` events for Go are plain semver (`0.3.7`), never
        // carrying the `v` prefix Go module versions require in go.mod.
        if version.starts_with('v') {
            version.to_string()
        } else {
            format!("v{version}")
        }
    }

    fn osv_version(&self, version: &str) -> String {
        // Go module versions always carry a mandatory "v" prefix
        // (golang.org/x/mod/module convention), but OSV.dev's SEMVER range
        // matching forbids it — strip it before sending on the wire.
        version.strip_prefix('v').unwrap_or(version).to_string()
    }

    fn manifest_requirement_is_resolved_version(&self, dep: &dyn Dependency) -> bool {
        // go.mod's `require` line is already the module version selected by
        // Go's MVS, never a range — unlike Cargo/npm. go.sum, by contrast,
        // only ever gets appended to (`go get`/`go build`; only
        // `go mod tidy` prunes it), so a stale higher version left over from
        // a downgrade can still be recorded there and win naive
        // last-occurrence-wins parsing (#235).
        //
        // Restricted to `GoDirective::Require`: `exclude`/`replace`
        // directives are also surfaced as dependencies, but their
        // `version_requirement()` is not an in-use version (the excluded
        // version, or the replaced-from version) — treating those as
        // resolved would fabricate a "current version" claim for a
        // dependency that isn't actually pinned there (#235 review).
        dep.as_any()
            .downcast_ref::<GoDependency>()
            .is_some_and(|go_dep| go_dep.directive == GoDirective::Require)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tower_lsp_server::ls_types::{Position, Range};

    fn go_dep(directive: GoDirective, version: &str) -> GoDependency {
        GoDependency {
            module_path: PackageName::new("github.com/gorilla/mux"),
            module_path_range: Range::new(Position::new(0, 0), Position::new(0, 1)),
            version: Some(deps_core::VersionReq::new(version)),
            version_range: Some(Range::new(Position::new(0, 0), Position::new(0, 1))),
            directive,
            indirect: false,
        }
    }

    /// Regression test for critique M1 (`.local/handoff/2026-08-23T20-55-32-critic.md`):
    /// a `require` directive's version is the exact MVS-selected version (#235), but
    /// `exclude`/`replace` directives are also surfaced as dependencies whose
    /// `version_requirement()` is not an in-use version (the excluded version, or the
    /// replaced-from version) — those must not be reported as resolved.
    #[test]
    fn test_manifest_requirement_is_resolved_version_only_for_require_directive() {
        let formatter = GoFormatter;

        let require_dep = go_dep(GoDirective::Require, "v1.8.0");
        assert!(formatter.manifest_requirement_is_resolved_version(&require_dep));

        let exclude_dep = go_dep(GoDirective::Exclude, "v0.1.0");
        assert!(!formatter.manifest_requirement_is_resolved_version(&exclude_dep));

        let replace_dep = go_dep(GoDirective::Replace, "v1.0.0");
        assert!(!formatter.manifest_requirement_is_resolved_version(&replace_dep));

        let retract_dep = go_dep(GoDirective::Retract, "v1.0.0");
        assert!(!formatter.manifest_requirement_is_resolved_version(&retract_dep));
    }

    #[test]
    fn test_format_version_for_text_edit() {
        let formatter = GoFormatter;

        // Standard semantic version
        assert_eq!(formatter.format_version_for_text_edit("v1.2.3"), "v1.2.3");

        // Pseudo-version
        assert_eq!(
            formatter.format_version_for_text_edit("v0.0.0-20191109021931-daa7c04131f5"),
            "v0.0.0-20191109021931-daa7c04131f5"
        );

        // Version with +incompatible
        assert_eq!(
            formatter.format_version_for_text_edit("v2.0.0+incompatible"),
            "v2.0.0+incompatible"
        );
    }

    #[test]
    fn test_package_url() {
        let formatter = GoFormatter;

        // Standard package
        assert_eq!(
            formatter.package_url(&PackageName::new("github.com/gin-gonic/gin")),
            "https://pkg.go.dev/github.com/gin-gonic/gin"
        );

        // Package with version path
        assert_eq!(
            formatter.package_url(&PackageName::new("github.com/go-redis/redis/v8")),
            "https://pkg.go.dev/github.com/go-redis/redis/v8"
        );

        // Standard library package
        assert_eq!(
            formatter.package_url(&PackageName::new("fmt")),
            "https://pkg.go.dev/fmt"
        );

        // Package with @ character (should be URL encoded)
        assert_eq!(
            formatter.package_url(&PackageName::new("github.com/user@org/package")),
            "https://pkg.go.dev/github.com/user%40org/package"
        );

        // Package with space (should be URL encoded)
        assert_eq!(
            formatter.package_url(&PackageName::new("github.com/user/pkg name")),
            "https://pkg.go.dev/github.com/user/pkg%20name"
        );
    }

    #[test]
    fn test_version_satisfies_requirement_exact_match() {
        let formatter = GoFormatter;

        // Exact version match
        assert!(formatter.version_satisfies_requirement("v1.2.3", "v1.2.3"));
        assert!(formatter.version_satisfies_requirement("v0.1.0", "v0.1.0"));
    }

    #[test]
    fn test_version_satisfies_requirement_pseudo_version() {
        let formatter = GoFormatter;

        // Pseudo-version prefix match
        assert!(
            formatter.version_satisfies_requirement("v0.0.0-20191109021931-daa7c04131f5", "v0.0.0")
        );

        // Full pseudo-version match
        assert!(formatter.version_satisfies_requirement(
            "v0.0.0-20191109021931-daa7c04131f5",
            "v0.0.0-20191109021931-daa7c04131f5"
        ));
    }

    #[test]
    fn test_version_satisfies_requirement_incompatible() {
        let formatter = GoFormatter;

        // +incompatible suffix handling
        assert!(formatter.version_satisfies_requirement("v2.0.0+incompatible", "v2.0.0"));

        // Exact match with +incompatible
        assert!(
            formatter.version_satisfies_requirement("v2.0.0+incompatible", "v2.0.0+incompatible")
        );
    }

    #[test]
    fn test_version_does_not_satisfy_requirement() {
        let formatter = GoFormatter;

        // Different versions
        assert!(!formatter.version_satisfies_requirement("v1.2.3", "v1.2.4"));
        assert!(!formatter.version_satisfies_requirement("v2.0.0", "v1.0.0"));

        // Partial match that doesn't start with requirement
        assert!(!formatter.version_satisfies_requirement("v1.2.3", "v1.2.3.4"));
    }

    #[test]
    fn test_version_satisfies_requirement_prefix_scenarios() {
        let formatter = GoFormatter;

        // Version is prefix of requirement (should NOT match)
        assert!(!formatter.version_satisfies_requirement("v1.2", "v1.2.3"));

        // Requirement is prefix of version with dot boundary (should match)
        assert!(formatter.version_satisfies_requirement("v1.2.3", "v1.2"));

        // False positive prevention: v1.2.30 should NOT match v1.2.3
        assert!(!formatter.version_satisfies_requirement("v1.2.30", "v1.2.3"));

        // But v1.2.3.1 SHOULD match v1.2.3 (if it has dot boundary)
        assert!(formatter.version_satisfies_requirement("v1.2.3.1", "v1.2.3"));
    }

    #[test]
    fn test_osv_version_to_native_prepends_v_prefix() {
        let formatter = GoFormatter;

        assert_eq!(formatter.osv_version_to_native("0.3.7"), "v0.3.7");
        // Already-prefixed input (should not occur in practice, but must
        // not be double-prefixed) round-trips unchanged.
        assert_eq!(formatter.osv_version_to_native("v0.3.7"), "v0.3.7");
    }

    #[test]
    fn test_osv_version_strips_v_prefix() {
        let formatter = GoFormatter;

        assert_eq!(formatter.osv_version("v1.2.3"), "1.2.3");
        assert_eq!(
            formatter.osv_version("v0.0.0-20191109021931-daa7c04131f5"),
            "0.0.0-20191109021931-daa7c04131f5"
        );
        assert_eq!(
            formatter.osv_version("v2.0.0+incompatible"),
            "2.0.0+incompatible"
        );
    }

    #[test]
    fn test_osv_version_unprefixed_is_unaffected() {
        let formatter = GoFormatter;

        // A version without the "v" prefix (should not normally occur for
        // Go, but the transform must be a no-op rather than corrupt it).
        assert_eq!(formatter.osv_version("1.2.3"), "1.2.3");
    }

    #[test]
    fn test_compile_requirement_satisfiable() {
        let formatter = GoFormatter;
        let matcher = formatter
            .compile_requirement(&VersionReq::new("v1.9.1"))
            .expect("an ordinary tagged requirement compiles");
        assert_eq!(matcher.matches("v1.9.1"), Some(true));
        assert_eq!(matcher.matches("v1.9.2"), Some(false));
    }

    #[test]
    fn test_compile_requirement_never_skips_a_candidate() {
        // Go's matcher has no external parser to fail on, so unlike other ecosystems it
        // never returns `None` for a candidate.
        let formatter = GoFormatter;
        let matcher = formatter
            .compile_requirement(&VersionReq::new("v1.9.1"))
            .unwrap();
        assert_eq!(matcher.matches("not-a-version-at-all"), Some(false));
    }

    /// S1 regression: `/@v/list` never enumerates pseudo-versions, so a pseudo-version
    /// requirement (an ordinary `go.mod` commit pin) can never be found in `available` —
    /// the whole scan must be suppressed (`None`), not scanned to a false "unsatisfiable".
    #[test]
    fn test_compile_requirement_pseudo_version_requirement_returns_none() {
        let formatter = GoFormatter;
        assert!(
            formatter
                .compile_requirement(&VersionReq::new("v0.0.0-20191109021931-daa7c04131f5"))
                .is_none()
        );
    }

    /// A `+incompatible`-suffixed *tag* is a real, enumerable `/@v/list` entry (not a
    /// pseudo-version), so it must not be caught by the pseudo-version guard above.
    #[test]
    fn test_compile_requirement_incompatible_tag_still_compiles() {
        let formatter = GoFormatter;
        let matcher = formatter
            .compile_requirement(&VersionReq::new("v2.0.0+incompatible"))
            .expect("a +incompatible tag is not a pseudo-version");
        assert_eq!(matcher.matches("v2.0.0+incompatible"), Some(true));
    }
}
