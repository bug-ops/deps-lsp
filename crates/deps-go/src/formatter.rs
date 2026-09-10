use deps_core::VersionReq;
use deps_core::lsp_helpers::{
    DiagnosticMessages, DiagnosticPolicy, OsvNaming, PackageNaming, PackageRendering,
    RequirementMatcher, RequirementResolution, SourcePolicy, compile_requirement_unless,
};
use deps_core::{ConcreteVersion, Dependency, DepsError, InvalidPackageName, PackageName};

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
    fn matches(&self, version: &ConcreteVersion) -> Option<bool> {
        let version = version.as_str();
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

impl PackageNaming for GoFormatter {
    /// Reuses `crate::registry::validate_module_path` — the same structural rule that
    /// gates every registry request — so a malformed module path (empty, too long, or
    /// containing a `.`/`..` path segment) is reported as "Invalid package name" instead of
    /// falling through to a registry lookup and rendering the generic "Registry lookup
    /// failed" diagnostic (#402).
    ///
    /// # Errors
    ///
    /// Returns [`InvalidPackageName`] carrying `validate_module_path`'s rejection reason.
    fn validate_package_name(&self, name: &str) -> Result<(), InvalidPackageName> {
        let Err(err) = crate::registry::validate_module_path(name) else {
            return Ok(());
        };
        // `validate_module_path` only ever constructs `DepsError::InvalidVersionReq` (#399
        // documents it as the shared "invalid input" carrier it deliberately reuses for this),
        // so this is the only reachable arm — matched explicitly rather than a catch-all
        // `.to_string()` fallback, both to avoid dead code per CLAUDE.md and because
        // `DepsError`'s `Display` prefixes an unrelated "invalid version requirement: " label
        // that would misrender the module-path reason here (#402 critique M3).
        let DepsError::InvalidVersionReq(reason) = err else {
            unreachable!("validate_module_path only ever returns DepsError::InvalidVersionReq")
        };
        Err(InvalidPackageName::new(reason))
    }
}

impl PackageRendering for GoFormatter {
    fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
        let version = version.as_str();
        // Go versions in go.mod are unquoted: v1.2.3
        // Return version as-is since it should already have "v" prefix from registry
        version.to_string()
    }

    fn package_url(&self, name: &PackageName) -> String {
        crate::registry::package_url(name.as_str())
    }

    /// S4 (spec 034 review): suppresses the `pkg.go.dev` hover link for anything but a plain
    /// public-registry dependency, reusing `SourcePolicy::source_is_public_registry_content`'s
    /// default (`Registry` only — Go has no crates.io-style verified-mirror concept for
    /// `AlternateRegistry` to except, mirroring `deps-pypi`'s identical reasoning). Without
    /// this, a `GOPRIVATE`-matched module's hover still rendered a clickable
    /// `pkg.go.dev/<private-path>` link, undermining the confidentiality guarantee FR-008/
    /// NFR-003(2) exist for — the module path never reaches `pkg.go.dev` over the network
    /// either way (this is a display link only, see `crate::registry::package_url`'s doc),
    /// but the link itself named the private path in the rendered hover text.
    fn suppress_package_url(&self, source: &deps_core::parser::DependencySource) -> bool {
        !self.source_is_public_registry_content(source)
    }
}

impl RequirementResolution for GoFormatter {
    fn version_satisfies_requirement(&self, version: &ConcreteVersion, requirement: &str) -> bool {
        let version = version.as_str();
        go_version_matches(version, requirement)
    }

    /// Compiles `requirement` into an `ExactMatcher` using the same exact/pseudo-version
    /// comparison `version_satisfies_requirement` uses — Go's requirement syntax has no
    /// separate "loose" vs. "precise" distinction, so both share `go_version_matches`. Uses
    /// [`compile_requirement_unless`] (see that function and
    /// [`deps_core::lsp_helpers::RequirementResolution::compile_requirement`] for the shared "undecidable" contract).
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

impl DiagnosticMessages for GoFormatter {}

impl DiagnosticPolicy for GoFormatter {}

impl SourcePolicy for GoFormatter {
    /// FR-012 (spec 034): accepts `Registry` (default) and `AlternateRegistry` (a `$GOENV`
    /// `GOPROXY`-chain or `GOPRIVATE`-bypass resolution) so hover/diagnostics/code-actions
    /// gate correctly; `CustomRegistry` (FR-009's fail-closed state, every hop invalid) is
    /// deliberately not accepted — falls through to the default `is_version_resolvable() ==
    /// false`, keeping the existing fail-closed gate intact.
    fn can_resolve_source(&self, source: &deps_core::parser::DependencySource) -> bool {
        matches!(
            source,
            deps_core::parser::DependencySource::Registry
                | deps_core::parser::DependencySource::AlternateRegistry { .. }
        )
    }
}

impl OsvNaming for GoFormatter {
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
            source: deps_core::parser::DependencySource::Registry,
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
        assert_eq!(
            formatter.format_version_for_text_edit(&ConcreteVersion::new("v1.2.3")),
            "v1.2.3"
        );

        // Pseudo-version
        assert_eq!(
            formatter.format_version_for_text_edit(&ConcreteVersion::new(
                "v0.0.0-20191109021931-daa7c04131f5"
            )),
            "v0.0.0-20191109021931-daa7c04131f5"
        );

        // Version with +incompatible
        assert_eq!(
            formatter.format_version_for_text_edit(&ConcreteVersion::new("v2.0.0+incompatible")),
            "v2.0.0+incompatible"
        );
    }

    // #758: exact-value `EcosystemFormatter` conformance, replacing test_package_url,
    // test_validate_package_name_accepts_valid_module_path, test_validate_package_name_rejects_empty,
    // test_validate_package_name_rejects_dot_segment, test_version_satisfies_requirement_exact_match,
    // test_version_satisfies_requirement_pseudo_version, test_version_satisfies_requirement_incompatible,
    // test_version_does_not_satisfy_requirement, and test_version_satisfies_requirement_prefix_scenarios.
    // test_validate_package_name_rejects_too_long below stays hand-written: it asserts on a
    // computed (`.repeat(n)`) length, which doesn't fit the macro's `literal`-only list.
    deps_core::formatter_conformance! {
        mod go_formatter_conformance;
        build: GoFormatter;
        package_url: {
            "github.com/gin-gonic/gin" => "https://pkg.go.dev/github.com/gin-gonic/gin",
            "github.com/go-redis/redis/v8" => "https://pkg.go.dev/github.com/go-redis/redis/v8",
            "fmt" => "https://pkg.go.dev/fmt",
            "github.com/user@org/package" => "https://pkg.go.dev/github.com/user%40org/package",
            "github.com/user/pkg name" => "https://pkg.go.dev/github.com/user/pkg%20name",
        };
        accepts: [
            "github.com/gin-gonic/gin", "golang.org/x/mod"
        ];
        rejects: [
            "", "github.com/user/..", "./evil"
        ];
        version_roundtrip: [
            "v1.2.3", "v1.2.3" => true,
            "v0.1.0", "v0.1.0" => true,
            "v0.0.0-20191109021931-daa7c04131f5", "v0.0.0" => true,
            "v0.0.0-20191109021931-daa7c04131f5", "v0.0.0-20191109021931-daa7c04131f5" => true,
            "v2.0.0+incompatible", "v2.0.0" => true,
            "v2.0.0+incompatible", "v2.0.0+incompatible" => true,
            "v1.2.3", "v1.2.4" => false,
            "v2.0.0", "v1.0.0" => false,
            "v1.2.3", "v1.2.3.4" => false,
            "v1.2", "v1.2.3" => false,
            "v1.2.3", "v1.2" => true,
            "v1.2.30", "v1.2.3" => false,
            "v1.2.3.1", "v1.2.3" => true
        ];
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
        assert_eq!(matcher.matches(&ConcreteVersion::new("v1.9.1")), Some(true));
        assert_eq!(
            matcher.matches(&ConcreteVersion::new("v1.9.2")),
            Some(false)
        );
    }

    #[test]
    fn test_compile_requirement_never_skips_a_candidate() {
        // Go's matcher has no external parser to fail on, so unlike other ecosystems it
        // never returns `None` for a candidate.
        let formatter = GoFormatter;
        let matcher = formatter
            .compile_requirement(&VersionReq::new("v1.9.1"))
            .unwrap();
        assert_eq!(
            matcher.matches(&ConcreteVersion::new("not-a-version-at-all")),
            Some(false)
        );
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
        assert_eq!(
            matcher.matches(&ConcreteVersion::new("v2.0.0+incompatible")),
            Some(true)
        );
    }

    /// FR-012 (spec 034): `can_resolve_source` accepts `Registry`/`AlternateRegistry`,
    /// rejects `CustomRegistry` (FR-009's fail-closed state).
    #[test]
    fn test_can_resolve_source() {
        let formatter = GoFormatter;
        assert!(formatter.can_resolve_source(&deps_core::parser::DependencySource::Registry));
        assert!(formatter.can_resolve_source(
            &deps_core::parser::DependencySource::AlternateRegistry {
                index: "go-proxy:deadbeef".to_string(),
                mirrors_crates_io: false,
            }
        ));
        assert!(!formatter.can_resolve_source(
            &deps_core::parser::DependencySource::CustomRegistry {
                url: "not-a-valid-url".to_string(),
            }
        ));
    }

    /// S4 (spec 034 review): the `pkg.go.dev` hover link is suppressed for anything but a
    /// plain public-registry dependency — a `GOPRIVATE`/`GOPROXY`-resolved module's hover
    /// must not render a clickable link naming its own (potentially private) module path.
    #[test]
    fn test_suppress_package_url() {
        let formatter = GoFormatter;
        assert!(!formatter.suppress_package_url(&deps_core::parser::DependencySource::Registry));
        assert!(formatter.suppress_package_url(
            &deps_core::parser::DependencySource::AlternateRegistry {
                index: "go-proxy:deadbeef".to_string(),
                mirrors_crates_io: false,
            }
        ));
        assert!(formatter.suppress_package_url(
            &deps_core::parser::DependencySource::CustomRegistry {
                url: "not-a-valid-url".to_string(),
            }
        ));
    }

    #[test]
    fn test_validate_package_name_rejects_too_long() {
        let formatter = GoFormatter;
        let too_long = "a".repeat(501);
        assert!(formatter.validate_package_name(&too_long).is_err());
    }
}
