//! `EcosystemFormatter` implementation for Deno manifests (D4).
//!
//! Version comparison, package URLs, and yanked-wording all dispatch on the scheme carried
//! inside the (already scheme-qualified, per D2) package name, mirroring
//! [`crate::registry`]'s dispatch — `jsr:` requirements compile through the same
//! `node_semver::Range` grammar JSR itself mandates, and `npm:` requirements delegate to
//! `deps-npm`'s own rules where a bare name check is enough (validation) or reuse
//! `deps-npm`'s wording outright (yanked messages, S2).

use crate::specifier::{Scheme, split_scheme, split_scoped};
use deps_core::lsp_helpers::{EcosystemFormatter, RequirementMatcher};
use deps_core::{Dependency, InvalidPackageName, PackageName, VersionReq};

/// Precise `node-semver` range matcher, compiled once per dependency by
/// [`DenoFormatter::compile_requirement`]. Correct for both `jsr:` and `npm:`
/// requirements: JSR mandates strict semver, and this is the same grammar/crate
/// `deps-npm` already uses for `npm:` requirements.
struct NodeSemverMatcher(node_semver::Range);

impl RequirementMatcher for NodeSemverMatcher {
    fn matches(&self, version: &str) -> Option<bool> {
        node_semver::Version::parse(version)
            .ok()
            .map(|v| self.0.satisfies(&v))
    }
}

/// Conservative cap on a `jsr:` scope/package-name segment's length (S-L1). JSR's own
/// limits are narrower (32/58); this single cap is all the URL-shape concern below needs —
/// `validate_package_name` is a diagnostic lint, not a strict mirror of JSR's registration
/// rules.
const MAX_JSR_SEGMENT_LENGTH: usize = 64;

/// Validates one `@scope`/`pkg` segment of a `jsr:` specifier (S-L1): rejects a segment
/// starting with `.` (blocks both `.` and `..`, which would otherwise let
/// `jsr:@a/..@1`/`jsr:@../x@1` build a `jsr.io` URL that path-normalizes away from the
/// intended `/@scope/pkg` shape) and caps segment length. `split_scoped` already
/// guarantees non-empty segments, so emptiness is not re-checked here.
fn validate_jsr_segment(segment: &str) -> Result<(), InvalidPackageName> {
    if segment.starts_with('.') {
        return Err(InvalidPackageName::new(
            "jsr: scope and package name must not start with '.'",
        ));
    }
    if segment.chars().count() > MAX_JSR_SEGMENT_LENGTH {
        return Err(InvalidPackageName::new(format!(
            "jsr: scope/package name cannot exceed {MAX_JSR_SEGMENT_LENGTH} characters"
        )));
    }
    Ok(())
}

/// `EcosystemFormatter` for Deno manifests (D4).
pub struct DenoFormatter;

impl EcosystemFormatter for DenoFormatter {
    fn format_version_for_text_edit(&self, version: &str) -> String {
        // `version_range` covers only the version text inside the specifier string — no
        // quotes, no '@' — exactly like npm's (`deps-npm/src/formatter.rs`).
        version.to_string()
    }

    fn package_url(&self, name: &PackageName) -> String {
        match split_scheme(name.as_str()) {
            Some((Scheme::Jsr, rest)) => split_scoped(rest)
                .map(|(scope, pkg)| crate::registry::jsr_package_url(scope, pkg))
                .unwrap_or_default(),
            Some((Scheme::Npm, rest)) => deps_npm::package_url(rest),
            None => String::new(),
        }
    }

    /// S2: adopts `deps-npm`'s wording for the *whole* formatter (both `jsr:` and `npm:`
    /// specifiers), rather than the `deps-core` defaults ("yanked"). Spec.md US-002/
    /// FR-013 treat cross-ecosystem wording divergence for the same npm package as a
    /// first-class bug, and `EcosystemFormatter::yanked_message`/`yanked_label` take only
    /// `&self` (no `&dyn Dependency`), so a per-scheme override is not possible without a
    /// `deps-core` trait change — this is the zero-cost fix available today.
    fn yanked_message(&self) -> &'static str {
        "This version is deprecated"
    }

    fn yanked_label(&self) -> &'static str {
        "*(deprecated)*"
    }

    /// Validates the scheme-qualified name: `jsr:` requires the scoped `@scope/name`
    /// form (mirroring JSR's own registration rules); `npm:` delegates to npm's own
    /// validator on the bare name (`ECOSYSTEM_GUIDE.md` "npm Package Name Validation");
    /// any other/missing scheme is rejected outright.
    fn validate_package_name(&self, name: &str) -> Result<(), InvalidPackageName> {
        match split_scheme(name) {
            Some((Scheme::Jsr, rest)) => {
                let Some((scope, pkg)) = split_scoped(rest) else {
                    return Err(InvalidPackageName::new(
                        "jsr: packages must be scoped as @scope/name",
                    ));
                };
                validate_jsr_segment(scope)?;
                validate_jsr_segment(pkg)?;
                Ok(())
            }
            Some((Scheme::Npm, rest)) => deps_npm::NpmFormatter.validate_package_name(rest),
            None => Err(InvalidPackageName::new(
                "unsupported specifier scheme (expected jsr: or npm:)",
            )),
        }
    }

    /// Compiles `requirement` via `node_semver::Range`, the same crate `deps-npm` uses —
    /// correct for JSR too, since JSR mandates semver.
    fn compile_requirement(&self, requirement: &VersionReq) -> Option<Box<dyn RequirementMatcher>> {
        node_semver::Range::parse(requirement.as_str())
            .ok()
            .map(|req| Box::new(NodeSemverMatcher(req)) as Box<dyn RequirementMatcher>)
    }

    /// Restricts the yanked-only-match diagnostic to an exact-pin requirement, copying
    /// npm's rationale (`deps-npm/src/formatter.rs`): applies uniformly to `jsr:` and
    /// `npm:` since this hook takes only a `&VersionReq`, with no way to tell which
    /// scheme it came from (accepted limitation L1 — JSR's genuinely better per-version
    /// signal is under-used for range requirements, in exchange for not reintroducing
    /// npm's package-wide-`deprecated` false-positive storm).
    fn yanked_diagnostic_applies_to(&self, requirement: &VersionReq) -> bool {
        node_semver::Version::parse(requirement.as_str().trim()).is_ok()
    }

    /// `npm:` dependencies map to OSV's `npm` ecosystem via their bare name (D5);
    /// `jsr:` dependencies return `None` — OSV has no JSR ecosystem (live-verified:
    /// `POST api.osv.dev/v1/query` with `{"ecosystem":"JSR"}` returns `code 3, invalid
    /// ecosystem`) — which cleanly skips them from the scan rather than risking a
    /// cross-registry name collision.
    fn osv_package_name(&self, dep: &dyn Dependency) -> Option<String> {
        match split_scheme(dep.name().as_str()) {
            Some((Scheme::Npm, rest)) => Some(rest.to_string()),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_package_url_jsr() {
        let formatter = DenoFormatter;
        assert_eq!(
            formatter.package_url(&PackageName::new("jsr:@std/fs")),
            "https://jsr.io/@std/fs"
        );
    }

    #[test]
    fn test_package_url_npm() {
        let formatter = DenoFormatter;
        assert_eq!(
            formatter.package_url(&PackageName::new("npm:react")),
            "https://www.npmjs.com/package/react"
        );
    }

    #[test]
    fn test_package_url_npm_scoped() {
        let formatter = DenoFormatter;
        assert_eq!(
            formatter.package_url(&PackageName::new("npm:@types/node")),
            "https://www.npmjs.com/package/@types/node"
        );
    }

    #[test]
    fn test_yanked_wording_matches_npm() {
        let formatter = DenoFormatter;
        assert_eq!(formatter.yanked_message(), "This version is deprecated");
        assert_eq!(formatter.yanked_label(), "*(deprecated)*");
    }

    #[test]
    fn test_validate_package_name_jsr_requires_scope() {
        let formatter = DenoFormatter;
        assert!(formatter.validate_package_name("jsr:@std/fs").is_ok());
        assert!(formatter.validate_package_name("jsr:std").is_err());
        assert!(formatter.validate_package_name("jsr:@std").is_err());
    }

    #[test]
    fn test_validate_package_name_jsr_rejects_dot_segments() {
        // S-L1: without this, `jsr:@a/..` builds a URL that path-normalizes away from
        // `jsr.io`'s intended `/@scope/pkg` shape.
        let formatter = DenoFormatter;
        assert!(formatter.validate_package_name("jsr:@a/..").is_err());
        assert!(formatter.validate_package_name("jsr:@../x").is_err());
        assert!(formatter.validate_package_name("jsr:@./x").is_err());
        assert!(formatter.validate_package_name("jsr:@a/.hidden").is_err());
    }

    #[test]
    fn test_validate_package_name_jsr_rejects_overlong_segment() {
        let formatter = DenoFormatter;
        let too_long = "a".repeat(65);
        assert!(
            formatter
                .validate_package_name(&format!("jsr:@{too_long}/pkg"))
                .is_err()
        );
        assert!(
            formatter
                .validate_package_name(&format!("jsr:@scope/{too_long}"))
                .is_err()
        );
        let max_len = "a".repeat(64);
        assert!(
            formatter
                .validate_package_name(&format!("jsr:@{max_len}/pkg"))
                .is_ok()
        );
    }

    #[test]
    fn test_validate_package_name_npm_delegates_to_npm_rules() {
        let formatter = DenoFormatter;
        assert!(formatter.validate_package_name("npm:react").is_ok());
        assert!(formatter.validate_package_name("npm:@types/node").is_ok());
        // npm rejects a reserved name.
        assert!(formatter.validate_package_name("npm:node_modules").is_err());
    }

    #[test]
    fn test_validate_package_name_rejects_unknown_scheme() {
        let formatter = DenoFormatter;
        assert!(
            formatter
                .validate_package_name("https://example.com")
                .is_err()
        );
    }

    #[test]
    fn test_compile_requirement_satisfiable() {
        let formatter = DenoFormatter;
        let matcher = formatter
            .compile_requirement(&VersionReq::new("^1.0.0"))
            .expect("valid node-semver range must compile");
        assert_eq!(matcher.matches("1.5.0"), Some(true));
        assert_eq!(matcher.matches("2.0.0"), Some(false));
    }

    #[test]
    fn test_compile_requirement_dist_tag_returns_none() {
        // M6: dist-tags like `npm:react@latest` fail `node_semver::Range::parse`, so
        // `compile_requirement` correctly returns `None` — matching how package.json
        // already handles dist-tags, not an accident.
        let formatter = DenoFormatter;
        assert!(
            formatter
                .compile_requirement(&VersionReq::new("latest"))
                .is_none()
        );
        assert!(
            formatter
                .compile_requirement(&VersionReq::new("next"))
                .is_none()
        );
    }

    #[test]
    fn test_yanked_diagnostic_applies_to_exact_pin_only() {
        let formatter = DenoFormatter;
        assert!(formatter.yanked_diagnostic_applies_to(&VersionReq::new("1.2.3")));
        assert!(!formatter.yanked_diagnostic_applies_to(&VersionReq::new("^1.2.3")));
        assert!(!formatter.yanked_diagnostic_applies_to(&VersionReq::new("*")));
    }

    #[test]
    fn test_osv_package_name_npm_maps_to_bare_name() {
        let formatter = DenoFormatter;

        struct FakeDep(deps_core::PackageName);
        impl Dependency for FakeDep {
            fn name(&self) -> &deps_core::PackageName {
                &self.0
            }
            fn name_range(&self) -> tower_lsp_server::ls_types::Range {
                tower_lsp_server::ls_types::Range::default()
            }
            fn version_requirement(&self) -> Option<&VersionReq> {
                None
            }
            fn version_range(&self) -> Option<tower_lsp_server::ls_types::Range> {
                None
            }
            fn source(&self) -> deps_core::parser::DependencySource {
                deps_core::parser::DependencySource::Registry
            }
            fn as_any(&self) -> &dyn std::any::Any {
                self
            }
        }

        let npm_dep = FakeDep(PackageName::new("npm:react"));
        assert_eq!(
            formatter.osv_package_name(&npm_dep),
            Some("react".to_string())
        );

        let jsr_dep = FakeDep(PackageName::new("jsr:@std/fs"));
        assert_eq!(formatter.osv_package_name(&jsr_dep), None);
    }
}
