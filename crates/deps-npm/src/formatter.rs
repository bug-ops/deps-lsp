use deps_core::lsp_helpers::{
    DiagnosticMessages, DiagnosticPolicy, OsvNaming, PackageNaming, PackageRendering,
    RequirementMatcher, RequirementResolution, SourcePolicy,
    requirement_contains_dollar_placeholder,
};
use deps_core::{ConcreteVersion, Dependency, InvalidPackageName, PackageName, VersionReq};

/// Precise npm semver range matcher, compiled once per dependency by
/// [`NpmFormatter::compile_requirement`].
struct NodeSemverMatcher(node_semver::Range);

impl RequirementMatcher for NodeSemverMatcher {
    fn matches(&self, version: &ConcreteVersion) -> Option<bool> {
        let version = version.as_str();
        node_semver::Version::parse(version)
            .ok()
            .map(|v| self.0.satisfies(&v))
    }
}

/// Maximum name length npm's registry accepts.
///
/// npm counts UTF-16 code units; this counts Unicode scalar values
/// (`str::chars().count()`) instead, which undercounts names containing
/// characters outside the Basic Multilingual Plane. Still strictly more
/// accurate than a byte-length check for the common case of non-ASCII names
/// within the BMP.
const MAX_NAME_LENGTH: usize = 214;

/// Names npm's own validator hard-rejects regardless of character content.
const BLOCKED_NAMES: [&str; 2] = ["node_modules", "favicon.ico"];

/// Reports whether every character of `segment` is in npm's unreserved set —
/// the set `encodeURIComponent` leaves untouched (`A-Za-z0-9` plus
/// `! ' ( ) * - . _ ~`). This mirrors npm's actual
/// `encodeURIComponent(segment) === segment` check: any other ASCII
/// punctuation or any non-ASCII character fails it.
fn is_url_friendly_segment(segment: &str) -> bool {
    segment.chars().all(|c| {
        c.is_ascii_alphanumeric()
            || matches!(c, '!' | '\'' | '(' | ')' | '*' | '-' | '.' | '_' | '~')
    })
}

/// [`EcosystemFormatter`](deps_core::lsp_helpers::EcosystemFormatter) implementation for npm.
pub struct NpmFormatter;

impl PackageNaming for NpmFormatter {
    /// Lints `name` against npm's own `validate-npm-package-name` rules.
    ///
    /// Deliberately permissive beyond what npm hard-rejects: uppercase letters are
    /// allowed (npm only warns for legacy packages, never rejects), and any
    /// character in npm's unreserved set (`! ' ( ) * - . _ ~` plus alphanumerics)
    /// is accepted, matching npm's `encodeURIComponent(name) === name` check
    /// exactly rather than an approximation of it.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidPackageName`] if `name` is empty, exceeds 214 characters,
    /// starts with `.` or `_`, is a reserved name (`node_modules`, `favicon.ico`),
    /// has a malformed `@scope/name` structure, or contains a character outside
    /// npm's unreserved set.
    fn validate_package_name(&self, name: &str) -> Result<(), InvalidPackageName> {
        if name.is_empty() {
            return Err(InvalidPackageName::new("name cannot be empty"));
        }
        if name.chars().count() > MAX_NAME_LENGTH {
            return Err(InvalidPackageName::new(format!(
                "name cannot exceed {MAX_NAME_LENGTH} characters"
            )));
        }
        if name.starts_with('.') {
            return Err(InvalidPackageName::new("name cannot start with a period"));
        }
        if name.starts_with('_') {
            return Err(InvalidPackageName::new(
                "name cannot start with an underscore",
            ));
        }
        if BLOCKED_NAMES
            .iter()
            .any(|blocked| name.eq_ignore_ascii_case(blocked))
        {
            return Err(InvalidPackageName::new(format!(
                "'{name}' is a reserved name"
            )));
        }

        // Scoped names are `@scope/name`; anything else with a '/' is invalid.
        let (scope, pkg_name) = match name.split_once('/') {
            Some((scope, pkg_name)) => {
                let Some(scope) = scope.strip_prefix('@') else {
                    return Err(InvalidPackageName::new("unscoped name cannot contain '/'"));
                };
                (Some(scope), pkg_name)
            }
            None => (None, name),
        };

        if let Some(scope) = scope {
            if scope.is_empty() {
                return Err(InvalidPackageName::new("scope cannot be empty"));
            }
            if !is_url_friendly_segment(scope) {
                return Err(InvalidPackageName::new(
                    "scope contains characters that are not URL-friendly",
                ));
            }
        }

        if pkg_name.is_empty() {
            return Err(InvalidPackageName::new("name cannot be empty"));
        }
        if pkg_name.contains('/') {
            return Err(InvalidPackageName::new(
                "name cannot contain more than one '/'",
            ));
        }
        if !is_url_friendly_segment(pkg_name) {
            return Err(InvalidPackageName::new(
                "name contains characters that are not URL-friendly",
            ));
        }

        Ok(())
    }
}

impl PackageRendering for NpmFormatter {
    fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
        let version = version.as_str();
        version.to_string()
    }

    /// #1374 hardening: an unresolved `$VAR`/`${VAR}`-style external-templating placeholder
    /// (see `requirement_contains_dollar_placeholder`) in `current` leaves `current`
    /// unchanged instead of substituting `version`, so a vulnerability-fix or "update to
    /// latest" edit can never hardcode a literal version over it — mirrors
    /// `MavenFormatter`/`GradleFormatter`/`NuGetFormatter`'s identical-shaped
    /// `${property}`/`$(Property)` guards, all on this same non-`dep`-aware hook (npm has no
    /// dependency-identity-dependent rewrite logic, unlike `GitlabCiFormatter`/
    /// `BundlerFormatter`, which override `format_version_replacing_for` instead).
    fn format_version_replacing(&self, version: &ConcreteVersion, current: &str) -> String {
        if requirement_contains_dollar_placeholder(current) {
            return current.to_string();
        }
        self.format_version_for_text_edit(version)
    }

    fn package_url(&self, name: &PackageName) -> String {
        crate::registry::package_url(name.as_str())
    }
}

impl RequirementResolution for NpmFormatter {
    /// Compiles `requirement` via `node_semver::Range`, the same crate `deps-npm`'s
    /// registry uses for matching — precise npm semver range semantics, unlike the
    /// default `version_satisfies_requirement` heuristic this method deliberately does
    /// not reuse (see that method's docs).
    ///
    /// #1374 hardening: an unresolved placeholder (see
    /// [`Self::requirement_is_unresolved`]) never reaches `node_semver::Range::parse` —
    /// returning `None` up front keeps this consistent with `requirement_is_unresolved`
    /// even for the rare case `node_semver` might otherwise parse loosely.
    fn compile_requirement(&self, requirement: &VersionReq) -> Option<Box<dyn RequirementMatcher>> {
        if self.requirement_is_unresolved(requirement) {
            return None;
        }
        node_semver::Range::parse(requirement.as_str())
            .ok()
            .map(|req| Box::new(NodeSemverMatcher(req)) as Box<dyn RequirementMatcher>)
    }

    /// #1370: npm has no separate "concrete but undecidable ref" case
    /// [`Self::requirement_is_unresolved`] would need to stay broader than this — a
    /// `$VAR`/`${VAR}`-style placeholder is the only unresolved shape npm has, so both
    /// predicates key off the same `requirement_contains_dollar_placeholder` detector.
    fn requirement_is_placeholder(&self, requirement: &VersionReq) -> bool {
        requirement_contains_dollar_placeholder(requirement.as_str())
    }
}

impl DiagnosticMessages for NpmFormatter {
    fn yanked_message(&self) -> &'static str {
        "This version is deprecated"
    }

    fn yanked_label(&self) -> &'static str {
        "*(deprecated)*"
    }
}

impl DiagnosticPolicy for NpmFormatter {
    /// `node_semver::Range::satisfies` excludes pre-releases unless `requirement` itself pins
    /// to the same `X.Y.Z` tuple with a pre-release tag — strict SemVer 2.0.0 semantics (#299).
    fn strict_semver_prerelease_exclusion(&self) -> bool {
        true
    }

    /// Disables the manifest-requirement-level "requirement satisfiable only by a yanked
    /// version" diagnostic entirely (#436, follow-up to #205's plan.md §6): unconditionally
    /// `false`, for every requirement shape, not only ranges.
    ///
    /// npm's `Version::removal_status()` is genuinely per-version data (`npm deprecate` can
    /// target one version), but `npm deprecate` is routinely applied to *every* published
    /// version of a package at once (live-verified: the `request` package has all 126/126
    /// versions marked deprecated) — common enough that this diagnostic would frequently
    /// duplicate the dedicated package-level deprecation diagnostic
    /// ([`deps_core::lsp_helpers::DiagnosticMessages::deprecated_message`], issue #205), including for an exact-pin
    /// requirement (the case this hook used to still allow through). This does not touch
    /// [`Registry::reports_yanked`](deps_core::Registry::reports_yanked), which npm keeps at
    /// its default `true`: the independent in-use-version yanked check (#263,
    /// `crates/deps-core/src/lsp_helpers/diagnostics.rs`) reads real per-version data and
    /// stays live — e.g. a lockfile-pinned old version flagged by `npm deprecate pkg@"<1.2.3"`
    /// while `latest` is clean still surfaces its own "yanked" diagnostic.
    fn yanked_diagnostic_applies_to(
        &self,
        _dep: &dyn Dependency,
        _requirement: &VersionReq,
    ) -> bool {
        false
    }
}

impl SourcePolicy for NpmFormatter {
    /// FR-009: widens [`SourcePolicy::can_resolve_source`] so a `.npmrc`-resolved
    /// `AlternateRegistry` is resolvable alongside the default public `Registry` — gates
    /// hover/diagnostics/code-actions onto the router's per-source dispatch
    /// (`NpmRegistry::get_versions_from`) instead of the source-blind path. `CustomRegistry`
    /// (FR-006's fail-closed state) keeps the default's `false`.
    fn resolves_alternate_registry(&self) -> bool {
        true
    }
}

impl OsvNaming for NpmFormatter {}

#[cfg(test)]
mod tests {
    use super::*;

    /// O2: npm never offers the #205 "Replace with X" rename action — its only
    /// successor signal is free text (`deprecated`'s message), and regex-extracting a
    /// package name from registry-controlled prose to rewrite a manifest is a
    /// typosquatting vector. `supports_package_rename` stays the trait default (`false`).
    #[test]
    fn test_supports_package_rename_false() {
        assert!(!NpmFormatter.supports_package_rename());
    }

    /// npm's deprecation wording reuses the trait default (only Composer overrides it,
    /// to match Packagist's "abandoned" vocabulary).
    #[test]
    fn test_deprecated_message_and_label_use_defaults() {
        let f = NpmFormatter;
        assert_eq!(f.deprecated_message(), "This package is deprecated");
        assert_eq!(f.deprecated_label(), "*(deprecated)*");
    }

    // #758: replaces several hand-written EcosystemFormatter tests. test_validate_package_name_length_boundary
    // below stays separate: its computed (`.repeat(n)`) boundary name doesn't fit the macro's literal-only lists.
    deps_core::formatter_conformance! {
        mod npm_formatter_conformance;
        build: NpmFormatter;
        package_url: {
            "react" => "https://www.npmjs.com/package/react",
            "@types/node" => "https://www.npmjs.com/package/@types/node",
        };
        accepts: [
            "@types/node", "@scope/_private", "@scope/.config", "lodash.debounce", "c8", "-", "a",
            "MyLegacyPackage",
            // encodeURIComponent leaves `!'()*-._~` untouched, so `*` is legitimate here.
            "weird*name"
        ];
        rejects: [
            "", "node_modules", "NODE_MODULES", "favicon.ico", "foo/bar", "a\\b", ".hidden",
            "_private", "@scope", "@/pkg", "@scope/", "@scope/pkg/extra",
            // Well-formed `@scope/name` but the scope segment contains a space.
            "@sco pe/valid-pkg",
            // Well-formed `@scope/name` but the name segment contains a space.
            "@valid-scope/pkg name"
        ];
        version_roundtrip: [
            "1.2.3", "1.2.3" => true,
            "1.2.3", "1" => true,
            "1.2.3", "1.2" => true,
            "1.2.3", "^1.2" => true,
            "1.2.3", "^1.0" => true,
            "1.5.0", "^1.2.3" => true,
            "10.1.3", "^10.1.3" => true,
            "10.2.0", "^10.1.3" => true,
            "1.2.3", "~1.2" => true,
            "1.2.5", "~1.2" => true,
            "1.2.3", "2.0.0" => false,
            "1.2.3", "1.3" => false,
            "2.0.0", "^1.2.3" => false
        ];
    }

    /// Boundary pair for `MAX_NAME_LENGTH`: exactly 214 chars accepted, 215 rejected.
    /// Computed (`.repeat(n)`) lengths, so this doesn't fit `formatter_conformance!`'s
    /// `literal`-only accepts/rejects lists above.
    #[test]
    fn test_validate_package_name_length_boundary() {
        let formatter = NpmFormatter;
        assert!(formatter.validate_package_name(&"a".repeat(214)).is_ok());
        assert!(formatter.validate_package_name(&"a".repeat(215)).is_err());
    }

    /// FR-009 (M7): `can_resolve_source` accepts `Registry` and `AlternateRegistry`, rejects
    /// `CustomRegistry` (FR-006's fail-closed state).
    #[test]
    fn test_can_resolve_source_fr009() {
        let formatter = NpmFormatter;
        assert!(formatter.can_resolve_source(&deps_core::DependencySource::Registry));
        assert!(
            formatter.can_resolve_source(&deps_core::DependencySource::AlternateRegistry {
                index: "https://npm.pkg.github.com".to_string(),
                mirrors_crates_io: false,
            })
        );
        assert!(
            !formatter.can_resolve_source(&deps_core::DependencySource::CustomRegistry {
                url: "not-a-valid-url".to_string(),
            })
        );
    }

    /// FR-015 (M7): no npmjs.com hover link for anything but the plain public registry.
    #[test]
    fn test_suppress_package_url_fr015() {
        let formatter = NpmFormatter;
        assert!(!formatter.suppress_package_url(&deps_core::DependencySource::Registry));
        assert!(
            formatter.suppress_package_url(&deps_core::DependencySource::AlternateRegistry {
                index: "https://npm.pkg.github.com".to_string(),
                mirrors_crates_io: false,
            })
        );
        assert!(
            formatter.suppress_package_url(&deps_core::DependencySource::CustomRegistry {
                url: "not-a-valid-url".to_string(),
            })
        );
    }

    #[test]
    fn test_format_version() {
        let formatter = NpmFormatter;
        assert_eq!(
            formatter.format_version_for_text_edit(&ConcreteVersion::new("1.0.214")),
            "1.0.214"
        );
        assert_eq!(
            formatter.format_version_for_text_edit(&ConcreteVersion::new("18.3.1")),
            "18.3.1"
        );
    }

    #[test]
    fn test_default_normalize_is_identity() {
        let formatter = NpmFormatter;
        assert_eq!(
            formatter.normalize_package_name(&PackageName::new("react")),
            "react"
        );
        assert_eq!(
            formatter.normalize_package_name(&PackageName::new("@types/node")),
            "@types/node"
        );
    }

    #[test]
    fn test_deprecated_messages() {
        let formatter = NpmFormatter;
        assert_eq!(formatter.yanked_message(), "This version is deprecated");
        assert_eq!(formatter.yanked_label(), "*(deprecated)*");
    }

    #[test]
    fn test_compile_requirement_satisfiable() {
        let formatter = NpmFormatter;
        let matcher = formatter
            .compile_requirement(&VersionReq::new("^1.0.0"))
            .expect("valid npm range must compile");
        assert_eq!(matcher.matches(&ConcreteVersion::new("1.5.0")), Some(true));
        assert_eq!(matcher.matches(&ConcreteVersion::new("2.0.0")), Some(false));
    }

    #[test]
    fn test_compile_requirement_unparseable_requirement_returns_none() {
        let formatter = NpmFormatter;
        assert!(
            formatter
                .compile_requirement(&VersionReq::new("not a range"))
                .is_none()
        );
    }

    #[test]
    fn test_compile_requirement_unparseable_candidate_is_skipped() {
        let formatter = NpmFormatter;
        let matcher = formatter
            .compile_requirement(&VersionReq::new("^1.0.0"))
            .unwrap();
        assert_eq!(
            matcher.matches(&ConcreteVersion::new("not-a-version")),
            None
        );
    }

    /// §3.1 worked example counterpart for npm (this formatter also relies on the
    /// default loose `version_satisfies_requirement`).
    #[test]
    fn test_compile_requirement_comparator_list_satisfiable() {
        let formatter = NpmFormatter;
        let matcher = formatter
            .compile_requirement(&VersionReq::new(">=1.0.0 <2.0.0"))
            .unwrap();
        assert_eq!(matcher.matches(&ConcreteVersion::new("1.5.0")), Some(true));
    }

    /// §3.3 case for npm: `^0.2.999` and latest `0.2.14` share the leading zero-major
    /// minor component, so the loose heuristic (and the removed `Outdated` gate) would
    /// call this up to date. The precise matcher must reject it.
    #[test]
    fn test_compile_requirement_caret_zero_mistyped_patch_is_unsatisfiable() {
        let formatter = NpmFormatter;
        let matcher = formatter
            .compile_requirement(&VersionReq::new("^0.2.999"))
            .unwrap();
        assert_eq!(
            matcher.matches(&ConcreteVersion::new("0.2.14")),
            Some(false)
        );
    }

    /// #436: the manifest-requirement-level yanked diagnostic never applies to npm, for
    /// any requirement shape — including an exact pin, which the pre-#436 exact-pin
    /// restriction used to still allow through.
    #[test]
    fn test_yanked_diagnostic_applies_to_always_false() {
        use crate::types::{NpmDependency, NpmDependencySection};

        let formatter = NpmFormatter;
        for requirement in ["1.2.3", "^1.2.3", "~1.2.3", ">=1.0.0 <2.0.0", "*", "1.x"] {
            // Mirrors the sole call site: `requirement` is always `dep.version_requirement().unwrap()`.
            let dep = NpmDependency {
                name: PackageName::new("lodash"),
                name_range: deps_core::Range::default(),
                version_req: Some(VersionReq::new(requirement)),
                version_range: None,
                section: NpmDependencySection::Dependencies,
                source: deps_core::parser::DependencySource::Registry,
                catalog: None,
                package: None,
            };
            assert!(
                !formatter.yanked_diagnostic_applies_to(&dep, &VersionReq::new(requirement)),
                "expected {requirement:?} to be rejected"
            );
        }
    }
}
