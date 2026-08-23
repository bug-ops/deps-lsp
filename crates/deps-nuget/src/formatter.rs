//! Version formatting for the NuGet ecosystem.

use deps_core::lsp_helpers::EcosystemFormatter;
use deps_core::{PackageName, VersionReq};

pub struct NuGetFormatter;

impl EcosystemFormatter for NuGetFormatter {
    fn format_version_for_text_edit(&self, version: &str) -> String {
        // NuGet manifests store plain version text; no prefix/wrapping on insert.
        version.to_string()
    }

    fn package_url(&self, name: &PackageName) -> String {
        crate::registry::package_url(name.as_str())
    }

    /// Overridden because the default npm caret/tilde semantics do not apply to NuGet's
    /// interval-notation ranges (`[1.0,2.0)`) and floating patterns (`1.1.*`).
    fn version_satisfies_requirement(&self, version: &str, requirement: &str) -> bool {
        if requirement.contains('*') {
            let versions = [version.to_string()];
            return crate::version::resolve_float(&versions, requirement).is_some();
        }
        crate::version::satisfies(version, requirement)
    }

    /// NuGet package ids are case-insensitive and every V3 API path segment is lowercased.
    fn normalize_package_name(&self, name: &PackageName) -> String {
        name.as_str().to_lowercase()
    }

    /// Overridden because a minimum-only range (a bare `Version="1.0.0"`, or its explicit
    /// open-ended-minimum spellings `[1.0.0,)`/`(1.0.0,)`/`[1.0.0,]`) is a floor under
    /// `PackageReference`/`PackageVersion` semantics, not an auto-following range:
    /// `version_satisfies_requirement` accepts any version `>= 1.0.0`, so delegating to it
    /// here would never flag a floor as outdated. `latest` behind the floor is not
    /// "outdated" either (it would read as a downgrade suggestion), so up to date is
    /// `latest <= floor` here, not `latest == floor`. Exact pins, maximums, bounded ranges,
    /// and floating patterns (`1.1.*`) already express the intended forward-compatibility
    /// window, so those keep the general satisfies check.
    fn is_requirement_up_to_date(&self, requirement: &VersionReq, latest: &str) -> bool {
        let requirement = requirement.as_str();
        if requirement.contains('*') {
            return self.version_satisfies_requirement(latest, requirement);
        }
        match crate::version::compare_minimum_floor(requirement, latest) {
            Some(ordering) => ordering != std::cmp::Ordering::Less,
            None => self.version_satisfies_requirement(latest, requirement),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_version() {
        let f = NuGetFormatter;
        assert_eq!(f.format_version_for_text_edit("13.0.3"), "13.0.3");
    }

    #[test]
    fn test_package_url() {
        let f = NuGetFormatter;
        assert_eq!(
            f.package_url(&PackageName::new("Newtonsoft.Json")),
            "https://www.nuget.org/packages/Newtonsoft.Json"
        );
    }

    #[test]
    fn test_version_satisfies_exact_pin() {
        let f = NuGetFormatter;
        assert!(f.version_satisfies_requirement("1.0.0", "[1.0.0]"));
        assert!(!f.version_satisfies_requirement("1.0.1", "[1.0.0]"));
    }

    #[test]
    fn test_version_satisfies_bare_floor() {
        let f = NuGetFormatter;
        assert!(f.version_satisfies_requirement("2.0.0", "1.0.0"));
        assert!(!f.version_satisfies_requirement("0.9.0", "1.0.0"));
    }

    #[test]
    fn test_version_satisfies_floating() {
        let f = NuGetFormatter;
        assert!(f.version_satisfies_requirement("1.1.5", "1.1.*"));
        assert!(!f.version_satisfies_requirement("1.2.0", "1.1.*"));
    }

    #[test]
    fn test_is_up_to_date_bare_floor_outdated() {
        let f = NuGetFormatter;
        // Bare floors are pins under PackageReference: a newer latest is outdated,
        // even though it satisfies the floor (>= 13.0.3).
        assert!(!f.is_requirement_up_to_date(&VersionReq::new("13.0.3"), "13.0.4"));
        assert!(!f.is_requirement_up_to_date(&VersionReq::new("13.0.3"), "14.0.0"));
    }

    #[test]
    fn test_is_up_to_date_bare_floor_matches_latest() {
        let f = NuGetFormatter;
        assert!(f.is_requirement_up_to_date(&VersionReq::new("13.0.3"), "13.0.3"));
    }

    #[test]
    fn test_is_up_to_date_open_ended_minimum_bracket_forms_outdated() {
        let f = NuGetFormatter;
        // Same floor semantics as a bare version, spelled with explicit interval brackets.
        assert!(!f.is_requirement_up_to_date(&VersionReq::new("[13.0.3,)"), "13.0.4"));
        assert!(!f.is_requirement_up_to_date(&VersionReq::new("(13.0.3,)"), "13.0.4"));
        assert!(!f.is_requirement_up_to_date(&VersionReq::new("[13.0.3,]"), "13.0.4"));
        assert!(f.is_requirement_up_to_date(&VersionReq::new("[13.0.3,)"), "13.0.3"));
    }

    #[test]
    fn test_is_up_to_date_floor_ahead_of_latest_is_not_outdated() {
        let f = NuGetFormatter;
        // A floor already ahead of the registry's latest (a preview/prerelease pin, or a
        // latest that regressed) must not render a downgrade suggestion.
        assert!(f.is_requirement_up_to_date(&VersionReq::new("13.0.5"), "13.0.4"));
        assert!(f.is_requirement_up_to_date(&VersionReq::new("9.0.0-preview.5"), "8.0.11"));
        // A prerelease pin genuinely behind a newer stable release is still outdated.
        assert!(!f.is_requirement_up_to_date(&VersionReq::new("9.0.0-preview.5"), "9.0.0"));
    }

    #[test]
    fn test_is_up_to_date_exact_pin_and_ranges_keep_satisfies_semantics() {
        let f = NuGetFormatter;
        assert!(f.is_requirement_up_to_date(&VersionReq::new("[13.0.3]"), "13.0.3"));
        assert!(!f.is_requirement_up_to_date(&VersionReq::new("[13.0.3]"), "14.0.0"));
        assert!(f.is_requirement_up_to_date(&VersionReq::new("[1.0,2.0)"), "1.5.0"));
        assert!(f.is_requirement_up_to_date(&VersionReq::new("1.1.*"), "1.1.5"));
        assert!(!f.is_requirement_up_to_date(&VersionReq::new("1.1.*"), "1.2.0"));
    }

    #[test]
    fn test_normalize_lowercases() {
        let f = NuGetFormatter;
        assert_eq!(
            f.normalize_package_name(&PackageName::new("Newtonsoft.Json")),
            "newtonsoft.json"
        );
    }
}
