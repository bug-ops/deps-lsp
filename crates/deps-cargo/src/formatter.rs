use deps_core::lsp_helpers::{EcosystemFormatter, RequirementMatcher};
use deps_core::{PackageName, VersionReq};

/// Precise semver `VersionReq` matcher, compiled once per dependency by
/// [`CargoFormatter::compile_requirement`].
struct SemverMatcher(semver::VersionReq);

impl RequirementMatcher for SemverMatcher {
    fn matches(&self, version: &str) -> Option<bool> {
        version
            .parse::<semver::Version>()
            .ok()
            .map(|v| self.0.matches(&v))
    }
}

pub struct CargoFormatter;

impl EcosystemFormatter for CargoFormatter {
    fn format_version_for_text_edit(&self, version: &str) -> String {
        version.to_string()
    }

    fn package_url(&self, name: &PackageName) -> String {
        crate::registry::crate_url(name.as_str())
    }

    /// Compiles `requirement` via `semver::VersionReq`, the same crate `deps-cargo`'s
    /// registry uses for matching — precise range semantics (`^`, `~`, comparator lists),
    /// unlike the default `version_satisfies_requirement` heuristic this method
    /// deliberately does not reuse (see that method's docs).
    fn compile_requirement(&self, requirement: &VersionReq) -> Option<Box<dyn RequirementMatcher>> {
        requirement
            .as_str()
            .parse::<semver::VersionReq>()
            .ok()
            .map(|req| Box::new(SemverMatcher(req)) as Box<dyn RequirementMatcher>)
    }

    /// `semver::VersionReq::matches` excludes pre-releases unless `requirement` itself pins
    /// to the same `X.Y.Z` tuple with a pre-release tag — strict SemVer 2.0.0 semantics (#299).
    fn strict_semver_prerelease_exclusion(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_version() {
        let formatter = CargoFormatter;
        assert_eq!(formatter.format_version_for_text_edit("1.0.214"), "1.0.214");
        assert_eq!(formatter.format_version_for_text_edit("0.1.0"), "0.1.0");
    }

    #[test]
    fn test_package_url() {
        let formatter = CargoFormatter;
        assert_eq!(
            formatter.package_url(&PackageName::new("serde")),
            "https://crates.io/crates/serde"
        );
        assert_eq!(
            formatter.package_url(&PackageName::new("tokio-util")),
            "https://crates.io/crates/tokio-util"
        );
    }

    #[test]
    fn test_default_normalize_is_identity() {
        let formatter = CargoFormatter;
        assert_eq!(
            formatter.normalize_package_name(&PackageName::new("serde")),
            "serde"
        );
        assert_eq!(
            formatter.normalize_package_name(&PackageName::new("tokio-util")),
            "tokio-util"
        );
    }

    #[test]
    fn test_default_yanked_message() {
        let formatter = CargoFormatter;
        assert_eq!(formatter.yanked_message(), "This version has been yanked");
        assert_eq!(formatter.yanked_label(), "*(yanked)*");
    }

    #[test]
    fn test_version_satisfies_requirement() {
        let formatter = CargoFormatter;

        assert!(formatter.version_satisfies_requirement("1.2.3", "1.2.3"));
        assert!(formatter.version_satisfies_requirement("1.2.3", "^1.2"));
        assert!(formatter.version_satisfies_requirement("1.2.3", "~1.2"));
        assert!(formatter.version_satisfies_requirement("1.2.3", "1"));
        assert!(formatter.version_satisfies_requirement("1.2.3", "1.2"));

        assert!(!formatter.version_satisfies_requirement("1.2.3", "2.0.0"));
        assert!(!formatter.version_satisfies_requirement("1.2.3", "1.3"));
    }

    #[test]
    fn test_compile_requirement_satisfiable() {
        let formatter = CargoFormatter;
        let matcher = formatter
            .compile_requirement(&VersionReq::new("^1.0"))
            .expect("valid semver requirement must compile");
        assert_eq!(matcher.matches("1.5.0"), Some(true));
        assert_eq!(matcher.matches("2.0.0"), Some(false));
    }

    #[test]
    fn test_compile_requirement_unparseable_requirement_returns_none() {
        let formatter = CargoFormatter;
        assert!(
            formatter
                .compile_requirement(&VersionReq::new("not a semver req"))
                .is_none()
        );
    }

    #[test]
    fn test_compile_requirement_unparseable_candidate_is_skipped() {
        let formatter = CargoFormatter;
        let matcher = formatter
            .compile_requirement(&VersionReq::new("^1.0"))
            .unwrap();
        assert_eq!(matcher.matches("not-a-version"), None);
    }

    /// §3.1 worked example: an ordinary comparator-list requirement, which
    /// `version_satisfies_requirement`'s loose heuristic (no `^`/`~` prefix, three dot
    /// segments so `is_partial_version` is false) incorrectly rejects. The precise
    /// `compile_requirement` matcher must accept it.
    #[test]
    fn test_compile_requirement_comparator_list_satisfiable() {
        let formatter = CargoFormatter;
        let matcher = formatter
            .compile_requirement(&VersionReq::new(">=1.0, <2.0"))
            .unwrap();
        assert_eq!(matcher.matches("1.5.0"), Some(true));
    }

    /// §3.3 case: `~1.0.999` and latest `1.0.214` share major/minor, so the loose
    /// `is_same_major_minor`-based heuristic (and the removed `status == Outdated` gate)
    /// would treat this as up to date. The precise matcher must reject it — patch `999`
    /// is not published.
    #[test]
    fn test_compile_requirement_tilde_mistyped_patch_is_unsatisfiable() {
        let formatter = CargoFormatter;
        let matcher = formatter
            .compile_requirement(&VersionReq::new("~1.0.999"))
            .unwrap();
        assert_eq!(matcher.matches("1.0.214"), Some(false));
    }
}
