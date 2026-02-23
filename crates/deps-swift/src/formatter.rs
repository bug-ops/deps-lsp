//! Swift ecosystem formatter.

use deps_core::lsp_helpers::EcosystemFormatter;

/// Returns `true` if `name` matches the `owner/repo` GitHub identifier pattern.
fn is_valid_owner_repo(name: &str) -> bool {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let re = RE.get_or_init(|| {
        regex::Regex::new(r"^[a-zA-Z0-9._-]+/[a-zA-Z0-9._-]+$").expect("hardcoded regex is valid")
    });
    re.is_match(name)
}

/// Formatter for Swift/SPM ecosystem LSP responses.
pub struct SwiftFormatter;

impl EcosystemFormatter for SwiftFormatter {
    fn format_version_for_text_edit(&self, version: &str) -> String {
        version.to_string()
    }

    fn package_url(&self, name: &str) -> String {
        if is_valid_owner_repo(name) {
            format!("https://github.com/{name}")
        } else {
            String::new()
        }
    }

    fn normalize_package_name(&self, name: &str) -> String {
        name.to_lowercase()
    }

    fn version_satisfies_requirement(&self, version: &str, requirement: &str) -> bool {
        let Ok(ver) = semver::Version::parse(version) else {
            return false;
        };
        let Ok(req) = semver::VersionReq::parse(requirement) else {
            return false;
        };
        req.matches(&ver)
    }

    fn yanked_message(&self) -> &'static str {
        "This version has been yanked"
    }

    fn yanked_label(&self) -> &'static str {
        "*(yanked)*"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_version() {
        let fmt = SwiftFormatter;
        assert_eq!(fmt.format_version_for_text_edit("2.40.0"), "2.40.0");
    }

    #[test]
    fn test_package_url() {
        let fmt = SwiftFormatter;
        assert_eq!(
            fmt.package_url("apple/swift-nio"),
            "https://github.com/apple/swift-nio"
        );
    }

    #[test]
    fn test_package_url_invalid_returns_empty() {
        let fmt = SwiftFormatter;
        assert_eq!(fmt.package_url("../../etc/passwd"), "");
        assert_eq!(fmt.package_url("no-slash"), "");
        assert_eq!(fmt.package_url("owner/repo/extra"), "");
    }

    #[test]
    fn test_normalize_package_name() {
        let fmt = SwiftFormatter;
        assert_eq!(
            fmt.normalize_package_name("Apple/Swift-NIO"),
            "apple/swift-nio"
        );
    }

    #[test]
    fn test_version_satisfies() {
        let fmt = SwiftFormatter;
        assert!(fmt.version_satisfies_requirement("2.62.0", ">=2.0.0, <3.0.0"));
        assert!(!fmt.version_satisfies_requirement("3.0.0", ">=2.0.0, <3.0.0"));
        assert!(fmt.version_satisfies_requirement("1.4.2", "=1.4.2"));
        assert!(!fmt.version_satisfies_requirement("1.4.3", "=1.4.2"));
    }

    #[test]
    fn test_yanked_labels() {
        let fmt = SwiftFormatter;
        assert_eq!(fmt.yanked_message(), "This version has been yanked");
        assert_eq!(fmt.yanked_label(), "*(yanked)*");
    }

    #[test]
    fn test_version_satisfies_up_to_next_major_range() {
        let fmt = SwiftFormatter;
        // upToNextMajor(from: "1.5.0") → ">=1.5.0, <2.0.0"
        assert!(fmt.version_satisfies_requirement("1.9.9", ">=1.5.0, <2.0.0"));
        assert!(!fmt.version_satisfies_requirement("2.0.0", ">=1.5.0, <2.0.0"));
        assert!(!fmt.version_satisfies_requirement("1.4.9", ">=1.5.0, <2.0.0"));
    }

    #[test]
    fn test_version_satisfies_up_to_next_minor_range() {
        let fmt = SwiftFormatter;
        // upToNextMinor(from: "2.3.0") → ">=2.3.0, <2.4.0"
        assert!(fmt.version_satisfies_requirement("2.3.5", ">=2.3.0, <2.4.0"));
        assert!(!fmt.version_satisfies_requirement("2.4.0", ">=2.3.0, <2.4.0"));
        assert!(!fmt.version_satisfies_requirement("2.2.9", ">=2.3.0, <2.4.0"));
    }

    #[test]
    fn test_version_satisfies_closed_range() {
        let fmt = SwiftFormatter;
        // "1.0.0"..."1.9.9" → ">=1.0.0, <=1.9.9"
        assert!(fmt.version_satisfies_requirement("1.9.9", ">=1.0.0, <=1.9.9"));
        assert!(fmt.version_satisfies_requirement("1.0.0", ">=1.0.0, <=1.9.9"));
        assert!(!fmt.version_satisfies_requirement("2.0.0", ">=1.0.0, <=1.9.9"));
    }

    #[test]
    fn test_version_satisfies_invalid_version_returns_false() {
        let fmt = SwiftFormatter;
        assert!(!fmt.version_satisfies_requirement("not-a-version", ">=1.0.0"));
    }

    #[test]
    fn test_version_satisfies_invalid_requirement_returns_false() {
        let fmt = SwiftFormatter;
        assert!(!fmt.version_satisfies_requirement("1.0.0", "not-a-req"));
    }

    #[test]
    fn test_version_satisfies_prerelease() {
        let fmt = SwiftFormatter;
        // Pre-release versions should not satisfy ranges by default (semver crate behavior)
        assert!(!fmt.version_satisfies_requirement("2.0.0-beta.1", ">=1.0.0, <3.0.0"));
    }
}
