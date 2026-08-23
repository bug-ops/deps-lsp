//! Swift ecosystem formatter.

use deps_core::Dependency;
use deps_core::PackageName;
use deps_core::lsp_helpers::EcosystemFormatter;

use crate::types::SwiftDependency;

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

    fn package_url(&self, name: &PackageName) -> String {
        if is_valid_owner_repo(name.as_str()) {
            format!("https://github.com/{name}")
        } else {
            String::new()
        }
    }

    fn normalize_package_name(&self, name: &PackageName) -> String {
        name.as_str().to_lowercase()
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

    /// Raw `dep.name()`, NOT [`Self::normalize_package_name`]: that
    /// lowercases, and OSV's `SwiftURL` matching is case-sensitive, so
    /// lowercasing would mangle mixed-case repos. Gated on the dependency's
    /// source host being `github.com`: only that host is populated in OSV's
    /// `SwiftURL` ecosystem, and `dep.name()`'s `owner/repo` shape alone
    /// cannot distinguish a GitHub coordinate from a same-shaped GitLab/self-hosted
    /// one — attributing a GitHub project's advisories to an unrelated
    /// same-named repo elsewhere would be a false positive, not just a miss.
    fn osv_package_name(&self, dep: &dyn Dependency) -> Option<String> {
        let swift_dep = dep.as_any().downcast_ref::<SwiftDependency>()?;
        let host = reqwest::Url::parse(&swift_dep.url).ok()?;
        matches!(host.host_str(), Some("github.com" | "www.github.com"))
            .then(|| format!("github.com/{}", dep.name()))
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
            fmt.package_url(&PackageName::new("apple/swift-nio")),
            "https://github.com/apple/swift-nio"
        );
    }

    #[test]
    fn test_package_url_invalid_returns_empty() {
        let fmt = SwiftFormatter;
        assert_eq!(fmt.package_url(&PackageName::new("../../etc/passwd")), "");
        assert_eq!(fmt.package_url(&PackageName::new("no-slash")), "");
        assert_eq!(fmt.package_url(&PackageName::new("owner/repo/extra")), "");
    }

    #[test]
    fn test_normalize_package_name() {
        let fmt = SwiftFormatter;
        assert_eq!(
            fmt.normalize_package_name(&PackageName::new("Apple/Swift-NIO")),
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

    fn dep_with_url(name: &str, url: &str) -> SwiftDependency {
        use deps_core::parser::DependencySource;
        use tower_lsp_server::ls_types::{Position, Range};

        SwiftDependency {
            name: name.into(),
            name_range: Range::new(Position::new(0, 0), Position::new(0, 1)),
            version_req: Some(">=1.0.0".into()),
            version_range: None,
            url: url.to_string(),
            source: DependencySource::Registry,
        }
    }

    #[test]
    fn test_osv_package_name_github_host_prefixes_and_preserves_case() {
        let fmt = SwiftFormatter;
        let dep = dep_with_url("apple/swift-nio", "https://github.com/apple/swift-nio.git");
        assert_eq!(
            fmt.osv_package_name(&dep),
            Some("github.com/apple/swift-nio".to_string())
        );
    }

    #[test]
    fn test_osv_package_name_www_github_host_accepted() {
        let fmt = SwiftFormatter;
        let dep = dep_with_url(
            "apple/swift-nio",
            "https://www.github.com/apple/swift-nio.git",
        );
        assert_eq!(
            fmt.osv_package_name(&dep),
            Some("github.com/apple/swift-nio".to_string())
        );
    }

    #[test]
    fn test_osv_package_name_non_github_host_returns_none() {
        let fmt = SwiftFormatter;
        let dep = dep_with_url("foo/bar", "https://gitlab.com/foo/bar.git");
        assert_eq!(fmt.osv_package_name(&dep), None);
    }

    #[test]
    fn test_osv_package_name_self_hosted_host_returns_none() {
        let fmt = SwiftFormatter;
        let dep = dep_with_url("foo/bar", "https://git.corp.internal/foo/bar.git");
        assert_eq!(fmt.osv_package_name(&dep), None);
    }

    #[test]
    fn test_osv_package_name_unparseable_url_returns_none() {
        let fmt = SwiftFormatter;
        let dep = dep_with_url("foo/bar", "not a url");
        assert_eq!(fmt.osv_package_name(&dep), None);
    }

    #[test]
    fn test_osv_package_name_differs_from_normalize_package_name() {
        // Regression guard: normalize_package_name lowercases (this project's
        // internal lookup key), while osv_package_name must NOT lowercase the
        // owner/repo segment (OSV's SwiftURL matching is case-sensitive).
        let fmt = SwiftFormatter;
        let dep = dep_with_url("Apple/Swift-NIO", "https://github.com/Apple/Swift-NIO.git");
        assert_eq!(
            fmt.osv_package_name(&dep),
            Some("github.com/Apple/Swift-NIO".to_string())
        );
        assert_eq!(
            fmt.normalize_package_name(&dep.name),
            "apple/swift-nio".to_string()
        );
    }

    #[test]
    fn test_version_satisfies_prerelease() {
        let fmt = SwiftFormatter;
        // Pre-release versions should not satisfy ranges by default (semver crate behavior)
        assert!(!fmt.version_satisfies_requirement("2.0.0-beta.1", ">=1.0.0, <3.0.0"));
    }
}
