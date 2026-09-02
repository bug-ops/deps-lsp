//! Swift ecosystem formatter.

use deps_core::ConcreteVersion;
use deps_core::Dependency;
use deps_core::InvalidPackageName;
use deps_core::PackageName;
use deps_core::VersionReq;
use deps_core::is_dot_segment;
use deps_core::lsp_helpers::{
    DiagnosticMessages, DiagnosticPolicy, OsvNaming, PackageNaming, PackageRendering,
    RequirementMatcher, RequirementResolution, SourcePolicy, warn_rejected_value,
};

/// Precise semver `VersionReq` matcher, compiled once per dependency by
/// [`SwiftFormatter::compile_requirement`] — the same crate `version_satisfies_requirement`
/// uses, but with the compile step (and its failure) split out from the per-candidate check.
struct SemverMatcher(semver::VersionReq);

impl RequirementMatcher for SemverMatcher {
    fn matches(&self, version: &ConcreteVersion) -> Option<bool> {
        let version = version.as_str();
        semver::Version::parse(version)
            .ok()
            .map(|v| self.0.matches(&v))
    }
}

use crate::types::SwiftDependency;

/// Returns `true` if `name` matches the `owner/repo` GitHub identifier pattern.
///
/// Delegates to [`crate::is_valid_github_identity`], shared with `registry`'s
/// credential-bearing fetch-URL gate, so a `.`/`..` segment is rejected here too (#357 M1) —
/// otherwise this display-URL gate could still render `https://github.com/apple/..`.
fn is_valid_owner_repo(name: &str) -> bool {
    crate::is_valid_github_identity(name)
}

/// Formatter for Swift/SPM ecosystem LSP responses.
pub struct SwiftFormatter;

impl PackageNaming for SwiftFormatter {
    fn normalize_package_name(&self, name: &PackageName) -> String {
        name.as_str().to_lowercase()
    }

    /// Accepts either `is_valid_owner_repo`'s `owner/repo` GitHub identifier shape (the same
    /// one `package_url` and the registry's fetch-URL gate require), or a bare single-segment
    /// name with no `/`.
    ///
    /// The bare-name case matters because `name` is not always a GitHub coordinate to begin
    /// with: `deps_swift::parser`'s `.package(path:)` handling sets it to the target
    /// directory's basename (`crates/deps-swift/src/parser.rs`, the `RE_PATH` arm) for a
    /// `DependencySource::Path` dependency, which never contains a `/` and has no GitHub
    /// identity at all. `validate_package_name` only sees the bare string, not the
    /// dependency's source, so it cannot tell a local package's basename apart from a
    /// registry-style name typo'd without its `owner/` prefix — per this trait's "err on the
    /// side of accepting anything ambiguous" contract, the bare form is accepted rather than
    /// flagged, which also fixes a false "Invalid package name" on every local Swift package
    /// dependency (#402 critique C1). A multi-segment name (extra segment, disallowed
    /// character, or a `.`/`..` segment) still fails the `owner/repo` check and is rejected,
    /// same as before.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidPackageName`] when `name` is empty, is exactly `.`/`..`, or contains a
    /// `/` without matching the `owner/repo` shape.
    fn validate_package_name(&self, name: &str) -> Result<(), InvalidPackageName> {
        let bare_name_ok = !name.contains('/') && !name.is_empty() && !is_dot_segment(name);
        if is_valid_owner_repo(name) || bare_name_ok {
            Ok(())
        } else {
            Err(InvalidPackageName::new(
                "name must be a GitHub 'owner/repo' identifier",
            ))
        }
    }
}

impl PackageRendering for SwiftFormatter {
    fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
        let version = version.as_str();
        version.to_string()
    }

    fn package_url(&self, name: &PackageName) -> String {
        if is_valid_owner_repo(name.as_str()) {
            format!("https://github.com/{name}")
        } else {
            warn_rejected_value(
                "is_valid_owner_repo",
                "swift package display formatting",
                name.as_str(),
            );
            String::new()
        }
    }
}

impl RequirementResolution for SwiftFormatter {
    fn version_satisfies_requirement(&self, version: &ConcreteVersion, requirement: &str) -> bool {
        let version = version.as_str();
        let Ok(ver) = semver::Version::parse(version) else {
            return false;
        };
        let Ok(req) = semver::VersionReq::parse(requirement) else {
            return false;
        };
        req.matches(&ver)
    }

    /// Compiles `requirement` via `semver::VersionReq`, the same crate
    /// `version_satisfies_requirement` uses. `None` on parse failure is the fallible-parse
    /// shape of `compile_requirement`'s "undecidable" contract (see
    /// [`deps_core::lsp_helpers::RequirementResolution::compile_requirement`]) — Swift's registry client follows GitHub
    /// tags pagination to build `available`, so a `None` here is purely "this requirement
    /// string doesn't parse as semver," not a gap in what pagination could return.
    fn compile_requirement(&self, requirement: &VersionReq) -> Option<Box<dyn RequirementMatcher>> {
        requirement
            .as_str()
            .parse::<semver::VersionReq>()
            .ok()
            .map(|req| Box::new(SemverMatcher(req)) as Box<dyn RequirementMatcher>)
    }
}

impl DiagnosticMessages for SwiftFormatter {
    fn yanked_message(&self) -> &'static str {
        "This version has been yanked"
    }

    fn yanked_label(&self) -> &'static str {
        "*(yanked)*"
    }
}

impl DiagnosticPolicy for SwiftFormatter {
    /// `semver::VersionReq::matches` excludes pre-releases unless `requirement` itself pins
    /// to the same `X.Y.Z` tuple with a pre-release tag — strict SemVer 2.0.0 semantics (#299).
    fn strict_semver_prerelease_exclusion(&self) -> bool {
        true
    }
}

impl SourcePolicy for SwiftFormatter {}

impl OsvNaming for SwiftFormatter {
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

    use deps_core::test_util::capture_tracing_output;

    #[test]
    fn test_format_version() {
        let fmt = SwiftFormatter;
        assert_eq!(
            fmt.format_version_for_text_edit(&ConcreteVersion::new("2.40.0")),
            "2.40.0"
        );
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
    fn test_package_url_rejection_logs_warn_rejected_value() {
        // #380 B3: the fallback-return-value tests above don't prove `warn_rejected_value`
        // actually fires — a refactor could delete the warn call and they would stay green.
        let fmt = SwiftFormatter;
        let output = capture_tracing_output(|| {
            let _ = fmt.package_url(&PackageName::new("../../etc/passwd"));
        });
        assert!(
            output.contains("is_valid_owner_repo"),
            "output was: {output}"
        );
        assert!(
            output.contains("swift package display formatting"),
            "output was: {output}"
        );
        assert!(
            !output.contains("etc/passwd"),
            "raw rejected value must not be logged: {output}"
        );
    }

    #[test]
    fn test_package_url_accepted_logs_no_warn() {
        let fmt = SwiftFormatter;
        let output = capture_tracing_output(|| {
            let _ = fmt.package_url(&PackageName::new("apple/swift-nio"));
        });
        assert!(output.is_empty(), "output was: {output}");
    }

    #[test]
    fn test_package_url_rejects_dot_segment() {
        // Regression for #357 M1: `is_valid_owner_repo` now shares
        // `crate::is_valid_github_identity` with `registry::validate_owner_repo`, so a
        // `..`/`.` repo or owner segment is rejected here too, not just on the
        // credential-bearing fetch path.
        let fmt = SwiftFormatter;
        assert_eq!(fmt.package_url(&PackageName::new("apple/..")), "");
        assert_eq!(fmt.package_url(&PackageName::new("apple/.")), "");
        assert_eq!(fmt.package_url(&PackageName::new("../repo")), "");
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
        assert!(
            fmt.version_satisfies_requirement(&ConcreteVersion::new("2.62.0"), ">=2.0.0, <3.0.0")
        );
        assert!(
            !fmt.version_satisfies_requirement(&ConcreteVersion::new("3.0.0"), ">=2.0.0, <3.0.0")
        );
        assert!(fmt.version_satisfies_requirement(&ConcreteVersion::new("1.4.2"), "=1.4.2"));
        assert!(!fmt.version_satisfies_requirement(&ConcreteVersion::new("1.4.3"), "=1.4.2"));
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
        assert!(
            fmt.version_satisfies_requirement(&ConcreteVersion::new("1.9.9"), ">=1.5.0, <2.0.0")
        );
        assert!(
            !fmt.version_satisfies_requirement(&ConcreteVersion::new("2.0.0"), ">=1.5.0, <2.0.0")
        );
        assert!(
            !fmt.version_satisfies_requirement(&ConcreteVersion::new("1.4.9"), ">=1.5.0, <2.0.0")
        );
    }

    #[test]
    fn test_version_satisfies_up_to_next_minor_range() {
        let fmt = SwiftFormatter;
        // upToNextMinor(from: "2.3.0") → ">=2.3.0, <2.4.0"
        assert!(
            fmt.version_satisfies_requirement(&ConcreteVersion::new("2.3.5"), ">=2.3.0, <2.4.0")
        );
        assert!(
            !fmt.version_satisfies_requirement(&ConcreteVersion::new("2.4.0"), ">=2.3.0, <2.4.0")
        );
        assert!(
            !fmt.version_satisfies_requirement(&ConcreteVersion::new("2.2.9"), ">=2.3.0, <2.4.0")
        );
    }

    #[test]
    fn test_version_satisfies_closed_range() {
        let fmt = SwiftFormatter;
        // "1.0.0"..."1.9.9" → ">=1.0.0, <=1.9.9"
        assert!(
            fmt.version_satisfies_requirement(&ConcreteVersion::new("1.9.9"), ">=1.0.0, <=1.9.9")
        );
        assert!(
            fmt.version_satisfies_requirement(&ConcreteVersion::new("1.0.0"), ">=1.0.0, <=1.9.9")
        );
        assert!(
            !fmt.version_satisfies_requirement(&ConcreteVersion::new("2.0.0"), ">=1.0.0, <=1.9.9")
        );
    }

    #[test]
    fn test_version_satisfies_invalid_version_returns_false() {
        let fmt = SwiftFormatter;
        assert!(
            !fmt.version_satisfies_requirement(&ConcreteVersion::new("not-a-version"), ">=1.0.0")
        );
    }

    #[test]
    fn test_version_satisfies_invalid_requirement_returns_false() {
        let fmt = SwiftFormatter;
        assert!(!fmt.version_satisfies_requirement(&ConcreteVersion::new("1.0.0"), "not-a-req"));
    }

    fn dep_with_url(name: &str, url: &str) -> SwiftDependency {
        use deps_core::parser::DependencySource;
        use tower_lsp_server::ls_types::{Position, Range};

        SwiftDependency {
            name: name.into(),
            name_range: Range::new(Position::new(0, 0), Position::new(0, 1)),
            version_req: Some(">=1.0.0".into()),
            version_range: None,
            version_literal: None,
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
        assert!(!fmt.version_satisfies_requirement(
            &ConcreteVersion::new("2.0.0-beta.1"),
            ">=1.0.0, <3.0.0"
        ));
    }

    #[test]
    fn test_osv_version_to_native_round_trips_through_own_parser() {
        // Critic S2 gate: `osv_version_to_native` is identity for Swift (OSV
        // SwiftURL records use plain semver), so the version it hands to
        // `format_version_for_text_edit` must itself satisfy the
        // requirement text that edit produces.
        let fmt = SwiftFormatter;
        let osv_version = "1.2.3";
        let native = fmt.osv_version_to_native(osv_version);
        assert_eq!(native, osv_version);
        let native = ConcreteVersion::new(native);
        let edit_text = fmt.format_version_for_text_edit(&native);
        assert!(fmt.version_satisfies_requirement(&native, &edit_text));
    }

    #[test]
    fn test_compile_requirement_satisfiable() {
        let fmt = SwiftFormatter;
        let matcher = fmt
            .compile_requirement(&VersionReq::new(">=1.5.0, <2.0.0"))
            .expect("valid semver requirement must compile");
        assert_eq!(matcher.matches(&ConcreteVersion::new("1.9.9")), Some(true));
        assert_eq!(matcher.matches(&ConcreteVersion::new("2.0.0")), Some(false));
    }

    #[test]
    fn test_compile_requirement_unparseable_requirement_returns_none() {
        let fmt = SwiftFormatter;
        assert!(
            fmt.compile_requirement(&VersionReq::new("not-a-req"))
                .is_none()
        );
    }

    #[test]
    fn test_compile_requirement_unparseable_candidate_is_skipped() {
        let fmt = SwiftFormatter;
        let matcher = fmt
            .compile_requirement(&VersionReq::new(">=1.0.0"))
            .unwrap();
        assert_eq!(
            matcher.matches(&ConcreteVersion::new("not-a-version")),
            None
        );
    }

    #[test]
    fn test_validate_package_name_accepts_owner_repo() {
        let fmt = SwiftFormatter;
        assert!(fmt.validate_package_name("apple/swift-nio").is_ok());
    }

    /// #402 critique C1: a `.package(path:)` dependency's name is the target directory's
    /// basename (see `deps_swift::parser`'s `RE_PATH` arm), never an `owner/repo` GitHub
    /// coordinate — it must not be flagged as an invalid package name.
    #[test]
    fn test_validate_package_name_accepts_bare_name_for_path_dependencies() {
        let fmt = SwiftFormatter;
        for name in ["MyLib", "my-package", "LocalPackage", "no-slash"] {
            assert!(
                fmt.validate_package_name(name).is_ok(),
                "expected {name:?} to be accepted"
            );
        }
    }

    /// #402: a structurally invalid Swift package name must be reported as an invalid
    /// package name, not forwarded to the registry lookup that produces the misleading
    /// generic "Registry lookup failed" diagnostic. Only multi-segment shapes are still
    /// checked against `owner/repo` — a bare name has no `/` to validate the shape of (see
    /// `test_validate_package_name_accepts_bare_name_for_path_dependencies`).
    #[test]
    fn test_validate_package_name_rejects_malformed_names() {
        let fmt = SwiftFormatter;
        for name in [
            "",
            ".",
            "..",
            "owner/repo/extra",
            "../../etc/passwd",
            "apple/..",
        ] {
            assert!(
                fmt.validate_package_name(name).is_err(),
                "expected {name:?} to be rejected"
            );
        }
    }
}
