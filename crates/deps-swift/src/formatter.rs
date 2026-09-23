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

/// Whether `requirement` contains an unresolved Swift string-interpolation placeholder
/// (`\(...)`), e.g. `.package(url: ..., from: "\(v)")`. `deps-swift`'s parser does not degrade
/// this shape to `version_requirement: None`, so it reaches [`RequirementResolution`] and
/// [`PackageRendering`] directly — issue #1354 security audit: `compile_requirement` returns
/// `None` for it already (the interpolated text fails `semver::VersionReq::parse`), but
/// nothing previously stopped `format_version_replacing` from planning a destructive
/// `"9.9.9"`-literal rewrite over the interpolation. Mirrors `NuGetFormatter`'s `$(Property)`
/// guard (#1352).
fn requirement_contains_unresolved_interpolation(requirement: &str) -> bool {
    requirement.contains("\\(")
}

/// Returns `true` if `name` matches the `owner/repo` GitHub identifier pattern.
///
/// Delegates to [`crate::is_valid_github_identity`], shared with `registry`'s
/// credential-bearing fetch-URL gate, so a `.`/`..` segment is rejected here too (#357 M1) —
/// otherwise this display-URL gate could still render `https://github.com/apple/..`.
fn is_valid_owner_repo(name: &str) -> bool {
    crate::is_valid_github_identity(name)
}

/// Returns `true` when `name` parses as a URL (HTTPS or `git@host:path` SSH form) whose
/// host is present but is not GitHub's.
///
/// `parser::resolve_registry_source` (#979/#982) sets a registry-form dependency's
/// `dep.name()` to its raw URL when that URL's host isn't GitHub, tagging the dependency
/// `DependencySource::Git` instead of `Registry`. `validate_package_name` sees only that
/// raw string, so this reuses [`crate::parser::parse_git_url`] — the same URL
/// normalization+parse step [`crate::parser::url_to_identity`] uses — and
/// [`crate::is_github_host`], the same host predicate #982 uses to decide the `Git`
/// tagging, rather than re-deriving either from scratch here and drifting out of sync
/// (#983 critic S2: a from-scratch `reqwest::Url::parse` on the raw string would miss the
/// SSH form, since it has no URL scheme).
fn is_non_github_registry_url(name: &str) -> bool {
    crate::parser::parse_git_url(name).is_some_and(|url| {
        url.host_str()
            .is_some_and(|host| !crate::is_github_host(host))
    })
}

/// Formatter for Swift/SPM ecosystem LSP responses.
pub struct SwiftFormatter;

impl PackageNaming for SwiftFormatter {
    fn normalize_package_name(&self, name: &PackageName) -> String {
        name.as_str().to_lowercase()
    }

    /// Accepts `is_valid_owner_repo`'s `owner/repo` GitHub identifier shape (the same one
    /// `package_url` and the registry's fetch-URL gate require), a bare single-segment name
    /// with no `/`, or a URL on a non-GitHub host.
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
    /// dependency (#402 critique C1).
    ///
    /// The non-GitHub-host-URL case (#983) follows the exact same precedent, applied to
    /// `resolve_registry_source`'s raw-URL fallback name for a non-GitHub registry-form
    /// dependency (`DependencySource::Git`, per PR #982): this crate's `can_resolve_source`
    /// (default, unoverridden — see `deps-github-actions::formatter::GithubActionsFormatter`'s
    /// analogous override for the same pattern) already treats that source as non-resolvable,
    /// so returning `Err` here — even with a reworded reason — would still surface a WARNING
    /// diagnostic implying the manifest itself is wrong. Accepting it instead means no
    /// diagnostic fires at all, consistent with how every other non-resolvable source in this
    /// codebase is handled silently.
    ///
    /// A multi-segment name that is neither the `owner/repo` shape nor a parseable URL (extra
    /// segment, disallowed character, or a `.`/`..` segment) still fails and is rejected, same
    /// as before.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidPackageName`] when `name` is empty, is exactly `.`/`..`, or contains a
    /// `/` without matching the `owner/repo` shape and without parsing as a non-GitHub-host
    /// URL.
    fn validate_package_name(&self, name: &str) -> Result<(), InvalidPackageName> {
        let bare_name_ok = !name.contains('/') && !name.is_empty() && !is_dot_segment(name);
        if is_valid_owner_repo(name) || bare_name_ok || is_non_github_registry_url(name) {
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
            format!("https://github.com/{}", name.as_str())
        } else {
            warn_rejected_value(
                "is_valid_owner_repo",
                "swift package display formatting",
                name.as_str(),
            );
            String::new()
        }
    }

    /// #1354 hardening: an unresolved Swift string interpolation (see
    /// `requirement_contains_unresolved_interpolation`) in `current` leaves `current`
    /// unchanged instead of substituting `version`, so a vulnerability-fix or "update to
    /// latest" edit can never hardcode a literal version over `\(...)` — mirrors
    /// `NuGetFormatter::format_version_replacing`'s `$(Property)` guard.
    ///
    /// Not sufficient on its own for Swift — see [`Self::format_version_replacing_for`]'s doc
    /// (#1354 critic S1) for why the dependency-aware override below is the one every real
    /// caller actually reaches.
    fn format_version_replacing(&self, version: &ConcreteVersion, current: &str) -> String {
        if requirement_contains_unresolved_interpolation(current) {
            return current.to_string();
        }
        self.format_version_for_text_edit(version)
    }

    /// #1354 critic S1: both production callers
    /// (`lsp_helpers::code_actions::build_vulnerability_fix_action`, `deps-cli`'s
    /// `update::security`) pass the *declared requirement string* as `current`, never
    /// `dep.version_literal()`. For a synthesized comparator like `from: "\(v)"`'s
    /// `">=\(v), <1.0.0"`, [`Self::format_version_replacing`]'s guard leaves `current` itself
    /// unchanged — but `plan_vulnerability_fix`'s no-op guard compares that result against
    /// `dep.version_literal()` (the narrower `\(v)` span actually spliced into the manifest),
    /// not against `current`. A `current`-echoing no-op therefore still reads as a genuine
    /// rewrite there and gets spliced in as `">=\(v), <1.0.0"` over the bare `\(v)` literal,
    /// corrupting the manifest. Returning the literal itself (when either `current` or the
    /// literal is unresolved) makes the two compare equal, so the planner correctly no-ops —
    /// and, as a side effect, makes every REFACTOR "Update to X" candidate for this dependency
    /// dedup away against the unchanged literal too, closing S3 (a bogus REFACTOR action with
    /// text `">=\(v), <1.0.0"`) for free.
    fn format_version_replacing_for(
        &self,
        dep: &dyn Dependency,
        version: &ConcreteVersion,
        current: &str,
    ) -> String {
        let literal = dep.version_literal();
        let unresolved = requirement_contains_unresolved_interpolation(current)
            || literal.is_some_and(requirement_contains_unresolved_interpolation);
        if unresolved {
            return literal.unwrap_or(current).to_string();
        }
        self.format_version_replacing(version, current)
    }
}

impl RequirementResolution for SwiftFormatter {
    /// #1354 hardening: an unresolved requirement (see [`Self::requirement_is_unresolved`])
    /// returns `true` (treated as satisfied) rather than falling into `semver::VersionReq`
    /// parsing, which already fails closed for this shape but without the explicit
    /// classification `requirement_status`/`Unresolved` needs — mirrors `NuGetFormatter`'s
    /// identical guard.
    fn version_satisfies_requirement(&self, version: &ConcreteVersion, requirement: &str) -> bool {
        if self.requirement_is_unresolved(&VersionReq::new(requirement)) {
            return true;
        }
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
    ///
    /// #1354: an unresolved interpolation (see [`Self::requirement_is_unresolved`]) is
    /// checked explicitly first rather than relying on `semver::VersionReq::parse` to keep
    /// failing on it — defense-in-depth against a future interpolation spelling that happens
    /// to parse as valid semver syntax.
    fn compile_requirement(&self, requirement: &VersionReq) -> Option<Box<dyn RequirementMatcher>> {
        if self.requirement_is_unresolved(requirement) {
            return None;
        }
        requirement
            .as_str()
            .parse::<semver::VersionReq>()
            .ok()
            .map(|req| Box::new(SemverMatcher(req)) as Box<dyn RequirementMatcher>)
    }

    /// #1354: an unexpanded Swift string-interpolation placeholder (`\(...)`) inside a
    /// requirement — see `requirement_contains_unresolved_interpolation`.
    fn requirement_is_unresolved(&self, requirement: &VersionReq) -> bool {
        requirement_contains_unresolved_interpolation(requirement.as_str())
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
        host.host_str()
            .is_some_and(crate::is_github_host)
            .then(|| format!("github.com/{}", dep.name().as_str()))
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

    /// #1203 side effect (critic note): `SwiftFormatter` never overrode
    /// `suppress_package_url`, so a `.branch(...)`/`.revision(...)`/`.package(path: ...)`
    /// dependency's hover previously still rendered a github.com heading link even though
    /// `can_resolve_source` already correctly refused to fetch its version data — flipping
    /// `PackageRendering::suppress_package_url`'s default polarity fixes this for Swift with
    /// no crate-local change. Pinned here since it was previously untested.
    #[test]
    fn test_suppress_package_url_true_for_git_source() {
        use deps_core::parser::DependencySource;

        let fmt = SwiftFormatter;
        assert!(fmt.suppress_package_url(&DependencySource::Git {
            url: "https://github.com/dev/tool".into(),
            rev: Some("main".into()),
        }));
        assert!(!fmt.suppress_package_url(&DependencySource::Registry));
    }

    // #758: exact-value `EcosystemFormatter` conformance, replacing test_package_url,
    // test_package_url_invalid_returns_empty, test_package_url_rejects_dot_segment,
    // test_validate_package_name_accepts_owner_repo,
    // test_validate_package_name_accepts_bare_name_for_path_dependencies,
    // test_validate_package_name_rejects_malformed_names, test_version_satisfies,
    // test_version_satisfies_invalid_version_returns_false, and
    // test_version_satisfies_invalid_requirement_returns_false. `test_version_satisfies_up_to_next_major_range`/
    // `_minor_range`/`_closed_range`/`_prerelease` stay hand-written: they document SPM's
    // `upToNextMajor`/`upToNextMinor`/closed-range syntax translation, not simple literal
    // roundtrips.
    deps_core::formatter_conformance! {
        mod swift_formatter_conformance;
        build: SwiftFormatter;
        package_url: {
            "apple/swift-nio" => "https://github.com/apple/swift-nio",
            "../../etc/passwd" => "",
            "no-slash" => "",
            "owner/repo/extra" => "",
            "apple/.." => "",
            "apple/." => "",
            "../repo" => "",
        };
        accepts: [
            "apple/swift-nio", "MyLib", "my-package", "LocalPackage", "no-slash",
            "https://gitlab.com/myorg/myrepo", "git@gitlab.com:myorg/myrepo.git"
        ];
        rejects: ["", ".", "..", "owner/repo/extra", "../../etc/passwd", "apple/.."];
        version_roundtrip: [
            "2.62.0", ">=2.0.0, <3.0.0" => true,
            "3.0.0", ">=2.0.0, <3.0.0" => false,
            "1.4.2", "=1.4.2" => true,
            "1.4.3", "=1.4.2" => false,
            "not-a-version", ">=1.0.0" => false,
            "1.0.0", "not-a-req" => false
        ];
        hostile_package_url_expected: "";
    }

    // #782 critic M2: the former hand-written test_package_url_hostile_display_link_payload_returns_empty
    // is now generated by `formatter_conformance!` above (`hostile_package_url_expected: "";`,
    // -> `formatter_package_url_hostile_input_expected`), which pins the same exact value.

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
    fn test_validate_package_name_non_github_host_url_accepted() {
        // #983 critic S1: `apply_unknown_package_rule` wraps any `Err` reason as
        // "Invalid package name '<url>': {reason}" regardless of wording, so a non-GitHub
        // registry-form dependency's raw URL must return `Ok(())` — no diagnostic at all —
        // rather than a differently-worded `Err`, which would still misleadingly imply the
        // URL itself is malformed.
        let fmt = SwiftFormatter;
        assert!(
            fmt.validate_package_name("https://gitlab.com/myorg/myrepo")
                .is_ok()
        );
    }

    #[test]
    fn test_validate_package_name_non_github_ssh_host_url_accepted() {
        // #983 critic S2: the SCP-style SSH form (`git@host:path`, no URL scheme) must be
        // recognized too — `parser::parse_git_url` normalizes it before parsing, shared
        // with `url_to_identity`, so this can't silently regress to the malformed-name
        // branch the way a from-scratch `reqwest::Url::parse(name)` would.
        let fmt = SwiftFormatter;
        assert!(
            fmt.validate_package_name("git@gitlab.com:myorg/myrepo.git")
                .is_ok()
        );
    }

    #[test]
    fn test_validate_package_name_malformed_name_keeps_owner_repo_message() {
        // A genuinely malformed name (not a URL at all) must keep the original wording —
        // the #983 fix only changes behavior for the non-GitHub-host-URL case.
        let fmt = SwiftFormatter;
        let err = fmt
            .validate_package_name("owner/repo/extra")
            .expect_err("multi-segment name must still be rejected");
        assert_eq!(
            err.reason(),
            "name must be a GitHub 'owner/repo' identifier"
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
    fn test_normalize_package_name() {
        let fmt = SwiftFormatter;
        assert_eq!(
            fmt.normalize_package_name(&PackageName::new("Apple/Swift-NIO")),
            "apple/swift-nio"
        );
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

    fn dep_with_url(name: &str, url: &str) -> SwiftDependency {
        use deps_core::parser::DependencySource;
        use deps_core::position::{Position, Range};

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

    // --- #1354: unresolved Swift interpolation (`\(...)`) must never be rewritten ---

    #[test]
    fn test_requirement_is_unresolved_swift_interpolation() {
        let fmt = SwiftFormatter;
        assert!(fmt.requirement_is_unresolved(&VersionReq::new(">=\\(v), <1.0.0")));
        assert!(!fmt.requirement_is_unresolved(&VersionReq::new(">=1.5.0, <2.0.0")));
    }

    #[test]
    fn test_compile_requirement_none_for_unresolved_interpolation() {
        let fmt = SwiftFormatter;
        assert!(
            fmt.compile_requirement(&VersionReq::new(">=\\(v), <1.0.0"))
                .is_none()
        );
    }

    #[test]
    fn test_version_satisfies_requirement_unresolved_interpolation_returns_true() {
        let fmt = SwiftFormatter;
        assert!(
            fmt.version_satisfies_requirement(&ConcreteVersion::new("1.2.3"), ">=\\(v), <1.0.0")
        );
    }

    #[test]
    fn test_format_version_replacing_guards_unresolved_interpolation() {
        let fmt = SwiftFormatter;
        assert_eq!(
            fmt.format_version_replacing(&ConcreteVersion::new("9.9.9"), "\\(v)"),
            "\\(v)"
        );
        assert_eq!(
            fmt.format_version_replacing(&ConcreteVersion::new("9.9.9"), "1.5.0"),
            "9.9.9"
        );
    }

    /// #1354 critic S1: reproduces the exact shape `from:` produces — `current` is the
    /// synthesized comparator (`">=\(v), <1.0.0"`, what real callers pass), and
    /// `version_literal` is the narrower raw span (`"\(v)"`) actually spliced into the
    /// manifest. `format_version_replacing_for` must return the *literal*, not `current`
    /// unchanged — otherwise `plan_vulnerability_fix`'s no-op guard (which compares against
    /// `version_literal`) still sees a difference and plans a destructive rewrite.
    #[test]
    fn test_format_version_replacing_for_returns_literal_not_synthesized_current() {
        use deps_core::parser::DependencySource;
        use deps_core::position::{Position, Range};

        let fmt = SwiftFormatter;
        let dep = SwiftDependency {
            name: "apple/swift-nio".into(),
            name_range: Range::new(Position::new(0, 0), Position::new(0, 1)),
            version_req: Some(">=\\(v), <1.0.0".into()),
            version_range: None,
            version_literal: Some("\\(v)".to_string()),
            url: "https://github.com/apple/swift-nio".to_string(),
            source: DependencySource::Registry,
        };
        let current = dep.version_req.as_ref().unwrap().as_str();
        let rewritten =
            fmt.format_version_replacing_for(&dep, &ConcreteVersion::new("2.40.0"), current);
        assert_eq!(
            rewritten, "\\(v)",
            "must reproduce the literal span, not echo the synthesized requirement back"
        );
    }

    /// A resolved (non-interpolated) dependency is unaffected by the S1 override — it still
    /// falls through to the ordinary `format_version_replacing` substitution.
    #[test]
    fn test_format_version_replacing_for_resolved_dependency_still_substitutes() {
        use deps_core::parser::DependencySource;
        use deps_core::position::{Position, Range};

        let fmt = SwiftFormatter;
        let dep = SwiftDependency {
            name: "apple/swift-nio".into(),
            name_range: Range::new(Position::new(0, 0), Position::new(0, 1)),
            version_req: Some(">=1.5.0, <2.0.0".into()),
            version_range: None,
            version_literal: Some("1.5.0".to_string()),
            url: "https://github.com/apple/swift-nio".to_string(),
            source: DependencySource::Registry,
        };
        let rewritten =
            fmt.format_version_replacing_for(&dep, &ConcreteVersion::new("2.40.0"), "1.5.0");
        assert_eq!(rewritten, "2.40.0");
    }

    /// #1354 security audit: exercises `deps_core::edit::plan_vulnerability_fix` with the
    /// *real* `SwiftFormatter` (not a hand-rolled mock) and a `SwiftDependency` obtained from
    /// the real `crate::parser::parse_package_swift` path, on a vulnerable package whose
    /// declared `from:` bound is an unexpanded Swift string interpolation — mirrors
    /// `deps-nuget`'s `test_plan_vulnerability_fix_with_real_formatter_and_parsed_dependency`
    /// (#1352) and `deps-bundler`'s equivalent (#1354).
    ///
    /// `compile_requirement` already returns `None` here (the interpolated text fails
    /// `semver::VersionReq::parse`), but nothing previously stopped
    /// `format_version_replacing` from planning a destructive rewrite once
    /// `plan_vulnerability_fix`'s no-op guard compared the synthesized literal against it.
    ///
    /// #1354 critic S1/S2: `current` is `dep.version_requirement()` (the synthesized
    /// `">=\(v), <1.0.0"` comparator `from:` produces), exactly as both production callers
    /// (`lsp_helpers::code_actions::build_vulnerability_fix_action`, `deps-cli`'s
    /// `update::security`) call this — passing `dep.version_literal()` (`\(v)`) instead would
    /// mask a real bug: it differs from what real callers pass, so a formatter whose
    /// `format_version_replacing_for` only echoes `current` back unchanged (not the narrower
    /// literal) would pass this test despite still corrupting the manifest on the real path.
    #[test]
    fn test_plan_vulnerability_fix_unresolved_interpolation_skips_via_no_op_rewrite() {
        use deps_core::ParseResult;
        use deps_core::edit::plan_vulnerability_fix;
        use deps_core::osv::{
            Advisory, Capped, DependencyVulnerabilities, UpgradeStatus, VulnSeverity,
        };

        let manifest = r#".package(url: "https://github.com/apple/swift-nio", from: "\(v)")"#;
        let uri = deps_core::test_util::test_uri("/test/Package.swift");
        let result = crate::parser::parse_package_swift(manifest, &uri).expect("valid manifest");
        let deps = result.dependencies();
        let dep = deps.first().expect("one dependency parsed");
        let current = dep
            .version_requirement()
            .expect("from: synthesizes a version requirement")
            .as_str();
        assert_eq!(current, ">=\\(v), <1.0.0");
        assert_eq!(dep.version_literal(), Some("\\(v)"));

        let advisory = std::sync::Arc::new(
            Advisory::new(
                "GHSA-test-0003".to_string(),
                "2024-01-01T00:00:00Z".to_string(),
                VulnSeverity::High,
            )
            .expect("valid osv id")
            .with_fixed_versions(vec!["2.40.0".to_string()]),
        );
        let dv = DependencyVulnerabilities::new(Capped::new(vec![advisory], 1))
            .with_fix_target_status(UpgradeStatus::CandidateClean {
                version: "2.40.0".to_string(),
            });

        let planned = plan_vulnerability_fix(
            *dep,
            deps_core::position::Range::default(),
            current,
            &dv,
            &SwiftFormatter,
        );

        // `NoOpRewrite`, not `RequirementAlreadyResolves`: `compile_requirement` is `None`
        // here (undecidable, guarded by `requirement_is_unresolved`), so
        // `requirement_already_resolves_to`'s default gate never short-circuits — it's
        // `format_version_replacing_for`'s S1 override, reproducing `version_literal`
        // unchanged, that makes the planner's textual no-op check fire.
        assert_eq!(
            planned,
            Err(deps_core::edit::VulnFixSkip::NoOpRewrite),
            "the real SwiftFormatter must suppress the fix for an unresolved interpolation via \
             NoOpRewrite, got {planned:?}"
        );
    }
}
