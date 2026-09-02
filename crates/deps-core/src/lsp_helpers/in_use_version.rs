//! "What version does this dependency occurrence actually have" — shared by
//! `deps-lsp`'s registry-fetch/OSV-target pipeline and, for #394's S1 fix,
//! the yanked-diagnostic consistency check in [`super::diagnostics`].

use std::collections::HashMap;

use crate::lsp_helpers::EcosystemFormatter;
use crate::{ConcreteVersion, Dependency, EcosystemId, PackageName};

/// How a *bare* (no explicit pin marker) version requirement should be treated when
/// deciding whether it denotes a single concrete version.
///
/// Replaces a plain boolean (critique B2 of #208's plan) because neither `true` nor
/// `false` is correct for GitHub Actions: `AlwaysRange`/`Concrete` alone cannot express
/// "a bare `v4` is a range, but a bare `v4.2.0` is a pin" — the two forms share no
/// syntactic marker to distinguish them by, only the number of components present.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BareRequirementPolicy {
    /// A bare requirement is always a range under this ecosystem's own default
    /// semantics (Cargo's implicit caret, npm/Composer's implicit caret) — never
    /// treated as concrete without an explicit `=`/`==` pin marker.
    AlwaysRange,
    /// A bare requirement is concrete only when it has the shape of a full
    /// `major.minor.patch` version ([`is_full_semver_shape`]); a partial form (a bare
    /// major or major.minor, e.g. GitHub Actions' moving-major `v4` tag) is treated as
    /// a range instead, since it is one.
    ConcreteIfFullVersion,
    /// A bare requirement is already exact (no implicit range operator).
    Concrete,
}

/// Ecosystems whose *bare* (no explicit pin marker) version requirement is a
/// range under that ecosystem's own default semantics — Cargo's implicit
/// caret, npm/Composer's implicit caret. For these, [`is_concrete_version`]
/// requires an explicit `=`/`==` (or an exact-bracket wrap) before treating a
/// requirement as concrete; a bare `"1.2.3"` alone is not enough evidence
/// (critique C2).
///
/// Deno reuses npm's exact grammar for both its `jsr:` and `npm:` specifiers
/// (`DenoFormatter::compile_requirement` compiles both through the same
/// `node_semver::Range` npm itself uses), so it gets the same treatment here.
///
/// GitHub Actions gets [`BareRequirementPolicy::ConcreteIfFullVersion`]: a bare `v4`
/// (a moving-major tag) genuinely is a range, so it must not be queried as if it were
/// the concrete version `4`, but a bare `v4.2.0` is a pin — see
/// [`BareRequirementPolicy`]'s docs. A bare 40-character SHA also falls to the
/// `None` side of this gate ([`is_full_semver_shape`] rejects it), which is the
/// correct "honest unknown" outcome: resolving a SHA to its tag would need registry
/// access this pure function does not have.
///
/// Gradle is deliberately excluded: a bare Gradle coordinate version (e.g.
/// `"2.14.1"`) is an exact match under `GradleFormatter`'s own
/// `version_satisfies_requirement` unless it uses the `+` dynamic-version
/// suffix, which [`looks_like_a_single_version`] already rejects via its
/// reject-char set — Gradle has no implicit-caret default the way
/// Cargo/npm/Composer do.
const fn bare_requirement_policy(ecosystem: EcosystemId) -> BareRequirementPolicy {
    match ecosystem {
        EcosystemId::Cargo | EcosystemId::Npm | EcosystemId::Composer | EcosystemId::Deno => {
            BareRequirementPolicy::AlwaysRange
        }
        EcosystemId::GithubActions => BareRequirementPolicy::ConcreteIfFullVersion,
        _ => BareRequirementPolicy::Concrete,
    }
}

/// Whether `s` has the shape of a full `major.minor.patch` version.
///
/// An optional leading `v`/`V`, three dot-separated all-digit components, and an
/// optional SemVer-style prerelease/build suffix introduced by `-` or `+` (accepted,
/// but not itself validated beyond "starts here").
///
/// Hand-rolled rather than pulled in via the `regex` crate: this is consulted from
/// `bare_requirement_policy` in `deps-core`, the workspace's most-depended-on crate,
/// which has no `regex` dependency today — equivalent to the pattern
/// `^v?\d+\.\d+\.\d+(?:[-+].*)?$`. Shared verbatim by `deps-github-actions`'s
/// SHA-comment-tag parsing rule so the two mechanisms can never silently diverge on
/// what counts as a full version (e.g. `v4.2.0-beta.1` must be treated identically by
/// both).
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::is_full_semver_shape;
///
/// assert!(is_full_semver_shape("v4.2.0"));
/// assert!(is_full_semver_shape("4.2.0-beta.1"));
/// assert!(!is_full_semver_shape("v4"));
/// assert!(!is_full_semver_shape("v4.2"));
/// assert!(!is_full_semver_shape("not-a-version"));
/// ```
#[must_use]
pub fn is_full_semver_shape(s: &str) -> bool {
    let s = s.strip_prefix(['v', 'V']).unwrap_or(s);
    let core = match s.find(['-', '+']) {
        Some(idx) => &s[..idx],
        None => s,
    };
    let mut parts = core.split('.');
    let (Some(major), Some(minor), Some(patch), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    [major, minor, patch]
        .iter()
        .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
}

/// Returns `true` if `s` (already stripped of any pin marker) has the shape
/// of a single concrete version: non-empty, no wildcard/range-operator
/// character, and starting with a digit (after an optional `v`/`V` prefix,
/// e.g. Go's `v1.9.1`).
///
/// Deliberately conservative — see [`is_concrete_version`]'s doc for why a
/// false positive here is worse than a false negative.
fn looks_like_a_single_version(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    if s.contains([
        '^', '~', '*', '<', '>', ',', '|', '(', ')', '[', ']', ' ', '\t', ':', '+', 'x', 'X',
    ]) {
        return false;
    }
    let core = s.strip_prefix(['v', 'V']).unwrap_or(s);
    core.chars().next().is_some_and(|c| c.is_ascii_digit())
}

/// Returns the concrete version text `requirement` denotes, or `None` if
/// `requirement` is not the shape of a single concrete version.
///
/// Any pin marker (`=`/`==`, or a single-value bracket wrap like NuGet's
/// `[1.0.0]`) is stripped off. The only shape safe to query OSV with
/// directly, and, for #233, the only shape safe to compare against a real
/// registry version string in the yanked-version probe. A wrong answer here
/// is invisible in testing (OSV silently returns `{}` for a fabricated
/// version; the yanked probe silently finds no match), so getting this
/// right matters more than covering every ecosystem's full range grammar.
///
/// An explicit pin marker is always accepted, and its marker is stripped
/// from the returned text — required because PyPI's parser retains the
/// pep440 comparator in `Dependency::version_requirement()` (an exact pin
/// parses to `"==4.9.0"`, not `"4.9.0"`; confirmed by
/// `deps-pypi`'s `test_basic_pinned`), so comparing the *unstripped* text
/// against a real registry version string (`"4.9.0"`) would never match. A
/// *bare* requirement (no marker) is returned verbatim, and is accepted only
/// for ecosystems where a bare version is not itself a range by default
/// (critique C2) — see `bare_version_is_a_range`.
///
/// # Examples
///
/// ```
/// use deps_core::EcosystemId;
/// use deps_core::lsp_helpers::concrete_pin_version;
///
/// // An explicit pin marker is stripped, for any ecosystem.
/// assert_eq!(
///     concrete_pin_version("=1.2.3", EcosystemId::Cargo),
///     Some("1.2.3")
/// );
///
/// // Cargo's bare version is a caret range by default, not a pin.
/// assert_eq!(concrete_pin_version("1.2.3", EcosystemId::Cargo), None);
///
/// // Maven has no implicit range operator, so a bare version is exact.
/// assert_eq!(
///     concrete_pin_version("2.14.1", EcosystemId::Maven),
///     Some("2.14.1")
/// );
/// ```
pub fn concrete_pin_version(requirement: &str, ecosystem: EcosystemId) -> Option<&str> {
    let trimmed = requirement.trim();
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("latest") {
        return None;
    }

    let pinned = trimmed
        .strip_prefix("==")
        .or_else(|| trimmed.strip_prefix('='));
    let bracket_pinned = trimmed
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .filter(|inner| !inner.contains(','));

    match pinned.or(bracket_pinned) {
        Some(body) => looks_like_a_single_version(body).then_some(body),
        None => match bare_requirement_policy(ecosystem) {
            BareRequirementPolicy::AlwaysRange => None,
            BareRequirementPolicy::Concrete => {
                looks_like_a_single_version(trimmed).then_some(trimmed)
            }
            BareRequirementPolicy::ConcreteIfFullVersion => {
                is_full_semver_shape(trimmed).then_some(trimmed)
            }
        },
    }
}

/// Returns `true` if `requirement` denotes a single concrete version. See
/// [`concrete_pin_version`], whose boolean projection this is, for the
/// acceptance rules. Test-only: production code needs the stripped text
/// from `concrete_pin_version` itself, not just the boolean.
#[cfg(test)]
fn is_concrete_version(requirement: &str, ecosystem: EcosystemId) -> bool {
    concrete_pin_version(requirement, ecosystem).is_some()
}

/// The version of `dep` this project treats as actually in use.
///
/// The lock-file-resolved version, else the declared requirement when it is
/// already concrete ([`concrete_pin_version`]). `None` when neither applies.
///
/// A dependency whose manifest requirement is itself the resolved version
/// ([`crate::lsp_helpers::RequirementResolution::manifest_requirement_is_resolved_version`] — a Go
/// `require`-directive dependency) skips the lockfile step entirely, going
/// straight to the declared requirement (go.sum is unreliable there — a
/// checksum ledger that `go get`/`go build` only ever append to, so its
/// last-occurrence-wins parse can surface a version still recorded in the
/// file but no longer selected by Go's MVS). Shared by `deps-lsp`'s OSV
/// target selection, its yanked-version check, and the yanked-diagnostic
/// consistency check in [`super::diagnostics::generate_diagnostics_from_cache`]
/// (#394 S1) — all three need "what version does the user actually have"
/// for the same reason: querying a fabricated version produces a silent
/// false negative.
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::{
///     DiagnosticMessages, DiagnosticPolicy, OsvNaming, PackageNaming, PackageRendering,
///     RequirementResolution, SourcePolicy, in_use_version,
/// };
/// use deps_core::{ConcreteVersion, Dependency, EcosystemId, PackageName, VersionReq};
/// use std::any::Any;
/// use std::collections::HashMap;
/// use tower_lsp_server::ls_types::Range;
///
/// struct SimpleDep {
///     name: PackageName,
///     version_req: Option<VersionReq>,
/// }
///
/// impl Dependency for SimpleDep {
///     fn name(&self) -> &PackageName {
///         &self.name
///     }
///     fn name_range(&self) -> Range {
///         Range::default()
///     }
///     fn version_requirement(&self) -> Option<&VersionReq> {
///         self.version_req.as_ref()
///     }
///     fn version_range(&self) -> Option<Range> {
///         None
///     }
///     fn source(&self) -> deps_core::parser::DependencySource {
///         deps_core::parser::DependencySource::Registry
///     }
///     fn as_any(&self) -> &dyn Any {
///         self
///     }
/// }
///
/// struct SimpleFormatter;
/// impl PackageNaming for SimpleFormatter {}
/// impl PackageRendering for SimpleFormatter {
///     fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
///         version.to_string()
///     }
///     fn package_url(&self, name: &PackageName) -> String {
///         name.to_string()
///     }
/// }
/// impl RequirementResolution for SimpleFormatter {}
/// impl DiagnosticMessages for SimpleFormatter {}
/// impl DiagnosticPolicy for SimpleFormatter {}
/// impl SourcePolicy for SimpleFormatter {}
/// impl OsvNaming for SimpleFormatter {}
///
/// let dep = SimpleDep {
///     name: PackageName::new("time"),
///     version_req: Some(VersionReq::new("=0.1.43")),
/// };
/// let resolved_versions: HashMap<PackageName, ConcreteVersion> = HashMap::new();
///
/// // No lock file, but the requirement is already an exact pin — falls
/// // back to it, stripped of its `=` marker.
/// assert_eq!(
///     in_use_version(&dep, "time", &resolved_versions, &SimpleFormatter, EcosystemId::Cargo),
///     Some("0.1.43".to_string())
/// );
/// ```
pub fn in_use_version(
    dep: &dyn Dependency,
    normalized_name: &str,
    resolved_versions: &HashMap<PackageName, ConcreteVersion>,
    formatter: &dyn EcosystemFormatter,
    ecosystem: EcosystemId,
) -> Option<String> {
    if formatter.manifest_requirement_is_resolved_version(dep) {
        dep.version_requirement()
            .and_then(|req| concrete_pin_version(req.as_str(), ecosystem))
            .map(str::to_string)
    } else {
        resolved_versions
            .get(normalized_name)
            .or_else(|| resolved_versions.get(dep.name()))
            .map(ConcreteVersion::to_string)
            .or_else(|| {
                dep.version_requirement()
                    .and_then(|req| concrete_pin_version(req.as_str(), ecosystem))
                    .map(str::to_string)
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_concrete_version_accepts_explicit_pins_in_any_ecosystem() {
        for eco in [EcosystemId::Cargo, EcosystemId::Npm, EcosystemId::Go] {
            assert!(is_concrete_version("=1.2.3", eco), "{eco:?}");
        }
        // Go's go.mod bare `v1.9.1` style: Go is not in the
        // range-default set, so the bare form (with its `v` prefix) is
        // accepted without needing an explicit `=`.
        assert!(is_concrete_version("v1.9.1", EcosystemId::Go));
    }

    #[test]
    fn is_concrete_version_pep440_double_equals_is_a_pin() {
        // Critique C2: `strip_prefix('=')` alone turns PEP 440 `"==2.28.0"`
        // into `"=2.28.0"`, whose first char then fails the digit check.
        assert!(is_concrete_version("==2.28.0", EcosystemId::Pypi));
    }

    #[test]
    fn is_concrete_version_bare_digit_accepted_for_non_range_default_ecosystems() {
        // Maven/Go/Bundler/Dart/Gradle/NuGet: a bare version is already
        // exact (or, for NuGet's PackageReference floor, resolves to
        // exactly that version in practice). Gradle in particular has no
        // implicit-caret default for a plain coordinate version like
        // `"2.14.1"` — only the `+` dynamic-version suffix is a range,
        // and that's rejected separately by `looks_like_a_single_version`.
        for eco in [
            EcosystemId::Maven,
            EcosystemId::Go,
            EcosystemId::Bundler,
            EcosystemId::Dart,
            EcosystemId::Gradle,
            EcosystemId::NuGet,
        ] {
            assert!(is_concrete_version("2.14.1", eco), "{eco:?}");
        }
    }

    #[test]
    fn is_concrete_version_bare_digit_rejected_for_range_default_ecosystems() {
        // Critique C2: Cargo's bare "1.2.3" is a caret range under
        // Cargo's own default operator, not a pin — same for npm and
        // Composer's implicit range notations. Deno reuses npm's exact
        // grammar for both `jsr:` and `npm:` requirements, so it gets the
        // same treatment (`bare_version_is_a_range`'s doc comment).
        for eco in [
            EcosystemId::Cargo,
            EcosystemId::Npm,
            EcosystemId::Composer,
            EcosystemId::Deno,
        ] {
            assert!(!is_concrete_version("1.2.3", eco), "{eco:?}");
            // ...but an explicit pin is still accepted.
            assert!(is_concrete_version("=1.2.3", eco), "{eco:?}");
        }
    }

    #[test]
    fn is_concrete_version_rejects_partials_and_wildcards() {
        // Critique C2: npm/Composer "1.x"/"1.2.x" and bare partials like
        // "1.2" are ranges, and Gradle's "1.+" is a dynamic version —
        // none of these contained a previously-rejected character.
        for eco in [EcosystemId::Npm, EcosystemId::Composer] {
            assert!(!is_concrete_version("1.x", eco), "{eco:?}");
            assert!(!is_concrete_version("1.2.x", eco), "{eco:?}");
            assert!(!is_concrete_version("1.2", eco), "{eco:?}");
        }
        assert!(!is_concrete_version("1.+", EcosystemId::Gradle));
    }

    #[test]
    fn is_concrete_version_rejects_ranges_and_wildcards() {
        for eco in [EcosystemId::Maven, EcosystemId::Go] {
            assert!(!is_concrete_version("^1.0", eco));
            assert!(!is_concrete_version("~1.2", eco));
            assert!(!is_concrete_version("*", eco));
            assert!(!is_concrete_version(">=1.0", eco));
            assert!(!is_concrete_version(">=1.0 <2.0", eco));
            assert!(!is_concrete_version("1.0.*", eco));
            assert!(!is_concrete_version("", eco));
        }
    }

    #[test]
    fn is_concrete_version_rejects_non_version_schemes() {
        let eco = EcosystemId::Go;
        assert!(!is_concrete_version("latest", eco));
        assert!(!is_concrete_version("github:user/repo", eco));
        assert!(!is_concrete_version("file:../x", eco));
        assert!(!is_concrete_version("main", eco));
    }

    #[test]
    fn concrete_pin_version_strips_pep440_double_equals_comparator() {
        // Regression guard: PyPI's parser retains the pep440 comparator
        // in `version_requirement().as_str()` (`"==4.9.0"`, not
        // `"4.9.0"` — confirmed by deps-pypi's `test_basic_pinned`). The
        // verbatim string was silently unusable against real registry
        // version strings in the yanked probe; `concrete_pin_version`
        // must strip it.
        assert_eq!(
            concrete_pin_version("==4.9.0", EcosystemId::Pypi),
            Some("4.9.0")
        );
    }

    #[test]
    fn concrete_pin_version_strips_single_equals_and_bracket_pins() {
        assert_eq!(
            concrete_pin_version("=1.2.3", EcosystemId::Cargo),
            Some("1.2.3")
        );
        assert_eq!(
            concrete_pin_version("[1.0.0]", EcosystemId::NuGet),
            Some("1.0.0")
        );
    }

    #[test]
    fn concrete_pin_version_bare_version_returned_verbatim() {
        // No operator to strip: Maven/Go/Bundler/Dart/Gradle/NuGet treat
        // a bare version as already exact.
        assert_eq!(
            concrete_pin_version("2.14.1", EcosystemId::Maven),
            Some("2.14.1")
        );
    }

    #[test]
    fn concrete_pin_version_rejects_ranges_and_partials() {
        assert_eq!(concrete_pin_version("^1.0", EcosystemId::Cargo), None);
        assert_eq!(concrete_pin_version("1.2.3", EcosystemId::Cargo), None);
        assert_eq!(concrete_pin_version(">=1.0,<2.0", EcosystemId::Pypi), None);
    }

    // --- is_full_semver_shape ---

    #[test]
    fn is_full_semver_shape_accepts_full_versions_with_and_without_v_prefix() {
        assert!(is_full_semver_shape("4.2.0"));
        assert!(is_full_semver_shape("v4.2.0"));
        assert!(is_full_semver_shape("V4.2.0"));
    }

    #[test]
    fn is_full_semver_shape_accepts_prerelease_and_build_suffixes() {
        assert!(is_full_semver_shape("v4.2.0-beta.1"));
        assert!(is_full_semver_shape("4.2.0+build.5"));
    }

    #[test]
    fn is_full_semver_shape_rejects_partial_versions() {
        assert!(!is_full_semver_shape("v4"));
        assert!(!is_full_semver_shape("v4.2"));
    }

    #[test]
    fn is_full_semver_shape_rejects_non_version_and_sha_shapes() {
        assert!(!is_full_semver_shape("main"));
        assert!(!is_full_semver_shape(
            "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
        ));
        assert!(!is_full_semver_shape(""));
        assert!(!is_full_semver_shape("4.2.0.1"));
        assert!(!is_full_semver_shape("4..0"));
    }

    // --- concrete_pin_version: BareRequirementPolicy::ConcreteIfFullVersion (GitHub Actions) ---

    #[test]
    fn concrete_pin_version_github_actions_full_bare_tag_is_concrete() {
        assert_eq!(
            concrete_pin_version("v4.2.0", EcosystemId::GithubActions),
            Some("v4.2.0")
        );
    }

    #[test]
    fn concrete_pin_version_github_actions_moving_major_tag_is_a_range() {
        // `v4` genuinely is a range (a moving major tag) — must not be queried as if
        // it were the concrete version `4` (critique B2).
        assert_eq!(concrete_pin_version("v4", EcosystemId::GithubActions), None);
        assert_eq!(
            concrete_pin_version("v4.2", EcosystemId::GithubActions),
            None
        );
    }

    #[test]
    fn concrete_pin_version_github_actions_bare_sha_is_not_concrete() {
        // A bare SHA has no dots, so it fails `is_full_semver_shape` and falls to the
        // honest "unknown" `None` rather than being queried as a fabricated version.
        assert_eq!(
            concrete_pin_version(
                "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
                EcosystemId::GithubActions
            ),
            None
        );
    }
}
