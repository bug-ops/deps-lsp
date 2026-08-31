//! "What version does this dependency occurrence actually have" — shared by
//! `deps-lsp`'s registry-fetch/OSV-target pipeline and, for #394's S1 fix,
//! the yanked-diagnostic consistency check in [`super::diagnostics`].

use std::collections::HashMap;

use crate::lsp_helpers::EcosystemFormatter;
use crate::{Dependency, EcosystemId, PackageName};

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
/// Gradle is deliberately excluded: a bare Gradle coordinate version (e.g.
/// `"2.14.1"`) is an exact match under `GradleFormatter`'s own
/// `version_satisfies_requirement` unless it uses the `+` dynamic-version
/// suffix, which [`looks_like_a_single_version`] already rejects via its
/// reject-char set — Gradle has no implicit-caret default the way
/// Cargo/npm/Composer do.
const fn bare_version_is_a_range(ecosystem: EcosystemId) -> bool {
    matches!(
        ecosystem,
        EcosystemId::Cargo | EcosystemId::Npm | EcosystemId::Composer | EcosystemId::Deno
    )
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
        None if bare_version_is_a_range(ecosystem) => None,
        None => looks_like_a_single_version(trimmed).then_some(trimmed),
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
/// ([`EcosystemFormatter::manifest_requirement_is_resolved_version`] — a Go
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
/// use deps_core::lsp_helpers::{EcosystemFormatter, in_use_version};
/// use deps_core::{Dependency, EcosystemId, PackageName, VersionReq};
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
/// impl EcosystemFormatter for SimpleFormatter {
///     fn format_version_for_text_edit(&self, version: &str) -> String {
///         version.to_string()
///     }
///     fn package_url(&self, name: &PackageName) -> String {
///         name.to_string()
///     }
/// }
///
/// let dep = SimpleDep {
///     name: PackageName::new("time"),
///     version_req: Some(VersionReq::new("=0.1.43")),
/// };
/// let resolved_versions = HashMap::new();
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
    resolved_versions: &HashMap<PackageName, String>,
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
            .cloned()
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
}
