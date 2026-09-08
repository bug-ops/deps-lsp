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
    /// semantics (Cargo's implicit caret) — never treated as concrete without an
    /// explicit `=`/`==` pin marker.
    AlwaysRange,
    /// A bare requirement is concrete only when it has the shape of a full
    /// `major.minor.patch` version ([`is_full_semver_shape`]); a partial form (a bare
    /// major or major.minor, e.g. GitHub Actions' moving-major `v4` tag, or npm's
    /// bare `"4.17"`) is treated as a range instead, since it is one.
    ConcreteIfFullVersion,
    /// A bare requirement is already exact (no implicit range operator).
    Concrete,
}

/// Ecosystems whose *bare* (no explicit pin marker) version requirement is
/// unconditionally a range under that ecosystem's own default semantics —
/// Cargo's implicit caret. For these, [`is_concrete_version`] requires an
/// explicit `=`/`==` (or an exact-bracket wrap) before treating a requirement
/// as concrete; a bare `"1.2.3"` alone is not enough evidence (critique C2).
///
/// Deno reuses npm's exact grammar for both its `jsr:` and `npm:` specifiers
/// (`DenoFormatter::compile_requirement` compiles both through the same
/// `node_semver::Range` npm itself uses), so — unlike Cargo — a bare Deno
/// requirement is genuinely **not** unconditionally a range either; it stays
/// `AlwaysRange` here anyway, deliberately conservative rather than
/// following npm/Composer into `ConcreteIfFullVersion` in this PR
/// (impl-critic #664 review, finding S2, corrects an earlier draft of this
/// comment that asserted the opposite rationale — that Deno's lack of a
/// resolved-version concept made the fix low-value for it; the code says the
/// reverse: `deps-deno` has **no lockfile support at all**
/// (`crates/deps-deno/src/ecosystem.rs`'s `LockFileProvider` is unimplemented
/// for Deno), so `concrete_pin_version` is the *only* possible source of an
/// in-use version for any Deno dependency — a `deno.json` `"npm:express@4.17.0"`
/// import parses to the bare requirement `"4.17.0"`, and with `AlwaysRange`
/// that requirement can never resolve to a concrete version, so **no Deno
/// dependency ever receives an OSV scan, under any manifest**, bare-pinned or
/// not). Left unconditionally range-only here pending a dedicated follow-up
/// issue to move Deno to `ConcreteIfFullVersion` — out of #664's own scope,
/// which is limited to npm/Composer.
///
/// GitHub Actions, GitLab CI, npm, and Composer all get
/// [`BareRequirementPolicy::ConcreteIfFullVersion`] instead — see that
/// variant's docs for the shared "full version is a pin, partial version is
/// a range" rule, and below for why each of the four qualifies:
///
/// - GitHub Actions: a bare `v4` (a moving-major tag) genuinely is a range,
///   so it must not be queried as if it were the concrete version `4`, but a
///   bare `v4.2.0` is a pin. A bare 40-character SHA also falls to the
///   `None` side of this gate ([`is_full_semver_shape`] rejects it), which is
///   the correct "honest unknown" outcome: resolving a SHA to its tag would
///   need registry access this pure function does not have.
/// - GitLab CI: a `component:` include's partial-semver pin (`1`, `1.2`) is a
///   range exactly like GitHub Actions' moving-major tag
///   ([`is_full_semver_shape`] correctly rejects it, since it requires all
///   three components), while a full `1.2.3`/`v1.2.3` tag or release-name pin
///   is concrete. A SHA pin (`project:`'s or `component:`'s) falls to the
///   same honest "unknown" `None` as GitHub Actions' bare SHA, and
///   `~latest`/a branch-shaped ref never look like a full version shape
///   either, so both also correctly fall through to `None`.
/// - npm and Composer (#664): unlike Cargo, a bare version is **not**
///   unconditionally a range under either ecosystem's own semver grammar. A
///   bare *full* `major.minor.patch` (e.g. npm's `"4.17.0"`,
///   `deps-npm::formatter`'s `node_semver::Range` compiles it to an exact
///   match; Composer's `version_satisfies_requirement` treats a full bare
///   version identically) is an exact pin. Only a bare *partial* version
///   (`"4.17"`, `"4"`) expands to an implicit range/prefix match — npm's
///   X-range semantics, Composer's `ver_parts.starts_with(&req_parts)`
///   prefix match in `deps-composer::formatter`. Before this fix both
///   ecosystems were grouped with Cargo under `AlwaysRange`, which silently
///   dropped `in_use_version` resolution (and therefore hover License/OSV
///   sections) for any bare-pinned npm/Composer manifest with no lock file.
///
/// Every remaining ecosystem (Pypi, Go, Bundler, Dart, Maven, Gradle, Swift,
/// NuGet) gets plain [`BareRequirementPolicy::Concrete`]: none of them has an
/// implicit-range default the way Cargo/Deno do. Gradle in particular: a bare
/// coordinate version (e.g. `"2.14.1"`) is an exact match under
/// `GradleFormatter`'s own `version_satisfies_requirement` unless it uses the
/// `+` dynamic-version suffix, which [`looks_like_a_single_version`] already
/// rejects via its reject-char set.
///
/// Spelled out as explicit arms rather than a `_` catch-all (impl-critic
/// #664 review, finding M4): `EcosystemId` is deliberately exhaustive so a
/// 15th ecosystem forces every `match` on it to be updated at compile time
/// (`.claude/CLAUDE.md`'s bug-class-#118 rule) — a wildcard here would
/// silently default a new ecosystem to `Concrete`, the *least* conservative
/// policy, contradicting [`concrete_pin_version`]'s own doc that a false
/// positive is worse than a false negative.
const fn bare_requirement_policy(ecosystem: EcosystemId) -> BareRequirementPolicy {
    match ecosystem {
        EcosystemId::Cargo | EcosystemId::Deno => BareRequirementPolicy::AlwaysRange,
        EcosystemId::GithubActions
        | EcosystemId::GitlabCi
        | EcosystemId::Npm
        | EcosystemId::Composer => BareRequirementPolicy::ConcreteIfFullVersion,
        EcosystemId::Pypi
        | EcosystemId::Go
        | EcosystemId::Bundler
        | EcosystemId::Dart
        | EcosystemId::Maven
        | EcosystemId::Gradle
        | EcosystemId::Swift
        | EcosystemId::NuGet => BareRequirementPolicy::Concrete,
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
    let s = crate::github::normalize_tag(s);
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
    let core = crate::github::normalize_tag(s);
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
        .strip_circumfix('[', ']')
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

/// Picks the lock-file-resolved candidate that best matches one dependency occurrence's own
/// version requirement (FR-001/FR-002), among a name's multiple retained lock-file entries.
///
/// Filters `candidates` down to those [`EcosystemFormatter::version_satisfies_requirement`]
/// accepts, then returns the highest-semver entry among that satisfying subset — falling back
/// to [`crate::lockfile`]'s lexicographic tiebreak for non-parseable versions
/// ([`crate::lockfile::compare_lockfile_versions`]), the same ordering a single-candidate
/// collapse already uses, so this never diverges from it. Returns `None` when nothing
/// satisfies the requirement (FR-003) — the caller must not then substitute an arbitrary
/// non-matching entry.
/// Prefers [`RequirementResolution::compile_requirement`]'s precise, ecosystem-native
/// comparator (e.g. `deps-cargo`'s real `semver::VersionReq` range semantics) over
/// [`RequirementResolution::version_satisfies_requirement`]'s looser heuristic — critical
/// here specifically because that heuristic's plain/partial-requirement branch requires
/// *minor-version equality* (`is_same_major_minor`), so a caret-range requirement like
/// Cargo's `"2.4"` (meaning `>=2.4.0, <3.0.0`) would wrongly reject a `2.9.4` candidate,
/// turning a real match into a false FR-003 skip. `compile_requirement` is only used when
/// it succeeds; an ecosystem that returns `None` (requirement fails to parse under its own
/// comparator) falls back to the heuristic exactly as it did before this existed.
fn version_matches_requirement(
    formatter: &dyn EcosystemFormatter,
    version: &ConcreteVersion,
    requirement: &crate::VersionReq,
) -> bool {
    if let Some(matcher) = formatter.compile_requirement(requirement) {
        matcher.matches(version) == Some(true)
    } else {
        formatter.version_satisfies_requirement(version, requirement.as_str())
    }
}

fn best_candidate_for_requirement<'a>(
    candidates: &'a [ConcreteVersion],
    requirement: &crate::VersionReq,
    formatter: &dyn EcosystemFormatter,
) -> Option<&'a ConcreteVersion> {
    candidates
        .iter()
        .filter(|v| version_matches_requirement(formatter, v, requirement))
        .max_by(|a, b| crate::lockfile::compare_lockfile_versions(a.as_str(), b.as_str()))
}

/// Resolves one dependency occurrence's lock-file version, disambiguating by its own
/// `version_requirement()` when the resolved name has more than one retained lock-file entry
/// (issue #649).
///
/// `resolved_version_candidates` holds every retained lock-file entry per name (built from
/// [`crate::lockfile::ResolvedPackages::iter_all`]) but, per NFR-003, is expected to carry an
/// entry **only** for names with more than one occurrence — the common single-occurrence case
/// falls straight through to `resolved_versions` (the fast `HashMap` lookup, unchanged from
/// before this function existed, FR-005) without ever consulting the candidates map. The same
/// fallback applies when `dep.version_requirement()` is `None` (edge case: a renamed
/// occurrence with no version to disambiguate against) or when no candidate satisfies the
/// requirement (FR-003) — that last case intentionally does not substitute the collapsed
/// value, since it would be an arbitrary, possibly wrong, non-matching entry.
///
/// Shared by [`in_use_version`] and the resolved-version lookups in
/// [`super::hover::generate_hover`] and [`super::inlay_hints::generate_inlay_hints`] so all
/// three surfaces (hover, inlay hints, OSV target selection) apply the identical
/// per-occurrence disambiguation policy (US-001/US-002).
pub(crate) fn resolve_occurrence_version<'a>(
    dep: &dyn Dependency,
    normalized_name: &str,
    resolved_versions: &'a HashMap<PackageName, ConcreteVersion>,
    resolved_version_candidates: Option<&'a HashMap<PackageName, Vec<ConcreteVersion>>>,
    formatter: &dyn EcosystemFormatter,
) -> Option<&'a ConcreteVersion> {
    let candidates = resolved_version_candidates.and_then(|candidates| {
        candidates
            .get(normalized_name)
            .or_else(|| candidates.get(dep.name()))
    });

    match (candidates, dep.version_requirement()) {
        (Some(candidates), Some(req)) if candidates.len() > 1 => {
            best_candidate_for_requirement(candidates, req, formatter)
        }
        _ => resolved_versions
            .get(normalized_name)
            .or_else(|| resolved_versions.get(dep.name())),
    }
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
/// `resolved_version_candidates` disambiguates a name with more than one lock-file entry by
/// the occurrence's own `version_requirement()` (issue #649) — see this module's
/// `resolve_occurrence_version` for the exact policy. `None` (most callers with no such map
/// to give) behaves exactly as before this parameter existed.
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
///     in_use_version(&dep, "time", &resolved_versions, None, &SimpleFormatter, EcosystemId::Cargo),
///     Some("0.1.43".to_string())
/// );
/// ```
pub fn in_use_version(
    dep: &dyn Dependency,
    normalized_name: &str,
    resolved_versions: &HashMap<PackageName, ConcreteVersion>,
    resolved_version_candidates: Option<&HashMap<PackageName, Vec<ConcreteVersion>>>,
    formatter: &dyn EcosystemFormatter,
    ecosystem: EcosystemId,
) -> Option<String> {
    if formatter.manifest_requirement_is_resolved_version(dep) {
        return dep
            .version_requirement()
            .and_then(|req| concrete_pin_version(req.as_str(), ecosystem))
            .map(str::to_string);
    }

    resolve_occurrence_version(
        dep,
        normalized_name,
        resolved_versions,
        resolved_version_candidates,
        formatter,
    )
    .map(ConcreteVersion::to_string)
    .or_else(|| {
        dep.version_requirement()
            .and_then(|req| concrete_pin_version(req.as_str(), ecosystem))
            .map(str::to_string)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal formatter with a real `compile_requirement` (Cargo-style `semver::VersionReq`
    /// semantics), for tests that must distinguish `best_candidate_for_requirement`'s
    /// precise `compile_requirement` path from `MockFormatter`'s heuristic-only fallback
    /// (issue #649 critic finding C1).
    struct CaretFormatter;

    struct SemverMatcher(semver::VersionReq);
    impl crate::lsp_helpers::RequirementMatcher for SemverMatcher {
        fn matches(&self, version: &ConcreteVersion) -> Option<bool> {
            version
                .as_str()
                .parse::<semver::Version>()
                .ok()
                .map(|v| self.0.matches(&v))
        }
    }

    impl crate::lsp_helpers::PackageNaming for CaretFormatter {}
    impl crate::lsp_helpers::PackageRendering for CaretFormatter {
        fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
            version.to_string()
        }
        fn package_url(&self, name: &PackageName) -> String {
            name.to_string()
        }
    }
    impl crate::lsp_helpers::RequirementResolution for CaretFormatter {
        fn compile_requirement(
            &self,
            requirement: &crate::VersionReq,
        ) -> Option<Box<dyn crate::lsp_helpers::RequirementMatcher>> {
            requirement
                .as_str()
                .parse::<semver::VersionReq>()
                .ok()
                .map(|req| {
                    Box::new(SemverMatcher(req)) as Box<dyn crate::lsp_helpers::RequirementMatcher>
                })
        }
    }
    impl crate::lsp_helpers::DiagnosticMessages for CaretFormatter {}
    impl crate::lsp_helpers::DiagnosticPolicy for CaretFormatter {}
    impl crate::lsp_helpers::SourcePolicy for CaretFormatter {}
    impl crate::lsp_helpers::OsvNaming for CaretFormatter {}

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
        // Critique C2: Cargo's bare "1.2.3" is a caret range under Cargo's
        // own default operator, not a pin. Deno reuses npm's exact grammar
        // for both `jsr:` and `npm:` requirements but keeps `AlwaysRange`
        // (`bare_requirement_policy`'s doc comment) — npm/Composer
        // themselves moved to `ConcreteIfFullVersion` (#664), since a bare
        // *full* version is their own exact pin.
        for eco in [EcosystemId::Cargo, EcosystemId::Deno] {
            assert!(!is_concrete_version("1.2.3", eco), "{eco:?}");
            // ...but an explicit pin is still accepted.
            assert!(is_concrete_version("=1.2.3", eco), "{eco:?}");
        }
    }

    #[test]
    fn is_concrete_version_rejects_partials_and_wildcards() {
        // Critique C2: npm/Composer "1.x"/"1.2.x" and bare partials like
        // "1.2" are ranges, and Gradle's "1.+" is a dynamic version —
        // "1.x"/"1.2.x" are rejected by the `x` reject-char regardless of
        // policy, and "1.2" is rejected by `ConcreteIfFullVersion`'s
        // `is_full_semver_shape` gate (#664: a bare partial version is
        // still a range for npm/Composer, only a bare *full* version is
        // now concrete).
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

    // --- concrete_pin_version: BareRequirementPolicy::ConcreteIfFullVersion (GitLab CI) ---

    #[test]
    fn concrete_pin_version_gitlab_ci_full_tag_is_concrete() {
        assert_eq!(
            concrete_pin_version("1.2.3", EcosystemId::GitlabCi),
            Some("1.2.3")
        );
        assert_eq!(
            concrete_pin_version("v1.2.3", EcosystemId::GitlabCi),
            Some("v1.2.3")
        );
    }

    #[test]
    fn concrete_pin_version_gitlab_ci_partial_pin_is_a_range() {
        // H2 regression (#466 review): a `component:` partial-semver pin (`1`, `1.2`)
        // is a range under GitLab's own documented `~{raw}` semantics, not a single
        // version — must not be queried as if it were the concrete version `1.2`.
        assert_eq!(concrete_pin_version("1.2", EcosystemId::GitlabCi), None);
        assert_eq!(concrete_pin_version("1", EcosystemId::GitlabCi), None);
    }

    #[test]
    fn concrete_pin_version_gitlab_ci_digit_leading_sha_is_not_concrete() {
        // A 40-hex SHA that happens to start with a digit must still fall to the
        // honest "unknown" `None` rather than being misread as a version — it has no
        // dots, so it fails `is_full_semver_shape` regardless of its leading
        // character.
        assert_eq!(
            concrete_pin_version(
                "1234567890abcdef1234567890abcdef12345678",
                EcosystemId::GitlabCi
            ),
            None
        );
    }

    // --- concrete_pin_version: BareRequirementPolicy::ConcreteIfFullVersion (npm/Composer, #664) ---

    #[test]
    fn concrete_pin_version_npm_full_bare_version_is_concrete() {
        assert_eq!(
            concrete_pin_version("4.17.0", EcosystemId::Npm),
            Some("4.17.0")
        );
    }

    #[test]
    fn concrete_pin_version_npm_partial_bare_version_is_a_range() {
        // node-semver's implicit X-range: a bare partial version expands to
        // `>=4.17.0 <4.18.0` (or wider), not a single version.
        assert_eq!(concrete_pin_version("4.17", EcosystemId::Npm), None);
        assert_eq!(concrete_pin_version("4", EcosystemId::Npm), None);
    }

    #[test]
    fn concrete_pin_version_npm_explicit_pin_still_concrete() {
        assert_eq!(
            concrete_pin_version("=4.17.0", EcosystemId::Npm),
            Some("4.17.0")
        );
    }

    #[test]
    fn concrete_pin_version_composer_full_bare_version_is_concrete() {
        assert_eq!(
            concrete_pin_version("2.0.0", EcosystemId::Composer),
            Some("2.0.0")
        );
    }

    #[test]
    fn concrete_pin_version_composer_partial_bare_version_is_a_range() {
        // Composer's prefix-match semantics: a bare partial version matches
        // any version sharing that prefix, not a single version.
        assert_eq!(concrete_pin_version("2.0", EcosystemId::Composer), None);
        assert_eq!(concrete_pin_version("2", EcosystemId::Composer), None);
    }

    #[test]
    fn concrete_pin_version_composer_explicit_pin_still_concrete() {
        assert_eq!(
            concrete_pin_version("=2.0.0", EcosystemId::Composer),
            Some("2.0.0")
        );
    }

    /// Regression guard for issue #649 (deps-cargo `package = "..."` rename, follow-up to
    /// #648): two manifest occurrences of the same crate — one plain, one renamed via
    /// `package = "..."` to select an older major — both resolve `Dependency::name()` to
    /// the same registry name. Before this fix, both collided on `resolved_versions`'s
    /// single collapsed highest-semver entry (asserted by a since-superseded version of
    /// this test — see the critic handoff `.local/handoff/2026-09-05T23-48-31-critic.md`,
    /// finding S1, for the original failure-mode analysis). With
    /// `resolved_version_candidates` populated, each occurrence now resolves to the
    /// lock-file entry that actually satisfies its own `version_requirement()`
    /// (US-001/US-002, FR-001/FR-002).
    #[test]
    fn in_use_version_renamed_occurrence_resolves_its_own_major() {
        use crate::VersionReq;
        use crate::lsp_helpers::test_support::MockDep;

        let renamed_old_major = MockDep {
            name: PackageName::new("serde"),
            version_req: VersionReq::new("0.9"),
            version_range: tower_lsp_server::ls_types::Range::default(),
            name_range: tower_lsp_server::ls_types::Range::default(),
        };
        let plain_current_major = MockDep {
            name: PackageName::new("serde"),
            version_req: VersionReq::new("1.0"),
            version_range: tower_lsp_server::ls_types::Range::default(),
            name_range: tower_lsp_server::ls_types::Range::default(),
        };

        let mut resolved_versions = HashMap::new();
        resolved_versions.insert(PackageName::new("serde"), ConcreteVersion::from("1.0.219"));
        let mut candidates = HashMap::new();
        candidates.insert(
            PackageName::new("serde"),
            vec![
                ConcreteVersion::from("0.9.15"),
                ConcreteVersion::from("1.0.219"),
            ],
        );

        let renamed_result = in_use_version(
            &renamed_old_major,
            "serde",
            &resolved_versions,
            Some(&candidates),
            &crate::lsp_helpers::test_support::MockFormatter,
            EcosystemId::Cargo,
        );
        let plain_result = in_use_version(
            &plain_current_major,
            "serde",
            &resolved_versions,
            Some(&candidates),
            &crate::lsp_helpers::test_support::MockFormatter,
            EcosystemId::Cargo,
        );

        assert_eq!(renamed_result, Some("0.9.15".to_string()));
        assert_eq!(plain_result, Some("1.0.219".to_string()));
    }

    /// FR-003: when no lock-file candidate satisfies the occurrence's own requirement, the
    /// result is the honest "no concrete version" skip — never an arbitrary non-matching
    /// entry.
    #[test]
    fn in_use_version_no_candidate_satisfies_requirement_returns_none() {
        use crate::VersionReq;
        use crate::lsp_helpers::test_support::MockDep;

        let dep = MockDep {
            name: PackageName::new("serde"),
            version_req: VersionReq::new("0.9"),
            version_range: tower_lsp_server::ls_types::Range::default(),
            name_range: tower_lsp_server::ls_types::Range::default(),
        };

        let resolved_versions = HashMap::new();
        let mut candidates = HashMap::new();
        candidates.insert(
            PackageName::new("serde"),
            vec![
                ConcreteVersion::from("1.0.219"),
                ConcreteVersion::from("1.1.0"),
            ],
        );

        let result = in_use_version(
            &dep,
            "serde",
            &resolved_versions,
            Some(&candidates),
            &crate::lsp_helpers::test_support::MockFormatter,
            EcosystemId::Cargo,
        );

        assert_eq!(result, None);
    }

    /// Edge case (spec section 6): a renamed occurrence with no `version_requirement()` to
    /// disambiguate against falls back to the collapsed highest-semver value, same as
    /// before this fix — no new skip-reason variant.
    #[test]
    fn in_use_version_no_requirement_falls_back_to_collapsed_value() {
        use crate::lsp_helpers::test_support::MockMarkedDep;

        let dep = MockMarkedDep {
            name: PackageName::new("serde"),
            name_range: tower_lsp_server::ls_types::Range::default(),
            markers: None,
        };

        let mut resolved_versions = HashMap::new();
        resolved_versions.insert(PackageName::new("serde"), ConcreteVersion::from("1.0.219"));
        let mut candidates = HashMap::new();
        candidates.insert(
            PackageName::new("serde"),
            vec![
                ConcreteVersion::from("0.9.15"),
                ConcreteVersion::from("1.0.219"),
            ],
        );

        let result = in_use_version(
            &dep,
            "serde",
            &resolved_versions,
            Some(&candidates),
            &crate::lsp_helpers::test_support::MockFormatter,
            EcosystemId::Cargo,
        );

        assert_eq!(result, Some("1.0.219".to_string()));
    }

    /// FR-005/NFR-001: a single-candidate name (the dominant case, no rename involved)
    /// behaves identically whether or not a candidates map is supplied — the fast path
    /// never routes through the per-occurrence filter.
    #[test]
    fn in_use_version_single_candidate_matches_collapsed_fast_path() {
        use crate::VersionReq;
        use crate::lsp_helpers::test_support::MockDep;

        let dep = MockDep {
            name: PackageName::new("serde"),
            version_req: VersionReq::new("1.0"),
            version_range: tower_lsp_server::ls_types::Range::default(),
            name_range: tower_lsp_server::ls_types::Range::default(),
        };

        let mut resolved_versions = HashMap::new();
        resolved_versions.insert(PackageName::new("serde"), ConcreteVersion::from("1.0.219"));
        let mut candidates = HashMap::new();
        candidates.insert(
            PackageName::new("serde"),
            vec![ConcreteVersion::from("1.0.219")],
        );

        let with_candidates = in_use_version(
            &dep,
            "serde",
            &resolved_versions,
            Some(&candidates),
            &crate::lsp_helpers::test_support::MockFormatter,
            EcosystemId::Cargo,
        );
        let without_candidates = in_use_version(
            &dep,
            "serde",
            &resolved_versions,
            None,
            &crate::lsp_helpers::test_support::MockFormatter,
            EcosystemId::Cargo,
        );

        assert_eq!(with_candidates, Some("1.0.219".to_string()));
        assert_eq!(with_candidates, without_candidates);
    }

    /// Edge case (spec section 6): non-semver-parseable versions among the candidates fall
    /// back to `compare_lockfile_versions`'s lexicographic tiebreak, not a second, divergent
    /// comparison policy.
    #[test]
    fn best_candidate_for_requirement_non_semver_uses_lexicographic_tiebreak() {
        // Testing gap 2 fix: both candidates must actually satisfy the requirement and
        // both must fail semver parsing, so `max_by` is genuinely invoked on two elements
        // and falls all the way to `compare_lockfile_versions`'s `(Err, Err) => a.cmp(b)`
        // branch — a single-match case (the previous version of this test) never calls the
        // comparator at all. `MockFormatter` has no `compile_requirement` override (default
        // `None`), so this exercises the `version_satisfies_requirement` fallback path:
        // requirement `"1"` is a partial-version bare requirement, and both `"1-rc1"` and
        // `"1-rc2"` satisfy it via the `starts_with` branch (`lsp_helpers::mod::is_same_major_minor`
        // fails for both, since neither has a `.`, but `starts_with("1")` holds for both).
        let candidates = vec![
            ConcreteVersion::from("1-rc1"),
            ConcreteVersion::from("1-rc2"),
        ];

        let result = best_candidate_for_requirement(
            &candidates,
            &crate::VersionReq::new("1"),
            &crate::lsp_helpers::test_support::MockFormatter,
        );

        assert_eq!(result, Some(&ConcreteVersion::from("1-rc2")));
    }

    /// C1 fix regression guard: `best_candidate_for_requirement` must prefer
    /// `compile_requirement`'s precise comparator over `version_satisfies_requirement`'s
    /// heuristic. The heuristic's partial-requirement branch requires *minor-version
    /// equality*, so a Cargo-style caret requirement `"2.4"` (meaning `>=2.4.0, <3.0.0`)
    /// would wrongly reject `2.9.4` under the heuristic alone — this is the exact
    /// false-negative the critic's C1 finding identified (a real dependency silently
    /// dropped from in-use-version resolution, and therefore from the OSV scan).
    #[test]
    fn best_candidate_for_requirement_uses_compile_requirement_when_available() {
        use crate::VersionReq;

        let candidates = vec![
            ConcreteVersion::from("1.3.2"),
            ConcreteVersion::from("2.9.4"),
        ];

        // Bare "2.4" under Cargo's real semver semantics is a caret range matching
        // 2.9.4, not 1.3.2 — but the heuristic's minor-equality check would reject both
        // (neither candidate has minor "4"), producing a false FR-003 skip.
        let result =
            best_candidate_for_requirement(&candidates, &VersionReq::new("2.4"), &CaretFormatter);

        assert_eq!(result, Some(&ConcreteVersion::from("2.9.4")));
    }

    /// FR-002: when more than one lock-file entry satisfies an occurrence's requirement,
    /// the tiebreak must pick the highest-semver *among the satisfying subset*, not the
    /// highest overall — `2.0.0` here is the highest candidate but does not satisfy `^1.0`,
    /// so it must never be picked.
    #[test]
    fn best_candidate_for_requirement_picks_highest_of_satisfying_subset() {
        use crate::VersionReq;

        let candidates = vec![
            ConcreteVersion::from("1.0.1"),
            ConcreteVersion::from("1.0.5"),
            ConcreteVersion::from("2.0.0"),
        ];

        let result =
            best_candidate_for_requirement(&candidates, &VersionReq::new("^1.0"), &CaretFormatter);

        assert_eq!(result, Some(&ConcreteVersion::from("1.0.5")));
    }

    /// FR-002 end-to-end through `in_use_version`/`resolve_occurrence_version`, not just the
    /// isolated `best_candidate_for_requirement` helper.
    #[test]
    fn in_use_version_tiebreaks_among_multiple_satisfying_candidates() {
        use crate::VersionReq;
        use crate::lsp_helpers::test_support::MockDep;

        let dep = MockDep {
            name: PackageName::new("pkg"),
            version_req: VersionReq::new("^1.0"),
            version_range: tower_lsp_server::ls_types::Range::default(),
            name_range: tower_lsp_server::ls_types::Range::default(),
        };

        let resolved_versions = HashMap::new();
        let mut candidates = HashMap::new();
        candidates.insert(
            PackageName::new("pkg"),
            vec![
                ConcreteVersion::from("1.0.1"),
                ConcreteVersion::from("1.0.5"),
                ConcreteVersion::from("2.0.0"),
            ],
        );

        let result = in_use_version(
            &dep,
            "pkg",
            &resolved_versions,
            Some(&candidates),
            &CaretFormatter,
            EcosystemId::Cargo,
        );

        assert_eq!(result, Some("1.0.5".to_string()));
    }

    // --- in_use_version end-to-end: #664's exact repro (no lock file, bare full version) ---

    /// #664's exact repro: `"express": "4.17.0"` in `package.json` with no
    /// `package-lock.json` — `resolve_occurrence_version` has nothing to resolve from
    /// (empty `resolved_versions`, no candidates), so the fix must be observable through
    /// the fallback to `concrete_pin_version`, not just in that helper in isolation.
    #[test]
    fn in_use_version_npm_bare_full_version_no_lockfile_resolves_664_repro() {
        use crate::VersionReq;
        use crate::lsp_helpers::test_support::MockDep;

        let dep = MockDep {
            name: PackageName::new("express"),
            version_req: VersionReq::new("4.17.0"),
            version_range: tower_lsp_server::ls_types::Range::default(),
            name_range: tower_lsp_server::ls_types::Range::default(),
        };

        let result = in_use_version(
            &dep,
            "express",
            &HashMap::new(),
            None,
            &crate::lsp_helpers::test_support::MockFormatter,
            EcosystemId::Npm,
        );

        assert_eq!(result, Some("4.17.0".to_string()));
    }

    /// Composer counterpart of the #664 repro: `"monolog/monolog": "2.0.0"` in
    /// `composer.json` with no `composer.lock`.
    #[test]
    fn in_use_version_composer_bare_full_version_no_lockfile_resolves_664_repro() {
        use crate::VersionReq;
        use crate::lsp_helpers::test_support::MockDep;

        let dep = MockDep {
            name: PackageName::new("monolog/monolog"),
            version_req: VersionReq::new("2.0.0"),
            version_range: tower_lsp_server::ls_types::Range::default(),
            name_range: tower_lsp_server::ls_types::Range::default(),
        };

        let result = in_use_version(
            &dep,
            "monolog/monolog",
            &HashMap::new(),
            None,
            &crate::lsp_helpers::test_support::MockFormatter,
            EcosystemId::Composer,
        );

        assert_eq!(result, Some("2.0.0".to_string()));
    }

    /// Regression guard: Cargo's identically-shaped bare full version must still resolve
    /// to no concrete pin end-to-end (not just via `concrete_pin_version` in isolation) —
    /// #664 only reclassified npm/Composer, not Cargo's real implicit-caret default.
    #[test]
    fn in_use_version_cargo_bare_full_version_no_lockfile_still_none() {
        use crate::VersionReq;
        use crate::lsp_helpers::test_support::MockDep;

        let dep = MockDep {
            name: PackageName::new("serde"),
            version_req: VersionReq::new("1.0.219"),
            version_range: tower_lsp_server::ls_types::Range::default(),
            name_range: tower_lsp_server::ls_types::Range::default(),
        };

        let result = in_use_version(
            &dep,
            "serde",
            &HashMap::new(),
            None,
            &crate::lsp_helpers::test_support::MockFormatter,
            EcosystemId::Cargo,
        );

        assert_eq!(result, None);
    }
}
