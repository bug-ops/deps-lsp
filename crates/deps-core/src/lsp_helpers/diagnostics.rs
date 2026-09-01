use tower_lsp_server::ls_types::{
    CodeDescription, Diagnostic, DiagnosticSeverity, NumberOrString, Uri,
};

use crate::osv::{ADVISORY_DISPLAY_CAP, ScanOutcome, diagnostic_severity_for};
use crate::{
    ConcreteVersion, Dependency, ParseResult, PublishTime, Registry, VersionReq,
    format_relative_age, is_within_cooldown,
};

use super::{EcosystemFormatter, RequirementMatcher, RequirementStatus, VersionData};

/// Stable [`Diagnostic::code`] set on the unsatisfiable-requirement diagnostic.
///
/// Set by `generate_diagnostics_from_cache`, so `build_unsatisfiable_fix_action`'s
/// stashed `CodeAction::data` can name it and the `deps-lsp` handler's diagnostic-binding
/// step can match on it — the same mechanism `build_vulnerability_fix_action` uses with an
/// advisory id, generalized to a constant since this diagnostic has no per-instance
/// identifier.
pub const UNSATISFIABLE_DIAGNOSTIC_CODE: &str = "unsatisfiable-requirement";

/// Diagnostic severity levels for the four per-dependency issue categories.
///
/// Threaded from `DiagnosticsConfig` (`deps-lsp`) through
/// [`crate::Ecosystem::generate_diagnostics`] into [`generate_diagnostics_from_cache`]
/// and [`generate_diagnostics`].
///
/// # Examples
///
/// ```
/// use deps_core::DiagnosticSeverities;
/// use tower_lsp_server::ls_types::DiagnosticSeverity;
///
/// let severities = DiagnosticSeverities::default();
/// assert_eq!(severities.outdated, DiagnosticSeverity::HINT);
/// assert_eq!(severities.unknown, DiagnosticSeverity::WARNING);
/// assert_eq!(severities.yanked, DiagnosticSeverity::WARNING);
/// assert_eq!(severities.unsatisfiable, DiagnosticSeverity::WARNING);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiagnosticSeverities {
    /// Severity for a dependency with a newer version available.
    pub outdated: DiagnosticSeverity,
    /// Severity for a dependency not found in the registry (or with an invalid name).
    pub unknown: DiagnosticSeverity,
    /// Severity for a dependency pinned to a yanked/deprecated version.
    pub yanked: DiagnosticSeverity,
    /// Severity for a dependency whose requirement matches zero published versions.
    pub unsatisfiable: DiagnosticSeverity,
}

impl Default for DiagnosticSeverities {
    fn default() -> Self {
        Self {
            outdated: DiagnosticSeverity::HINT,
            unknown: DiagnosticSeverity::WARNING,
            yanked: DiagnosticSeverity::WARNING,
            unsatisfiable: DiagnosticSeverity::WARNING,
        }
    }
}

/// Shared shape for a [`EcosystemFormatter::compile_requirement`] guarded by one predicate.
///
/// This is the pattern several ecosystems' guards independently re-implemented
/// (`deps-go`'s pseudo-version check, `deps-composer`'s dev-branch/`@dev` check,
/// `deps-bundler`'s exact-pin check, `deps-maven`/`deps-gradle`'s malformed-range check,
/// `deps-nuget`'s malformed-requirement check). See
/// [`EcosystemFormatter::compile_requirement`]'s docs for why `None` is correct in exactly
/// this case: `is_undecidable(requirement)` true means the fetched `available` list
/// structurally cannot contain a version that would decide the match either way, so scanning
/// it would always report `Some(false)` and produce a false "no published version satisfies
/// this requirement" diagnostic.
///
/// Returns `None` when `is_undecidable(requirement)` is `true`. Otherwise builds `matcher`
/// from `requirement`'s owned `String` and boxes it as the trait object
/// [`EcosystemFormatter::compile_requirement`] returns.
///
/// Ecosystems whose guard is a fallible parse rather than a named predicate over the
/// requirement string (`deps-cargo`, `deps-npm`, `deps-pypi`, `deps-swift`) don't fit this
/// shape and implement `compile_requirement` directly via `.ok().map(...)` instead.
/// `deps-dart` implements `compile_requirement` but has no guard at all — every requirement
/// string is a valid Dart constraint by construction, so it is always `Some`.
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::{compile_requirement_unless, RequirementMatcher};
/// use deps_core::ConcreteVersion;
///
/// struct ExactMatcher(String);
/// impl RequirementMatcher for ExactMatcher {
///     fn matches(&self, version: &ConcreteVersion) -> Option<bool> {
///         Some(version.as_str() == self.0)
///     }
/// }
///
/// let is_pseudo_version = |r: &str| r.starts_with("v0.0.0-");
///
/// assert!(
///     compile_requirement_unless(
///         "v0.0.0-20191109021931-daa7c04131f5",
///         is_pseudo_version,
///         ExactMatcher,
///     )
///     .is_none()
/// );
/// assert!(compile_requirement_unless("v1.2.3", is_pseudo_version, ExactMatcher).is_some());
/// ```
pub fn compile_requirement_unless<M>(
    requirement: &str,
    is_undecidable: impl FnOnce(&str) -> bool,
    matcher: impl FnOnce(String) -> M,
) -> Option<Box<dyn RequirementMatcher>>
where
    M: RequirementMatcher + 'static,
{
    if is_undecidable(requirement) {
        return None;
    }
    Some(Box::new(matcher(requirement.to_string())))
}

/// Requirement strings longer than this are rejected by [`requirement_is_unsatisfiable`]
/// before compilation, rather than compiled and scanned. No real manifest requirement in any
/// supported ecosystem approaches this length; it exists solely to bound the cost of an
/// adversarial or corrupted requirement string. All eleven ecosystems' `compile_requirement`
/// implementations now parse `requirement` exactly once per dependency and reuse the parsed
/// form across every candidate in `matches` — Maven/Gradle/NuGet's `RequirementMatcher`s were
/// the last holdouts re-parsing per candidate, fixed alongside this comment — so the scan
/// itself is O(`available.len()`) in the size of the candidate list, not the requirement.
/// This cap stays as defense-in-depth against the one-time parse cost: Maven's range union
/// can still degrade non-linearly on a pathological multi-KB comma union, and a stray
/// oversized string is never a real requirement, only a corrupted or adversarial one.
const MAX_REQUIREMENT_LEN: usize = 256;

/// Returns `true` when no published version satisfies `requirement`.
///
/// `available` must be non-empty, `requirement` must be a concrete (non-empty, resolved,
/// not implausibly long) constraint, and no entry in `available` — of any kind: stable,
/// prerelease, or yanked — may satisfy it. All of the following must hold for `true`:
///
/// 1. `!available.is_empty()` — an empty or not-yet-loaded list means "unknown", not
///    "unsatisfiable" (FR-004: no diagnostic while loading or offline).
/// 2. `!requirement.as_str().trim().is_empty()`.
/// 3. `requirement.as_str().len() <= MAX_REQUIREMENT_LEN` — see that constant's docs; an
///    oversized requirement is treated the same as "unmodellable" (suppressed, not warned).
/// 4. `!formatter.requirement_is_unresolved(requirement)` (FR-005) — an unresolved
///    placeholder requirement was never actually checked against anything.
/// 5. `!formatter.requirement_is_undecidable_given_available(requirement, available)` — this
///    ecosystem's registry can hide a published version that would have decided the match.
/// 6. `formatter.compile_requirement(requirement)` returns `Some(matcher)` — this
///    ecosystem opted in and the requirement string itself parses.
/// 7. Scanning `available` with `matcher.matches`: **at least one** candidate returned
///    `Some(false)`, and **none** returned `Some(true)`. Candidates returning `None`
///    (unparseable candidate strings) are skipped and count toward neither side —
///    condition 7's "at least one `Some(false)`" is load-bearing: if every candidate is
///    unparseable, nothing was decided, so the verdict is `false` (no diagnostic) rather
///    than a vacuous `true`.
///
/// The scan short-circuits on the first `Some(true)` — O(N) worst case, and the newest-first
/// ordering of `available` means a satisfiable requirement typically exits within the first
/// few entries.
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::{requirement_is_unsatisfiable, EcosystemFormatter, RequirementMatcher};
/// use deps_core::{ConcreteVersion, PackageName, VersionReq};
///
/// struct ExactMatcher(String);
/// impl RequirementMatcher for ExactMatcher {
///     fn matches(&self, version: &ConcreteVersion) -> Option<bool> {
///         Some(version.as_str() == self.0)
///     }
/// }
///
/// struct ExactFormatter;
/// impl EcosystemFormatter for ExactFormatter {
///     fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
///         version.to_string()
///     }
///     fn package_url(&self, name: &PackageName) -> String {
///         name.to_string()
///     }
///     fn compile_requirement(
///         &self,
///         requirement: &VersionReq,
///     ) -> Option<Box<dyn RequirementMatcher>> {
///         Some(Box::new(ExactMatcher(requirement.as_str().to_string())))
///     }
/// }
///
/// let available = vec![ConcreteVersion::new("1.0.0"), ConcreteVersion::new("0.9.0")];
/// assert!(requirement_is_unsatisfiable(
///     &ExactFormatter,
///     &VersionReq::new("2.0.0"),
///     &available,
/// ));
/// assert!(!requirement_is_unsatisfiable(
///     &ExactFormatter,
///     &VersionReq::new("1.0.0"),
///     &available,
/// ));
/// ```
pub fn requirement_is_unsatisfiable(
    formatter: &dyn EcosystemFormatter,
    requirement: &VersionReq,
    available: &[ConcreteVersion],
) -> bool {
    if available.is_empty() || requirement.as_str().trim().is_empty() {
        return false;
    }
    if requirement.as_str().len() > MAX_REQUIREMENT_LEN {
        return false;
    }
    if formatter.requirement_is_unresolved(requirement) {
        return false;
    }
    if formatter.requirement_is_undecidable_given_available(requirement, available) {
        return false;
    }
    let Some(matcher) = formatter.compile_requirement(requirement) else {
        return false;
    };

    let mut saw_decided_false = false;
    for candidate in available {
        match matcher.matches(candidate) {
            Some(true) => return false,
            Some(false) => saw_decided_false = true,
            None => {}
        }
    }
    saw_decided_false
}

/// Splits a strict-SemVer version string's stable `X.Y.Z` core from its pre-release
/// identifier, if `version` carries one — e.g. `"2.0.0-rc.1"` -> `Some("2.0.0")`,
/// `"2.0.0-rc.1+build.5"` -> `Some("2.0.0")`, `"2.0.0"` -> `None`.
///
/// `None` means `version` is already a stable release, not that it failed to parse — this
/// is a textual SemVer split, not a validating parse. Callers only rely on it for
/// strict-SemVer ecosystems (see
/// [`EcosystemFormatter::strict_semver_prerelease_exclusion`]), whose registries only
/// publish spec-conformant version strings.
fn semver_prerelease_base(version: &str) -> Option<&str> {
    let core = version.split('+').next().unwrap_or(version);
    core.find('-').map(|dash| &core[..dash])
}

/// Reports whether `requirement` itself already names a pre-release tag — a `-` embedded
/// directly in a version token (no surrounding whitespace), as opposed to a whitespace-padded
/// hyphen range operator (npm's `"1.2.3 - 2.3.4"`).
///
/// Guards [`matching_prerelease_would_satisfy`] (#299 S1): when the requirement already pins
/// to a pre-release tuple (e.g. `^2.0.0-rc.5`), a published pre-release that fails to match is
/// rejected by ordinary version *ordering* against that explicit floor, not by SemVer's
/// default pre-release exclusion — enriching the message in that case would misattribute the
/// cause.
fn requirement_names_prerelease(requirement: &str) -> bool {
    let bytes = requirement.as_bytes();
    bytes.iter().enumerate().any(|(i, &b)| {
        b == b'-'
            && i > 0
            && i + 1 < bytes.len()
            && !bytes[i - 1].is_ascii_whitespace()
            && !bytes[i + 1].is_ascii_whitespace()
    })
}

/// For strict-SemVer ecosystems (see
/// [`EcosystemFormatter::strict_semver_prerelease_exclusion`]), finds the newest published,
/// non-yanked pre-release in `available` whose stable core would satisfy `requirement` —
/// evidence that `requirement` reads as unsatisfiable only because SemVer's default comparator
/// excludes pre-releases, not because no compatible version was ever published (#299).
///
/// Returns `None` when the ecosystem hasn't opted in, `requirement` itself already names a
/// pre-release (see [`requirement_names_prerelease`] — in that shape a non-matching candidate
/// is rejected by ordering against the requirement's own explicit floor, not by pre-release
/// exclusion), `requirement` doesn't compile, or no such pre-release exists. `available` is
/// assumed newest-first (see [`PackageVersions::available`]), so the first match found is the
/// newest.
fn matching_prerelease_would_satisfy(
    formatter: &dyn EcosystemFormatter,
    requirement: &VersionReq,
    available: &[ConcreteVersion],
    yanked: &[ConcreteVersion],
) -> Option<String> {
    if !formatter.strict_semver_prerelease_exclusion() {
        return None;
    }
    if requirement_names_prerelease(requirement.as_str()) {
        return None;
    }
    let matcher = formatter.compile_requirement(requirement)?;
    available.iter().find_map(|candidate| {
        let base = semver_prerelease_base(candidate.as_str())?;
        (!yanked.iter().any(|y| y == candidate)
            && matcher.matches(&ConcreteVersion::new(base)) == Some(true))
        .then(|| candidate.to_string())
    })
}

/// Returns `true` when `requirement` is satisfied by at least one entry in `available`, but
/// every matching entry is yanked — i.e. the dependency is currently satisfiable only by a
/// yanked/deprecated version.
///
/// Mutually exclusive with [`requirement_is_unsatisfiable`]: both scan `available` through the
/// same `formatter.compile_requirement` matcher, but this one additionally cross-references
/// `yanked` (see [`PackageVersions::yanked`]) to distinguish "satisfied, but only by a yanked
/// version" from "satisfied by an ordinary version" or "not satisfied at all". Callers should
/// only invoke this once `requirement_is_unsatisfiable` has returned `false` for the same
/// `requirement`/`available` pair, so a match is already known to exist.
///
/// Shares `requirement_is_unsatisfiable`'s guard cascade (empty `available`/`requirement`,
/// oversized `requirement`, unresolved placeholder `requirement`, uncompilable `requirement`)
/// — each returns `false` here for the identical reason it does there.
///
/// Unlike `requirement_is_unsatisfiable`, an undecided candidate (`matcher.matches` returns
/// `None` — an unparseable candidate string) does not just get skipped: it disqualifies a
/// `true` verdict entirely. That candidate might have been a genuine non-yanked match this
/// scan simply could not evaluate, so claiming "every match is yanked" without accounting for
/// it would be a false positive — the same #206 conservatism (nothing decided means no
/// diagnostic, not a guess) applied to a different question than `requirement_is_unsatisfiable`
/// asks.
fn requirement_matches_only_yanked(
    formatter: &dyn EcosystemFormatter,
    requirement: &VersionReq,
    available: &[ConcreteVersion],
    yanked: &[ConcreteVersion],
) -> bool {
    if available.is_empty() || yanked.is_empty() || requirement.as_str().trim().is_empty() {
        return false;
    }
    if requirement.as_str().len() > MAX_REQUIREMENT_LEN {
        return false;
    }
    if formatter.requirement_is_unresolved(requirement) {
        return false;
    }
    let Some(matcher) = formatter.compile_requirement(requirement) else {
        return false;
    };

    let mut saw_match = false;
    let mut saw_undecided = false;
    for candidate in available {
        match matcher.matches(candidate) {
            Some(true) => {
                saw_match = true;
                if !yanked.iter().any(|y| y == candidate) {
                    return false;
                }
            }
            Some(false) => {}
            None => saw_undecided = true,
        }
    }
    saw_match && !saw_undecided
}

/// Generates diagnostics using cached versions (no network calls).
///
/// Uses pre-fetched version information from the lifecycle's parallel fetch.
/// This avoids making additional network requests during diagnostic generation.
///
/// # Arguments
///
/// * `parse_result` - Parsed dependencies from manifest
/// * `versions` - Latest (registry) and resolved (lock file) version maps, keyed by package name
/// * `formatter` - Ecosystem-specific formatting and comparison logic
/// * `freshness` - Whether to differentiate an "outdated" diagnostic still within the
///   release cooldown window (severity is unaffected either way — see the "Newer version
///   available" message below)
/// * `severities` - Configured severity for each diagnostic category
/// * `now` - The instant every publish age in this call is computed against. Taken as a
///   parameter rather than read internally via `PublishTime::now()` (issue #227 M4) so
///   callers can pin an exact cooldown-boundary instant deterministically in tests, and
///   so every dependency in one document is aged against the same instant.
pub fn generate_diagnostics_from_cache(
    parse_result: &dyn ParseResult,
    versions: VersionData<'_>,
    formatter: &dyn EcosystemFormatter,
    freshness: crate::freshness::FreshnessSettings,
    severities: DiagnosticSeverities,
    now: PublishTime,
) -> Vec<Diagnostic> {
    let deps = parse_result.dependencies();
    let mut diagnostics = Vec::with_capacity(deps.len());

    // #394 S2: version-qualified OSV lookup keys, so two occurrences of one
    // name pinned to different versions never share a `Vulnerable`/`Clean`
    // result. `None` when this `VersionData` carries no ecosystem (most test
    // fixtures) — the per-dep lookup below then falls back to the plain
    // name, unaffected.
    let vuln_keys = versions.ecosystem.map(|ecosystem| {
        crate::osv::vulnerability_keys(parse_result, versions.resolved, formatter, ecosystem)
    });

    for dep in deps {
        let normalized_name = formatter.normalize_package_name(dep.name());

        // Emitted before either early-`continue` below (registry outage,
        // no version range) so a registry failure never suppresses an OSV
        // finding — the two are independent data sources (FR-007/US-004).
        if let Some(vulnerabilities) = versions.vulnerabilities
            && let Some(ScanOutcome::Vulnerable(dv)) = vuln_keys
                .as_ref()
                .and_then(|keys| keys.get(&dep.name_range()))
                .and_then(|key| vulnerabilities.get(key))
                .or_else(|| vulnerabilities.get(&normalized_name))
                .or_else(|| vulnerabilities.get(dep.name().as_str()))
        {
            push_vulnerability_diagnostics(&mut diagnostics, dep, dv);
        }

        // Independent of the registry-outage/no-range early-`continue`s below,
        // for the same reason as the vulnerability push above — a yanked
        // finding from the lifecycle probe must never be suppressed by an
        // unrelated "latest" lookup failure.
        //
        // Two independent yanked-version checks exist and both run in this loop:
        // this one (#263) flags the specific in-use version (lockfile-resolved,
        // or an exact manifest pin) when it is yanked, while `yanked_only` below
        // (#247) flags a declared *range* requirement that can currently only be
        // satisfied by a yanked version, even with no lockfile at all. They answer
        // different questions and neither subsumes the other, but for a dependency
        // pinned to the one version that also happens to be the only version
        // satisfying its own requirement, both would fire on the same dependency.
        // `yanked_diagnostic_pushed` suppresses the second (#247) check once the
        // first (#263) already emitted a diagnostic for this dependency, so a
        // single dependency never gets two yanked diagnostics.
        //
        // The two checks deliberately keep different outdated-interaction policies —
        // this is not an oversight left over from the merge. This (#263) check has no
        // `continue`, so it co-emits alongside an "outdated" diagnostic for the same
        // dependency (see `test_generate_diagnostics_from_cache_yanked_and_outdated_both_emitted`,
        // asserting exactly that on the upstream #263 design). `yanked_only` below
        // (#247) does `continue`, suppressing "outdated" for the same dependency (see
        // `test_yanked_only_match_suppresses_outdated_diagnostic`). Each policy was
        // independently reviewed and tested before this merge; harmonizing them is out
        // of scope here.
        // #394 S1: when multiple occurrences share `normalized_name`, the
        // finding recorded under it may belong to a *different* occurrence
        // (e.g. `[dependencies] time = "=0.1.43"`, yanked, and
        // `[dev-dependencies] time = "=0.1.44"`, not yanked — both name-keyed
        // to the same `yanked_version`). Emitting unconditionally would push
        // a false-positive "yanked" diagnostic onto the safe occurrence, for
        // a version string that does not even appear on that line. Gated on
        // `versions.ecosystem` being set (production always sets it; the
        // check is skipped, matching pre-#394 behavior, for the test
        // fixtures that do not).
        let yanked_diagnostic_pushed = if let Some(yanked_version) =
            versions.yanked.and_then(|y| y.get(&normalized_name))
            && versions.ecosystem.is_none_or(|ecosystem| {
                super::in_use_version(
                    dep,
                    &normalized_name,
                    versions.resolved,
                    formatter,
                    ecosystem,
                )
                .as_deref()
                    == Some(yanked_version.as_str())
            }) {
            diagnostics.push(Diagnostic {
                range: dep.version_range().unwrap_or_else(|| dep.name_range()),
                severity: Some(severities.yanked),
                message: format!("{} ({})", formatter.yanked_message(), yanked_version),
                source: Some("deps-lsp".into()),
                ..Default::default()
            });
            true
        } else {
            false
        };

        let package_versions = versions
            .cached
            .get(normalized_name.as_str())
            .or_else(|| versions.cached.get(dep.name()));

        let Some(package_versions) = package_versions else {
            // Skip "unknown" diagnostic if package exists in lock file
            // (registry fetch may have failed due to rate limiting), or if
            // the source isn't resolvable against the registry this LSP
            // queries (e.g. `CustomRegistry` / Git / Path) — an absent cache
            // entry there just means we never fetched it, not that the
            // package doesn't exist (#248). Name-syntax validation is
            // unaffected: it never depends on registry data.
            let in_lockfile = versions.resolved.contains_key(normalized_name.as_str())
                || versions.resolved.contains_key(dep.name());
            if !in_lockfile {
                // A fetch error/timeout (#267) is not evidence the package doesn't
                // exist — the registry was never successfully asked. Report it
                // distinctly from a genuine "not found" so a transient registry
                // outage or a malformed response (e.g. unparseable
                // maven-metadata.xml) doesn't masquerade as "Unknown package".
                let fetch_failed = dep.source().is_version_resolvable()
                    && versions
                        .fetch_failed
                        .is_some_and(|f| f.contains(normalized_name.as_str()));
                let message = match formatter.validate_package_name(dep.name().as_str()) {
                    Err(reason) => Some(format!("Invalid package name '{}': {reason}", dep.name())),
                    Ok(()) if fetch_failed => Some(format!(
                        "Registry lookup failed for '{}'; package status could not be determined",
                        dep.name()
                    )),
                    Ok(()) if dep.source().is_version_resolvable() => {
                        Some(format!("Unknown package '{}'", dep.name()))
                    }
                    Ok(()) => None,
                };
                if let Some(message) = message {
                    diagnostics.push(Diagnostic {
                        range: dep.name_range(),
                        severity: Some(severities.unknown),
                        message,
                        source: Some("deps-lsp".into()),
                        ..Default::default()
                    });
                }
            }
            continue;
        };
        let latest = &package_versions.latest;

        let Some(version_range) = dep.version_range() else {
            continue;
        };

        // Path/git/URL/SDK/workspace dependencies never resolve against a
        // registry version list at all — `package_versions` (when present)
        // either came from a coincidentally-matching registry entry of the
        // same name (e.g. this workspace's own `deps-core = { path = ...
        // version = "0.10.1" }`, which only avoids a false WARNING today
        // because 0.10.1 also happens to be published) or an entirely
        // unrelated package (Dart's `{ sdk: flutter, version = "^3.24.0" }`
        // resolves against pub.dev's unrelated `flutter` package). Neither
        // is a meaningful "no published version satisfies this" check.
        let unsatisfiable = dep.source().is_version_resolvable()
            && dep.version_requirement().is_some_and(|version_req| {
                requirement_is_unsatisfiable(formatter, version_req, &package_versions.available)
            });

        if unsatisfiable {
            let req_str = dep.version_requirement().map_or("", |r| r.as_str());
            let mut message = format!(
                "No published version satisfies requirement '{req_str}'; latest is {latest}"
            );
            if let Some(prerelease) = dep.version_requirement().and_then(|version_req| {
                matching_prerelease_would_satisfy(
                    formatter,
                    version_req,
                    &package_versions.available,
                    &package_versions.yanked,
                )
            }) {
                use std::fmt::Write as _;
                let _ = write!(
                    message,
                    " (a pre-release, {prerelease}, is excluded by SemVer's default \
                     pre-release-matching rules; require it explicitly to use it)"
                );
            }
            diagnostics.push(Diagnostic {
                range: version_range,
                severity: Some(severities.unsatisfiable),
                message,
                source: Some("deps-lsp".into()),
                code: Some(NumberOrString::String(UNSATISFIABLE_DIAGNOSTIC_CODE.into())),
                ..Default::default()
            });
            continue;
        }

        // Same source-resolvability guard as `unsatisfiable` above — only meaningful once a
        // requirement is known to match *something* in `available` (see `requirement_is_unsatisfiable`).
        // `yanked_diagnostic_applies_to` additionally opts an ecosystem out for a requirement
        // shape where `removal_status()` is not a genuine per-version signal (npm/Composer
        // restrict to exact pins — see that method's docs). Skipped entirely when the in-use-version
        // check above already pushed a yanked diagnostic for this dependency (see
        // `yanked_diagnostic_pushed`), so the two checks never double-report.
        let yanked_only = !yanked_diagnostic_pushed
            && dep.source().is_version_resolvable()
            && dep.version_requirement().is_some_and(|version_req| {
                formatter.yanked_diagnostic_applies_to(version_req)
                    && requirement_matches_only_yanked(
                        formatter,
                        version_req,
                        &package_versions.available,
                        &package_versions.yanked,
                    )
            });

        if yanked_only {
            diagnostics.push(Diagnostic {
                range: version_range,
                severity: Some(severities.yanked),
                message: format!("{}; latest is {latest}", formatter.yanked_message()),
                source: Some("deps-lsp".into()),
                ..Default::default()
            });
            continue;
        }

        // As with the unsatisfiable check above, a non-resolvable source's `latest`
        // (when present at all) comes from an unrelated or coincidental cache entry,
        // not a real lookup against the registry this dependency actually resolves
        // against — so "Outdated" must not be evaluated for it either (#248).
        let status = match dep.version_requirement() {
            Some(version_req) if dep.source().is_version_resolvable() => {
                formatter.requirement_status(version_req, latest)
            }
            _ => RequirementStatus::Unresolved,
        };

        if status == RequirementStatus::Outdated {
            // Message-only differentiation: severity stays `severities.outdated` in both
            // cases (already the floor — see the module docs). A within-cooldown release
            // still deserves the recommendation, just with the extra context that it may
            // yet be yanked or superseded (issue #227 §4.3).
            let published_at = freshness
                .enabled
                .then_some(package_versions.published_at)
                .flatten();
            let message = match published_at {
                Some(published_at)
                    if is_within_cooldown(
                        published_at.age_secs_from(now),
                        freshness.cooldown_secs,
                    ) =>
                {
                    format!(
                        "Newer version available: {latest} (published {} — still within the release cooldown window)",
                        format_relative_age(published_at.age_secs_from(now))
                    )
                }
                _ => format!("Newer version available: {latest}"),
            };
            diagnostics.push(Diagnostic {
                range: version_range,
                severity: Some(severities.outdated),
                message,
                source: Some("deps-lsp".into()),
                ..Default::default()
            });
        }
    }

    diagnostics
}

/// Pushes one [`Diagnostic`] per advisory (each with its own severity, code,
/// and clickable `code_description`), capped at
/// [`ADVISORY_DISPLAY_CAP`] plus a trailing "+N more advisories" entry.
///
/// `N` is derived from `dv.total_known` — the batch result's reported count —
/// never from `dv.advisories.len()`, since invariant 3 (`architecture.md` §8)
/// caps the record *fetch* independently of the render cap.
fn push_vulnerability_diagnostics(
    diagnostics: &mut Vec<Diagnostic>,
    dep: &dyn Dependency,
    dv: &crate::osv::DependencyVulnerabilities,
) {
    let range = dep.version_range().unwrap_or_else(|| dep.name_range());

    let shown = dv.advisories.iter().take(ADVISORY_DISPLAY_CAP);
    let mut shown_count = 0usize;
    for advisory in shown {
        shown_count += 1;
        let code_description = advisory
            .url
            .parse::<Uri>()
            .ok()
            .map(|href| CodeDescription { href });

        diagnostics.push(Diagnostic {
            range,
            severity: Some(diagnostic_severity_for(advisory.severity)),
            message: format!(
                "{}: {}",
                advisory.id,
                advisory
                    .summary
                    .as_deref()
                    .unwrap_or("(no summary provided)")
            ),
            code: Some(NumberOrString::String(advisory.id.clone())),
            code_description,
            source: Some("deps-lsp".into()),
            ..Default::default()
        });
    }

    let remaining = dv.total_known.saturating_sub(shown_count);
    if remaining > 0 {
        diagnostics.push(Diagnostic {
            range,
            severity: Some(DiagnosticSeverity::INFORMATION),
            message: format!("+{remaining} more advisories"),
            source: Some("deps-lsp".into()),
            ..Default::default()
        });
    }
}

/// Generates diagnostics by fetching from registry (makes network calls).
///
/// **Warning**: This function makes network requests for each dependency.
/// Prefer `generate_diagnostics_from_cache` when cached versions are available. Not called
/// anywhere in this workspace (`deps-lsp` always has cached versions by the time
/// diagnostics run) — kept as public API for external callers of `deps-core` as a library,
/// re-exported as `deps_core::lsp_generate_diagnostics`. Does not emit a yanked-version
/// diagnostic: `get_latest_matching`'s trait contract filters yanked versions by default
/// (see [`Registry::get_latest_matching`]), so the version it returns is never yanked
/// under a normal requirement (#233).
pub async fn generate_diagnostics<R: Registry + ?Sized>(
    parse_result: &dyn ParseResult,
    registry: &R,
    formatter: &dyn EcosystemFormatter,
    _freshness: crate::freshness::FreshnessSettings,
    severities: DiagnosticSeverities,
) -> Vec<Diagnostic> {
    let deps = parse_result.dependencies();
    let mut diagnostics = Vec::with_capacity(deps.len());

    for dep in deps {
        // Deliberately `get_versions`, not `get_versions_with`: diagnostics render no
        // publish ages, so paying for a registry's extra freshness fetch here would be
        // pure waste. This function is not called anywhere in this workspace (see the
        // doc comment above), so `_freshness` stays unused by design, not oversight.
        let versions = match registry.get_versions(dep.name()).await {
            Ok(v) => v,
            Err(e) => {
                // Same distinction as `generate_diagnostics_from_cache`/`FetchResult::fetch_failed`
                // (#267): a genuine not-found means the registry answered "no such package",
                // while any other error means the registry couldn't be asked at all.
                let message = match formatter.validate_package_name(dep.name().as_str()) {
                    Err(reason) => format!("Invalid package name '{}': {reason}", dep.name()),
                    Ok(()) if e.is_not_found() => format!("Unknown package '{}'", dep.name()),
                    Ok(()) => format!(
                        "Registry lookup failed for '{}'; package status could not be determined",
                        dep.name()
                    ),
                };
                diagnostics.push(Diagnostic {
                    range: dep.name_range(),
                    severity: Some(severities.unknown),
                    message,
                    source: Some("deps-lsp".into()),
                    ..Default::default()
                });
                continue;
            }
        };

        let Some(version_req) = dep.version_requirement() else {
            continue;
        };
        let Some(version_range) = dep.version_range() else {
            continue;
        };

        let matching = registry
            .get_latest_matching(dep.name(), version_req)
            .await
            .ok()
            .flatten();

        if matching.is_some() {
            let latest = crate::registry::find_latest_stable(&versions);
            if let Some(latest) = latest
                && formatter.requirement_status(version_req, latest.version_string())
                    == RequirementStatus::Outdated
            {
                diagnostics.push(Diagnostic {
                    range: version_range,
                    severity: Some(severities.outdated),
                    message: format!("Newer version available: {}", latest.version_string()),
                    source: Some("deps-lsp".into()),
                    ..Default::default()
                });
            }
        }
    }

    diagnostics
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lsp_helpers::test_support::*;
    use crate::lsp_helpers::*;
    use crate::{PackageName, VersionReq};

    use std::collections::{HashMap, HashSet};
    use std::sync::Arc;

    #[test]
    fn test_generate_diagnostics_from_cache_unknown_package() {
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

        let formatter = MockFormatter;

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "unknown-pkg".into(),
                version_req: "1.0.0".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 11)),
            }],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let cached_versions = HashMap::new();
        let resolved_versions = HashMap::new();

        let diagnostics = generate_diagnostics_from_cache(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions),
            &formatter,
            crate::freshness::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
            PublishTime::now(),
        );

        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].severity, Some(DiagnosticSeverity::WARNING));
        assert!(diagnostics[0].message.contains("Unknown package"));
        assert!(diagnostics[0].message.contains("unknown-pkg"));
    }

    #[test]
    fn test_generate_diagnostics_from_cache_fetch_failed_not_reported_as_unknown() {
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

        // A package missing from `cached` because its registry fetch errored
        // or timed out (#267) must not be reported as "Unknown package" — the
        // registry was never successfully asked, so absence is not evidence
        // the package doesn't exist.
        let formatter = MockFormatter;

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "flaky-pkg".into(),
                version_req: "1.0.0".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 11)),
            }],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let cached_versions = HashMap::new();
        let resolved_versions = HashMap::new();
        let fetch_failed = HashSet::from(["flaky-pkg".to_string()]);

        let diagnostics = generate_diagnostics_from_cache(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions).with_fetch_failed(&fetch_failed),
            &formatter,
            crate::freshness::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
            PublishTime::now(),
        );

        assert_eq!(diagnostics.len(), 1);
        assert!(!diagnostics[0].message.contains("Unknown package"));
        assert!(diagnostics[0].message.contains("Registry lookup failed"));
        assert!(diagnostics[0].message.contains("flaky-pkg"));
    }

    #[test]
    fn test_generate_diagnostics_from_cache_fetch_failed_does_not_mask_invalid_name() {
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

        // A syntactically invalid name is a local, name-only check independent
        // of any registry round trip — it must win over a fetch-failure
        // marker for the same (invalid) name, not be suppressed by it.
        let formatter = RejectingFormatter;

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "bad name".into(),
                version_req: "1.0.0".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 11)),
            }],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let cached_versions = HashMap::new();
        let resolved_versions = HashMap::new();
        let fetch_failed = HashSet::from(["bad name".to_string()]);

        let diagnostics = generate_diagnostics_from_cache(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions).with_fetch_failed(&fetch_failed),
            &formatter,
            crate::freshness::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
            PublishTime::now(),
        );

        assert_eq!(diagnostics.len(), 1);
        assert!(diagnostics[0].message.contains("Invalid package name"));
    }

    #[test]
    fn test_generate_diagnostics_from_cache_invalid_package_name() {
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

        // A formatter that rejects every name must produce exactly one
        // "Invalid package name" diagnostic per unresolved dependency, never
        // both that and "Unknown package".
        let formatter = RejectingFormatter;

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "bad-pkg".into(),
                version_req: "1.0.0".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 7)),
            }],
            uri: crate::test_util::test_uri("/test/package.json"),
        };

        let cached_versions = HashMap::new();
        let resolved_versions = HashMap::new();

        let diagnostics = generate_diagnostics_from_cache(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions),
            &formatter,
            crate::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
            PublishTime::now(),
        );

        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].severity, Some(DiagnosticSeverity::WARNING));
        assert!(diagnostics[0].message.starts_with("Invalid package name"));
        assert!(!diagnostics[0].message.contains("Unknown package"));
    }

    #[tokio::test]
    async fn test_generate_diagnostics_invalid_package_name() {
        use tower_lsp_server::ls_types::{Position, Range};

        // Network variant: a registry lookup failure combined with a rejected
        // name must produce "Invalid package name", not "Unknown package".
        let formatter = RejectingFormatter;

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "bad-pkg".into(),
                version_req: "1.0.0".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 7)),
            }],
            uri: crate::test_util::test_uri("/test/package.json"),
        };

        let diagnostics = generate_diagnostics(
            &parse_result,
            &ErrorRegistry,
            &formatter,
            crate::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
        )
        .await;

        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].severity, Some(DiagnosticSeverity::WARNING));
        assert!(diagnostics[0].message.starts_with("Invalid package name"));
        assert!(!diagnostics[0].message.contains("Unknown package"));
    }

    #[tokio::test]
    async fn test_generate_diagnostics_unknown_uses_configured_severity() {
        use tower_lsp_server::ls_types::{Position, Range};

        // `NotFoundRegistry`, not `ErrorRegistry`: "Unknown package" is only
        // correct when the registry was actually asked and said "no such
        // package" (#267 C1) — an opaque `CacheError` must not reach this
        // branch, or a transient outage would be mislabeled as a genuinely
        // nonexistent dependency.
        let formatter = MockFormatter;

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "serde".into(),
                version_req: "1.0.0".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)),
            }],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let severities = DiagnosticSeverities {
            unknown: DiagnosticSeverity::ERROR,
            ..DiagnosticSeverities::default()
        };

        let diagnostics = generate_diagnostics(
            &parse_result,
            &NotFoundRegistry,
            &formatter,
            crate::FreshnessSettings::default(),
            severities,
        )
        .await;

        assert_eq!(diagnostics.len(), 1);
        assert!(diagnostics[0].message.starts_with("Unknown package"));
        assert_eq!(diagnostics[0].severity, Some(DiagnosticSeverity::ERROR));
    }

    #[tokio::test]
    async fn test_generate_diagnostics_registry_error_not_reported_as_unknown() {
        use tower_lsp_server::ls_types::{Position, Range};

        // #267 C1: an opaque registry failure (`ErrorRegistry`'s `CacheError`,
        // standing in for a network error, timeout, or malformed response)
        // must not produce "Unknown package" — the registry was never
        // successfully asked, so absence of a result is not evidence the
        // package doesn't exist.
        let formatter = MockFormatter;

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "serde".into(),
                version_req: "1.0.0".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)),
            }],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let diagnostics = generate_diagnostics(
            &parse_result,
            &ErrorRegistry,
            &formatter,
            crate::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
        )
        .await;

        assert_eq!(diagnostics.len(), 1);
        assert!(!diagnostics[0].message.contains("Unknown package"));
        assert!(diagnostics[0].message.contains("Registry lookup failed"));
    }

    #[tokio::test]
    async fn test_generate_diagnostics_outdated_uses_configured_severity() {
        use tower_lsp_server::ls_types::{Position, Range};

        let formatter = MockFormatter;

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "serde".into(),
                version_req: "1.0.0".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)),
            }],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let severities = DiagnosticSeverities {
            outdated: DiagnosticSeverity::ERROR,
            ..DiagnosticSeverities::default()
        };

        let diagnostics = generate_diagnostics(
            &parse_result,
            &OutdatedRegistry,
            &formatter,
            crate::FreshnessSettings::default(),
            severities,
        )
        .await;

        let outdated_diag = diagnostics
            .iter()
            .find(|d| d.message.starts_with("Newer version available"))
            .expect("expected an outdated diagnostic");
        assert_eq!(outdated_diag.severity, Some(DiagnosticSeverity::ERROR));
    }

    #[test]
    fn test_generate_diagnostics_from_cache_outdated_version() {
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

        let formatter = MockFormatter;

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "serde".into(),
                version_req: "1.0".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)),
            }],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let mut cached_versions = HashMap::new();
        cached_versions.insert("serde".into(), PackageVersions::latest_only("2.0.0"));

        let resolved_versions = HashMap::new();

        let diagnostics = generate_diagnostics_from_cache(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions),
            &formatter,
            crate::freshness::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
            PublishTime::now(),
        );

        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].severity, Some(DiagnosticSeverity::HINT));
        assert!(diagnostics[0].message.contains("Newer version available"));
        assert!(diagnostics[0].message.contains("2.0.0"));
    }

    /// Issue #227 §4.3: an outdated dependency whose `latest` was published within the
    /// configured cooldown window gets the extra context appended, severity unchanged.
    #[test]
    fn test_generate_diagnostics_from_cache_outdated_within_cooldown_appends_context() {
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

        let formatter = MockFormatter;

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "serde".into(),
                version_req: "1.0".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)),
            }],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let mut cached_versions = HashMap::new();
        cached_versions.insert(
            "serde".into(),
            PackageVersions {
                latest: "2.0.0".into(),
                available: Arc::from(vec!["2.0.0".into()]),
                yanked: Arc::from(Vec::new()),
                // 1 hour ago — well within the default 3-day cooldown.
                published_at: Some(PublishTime::from_unix_secs(
                    PublishTime::now().as_unix_secs() - 60 * 60,
                )),
            },
        );
        let resolved_versions = HashMap::new();

        let diagnostics = generate_diagnostics_from_cache(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions),
            &formatter,
            crate::freshness::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
            PublishTime::now(),
        );

        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].severity, Some(DiagnosticSeverity::HINT));
        assert_eq!(
            diagnostics[0].message,
            "Newer version available: 2.0.0 (published 1 hour ago — still within the release cooldown window)"
        );
        // Guards against reintroducing the "ago ago" duplication bug found while
        // writing this test — `format_relative_age` already appends "ago".
        assert!(!diagnostics[0].message.contains("ago ago"));
    }

    /// Same setup, but `latest` was published well outside the cooldown window — the
    /// message must stay exactly the pre-feature text.
    #[test]
    fn test_generate_diagnostics_from_cache_outdated_outside_cooldown_plain_message() {
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

        let formatter = MockFormatter;

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "serde".into(),
                version_req: "1.0".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)),
            }],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let mut cached_versions = HashMap::new();
        cached_versions.insert(
            "serde".into(),
            PackageVersions {
                latest: "2.0.0".into(),
                available: Arc::from(vec!["2.0.0".into()]),
                yanked: Arc::from(Vec::new()),
                // 10 days ago — outside the default 3-day cooldown.
                published_at: Some(PublishTime::from_unix_secs(
                    PublishTime::now().as_unix_secs() - 10 * 24 * 60 * 60,
                )),
            },
        );
        let resolved_versions = HashMap::new();

        let diagnostics = generate_diagnostics_from_cache(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions),
            &formatter,
            crate::freshness::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
            PublishTime::now(),
        );

        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].message, "Newer version available: 2.0.0");
    }

    /// `freshness.enabled: false` suppresses the cooldown differentiation even when the
    /// publish age would otherwise qualify.
    #[test]
    fn test_generate_diagnostics_from_cache_outdated_freshness_disabled_plain_message() {
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

        let formatter = MockFormatter;

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "serde".into(),
                version_req: "1.0".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)),
            }],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let mut cached_versions = HashMap::new();
        cached_versions.insert(
            "serde".into(),
            PackageVersions {
                latest: "2.0.0".into(),
                available: Arc::from(vec!["2.0.0".into()]),
                yanked: Arc::from(Vec::new()),
                published_at: Some(PublishTime::from_unix_secs(
                    PublishTime::now().as_unix_secs() - 60 * 60,
                )),
            },
        );
        let resolved_versions = HashMap::new();

        let diagnostics = generate_diagnostics_from_cache(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions),
            &formatter,
            crate::freshness::FreshnessSettings {
                enabled: false,
                ..crate::freshness::FreshnessSettings::default()
            },
            DiagnosticSeverities::default(),
            PublishTime::now(),
        );

        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].message, "Newer version available: 2.0.0");
    }

    /// Deterministic boundary test (issue #227 M4): `now` is threaded in as a parameter
    /// rather than read internally, so `published_at`/`now`/`cooldown_secs` can be pinned
    /// to fixed absolute values with no wall-clock dependency. `age == cooldown_secs`
    /// exactly must NOT be within cooldown — the bound is exclusive (`age < cooldown`).
    #[test]
    fn test_generate_diagnostics_from_cache_outdated_cooldown_boundary_is_exclusive() {
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

        const COOLDOWN_SECS: u64 = 100;
        let now = PublishTime::from_unix_secs(10_000);
        let published_at_at_boundary =
            PublishTime::from_unix_secs(10_000 - COOLDOWN_SECS.cast_signed());

        let formatter = MockFormatter;
        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "serde".into(),
                version_req: "1.0".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)),
            }],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let mut cached_versions = HashMap::new();
        cached_versions.insert(
            "serde".into(),
            PackageVersions {
                latest: "2.0.0".into(),
                available: Arc::from(vec!["2.0.0".into()]),
                yanked: Arc::from(Vec::new()),
                published_at: Some(published_at_at_boundary),
            },
        );
        let resolved_versions = HashMap::new();

        let diagnostics = generate_diagnostics_from_cache(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions),
            &formatter,
            crate::freshness::FreshnessSettings {
                enabled: true,
                cooldown_secs: COOLDOWN_SECS,
            },
            DiagnosticSeverities::default(),
            now,
        );

        assert_eq!(diagnostics.len(), 1);
        assert_eq!(
            diagnostics[0].message, "Newer version available: 2.0.0",
            "age exactly equal to cooldown_secs must not be within cooldown"
        );
    }

    /// Same fixture, one second younger — must flip to the within-cooldown message.
    #[test]
    fn test_generate_diagnostics_from_cache_outdated_cooldown_boundary_one_second_inside() {
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

        const COOLDOWN_SECS: u64 = 100;
        let now = PublishTime::from_unix_secs(10_000);
        let published_at_just_inside =
            PublishTime::from_unix_secs(10_000 - (COOLDOWN_SECS.cast_signed() - 1));

        let formatter = MockFormatter;
        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "serde".into(),
                version_req: "1.0".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)),
            }],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let mut cached_versions = HashMap::new();
        cached_versions.insert(
            "serde".into(),
            PackageVersions {
                latest: "2.0.0".into(),
                available: Arc::from(vec!["2.0.0".into()]),
                yanked: Arc::from(Vec::new()),
                published_at: Some(published_at_just_inside),
            },
        );
        let resolved_versions = HashMap::new();

        let diagnostics = generate_diagnostics_from_cache(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions),
            &formatter,
            crate::freshness::FreshnessSettings {
                enabled: true,
                cooldown_secs: COOLDOWN_SECS,
            },
            DiagnosticSeverities::default(),
            now,
        );

        assert_eq!(diagnostics.len(), 1);
        assert_eq!(
            diagnostics[0].message,
            "Newer version available: 2.0.0 (published 1 minute ago — still within the release cooldown window)",
            "age == cooldown_secs - 1 must be within cooldown"
        );
    }

    #[test]
    fn test_generate_diagnostics_from_cache_up_to_date() {
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

        let formatter = MockFormatter;

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "serde".into(),
                version_req: "^1.0".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)),
            }],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let mut cached_versions = HashMap::new();
        cached_versions.insert("serde".into(), PackageVersions::latest_only("1.0.214"));

        let resolved_versions = HashMap::new();

        let diagnostics = generate_diagnostics_from_cache(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions),
            &formatter,
            crate::freshness::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
            PublishTime::now(),
        );

        assert!(
            diagnostics.is_empty(),
            "Expected no diagnostics for up-to-date dependency"
        );
    }

    #[test]
    fn test_generate_diagnostics_from_cache_multiple_deps() {
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

        let formatter = MockFormatter;

        let parse_result = MockParseResult {
            deps: vec![
                MockDep {
                    name: "serde".into(),
                    version_req: "^1.0".into(),
                    version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                    name_range: Range::new(Position::new(0, 0), Position::new(0, 5)),
                },
                MockDep {
                    name: "tokio".into(),
                    version_req: "1.0".into(),
                    version_range: Range::new(Position::new(1, 10), Position::new(1, 20)),
                    name_range: Range::new(Position::new(1, 0), Position::new(1, 5)),
                },
                MockDep {
                    name: "unknown".into(),
                    version_req: "1.0".into(),
                    version_range: Range::new(Position::new(2, 10), Position::new(2, 20)),
                    name_range: Range::new(Position::new(2, 0), Position::new(2, 7)),
                },
            ],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let mut cached_versions = HashMap::new();
        cached_versions.insert("serde".into(), PackageVersions::latest_only("1.0.214"));
        cached_versions.insert("tokio".into(), PackageVersions::latest_only("2.0.0"));

        let resolved_versions = HashMap::new();

        let diagnostics = generate_diagnostics_from_cache(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions),
            &formatter,
            crate::freshness::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
            PublishTime::now(),
        );

        assert_eq!(diagnostics.len(), 2);

        let has_outdated = diagnostics
            .iter()
            .any(|d| d.message.contains("Newer version"));
        let has_unknown = diagnostics
            .iter()
            .any(|d| d.message.contains("Unknown package"));

        assert!(has_outdated, "Expected outdated version diagnostic");
        assert!(has_unknown, "Expected unknown package diagnostic");
    }

    #[test]
    fn test_generate_diagnostics_from_cache_unresolved_emits_no_diagnostic() {
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

        let formatter = MockUnresolvedFormatter;

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "spring-boot-starter".into(),
                version_req: "$missing".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)),
            }],
            uri: crate::test_util::test_uri("/test/libs.versions.toml"),
        };

        let mut cached_versions = HashMap::new();
        cached_versions.insert(
            "spring-boot-starter".into(),
            PackageVersions::latest_only("3.2.0"),
        );

        let resolved_versions = HashMap::new();

        let diagnostics = generate_diagnostics_from_cache(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions),
            &formatter,
            crate::freshness::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
            PublishTime::now(),
        );

        assert!(
            diagnostics.is_empty(),
            "Expected no diagnostics for an unresolved requirement, got: {diagnostics:?}"
        );
    }

    #[test]
    fn test_generate_diagnostics_from_cache_yanked_uses_configured_severity() {
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

        let formatter = MockFormatter;

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "serde".into(),
                version_req: "1.0.5".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)),
            }],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let cached_versions = HashMap::new();
        let resolved_versions = HashMap::new();
        let mut yanked = HashMap::new();
        yanked.insert("serde".to_string(), "1.0.5".into());

        let severities = DiagnosticSeverities {
            yanked: DiagnosticSeverity::ERROR,
            ..DiagnosticSeverities::default()
        };

        let diagnostics = generate_diagnostics_from_cache(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions).with_yanked(&yanked),
            &formatter,
            crate::freshness::FreshnessSettings::default(),
            severities,
            PublishTime::now(),
        );

        let yanked_diag = diagnostics
            .iter()
            .find(|d| d.message.starts_with(formatter.yanked_message()))
            .expect("expected a yanked diagnostic");
        assert_eq!(yanked_diag.severity, Some(DiagnosticSeverity::ERROR));
        assert!(yanked_diag.message.contains("1.0.5"));
    }

    #[test]
    fn test_generate_diagnostics_from_cache_yanked_default_severity_unchanged() {
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

        let formatter = MockFormatter;

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "serde".into(),
                version_req: "1.0.5".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)),
            }],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let cached_versions = HashMap::new();
        let resolved_versions = HashMap::new();
        let mut yanked = HashMap::new();
        yanked.insert("serde".to_string(), "1.0.5".into());

        let diagnostics = generate_diagnostics_from_cache(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions).with_yanked(&yanked),
            &formatter,
            crate::freshness::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
            PublishTime::now(),
        );

        let yanked_diag = diagnostics
            .iter()
            .find(|d| d.message.starts_with(formatter.yanked_message()))
            .expect("expected a yanked diagnostic");
        assert_eq!(yanked_diag.severity, Some(DiagnosticSeverity::WARNING));
    }

    #[test]
    fn test_generate_diagnostics_from_cache_no_yanked_map_emits_no_yanked_diagnostic() {
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

        // Regression guard for the four handlers (hover, completion, code_lens,
        // inlay_hints) that keep calling `VersionData::new` without
        // `.with_yanked(..)` — `yanked: None` must never produce a diagnostic.
        let formatter = MockFormatter;

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "serde".into(),
                version_req: "1.0.5".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)),
            }],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let mut cached_versions = HashMap::new();
        cached_versions.insert("serde".into(), PackageVersions::latest_only("1.0.5"));
        let resolved_versions = HashMap::new();

        let diagnostics = generate_diagnostics_from_cache(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions),
            &formatter,
            crate::freshness::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
            PublishTime::now(),
        );

        assert!(
            !diagnostics
                .iter()
                .any(|d| d.message.starts_with(formatter.yanked_message())),
            "Expected no yanked diagnostic when `yanked` is None, got: {diagnostics:?}"
        );
    }

    #[test]
    fn test_generate_diagnostics_from_cache_yanked_and_outdated_both_emitted() {
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

        // Proves the yanked push sits before the early-`continue`s, so a dep
        // that is both yanked (in-use version) and outdated (vs. latest)
        // gets both diagnostics.
        let formatter = MockFormatter;

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "serde".into(),
                version_req: "1.0.5".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)),
            }],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let mut cached_versions = HashMap::new();
        cached_versions.insert("serde".into(), PackageVersions::latest_only("2.0.0"));
        let resolved_versions = HashMap::new();
        let mut yanked = HashMap::new();
        yanked.insert("serde".to_string(), "1.0.5".into());

        let diagnostics = generate_diagnostics_from_cache(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions).with_yanked(&yanked),
            &formatter,
            crate::freshness::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
            PublishTime::now(),
        );

        assert_eq!(
            diagnostics.len(),
            2,
            "expected both diagnostics: {diagnostics:?}"
        );
        assert!(
            diagnostics
                .iter()
                .any(|d| d.message.starts_with(formatter.yanked_message()))
        );
        assert!(
            diagnostics
                .iter()
                .any(|d| d.message.contains("Newer version available"))
        );
    }

    #[test]
    fn test_generate_diagnostics_from_cache_yanked_no_version_range_uses_name_range() {
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

        let formatter = MockFormatter;
        let name_range = Range::new(Position::new(0, 0), Position::new(0, 5));

        let parse_result = MockMarkedParseResult {
            dep: MockMarkedDep {
                name: "serde".into(),
                name_range,
                markers: None,
            },
            uri: crate::test_util::test_uri("/test/pyproject.toml"),
        };

        let cached_versions = HashMap::new();
        let resolved_versions = HashMap::new();
        let mut yanked = HashMap::new();
        yanked.insert("serde".to_string(), "1.0.5".into());

        let diagnostics = generate_diagnostics_from_cache(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions).with_yanked(&yanked),
            &formatter,
            crate::freshness::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
            PublishTime::now(),
        );

        let yanked_diag = diagnostics
            .iter()
            .find(|d| d.message.starts_with(formatter.yanked_message()))
            .expect("expected a yanked diagnostic even without a version_range");
        assert_eq!(yanked_diag.range, name_range);
    }

    #[test]
    fn test_generate_diagnostics_from_cache_yanked_normalized_name_keying() {
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

        /// Mirrors a Composer/NuGet/Swift-shaped formatter whose normalized
        /// name differs from the manifest-declared raw name.
        struct MockLowercaseFormatter;
        impl EcosystemFormatter for MockLowercaseFormatter {
            fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
                version.to_string()
            }
            fn package_url(&self, name: &PackageName) -> String {
                format!("https://example.com/{name}")
            }
            fn normalize_package_name(&self, name: &PackageName) -> String {
                name.to_string().to_lowercase()
            }
        }

        let formatter = MockLowercaseFormatter;

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "Newtonsoft.Json".into(),
                version_req: "13.0.1".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)),
            }],
            uri: crate::test_util::test_uri("/test/project.csproj"),
        };

        let cached_versions = HashMap::new();
        let resolved_versions = HashMap::new();
        let mut yanked = HashMap::new();
        // Keyed by the *normalized* (lowercase) name, not the raw manifest name.
        yanked.insert("newtonsoft.json".to_string(), "13.0.1".into());

        let diagnostics = generate_diagnostics_from_cache(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions).with_yanked(&yanked),
            &formatter,
            crate::freshness::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
            PublishTime::now(),
        );

        assert!(
            diagnostics
                .iter()
                .any(|d| d.message.starts_with(formatter.yanked_message())),
            "expected normalized-name lookup to resolve the yanked entry, got: {diagnostics:?}"
        );
    }

    #[test]
    fn test_generate_diagnostics_from_cache_yanked_not_shared_across_duplicate_name_occurrences() {
        // #394 S1: two occurrences of `time` (e.g. under `[dependencies]` and
        // `[dev-dependencies]`) pinned to different exact versions, only one
        // of which is actually yanked. `yanked` is name-keyed (single value),
        // recording only "0.1.43" — the occurrence pinned to "0.1.44" must
        // NOT also render "yanked (0.1.43)" just because it shares the name;
        // that version string doesn't even appear on its line.
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

        let formatter = MockFormatter;

        let parse_result = MockParseResult {
            deps: vec![
                MockDep {
                    name: "time".into(),
                    version_req: "=0.1.43".into(),
                    version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                    name_range: Range::new(Position::new(0, 0), Position::new(0, 5)),
                },
                MockDep {
                    name: "time".into(),
                    version_req: "=0.1.44".into(),
                    version_range: Range::new(Position::new(3, 10), Position::new(3, 20)),
                    name_range: Range::new(Position::new(3, 0), Position::new(3, 5)),
                },
            ],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let cached_versions = HashMap::new();
        let resolved_versions = HashMap::new();
        let mut yanked = HashMap::new();
        yanked.insert("time".to_string(), "0.1.43".into());

        let diagnostics = generate_diagnostics_from_cache(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions)
                .with_yanked(&yanked)
                .with_ecosystem(crate::EcosystemId::Cargo),
            &formatter,
            crate::freshness::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
            PublishTime::now(),
        );

        let yanked_diags: Vec<_> = diagnostics
            .iter()
            .filter(|d| d.message.starts_with(formatter.yanked_message()))
            .collect();
        assert_eq!(
            yanked_diags.len(),
            1,
            "exactly one occurrence must get the yanked diagnostic, got: {diagnostics:?}"
        );
        assert_eq!(
            yanked_diags[0].range.start.line, 0,
            "must land on the yanked occurrence's own line"
        );
        assert!(yanked_diags[0].message.contains("0.1.43"));
    }

    #[test]
    fn test_generate_diagnostics_from_cache_yanked_no_ecosystem_keeps_pre_394_behavior() {
        // Without `with_ecosystem` (most test fixtures, and any caller that
        // predates #394), the consistency check is skipped entirely and both
        // occurrences render the shared name-keyed finding — the exact
        // pre-#394 behavior, preserved deliberately for backward
        // compatibility rather than silently tightened.
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

        let formatter = MockFormatter;

        let parse_result = MockParseResult {
            deps: vec![
                MockDep {
                    name: "time".into(),
                    version_req: "=0.1.43".into(),
                    version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                    name_range: Range::new(Position::new(0, 0), Position::new(0, 5)),
                },
                MockDep {
                    name: "time".into(),
                    version_req: "=0.1.44".into(),
                    version_range: Range::new(Position::new(3, 10), Position::new(3, 20)),
                    name_range: Range::new(Position::new(3, 0), Position::new(3, 5)),
                },
            ],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let cached_versions = HashMap::new();
        let resolved_versions = HashMap::new();
        let mut yanked = HashMap::new();
        yanked.insert("time".to_string(), "0.1.43".into());

        let diagnostics = generate_diagnostics_from_cache(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions).with_yanked(&yanked),
            &formatter,
            crate::freshness::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
            PublishTime::now(),
        );

        let yanked_diags = diagnostics
            .iter()
            .filter(|d| d.message.starts_with(formatter.yanked_message()))
            .count();
        assert_eq!(
            yanked_diags, 2,
            "no `ecosystem` set: both occurrences share the finding as before #394"
        );
    }

    #[test]
    fn test_generate_diagnostics_unsatisfiable_enriched_with_matching_prerelease() {
        let cached_versions = {
            let mut m = HashMap::new();
            m.insert(
                "dep".into(),
                PackageVersions {
                    latest: "1.5.0".into(),
                    available: Arc::from(vec!["2.0.0-rc.1".into(), "1.5.0".into(), "1.4.0".into()]),
                    yanked: Arc::from(Vec::new()),
                    published_at: None,
                },
            );
            m
        };
        let resolved_versions = HashMap::new();
        let uri = crate::test_util::test_uri("/test/Cargo.toml");
        let mut dependency = dep_at("dep");
        dependency.version_req = VersionReq::new("^2.0.0");
        let parse_result = SingleDepParseResult {
            dep: dependency,
            uri,
        };

        let diagnostics = generate_diagnostics_from_cache(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions),
            &StrictSemverFormatter,
            crate::freshness::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
            PublishTime::now(),
        );

        let message = diagnostics
            .iter()
            .find(|d| d.message.contains("No published version satisfies"))
            .map(|d| d.message.as_str())
            .expect("unsatisfiable WARNING must fire");
        assert!(
            message.contains("2.0.0-rc.1") && message.contains("pre-release"),
            "message must mention the matching pre-release, got: {message}"
        );
    }

    #[test]
    fn test_generate_diagnostics_unsatisfiable_no_enrichment_without_matching_prerelease() {
        let cached_versions = {
            let mut m = HashMap::new();
            m.insert(
                "dep".into(),
                PackageVersions {
                    latest: "1.5.0".into(),
                    available: Arc::from(vec!["1.5.0".into(), "1.4.0".into()]),
                    yanked: Arc::from(Vec::new()),
                    published_at: None,
                },
            );
            m
        };
        let resolved_versions = HashMap::new();
        let uri = crate::test_util::test_uri("/test/Cargo.toml");
        let mut dependency = dep_at("dep");
        dependency.version_req = VersionReq::new("^2.0.0");
        let parse_result = SingleDepParseResult {
            dep: dependency,
            uri,
        };

        let diagnostics = generate_diagnostics_from_cache(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions),
            &StrictSemverFormatter,
            crate::freshness::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
            PublishTime::now(),
        );

        let message = diagnostics
            .iter()
            .find(|d| d.message.contains("No published version satisfies"))
            .map(|d| d.message.as_str())
            .expect("unsatisfiable WARNING must fire");
        assert!(
            !message.contains("pre-release"),
            "message must not mention a pre-release when none satisfies, got: {message}"
        );
    }

    #[test]
    fn test_generate_diagnostics_unsatisfiable_skipped_for_non_registry_sources() {
        use crate::parser::DependencySource;

        let cached_versions = {
            let mut m = HashMap::new();
            m.insert("dep".into(), PackageVersions::latest_only("9.9.9"));
            m
        };
        let resolved_versions = HashMap::new();
        let uri = crate::test_util::test_uri("/test/Cargo.toml");

        // Requirement "1.0.0" against available ["9.9.9"] is unsatisfiable
        // under ExactMatchFormatter — proven by the Registry-source case below.
        for source in [
            DependencySource::Path {
                path: "../local".into(),
            },
            DependencySource::Git {
                url: "https://example.com/repo.git".into(),
                rev: None,
            },
            DependencySource::Url {
                url: "https://example.com/pkg.tar.gz".into(),
            },
            DependencySource::Sdk {
                sdk: "flutter".into(),
            },
            DependencySource::Workspace,
            DependencySource::CustomRegistry {
                url: "my-corp".into(),
            },
        ] {
            let parse_result = SingleDepParseResult {
                dep: NonRegistryDep(dep_at("dep"), source.clone()),
                uri: uri.clone(),
            };
            let diagnostics = generate_diagnostics_from_cache(
                &parse_result,
                VersionData::new(&cached_versions, &resolved_versions),
                &ExactMatchFormatter,
                crate::freshness::FreshnessSettings::default(),
                DiagnosticSeverities::default(),
                PublishTime::now(),
            );
            assert!(
                diagnostics
                    .iter()
                    .all(|d| !d.message.contains("No published version satisfies")),
                "source {source:?} must never produce the unsatisfiable-requirement WARNING"
            );
        }

        // Control: the same requirement/available pair on a Registry-source
        // dependency DOES produce the WARNING, proving the loop above isn't
        // vacuously passing because the fixture never triggers it at all.
        let registry_parse_result = SingleDepParseResult {
            dep: dep_at("dep"),
            uri,
        };
        let diagnostics = generate_diagnostics_from_cache(
            &registry_parse_result,
            VersionData::new(&cached_versions, &resolved_versions),
            &ExactMatchFormatter,
            crate::freshness::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
            PublishTime::now(),
        );
        assert!(
            diagnostics
                .iter()
                .any(|d| d.message.contains("No published version satisfies")),
            "control case: a Registry-source dependency must still produce the WARNING"
        );
    }

    #[test]
    fn test_generate_diagnostics_unknown_package_skipped_for_non_registry_sources() {
        use crate::parser::DependencySource;

        // No cache entry at all for "dep" — simulates a `CustomRegistry`
        // dependency, which this LSP never fetches from a real registry.
        let cached_versions = HashMap::new();
        let resolved_versions = HashMap::new();
        let uri = crate::test_util::test_uri("/test/Cargo.toml");

        let parse_result = SingleDepParseResult {
            dep: NonRegistryDep(
                dep_at("dep"),
                DependencySource::CustomRegistry {
                    url: "my-corp".into(),
                },
            ),
            uri: uri.clone(),
        };
        let diagnostics = generate_diagnostics_from_cache(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions),
            &MockFormatter,
            crate::freshness::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
            PublishTime::now(),
        );
        assert!(
            diagnostics
                .iter()
                .all(|d| !d.message.contains("Unknown package")),
            "a CustomRegistry-sourced dependency must never produce the \"Unknown package\" WARNING"
        );

        // Control: the same missing cache entry on a Registry-source
        // dependency DOES produce the WARNING.
        let registry_parse_result = SingleDepParseResult {
            dep: dep_at("dep"),
            uri,
        };
        let diagnostics = generate_diagnostics_from_cache(
            &registry_parse_result,
            VersionData::new(&cached_versions, &resolved_versions),
            &MockFormatter,
            crate::freshness::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
            PublishTime::now(),
        );
        assert!(
            diagnostics
                .iter()
                .any(|d| d.message.contains("Unknown package")),
            "control case: a Registry-source dependency must still produce the WARNING"
        );
    }

    #[test]
    fn test_generate_diagnostics_invalid_name_still_reported_for_non_registry_sources() {
        use crate::parser::DependencySource;

        // Invalid-name validation is pure syntax checking, independent of
        // registry data — it must still fire even when the source is not
        // resolvable (unlike "Unknown package", which requires a real lookup).
        let cached_versions = HashMap::new();
        let resolved_versions = HashMap::new();
        let uri = crate::test_util::test_uri("/test/package.json");

        let parse_result = SingleDepParseResult {
            dep: NonRegistryDep(
                dep_at("dep"),
                DependencySource::CustomRegistry {
                    url: "my-corp".into(),
                },
            ),
            uri,
        };
        let diagnostics = generate_diagnostics_from_cache(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions),
            &RejectingFormatter,
            crate::freshness::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
            PublishTime::now(),
        );
        assert_eq!(diagnostics.len(), 1);
        assert!(diagnostics[0].message.starts_with("Invalid package name"));
    }

    #[test]
    fn test_generate_diagnostics_outdated_skipped_for_non_registry_sources() {
        use crate::parser::DependencySource;

        // "dep" resolves to a coincidentally-matching cache entry with a newer
        // "latest", as would happen for a Cargo path dependency that happens
        // to share a name with an unrelated published crate.
        let cached_versions = {
            let mut m = HashMap::new();
            m.insert("dep".into(), PackageVersions::latest_only("9.9.9"));
            m
        };
        let resolved_versions = HashMap::new();
        let uri = crate::test_util::test_uri("/test/Cargo.toml");

        let parse_result = SingleDepParseResult {
            dep: NonRegistryDep(
                dep_at("dep"),
                DependencySource::CustomRegistry {
                    url: "my-corp".into(),
                },
            ),
            uri: uri.clone(),
        };
        let diagnostics = generate_diagnostics_from_cache(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions),
            &MockFormatter,
            crate::freshness::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
            PublishTime::now(),
        );
        assert!(
            diagnostics
                .iter()
                .all(|d| !d.message.contains("Newer version available")),
            "a CustomRegistry-sourced dependency must never produce the \"Outdated\" WARNING"
        );

        // Control: the same requirement/cache pair on a Registry-source
        // dependency DOES produce the WARNING.
        let registry_parse_result = SingleDepParseResult {
            dep: dep_at("dep"),
            uri,
        };
        let diagnostics = generate_diagnostics_from_cache(
            &registry_parse_result,
            VersionData::new(&cached_versions, &resolved_versions),
            &MockFormatter,
            crate::freshness::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
            PublishTime::now(),
        );
        assert!(
            diagnostics
                .iter()
                .any(|d| d.message.contains("Newer version available")),
            "control case: a Registry-source dependency must still produce the WARNING"
        );
    }

    #[test]
    fn test_generate_diagnostics_vulnerable_dependency_emits_advisory_diagnostic_even_without_registry_data()
     {
        use crate::osv::{
            DependencyVulnerabilities, ScanOutcome, UpgradeStatus, VulnSeverity, VulnerabilityMap,
        };

        let formatter = MockFormatter;
        let parse_result = MockParseResult {
            deps: vec![dep_at("vulnerable-pkg")],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        // Registry data is entirely absent (as if the registry fetch failed),
        // which must never suppress the OSV finding.
        let cached_versions = HashMap::new();
        let resolved_versions = HashMap::new();

        let mut vulns: VulnerabilityMap = VulnerabilityMap::new();
        vulns.insert(
            "vulnerable-pkg".to_string(),
            ScanOutcome::Vulnerable(DependencyVulnerabilities {
                advisories: vec![sample_advisory("RUSTSEC-2020-0071", VulnSeverity::High)],
                total_known: 1,
                upgrade_status: UpgradeStatus::NotChecked,
            }),
        );

        let diagnostics = generate_diagnostics_from_cache(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions).with_vulnerabilities(&vulns),
            &formatter,
            crate::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
            PublishTime::now(),
        );

        let vuln_diag = diagnostics
            .iter()
            .find(|d| d.message.contains("RUSTSEC-2020-0071"))
            .expect("vulnerability diagnostic must be emitted even without registry data");
        assert_eq!(vuln_diag.severity, Some(DiagnosticSeverity::WARNING));
        assert_eq!(
            vuln_diag.code,
            Some(NumberOrString::String("RUSTSEC-2020-0071".to_string()))
        );
    }

    #[test]
    fn test_generate_diagnostics_advisory_cap_emits_more_count_from_total_known() {
        use crate::osv::{
            DependencyVulnerabilities, ScanOutcome, UpgradeStatus, VulnSeverity, VulnerabilityMap,
        };

        let formatter = MockFormatter;
        let parse_result = MockParseResult {
            deps: vec![dep_at("noisy-pkg")],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };
        let cached_versions = HashMap::new();
        let resolved_versions = HashMap::new();

        let advisories: Vec<_> = (0..ADVISORY_DISPLAY_CAP)
            .map(|i| sample_advisory(&format!("ADV-{i}"), VulnSeverity::Low))
            .collect();

        let mut vulns: VulnerabilityMap = VulnerabilityMap::new();
        vulns.insert(
            "noisy-pkg".to_string(),
            ScanOutcome::Vulnerable(DependencyVulnerabilities {
                advisories,
                total_known: 40,
                upgrade_status: UpgradeStatus::NotChecked,
            }),
        );

        let diagnostics = generate_diagnostics_from_cache(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions).with_vulnerabilities(&vulns),
            &formatter,
            crate::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
            PublishTime::now(),
        );

        let more_diag = diagnostics
            .iter()
            .find(|d| d.message.contains("more advisories"))
            .expect("expected a trailing +N more advisories diagnostic");
        assert!(
            more_diag.message.contains("+35"),
            "got: {}",
            more_diag.message
        );
    }

    #[test]
    fn test_generate_diagnostics_vulnerability_not_shared_across_duplicate_name_occurrences() {
        // #394 S2: two occurrences of `pkg` (e.g. under `[dependencies]` and
        // `[dev-dependencies]`) pinned to different versions — one vulnerable,
        // one patched. Built via `vulnerability_keys` the same way
        // `deps-lsp`'s `build_scan_targets` would, so each occurrence's OSV
        // result lands under its own key instead of colliding on the plain
        // name. The patched occurrence must render no advisory diagnostic.
        use crate::osv::{
            DependencyVulnerabilities, ScanOutcome, UpgradeStatus, VulnSeverity, VulnerabilityMap,
            vulnerability_keys,
        };
        use tower_lsp_server::ls_types::{Position, Range};

        let formatter = MockFormatter;

        let vulnerable_dep = MockDep {
            name: "pkg".into(),
            version_req: "=1.0.0".into(),
            version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
            name_range: Range::new(Position::new(0, 0), Position::new(0, 5)),
        };
        let patched_dep = MockDep {
            name: "pkg".into(),
            version_req: "=2.0.0".into(),
            version_range: Range::new(Position::new(3, 10), Position::new(3, 20)),
            name_range: Range::new(Position::new(3, 0), Position::new(3, 5)),
        };
        let parse_result = MockParseResult {
            deps: vec![vulnerable_dep, patched_dep],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let cached_versions = HashMap::new();
        let resolved_versions = HashMap::new();

        let keys = vulnerability_keys(
            &parse_result,
            &resolved_versions,
            &formatter,
            crate::EcosystemId::Cargo,
        );
        let deps = parse_result.dependencies();
        let vulnerable_key = keys.get(&deps[0].name_range()).unwrap().clone();
        let patched_key = keys.get(&deps[1].name_range()).unwrap().clone();
        assert_ne!(
            vulnerable_key, patched_key,
            "differently-versioned occurrences of one name must get distinct keys"
        );

        let mut vulns: VulnerabilityMap = VulnerabilityMap::new();
        vulns.insert(
            vulnerable_key,
            ScanOutcome::Vulnerable(DependencyVulnerabilities {
                advisories: vec![sample_advisory("RUSTSEC-2020-0071", VulnSeverity::High)],
                total_known: 1,
                upgrade_status: UpgradeStatus::NotChecked,
            }),
        );
        vulns.insert(patched_key, ScanOutcome::Clean);

        let diagnostics = generate_diagnostics_from_cache(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions)
                .with_vulnerabilities(&vulns)
                .with_ecosystem(crate::EcosystemId::Cargo),
            &formatter,
            crate::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
            PublishTime::now(),
        );

        let advisory_diags: Vec<_> = diagnostics
            .iter()
            .filter(|d| d.message.contains("RUSTSEC-2020-0071"))
            .collect();
        assert_eq!(
            advisory_diags.len(),
            1,
            "exactly one occurrence must get the advisory diagnostic, got: {diagnostics:?}"
        );
        assert_eq!(
            advisory_diags[0].range.start.line, 0,
            "must land on the vulnerable occurrence's own line, not the patched one"
        );
    }

    #[test]
    fn test_generate_diagnostics_skipped_outcome_emits_no_vulnerability_diagnostic() {
        use crate::osv::{ScanOutcome, SkipReason, VulnerabilityMap};

        let formatter = MockFormatter;
        let parse_result = MockParseResult {
            deps: vec![dep_at("git-pkg")],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };
        let mut cached_versions = HashMap::new();
        cached_versions.insert("git-pkg".into(), PackageVersions::latest_only("1.0.0"));
        let resolved_versions = HashMap::new();

        let mut vulns: VulnerabilityMap = VulnerabilityMap::new();
        vulns.insert(
            "git-pkg".to_string(),
            ScanOutcome::Skipped(SkipReason::NonRegistrySource),
        );

        let diagnostics = generate_diagnostics_from_cache(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions).with_vulnerabilities(&vulns),
            &formatter,
            crate::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
            PublishTime::now(),
        );

        assert!(
            diagnostics.iter().all(|d| d.code.is_none()),
            "a Skipped outcome must never render an advisory diagnostic"
        );
    }

    /// Table-driven coverage for `requirement_is_unsatisfiable` (plan §4), using a
    /// formatter whose `compile_requirement` is configured per test via a closure-backed
    /// matcher, rather than one of the fixed ecosystem formatters.
    mod requirement_is_unsatisfiable_tests {
        use super::*;

        type Decide = Arc<dyn Fn(&str) -> Option<bool> + Send + Sync>;

        /// A matcher backed by a type-erased closure, so each test can express its own
        /// per-candidate decision table without a new named type per test.
        struct ClosureMatcher(Decide);

        impl RequirementMatcher for ClosureMatcher {
            fn matches(&self, version: &ConcreteVersion) -> Option<bool> {
                (self.0)(version.as_str())
            }
        }

        /// A formatter whose `compile_requirement` is `None` (requirement is treated as
        /// unmodellable) unless `requirement.as_str() == "modelled"`, in which case it
        /// returns a `ClosureMatcher` wrapping `decide`. `requirement_is_unresolved` fires
        /// on the literal string `"unresolved"`.
        struct TableFormatter {
            decide: Decide,
        }

        impl TableFormatter {
            fn new(decide: impl Fn(&str) -> Option<bool> + Send + Sync + 'static) -> Self {
                Self {
                    decide: Arc::new(decide),
                }
            }
        }

        impl EcosystemFormatter for TableFormatter {
            fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
                version.to_string()
            }
            fn package_url(&self, name: &PackageName) -> String {
                name.to_string()
            }
            fn requirement_is_unresolved(&self, requirement: &VersionReq) -> bool {
                requirement.as_str() == "unresolved"
            }
            fn compile_requirement(
                &self,
                requirement: &VersionReq,
            ) -> Option<Box<dyn RequirementMatcher>> {
                if requirement.as_str() != "modelled" {
                    return None;
                }
                Some(Box::new(ClosureMatcher(Arc::clone(&self.decide)))
                    as Box<dyn RequirementMatcher>)
            }
        }

        fn versions(strs: &[&str]) -> Vec<ConcreteVersion> {
            strs.iter().map(|s| (*s).into()).collect()
        }

        #[test]
        fn test_empty_available_list_is_false() {
            let formatter = TableFormatter::new(|_v| Some(true));
            assert!(!requirement_is_unsatisfiable(
                &formatter,
                &VersionReq::new("modelled"),
                &[],
            ));
        }

        #[test]
        fn test_empty_requirement_string_is_false() {
            let formatter = TableFormatter::new(|_v| Some(false));
            assert!(!requirement_is_unsatisfiable(
                &formatter,
                &VersionReq::new(""),
                &versions(&["1.0.0"]),
            ));
        }

        /// S-1 (security): an oversized requirement is rejected before `compile_requirement`
        /// is even called, bounding the cost of an adversarial/corrupted requirement string
        /// regardless of how expensive that ecosystem's matcher is per candidate.
        #[test]
        fn test_oversized_requirement_is_false_without_compiling() {
            let formatter =
                TableFormatter::new(|_v| panic!("must not compile/scan an oversized requirement"));
            let oversized = "1".repeat(MAX_REQUIREMENT_LEN + 1);
            assert!(!requirement_is_unsatisfiable(
                &formatter,
                &VersionReq::new(oversized),
                &versions(&["1.0.0"]),
            ));
        }

        #[test]
        fn test_unresolved_requirement_is_false() {
            let formatter = TableFormatter::new(|_v| Some(false));
            assert!(!requirement_is_unsatisfiable(
                &formatter,
                &VersionReq::new("unresolved"),
                &versions(&["1.0.0"]),
            ));
        }

        #[test]
        fn test_compile_requirement_none_is_false() {
            let formatter = TableFormatter::new(|_v| Some(false));
            assert!(!requirement_is_unsatisfiable(
                &formatter,
                &VersionReq::new("not-modelled"),
                &versions(&["1.0.0"]),
            ));
        }

        #[test]
        fn test_all_candidates_decided_false_is_true() {
            let formatter = TableFormatter::new(|_v| Some(false));
            assert!(requirement_is_unsatisfiable(
                &formatter,
                &VersionReq::new("modelled"),
                &versions(&["1.0.0", "2.0.0", "3.0.0"]),
            ));
        }

        #[test]
        fn test_one_match_among_many_non_matches_is_false() {
            let formatter = TableFormatter::new(|v| Some(v == "2.0.0"));
            assert!(!requirement_is_unsatisfiable(
                &formatter,
                &VersionReq::new("modelled"),
                &versions(&["1.0.0", "2.0.0", "3.0.0"]),
            ));
        }

        /// S2 regression: every candidate unparseable means nothing was decided, so the
        /// verdict must be `false` (no diagnostic), not a vacuous `true`.
        #[test]
        fn test_all_candidates_unparseable_is_false() {
            let formatter = TableFormatter::new(|_v| None);
            assert!(!requirement_is_unsatisfiable(
                &formatter,
                &VersionReq::new("modelled"),
                &versions(&["1.0.0", "2.0.0"]),
            ));
        }

        /// S2 regression, other half: a single junk entry among otherwise-all-`Some(false)`
        /// candidates is skipped, not fatal to the whole scan.
        #[test]
        fn test_one_unparseable_candidate_among_false_is_still_true() {
            let formatter = TableFormatter::new(|v| if v == "junk" { None } else { Some(false) });
            assert!(requirement_is_unsatisfiable(
                &formatter,
                &VersionReq::new("modelled"),
                &versions(&["1.0.0", "junk", "2.0.0"]),
            ));
        }

        /// §1.3: a match on a candidate that happens to be yanked still counts as
        /// satisfied — `available` carries no yanked flag, so this is exercised the same
        /// way any other match is: the matcher deciding `Some(true)` for that entry.
        #[test]
        fn test_match_on_yanked_only_candidate_is_false() {
            let formatter = TableFormatter::new(|v| Some(v == "1.0.0-yanked"));
            assert!(!requirement_is_unsatisfiable(
                &formatter,
                &VersionReq::new("modelled"),
                &versions(&["1.0.0-yanked"]),
            ));
        }

        /// §1.2: same, for a prerelease-only match.
        #[test]
        fn test_match_on_prerelease_only_candidate_is_false() {
            let formatter = TableFormatter::new(|v| Some(v == "2.0.0-beta.1"));
            assert!(!requirement_is_unsatisfiable(
                &formatter,
                &VersionReq::new("modelled"),
                &versions(&["2.0.0-beta.1"]),
            ));
        }

        #[test]
        fn test_scan_short_circuits_on_first_match() {
            let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let calls_clone = Arc::clone(&calls);
            let formatter = TableFormatter::new(move |v| {
                calls_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Some(v == "1.0.0")
            });
            let result = requirement_is_unsatisfiable(
                &formatter,
                &VersionReq::new("modelled"),
                &versions(&["1.0.0", "0.9.0", "0.8.0"]),
            );
            assert!(!result);
            assert_eq!(
                calls.load(std::sync::atomic::Ordering::SeqCst),
                1,
                "must stop scanning at the first Some(true)"
            );
        }
    }

    /// Coverage for `matching_prerelease_would_satisfy` and `semver_prerelease_base` (#299):
    /// enriching the unsatisfiable-requirement WARNING for strict-SemVer ecosystems with a
    /// mention of a published pre-release that would satisfy the requirement's stable core.
    mod matching_prerelease_would_satisfy_tests {
        use super::*;

        /// Same matcher as `StrictSemverFormatter` (defined in the parent `tests` module and
        /// shared with the `generate_diagnostics_from_cache` end-to-end coverage), but not
        /// opted into `strict_semver_prerelease_exclusion` — mirrors Maven/NuGet/Composer/
        /// Gradle, which must never get the enrichment.
        struct NonStrictFormatter;
        impl EcosystemFormatter for NonStrictFormatter {
            fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
                version.to_string()
            }
            fn package_url(&self, name: &PackageName) -> String {
                name.to_string()
            }
            fn compile_requirement(
                &self,
                requirement: &VersionReq,
            ) -> Option<Box<dyn RequirementMatcher>> {
                requirement
                    .as_str()
                    .parse::<semver::VersionReq>()
                    .ok()
                    .map(|req| Box::new(RealSemverMatcher(req)) as Box<dyn RequirementMatcher>)
            }
        }

        fn versions(strs: &[&str]) -> Vec<ConcreteVersion> {
            strs.iter().map(|s| (*s).into()).collect()
        }

        #[test]
        fn test_semver_prerelease_base() {
            assert_eq!(semver_prerelease_base("2.0.0-rc.1"), Some("2.0.0"));
            assert_eq!(semver_prerelease_base("2.0.0-rc.1+build.5"), Some("2.0.0"));
            assert_eq!(semver_prerelease_base("2.0.0"), None);
            assert_eq!(semver_prerelease_base("2.0.0+build.5"), None);
        }

        #[test]
        fn test_requirement_names_prerelease() {
            assert!(requirement_names_prerelease("2.0.0-rc.5"));
            assert!(requirement_names_prerelease("^2.0.0-rc.5"));
            assert!(requirement_names_prerelease("~2.0.0-rc.5"));
            assert!(requirement_names_prerelease(">=2.0.0-rc.5"));
            assert!(requirement_names_prerelease("=2.0.0-rc.5"));
            assert!(!requirement_names_prerelease("^2.0.0"));
            assert!(!requirement_names_prerelease(">=1.0.0, <2.0.0"));
            // npm's whitespace-padded hyphen range operator must not be mistaken for an
            // embedded pre-release tag.
            assert!(!requirement_names_prerelease("1.2.3 - 2.3.4"));
        }

        /// (a) No pre-release exists among `available` — no enrichment.
        #[test]
        fn test_no_prerelease_available_returns_none() {
            assert_eq!(
                matching_prerelease_would_satisfy(
                    &StrictSemverFormatter,
                    &VersionReq::new("^2.0.0"),
                    &versions(&["1.5.0", "1.4.0"]),
                    &[],
                ),
                None
            );
        }

        /// (b) A pre-release exists that would satisfy the requirement's stable core — the
        /// scenario from the issue's example (`^2.0.0` vs. published `2.0.0-rc.1`).
        #[test]
        fn test_matching_prerelease_is_found() {
            assert_eq!(
                matching_prerelease_would_satisfy(
                    &StrictSemverFormatter,
                    &VersionReq::new("^2.0.0"),
                    &versions(&["2.0.0-rc.1", "1.5.0"]),
                    &[],
                ),
                Some("2.0.0-rc.1".to_string())
            );
        }

        /// The newest matching pre-release wins when several are published (`available` is
        /// newest-first).
        #[test]
        fn test_returns_newest_matching_prerelease_first() {
            assert_eq!(
                matching_prerelease_would_satisfy(
                    &StrictSemverFormatter,
                    &VersionReq::new("^2.0.0"),
                    &versions(&["2.0.0-rc.2", "2.0.0-rc.1", "1.5.0"]),
                    &[],
                ),
                Some("2.0.0-rc.2".to_string())
            );
        }

        /// A published pre-release whose stable core still fails the requirement (wrong
        /// major version) must not be surfaced.
        #[test]
        fn test_non_matching_prerelease_returns_none() {
            assert_eq!(
                matching_prerelease_would_satisfy(
                    &StrictSemverFormatter,
                    &VersionReq::new("^2.0.0"),
                    &versions(&["3.0.0-rc.1", "1.5.0"]),
                    &[],
                ),
                None
            );
        }

        /// (c) The requirement is itself an exact pin to a nonexistent pre-release
        /// (`=2.0.0-rc.5`) — existing #206 behavior. A published pre-release with a
        /// different tag must not be surfaced, since the requirement already names a
        /// pre-release tag (`requirement_names_prerelease` bails before even compiling).
        #[test]
        fn test_exact_prerelease_pin_does_not_misfire_on_unrelated_prerelease() {
            assert_eq!(
                matching_prerelease_would_satisfy(
                    &StrictSemverFormatter,
                    &VersionReq::new("=2.0.0-rc.5"),
                    &versions(&["2.0.0-rc.1", "1.5.0"]),
                    &[],
                ),
                None
            );
        }

        /// S1 regression: a `^`-ranged requirement whose floor itself names a pre-release
        /// tag must not enrich, even though `2.0.0-rc.1`'s stable core (`2.0.0`) would
        /// satisfy `^2.0.0-rc.5` (verified against real `semver` 1.0.28) — the real reason
        /// `2.0.0-rc.1` doesn't match is ordering against the requirement's own explicit
        /// floor (`rc.1 < rc.5`), not SemVer's default pre-release exclusion.
        #[test]
        fn test_caret_requirement_naming_prerelease_returns_none() {
            assert_eq!(
                matching_prerelease_would_satisfy(
                    &StrictSemverFormatter,
                    &VersionReq::new("^2.0.0-rc.5"),
                    &versions(&["2.0.0-rc.1", "1.5.0"]),
                    &[],
                ),
                None
            );
        }

        /// S1 regression, `~` shape.
        #[test]
        fn test_tilde_requirement_naming_prerelease_returns_none() {
            assert_eq!(
                matching_prerelease_would_satisfy(
                    &StrictSemverFormatter,
                    &VersionReq::new("~2.0.0-rc.5"),
                    &versions(&["2.0.0-rc.1", "1.5.0"]),
                    &[],
                ),
                None
            );
        }

        /// S1 regression, `>=` shape.
        #[test]
        fn test_gte_requirement_naming_prerelease_returns_none() {
            assert_eq!(
                matching_prerelease_would_satisfy(
                    &StrictSemverFormatter,
                    &VersionReq::new(">=2.0.0-rc.5"),
                    &versions(&["2.0.0-rc.1", "1.5.0"]),
                    &[],
                ),
                None
            );
        }

        /// M1: a matching pre-release that is itself yanked must not be surfaced — it isn't
        /// actually usable, so naming it as "would satisfy" would be misleading.
        #[test]
        fn test_yanked_matching_prerelease_is_skipped() {
            assert_eq!(
                matching_prerelease_would_satisfy(
                    &StrictSemverFormatter,
                    &VersionReq::new("^2.0.0"),
                    &versions(&["2.0.0-rc.1", "1.5.0"]),
                    &versions(&["2.0.0-rc.1"]),
                ),
                None
            );
        }

        /// M1: a yanked pre-release is skipped in favor of an older, non-yanked matching one.
        #[test]
        fn test_yanked_matching_prerelease_falls_back_to_non_yanked() {
            assert_eq!(
                matching_prerelease_would_satisfy(
                    &StrictSemverFormatter,
                    &VersionReq::new("^2.0.0"),
                    &versions(&["2.0.0-rc.2", "2.0.0-rc.1", "1.5.0"]),
                    &versions(&["2.0.0-rc.2"]),
                ),
                Some("2.0.0-rc.1".to_string())
            );
        }

        /// Ecosystems that have not opted in (Maven/NuGet/Composer/Gradle) never get the
        /// enrichment, even against a requirement/available pair that would otherwise match.
        #[test]
        fn test_non_opted_in_ecosystem_returns_none() {
            assert_eq!(
                matching_prerelease_would_satisfy(
                    &NonStrictFormatter,
                    &VersionReq::new("^2.0.0"),
                    &versions(&["2.0.0-rc.1", "1.5.0"]),
                    &[],
                ),
                None
            );
        }
    }

    /// Coverage for `requirement_matches_only_yanked` and its wiring into
    /// `generate_diagnostics_from_cache` (issue #247): the cache-only diagnostics path's
    /// substitute for the network path's `current.removal_status()` check in `generate_diagnostics`,
    /// which never fires against a real registry because `Registry::get_latest_matching`
    /// filters yanked entries out by contract on every current implementation (#233). This
    /// scans `available`/`yanked` directly instead, so it observes yanked entries that
    /// `get_latest_matching` never returns.
    mod requirement_matches_only_yanked_tests {
        use super::*;

        type Decide = Arc<dyn Fn(&str) -> Option<bool> + Send + Sync>;

        struct ClosureMatcher(Decide);

        impl RequirementMatcher for ClosureMatcher {
            fn matches(&self, version: &ConcreteVersion) -> Option<bool> {
                (self.0)(version.as_str())
            }
        }

        /// Same shape as `requirement_is_unsatisfiable_tests::TableFormatter`:
        /// `compile_requirement` only opts in for the literal requirement string `"modelled"`.
        struct TableFormatter {
            decide: Decide,
        }

        impl TableFormatter {
            fn new(decide: impl Fn(&str) -> Option<bool> + Send + Sync + 'static) -> Self {
                Self {
                    decide: Arc::new(decide),
                }
            }
        }

        impl EcosystemFormatter for TableFormatter {
            fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
                version.to_string()
            }
            fn package_url(&self, name: &PackageName) -> String {
                name.to_string()
            }
            fn requirement_is_unresolved(&self, requirement: &VersionReq) -> bool {
                requirement.as_str() == "unresolved"
            }
            fn compile_requirement(
                &self,
                requirement: &VersionReq,
            ) -> Option<Box<dyn RequirementMatcher>> {
                if requirement.as_str() != "modelled" {
                    return None;
                }
                Some(Box::new(ClosureMatcher(Arc::clone(&self.decide)))
                    as Box<dyn RequirementMatcher>)
            }
        }

        fn versions(strs: &[&str]) -> Vec<ConcreteVersion> {
            strs.iter().map(|s| (*s).into()).collect()
        }

        #[test]
        fn test_yanked_only_match_is_true() {
            let formatter = TableFormatter::new(|v| Some(v == "1.2.1"));
            assert!(requirement_matches_only_yanked(
                &formatter,
                &VersionReq::new("modelled"),
                &versions(&["1.2.1"]),
                &versions(&["1.2.1"]),
            ));
        }

        #[test]
        fn test_no_match_is_false() {
            let formatter = TableFormatter::new(|_v| Some(false));
            assert!(!requirement_matches_only_yanked(
                &formatter,
                &VersionReq::new("modelled"),
                &versions(&["1.2.1"]),
                &versions(&["1.2.1"]),
            ));
        }

        #[test]
        fn test_match_on_non_yanked_alongside_yanked_is_false() {
            // "^1.0" matches both a yanked 1.0.0 and a non-yanked 1.0.1 — a non-yanked
            // alternative exists, so this must not be reported as "yanked-only".
            let formatter = TableFormatter::new(|v| Some(v == "1.0.0" || v == "1.0.1"));
            assert!(!requirement_matches_only_yanked(
                &formatter,
                &VersionReq::new("modelled"),
                &versions(&["1.0.1", "1.0.0"]),
                &versions(&["1.0.0"]),
            ));
        }

        #[test]
        fn test_scan_continues_past_a_yanked_match_to_find_a_non_yanked_alternative() {
            // Same as above but with the yanked candidate ordered first, so a scan that
            // stopped at the first `Some(true)` (as `requirement_is_unsatisfiable` does) would
            // wrongly report "yanked-only" here.
            let formatter = TableFormatter::new(|v| Some(v == "1.0.0" || v == "1.0.1"));
            assert!(!requirement_matches_only_yanked(
                &formatter,
                &VersionReq::new("modelled"),
                &versions(&["1.0.0", "1.0.1"]),
                &versions(&["1.0.0"]),
            ));
        }

        #[test]
        fn test_empty_yanked_list_is_false_without_compiling() {
            let formatter =
                TableFormatter::new(|_v| panic!("must not compile/scan when yanked is empty"));
            assert!(!requirement_matches_only_yanked(
                &formatter,
                &VersionReq::new("modelled"),
                &versions(&["1.0.0"]),
                &[],
            ));
        }

        #[test]
        fn test_empty_available_list_is_false() {
            let formatter = TableFormatter::new(|_v| Some(true));
            assert!(!requirement_matches_only_yanked(
                &formatter,
                &VersionReq::new("modelled"),
                &[],
                &versions(&["1.0.0"]),
            ));
        }

        #[test]
        fn test_unresolved_requirement_is_false() {
            let formatter = TableFormatter::new(|_v| Some(true));
            assert!(!requirement_matches_only_yanked(
                &formatter,
                &VersionReq::new("unresolved"),
                &versions(&["1.0.0"]),
                &versions(&["1.0.0"]),
            ));
        }

        #[test]
        fn test_compile_requirement_none_is_false() {
            let formatter = TableFormatter::new(|_v| Some(true));
            assert!(!requirement_matches_only_yanked(
                &formatter,
                &VersionReq::new("not-modelled"),
                &versions(&["1.0.0"]),
                &versions(&["1.0.0"]),
            ));
        }

        /// End-to-end: `generate_diagnostics_from_cache` emits the yanked diagnostic (default
        /// severity, `formatter.yanked_message()` plus a "; latest is X" suffix mirroring the
        /// sibling unsatisfiable diagnostic's actionability) and nothing else for a dependency
        /// whose requirement matches only a yanked version.
        #[test]
        fn test_generate_diagnostics_from_cache_yanked_only_match_fires_yanked_diagnostic() {
            let formatter = TableFormatter::new(|v| Some(v == "1.2.1"));

            let parse_result = MockParseResult {
                deps: vec![MockDep {
                    name: "serde".into(),
                    version_req: "modelled".into(),
                    version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                    name_range: Range::new(Position::new(0, 0), Position::new(0, 5)),
                }],
                uri: crate::test_util::test_uri("/test/Cargo.toml"),
            };

            let mut cached_versions = HashMap::new();
            cached_versions.insert(
                "serde".into(),
                PackageVersions {
                    latest: "2.0.0".into(),
                    available: Arc::from(vec!["2.0.0".into(), "1.2.1".into()]),
                    yanked: Arc::from(vec!["1.2.1".into()]),
                    published_at: None,
                },
            );
            let resolved_versions = HashMap::new();

            let diagnostics = generate_diagnostics_from_cache(
                &parse_result,
                VersionData::new(&cached_versions, &resolved_versions),
                &formatter,
                crate::freshness::FreshnessSettings::default(),
                DiagnosticSeverities::default(),
                PublishTime::now(),
            );

            assert_eq!(diagnostics.len(), 1, "expected exactly one diagnostic");
            assert_eq!(diagnostics[0].severity, Some(DiagnosticSeverity::WARNING));
            assert_eq!(
                diagnostics[0].message,
                format!("{}; latest is 2.0.0", formatter.yanked_message())
            );
        }

        /// #247 vs. #263 dedup: a dependency whose in-use version (lock-file-resolved, or an
        /// exact pin) is yanked *and* is the only version satisfying its own requirement
        /// triggers both the in-use-version check (`versions.yanked`, #263) and the
        /// requirement-only-satisfiable-by-yanked check (`requirement_matches_only_yanked`,
        /// #247). Exactly one diagnostic must be emitted, not two.
        #[test]
        fn test_generate_diagnostics_from_cache_yanked_dedup_in_use_and_requirement_only_match() {
            let formatter = TableFormatter::new(|v| Some(v == "1.2.1"));

            let parse_result = MockParseResult {
                deps: vec![MockDep {
                    name: "serde".into(),
                    version_req: "modelled".into(),
                    version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                    name_range: Range::new(Position::new(0, 0), Position::new(0, 5)),
                }],
                uri: crate::test_util::test_uri("/test/Cargo.toml"),
            };

            let mut cached_versions = HashMap::new();
            cached_versions.insert(
                "serde".into(),
                PackageVersions {
                    latest: "2.0.0".into(),
                    available: Arc::from(vec!["2.0.0".into(), "1.2.1".into()]),
                    yanked: Arc::from(vec!["1.2.1".into()]),
                    published_at: None,
                },
            );
            let resolved_versions = HashMap::new();
            let mut in_use_yanked = HashMap::new();
            in_use_yanked.insert("serde".to_string(), "1.2.1".into());

            let diagnostics = generate_diagnostics_from_cache(
                &parse_result,
                VersionData::new(&cached_versions, &resolved_versions).with_yanked(&in_use_yanked),
                &formatter,
                crate::freshness::FreshnessSettings::default(),
                DiagnosticSeverities::default(),
                PublishTime::now(),
            );

            // Two diagnostics are expected, not one: the in-use-version check (#263) has
            // no `continue`, so it co-emits alongside the ordinary "outdated" diagnostic
            // for the same dependency (the fixture's declared requirement "modelled"
            // does not itself equal `latest` "2.0.0", so `requirement_status` reports
            // `Outdated`) — this is #263's deliberate, separately-tested policy, see
            // `test_generate_diagnostics_from_cache_yanked_and_outdated_both_emitted`.
            // What this test actually proves is narrower: exactly one *yanked*
            // diagnostic, not two — #247's `yanked_only` check must not also fire.
            let yanked_diags: Vec<_> = diagnostics
                .iter()
                .filter(|d| d.message.starts_with(formatter.yanked_message()))
                .collect();
            assert_eq!(
                yanked_diags.len(),
                1,
                "expected exactly one yanked diagnostic, got: {diagnostics:?}"
            );
            // The in-use-version check (#263) runs first and wins.
            assert_eq!(
                yanked_diags[0].message,
                format!("{} (1.2.1)", formatter.yanked_message())
            );
            assert_eq!(
                diagnostics.len(),
                2,
                "expected exactly the yanked diagnostic plus the co-emitted outdated \
                 diagnostic (#263's policy), got: {diagnostics:?}"
            );
            assert!(
                diagnostics
                    .iter()
                    .any(|d| d.message == "Newer version available: 2.0.0"),
                "expected the co-emitted outdated diagnostic, got: {diagnostics:?}"
            );
        }

        /// `severities.yanked` reaches the emitted diagnostic on the cache-only path, the same
        /// way `outdated_severity`/`unknown_severity`/`unsatisfiable_severity` already do.
        #[test]
        fn test_generate_diagnostics_from_cache_yanked_only_match_uses_configured_severity() {
            let formatter = TableFormatter::new(|v| Some(v == "1.2.1"));

            let parse_result = MockParseResult {
                deps: vec![MockDep {
                    name: "serde".into(),
                    version_req: "modelled".into(),
                    version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                    name_range: Range::new(Position::new(0, 0), Position::new(0, 5)),
                }],
                uri: crate::test_util::test_uri("/test/Cargo.toml"),
            };

            let mut cached_versions = HashMap::new();
            cached_versions.insert(
                "serde".into(),
                PackageVersions {
                    latest: "1.2.1".into(),
                    available: Arc::from(vec!["1.2.1".into()]),
                    yanked: Arc::from(vec!["1.2.1".into()]),
                    published_at: None,
                },
            );
            let resolved_versions = HashMap::new();

            let severities = DiagnosticSeverities {
                yanked: DiagnosticSeverity::ERROR,
                ..DiagnosticSeverities::default()
            };

            let diagnostics = generate_diagnostics_from_cache(
                &parse_result,
                VersionData::new(&cached_versions, &resolved_versions),
                &formatter,
                crate::freshness::FreshnessSettings::default(),
                severities,
                PublishTime::now(),
            );

            assert_eq!(diagnostics.len(), 1);
            assert_eq!(diagnostics[0].severity, Some(DiagnosticSeverity::ERROR));
        }

        /// When a non-yanked version also satisfies the requirement, no yanked diagnostic
        /// fires — the dependency falls through to the ordinary outdated/up-to-date check.
        #[test]
        fn test_generate_diagnostics_from_cache_match_with_non_yanked_alternative_skips_yanked_diagnostic()
         {
            let formatter = TableFormatter::new(|v| Some(v == "1.0.0" || v == "1.0.1"));

            let parse_result = MockParseResult {
                deps: vec![MockDep {
                    name: "serde".into(),
                    version_req: "modelled".into(),
                    version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                    name_range: Range::new(Position::new(0, 0), Position::new(0, 5)),
                }],
                uri: crate::test_util::test_uri("/test/Cargo.toml"),
            };

            let mut cached_versions = HashMap::new();
            cached_versions.insert(
                "serde".into(),
                PackageVersions {
                    latest: "2.0.0".into(),
                    available: Arc::from(vec!["2.0.0".into(), "1.0.1".into(), "1.0.0".into()]),
                    yanked: Arc::from(vec!["1.0.0".into()]),
                    published_at: None,
                },
            );
            let resolved_versions = HashMap::new();

            let diagnostics = generate_diagnostics_from_cache(
                &parse_result,
                VersionData::new(&cached_versions, &resolved_versions),
                &formatter,
                crate::freshness::FreshnessSettings::default(),
                DiagnosticSeverities::default(),
                PublishTime::now(),
            );

            assert!(
                !diagnostics
                    .iter()
                    .any(|d| d.message.starts_with(formatter.yanked_message())),
                "a non-yanked match exists, so no yanked diagnostic should fire, got: {diagnostics:?}"
            );
        }

        /// M1 regression: an undecided candidate (`matcher.matches` returns `None`) must not
        /// be silently skipped — it might have been a genuine non-yanked match this scan
        /// could not evaluate, so it disqualifies a `true` verdict entirely.
        #[test]
        fn test_undecided_candidate_prevents_true_verdict() {
            let formatter = TableFormatter::new(|v| match v {
                "1.2.1" => Some(true),
                "unparseable" => None,
                _ => Some(false),
            });
            assert!(!requirement_matches_only_yanked(
                &formatter,
                &VersionReq::new("modelled"),
                &versions(&["1.2.1", "unparseable"]),
                &versions(&["1.2.1"]),
            ));
        }

        /// Same scenario, but the undecided candidate is scanned before the yanked match —
        /// proves the early `return false` on a non-yanked match doesn't accidentally mask
        /// this case, and that the `saw_undecided` flag survives regardless of scan order.
        #[test]
        fn test_undecided_candidate_before_match_still_prevents_true_verdict() {
            let formatter = TableFormatter::new(|v| match v {
                "1.2.1" => Some(true),
                "unparseable" => None,
                _ => Some(false),
            });
            assert!(!requirement_matches_only_yanked(
                &formatter,
                &VersionReq::new("modelled"),
                &versions(&["unparseable", "1.2.1"]),
                &versions(&["1.2.1"]),
            ));
        }

        #[test]
        fn test_oversized_requirement_is_false_without_compiling() {
            let formatter =
                TableFormatter::new(|_v| panic!("must not compile/scan an oversized requirement"));
            let oversized = "1".repeat(MAX_REQUIREMENT_LEN + 1);
            assert!(!requirement_matches_only_yanked(
                &formatter,
                &VersionReq::new(oversized),
                &versions(&["1.0.0"]),
                &versions(&["1.0.0"]),
            ));
        }

        /// The yanked-only-match diagnostic must never fire for a non-registry-resolvable
        /// dependency source (path/git/URL/SDK/workspace) — the same guard
        /// `requirement_is_unsatisfiable` already has (see
        /// `test_generate_diagnostics_unsatisfiable_skipped_for_non_registry_sources`).
        #[test]
        fn test_yanked_only_match_skipped_for_non_registry_sources() {
            let formatter = TableFormatter::new(|v| Some(v == "1.2.1"));
            let uri = crate::test_util::test_uri("/test/Cargo.toml");

            let mut cached_versions = HashMap::new();
            cached_versions.insert(
                "dep".into(),
                PackageVersions {
                    latest: "2.0.0".into(),
                    available: Arc::from(vec!["2.0.0".into(), "1.2.1".into()]),
                    yanked: Arc::from(vec!["1.2.1".into()]),
                    published_at: None,
                },
            );
            let resolved_versions = HashMap::new();

            let dep = MockDep {
                name: "dep".into(),
                version_req: "modelled".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 3)),
            };
            let parse_result = SingleDepParseResult {
                dep: NonRegistryDep(
                    dep,
                    crate::parser::DependencySource::Path {
                        path: "../local".into(),
                    },
                ),
                uri,
            };

            let diagnostics = generate_diagnostics_from_cache(
                &parse_result,
                VersionData::new(&cached_versions, &resolved_versions),
                &formatter,
                crate::freshness::FreshnessSettings::default(),
                DiagnosticSeverities::default(),
                PublishTime::now(),
            );

            assert!(
                diagnostics
                    .iter()
                    .all(|d| !d.message.starts_with(formatter.yanked_message())),
                "a path dependency must never produce the yanked diagnostic, got: {diagnostics:?}"
            );
        }

        /// The `continue` after emitting the yanked diagnostic must suppress the sibling
        /// outdated check for the same dependency — proven directly rather than just
        /// inferred from `diagnostics.len() == 1` elsewhere in this module.
        #[test]
        fn test_yanked_only_match_suppresses_outdated_diagnostic() {
            let formatter = TableFormatter::new(|v| Some(v == "1.2.1"));

            let parse_result = MockParseResult {
                deps: vec![MockDep {
                    name: "serde".into(),
                    version_req: "modelled".into(),
                    version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                    name_range: Range::new(Position::new(0, 0), Position::new(0, 5)),
                }],
                uri: crate::test_util::test_uri("/test/Cargo.toml"),
            };

            let mut cached_versions = HashMap::new();
            cached_versions.insert(
                "serde".into(),
                PackageVersions {
                    latest: "2.0.0".into(),
                    available: Arc::from(vec!["2.0.0".into(), "1.2.1".into()]),
                    yanked: Arc::from(vec!["1.2.1".into()]),
                    published_at: None,
                },
            );
            let resolved_versions = HashMap::new();

            let diagnostics = generate_diagnostics_from_cache(
                &parse_result,
                VersionData::new(&cached_versions, &resolved_versions),
                &formatter,
                crate::freshness::FreshnessSettings::default(),
                DiagnosticSeverities::default(),
                PublishTime::now(),
            );

            assert!(
                !diagnostics
                    .iter()
                    .any(|d| d.message.contains("Newer version available")),
                "the yanked diagnostic must suppress the outdated hint, not add to it, got: {diagnostics:?}"
            );
        }
    }
}
