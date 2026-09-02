use deps_core::ConcreteVersion;
use deps_core::Dependency;
use deps_core::InvalidPackageName;
use deps_core::PackageName;
use deps_core::VersionReq;
use deps_core::lsp_helpers::{
    DiagnosticMessages, DiagnosticPolicy, OsvNaming, PackageNaming, PackageRendering,
    RequirementMatcher, RequirementResolution, SourcePolicy, compile_requirement_unless,
};
use deps_core::normalize_operator_spacing;
use tower_lsp_server::ls_types::Position;

/// Whether `segment` matches Packagist's vendor/package name-segment charset: starts and ends
/// with an ASCII alphanumeric character, with only `.`, `_`, `-` allowed in between (Composer's
/// `composer.json` schema pattern, applied case-insensitively here — Composer itself lowercases
/// dependency names, so a mixed-case `require` entry is not on its own a rejection reason).
fn is_valid_composer_segment(segment: &str) -> bool {
    segment
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphanumeric())
        && segment
            .chars()
            .last()
            .is_some_and(|c| c.is_ascii_alphanumeric())
        && segment
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// Composer requirement matcher, compiled once per dependency by
/// [`ComposerFormatter::compile_requirement`]. Shares `version_satisfies_requirement`'s
/// hand-rolled comparator, which has no external parser to fail on, so this always
/// decides (`Some`).
struct ComposerMatcher(String);

impl RequirementMatcher for ComposerMatcher {
    fn matches(&self, version: &ConcreteVersion) -> Option<bool> {
        Some(ComposerFormatter.version_satisfies_requirement(version, &self.0))
    }
}

/// Composer-specific LSP formatting.
///
/// Overrides version_satisfies_requirement to implement Composer's tilde (~)
/// operator semantics, which differ from npm:
/// - `~1.2.3` means `>=1.2.3 <1.3.0` (same as npm)
/// - `~1.2` means `>=1.2.0 <2.0.0` (DIFFERENT from npm where ~1.2 = >=1.2.0 <1.3.0)
pub struct ComposerFormatter;

impl PackageNaming for ComposerFormatter {
    fn normalize_package_name(&self, name: &PackageName) -> String {
        name.as_str().to_lowercase()
    }

    /// Lints `name` against Packagist's `vendor/package` coordinate shape (see
    /// `is_valid_composer_segment`), so a structurally invalid name is reported as
    /// "Invalid package name" instead of falling through to a registry lookup and rendering
    /// the generic "Registry lookup failed" diagnostic (#402).
    ///
    /// # Errors
    ///
    /// Returns [`InvalidPackageName`] if `name` is not exactly `vendor/package`, or either
    /// segment is empty, starts/ends with a separator, or contains a character outside
    /// Packagist's `[a-zA-Z0-9.\-_]` charset.
    fn validate_package_name(&self, name: &str) -> Result<(), InvalidPackageName> {
        let Some((vendor, package)) = name.split_once('/') else {
            return Err(InvalidPackageName::new(
                "name must be in 'vendor/package' form",
            ));
        };
        if package.contains('/') {
            return Err(InvalidPackageName::new("name must contain exactly one '/'"));
        }
        if !is_valid_composer_segment(vendor) {
            return Err(InvalidPackageName::new("vendor segment is malformed"));
        }
        if !is_valid_composer_segment(package) {
            return Err(InvalidPackageName::new("package segment is malformed"));
        }
        Ok(())
    }
}

impl PackageRendering for ComposerFormatter {
    fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
        let version = version.as_str();
        version.to_string()
    }

    fn package_url(&self, name: &PackageName) -> String {
        crate::registry::package_url(name.as_str())
    }

    /// Widens the rename quickfix's discoverability: without this, only a cursor on
    /// `version_range` (the default) reaches `generate_code_actions`, so a user reading
    /// "this package is abandoned" and clicking the package *name* — the very token the
    /// rename rewrites — would find no action offered.
    ///
    /// Rejects a degenerate (zero-width) `name_range` rather than reusing the default's
    /// `version_range`-only check plus this: `find_positions` (`parser.rs`) falls back to
    /// `Range::default()` — `(0,0)-(0,0)` — when its name-literal search misses (e.g. a
    /// legal escaped-solidus `"vendor\/package"` key), and `position_in_range` is
    /// inclusive on both ends, so an unguarded widen would make that sentinel
    /// *selectable* by a cursor resting on the file's opening `{` — reopening the exact
    /// `Range::default()` hazard `build_replacement_action`'s literal-span guard exists
    /// to prevent, just through the position check instead of the edit itself.
    ///
    /// This is the shared entry point [`generate_code_actions`](deps_core::lsp_helpers::generate_code_actions)
    /// uses to find "the dependency at this position" for *every* action kind, not only
    /// the rename — a cursor on the package name in `composer.json` now also surfaces
    /// the version-bump/vulnerability-fix actions it previously didn't (their edits still
    /// target `version_range` regardless of where the cursor landed, so this only widens
    /// where the actions are *offered from*, never what they write). Accepted, not scoped
    /// narrower to the rename alone: a single shared boolean gate has no per-action-kind
    /// dial, and a cursor on the name is exactly where a user reading "this package is
    /// abandoned" is likely to click for *any* fix, not just the rename.
    fn is_position_on_dependency(&self, dep: &dyn Dependency, position: Position) -> bool {
        let name_range = dep.name_range();
        if name_range.start != name_range.end
            && deps_core::lsp_helpers::position_in_range(position, name_range)
        {
            return true;
        }
        dep.version_range()
            .is_some_and(|r| deps_core::lsp_helpers::position_in_range(position, r))
    }
}

impl RequirementResolution for ComposerFormatter {
    /// Checks if a version satisfies a Composer version requirement.
    ///
    /// Handles Composer-specific operators:
    /// - `^` — caret (same semantics as default)
    /// - `~X.Y.Z` — tilde with patch: `>=X.Y.Z <X.(Y+1).0`
    /// - `~X.Y` — tilde without patch: `>=X.Y.0 <(X+1).0.0` (Composer-specific!)
    /// - `X.Y.*` — wildcard patch
    /// - `>=X <Y` — range (space = AND)
    /// - `X || Y` — OR combinator
    fn version_satisfies_requirement(&self, version: &ConcreteVersion, requirement: &str) -> bool {
        let version = version.as_str();
        let version = version.strip_prefix('v').unwrap_or(version);
        let requirement = requirement.trim();
        // Composer's own version parser strips a leading `v` from every version string it
        // normalizes, tags and constraints alike. Mirroring that only for `version` above
        // and not here made an exact/wildcard/caret/tilde requirement pinned with a `v`
        // prefix (e.g. `"v1.2.3"`, `"^v1.2.0"`) never match, since `version` had already
        // lost its `v` while `requirement` had not. Only strip when it leaves something
        // behind — a bare `"v"` requirement is not a valid version prefix and must fall
        // through to the exact/partial match below (which correctly rejects it), rather
        // than collapsing to `""` and being swallowed by the empty/wildcard guard next.
        let requirement = match requirement.strip_prefix('v') {
            Some(rest) if !rest.is_empty() => rest,
            _ => requirement,
        };
        // A per-dependency `@stability` flag (`@stable`, `@RC`, `@beta`, `@alpha`, `@dev`) is
        // a constraint-grammar element, not part of the version-range text — see
        // `strip_stability_flag`. Must run before the range operators below see the
        // requirement, or the flag text is parsed as part of the numeric core (#424).
        let (requirement, _stability_flag) = strip_stability_flag(requirement);
        let requirement = requirement.trim();

        if requirement.is_empty() || requirement == "*" {
            return true;
        }

        // OR combinator: "1.0 || 2.0"
        if requirement.contains("||") {
            return requirement.split("||").any(|part| {
                self.version_satisfies_requirement(&ConcreteVersion::new(version), part.trim())
            });
        }

        // Collapse whitespace between a range operator and its version (">= 1.0" ->
        // ">=1.0") so the AND split below treats the operator and its version as one
        // token instead of two separate (and individually meaningless) clauses. Borrows
        // `requirement` unchanged when there is nothing to collapse — this runs on every
        // candidate version `ComposerMatcher::matches` checks, so the common case (no
        // spaced operators) must not allocate.
        let requirement = normalize_operator_spacing(requirement);
        let requirement = &*requirement;

        // Range with AND (space-separated constraints like ">=1.0 <2.0")
        // Only treat as AND if there are multiple space-separated tokens that look like constraints
        let parts: Vec<&str> = requirement.split_whitespace().collect();
        if parts.len() > 1
            && parts
                .iter()
                .any(|p| p.starts_with('>') || p.starts_with('<'))
        {
            return parts.iter().all(|part| {
                self.version_satisfies_requirement(&ConcreteVersion::new(version), part)
            });
        }

        // Caret operator
        if let Some(req) = requirement.strip_prefix('^') {
            let req = req.strip_prefix('v').unwrap_or(req);
            return satisfies_caret(version, req);
        }

        // Tilde operator — Composer-specific semantics
        if let Some(req) = requirement.strip_prefix('~') {
            let req = req.strip_prefix('v').unwrap_or(req);
            return satisfies_tilde_composer(version, req);
        }

        // Comparison operators. `req` may itself be `v`-prefixed (e.g. ">=v1.0.0"); strip it
        // the same way the caret/tilde branches above do, so it does not fall into
        // `split_composer_core_and_suffix`'s qualifier-suffix branch and compare as core `0`.
        if let Some(req) = requirement.strip_prefix(">=") {
            let req = req.trim();
            let req = req.strip_prefix('v').unwrap_or(req);
            return compare_versions(version, req) >= 0;
        }
        if let Some(req) = requirement.strip_prefix("<=") {
            let req = req.trim();
            let req = req.strip_prefix('v').unwrap_or(req);
            return compare_versions(version, req) <= 0;
        }
        if let Some(req) = requirement.strip_prefix('>') {
            let req = req.trim();
            let req = req.strip_prefix('v').unwrap_or(req);
            return compare_versions(version, req) > 0;
        }
        if let Some(req) = requirement.strip_prefix('<') {
            let req = req.trim();
            let req = req.strip_prefix('v').unwrap_or(req);
            return compare_versions(version, req) < 0;
        }
        if let Some(req) = requirement.strip_prefix('=') {
            let req = req.trim();
            let req = req.strip_prefix('v').unwrap_or(req);
            return compare_versions(version, req) == 0;
        }
        if let Some(req) = requirement.strip_prefix("!=") {
            let req = req.trim();
            let req = req.strip_prefix('v').unwrap_or(req);
            return compare_versions(version, req) != 0;
        }

        // Wildcard: "1.0.*" means >=1.0.0 <1.1.0
        if requirement.ends_with(".*") {
            let prefix = requirement.trim_end_matches(".*");
            return version.starts_with(prefix) && version[prefix.len()..].starts_with('.');
        }

        // Exact or partial version match
        let req_parts: Vec<&str> = requirement.split('.').collect();
        let ver_parts: Vec<&str> = version.split('.').collect();

        if req_parts.len() == ver_parts.len() {
            return version == requirement;
        }

        // Partial version: "1" matches "1.x.x", "1.2" matches "1.2.x"
        if req_parts.len() < ver_parts.len() {
            return ver_parts.starts_with(&req_parts);
        }

        false
    }

    /// Compiles `requirement` into a `ComposerMatcher` using the same
    /// `version_satisfies_requirement` comparator — Composer requirements have no separate
    /// "loose" vs. "precise" form to distinguish. Uses [`compile_requirement_unless`] (see
    /// that function and [`deps_core::lsp_helpers::RequirementResolution::compile_requirement`] for the shared
    /// "undecidable" contract).
    ///
    /// The undecidable predicate rejects a `dev-*`/`*-dev` branch requirement (e.g.
    /// `"dev-master"`, `"1.0.x-dev"`) and a bare `@dev` minimum-stability flag (e.g.
    /// `"1.0.*@dev"`, `"2.0@dev"`): `PackagistRegistry::get_versions`
    /// (`expand_minified_versions`) filters exactly those version strings — and the `x-dev`
    /// shape `@dev` normalizes to — out of every result, so `available` — unlike every other
    /// ecosystem's, which is the plan's "unfiltered `get_versions` output" invariant — can
    /// never contain one, even when the branch itself is real and installable.
    fn compile_requirement(&self, requirement: &VersionReq) -> Option<Box<dyn RequirementMatcher>> {
        compile_requirement_unless(
            requirement.as_str().trim(),
            |r| r.starts_with("dev-") || r.ends_with("-dev") || r.contains("@dev"),
            ComposerMatcher,
        )
    }
}

impl DiagnosticMessages for ComposerFormatter {
    fn yanked_message(&self) -> &'static str {
        "This package is abandoned"
    }

    fn yanked_label(&self) -> &'static str {
        "*(abandoned)*"
    }

    /// Reuses Packagist's own "abandoned" wording for #205's package-level diagnostic,
    /// mirroring the yanked pair above rather than the trait default's generic
    /// "deprecated" — pattern reuse, not a new ecosystem-specific branch.
    fn deprecated_message(&self) -> &'static str {
        "This package is abandoned"
    }

    fn deprecated_label(&self) -> &'static str {
        "*(abandoned)*"
    }
}

impl DiagnosticPolicy for ComposerFormatter {
    /// Packagist's `abandoned` replacement name is a structured, registry-validated
    /// field (see `deprecation_from_abandoned` in `registry.rs`), unlike npm's free-text
    /// `deprecated` message — safe to offer as a rename target.
    fn supports_package_rename(&self) -> bool {
        true
    }
}

impl SourcePolicy for ComposerFormatter {}

impl OsvNaming for ComposerFormatter {
    /// Packagist's canonical form is lowercase, and `composer.json` files
    /// legitimately carry mixed case (Composer resolves case-insensitively).
    /// This is the mirror image of NuGet: there, lowercasing kills the
    /// ecosystem; here, *not* lowercasing does (OSV is case-sensitive for
    /// every ecosystem except PyPI).
    fn osv_package_name(&self, dep: &dyn Dependency) -> Option<String> {
        Some(self.normalize_package_name(dep.name()))
    }
}

/// Composer tilde semantics.
///
/// - `~X.Y.Z` — `>=X.Y.Z <X.(Y+1).0` (bumps minor)
/// - `~X.Y` — `>=X.Y.0 <(X+1).0.0` (bumps MAJOR — Composer-specific!)
/// - `~X` — `>=X.0.0 <(X+1).0.0`
fn satisfies_tilde_composer(version: &str, req: &str) -> bool {
    let req_parts: Vec<&str> = req.split('.').collect();
    let ver_parts: Vec<&str> = version.split('.').collect();

    if req_parts.len() >= 3 {
        // ~X.Y.Z: same as default — >=X.Y.Z <X.(Y+1).0
        // Must have same major and minor
        if req_parts.first() != ver_parts.first() {
            return false;
        }
        if req_parts.get(1) != ver_parts.get(1) {
            return false;
        }
        // Patch must be >= req patch
        let req_patch: u64 = req_parts.get(2).and_then(|p| p.parse().ok()).unwrap_or(0);
        let ver_patch: u64 = ver_parts.get(2).and_then(|p| p.parse().ok()).unwrap_or(0);
        ver_patch >= req_patch
    } else if req_parts.len() == 2 {
        // ~X.Y: >=X.Y.0 <(X+1).0.0 — bumps MAJOR (Composer-specific!)
        let req_major: u64 = req_parts.first().and_then(|p| p.parse().ok()).unwrap_or(0);
        let req_minor: u64 = req_parts.get(1).and_then(|p| p.parse().ok()).unwrap_or(0);
        let ver_major: u64 = ver_parts.first().and_then(|p| p.parse().ok()).unwrap_or(0);
        let ver_minor: u64 = ver_parts.get(1).and_then(|p| p.parse().ok()).unwrap_or(0);

        if ver_major != req_major {
            return false;
        }
        // Same major: minor must be >= req_minor
        ver_minor >= req_minor
    } else {
        // ~X: >=X.0.0 <(X+1).0.0 — same as caret for single segment
        req_parts.first() == ver_parts.first()
    }
}

/// Caret operator — same as default EcosystemFormatter but inlined for clarity.
fn satisfies_caret(version: &str, req: &str) -> bool {
    let req_parts: Vec<&str> = req.split('.').collect();
    let ver_parts: Vec<&str> = version.split('.').collect();

    if req_parts.first() != ver_parts.first() {
        return false;
    }

    if req_parts.first().is_some_and(|m| *m != "0") {
        return true;
    }

    if req_parts.len() >= 2 && ver_parts.len() >= 2 {
        return req_parts[1] == ver_parts[1];
    }

    true
}

/// Rank of a Composer stability keyword in `dev < alpha < beta < RC < stable` (matching
/// Composer's `VersionParser` keyword aliases `a`/`b` for alpha/beta), matched
/// case-insensitively. An empty word (no qualifier at all) ranks as `stable`, the top of the
/// scale, and so does any unrecognized suffix word — this happens to agree with Composer for
/// its own `stable`/`patch`/`pl`/`p` aliases (all release-equivalent), but is not a general
/// unknown-qualifier rule: a truly unrecognized word is not otherwise a valid Composer
/// stability suffix.
///
/// `pub(crate)`: shared with `registry.rs`, which ranks a `composer.json` `minimum-stability`
/// value and a per-dependency `@stability` flag word on this exact same scale (#424) — one
/// ranking function for "what does this stability word mean" everywhere in the crate.
pub(crate) const COMPOSER_STABLE_RANK: u8 = 4;

pub(crate) fn composer_stability_rank(word: &str) -> u8 {
    match word.to_ascii_lowercase().as_str() {
        "dev" => 0,
        "alpha" | "a" => 1,
        "beta" | "b" => 2,
        "rc" => 3,
        _ => COMPOSER_STABLE_RANK,
    }
}

/// A version string's own Composer stability rank (`dev < alpha < beta < RC < stable`),
/// reusing [`split_composer_core_and_suffix`]/[`parse_composer_qualifier`] — the same
/// separator-optional qualifier parser `compare_versions` already relies on, so a
/// separator-less suffix (`1.0.0RC1`) ranks identically to its hyphenated form
/// (`1.0.0-RC1`) with no separate classification path to drift out of sync (#424 S3).
///
/// `registry.rs` uses this instead of [`deps_core::Version::is_prerelease`] when filtering
/// "latest version" candidates against an [`effective_minimum_stability_rank`]-computed
/// floor: a boolean prerelease flag cannot express "beta or newer, but not alpha" the way a
/// `minimum-stability: beta` manifest setting requires.
///
/// Strips a leading `v`/`V` before splitting — without this, `split_composer_core_and_suffix`
/// finds its split point at that very first non-digit character, so a real candidate version
/// like `v2.3.0-alpha.1` (Packagist tags are routinely `v`-prefixed, e.g. every `symfony/*`
/// release) yields core `""` and qualifier word `"v"`, which `composer_stability_rank` cannot
/// recognize and ranks as fully stable — silently reopening #422 for every `v`-prefixed
/// prerelease (#424 critique C1). `version_satisfies_requirement`'s own operator branches
/// already strip `v` before reaching `compare_versions`/`satisfies_caret`, so this is the only
/// caller of `split_composer_core_and_suffix` that needed the same guard added directly.
///
/// [`effective_minimum_stability_rank`]: crate::registry::effective_minimum_stability_rank
pub(crate) fn composer_version_stability_rank(version: &str) -> u8 {
    let version = version.strip_prefix(['v', 'V']).unwrap_or(version);
    let (_, suffix) = split_composer_core_and_suffix(version);
    suffix.map_or(COMPOSER_STABLE_RANK, |s| parse_composer_qualifier(s).rank)
}

/// Splits a trailing Composer per-dependency stability flag (`@stable`, `@RC`, `@beta`,
/// `@alpha`, `@dev`, matched case-insensitively) off `requirement`, returning the requirement
/// text with the flag removed and the flag's own word when one was recognized.
///
/// The flag is a syntax element of the *constraint* grammar
/// (`composer/semver`'s `VersionParser::parseStabilityFlag`), not part of the version-range
/// text itself, so it must be stripped before `satisfies_caret`/`satisfies_tilde_composer`/
/// `compare_versions` ever see the constraint. Left in place, it is parsed as part of the
/// numeric core instead (e.g. `^1.0@beta`'s minor segment becomes `"0@beta"`), which only
/// happens to still match today because `satisfies_caret`'s nonzero-major fast path returns
/// before it would ever look at that garbled segment — every other operator (tilde,
/// `>=`/`<=`, exact/partial) has no such fast path and silently never matches (#424).
///
/// `pub(crate)`: also used by `registry.rs`'s [`effective_minimum_stability_rank`] to read
/// the flag as a per-dependency stability opt-in, overriding both the concrete-requirement
/// default and any manifest-level `minimum-stability`.
///
/// [`effective_minimum_stability_rank`]: crate::registry::effective_minimum_stability_rank
pub(crate) fn strip_stability_flag(requirement: &str) -> (&str, Option<&str>) {
    let Some(at_idx) = requirement.rfind('@') else {
        return (requirement, None);
    };
    let flag = &requirement[at_idx + 1..];
    if matches!(
        flag.to_ascii_lowercase().as_str(),
        "stable" | "rc" | "beta" | "alpha" | "dev"
    ) {
        (&requirement[..at_idx], Some(flag))
    } else {
        (requirement, None)
    }
}

/// A parsed Composer stability qualifier: a stability rank plus every numeric group in its
/// suffix (Composer's modifier regex allows any number of them, e.g. `alpha1.5`), compared
/// group by group so `beta10` outranks `beta2` and `alpha1.5` outranks `alpha1.2`.
struct ComposerQualifier {
    rank: u8,
    numeric: Vec<u64>,
}

/// Parses a qualifier suffix (already stripped of its leading separator, e.g. `"beta1"`,
/// `"RC.2"`, `"dev"`, `"alpha1.5"`) into its stability rank and every digit run that follows
/// the keyword, in order.
fn parse_composer_qualifier(suffix: &str) -> ComposerQualifier {
    let alpha_len = suffix.bytes().take_while(u8::is_ascii_alphabetic).count();
    let (word, rest) = suffix.split_at(alpha_len);
    let numeric = rest
        .split(|c: char| !c.is_ascii_digit())
        .filter(|s| !s.is_empty())
        .map(|s| s.parse().unwrap_or(0))
        .collect();
    ComposerQualifier {
        rank: composer_stability_rank(word),
        numeric,
    }
}

/// Splits `version` into its bare numeric-dot core and, if present, its raw stability
/// qualifier suffix (leading `-`/`_`/`.` separator stripped). Build metadata (after `+`) is
/// discarded first.
fn split_composer_core_and_suffix(version: &str) -> (&str, Option<&str>) {
    let without_build = version.split('+').next().unwrap_or(version);
    let split_at = without_build
        .find(|c: char| !c.is_ascii_digit() && c != '.')
        .unwrap_or(without_build.len());
    let core = &without_build[..split_at];
    let rest = without_build[split_at..].trim_start_matches(['-', '_', '.']);
    if rest.is_empty() {
        (core, None)
    } else {
        (core, Some(rest))
    }
}

/// Simple semantic version comparison returning -1, 0, or 1.
///
/// Compares the numeric-dot core segment by segment, then applies Composer's stability
/// precedence to any qualifier suffix (`dev < alpha < beta < RC < stable`, see
/// [`composer_stability_rank`]) — a qualified version always sorts below its unqualified
/// counterpart, and two qualifiers of the same stability compare by their numeric suffix
/// (e.g. `beta2` < `beta10`).
fn compare_versions(a: &str, b: &str) -> i32 {
    let (a_core, a_suffix) = split_composer_core_and_suffix(a);
    let (b_core, b_suffix) = split_composer_core_and_suffix(b);

    let a_parts: Vec<u64> = a_core.split('.').map(|s| s.parse().unwrap_or(0)).collect();
    let b_parts: Vec<u64> = b_core.split('.').map(|s| s.parse().unwrap_or(0)).collect();

    let len = a_parts.len().max(b_parts.len());
    for i in 0..len {
        let av = a_parts.get(i).copied().unwrap_or(0);
        let bv = b_parts.get(i).copied().unwrap_or(0);
        if av < bv {
            return -1;
        }
        if av > bv {
            return 1;
        }
    }

    let a_q = a_suffix.map_or(
        ComposerQualifier {
            rank: COMPOSER_STABLE_RANK,
            numeric: Vec::new(),
        },
        parse_composer_qualifier,
    );
    let b_q = b_suffix.map_or(
        ComposerQualifier {
            rank: COMPOSER_STABLE_RANK,
            numeric: Vec::new(),
        },
        parse_composer_qualifier,
    );

    if a_q.rank != b_q.rank {
        return if a_q.rank < b_q.rank { -1 } else { 1 };
    }
    if a_q.numeric != b_q.numeric {
        return if a_q.numeric < b_q.numeric { -1 } else { 1 };
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ComposerDependency, ComposerSection};
    use std::collections::HashMap;
    use tower_lsp_server::ls_types::Range;

    #[test]
    fn test_normalize_package_name() {
        let f = ComposerFormatter;
        assert_eq!(
            f.normalize_package_name(&PackageName::new("Vendor/Package")),
            "vendor/package"
        );
        assert_eq!(
            f.normalize_package_name(&PackageName::new("symfony/console")),
            "symfony/console"
        );
    }

    #[test]
    fn test_package_url() {
        let f = ComposerFormatter;
        assert_eq!(
            f.package_url(&PackageName::new("symfony/console")),
            "https://packagist.org/packages/symfony/console"
        );
    }

    #[test]
    fn test_wildcard() {
        let f = ComposerFormatter;
        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("1.2.3"), "*"));
        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("99.0.0"), "*"));
    }

    #[test]
    fn test_caret_operator() {
        let f = ComposerFormatter;
        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("1.2.3"), "^1.2"));
        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("1.5.0"), "^1.0"));
        assert!(!f.version_satisfies_requirement(&ConcreteVersion::new("2.0.0"), "^1.2"));
        assert!(!f.version_satisfies_requirement(&ConcreteVersion::new("0.3.0"), "^1.0"));
    }

    #[test]
    fn test_tilde_with_three_segments() {
        let f = ComposerFormatter;
        // ~1.2.3 means >=1.2.3 <1.3.0 (same as npm)
        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("1.2.3"), "~1.2.3"));
        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("1.2.9"), "~1.2.3"));
        assert!(!f.version_satisfies_requirement(&ConcreteVersion::new("1.3.0"), "~1.2.3"));
        assert!(!f.version_satisfies_requirement(&ConcreteVersion::new("1.2.2"), "~1.2.3"));
    }

    #[test]
    fn test_tilde_with_two_segments_composer_specific() {
        let f = ComposerFormatter;
        // ~1.2 means >=1.2.0 <2.0.0 (DIFFERENT from npm ~1.2 = >=1.2.0 <1.3.0)
        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("1.2.0"), "~1.2"));
        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("1.9.9"), "~1.2"));
        assert!(!f.version_satisfies_requirement(&ConcreteVersion::new("2.0.0"), "~1.2")); // upper bound is <2.0.0
        assert!(!f.version_satisfies_requirement(&ConcreteVersion::new("1.1.9"), "~1.2")); // minor too low
        assert!(!f.version_satisfies_requirement(&ConcreteVersion::new("0.9.0"), "~1.2")); // major too low
    }

    #[test]
    fn test_wildcard_version() {
        let f = ComposerFormatter;
        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("1.0.5"), "1.0.*"));
        assert!(!f.version_satisfies_requirement(&ConcreteVersion::new("1.1.0"), "1.0.*"));
    }

    #[test]
    fn test_or_combinator() {
        let f = ComposerFormatter;
        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("1.0.0"), "1.0.0 || 2.0.0"));
        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("2.0.0"), "1.0.0 || 2.0.0"));
        assert!(!f.version_satisfies_requirement(&ConcreteVersion::new("3.0.0"), "1.0.0 || 2.0.0"));
    }

    #[test]
    fn test_range_constraint() {
        let f = ComposerFormatter;
        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("1.5.0"), ">=1.0 <2.0"));
        assert!(!f.version_satisfies_requirement(&ConcreteVersion::new("2.0.0"), ">=1.0 <2.0"));
        assert!(!f.version_satisfies_requirement(&ConcreteVersion::new("0.9.0"), ">=1.0 <2.0"));
    }

    #[test]
    fn test_range_constraint_spaced_operators() {
        let f = ComposerFormatter;
        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("1.5.0"), ">= 1.0 < 2.0"));
        assert!(!f.version_satisfies_requirement(&ConcreteVersion::new("2.0.0"), ">= 1.0 < 2.0"));
        assert!(!f.version_satisfies_requirement(&ConcreteVersion::new("0.9.0"), ">= 1.0 < 2.0"));
    }

    #[test]
    fn test_bare_v_requirement_does_not_match_everything() {
        let f = ComposerFormatter;
        assert!(!f.version_satisfies_requirement(&ConcreteVersion::new("1.2.3"), "v"));
        assert!(!f.version_satisfies_requirement(&ConcreteVersion::new("0.0.0"), "v"));
    }

    /// Regression test for #418: a stability qualifier suffix must not be silently
    /// truncated and tie with its stable counterpart.
    #[test]
    fn test_compare_versions_prerelease_vs_stable() {
        assert_eq!(compare_versions("2.0.0", "2.0.0-beta1"), 1);
        assert_eq!(compare_versions("2.0.0-beta1", "2.0.0"), -1);
        assert_ne!(compare_versions("2.0.0", "2.0.0-beta1"), 0);
    }

    #[test]
    fn test_compare_versions_qualifier_ordering() {
        // dev < alpha < beta < RC < stable.
        assert_eq!(compare_versions("1.0.0-dev", "1.0.0-alpha1"), -1);
        assert_eq!(compare_versions("1.0.0-alpha1", "1.0.0-beta1"), -1);
        assert_eq!(compare_versions("1.0.0-beta1", "1.0.0-RC1"), -1);
        assert_eq!(compare_versions("1.0.0-RC1", "1.0.0"), -1);
        // Keyword aliases (a/b) and case-insensitivity.
        assert_eq!(compare_versions("1.0.0-a1", "1.0.0-alpha1"), 0);
        assert_eq!(compare_versions("1.0.0-b1", "1.0.0-beta1"), 0);
        assert_eq!(compare_versions("1.0.0-rc1", "1.0.0-RC1"), 0);
    }

    #[test]
    fn test_compare_versions_qualifier_numeric_suffix() {
        assert_eq!(compare_versions("1.0.0-beta2", "1.0.0-beta10"), -1);
        assert_eq!(compare_versions("1.0.0-beta10", "1.0.0-beta2"), 1);
        assert_eq!(compare_versions("1.0.0-beta.1", "1.0.0-beta.2"), -1);
    }

    /// Regression test for impl-critic M2: Composer's modifier regex allows any number of
    /// numeric groups after the stability keyword (`(?:[.-]?\d+)*`), so every group must be
    /// compared, not just the first — otherwise "alpha1.5" and "alpha1.2" silently tie.
    #[test]
    fn test_compare_versions_qualifier_multiple_numeric_groups() {
        assert_eq!(compare_versions("1.0.0-alpha1.5", "1.0.0-alpha1.2"), 1);
        assert_eq!(compare_versions("1.0.0-alpha1.2", "1.0.0-alpha1.5"), -1);
        assert_ne!(compare_versions("1.0.0-alpha1.5", "1.0.0-alpha1.2"), 0);
    }

    #[test]
    fn test_compare_versions_numeric_segments_still_correct() {
        assert_eq!(compare_versions("1.0.0", "1.0.0"), 0);
        assert_eq!(compare_versions("1.0.1", "1.0.0"), 1);
        assert_eq!(compare_versions("1.0.0", "1.0.1"), -1);
        assert_eq!(compare_versions("2.0.0", "1.9.9"), 1);
        assert_eq!(compare_versions("10.0.0", "9.0.0"), 1);
    }

    /// A qualified alpha/beta/RC version must not tie with its stable release under this
    /// comparator. Note this only fixes `version_satisfies_requirement`'s own ordering — it
    /// does not, by itself, fix "latest version" selection: `registry.rs`'s
    /// `select_latest_matching` returns the first Packagist entry satisfying a requirement
    /// with no minimum-stability filter of its own, so a real alpha/beta/RC release (only
    /// `dev-*`/`*-dev` branches are filtered) can still be reported as "latest" for a
    /// concrete requirement like `>=1.0` (tracked separately).
    #[test]
    fn test_compare_versions_sorts_prerelease_below_stable() {
        let mut versions = vec!["2.0.0-beta1", "2.0.0", "2.0.0-alpha1", "2.0.0-RC1"];
        versions.sort_by(|a, b| compare_versions(a, b).cmp(&0));
        assert_eq!(
            versions,
            vec!["2.0.0-alpha1", "2.0.0-beta1", "2.0.0-RC1", "2.0.0"]
        );
    }

    #[test]
    fn test_compare_versions_build_metadata_ignored() {
        assert_eq!(compare_versions("1.0.0+build1", "1.0.0+build2"), 0);
    }

    /// Build metadata must be stripped before the qualifier is parsed, not after — otherwise
    /// a qualifier suffix could be dragged into the discarded build segment or vice versa.
    #[test]
    fn test_compare_versions_qualifier_with_build_metadata() {
        assert_eq!(
            compare_versions("2.0.0-beta1+build1", "2.0.0-beta1+build2"),
            0
        );
        assert_eq!(compare_versions("2.0.0-beta1+build1", "2.0.0+build2"), -1);
        assert_eq!(compare_versions("2.0.0+build1", "2.0.0-beta1+build2"), 1);
    }

    /// Regression guard for a core with fewer dot segments than its counterpart (e.g. a
    /// Composer partial version): the missing trailing segment must be treated as `0`, not
    /// cause a spurious mismatch.
    #[test]
    fn test_compare_versions_partial_core_length_mismatch() {
        assert_eq!(compare_versions("1.0", "1.0.0"), 0);
        assert_eq!(compare_versions("1.0.0", "1.0"), 0);
        assert_eq!(compare_versions("1.1", "1.0.5"), 1);
        assert_eq!(compare_versions("1", "1.0.0-beta1"), 1);
    }

    #[test]
    fn test_comparison_operators() {
        let f = ComposerFormatter;
        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("2.0.0"), ">=2.0.0"));
        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("2.0.1"), ">=2.0.0"));
        assert!(!f.version_satisfies_requirement(&ConcreteVersion::new("1.9.9"), ">=2.0.0"));

        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("1.9.9"), "<2.0.0"));
        assert!(!f.version_satisfies_requirement(&ConcreteVersion::new("2.0.0"), "<2.0.0"));

        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("1.0.0"), "=1.0.0"));
        assert!(!f.version_satisfies_requirement(&ConcreteVersion::new("1.0.1"), "=1.0.0"));
    }

    #[test]
    fn test_exact_version() {
        let f = ComposerFormatter;
        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("1.2.3"), "1.2.3"));
        assert!(!f.version_satisfies_requirement(&ConcreteVersion::new("1.2.4"), "1.2.3"));
    }

    #[test]
    fn test_partial_version() {
        let f = ComposerFormatter;
        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("1.2.3"), "1"));
        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("1.2.3"), "1.2"));
        assert!(!f.version_satisfies_requirement(&ConcreteVersion::new("2.0.0"), "1.2"));
    }

    #[test]
    fn test_osv_package_name_lowercases_unlike_normalize_used_elsewhere() {
        use crate::types::{ComposerDependency, ComposerSection};
        use tower_lsp_server::ls_types::{Position, Range};

        let f = ComposerFormatter;
        let dep = ComposerDependency {
            name: "Symfony/Http-Kernel".into(),
            name_range: Range::new(Position::new(0, 0), Position::new(0, 1)),
            version_req: Some("^4.4".into()),
            version_range: None,
            section: ComposerSection::Require,
        };

        assert_eq!(
            f.osv_package_name(&dep),
            Some("symfony/http-kernel".to_string())
        );
        // Regression guard: a future "tidy-up" that routes osv_package_name
        // through normalize_package_name directly instead of calling it
        // explicitly would still be correct for Composer, but this pins the
        // observable behavior so any drift is caught.
        assert_eq!(
            f.osv_package_name(&dep).as_deref(),
            Some(f.normalize_package_name(&dep.name).as_str())
        );
    }

    #[test]
    fn test_v_prefix_stripped() {
        let f = ComposerFormatter;
        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("v1.24.1"), "^1.24"));
        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("v1.2.3"), "~1.2.3"));
        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("v2.0.0"), ">=2.0.0"));
        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("v1.0.5"), "1.0.*"));
        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("v1.2.3"), "1.2.3"));
        assert!(!f.version_satisfies_requirement(&ConcreteVersion::new("v2.0.0"), "^1.0"));
    }

    #[test]
    fn test_v_prefix_symmetric_on_requirement_side() {
        let f = ComposerFormatter;
        // Exact pin with a `v`-prefixed requirement, matched against an un-prefixed
        // candidate (the common case: registry candidates already had `v` stripped).
        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("1.2.3"), "v1.2.3"));
        // Both sides `v`-prefixed.
        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("v1.2.3"), "v1.2.3"));
        // Operator-prefixed requirement with a `v`-prefixed version literal.
        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("1.5.0"), "^v1.2.0"));
        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("1.2.9"), "~v1.2.3"));
        assert!(!f.version_satisfies_requirement(&ConcreteVersion::new("2.0.0"), "^v1.2.0"));
        // Wildcard with a `v`-prefixed requirement.
        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("1.0.5"), "v1.0.*"));
    }

    /// #424 S2: `strip_stability_flag` recognizes every Composer stability flag word
    /// case-insensitively and leaves an unrecognized trailing `@word` alone.
    #[test]
    fn test_strip_stability_flag_recognizes_known_words() {
        assert_eq!(strip_stability_flag("^1.0@beta"), ("^1.0", Some("beta")));
        assert_eq!(strip_stability_flag("^1.0@BETA"), ("^1.0", Some("BETA")));
        assert_eq!(strip_stability_flag("1.0.*@dev"), ("1.0.*", Some("dev")));
        assert_eq!(strip_stability_flag("2.0@RC"), ("2.0", Some("RC")));
        assert_eq!(strip_stability_flag("2.0@alpha"), ("2.0", Some("alpha")));
        assert_eq!(strip_stability_flag("2.0@stable"), ("2.0", Some("stable")));
    }

    #[test]
    fn test_strip_stability_flag_no_flag_present() {
        assert_eq!(strip_stability_flag("^1.0"), ("^1.0", None));
        assert_eq!(strip_stability_flag("*"), ("*", None));
    }

    /// An unrecognized trailing `@word` (not one of Composer's five stability flags) must be
    /// left untouched rather than silently swallowed.
    #[test]
    fn test_strip_stability_flag_unrecognized_word_left_alone() {
        assert_eq!(
            strip_stability_flag("^1.0@notaflag"),
            ("^1.0@notaflag", None)
        );
    }

    /// #424 S2 correctness prerequisite: with the flag stripped, a tilde requirement whose
    /// upper bound has no nonzero-major fast path to paper over a leftover flag must still
    /// compute the correct range.
    #[test]
    fn test_version_satisfies_requirement_at_flag_tilde_range() {
        let f = ComposerFormatter;
        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("1.2.5"), "~1.2.3@beta"));
        assert!(!f.version_satisfies_requirement(&ConcreteVersion::new("1.3.0"), "~1.2.3@beta"));
        assert!(!f.version_satisfies_requirement(&ConcreteVersion::new("1.2.2"), "~1.2.3@beta"));
    }

    /// #424: `composer_version_stability_rank` ranks a version's own qualifier on the same
    /// `dev < alpha < beta < RC < stable` scale as `composer_stability_rank`, agreeing with
    /// `compare_versions`'s qualifier ordering (`test_compare_versions_qualifier_ordering`).
    #[test]
    fn test_composer_version_stability_rank_orders_qualifiers() {
        assert_eq!(composer_version_stability_rank("1.0.0-dev"), 0);
        assert_eq!(composer_version_stability_rank("1.0.0-alpha1"), 1);
        assert_eq!(composer_version_stability_rank("1.0.0-beta1"), 2);
        assert_eq!(composer_version_stability_rank("1.0.0-RC1"), 3);
        assert_eq!(
            composer_version_stability_rank("1.0.0"),
            COMPOSER_STABLE_RANK
        );
    }

    /// #424 S3: a separator-less suffix ranks identically to its hyphenated form — the same
    /// qualifier parser (`split_composer_core_and_suffix`) backs both.
    #[test]
    fn test_composer_version_stability_rank_separatorless_suffix() {
        assert_eq!(
            composer_version_stability_rank("2.0.0RC1"),
            composer_version_stability_rank("2.0.0-RC1"),
        );
    }

    /// #424 critique C1 (CRITICAL regression): a `v`-prefixed prerelease (e.g. every
    /// `symfony/*`/`sylius/sylius` release) must still rank below `COMPOSER_STABLE_RANK` —
    /// before the fix, the leading `v`/`V` was consumed as the qualifier "word" itself,
    /// which `composer_stability_rank` cannot recognize and silently ranks as stable,
    /// reopening #422 for any package whose newest release is `v`-prefixed.
    #[test]
    fn test_composer_version_stability_rank_strips_v_prefix() {
        for prerelease in [
            "v2.3.0-alpha.1",
            "v6.0.0-BETA1",
            "v2.0.0-alpha1",
            "V3.0.0-RC1",
        ] {
            assert!(
                composer_version_stability_rank(prerelease) < COMPOSER_STABLE_RANK,
                "{prerelease:?} must rank below stable, not be swallowed as an unrecognized qualifier word"
            );
        }
    }

    /// #424 critique C1: a `v`-prefixed prerelease must rank strictly below a `v`-prefixed
    /// (or plain) stable release of the same series, matching the real Packagist ordering
    /// `sylius/sylius`'s `v2.3.0-alpha.1` vs. `v2.2.8` regressed on.
    #[test]
    fn test_composer_version_stability_rank_v_prefixed_prerelease_below_stable() {
        assert!(
            composer_version_stability_rank("v2.3.0-alpha.1")
                < composer_version_stability_rank("v2.2.8")
        );
        assert!(
            composer_version_stability_rank("v2.3.0-alpha.1")
                < composer_version_stability_rank("2.3.0")
        );
    }

    /// Regression test for impl-critic S1: a `v`-prefixed literal on the plain
    /// comparison-operator branches (`>=`, `<=`, `>`, `<`, `=`, `!=`) must be stripped the
    /// same way the caret/tilde branches already do, not fall into
    /// `split_composer_core_and_suffix`'s qualifier-suffix branch and compare as core `0`.
    #[test]
    fn test_v_prefix_on_comparison_operators() {
        let f = ComposerFormatter;
        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("1.5.0"), ">=v1.0.0"));
        assert!(!f.version_satisfies_requirement(&ConcreteVersion::new("0.9.0"), ">=v1.0.0"));
        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("1.5.0"), "<=v2.0.0"));
        assert!(!f.version_satisfies_requirement(&ConcreteVersion::new("2.5.0"), "<v2.0.0"));
        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("2.0.1"), ">v2.0.0"));
        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("2.0.0"), "=v2.0.0"));
        assert!(!f.version_satisfies_requirement(&ConcreteVersion::new("2.0.0"), "!=v2.0.0"));
        assert!(
            f.version_satisfies_requirement(&ConcreteVersion::new("1.5.0"), ">=v1.0.0 <v2.0.0")
        );
    }

    #[test]
    fn test_compile_requirement_bare_at_dev_returns_none() {
        let f = ComposerFormatter;
        assert!(f.compile_requirement(&VersionReq::new("@dev")).is_none());
    }

    #[test]
    fn test_compile_requirement_satisfiable() {
        let f = ComposerFormatter;
        let matcher = f
            .compile_requirement(&VersionReq::new("^1.2"))
            .expect("Composer requirement always compiles");
        assert_eq!(matcher.matches(&ConcreteVersion::new("1.5.0")), Some(true));
        assert_eq!(matcher.matches(&ConcreteVersion::new("2.0.0")), Some(false));
    }

    /// S2 regression: `get_versions` filters `dev-*`/`*-dev` entries out of `available`, so
    /// a branch requirement must suppress the whole scan rather than being checked against
    /// a list that structurally can never contain it.
    #[test]
    fn test_compile_requirement_dev_branch_prefix_returns_none() {
        let f = ComposerFormatter;
        assert!(
            f.compile_requirement(&VersionReq::new("dev-master"))
                .is_none()
        );
    }

    #[test]
    fn test_compile_requirement_dev_branch_suffix_returns_none() {
        let f = ComposerFormatter;
        assert!(
            f.compile_requirement(&VersionReq::new("1.0.x-dev"))
                .is_none()
        );
    }

    /// Minor item: a bare `@dev` minimum-stability flag resolves against dev-stability
    /// packages, which normalize to the same filtered-out `x-dev` shape as a dev branch.
    #[test]
    fn test_compile_requirement_at_dev_stability_flag_returns_none() {
        let f = ComposerFormatter;
        assert!(
            f.compile_requirement(&VersionReq::new("1.0.*@dev"))
                .is_none()
        );
        assert!(f.compile_requirement(&VersionReq::new("2.0@dev")).is_none());
    }

    #[test]
    fn test_validate_package_name_accepts_valid_names() {
        let f = ComposerFormatter;
        for name in ["symfony/console", "vendor.name/pkg-name", "a/b"] {
            assert!(
                f.validate_package_name(name).is_ok(),
                "expected {name:?} to be accepted"
            );
        }
    }

    /// #402: a structurally invalid Composer coordinate must be reported as an invalid
    /// package name, not forwarded to the registry lookup that produces the misleading
    /// generic diagnostic.
    #[test]
    fn test_validate_package_name_rejects_invalid_names() {
        let f = ComposerFormatter;
        for name in [
            "",
            "symfony",
            "symfony/console/extra",
            "/console",
            "symfony/",
            "-vendor/pkg",
            "vendor/-pkg",
            "vendor name/pkg",
        ] {
            assert!(
                f.validate_package_name(name).is_err(),
                "expected {name:?} to be rejected"
            );
        }
    }

    // --- #205 package-level deprecation ---

    #[test]
    fn test_deprecated_message_and_label_reuse_abandoned_wording() {
        let f = ComposerFormatter;
        assert_eq!(f.deprecated_message(), "This package is abandoned");
        assert_eq!(f.deprecated_label(), "*(abandoned)*");
    }

    #[test]
    fn test_supports_package_rename_true() {
        assert!(ComposerFormatter.supports_package_rename());
    }

    /// W1: the discoverability override must reject a degenerate (zero-width) name
    /// range — `find_positions` (`parser.rs`) falls back to `Range::default()`
    /// (`(0,0)-(0,0)`) on a name-locator miss, and `position_in_range` is inclusive on
    /// both ends, so an unguarded widen would make that sentinel selectable by a cursor
    /// resting on the file's opening `{`, reopening the C2 `Range::default()` hazard.
    #[test]
    fn test_is_position_on_dependency_rejects_zero_width_name_range() {
        use tower_lsp_server::ls_types::Position;

        let dep = ComposerDependency {
            name: "vendor/package".into(),
            name_range: Range::default(),
            version_req: Some("^1.0".into()),
            version_range: Some(Range::new(Position::new(1, 20), Position::new(1, 25))),
            section: ComposerSection::Require,
        };

        let f = ComposerFormatter;
        assert!(
            !f.is_position_on_dependency(&dep, Position::new(0, 0)),
            "a degenerate name_range must never be selectable, even at its own (0,0) span"
        );
        // The version range still works normally.
        assert!(f.is_position_on_dependency(&dep, Position::new(1, 22)));
    }

    /// The override still widens discoverability for a real (non-degenerate) name
    /// range — the whole point of overriding the shared default.
    #[test]
    fn test_is_position_on_dependency_accepts_real_name_range() {
        use tower_lsp_server::ls_types::Position;

        let dep = ComposerDependency {
            name: "vendor/package".into(),
            name_range: Range::new(Position::new(1, 4), Position::new(1, 20)),
            version_req: Some("^1.0".into()),
            version_range: Some(Range::new(Position::new(1, 23), Position::new(1, 28))),
            section: ComposerSection::Require,
        };

        let f = ComposerFormatter;
        assert!(f.is_position_on_dependency(&dep, Position::new(1, 10)));
    }

    /// T1 (D7(a)/C2): a Composer manifest whose name locator misses — a legal
    /// escaped-solidus `"vendor\/package"` key, which `find_positions`'s literal search
    /// for the serde-unescaped `"vendor/package"` never matches — must never offer a
    /// "Replace with X" rename action, rather than emitting a corrupting edit at
    /// `(0,0)`.
    ///
    /// Exercised two ways: end to end through the real parser (today's actual
    /// behavior — safe only because `version_range` also stays `None`, an incidental
    /// coupling, not a guarantee), and directly against `name_literal_guard`-shaped
    /// input (`version_range: Some(..)`, `name_range: Range::default()`) so the test
    /// still catches a regression if that coupling is ever broken by a parser change.
    #[tokio::test]
    async fn test_generate_code_actions_escaped_solidus_name_offers_no_rename_action() {
        let json = r#"{"require": {"vendor\/package": "^1.0"}}"#;
        let uri = deps_core::test_util::test_uri("/test/composer.json");
        let parse_result = crate::parser::parse_composer_json(json, &uri).unwrap();
        assert_eq!(parse_result.dependencies.len(), 1);
        let dep = &parse_result.dependencies[0];
        assert_eq!(
            dep.name_range,
            Range::default(),
            "escaped-solidus key must miss the literal-text search"
        );
        assert!(
            dep.version_range.is_none(),
            "today's incidental coupling: the version search never runs either"
        );

        let outcomes = deps_core::lsp_helpers::DependencyOutcomes::new().with_deprecation(
            "vendor/package",
            deps_core::Deprecation {
                reason: None,
                replacement: Some("other/package".to_string()),
            },
        );
        let cached = HashMap::new();
        let resolved = HashMap::new();
        let versions = deps_core::VersionData::new(&cached, &resolved).with_outcomes(&outcomes);

        let actions = deps_core::lsp_helpers::generate_code_actions(
            &parse_result,
            Position::new(0, 0),
            &uri,
            versions,
            json,
            &NoNetworkRegistry,
            &ComposerFormatter,
        )
        .await;
        assert!(
            actions.iter().all(|a| !a.title.starts_with("Replace with")),
            "no rename action may be offered when the name locator missed: {actions:?}"
        );

        // Direct regression guard for the guard mechanism itself (not just today's
        // incidental version_range coupling): a hand-built dependency with a valid
        // version_range but a degenerate name_range must still be rejected.
        let corrupted_dep = ComposerDependency {
            name: "vendor/package".into(),
            name_range: Range::default(),
            version_req: Some("^1.0".into()),
            version_range: Some(Range::new(Position::new(0, 33), Position::new(0, 37))),
            section: ComposerSection::Require,
        };
        let corrupted_result = crate::parser::ComposerParseResult {
            dependencies: vec![corrupted_dep],
            uri: uri.clone(),
            minimum_stability: None,
        };
        let actions = deps_core::lsp_helpers::generate_code_actions(
            &corrupted_result,
            Position::new(0, 34),
            &uri,
            versions,
            json,
            &NoNetworkRegistry,
            &ComposerFormatter,
        )
        .await;
        assert!(
            actions.iter().all(|a| !a.title.starts_with("Replace with")),
            "the name-literal guard must reject a degenerate name_range independent of \
             version_range: {actions:?}"
        );
    }

    /// Positive path (D7): a well-formed manifest with a real replacement name offers
    /// the "Replace with X" rename quickfix, targeting `name_range` with `replacement`.
    #[tokio::test]
    async fn test_generate_code_actions_offers_rename_action_for_well_formed_manifest() {
        let json = r#"{"require": {"vendor/package": "^1.0"}}"#;
        let uri = deps_core::test_util::test_uri("/test/composer.json");
        let parse_result = crate::parser::parse_composer_json(json, &uri).unwrap();
        let dep = &parse_result.dependencies[0];
        assert_ne!(dep.name_range, Range::default());
        let version_range = dep.version_range.expect("version_range must be present");

        let outcomes = deps_core::lsp_helpers::DependencyOutcomes::new().with_deprecation(
            "vendor/package",
            deps_core::Deprecation {
                reason: None,
                replacement: Some("other/package".to_string()),
            },
        );
        let cached = HashMap::new();
        let resolved = HashMap::new();
        let versions = deps_core::VersionData::new(&cached, &resolved).with_outcomes(&outcomes);

        let actions = deps_core::lsp_helpers::generate_code_actions(
            &parse_result,
            version_range.start,
            &uri,
            versions,
            json,
            &NoNetworkRegistry,
            &ComposerFormatter,
        )
        .await;

        let rename = actions
            .iter()
            .find(|a| a.title == "Replace with other/package")
            .unwrap_or_else(|| panic!("expected a rename action, got: {actions:?}"));
        let edits = rename
            .edit
            .as_ref()
            .and_then(|e| e.changes.as_ref())
            .and_then(|c| c.get(&uri))
            .expect("rename action must carry a WorkspaceEdit for this URI");
        assert_eq!(edits.len(), 1);
        assert_eq!(edits[0].range, dep.name_range);
        assert_eq!(edits[0].new_text, "other/package");
    }

    /// No-op [`deps_core::Registry`] so #205 code-action tests never hit the network —
    /// `generate_code_actions` calls `registry.get_versions` unconditionally after the
    /// registry-independent fix/rename actions are built.
    struct NoNetworkRegistry;

    impl deps_core::Registry for NoNetworkRegistry {
        fn get_versions<'a>(
            &'a self,
            _name: &'a PackageName,
        ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn deps_core::Version>>>>
        {
            Box::pin(async move { Ok(vec![]) })
        }

        fn get_latest_matching<'a>(
            &'a self,
            _name: &'a PackageName,
            _req: &'a VersionReq,
        ) -> deps_core::ecosystem::BoxFuture<
            'a,
            deps_core::Result<Option<Box<dyn deps_core::Version>>>,
        > {
            Box::pin(async move { Ok(None) })
        }

        fn search<'a>(
            &'a self,
            _query: &'a str,
            _limit: usize,
        ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn deps_core::Metadata>>>>
        {
            Box::pin(async move { Ok(vec![]) })
        }

        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }
}
