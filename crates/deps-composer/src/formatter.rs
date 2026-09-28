use deps_core::ConcreteVersion;
use deps_core::Dependency;
use deps_core::InvalidPackageName;
use deps_core::PackageName;
use deps_core::StabilityFloor;
use deps_core::VersionReq;
use deps_core::interval::{VersionRange, range_from_edges};
use deps_core::lsp_helpers::{
    DiagnosticMessages, DiagnosticPolicy, OsvNaming, PackageNaming, PackageRendering,
    RequirementMatcher, RequirementResolution, SourcePolicy, compile_requirement_unless,
    match_v_prefix_style, requirement_contains_template_placeholder,
};
use deps_core::normalize_operator_spacing;
use std::borrow::Cow;

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

/// Composer's own root-package version substitution keyword
/// (`composer/composer`'s `RootPackageLoader::isRootPackage`/`VersionParser`): pins a
/// dependency to the *root* package's own version, resolved by Composer itself at
/// generation time — most common in a monorepo lock-step split-package layout (e.g. the
/// Symfony/Laminas component split), where every split package's `composer.json` requires
/// its parent monorepo package as `self.version`. deps-lsp never resolves this itself.
const COMPOSER_SELF_VERSION: &str = "self.version";

/// True when `requirement` is one of Composer's non-rewritable, non-numeric constraint
/// forms that `deps-lsp` must never overwrite with a literal registry version:
/// - the literal keyword [`COMPOSER_SELF_VERSION`] (#1373)
/// - an inline alias, `<branch-or-constraint> as <alias-version>`
///   (`composer/semver`'s `VersionParser::parseConstraints`, `\s+as\s+` grammar), e.g.
///   `"dev-main as 1.0.0"` — pins a branch/constraint while presenting a different version
///   to satisfied dependents (#1373). Composer requires whitespace on both sides of `as`,
///   so a plain `" as "` substring check cannot false-positive against a hyphenated
///   branch/package token (e.g. `"feature-as-x"` has no surrounding spaces).
/// - an unexpanded external-templating placeholder anywhere in the text
///   (`requirement_contains_template_placeholder`, #1374/#1379 impl-critic M2/M3) — any of the
///   five forms that predicate recognizes (`$VAR`/`${VAR}`, `{{ VAR }}`/`{% ... %}`, `@VAR@`,
///   `%VAR%`, `<%= VAR %>`); `composer.json` has no such grammar itself, but a manifest
///   pre-processed by external templating (`envsubst`, CI templating, `configure_file`) can
///   still leave one in place, e.g. `"${PSR_LOG}"`; `composer.json`'s parser preserves this as
///   an ordinary string, so it reaches [`RequirementResolution`]/[`PackageRendering`] just
///   like the two Composer-native forms above.
///
/// None of these three forms is ever resolved by `deps-lsp` itself — the first two are
/// handled entirely by Composer's own installer, the third by whatever external tool
/// templated the manifest.
fn requirement_is_composer_unresolved(requirement: &str) -> bool {
    let trimmed = requirement.trim();
    trimmed == COMPOSER_SELF_VERSION
        || trimmed.contains(" as ")
        || requirement_contains_template_placeholder(requirement)
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

    /// Composer's requirement grammar is not strict SemVer 2.0.0 (#299) — must not opt in.
    fn strict_prerelease_exclusion(&self) -> bool {
        false
    }

    fn explicitly_excludes(&self, version: &ConcreteVersion) -> bool {
        composer_explicitly_excludes(version.as_str(), &self.0)
    }
}

/// Strips a leading `v`/`V` and a trailing `@stability` flag from one OR-branch (or the
/// whole requirement, before any `||` split), returning `None` for the wildcard sentinel
/// (empty, or `*`) — shared by [`walk_requirement`] and the OR-gap bound derivation
/// ([`composer_or_gap_excludes`]), which both need this per-branch normalization.
fn strip_branch_affixes(branch: &str) -> Option<&str> {
    let branch = branch.trim();
    // Only strip when it leaves something behind — a bare "v"/"V" branch must fall through
    // to the exact/partial match, not collapse to "" and hit the wildcard guard below.
    let branch = match branch.strip_prefix(['v', 'V']) {
        Some(rest) if !rest.is_empty() => rest,
        _ => branch,
    };
    // Must run before the operator branches below see the text, or a `@flag` is parsed as
    // part of the numeric core (#424).
    let (branch, _stability_flag) = strip_stability_flag(branch);
    let branch = branch.trim();
    if branch.is_empty() || branch == "*" {
        None
    } else {
        Some(branch)
    }
}

/// Normalizes a top-level comma AND-separator to whitespace — Composer treats the two
/// identically (`composer/semver`'s `VersionParser::parseConstraints`) — and runs the result
/// through [`normalize_operator_spacing`]. Shared by [`walk_requirement`]'s AND-splitting and
/// the OR-gap bound derivation ([`composer_or_gap_excludes`]) so both stay in sync, mirroring
/// this project's #1596/#1598 admit/exclude-walker dedup precedent.
fn normalize_and_separators(requirement: &str) -> Cow<'_, str> {
    if !requirement.contains(',') {
        return normalize_operator_spacing(requirement);
    }
    let comma_normalized = requirement.replace(',', " ");
    Cow::Owned(normalize_operator_spacing(&comma_normalized).into_owned())
}

/// Splits `s` on Composer's OR separator (#1609): `composer/semver`'s own
/// `VersionParser::parseConstraints` splits on `preg_split('{\s*\|\|?\s*}', ...)`, so a lone
/// `|` is accepted exactly like the documented `||`. Implemented as a manual scan collapsing
/// each maximal run of one-or-more `|` characters into a single split point (generalizing
/// "one or two pipes" to any run, so a stray `|||` degrades the same way rather than leaving a
/// spurious empty segment behind) — avoids a regex dependency for this.
///
/// Unlike naively splitting on every individual `|` character and filtering out empty strings,
/// this leaves a genuinely blank segment visible to the caller instead of silently discarding
/// it (impl-critic M1): two separator runs with only whitespace between them (`"A || || B"`),
/// or a trailing run (`"A ||"`), each produce an empty/whitespace-only element here. The
/// caller — [`walk_requirement`] and [`composer_or_gap_excludes`] — treats any such
/// blank-after-trim branch as a malformed OR expression (`composer/semver` itself rejects these
/// shapes) and fails closed, rather than the two callers silently disagreeing on how to handle
/// it depending on how the blanks happened to be produced.
///
/// Shared by [`walk_requirement`]'s OR-splitting and [`composer_or_gap_excludes`]'s `||`/`|`-
/// branch enumeration, mirroring this project's #1596/#1598 admit/exclude-walker dedup
/// precedent.
// `start`/`i` come from `char_indices()`, and every split point sits immediately before/after
// a single-byte ASCII `|`, always a char boundary.
#[allow(clippy::string_slice)]
pub(crate) fn split_or_branches(s: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0usize;
    let mut in_run = false;
    for (i, c) in s.char_indices() {
        if c == '|' {
            if !in_run {
                parts.push(&s[start..i]);
                in_run = true;
            }
        } else if in_run {
            start = i;
            in_run = false;
        }
    }
    parts.push(&s[if in_run { s.len() } else { start }..]);
    parts
}

/// Whether every one of `branches` is non-blank once trimmed — the shared malformed-OR guard
/// [`split_or_branches`]'s doc describes (impl-critic M1): a blank segment only ever comes from
/// a degenerate separator shape (`"A || || B"`, a trailing `"A ||"`), which `composer/semver`
/// itself rejects rather than treating as an implicit wildcard branch.
fn has_blank_or_branch(branches: &[&str]) -> bool {
    branches.iter().any(|b| b.trim().is_empty())
}

/// Whether `s`'s Composer numeric-dot core (before any qualifier suffix, and after a leading
/// `v`/`V` strip) is non-empty and entirely numeric.
///
/// [`increment_last_segment`] already applies this same discipline internally, but only to a
/// hyphen range's upper bound; this is the same check made reusable so the lower bound gets it
/// too (impl-critic S1) — without it, `compare_versions`' own `unwrap_or(0)` silently turns a
/// malformed bound like `"^1.0"` or `"abc"` into version `0`, which would make e.g.
/// `"^1.0 - 2.0"` or `"abc - 2.0"` admit everything below `hi` instead of falling closed —
/// exactly the fabricated-bound bug class #1610 already guards against for the upper edge.
fn has_valid_version_core(s: &str) -> bool {
    let (core, _suffix) = split_composer_core_and_suffix(strip_bound_v(s));
    !core.is_empty() && core.split('.').all(|seg| seg.parse::<u64>().is_ok())
}

/// Splits `branch` on composer/semver's Hyphenated Version Range separator (`X +- +Y`, #1608):
/// exactly three whitespace-separated tokens with the middle token literally `-`.
/// `split_whitespace` collapses any run of spaces around the hyphen for free (matching
/// composer/semver's own ` +- +` grammar — one or more spaces each side, impl-critic M2), and
/// never splits a hyphen embedded in a qualifier suffix with no surrounding whitespace
/// (`1.0.0-alpha`, kept together as one token).
///
/// A hyphen range AND-combined with another clause (`"1.0 - 2.0 !=1.4.0"`, also valid
/// composer/semver grammar) is not yet supported — its 4+ tokens fall through to `None` here
/// (tracked as a follow-up, impl-critic M2/D2); the caller's prior fail-closed handling for an
/// unrecognized shape applies unchanged.
fn split_hyphen_range(branch: &str) -> Option<(&str, &str)> {
    match branch.split_whitespace().collect::<Vec<_>>().as_slice() {
        [lo, "-", hi] => Some((*lo, *hi)),
        _ => None,
    }
}

/// Resolves a Composer Hyphenated Version Range (`X - Y`, #1608) to a single `(lower, upper)`
/// edge pair — shared by [`walk_requirement`] (evaluates the edges directly via
/// [`RequirementLeaf::eval_edge`], no `format!`/re-parse round trip) and [`branch_bound`] (feeds
/// them straight into [`range_from_edges`]), so the two admit/OR-gap paths cannot independently
/// drift out of sync (impl-critic S3 — the same #1591-class risk this project's other
/// admit/exclude walkers already guard against).
///
/// `composer/semver`'s `VersionParser::parseConstraints` resolves the upper edge two different
/// ways depending on `hi`'s precision (impl-critic S2, verified against Composer's own docs:
/// `"1.0.0 - 2.1.0"` == `">=1.0.0 <=2.1.0"`):
/// - A "full" `hi` — 3 or more numeric segments, or one already carrying its own stability
///   suffix — is admitted up to and including itself (`<=hi`).
/// - A "partial" `hi` (1-2 numeric segments, no suffix) widens to `<(last-segment+1)-dev`
///   instead of a plain `<(last-segment+1)`: `-dev` is Composer's own lowest stability rank
///   (below `alpha`), so it excludes every version — prerelease or stable — at that boundary
///   core, the way Composer's real `-dev`-suffixed exclusive bound does; a plain
///   `<(last-segment+1)` would let a same-core prerelease (e.g. `2.1.0-beta` under
///   `"1.0 - 2.0"`) slip under it, since a prerelease sorts below its own stable release under
///   [`compare_versions`]' qualifier precedence.
///
/// Returns `None` when `branch` isn't hyphen-range shaped ([`split_hyphen_range`]), or either
/// edge's numeric core isn't itself valid ([`has_valid_version_core`], impl-critic S1) — a
/// malformed bound like `"^1.0 - 2.0"` must not silently become version `0` and admit
/// everything below `hi`.
fn hyphen_range_edges(branch: &str) -> Option<((String, bool), (String, bool))> {
    let (lo, hi) = split_hyphen_range(branch)?;
    if !has_valid_version_core(lo) || !has_valid_version_core(hi) {
        return None;
    }
    let lo = strip_bound_v(lo).to_string();

    let hi_stripped = strip_bound_v(hi);
    let (hi_core, hi_suffix) = split_composer_core_and_suffix(hi_stripped);
    let full = hi_suffix.is_some() || hi_core.split('.').count() >= 3;
    let upper = if full {
        (hi_stripped.to_string(), true)
    } else {
        let incremented = increment_last_segment(hi_core)?;
        (format!("{incremented}-dev"), false)
    };
    Some(((lo, true), upper))
}

/// Shared OR (`||`/`|`)/AND (whitespace or comma)-splitting tree-walker for Composer's
/// requirement grammar, including its `v`-prefix and `@stability`-flag stripping — the
/// traversal [`ComposerFormatter::version_satisfies_requirement`] and
/// [`composer_explicitly_excludes`] both need identically (PR #1589 had to fix the same
/// `normalize_operator_spacing` spacing bug in both functions because they did not share this
/// walker; #1591 extracted it). #1603: a comma is Composer's other AND separator
/// (`">=1.0,<2.0"` == `">=1.0 <2.0"`) and must be split identically to whitespace, or a
/// comma-joined compound requirement silently collapses to its first clause (`eval_leaf`
/// strips the leading operator and treats everything after the first comma as part of a
/// single version string).
///
/// Any multi-token result — whether split on comma or whitespace — is always AND-combined
/// (impl-critic S3 follow-up to #1603): every legitimate single Composer clause (`^`/`~`,
/// `>=`/`<=`/`>`/`<`/`=`/`!=`, `X.Y.*` wildcard, exact/partial match) is exactly one token
/// once spacing is normalized, so there is no real single-clause shape with an internal
/// space to protect against splitting — unlike an earlier version of this function, which
/// only treated a multi-token run as AND when some token started with `>`/`<`, silently
/// collapsing e.g. `"^1.0 !=1.2.0"` to just its first token.
///
/// A hyphenated range (`"1.0 - 2.0"`, #1608) is checked next, on the whole branch before any
/// AND-splitting: it is composer/semver's own `X +- +Y` grammar form, but its own internal
/// space would otherwise be mis-split into bogus AND-clauses (`"1.0"`, `"-"`, `"2.0"`) by the
/// generic whitespace split below. [`hyphen_range_edges`] resolves it to a `(lower, upper)`
/// edge pair evaluated directly via [`RequirementLeaf::eval_edge`] — no `format!`/re-parse
/// round trip (impl-critic S3). A shape it cannot characterize (non-numeric bound, no
/// space-hyphen-space at all) falls through to that same generic split, preserving this
/// function's prior fail-closed behavior for it.
///
/// A blank branch produced by [`split_or_branches`] (impl-critic M1: a degenerate separator
/// shape like `"A || || B"` or a trailing `"A ||"`) fails the whole requirement closed
/// (`false`) rather than treating it as an implicit wildcard branch — `composer/semver` itself
/// rejects these shapes, and `false` is the correct answer for both the "admits" and
/// "explicitly excludes" questions on malformed input.
///
/// Only leaf evaluation and the AND-group's fold differ between the two callers — see
/// [`RequirementLeaf`].
fn walk_requirement<L: RequirementLeaf>(leaf: &L, version: &str, requirement: &str) -> bool {
    let version = version.strip_prefix(['v', 'V']).unwrap_or(version);
    let Some(requirement) = strip_branch_affixes(requirement) else {
        return leaf.on_wildcard();
    };

    if requirement.contains('|') {
        let branches = split_or_branches(requirement);
        if has_blank_or_branch(&branches) {
            return false;
        }
        return branches
            .into_iter()
            .any(|part| walk_requirement(leaf, version, part.trim()));
    }

    if let Some((lower, upper)) = hyphen_range_edges(requirement) {
        return leaf.combine_and(
            [
                leaf.eval_edge(version, &lower.0, lower.1, true),
                leaf.eval_edge(version, &upper.0, upper.1, false),
            ]
            .into_iter(),
        );
    }

    let requirement = normalize_and_separators(requirement);
    let requirement = &*requirement;

    let parts: Vec<&str> = requirement.split_whitespace().collect();
    if parts.len() > 1 {
        return leaf.combine_and(
            parts
                .iter()
                .map(|part| walk_requirement(leaf, version, part)),
        );
    }

    let requirement = parts.first().copied().unwrap_or(requirement);
    leaf.eval_leaf(version, requirement)
}

/// A single non-combinator requirement clause's evaluation, plumbed into [`walk_requirement`].
/// The OR/AND splitting and `v`-prefix/stability-flag normalization are identical for both
/// [`ComposerFormatter::version_satisfies_requirement`]'s "does this admit `version`" question
/// ([`AdmitLeaf`]) and [`composer_explicitly_excludes`]'s "does this explicitly ban `version`"
/// question ([`ExcludeLeaf`]) — only what a leaf decides, and how an AND-group folds its
/// clauses' results, differ.
///
/// The AND fold genuinely differs, not just the leaf: an "admit" AND-group needs every clause
/// satisfied (`>=1.0 <2.0` requires both bounds), but an "exclude" AND-group only needs one
/// `!=` clause to fire (`>=1.0 !=1.5.0 <2.0` bans 1.5.0 even though the range clauses never
/// individually exclude anything) — an `all()` fold would miss this, since the range clauses
/// never explicitly exclude anything on their own (fix-cycle #1571 M2).
trait RequirementLeaf {
    /// Result for an empty or `*` (wildcard) clause.
    fn on_wildcard(&self) -> bool;

    /// Evaluates one clause with no `||` and no multi-token AND group left to split.
    fn eval_leaf(&self, version: &str, clause: &str) -> bool;

    /// Folds an AND-separated clause group's per-clause results.
    fn combine_and(&self, results: impl Iterator<Item = bool>) -> bool;

    /// Evaluates a single bound edge (`(bound, inclusive)`, from either side of a hyphen range,
    /// #1608, via [`hyphen_range_edges`]) directly, without building and re-parsing an
    /// operator-prefixed clause string (impl-critic S3). `lower` is `true` for the range's
    /// lower edge (an implicit `>=`/`>`), `false` for its upper edge (`<=`/`<`).
    ///
    /// For [`AdmitLeaf`] this is a plain version-vs-bound comparison, equivalent to what
    /// [`AdmitLeaf::eval_leaf`]'s own `>=`/`<=`/`>`/`<` branches compute. For [`ExcludeLeaf`] a
    /// bound edge never itself excludes a version — only a literal `!=` clause does (see
    /// [`ExcludeLeaf::eval_leaf`]) — so this always answers `false`, mirroring how
    /// `ExcludeLeaf::eval_leaf` itself answers `false` for a `>=`/`<=`/`>`/`<` clause.
    fn eval_edge(&self, version: &str, bound: &str, inclusive: bool, lower: bool) -> bool;
}

/// [`RequirementLeaf`] for "does this admit `version`" — Composer's full requirement grammar
/// (`^`, `~`, `>=`/`<=`/`>`/`<`/`=`/`!=`, `X.Y.*` wildcard, exact/partial match).
struct AdmitLeaf;

impl RequirementLeaf for AdmitLeaf {
    fn on_wildcard(&self) -> bool {
        true
    }

    fn combine_and(&self, mut results: impl Iterator<Item = bool>) -> bool {
        results.all(|r| r)
    }

    fn eval_edge(&self, version: &str, bound: &str, inclusive: bool, lower: bool) -> bool {
        let ord = compare_versions(version, bound);
        if lower {
            if inclusive { ord >= 0 } else { ord > 0 }
        } else if inclusive {
            ord <= 0
        } else {
            ord < 0
        }
    }

    // `version.starts_with(prefix)` short-circuits before `prefix.len()` is used as a slice
    // bound, so it is always a char boundary.
    #[allow(clippy::string_slice)]
    fn eval_leaf(&self, version: &str, requirement: &str) -> bool {
        if let Some(req) = requirement.strip_prefix('^') {
            let req = req.strip_prefix(['v', 'V']).unwrap_or(req);
            return satisfies_caret(version, req);
        }

        if let Some(req) = requirement.strip_prefix('~') {
            let req = req.strip_prefix(['v', 'V']).unwrap_or(req);
            return satisfies_tilde_composer(version, req);
        }

        // `req` may itself be `v`-prefixed (e.g. ">=v1.0.0"); strip it independently of
        // `walk_requirement`'s leading strip, or it falls into
        // `split_composer_core_and_suffix`'s qualifier-suffix branch and compares as core `0`.
        if let Some(req) = requirement.strip_prefix(">=") {
            let req = req.trim();
            let req = req.strip_prefix(['v', 'V']).unwrap_or(req);
            return compare_versions(version, req) >= 0;
        }
        if let Some(req) = requirement.strip_prefix("<=") {
            let req = req.trim();
            let req = req.strip_prefix(['v', 'V']).unwrap_or(req);
            return compare_versions(version, req) <= 0;
        }
        if let Some(req) = requirement.strip_prefix('>') {
            let req = req.trim();
            let req = req.strip_prefix(['v', 'V']).unwrap_or(req);
            return compare_versions(version, req) > 0;
        }
        if let Some(req) = requirement.strip_prefix('<') {
            let req = req.trim();
            let req = req.strip_prefix(['v', 'V']).unwrap_or(req);
            return compare_versions(version, req) < 0;
        }
        if let Some(req) = requirement.strip_prefix('=') {
            let req = req.trim();
            let req = req.strip_prefix(['v', 'V']).unwrap_or(req);
            return compare_versions(version, req) == 0;
        }
        if let Some(req) = requirement.strip_prefix("!=") {
            let req = req.trim();
            let req = req.strip_prefix(['v', 'V']).unwrap_or(req);
            return compare_versions(version, req) != 0;
        }

        if requirement.ends_with(".*") {
            let prefix = requirement.trim_end_matches(".*");
            return version.starts_with(prefix) && version[prefix.len()..].starts_with('.');
        }

        let req_parts: Vec<&str> = requirement.split('.').collect();
        let ver_parts: Vec<&str> = version.split('.').collect();

        if req_parts.len() == ver_parts.len() {
            return version == requirement;
        }

        if req_parts.len() < ver_parts.len() {
            return ver_parts.starts_with(&req_parts);
        }

        false
    }
}

/// [`RequirementLeaf`] for "does this explicitly ban `version`" (fix-cycle #1571): only a
/// `!=` leaf naming `version` exactly counts — every other clause shape has "no opinion"
/// rather than affirmatively excluding anything, which is why its AND fold is `any()` rather
/// than [`AdmitLeaf`]'s `all()`.
///
/// The intensional signal [`RequirementMatcher::explicitly_excludes`] needs, since scanning
/// `available` for "does something newer also match" cannot distinguish a `!=`-punched hole
/// from a fallback that legitimately exceeds the requirement's ceiling (both make
/// `version_satisfies_requirement` return `false` identically).
struct ExcludeLeaf;

impl RequirementLeaf for ExcludeLeaf {
    fn on_wildcard(&self) -> bool {
        false
    }

    fn combine_and(&self, mut results: impl Iterator<Item = bool>) -> bool {
        results.any(|r| r)
    }

    fn eval_edge(&self, _version: &str, _bound: &str, _inclusive: bool, _lower: bool) -> bool {
        false
    }

    fn eval_leaf(&self, version: &str, requirement: &str) -> bool {
        let Some(req) = requirement.strip_prefix("!=") else {
            return false;
        };
        let req = req.trim();
        let req = req.strip_prefix(['v', 'V']).unwrap_or(req);
        compare_versions(version, req) == 0
    }
}

/// Thin [`walk_requirement`] wrapper for "does this explicitly ban `version`" — see
/// [`ExcludeLeaf`], combined with the `||`-alternation-gap check (#1601, see
/// [`composer_or_gap_excludes`]): a `!=` clause and an OR-gap are two independently sufficient
/// ways Composer can explicitly exclude a version with no single admitted-range ceiling to
/// blame it on.
fn composer_explicitly_excludes(version: &str, requirement: &str) -> bool {
    walk_requirement(&ExcludeLeaf, version, requirement)
        || composer_or_gap_excludes(version, requirement)
}

/// Strips a leading `v`/`V` from a clause's bound text — the same normalization
/// [`AdmitLeaf::eval_leaf`]'s own operator branches apply independently of
/// [`strip_branch_affixes`]'s branch-level strip (a clause may carry its own `v` right after
/// its operator, e.g. `">=v1.0.0"`).
fn strip_bound_v(s: &str) -> &str {
    s.strip_prefix(['v', 'V']).unwrap_or(s)
}

/// Increments `prefix`'s last dot-segment by one, forming the exclusive upper edge implied by
/// a wildcard clause (`X.Y.*` -> lower `X.Y`, upper `X.(Y+1)`) or a hyphen range's upper bound
/// (`X - Y` -> `>=X <Y+1`, #1608) — mirrors [`AdmitLeaf::eval_leaf`]'s wildcard branch exactly
/// (a prefix-of-segments check), just expressed as a literal boundary value instead of a
/// `starts_with` test.
///
/// Returns `None` — rather than silently fabricating a `0` segment (#1610's root-cause bug
/// class) — when any dot-segment is non-numeric (a malformed/typo'd bound like `"abc"`), or
/// when the last segment is already `u64::MAX` and cannot be incremented further; both cases
/// make the caller treat the clause/branch as an unrecognized shape, which only means detection
/// through it is skipped, never a false positive.
fn increment_last_segment(prefix: &str) -> Option<String> {
    let mut parts = Vec::new();
    for segment in prefix.split('.') {
        parts.push(segment.parse::<u64>().ok()?);
    }
    let last = parts.last_mut()?;
    *last = last.checked_add(1)?;
    Some(
        parts
            .iter()
            .map(u64::to_string)
            .collect::<Vec<_>>()
            .join("."),
    )
}

/// Composer's `compare_versions`, wrapped as an [`Ordering`](std::cmp::Ordering)-returning
/// comparator for [`deps_core::interval`]'s generic bound-comparison closures.
fn compare_versions_ord(a: &str, b: &str) -> std::cmp::Ordering {
    compare_versions(a, b).cmp(&0)
}

/// One AND-clause's contribution to its branch's overall admitted extent (#1601), expressed as
/// a [`deps_core::interval::VersionRange`] (#1610: reusing the same validated interval
/// representation `deps-maven`'s own OR/disjoint-range exclusion check builds on, rather than a
/// Composer-specific bound type). Returns `None` when the clause's admitted set cannot be
/// expressed as a value-based bound independent of a specific candidate's own segment count or
/// of a known matcher quirk:
///
/// - A bare exact/partial-match clause (no operator prefix) has no such bound —
///   [`AdmitLeaf::eval_leaf`]'s own partial-match branch admits or rejects based on how many
///   dot-segments the *candidate itself* has relative to the clause, not on a fixed value
///   range independent of that.
/// - A caret (`^`) clause is excluded too: [`satisfies_caret`]'s admitted range is well-defined
///   (`>=major.minor.patch[-suffix] <upper-dev`), but reproducing it here would duplicate its
///   zero-padding, first-nonzero-component lock, and synthetic `-dev`-suffix construction — not
///   worth it until a shared bound-string helper exists, so it stays grouped with tilde below.
/// - Tilde (`~`) is excluded too, for the same reason, even though
///   [`satisfies_tilde_composer`]'s own bound is well-defined — mixing a caret-adjacent
///   operator into bound derivation piecemeal is more error-prone than consistently treating
///   both as "unknown shape".
/// - A `!=` clause is handled by [`branch_bound`] itself, before this function is ever called
///   for it (it punctures a single point rather than restricting the branch's extent —
///   `ExcludeLeaf`'s own AND-fold already catches this independently, so it must not narrow the
///   bound derived here).
///
/// Excluding these shapes only means some real gaps go undetected — it is always safe, never
/// incorrect, mirroring `deps-maven`'s own defensive "unknown shape contributes no edge"
/// pattern in its `upper_edge`/`lower_edge`.
// TODO(critic): share comparator-prefix parsing with eval_leaf (follow-up to #1610).
fn clause_bound(clause: &str) -> Option<VersionRange<String>> {
    if let Some(req) = clause.strip_prefix(">=") {
        let v = strip_bound_v(req.trim()).to_string();
        return Some(VersionRange::Minimum {
            version: v,
            inclusive: true,
        });
    }
    if let Some(req) = clause.strip_prefix("<=") {
        let v = strip_bound_v(req.trim()).to_string();
        return Some(VersionRange::Maximum {
            version: v,
            inclusive: true,
        });
    }
    if let Some(req) = clause.strip_prefix('>') {
        let v = strip_bound_v(req.trim()).to_string();
        return Some(VersionRange::Minimum {
            version: v,
            inclusive: false,
        });
    }
    if let Some(req) = clause.strip_prefix('<') {
        let v = strip_bound_v(req.trim()).to_string();
        return Some(VersionRange::Maximum {
            version: v,
            inclusive: false,
        });
    }
    if let Some(req) = clause.strip_prefix('=') {
        let v = strip_bound_v(req.trim()).to_string();
        return Some(VersionRange::Exact(v));
    }
    if let Some(prefix) = clause.strip_suffix(".*") {
        // `increment_last_segment` itself rejects a non-numeric/empty prefix (code-review
        // finding: a malformed/typo'd clause like `"abc.*"` must fall through to `None`
        // (unknown shape) the same as caret/tilde/bare-partial, not silently treat `"abc"` as
        // version `0` and fabricate a bound `[0,1)` for a clause that admits nothing at all).
        if let Some(upper) = increment_last_segment(prefix) {
            return Some(VersionRange::Bounded {
                min: prefix.to_string(),
                min_inclusive: true,
                max: upper,
                max_inclusive: false,
            });
        }
    }
    None
}

/// Compares two optional lower edges and keeps the tighter (larger) one, matching a lower
/// bound's own AND-intersection: at equal value, an exclusive edge is tighter than inclusive.
fn tighter_lower(a: Option<(String, bool)>, b: Option<(String, bool)>) -> Option<(String, bool)> {
    match (a, b) {
        (None, x) | (x, None) => x,
        (Some((av, ai)), Some((bv, bi))) => match compare_versions(&av, &bv) {
            0 => Some((av, ai && bi)),
            ord if ord > 0 => Some((av, ai)),
            _ => Some((bv, bi)),
        },
    }
}

/// Compares two optional upper edges and keeps the tighter (smaller) one — mirrors
/// [`tighter_lower`].
fn tighter_upper(a: Option<(String, bool)>, b: Option<(String, bool)>) -> Option<(String, bool)> {
    match (a, b) {
        (None, x) | (x, None) => x,
        (Some((av, ai)), Some((bv, bi))) => match compare_versions(&av, &bv) {
            0 => Some((av, ai && bi)),
            ord if ord < 0 => Some((av, ai)),
            _ => Some((bv, bi)),
        },
    }
}

/// One `||`/`|`-branch's overall admitted extent, expressed as a
/// [`deps_core::interval::VersionRange`] built from [`range_from_edges`] (#1610). A hyphenated
/// range (#1608) is recognized on the whole branch first, mirroring [`walk_requirement`]'s own
/// interception (see that function's doc); otherwise each clause is AND-intersected via
/// [`clause_bound`], skipping a `!=` clause (non-narrowing, see that function's doc) and
/// bailing out entirely (`?`) on any other unrecognized clause shape.
///
/// Returns `None` when no clause contributed a bound (an all-`!=`/wildcard/unrecognized-clause
/// branch — functionally inert either way for [`composer_or_gap_excludes`]'s gap detection, so
/// omitting it from the `branches` list is equivalent to the alternative of keeping it with no
/// edges) or, via [`range_from_edges`], `Some(VersionRange::Empty)` when the intersected bound
/// turns out unsatisfiable (impl-critic M1: `lower > upper`, or equal with either edge
/// exclusive) — [`VersionRange::upper_edge`]/[`VersionRange::lower_edge`] give `Empty` no edge
/// either, so it contributes nothing to gap detection rather than manufacturing a fake gap out
/// of a branch that never admitted anything.
fn branch_bound(branch: &str) -> Option<VersionRange<String>> {
    let branch = strip_branch_affixes(branch)?;

    if let Some((lower, upper)) = hyphen_range_edges(branch) {
        return range_from_edges(Some(lower), Some(upper), |a: &String, b: &String| {
            compare_versions_ord(a, b)
        });
    }

    let normalized = normalize_and_separators(branch);
    let normalized = &*normalized;
    let parts: Vec<&str> = normalized.split_whitespace().collect();
    let parts: Vec<&str> = if parts.is_empty() {
        vec![normalized]
    } else {
        parts
    };

    let mut lower: Option<(String, bool)> = None;
    let mut upper: Option<(String, bool)> = None;
    for part in parts {
        if part.starts_with("!=") {
            continue;
        }
        let clause = clause_bound(part)?;
        lower = tighter_lower(lower, clause.lower_edge().map(|(v, i)| (v.clone(), i)));
        upper = tighter_upper(upper, clause.upper_edge().map(|(v, i)| (v.clone(), i)));
    }
    range_from_edges(lower, upper, |a: &String, b: &String| {
        compare_versions_ord(a, b)
    })
}

/// Whether `version` is explicitly excluded by an OR-alternation gap (#1601, same class as
/// Maven's #1590 disjoint-range gap): not admitted by any `||`/`|`-branch, yet sitting past one
/// branch's upper edge and before another's lower edge — Composer's counterpart of
/// `deps-maven`'s `range::explicitly_excludes`, generalized through
/// [`deps_core::interval::union_gap_excludes`] (the same representation-agnostic predicate
/// `deps-npm`'s own `||`-gap detection routes through).
///
/// Coverage is checked once, up front, via the real matcher
/// (`ComposerFormatter::version_satisfies_requirement`) over the *whole* original requirement
/// — not by re-deriving "covered" from the same [`VersionRange`]s used for edge detection
/// (impl-critic S2): a branch whose bound [`branch_bound`] cannot characterize (caret/tilde/
/// bare-partial — see [`clause_bound`]'s doc) is filtered out of the `branches` list entirely,
/// so a bound-derived "covered" check could never see a candidate that only the *real* matcher
/// knows is admitted by exactly such a branch — reporting both `matches == true` and
/// `explicitly_excludes == true` for the same candidate simultaneously. Routing "covered"
/// through the real matcher first, before any branch is filtered, rules that out: once this
/// early return has passed, no member below can be covering `version` either, so the
/// `union_gap_excludes` `covers` callback below is intentionally always `false`.
///
/// A version stripped here is *only* used against [`compare_versions`]-based edge comparisons
/// (impl-critic S1) — the coverage check above passes the original, unstripped `version` to
/// the real matcher instead, which already strips it internally
/// ([`walk_requirement`]'s own leading strip); `compare_versions` has no such built-in
/// stripping; a real Packagist tag left un-stripped here (e.g. `v1.5.0`, common for
/// `symfony/*`) would silently defeat every gap comparison.
fn composer_or_gap_excludes(version: &str, requirement: &str) -> bool {
    if ComposerFormatter.version_satisfies_requirement(&ConcreteVersion::new(version), requirement)
    {
        return false;
    }
    let Some(stripped_requirement) = strip_branch_affixes(requirement) else {
        return false;
    };
    if !stripped_requirement.contains('|') {
        return false;
    }
    let raw_branches = split_or_branches(stripped_requirement);
    if has_blank_or_branch(&raw_branches) {
        return false;
    }
    let branches: Vec<VersionRange<String>> = raw_branches
        .into_iter()
        .filter_map(|b| branch_bound(b.trim()))
        .collect();
    let version = version.strip_prefix(['v', 'V']).unwrap_or(version);
    let cmp = |a: &str, b: &String| compare_versions_ord(a, b);
    deps_core::interval::union_gap_excludes(
        &branches,
        // Coverage is already ruled out by the real-matcher check above.
        |_: &VersionRange<String>| false,
        |b: &VersionRange<String>| {
            deps_core::interval::admits_at_or_above(version, b.upper_edge(), cmp)
        },
        |b: &VersionRange<String>| {
            deps_core::interval::admits_at_or_below(version, b.lower_edge(), cmp)
        },
    )
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

    /// Preserves `current`'s `v`-prefix style rather than inserting Packagist's tag text
    /// verbatim (#1435): unlike `deps-github-actions`/`deps-gitlab-ci` (tag pins) or
    /// `deps-swift` (whose `SwiftRegistry` already strips a GitHub tag's `v`/`V` prefix at
    /// fetch time — see `crate::registry`'s doc — so `version` here is never `v`-prefixed to
    /// begin with), Packagist's `p2` API reports a version's tag text unstripped (e.g.
    /// `v4.0.0-alpha1`), so without this override an unprefixed requirement like `3.28.0`
    /// would be rewritten to a `v`-prefixed one on every "update version" action even though
    /// Composer itself already strips `v`/`V` before comparing
    /// (`walk_requirement`'s own leading strip).
    fn format_version_replacing(&self, version: &ConcreteVersion, current: &str) -> String {
        match_v_prefix_style(current, version.as_str())
    }

    /// Same fix as [`format_version_replacing`](Self::format_version_replacing), for
    /// completion's insert path (#1435 S3): `typed_prefix` carries only what the user has
    /// typed so far, which is enough signal for a plain `v`-style check.
    fn format_version_for_completion(
        &self,
        version: &ConcreteVersion,
        typed_prefix: &str,
    ) -> String {
        match_v_prefix_style(typed_prefix, version.as_str())
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
    fn is_position_on_dependency(
        &self,
        dep: &dyn Dependency,
        position: deps_core::position::Position,
    ) -> bool {
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
    /// - `^` — caret, npm-style: locked at the first non-zero component from the left (major,
    ///   else minor, else patch), stricter than `deps-core`'s shared default caret check
    /// - `~X.Y.Z` — tilde with patch: `>=X.Y.Z <X.(Y+1).0`
    /// - `~X.Y` — tilde without patch: `>=X.Y.0 <(X+1).0.0` (Composer-specific!)
    /// - `X.Y.*` — wildcard patch
    /// - `>=X <Y` — range (space = AND)
    /// - `X || Y` — OR combinator
    ///
    /// Delegates the OR/AND-splitting and `v`-prefix/`@stability`-flag normalization to the
    /// shared `walk_requirement` tree-walker (see `AdmitLeaf` for this method's leaf
    /// semantics).
    fn version_satisfies_requirement(&self, version: &ConcreteVersion, requirement: &str) -> bool {
        walk_requirement(&AdmitLeaf, version.as_str(), requirement)
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
            |r| {
                requirement_is_composer_unresolved(r)
                    || r.starts_with("dev-")
                    || r.ends_with("-dev")
                    || r.contains("@dev")
            },
            ComposerMatcher,
        )
    }

    /// #1373: `self.version` or an inline alias (see `requirement_is_composer_unresolved`)
    /// must never be reported as an unsatisfiable requirement — both are resolved entirely
    /// by Composer's own installer, not by any version published on Packagist, so
    /// `deps_core::lsp_helpers::requirement_is_unsatisfiable` (which checks this before
    /// calling `compile_requirement`) must treat them as unresolved instead of "no
    /// published version satisfies this".
    ///
    /// #1370/#1380: all three forms `requirement_is_composer_unresolved` covers
    /// (`self.version`, an inline alias, and a `$VAR`/`${VAR}` placeholder) are equally
    /// non-rewritable — Composer has no "concrete but undecidable, safe-to-rewrite" ref
    /// concept (unlike a SHA/branch pin) for `requirement_is_unresolved` to stay broader
    /// than this for, so its default delegates here rather than duplicating the detector.
    fn requirement_is_placeholder(&self, requirement: &VersionReq) -> bool {
        requirement_is_composer_unresolved(requirement.as_str())
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
    ///
    /// Must stay ungated: this is plain OSV-classification logic reachable from `deps-cli`, not LSP-response code (#1545).
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
        if req_parts.first() != ver_parts.first() {
            return false;
        }
        if req_parts.get(1) != ver_parts.get(1) {
            return false;
        }
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
        ver_minor >= req_minor
    } else {
        // ~X: >=X.0.0 <(X+1).0.0 — same as caret for single segment
        req_parts.first() == ver_parts.first()
    }
}

/// Caret operator — npm-style semantics (also Composer's own, per its docs and
/// `VersionParser`): the range is bounded above at the first non-zero component from the left
/// (major, else minor, else patch) and bounded below at the requirement itself, with missing
/// trailing segments in `req` treated as zero. E.g. `^1.5` — `>=1.5.0 <2.0.0`; `^0.3.2` —
/// `>=0.3.2 <0.4.0`; `^0.0.3` — `>=0.0.3 <0.0.4`.
///
/// Both edges carry a synthetic `-dev` suffix when `req` itself names none: `dev` is the lowest
/// [`StabilityFloor`] rank, so appending it to the upper bound excludes every prerelease of the
/// next boundary version too (not just its stable release), and appending it to the lower bound
/// still admits a prerelease *of the requirement itself* (e.g. `^1.5` must admit `1.5.0-RC1`).
///
/// Splits `req` through [`split_composer_core_and_suffix`] up front — not just `req.split('.')`
/// — so a requirement whose last segment fuses a stability suffix onto its digits with no
/// separator (e.g. `^0.0.3alpha1`) doesn't get parsed as a garbled numeric component. The
/// upper-bound arithmetic reuses [`increment_last_segment`] (already `checked_add`-guarded), so
/// an overflowing requirement segment is rejected rather than panicking or silently wrapping,
/// and a fully non-numeric requirement (`^abc`) is rejected up front for the same reason.
fn satisfies_caret(version: &str, req: &str) -> bool {
    let (core, req_suffix) = split_composer_core_and_suffix(req);
    if core.is_empty() {
        return false;
    }

    let mut nums = Vec::new();
    for segment in core.split('.') {
        let Ok(n) = segment.parse::<u64>() else {
            return false;
        };
        nums.push(n);
    }
    let Some(&major) = nums.first() else {
        return false;
    };
    let minor = nums.get(1).copied();

    let lock_len = if major != 0 || nums.len() < 2 {
        1
    } else if minor.is_some_and(|m| m != 0) || nums.len() < 3 {
        2
    } else {
        3
    };

    let Some(upper_prefix) = nums.get(..lock_len).and_then(|prefix| {
        let joined = prefix
            .iter()
            .map(u64::to_string)
            .collect::<Vec<_>>()
            .join(".");
        increment_last_segment(&joined)
    }) else {
        return false;
    };
    let upper = format!("{upper_prefix}-dev");

    let mut lower_nums = nums.clone();
    while lower_nums.len() < 3 {
        lower_nums.push(0);
    }
    let lower_core = lower_nums
        .iter()
        .map(u64::to_string)
        .collect::<Vec<_>>()
        .join(".");
    let lower = req_suffix.map_or_else(
        || format!("{lower_core}-dev"),
        |suffix| format!("{lower_core}-{suffix}"),
    );

    compare_versions(version, &lower) >= 0 && compare_versions(version, &upper) < 0
}

/// Lenient, version-*qualifier* stability classification (matching Composer's `VersionParser`
/// keyword aliases `a`/`b` for alpha/beta), matched case-insensitively. An empty word (no
/// qualifier at all) classifies as [`StabilityFloor::Stable`], the top of the scale, and so
/// does any unrecognized suffix word — this happens to agree with Composer for its own
/// `stable`/`patch`/`pl`/`p` aliases (all release-equivalent), but is not a general
/// unknown-qualifier rule: a truly unrecognized word is not otherwise a valid Composer
/// stability suffix.
///
/// Deliberately distinct from [`StabilityFloor`]'s own strict [`std::str::FromStr`] impl
/// (#1444): a `minimum-stability` *config value* (or `@flag`) must reject an unrecognized
/// word, but a version string's own qualifier suffix has always been classified leniently —
/// this function preserves that unchanged behavior for `compare_versions`/
/// `composer_version_stability`, while `registry.rs`'s config-facing paths go through
/// [`StabilityFloor::from_str`] instead.
fn qualifier_stability(word: &str) -> StabilityFloor {
    match word.to_ascii_lowercase().as_str() {
        "dev" => StabilityFloor::Dev,
        "alpha" | "a" => StabilityFloor::Alpha,
        "beta" | "b" => StabilityFloor::Beta,
        "rc" => StabilityFloor::Rc,
        _ => StabilityFloor::Stable,
    }
}

/// A version string's own Composer stability floor, reusing
/// [`split_composer_core_and_suffix`]/[`parse_composer_qualifier`] — the same
/// separator-optional qualifier parser `compare_versions` already relies on, so a
/// separator-less suffix (`1.0.0RC1`) classifies identically to its hyphenated form
/// (`1.0.0-RC1`) with no separate classification path to drift out of sync (#424 S3).
///
/// `registry.rs` uses this instead of [`deps_core::Version::is_prerelease`] when filtering
/// "latest version" candidates against an [`effective_minimum_stability`]-computed floor: a
/// boolean prerelease flag cannot express "beta or newer, but not alpha" the way a
/// `minimum-stability: beta` manifest setting requires.
///
/// Strips a leading `v`/`V` before splitting — without this, `split_composer_core_and_suffix`
/// finds its split point at that very first non-digit character, so a real candidate version
/// like `v2.3.0-alpha.1` (Packagist tags are routinely `v`-prefixed, e.g. every `symfony/*`
/// release) yields core `""` and qualifier word `"v"`, which [`qualifier_stability`] cannot
/// recognize and classifies as fully stable — silently reopening #422 for every `v`-prefixed
/// prerelease (#424 critique C1). `version_satisfies_requirement`'s own operator branches
/// already strip `v` before reaching `compare_versions`/`satisfies_caret`, so this is the only
/// caller of `split_composer_core_and_suffix` that needed the same guard added directly.
///
/// [`effective_minimum_stability`]: crate::registry::effective_minimum_stability
pub(crate) fn composer_version_stability(version: &str) -> StabilityFloor {
    let version = version.strip_prefix(['v', 'V']).unwrap_or(version);
    let (_, suffix) = split_composer_core_and_suffix(version);
    suffix.map_or(StabilityFloor::Stable, |s| parse_composer_qualifier(s).rank)
}

/// Splits a trailing Composer per-dependency stability flag (`@stable`, `@RC`, `@beta`,
/// `@alpha`, `@dev`, matched case-insensitively) off `requirement`, returning the requirement
/// text with the flag removed and the flag's own word when one was recognized.
///
/// The flag is a syntax element of the *constraint* grammar
/// (`composer/semver`'s `VersionParser::parseStabilityFlag`), not part of the version-range
/// text itself, so it must be stripped before `satisfies_caret`/`satisfies_tilde_composer`/
/// `compare_versions` ever see the constraint. Left in place, every operator except caret
/// parses it as part of the numeric core instead (e.g. `~1.0@beta`'s minor segment becomes
/// `"0@beta"`) and silently never matches (#424); `satisfies_caret` itself now tolerates a
/// leftover flag by construction — it splits `req`'s own stability suffix off before parsing
/// digits, so `@beta` lands in the suffix text (where it degrades to the same `Stable`,
/// no-numeric qualifier as no suffix at all) rather than a garbled digit segment — but that is
/// an incidental side effect, not a substitute for stripping the flag up front.
///
/// `pub(crate)`: also used by `registry.rs`'s [`effective_minimum_stability`] to read
/// the flag as a per-dependency stability opt-in, overriding both the concrete-requirement
/// default and any manifest-level `minimum-stability`.
///
/// [`effective_minimum_stability`]: crate::registry::effective_minimum_stability
// `at_idx` comes from `rfind('@')`, an ASCII byte, so both slice bounds are always char
// boundaries.
#[allow(clippy::string_slice)]
pub(crate) fn strip_stability_flag(requirement: &str) -> (&str, Option<StabilityFloor>) {
    let Some(at_idx) = requirement.rfind('@') else {
        return (requirement, None);
    };
    let flag = &requirement[at_idx + 1..];
    match flag.parse::<StabilityFloor>() {
        Ok(floor) => (&requirement[..at_idx], Some(floor)),
        Err(_) => (requirement, None),
    }
}

/// A parsed Composer stability qualifier: a stability floor plus every numeric group in its
/// suffix (Composer's modifier regex allows any number of them, e.g. `alpha1.5`), compared
/// group by group so `beta10` outranks `beta2` and `alpha1.5` outranks `alpha1.2`.
struct ComposerQualifier {
    rank: StabilityFloor,
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
        rank: qualifier_stability(word),
        numeric,
    }
}

/// Splits `version` into its bare numeric-dot core and, if present, its raw stability
/// qualifier suffix (leading `-`/`_`/`.` separator stripped). Build metadata (after `+`) is
/// discarded first.
// `split_at` comes from `find` of an ASCII predicate (non-digit, non-`.`) or `.len()`, so
// it is always a char boundary.
#[allow(clippy::string_slice)]
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
/// [`qualifier_stability`]) — a qualified version always sorts below its unqualified
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
            rank: StabilityFloor::Stable,
            numeric: Vec::new(),
        },
        parse_composer_qualifier,
    );
    let b_q = b_suffix.map_or(
        ComposerQualifier {
            rank: StabilityFloor::Stable,
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
    use deps_core::position::{Position as DomainPosition, Range};
    #[cfg(feature = "lsp-responses")]
    use std::collections::HashMap;
    #[cfg(feature = "lsp-responses")]
    use tower_lsp_server::ls_types::Position;

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

    // #758: exact-value `package_url`/`validate_package_name` conformance, replacing
    // test_package_url, test_validate_package_name_accepts_valid_names, and
    // test_validate_package_name_rejects_invalid_names. `version_satisfies_requirement`'s
    // own tests stay hand-written below: Composer's tilde/caret/range/OR/`v`-prefix
    // semantics are extensively documented, historically-regression-driven behavior (#424,
    // #534, ...), not simple redundant literal lists.
    deps_core::formatter_conformance! {
        mod composer_formatter_conformance;
        build: ComposerFormatter;
        package_url: {
            "symfony/console" => "https://packagist.org/packages/symfony/console",
        };
        accepts: ["symfony/console", "vendor.name/pkg-name", "a/b"];
        rejects: [
            "",
            "symfony",
            "symfony/console/extra",
            "/console",
            "symfony/",
            "-vendor/pkg",
            "vendor/-pkg",
            "vendor name/pkg"
        ];
        format_version: [ "1.2.3" => "1.2.3" ];
    }

    /// #1435: an unprefixed requirement stays unprefixed when replaced with a `v`-prefixed
    /// registry tag — the bug this override fixes.
    #[test]
    fn test_format_version_replacing_preserves_unprefixed_style() {
        let f = ComposerFormatter;
        assert_eq!(
            f.format_version_replacing(&ConcreteVersion::new("v4.0.0-alpha1"), "3.28.0"),
            "4.0.0-alpha1"
        );
    }

    /// #1435: a `v`-prefixed requirement stays `v`-prefixed against an unprefixed registry
    /// version — the mirror-image case `match_v_prefix_style` already covers for GHA/GitLab.
    #[test]
    fn test_format_version_replacing_preserves_v_prefixed_style() {
        let f = ComposerFormatter;
        assert_eq!(
            f.format_version_replacing(&ConcreteVersion::new("4.0.0"), "v3.28.0"),
            "v4.0.0"
        );
    }

    #[test]
    fn test_wildcard() {
        let f = ComposerFormatter;
        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("1.2.3"), "*"));
        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("99.0.0"), "*"));
    }

    /// `RequirementLeaf::on_wildcard` is the one branch of the #1591 tree-walker extraction
    /// with no existing direct assertion on the `ExcludeLeaf` side (all other exclude coverage
    /// runs through `!=`-bearing requirements via `test_fallback_edit_excludes_newer_*` in
    /// `ecosystem.rs`) — an empty/`*` requirement never explicitly excludes anything, unlike
    /// `AdmitLeaf::on_wildcard` (see `test_wildcard` above), which always admits.
    #[test]
    fn test_composer_explicitly_excludes_wildcard_never_excludes() {
        assert!(!composer_explicitly_excludes("1.5.0", "*"));
        assert!(!composer_explicitly_excludes("1.5.0", ""));
    }

    #[test]
    fn test_caret_operator() {
        let f = ComposerFormatter;
        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("1.2.3"), "^1.2"));
        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("1.5.0"), "^1.0"));
        assert!(!f.version_satisfies_requirement(&ConcreteVersion::new("2.0.0"), "^1.2"));
        assert!(!f.version_satisfies_requirement(&ConcreteVersion::new("0.3.0"), "^1.0"));
    }

    /// #1617: `satisfies_caret` enforced only the major-version upper cutoff, silently
    /// admitting any minor/patch below the stated lower bound (e.g. `^1.5` wrongly admitted
    /// `1.1.0`/`1.2.0`/`1.4.0`).
    #[test]
    fn test_caret_enforces_minor_lower_bound() {
        let f = ComposerFormatter;
        // ^1.5 == >=1.5.0 <2.0.0
        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("1.5.0"), "^1.5"));
        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("1.5.9"), "^1.5"));
        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("1.9.0"), "^1.5"));
        assert!(!f.version_satisfies_requirement(&ConcreteVersion::new("1.1.0"), "^1.5"));
        assert!(!f.version_satisfies_requirement(&ConcreteVersion::new("1.2.0"), "^1.5"));
        assert!(!f.version_satisfies_requirement(&ConcreteVersion::new("1.4.0"), "^1.5"));
        assert!(!f.version_satisfies_requirement(&ConcreteVersion::new("2.0.0"), "^1.5"));
        assert!(!f.version_satisfies_requirement(&ConcreteVersion::new("0.9.0"), "^1.5"));
    }

    /// 0.x caret locks tighter (Composer follows npm semantics here): `^0.3.2` ==
    /// `>=0.3.2 <0.4.0`, so a lower patch within the same minor must still be rejected.
    #[test]
    fn test_caret_zero_major_locks_to_first_nonzero_component() {
        let f = ComposerFormatter;
        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("0.3.2"), "^0.3.2"));
        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("0.3.9"), "^0.3.2"));
        assert!(!f.version_satisfies_requirement(&ConcreteVersion::new("0.3.1"), "^0.3.2"));
        assert!(!f.version_satisfies_requirement(&ConcreteVersion::new("0.4.0"), "^0.3.2"));

        // ^0.0.3 == >=0.0.3 <0.0.4 — locks all the way to patch.
        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("0.0.3"), "^0.0.3"));
        assert!(!f.version_satisfies_requirement(&ConcreteVersion::new("0.0.2"), "^0.0.3"));
        assert!(!f.version_satisfies_requirement(&ConcreteVersion::new("0.0.4"), "^0.0.3"));
    }

    /// impl-critic S1: the upper bound must exclude every prerelease of the next boundary
    /// version too, not just its stable release — a plain `<2.0.0` cutoff wrongly admits
    /// `2.0.0-beta1` because a prerelease sorts below its own stable release.
    #[test]
    fn test_caret_upper_bound_excludes_prerelease_of_next_boundary() {
        let f = ComposerFormatter;
        assert!(!f.version_satisfies_requirement(&ConcreteVersion::new("2.0.0-beta1"), "^1.5"));
        assert!(!f.version_satisfies_requirement(&ConcreteVersion::new("2.0.0-dev"), "^1.5"));
        assert!(!f.version_satisfies_requirement(&ConcreteVersion::new("0.4.0-RC1"), "^0.3.2"));
        assert!(!f.version_satisfies_requirement(&ConcreteVersion::new("0.0.4-alpha"), "^0.0.3"));
    }

    /// impl-critic M1: the lower bound must still admit a prerelease *of the requirement
    /// itself* when the requirement names no explicit stability (Composer/npm both allow this).
    #[test]
    fn test_caret_lower_bound_admits_prerelease_of_requirement_itself() {
        let f = ComposerFormatter;
        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("1.5.0-RC1"), "^1.5"));
        assert!(!f.version_satisfies_requirement(&ConcreteVersion::new("1.4.9-RC1"), "^1.5"));
    }

    /// impl-critic M2 / tester gap: a stability suffix on the requirement's own last segment
    /// must be preserved and attached to the *numeric core*, not appended after zero-padding
    /// (`^1.0-beta`'s lower bound is `1.0.0-beta`, not `1.0-beta.0`) — this must hold whether
    /// the requirement stops at the locked (minor) segment or goes deeper into a `0.0.x` core.
    #[test]
    fn test_caret_requirement_suffix_attaches_to_zero_padded_core() {
        let f = ComposerFormatter;
        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("1.0.0-beta"), "^1.0-beta"));
        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("0.3.0-beta"), "^0.3-beta"));
        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("0.3.5"), "^0.3-beta"));
        assert!(!f.version_satisfies_requirement(&ConcreteVersion::new("0.4.0"), "^0.3-beta"));

        // Referenced in `satisfies_caret`'s own doc comment: `^1.0.0-a1` must admit itself.
        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("1.0.0-a1"), "^1.0.0-a1"));

        // Tester gap: a fused, separator-optional suffix directly after the locking digit
        // (real Composer syntax, see `test_is_prerelease_marker_separatorless_suffix`) must
        // not corrupt the upper-bound's numeric parse and produce an inverted/unsatisfiable
        // range — `^0.0.3-alpha1` must admit its own exact version.
        assert!(
            f.version_satisfies_requirement(&ConcreteVersion::new("0.0.3-alpha1"), "^0.0.3-alpha1")
        );
        assert!(!f.version_satisfies_requirement(&ConcreteVersion::new("0.0.4"), "^0.0.3-alpha1"));
    }

    /// impl-critic M3: a fully non-numeric requirement (typo/malformed) must be rejected, not
    /// silently treated as `0` and admit everything with a matching major.
    #[test]
    fn test_caret_malformed_requirement_rejected() {
        let f = ComposerFormatter;
        assert!(!f.version_satisfies_requirement(&ConcreteVersion::new("0.5.0"), "^abc"));
        assert!(!f.version_satisfies_requirement(&ConcreteVersion::new("1.0.0"), "^abc"));
    }

    /// impl-critic S2: an overflowing requirement segment must not panic (debug) or silently
    /// wrap to a bogus bound (release) — `increment_last_segment`'s `checked_add` guard makes
    /// this simply unsatisfiable.
    #[test]
    fn test_caret_overflowing_major_does_not_panic() {
        let f = ComposerFormatter;
        assert!(!f.version_satisfies_requirement(
            &ConcreteVersion::new("18446744073709551615.0.0"),
            "^18446744073709551615"
        ));
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

    /// #1603: a comma is Composer's other AND separator, equivalent to whitespace — before
    /// the fix, `">=1.0.0,<2.0.0"` silently collapsed to its first clause (`>=1.0.0` alone),
    /// so a version above the upper bound was incorrectly admitted.
    #[test]
    fn test_comma_and_separator_equivalent_to_whitespace() {
        let f = ComposerFormatter;
        // Control: a plain caret requirement, unaffected by the comma fix.
        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("1.5.0"), "^1.0"));
        assert!(!f.version_satisfies_requirement(&ConcreteVersion::new("2.0.0"), "^1.0"));

        // The comma-joined compound requirement must gate on BOTH bounds, not just the first.
        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("1.5.0"), ">=1.0.0,<2.0.0"));
        assert!(!f.version_satisfies_requirement(&ConcreteVersion::new("2.5.0"), ">=1.0.0,<2.0.0"));
        assert!(!f.version_satisfies_requirement(&ConcreteVersion::new("0.5.0"), ">=1.0.0,<2.0.0"));

        // A lone `!=` clause, comma-adjacent syntax aside.
        assert!(!f.version_satisfies_requirement(&ConcreteVersion::new("1.1.0"), "!=1.1.0"));
        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("1.2.0"), "!=1.1.0"));

        // Compound: all three comma-separated clauses must hold.
        let compound = ">=1.0.0,<2.0.0,!=1.1.0";
        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("1.0.0"), compound));
        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("1.5.0"), compound));
        assert!(!f.version_satisfies_requirement(&ConcreteVersion::new("1.1.0"), compound));
        assert!(!f.version_satisfies_requirement(&ConcreteVersion::new("2.0.0"), compound));
        assert!(!f.version_satisfies_requirement(&ConcreteVersion::new("0.9.0"), compound));

        // Control: a plain lower bound alone stays unaffected.
        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("5.0.0"), ">=1.0.0"));
        assert!(!f.version_satisfies_requirement(&ConcreteVersion::new("0.5.0"), ">=1.0.0"));
    }

    /// #1603 impl-critic follow-up: the cooldown-fallback safety net
    /// (`ComposerMatcher::explicitly_excludes`) shares `walk_requirement`'s comma split, so a
    /// `!=` clause placed after a comma is now reachable by `ExcludeLeaf` too.
    #[test]
    fn test_composer_explicitly_excludes_reaches_comma_separated_exclusion() {
        assert!(composer_explicitly_excludes(
            "1.5.0",
            ">=1.0.0,!=1.5.0,<2.0.0"
        ));
        assert!(!composer_explicitly_excludes(
            "1.6.0",
            ">=1.0.0,!=1.5.0,<2.0.0"
        ));
    }

    /// #1601: a candidate sitting in the gap between two `||`-branches is explicitly excluded
    /// by the union's shape, mirroring Maven's #1590 disjoint-range gap.
    #[test]
    fn test_composer_explicitly_excludes_detects_or_alternation_gap() {
        assert!(composer_explicitly_excludes(
            "1.5.0",
            ">=1.0 <1.5 || >1.5 <2.0"
        ));
        assert!(!composer_explicitly_excludes(
            "1.2.0",
            ">=1.0 <1.5 || >1.5 <2.0"
        ));
        assert!(!composer_explicitly_excludes(
            "1.8.0",
            ">=1.0 <1.5 || >1.5 <2.0"
        ));
        assert!(!composer_explicitly_excludes(
            "0.5.0",
            ">=1.0 <1.5 || >1.5 <2.0"
        ));
        assert!(!composer_explicitly_excludes(
            "2.5.0",
            ">=1.0 <1.5 || >1.5 <2.0"
        ));
    }

    /// #1601: the same gap, expressed with fully open-ended halves.
    #[test]
    fn test_composer_explicitly_excludes_or_gap_open_ended_halves() {
        assert!(composer_explicitly_excludes("1.5.0", "<1.5 || >1.5 <2.0"));
        assert!(!composer_explicitly_excludes("1.2.0", "<1.5 || >1.5 <2.0"));
        assert!(!composer_explicitly_excludes("1.8.0", "<1.5 || >1.5 <2.0"));
    }

    /// #1601 control: an existing `!=` exclusion inside a single (non-OR) requirement must
    /// remain correct after the OR-gap check is added alongside it.
    #[test]
    fn test_composer_explicitly_excludes_control_ne_exclusion_still_correct() {
        assert!(composer_explicitly_excludes("1.5.0", ">=1.0 !=1.5.0 <2.0"));
        assert!(!composer_explicitly_excludes("1.6.0", ">=1.0 !=1.5.0 <2.0"));
    }

    /// A `||`-branch built from an unrecognized clause shape (caret) contributes no edge, so
    /// a real gap between recognized branches is still detected, and a candidate that would
    /// only be "excluded" via the unrecognized branch's own (unmodeled) shape is never
    /// falsely flagged.
    #[test]
    fn test_composer_explicitly_excludes_or_gap_ignores_unrecognized_branch() {
        // `^3.0` contributes no edge; the gap between `>=1.0 <1.5` and `>1.5 <2.0` is still found.
        assert!(composer_explicitly_excludes(
            "1.5.0",
            ">=1.0 <1.5 || >1.5 <2.0 || ^3.0"
        ));
        // A candidate admitted by the caret branch is covered, so never excluded.
        assert!(!composer_explicitly_excludes(
            "3.2.0",
            ">=1.0 <1.5 || >1.5 <2.0 || ^3.0"
        ));
    }

    /// A single `||`-branch alone has no "other side" to form a gap against.
    #[test]
    fn test_composer_explicitly_excludes_or_gap_requires_at_least_two_branches() {
        assert!(!composer_explicitly_excludes("5.0.0", ">=1.0 <2.0"));
    }

    /// Documents the deliberate scope limit from `clause_bound`'s doc: a union made
    /// *entirely* of caret/tilde branches has no recognized bound anywhere, so
    /// `composer_or_gap_excludes` has no branches left to compare and never fires — this is
    /// always safe (no false exclusion), just a known gap in detection coverage, unlike npm's
    /// `NodeSemverMatcher`, whose probe-based approach handles this same shape (see that
    /// module's own `^1.0.0 || ^3.0.0` regression test).
    #[test]
    fn test_composer_explicitly_excludes_or_gap_all_caret_branches_undetected() {
        assert!(!composer_explicitly_excludes("2.5.0", "^1.0.0 || ^3.0.0"));
    }

    /// impl-critic S1: a real Packagist tag is routinely `v`-prefixed (every `symfony/*`
    /// release), and OR-gap detection must strip it before comparing, exactly like every
    /// other comparison path in this module — without the strip, `v1.5.0` silently failed to
    /// register as excluded while the unprefixed `1.5.0` correctly did.
    #[test]
    fn test_composer_explicitly_excludes_or_gap_strips_v_prefix() {
        let req = ">=1.0 <1.5 || >1.5 <2.0";
        assert!(composer_explicitly_excludes("v1.5.0", req));
        assert!(!composer_explicitly_excludes("v1.2.0", req));
        assert!(!composer_explicitly_excludes("v1.8.0", req));
    }

    /// impl-critic S2: a candidate actually admitted by an unrecognized (caret) branch must
    /// never simultaneously be reported as explicitly excluded by a gap between the OTHER,
    /// recognized branches — `composer_or_gap_excludes`'s up-front real-matcher coverage check
    /// must see every branch, not just the ones with a derivable bound.
    #[test]
    fn test_composer_explicitly_excludes_or_gap_no_contradiction_with_opaque_branch() {
        let f = ComposerFormatter;
        let req = "<1.0 || ^1.5 || >=3.0";
        for candidate in ["1.5.0", "1.5", "1.9.9"] {
            let admitted = f.version_satisfies_requirement(&ConcreteVersion::new(candidate), req);
            let excluded = composer_explicitly_excludes(candidate, req);
            assert!(
                !(admitted && excluded),
                "{candidate}: admitted={admitted} excluded={excluded} must not both be true"
            );
            // `^1.5` genuinely admits all three, so this branch's coverage must win outright.
            assert!(admitted, "{candidate} should be admitted by ^1.5");
            assert!(!excluded, "{candidate} should not be reported excluded");
        }
    }

    /// impl-critic M1: a branch whose own bound is internally unsatisfiable (`>=5.0,<3.0`,
    /// inverted after AND-intersecting its clauses) must not manufacture a fake gap — it
    /// contributes no edge, the same as an unrecognized clause shape.
    #[test]
    fn test_composer_explicitly_excludes_or_gap_ignores_unsatisfiable_branch() {
        assert!(!composer_explicitly_excludes("4.0.0", "^1.0 || >=5.0,<3.0"));
    }

    /// impl-critic M4: two branches touching exactly at a shared inclusive boundary leave no
    /// real gap — the boundary version is genuinely covered by the second branch's inclusive
    /// lower edge, not caught between the two.
    #[test]
    fn test_composer_explicitly_excludes_or_gap_touching_inclusive_boundary_is_covered() {
        assert!(!composer_explicitly_excludes(
            "1.5.0",
            ">=1.0 <1.5 || >=1.5 <2.0"
        ));
    }

    /// Tester follow-up: `clause_bound`'s `<=` branch has no dedicated OR-gap regression test
    /// — the gap sits strictly between an inclusive `<=` upper edge and an exclusive `>` lower
    /// edge on the other branch, and the boundary versions on each side must resolve
    /// correctly (covered vs. excluded).
    #[test]
    fn test_composer_explicitly_excludes_or_gap_le_bound_clause() {
        let req = ">=1.0 <=1.5 || >1.6 <2.0";
        assert!(composer_explicitly_excludes("1.5.5", req));
        assert!(composer_explicitly_excludes("1.6.0", req));
        assert!(!composer_explicitly_excludes("1.2.0", req));
        assert!(!composer_explicitly_excludes("1.6.1", req));
        // Covered by the first branch's inclusive `<=1.5` edge, not a gap.
        assert!(!composer_explicitly_excludes("1.5.0", req));
    }

    /// Tester follow-up: `clause_bound`'s exact `=` branch (a single-point bound) has no
    /// dedicated OR-gap regression test — every version strictly between two exact pins is a
    /// genuine gap, and each pin itself must remain covered, not excluded.
    #[test]
    fn test_composer_explicitly_excludes_or_gap_exact_equals_clause() {
        let req = "=1.0 || =2.0";
        assert!(composer_explicitly_excludes("1.5.0", req));
        assert!(!composer_explicitly_excludes("1.0.0", req));
        assert!(!composer_explicitly_excludes("2.0.0", req));
        // Outside the union's overall span entirely — uncovered, not excluded.
        assert!(!composer_explicitly_excludes("0.5.0", req));
        assert!(!composer_explicitly_excludes("2.5.0", req));
    }

    /// Tester follow-up: `clause_bound`'s wildcard (`.* `) branch and
    /// `increment_last_segment`'s exclusive-upper-edge derivation have no dedicated OR-gap
    /// regression test.
    #[test]
    fn test_composer_explicitly_excludes_or_gap_wildcard_clause() {
        let req = "1.0.* || 1.2.*";
        assert!(composer_explicitly_excludes("1.1.5", req));
        assert!(!composer_explicitly_excludes("1.0.99", req));
        assert!(!composer_explicitly_excludes("1.2.5", req));
        // Outside the union's overall span entirely — uncovered, not excluded.
        assert!(!composer_explicitly_excludes("0.9.0", req));
        assert!(!composer_explicitly_excludes("1.3.0", req));
    }

    /// Code-review finding: a malformed/typo'd wildcard clause whose prefix isn't actually
    /// numeric (`"abc.*"`) must not fabricate a bound by treating `"abc"` as version `0` —
    /// it must contribute no edge, the same as an unrecognized clause shape (caret/tilde/
    /// bare-partial). Before this fix, `composer_explicitly_excludes` wrongly returned `true`
    /// here even though the real matcher agrees `1.0.0` isn't admitted by either branch for
    /// an unrelated reason (no real gap, just plain non-admission).
    #[test]
    fn test_composer_explicitly_excludes_or_gap_ignores_non_numeric_wildcard_prefix() {
        let f = ComposerFormatter;
        let req = "abc.* || >=2.0";
        assert!(!f.version_satisfies_requirement(&ConcreteVersion::new("1.0.0"), req));
        assert!(!composer_explicitly_excludes("1.0.0", req));
    }

    /// Tester follow-up: whitespace surrounding the comma AND-separator (on either side, or
    /// both) must normalize identically to the bare comma form.
    #[test]
    fn test_comma_with_surrounding_whitespace() {
        let f = ComposerFormatter;
        for req in [">=1.0,<2.0", ">=1.0, <2.0", ">=1.0 ,<2.0", ">=1.0 , <2.0"] {
            assert!(
                f.version_satisfies_requirement(&ConcreteVersion::new("1.5.0"), req),
                "{req}"
            );
            assert!(
                !f.version_satisfies_requirement(&ConcreteVersion::new("2.5.0"), req),
                "{req}"
            );
            assert!(
                !f.version_satisfies_requirement(&ConcreteVersion::new("0.5.0"), req),
                "{req}"
            );
        }
    }

    /// impl-critic M4: an AND-group inside one `||`-branch, using the comma form, still
    /// admits/excludes correctly (already passing before this round, now pinned by a test).
    #[test]
    fn test_and_inside_or_with_commas() {
        let f = ComposerFormatter;
        let req = "^0.9 || >=1.0,<2.0,!=1.5.0";
        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("1.6.0"), req));
        assert!(!f.version_satisfies_requirement(&ConcreteVersion::new("1.5.0"), req));
        assert!(!f.version_satisfies_requirement(&ConcreteVersion::new("2.0.0"), req));
    }

    /// impl-critic S3: a whitespace-AND clause list must combine every clause regardless of
    /// operator kind, mirroring the comma form's already-correct behavior — before this fix,
    /// only a group containing a `>`/`<`-prefixed token was split, so `"^1.0 !=1.2.0"`
    /// silently collapsed to just `^1.0` and admitted `1.2.0` anyway.
    #[test]
    fn test_and_split_handles_non_range_operator_tokens() {
        let f = ComposerFormatter;
        assert!(!f.version_satisfies_requirement(&ConcreteVersion::new("1.2.0"), "^1.0 !=1.2.0"));
        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("1.3.0"), "^1.0 !=1.2.0"));
        // Parity with the comma form, which already worked.
        assert!(!f.version_satisfies_requirement(&ConcreteVersion::new("1.2.0"), "^1.0,!=1.2.0"));

        assert!(!f.version_satisfies_requirement(&ConcreteVersion::new("1.0.5"), "~1.0 !=1.0.5"));
        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("1.0.6"), "~1.0 !=1.0.5"));
    }

    /// #1608: composer/semver's Hyphenated Version Range grammar, `"1.0 - 2.0"` ==
    /// `">=1.0.0 <2.1"` (verified against `composer/semver`'s own
    /// `VersionParser::parseConstraints` hyphen-range regex), is now resolved by
    /// `walk_requirement`/`clause_bound` instead of failing closed.
    #[test]
    fn test_hyphen_range_syntax_is_admitted() {
        let f = ComposerFormatter;
        for v in ["1.0.0", "1.5.0", "2.0.0", "2.0.9"] {
            assert!(
                f.version_satisfies_requirement(&ConcreteVersion::new(v), "1.0 - 2.0"),
                "{v} should be admitted by \"1.0 - 2.0\""
            );
        }
        // Below the lower bound, or at/above the exclusive upper bound (`2.1`, not `2.0`).
        for v in ["0.5.0", "2.1.0", "3.0.0"] {
            assert!(
                !f.version_satisfies_requirement(&ConcreteVersion::new(v), "1.0 - 2.0"),
                "{v} should not be admitted by \"1.0 - 2.0\""
            );
        }
    }

    /// #1608: a hyphen embedded in a qualifier suffix directly adjacent to the version text
    /// (`1.0.0-alpha`, no surrounding whitespace) must not be mistaken for the hyphen-range
    /// separator — only a space-hyphen-space (`" - "`) counts.
    #[test]
    fn test_hyphen_range_lower_bound_carries_qualifier_suffix() {
        let f = ComposerFormatter;
        assert!(f.version_satisfies_requirement(
            &ConcreteVersion::new("1.0.0-alpha"),
            "1.0.0-alpha - 2.0.0"
        ));
        assert!(
            !f.version_satisfies_requirement(&ConcreteVersion::new("0.9.0"), "1.0.0-alpha - 2.0.0")
        );
    }

    /// #1608: a plain (non-OR, non-`!=`) hyphen range never itself explicitly excludes a
    /// version — same as any other ordinary range clause.
    #[test]
    fn test_hyphen_range_never_explicitly_excludes_alone() {
        assert!(!composer_explicitly_excludes("1.5.0", "1.0 - 2.0"));
        assert!(!composer_explicitly_excludes("5.0.0", "1.0 - 2.0"));
    }

    /// #1608: two hyphen-range `||`-branches with a real gap between them are detected by the
    /// same OR-alternation-gap check the other clause shapes already exercise.
    #[test]
    fn test_hyphen_range_or_gap_detected() {
        let req = "1.0 - 1.4 || 1.6 - 2.0";
        assert!(composer_explicitly_excludes("1.5.0", req));
        assert!(!composer_explicitly_excludes("1.2.0", req));
        assert!(!composer_explicitly_excludes("1.8.0", req));
        assert!(!composer_explicitly_excludes("0.5.0", req));
        assert!(!composer_explicitly_excludes("2.5.0", req));
    }

    /// #1608: a malformed hyphen-adjacent shape (a second ` - ` landing inside what would be
    /// the upper bound) is not mistaken for a valid range — it falls through to the prior
    /// fail-closed AND-split behavior, same as any other unrecognized shape.
    #[test]
    fn test_hyphen_range_malformed_shape_fails_closed() {
        let f = ComposerFormatter;
        for v in ["1.0.0", "1.5.0", "2.0.0", "3.0.0"] {
            assert!(!f.version_satisfies_requirement(&ConcreteVersion::new(v), "1.0 - 2.0 - 3.0"));
        }
    }

    /// #1609: composer/semver's `VersionParser::parseConstraints` splits OR-branches on
    /// `preg_split('{\s*\|\|?\s*}', ...)`, which accepts a lone `|` exactly like the documented
    /// `||` — `walk_requirement` must treat both identically.
    #[test]
    fn test_single_pipe_or_separator_equivalent_to_double() {
        let f = ComposerFormatter;
        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("1.0.0"), "1.0.0 | 2.0.0"));
        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("2.0.0"), "1.0.0 | 2.0.0"));
        assert!(!f.version_satisfies_requirement(&ConcreteVersion::new("3.0.0"), "1.0.0 | 2.0.0"));
    }

    /// #1609: the OR-alternation-gap check must reach a single-pipe-separated union exactly
    /// like a `||`-separated one.
    #[test]
    fn test_single_pipe_or_gap_detected() {
        let req = ">=1.0 <1.5 | >1.5 <2.0";
        assert!(composer_explicitly_excludes("1.5.0", req));
        assert!(!composer_explicitly_excludes("1.2.0", req));
        assert!(!composer_explicitly_excludes("1.8.0", req));
    }

    #[test]
    fn test_split_or_branches_single_and_double_pipe() {
        assert_eq!(split_or_branches("A || B"), ["A ", " B"]);
        assert_eq!(split_or_branches("A | B"), ["A ", " B"]);
        assert_eq!(split_or_branches("A || B || C"), ["A ", " B ", " C"]);
        // A run of 3+ pipes collapses to a single separator, not multiple empty branches.
        assert_eq!(split_or_branches("A ||| B"), ["A ", " B"]);
        assert_eq!(split_or_branches("A |||| B"), ["A ", " B"]);
    }

    /// impl-critic M1: a degenerate separator shape (two runs with only whitespace between
    /// them, or a trailing run) must produce a genuinely blank segment instead of silently
    /// dropping it — [`has_blank_or_branch`] is what the caller uses to detect and reject it.
    #[test]
    fn test_split_or_branches_blank_segment_from_degenerate_separators() {
        assert!(has_blank_or_branch(&split_or_branches("A || || B")));
        assert!(has_blank_or_branch(&split_or_branches("A ||")));
        assert!(has_blank_or_branch(&split_or_branches("|| A")));
        // A single run (however long) never produces a blank segment on its own.
        assert!(!has_blank_or_branch(&split_or_branches("A |||| B")));
        assert!(!has_blank_or_branch(&split_or_branches("A || B")));
    }

    /// impl-critic M1: the blank-OR-branch shapes above must fail the whole requirement closed
    /// (both admit and explicitly-excludes) rather than being treated as an implicit wildcard
    /// branch.
    #[test]
    fn test_blank_or_branch_fails_requirement_closed() {
        let f = ComposerFormatter;
        for req in ["^1.0 ||", "^1.0 || || ^2.0", "|| ^1.0"] {
            assert!(
                !f.version_satisfies_requirement(&ConcreteVersion::new("9.9.9"), req),
                "{req}"
            );
            assert!(!composer_explicitly_excludes("9.9.9", req), "{req}");
        }
        // A single run of 3+ pipes is not itself a blank-branch shape — still a normal OR.
        assert!(
            f.version_satisfies_requirement(&ConcreteVersion::new("1.0.0"), "1.0.0 |||| 2.0.0")
        );
    }

    #[test]
    fn test_split_hyphen_range_accepts_and_rejects() {
        assert_eq!(split_hyphen_range("1.0 - 2.0"), Some(("1.0", "2.0")));
        assert_eq!(
            split_hyphen_range("1.0.0-alpha - 2.0.0"),
            Some(("1.0.0-alpha", "2.0.0"))
        );
        // impl-critic M2: multiple spaces on either side of the hyphen are still recognized
        // (composer/semver's own grammar is ` +- +`, one or more spaces each side).
        assert_eq!(split_hyphen_range("1.0  -  2.0"), Some(("1.0", "2.0")));
        assert_eq!(split_hyphen_range("1.0 -   2.0"), Some(("1.0", "2.0")));
        // No spaces around the hyphen: a qualifier suffix, not a range.
        assert_eq!(split_hyphen_range("1.0.0-alpha"), None);
        // A third token (whether another `-`-joined segment or an AND-combined clause) is not
        // yet supported — exactly 3 whitespace-separated tokens required (impl-critic M2/D2).
        assert_eq!(split_hyphen_range("1.0 - 2.0 - 3.0"), None);
        assert_eq!(split_hyphen_range("1.0 - 2.0 !=1.4.0"), None);
        assert_eq!(split_hyphen_range("1.0"), None);
        assert_eq!(split_hyphen_range(" - 2.0"), None);
        assert_eq!(split_hyphen_range("1.0 - "), None);
    }

    #[test]
    fn test_has_valid_version_core() {
        assert!(has_valid_version_core("1.0"));
        assert!(has_valid_version_core("1.0.0"));
        assert!(has_valid_version_core("v1.0"));
        assert!(has_valid_version_core("1.0.0-alpha"));
        // impl-critic S1: an operator-prefixed or non-numeric bound must not pass.
        assert!(!has_valid_version_core("^1.0"));
        assert!(!has_valid_version_core(">=1.0"));
        assert!(!has_valid_version_core("abc"));
        assert!(!has_valid_version_core(""));
    }

    /// impl-critic S1: a hyphen range whose `lo` isn't a valid bare version must not silently
    /// become version `0` via `compare_versions`' own `unwrap_or(0)` fallback — the whole
    /// requirement must fail closed instead of admitting everything below `hi`.
    #[test]
    fn test_hyphen_range_invalid_lower_bound_fails_closed() {
        let f = ComposerFormatter;
        for req in ["^1.0 - 2.0", ">=1.0 - 2.0", "abc - 2.0"] {
            assert!(
                !f.version_satisfies_requirement(&ConcreteVersion::new("0.5.0"), req),
                "{req}"
            );
            assert!(
                !f.version_satisfies_requirement(&ConcreteVersion::new("1.9.0"), req),
                "{req}"
            );
        }
    }

    /// impl-critic S2: composer/semver's own docs, `"1.0.0 - 2.1.0"` == `">=1.0.0 <=2.1.0"` —
    /// a "full" (3-segment) `hi` is admitted up to and including itself, unlike the partial
    /// (2-segment) `hi` case, which excludes even a same-core prerelease (see the next test).
    #[test]
    fn test_hyphen_range_full_upper_bound_is_inclusive() {
        let f = ComposerFormatter;
        let req = "1.0.0 - 2.1.0";
        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("2.1.0"), req));
        // A prerelease/finer-grained version at the same numeric core sorts above a bare
        // `<=2.1.0` boundary under `compare_versions`' own qualifier precedence, so it is
        // correctly excluded (this was the exact bug impl-critic S2 found: the old
        // always-exclusive `<2.2` implementation incorrectly admitted both of these).
        assert!(!f.version_satisfies_requirement(&ConcreteVersion::new("2.1.1-RC1"), req));
        assert!(!f.version_satisfies_requirement(&ConcreteVersion::new("2.1.0.1"), req));
    }

    /// impl-critic S2: a "partial" (fewer than 3 numeric segments, no suffix) `hi` widens to a
    /// `-dev`-floored exclusive upper bound, so a same-core prerelease is correctly excluded —
    /// unlike a plain `<incremented` bound, which a prerelease sorts below and would slip
    /// through.
    #[test]
    fn test_hyphen_range_partial_upper_bound_excludes_same_core_prerelease() {
        let f = ComposerFormatter;
        let req = "1.0 - 2.0";
        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("2.0.9"), req));
        assert!(!f.version_satisfies_requirement(&ConcreteVersion::new("2.1.0-beta"), req));
        assert!(!f.version_satisfies_requirement(&ConcreteVersion::new("2.1.0"), req));
    }

    /// impl-critic S2: a `hi` that already carries its own stability suffix is treated as
    /// "full" (inclusive) regardless of its numeric segment count.
    #[test]
    fn test_hyphen_range_qualified_upper_bound_is_inclusive() {
        let f = ComposerFormatter;
        let req = "1.0.0 - 2.0.0-beta";
        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("2.0.0-beta"), req));
        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("1.5.0"), req));
        // A stable release at the same core outranks the `-beta` boundary, so it's excluded.
        assert!(!f.version_satisfies_requirement(&ConcreteVersion::new("2.0.0"), req));
        assert!(!f.version_satisfies_requirement(&ConcreteVersion::new("2.0.1"), req));
    }

    #[test]
    fn test_increment_last_segment() {
        assert_eq!(increment_last_segment("1.0"), Some("1.1".to_string()));
        assert_eq!(increment_last_segment("2"), Some("3".to_string()));
        // Non-numeric segments must not fabricate a `0` bound (#1610).
        assert_eq!(increment_last_segment("abc"), None);
        assert_eq!(increment_last_segment(""), None);
        assert_eq!(increment_last_segment("1.abc"), None);
        // An already-maximal last segment must not saturate to a wrong, collapsed value.
        assert_eq!(increment_last_segment(&format!("1.{}", u64::MAX)), None);
    }

    /// A trailing/bare comma with nothing meaningful on one side must not panic or leave
    /// stray whitespace reaching `eval_leaf` — a dangling comma degrades to whatever real
    /// clause remains (mirrors trimming a trailing separator), not a crash or a corrupted
    /// comparison against a whitespace-padded string.
    #[test]
    fn test_comma_with_trailing_garbage_does_not_panic() {
        let f = ComposerFormatter;
        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("1.0.0"), "1.0.0,"));
        assert!(!f.version_satisfies_requirement(&ConcreteVersion::new("1.0.1"), "1.0.0,"));
        assert!(!f.version_satisfies_requirement(&ConcreteVersion::new("1.0.0"), ","));
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

    /// impl-critic M5 regression: a spaced bare `=` (`"= 1.0.0"`) must still match exactly like
    /// its unspaced form (`"=1.0.0"`, see `test_comparison_operators` above) — #1603's fix made
    /// `walk_requirement`'s AND-split unconditional for any multi-token result, so without
    /// `normalize_operator_spacing` also collapsing whitespace after a bare `=`, this silently
    /// split into a no-op bare `=` clause AND-ed with a bare `"1.0.0"` clause, making the whole
    /// requirement unsatisfiable for every version, including its own exact pin.
    #[test]
    fn test_spaced_bare_equals_operator() {
        let f = ComposerFormatter;
        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("1.0.0"), "= 1.0.0"));
        assert!(!f.version_satisfies_requirement(&ConcreteVersion::new("1.0.1"), "= 1.0.0"));
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
        use deps_core::position::{Position, Range};

        let f = ComposerFormatter;
        let dep = ComposerDependency {
            name: "Symfony/Http-Kernel".into(),
            name_range: Range::new(Position::new(0, 0), Position::new(0, 1)),
            version_req: Some("^4.4".into()),
            version_range: None,
            section: ComposerSection::Require,
            source: deps_core::parser::DependencySource::Registry,
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

    /// #534: an uppercase-`V`-prefixed candidate version (real Packagist tags, e.g.
    /// `jeremykenedy/laravel2step`'s `V3.1.0`/`V4.0.0`) must be stripped identically to a
    /// lowercase `v` prefix, across caret, tilde, comparison-operator, wildcard, and
    /// exact/partial-match branches.
    #[test]
    fn test_uppercase_v_prefix_stripped() {
        let f = ComposerFormatter;
        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("V3.1.0"), "^3.0"));
        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("V1.24.1"), "^1.24"));
        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("V1.2.3"), "~1.2.3"));
        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("V4.0.0"), ">=3.0"));
        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("V1.0.5"), "1.0.*"));
        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("V3.1.0"), "3.1.0"));
        assert!(!f.version_satisfies_requirement(&ConcreteVersion::new("V2.0.0"), "^1.0"));
    }

    /// #534: the requirement side may itself carry an uppercase `V` prefix (bare, or right
    /// after an operator), and either side's case must not affect the result.
    #[test]
    fn test_uppercase_v_prefix_symmetric_on_requirement_side() {
        let f = ComposerFormatter;
        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("1.2.3"), "V1.2.3"));
        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("V1.2.3"), "V1.2.3"));
        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("V1.2.3"), "v1.2.3"));
        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("v1.2.3"), "V1.2.3"));
        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("1.5.0"), "^V1.2.0"));
        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("1.2.9"), "~V1.2.3"));
        assert!(!f.version_satisfies_requirement(&ConcreteVersion::new("2.0.0"), "^V1.2.0"));
        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("1.0.5"), "V1.0.*"));
    }

    /// #534: the wildcard branch with BOTH the candidate version and the requirement
    /// carrying an uppercase `V` prefix simultaneously — existing coverage only exercised
    /// one side at a time.
    #[test]
    fn test_uppercase_v_prefix_wildcard_both_sides() {
        let f = ComposerFormatter;
        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("V1.0.5"), "V1.0.*"));
    }

    /// #534: uppercase-`V` on the plain comparison-operator branches (`>=`, `<=`, `>`, `<`,
    /// `=`, `!=`), mirroring `test_v_prefix_on_comparison_operators` for lowercase `v`.
    #[test]
    fn test_uppercase_v_prefix_on_comparison_operators() {
        let f = ComposerFormatter;
        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("1.5.0"), ">=V1.0.0"));
        assert!(!f.version_satisfies_requirement(&ConcreteVersion::new("0.9.0"), ">=V1.0.0"));
        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("1.5.0"), "<=V2.0.0"));
        assert!(!f.version_satisfies_requirement(&ConcreteVersion::new("2.5.0"), "<V2.0.0"));
        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("2.0.1"), ">V2.0.0"));
        assert!(f.version_satisfies_requirement(&ConcreteVersion::new("2.0.0"), "=V2.0.0"));
        assert!(!f.version_satisfies_requirement(&ConcreteVersion::new("2.0.0"), "!=V2.0.0"));
    }

    /// #534: a bare uppercase `"V"` requirement must fall through to exact/partial match
    /// unchanged, not collapse to `""` and be swallowed by the empty/wildcard guard —
    /// mirrors `test_bare_v_requirement_does_not_match_everything` for the lowercase case.
    #[test]
    fn test_bare_uppercase_v_requirement_does_not_match_everything() {
        let f = ComposerFormatter;
        assert!(!f.version_satisfies_requirement(&ConcreteVersion::new("1.2.3"), "V"));
        assert!(!f.version_satisfies_requirement(&ConcreteVersion::new("0.0.0"), "V"));
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
        assert_eq!(
            strip_stability_flag("^1.0@beta"),
            ("^1.0", Some(StabilityFloor::Beta))
        );
        assert_eq!(
            strip_stability_flag("^1.0@BETA"),
            ("^1.0", Some(StabilityFloor::Beta))
        );
        assert_eq!(
            strip_stability_flag("1.0.*@dev"),
            ("1.0.*", Some(StabilityFloor::Dev))
        );
        assert_eq!(
            strip_stability_flag("2.0@RC"),
            ("2.0", Some(StabilityFloor::Rc))
        );
        assert_eq!(
            strip_stability_flag("2.0@alpha"),
            ("2.0", Some(StabilityFloor::Alpha))
        );
        assert_eq!(
            strip_stability_flag("2.0@stable"),
            ("2.0", Some(StabilityFloor::Stable))
        );
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

    /// #424: `composer_version_stability` classifies a version's own qualifier on the same
    /// `dev < alpha < beta < RC < stable` scale as [`qualifier_stability`], agreeing with
    /// `compare_versions`'s qualifier ordering (`test_compare_versions_qualifier_ordering`).
    #[test]
    fn test_composer_version_stability_orders_qualifiers() {
        assert_eq!(composer_version_stability("1.0.0-dev"), StabilityFloor::Dev);
        assert_eq!(
            composer_version_stability("1.0.0-alpha1"),
            StabilityFloor::Alpha
        );
        assert_eq!(
            composer_version_stability("1.0.0-beta1"),
            StabilityFloor::Beta
        );
        assert_eq!(composer_version_stability("1.0.0-RC1"), StabilityFloor::Rc);
        assert_eq!(composer_version_stability("1.0.0"), StabilityFloor::Stable);
    }

    /// #424 S3: a separator-less suffix classifies identically to its hyphenated form — the
    /// same qualifier parser (`split_composer_core_and_suffix`) backs both.
    #[test]
    fn test_composer_version_stability_separatorless_suffix() {
        assert_eq!(
            composer_version_stability("2.0.0RC1"),
            composer_version_stability("2.0.0-RC1"),
        );
    }

    /// #424 critique C1 (CRITICAL regression): a `v`-prefixed prerelease (e.g. every
    /// `symfony/*`/`sylius/sylius` release) must still rank below `StabilityFloor::Stable` —
    /// before the fix, the leading `v`/`V` was consumed as the qualifier "word" itself,
    /// which the classifier cannot recognize and silently ranks as stable, reopening #422 for
    /// any package whose newest release is `v`-prefixed.
    #[test]
    fn test_composer_version_stability_strips_v_prefix() {
        for prerelease in [
            "v2.3.0-alpha.1",
            "v6.0.0-BETA1",
            "v2.0.0-alpha1",
            "V3.0.0-RC1",
        ] {
            assert!(
                composer_version_stability(prerelease) < StabilityFloor::Stable,
                "{prerelease:?} must rank below stable, not be swallowed as an unrecognized qualifier word"
            );
        }
    }

    /// #424 critique C1: a `v`-prefixed prerelease must rank strictly below a `v`-prefixed
    /// (or plain) stable release of the same series, matching the real Packagist ordering
    /// `sylius/sylius`'s `v2.3.0-alpha.1` vs. `v2.2.8` regressed on.
    #[test]
    fn test_composer_version_stability_v_prefixed_prerelease_below_stable() {
        assert!(
            composer_version_stability("v2.3.0-alpha.1") < composer_version_stability("v2.2.8")
        );
        assert!(composer_version_stability("v2.3.0-alpha.1") < composer_version_stability("2.3.0"));
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

    // --- #1373: self.version / inline-alias guard ---

    #[test]
    fn test_requirement_is_composer_unresolved_self_version() {
        assert!(requirement_is_composer_unresolved("self.version"));
        assert!(requirement_is_composer_unresolved("  self.version  "));
    }

    #[test]
    fn test_requirement_is_composer_unresolved_inline_alias() {
        assert!(requirement_is_composer_unresolved("dev-main as 1.0.0"));
        assert!(requirement_is_composer_unresolved("1.0.x-dev as 1.0.0"));
        assert!(requirement_is_composer_unresolved("^1.0 as 2.0"));
    }

    /// #1374 impl-critic M2: an unexpanded `$VAR`/`${VAR}` external-templating placeholder,
    /// anywhere in the requirement text, must be caught the same way npm/Cargo/Dart's own
    /// `requirement_contains_template_placeholder`-based guards catch it.
    #[test]
    fn test_requirement_is_composer_unresolved_dollar_placeholder() {
        assert!(requirement_is_composer_unresolved("${PSR_LOG}"));
        assert!(requirement_is_composer_unresolved("$PSR_LOG"));
        assert!(requirement_is_composer_unresolved("^1.0.0-$BUILD"));
    }

    /// A hyphenated branch/package token containing `as` with no surrounding whitespace
    /// must not false-positive against the inline-alias substring check.
    #[test]
    fn test_requirement_is_composer_unresolved_false_for_ordinary_requirements() {
        assert!(!requirement_is_composer_unresolved("^1.2"));
        assert!(!requirement_is_composer_unresolved("dev-feature-as-x"));
        assert!(!requirement_is_composer_unresolved("dev-master"));
        assert!(!requirement_is_composer_unresolved(""));
    }

    #[test]
    fn test_requirement_is_unresolved_trait_matches_free_function() {
        let f = ComposerFormatter;
        assert!(f.requirement_is_unresolved(&VersionReq::new("self.version")));
        assert!(f.requirement_is_unresolved(&VersionReq::new("dev-main as 1.0.0")));
        assert!(f.requirement_is_unresolved(&VersionReq::new("${PSR_LOG}")));
        assert!(!f.requirement_is_unresolved(&VersionReq::new("^1.2")));
    }

    /// A minimal [`ComposerDependency`] for probing [`deps_core::edit::replacement_text`]
    /// directly — its identity is irrelevant to the placeholder gate, which checks
    /// `current`/`version_literal()` only.
    fn placeholder_probe_dependency() -> ComposerDependency {
        ComposerDependency {
            name: PackageName::new("vendor/probe"),
            name_range: Range::default(),
            version_req: None,
            version_range: None,
            section: ComposerSection::Require,
            source: deps_core::parser::DependencySource::Registry,
        }
    }

    #[test]
    fn test_replacement_text_self_version_is_none() {
        use deps_core::edit::replacement_text;

        let f = ComposerFormatter;
        let dep = placeholder_probe_dependency();
        assert_eq!(
            replacement_text(&f, &dep, &ConcreteVersion::new("3.12.0"), "self.version"),
            None
        );
    }

    #[test]
    fn test_replacement_text_inline_alias_is_none() {
        use deps_core::edit::replacement_text;

        let f = ComposerFormatter;
        let dep = placeholder_probe_dependency();
        assert_eq!(
            replacement_text(
                &f,
                &dep,
                &ConcreteVersion::new("1.0.0"),
                "dev-main as 1.0.0"
            ),
            None
        );
    }

    #[test]
    fn test_replacement_text_dollar_placeholder_is_none() {
        use deps_core::edit::replacement_text;

        let f = ComposerFormatter;
        let dep = placeholder_probe_dependency();
        assert_eq!(
            replacement_text(&f, &dep, &ConcreteVersion::new("3.0.2"), "${PSR_LOG}"),
            None
        );
    }

    /// Positive control: an ordinary, resolved requirement must still be rewritten — the
    /// guard must not over-broadly suppress legitimate fixes.
    #[test]
    fn test_format_version_replacing_resolved_requirement_still_rewritten() {
        let f = ComposerFormatter;
        assert_eq!(
            f.format_version_replacing(&ConcreteVersion::new("1.2.0"), "^1.0"),
            "1.2.0"
        );
    }

    #[test]
    fn test_compile_requirement_self_version_returns_none() {
        let f = ComposerFormatter;
        assert!(
            f.compile_requirement(&VersionReq::new("self.version"))
                .is_none()
        );
    }

    #[test]
    fn test_compile_requirement_inline_alias_returns_none() {
        let f = ComposerFormatter;
        assert!(
            f.compile_requirement(&VersionReq::new("dev-main as 1.0.0"))
                .is_none()
        );
    }

    #[test]
    fn test_compile_requirement_dollar_placeholder_returns_none() {
        let f = ComposerFormatter;
        assert!(
            f.compile_requirement(&VersionReq::new("${PSR_LOG}"))
                .is_none()
        );
    }

    /// #1373: `self.version` must never be reported as an unsatisfiable requirement — it
    /// is resolved entirely by Composer's own installer, not by any published version.
    #[test]
    fn test_requirement_is_unsatisfiable_self_version_suppressed() {
        use deps_core::lsp_helpers::requirement_is_unsatisfiable;
        let f = ComposerFormatter;
        let available = vec![ConcreteVersion::new("1.0.0"), ConcreteVersion::new("2.0.0")];
        assert!(!requirement_is_unsatisfiable(
            &f,
            &VersionReq::new("self.version"),
            &available
        ));
    }

    #[test]
    fn test_requirement_is_unsatisfiable_inline_alias_suppressed() {
        use deps_core::lsp_helpers::requirement_is_unsatisfiable;
        let f = ComposerFormatter;
        let available = vec![ConcreteVersion::new("1.0.0"), ConcreteVersion::new("2.0.0")];
        assert!(!requirement_is_unsatisfiable(
            &f,
            &VersionReq::new("dev-main as 1.0.0"),
            &available
        ));
    }

    #[test]
    fn test_requirement_is_unsatisfiable_dollar_placeholder_suppressed() {
        use deps_core::lsp_helpers::requirement_is_unsatisfiable;
        let f = ComposerFormatter;
        let available = vec![ConcreteVersion::new("1.0.0"), ConcreteVersion::new("2.0.0")];
        assert!(!requirement_is_unsatisfiable(
            &f,
            &VersionReq::new("${PSR_LOG}"),
            &available
        ));
    }

    fn vuln_fix_dv(fixed_version: &str) -> deps_core::osv::DependencyVulnerabilities {
        use deps_core::osv::{
            Advisory, Capped, DependencyVulnerabilities, OsvVersion, UpgradeStatus, VulnSeverity,
        };
        use std::sync::Arc;

        let advisory = Arc::new(
            Advisory::new(
                "GHSA-0000-0000-0000".to_string(),
                "2024-01-01T00:00:00Z".to_string(),
                VulnSeverity::High,
            )
            .expect("valid osv id")
            .with_fixed_versions(vec![OsvVersion::new(fixed_version)]),
        );
        DependencyVulnerabilities::new(Capped::new(vec![advisory], 1)).with_fix_target_status(
            UpgradeStatus::CandidateClean {
                version: fixed_version.to_string(),
            },
        )
    }

    /// #1373/#1370 end-to-end regression: `plan_vulnerability_fix` must never rewrite
    /// `self.version` to a literal fix version — `ComposerFormatter::requirement_is_placeholder`'s
    /// central gate (consulted via `deps_core::edit::requirement_is_placeholder_for`) fires
    /// first and short-circuits to `UnresolvedPlaceholder`, before `format_version_replacing`
    /// is ever reached (#1391: that method no longer guards placeholders itself).
    #[test]
    fn test_plan_vulnerability_fix_self_version_is_not_rewritten() {
        use deps_core::edit::plan_vulnerability_fix;
        use deps_core::position::{Position, Range};

        let version_range = Range::new(Position::new(0, 20), Position::new(0, 33));
        let dep = ComposerDependency {
            name: "monolog/monolog".into(),
            name_range: Range::default(),
            version_req: Some("self.version".into()),
            version_range: Some(version_range),
            section: ComposerSection::Require,
            source: deps_core::parser::DependencySource::Registry,
        };

        let dv = vuln_fix_dv("3.12.0");
        assert_eq!(
            plan_vulnerability_fix(
                &dep,
                version_range,
                "self.version",
                &dv,
                None,
                &ComposerFormatter
            ),
            Err(deps_core::edit::VulnFixSkip::UnresolvedPlaceholder),
            "self.version must never be overwritten with a literal fix version"
        );
    }

    /// #1373 end-to-end regression: `plan_vulnerability_fix` must never rewrite an inline
    /// alias to a literal fix version.
    #[test]
    fn test_plan_vulnerability_fix_inline_alias_is_not_rewritten() {
        use deps_core::edit::plan_vulnerability_fix;
        use deps_core::position::{Position, Range};

        let version_range = Range::new(Position::new(0, 20), Position::new(0, 38));
        let dep = ComposerDependency {
            name: "symfony/console".into(),
            name_range: Range::default(),
            version_req: Some("dev-main as 1.0.0".into()),
            version_range: Some(version_range),
            section: ComposerSection::Require,
            source: deps_core::parser::DependencySource::Registry,
        };

        let dv = vuln_fix_dv("1.0.0");
        assert_eq!(
            plan_vulnerability_fix(
                &dep,
                version_range,
                "dev-main as 1.0.0",
                &dv,
                None,
                &ComposerFormatter
            ),
            Err(deps_core::edit::VulnFixSkip::UnresolvedPlaceholder),
            "an inline alias must never be overwritten with a literal fix version"
        );
    }

    /// #1374 impl-critic M2 end-to-end regression: `plan_vulnerability_fix` must never
    /// rewrite an unexpanded `${VAR}` external-templating placeholder to a literal fix
    /// version — this is the exact shape `deps-cli update --dry-run` was observed live
    /// rewriting (`"psr/log": "${PSR_LOG}"` -> `"psr/log": "3.0.2"`) before this guard.
    #[test]
    fn test_plan_vulnerability_fix_dollar_placeholder_is_not_rewritten() {
        use deps_core::edit::plan_vulnerability_fix;
        use deps_core::position::{Position, Range};

        let version_range = Range::new(Position::new(0, 20), Position::new(0, 30));
        let dep = ComposerDependency {
            name: "psr/log".into(),
            name_range: Range::default(),
            version_req: Some("${PSR_LOG}".into()),
            version_range: Some(version_range),
            section: ComposerSection::Require,
            source: deps_core::parser::DependencySource::Registry,
        };

        let dv = vuln_fix_dv("3.0.2");
        assert_eq!(
            plan_vulnerability_fix(
                &dep,
                version_range,
                "${PSR_LOG}",
                &dv,
                None,
                &ComposerFormatter
            ),
            Err(deps_core::edit::VulnFixSkip::UnresolvedPlaceholder),
            "an unexpanded ${{VAR}} placeholder must never be overwritten with a literal fix \
             version"
        );
    }

    /// Positive control: a resolved, well-formed requirement on the same dependency shape
    /// must still be rewritten. Uses an exact pin (not a `^`/`~` range) so the fix target
    /// does not already satisfy `current` — otherwise `requirement_already_resolves_to`
    /// would itself skip the edit as unnecessary, for an unrelated reason.
    #[test]
    fn test_plan_vulnerability_fix_resolved_requirement_still_returns_planned_edit() {
        use deps_core::edit::plan_vulnerability_fix;
        use deps_core::position::{Position, Range};

        let version_range = Range::new(Position::new(0, 20), Position::new(0, 25));
        let dep = ComposerDependency {
            name: "guzzlehttp/guzzle".into(),
            name_range: Range::default(),
            version_req: Some("6.0.0".into()),
            version_range: Some(version_range),
            section: ComposerSection::Require,
            source: deps_core::parser::DependencySource::Registry,
        };

        let dv = vuln_fix_dv("6.5.0");
        let planned =
            plan_vulnerability_fix(&dep, version_range, "6.0.0", &dv, None, &ComposerFormatter)
                .expect("a resolved requirement must still be rewritten to the fix version");
        assert_eq!(planned.edit.new_text, "6.5.0");
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
        let dep = ComposerDependency {
            name: "vendor/package".into(),
            name_range: Range::default(),
            version_req: Some("^1.0".into()),
            version_range: Some(Range::new(
                DomainPosition::new(1, 20),
                DomainPosition::new(1, 25),
            )),
            section: ComposerSection::Require,
            source: deps_core::parser::DependencySource::Registry,
        };

        let f = ComposerFormatter;
        assert!(
            !f.is_position_on_dependency(&dep, DomainPosition::new(0, 0)),
            "a degenerate name_range must never be selectable, even at its own (0,0) span"
        );
        // The version range still works normally.
        assert!(f.is_position_on_dependency(&dep, DomainPosition::new(1, 22)));
    }

    /// The override still widens discoverability for a real (non-degenerate) name
    /// range — the whole point of overriding the shared default.
    #[test]
    fn test_is_position_on_dependency_accepts_real_name_range() {
        let dep = ComposerDependency {
            name: "vendor/package".into(),
            name_range: Range::new(DomainPosition::new(1, 4), DomainPosition::new(1, 20)),
            version_req: Some("^1.0".into()),
            version_range: Some(Range::new(
                DomainPosition::new(1, 23),
                DomainPosition::new(1, 28),
            )),
            section: ComposerSection::Require,
            source: deps_core::parser::DependencySource::Registry,
        };

        let f = ComposerFormatter;
        assert!(f.is_position_on_dependency(&dep, DomainPosition::new(1, 10)));
    }

    /// T1 (D7(a)/C2): a Composer manifest with a legal escaped-solidus `"vendor\/package"`
    /// key must never offer a "Replace with X" rename action, rather than emitting a
    /// corrupting edit.
    ///
    /// #613: positions now come directly from the jsonc-parser AST, which correctly
    /// locates the escaped-solidus key's real span — unlike the pre-#613 literal-text
    /// search for the serde-unescaped `"vendor/package"`, which never matched it and left
    /// both `name_range` and `version_range` at their sentinel defaults. The *no rename
    /// action* guarantee no longer depends on that miss: it now holds because
    /// `build_replacement_action` slices `name_range` back out of `content` and compares
    /// it against the dependency's *unescaped* semantic name — the raw literal slice
    /// (`vendor\/package`, escape included) never textually equals the unescaped name
    /// (`vendor/package`), so the rename action is still correctly withheld.
    ///
    /// Exercised two ways: end to end through the real parser (today's actual behavior),
    /// and directly against `name_literal_guard`-shaped input (`version_range: Some(..)`,
    /// `name_range: Range::default()`) so the test still catches a regression if a future
    /// parser change ever reintroduces a degenerate `name_range`.
    #[cfg(feature = "lsp-responses")]
    #[tokio::test]
    async fn test_generate_code_actions_escaped_solidus_name_offers_no_rename_action() {
        let json = r#"{"require": {"vendor\/package": "^1.0"}}"#;
        let uri = deps_core::test_util::test_uri("/test/composer.json");
        let parse_result = crate::parser::parse_composer_json(json, &uri).unwrap();
        assert_eq!(parse_result.dependencies.len(), 1);
        let dep = &parse_result.dependencies[0];
        assert_ne!(
            dep.name_range,
            Range::default(),
            "AST-derived positions must locate the escaped-solidus key's real span"
        );
        assert!(
            dep.version_range.is_some(),
            "AST-derived positions must find the version literal too, decoupled from the \
             name lookup"
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
            "no rename action may be offered when the raw literal span (with its escape) \
             does not match the unescaped semantic name: {actions:?}"
        );

        // Direct regression guard for the guard mechanism itself (not just today's
        // incidental version_range coupling): a hand-built dependency with a valid
        // version_range but a degenerate name_range must still be rejected.
        let corrupted_dep = ComposerDependency {
            name: "vendor/package".into(),
            name_range: Range::default(),
            version_req: Some("^1.0".into()),
            version_range: Some(Range::new(
                DomainPosition::new(0, 33),
                DomainPosition::new(0, 37),
            )),
            section: ComposerSection::Require,
            source: deps_core::parser::DependencySource::Registry,
        };
        let corrupted_result = crate::parser::ComposerParseResult {
            dependencies: vec![corrupted_dep],
            uri: uri.clone(),
            minimum_stability: crate::parser::MinimumStability::Absent,
            dependency_truncation: None,
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
    #[cfg(feature = "lsp-responses")]
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
            version_range.start.into(),
            &uri,
            versions,
            json,
            &NoNetworkRegistry,
            &ComposerFormatter,
        )
        .await;

        let ls_uri = deps_core::to_ls_uri(&uri);
        let rename = actions
            .iter()
            .find(|a| a.title == "Replace with other/package")
            .unwrap_or_else(|| panic!("expected a rename action, got: {actions:?}"));
        let edits = rename
            .edit
            .as_ref()
            .and_then(|e| e.changes.as_ref())
            .and_then(|c| c.get(&ls_uri))
            .expect("rename action must carry a WorkspaceEdit for this URI");
        assert_eq!(edits.len(), 1);
        assert_eq!(edits[0].range, dep.name_range.into());
        assert_eq!(edits[0].new_text, "other/package");
    }

    /// No-op [`deps_core::Registry`] so #205 code-action tests never hit the network —
    /// `generate_code_actions` calls `registry.get_versions` unconditionally after the
    /// registry-independent fix/rename actions are built.
    #[cfg(feature = "lsp-responses")]
    struct NoNetworkRegistry;

    #[cfg(feature = "lsp-responses")]
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
            _selection_context: &'a deps_core::SelectionContext,
        ) -> deps_core::ecosystem::BoxFuture<
            'a,
            deps_core::Result<Option<Box<dyn deps_core::Version>>>,
        > {
            Box::pin(async move { Ok(None) })
        }

        fn search_raw<'a>(
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
