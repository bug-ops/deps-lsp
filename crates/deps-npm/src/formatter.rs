use deps_core::lsp_helpers::{
    DiagnosticMessages, DiagnosticPolicy, OsvNaming, PackageNaming, PackageRendering,
    RequirementMatcher, RequirementResolution, SourcePolicy,
};
use deps_core::{ConcreteVersion, Dependency, InvalidPackageName, PackageName, VersionReq};
use std::borrow::Cow;

/// Failure from [`parse_range_safe`]: either `node_semver`'s own parse rejection, or the
/// parser panicking instead of returning one.
#[derive(Debug, thiserror::Error)]
pub enum RangeParseError {
    /// `node_semver::Range::parse` returned `Err` normally.
    #[error(transparent)]
    Malformed(#[from] node_semver::SemverError),
    /// `node_semver::Range::parse` panicked instead of returning `Err` (#1630: certain
    /// short, well-formed-looking inputs, e.g. `"~*"`, hit an internal `unreachable!()` in
    /// `node_semver` 2.2.0's range-parsing state machine).
    #[error("node_semver panicked while parsing a range")]
    Panicked,
}

/// Whether a version component (as split on `.`) is a wildcard token (`x`/`X`/`*`) or a
/// clean, fully-numeric value (see [`is_clean_numeral`]). The *last* component tolerates a
/// trailing `-prerelease` suffix on the *wildcard* token too (e.g. `"x-beta"` from
/// `"=x.x.x-beta"`, #1646) — real npm still
/// resolves a fully-wildcard component set with a prerelease tag on the last component to
/// "any version" (live-verified). This tolerance is deliberately restricted to the last
/// component: `"~1.x-beta.3"` is not valid npm range grammar (a prerelease suffix belongs
/// only on the version's final component, confirmed live to be a real npm parse error, #1646
/// impl-critic M2) and must not be silently accepted as a wildcard middle component. `None`
/// covers anything else (e.g. empty, or otherwise malformed) — [`classify_token_shape`]
/// treats that as "can't tell" rather than guessing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VersionComponentKind {
    Wildcard,
    Concrete,
}

/// Whether `part` is a clean, fully-numeric version component — nothing but ASCII digits,
/// no suffix of any kind. Deliberately stricter than a `starts_with` prefix check (a prior
/// version of this classifier used that looser check and, once shape 3's `TildeWildcardPatch`
/// rewrite started treating a `Concrete` match as "safe to substitute", it let a malformed or
/// suffixed trailing component — `"3-alpha"`, `"3+build"`, `"3abc"`, or `"3.4"` folded into
/// one component by `splitn(3, '.')` — silently misclassify as a clean patch number and get
/// rewritten away, discarding the differentiating suffix instead of erroring, #1646
/// code-review finding). All four of those shapes are confirmed live to panic
/// `node_semver::Range::parse` outright, same as a genuine `~1.x.3` — they must fall through
/// to the safe `catch_unwind` backstop, not be misclassified as `Concrete`.
fn is_clean_numeral(part: &str) -> bool {
    !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit())
}

/// Classifies up to the first 3 dot-separated components of a partial-version-shaped
/// substring (e.g. `"1.x.3-beta"` from `"~1.x.3-beta"`, taken after stripping the `~`/`~>`/`=`
/// operator). Returns `None` for any component that is neither a wildcard token (a trailing
/// `-prerelease` suffix is only tolerated on the *last* component's wildcard check, see
/// [`VersionComponentKind`] — this tolerance does not extend to the `Concrete` check, see
/// [`is_clean_numeral`]) nor a clean, fully-numeric value, so [`classify_token_shape`] can
/// fall back to `catch_unwind` instead of guessing.
fn partial_version_components(version: &str) -> Option<Vec<VersionComponentKind>> {
    let parts: Vec<&str> = version.splitn(3, '.').collect();
    let last_index = parts.len() - 1;
    parts
        .iter()
        .enumerate()
        .map(|(index, part)| {
            let wildcard_token = if index == last_index {
                part.split('-').next().unwrap_or(part)
            } else {
                *part
            };
            if matches!(wildcard_token, "x" | "X" | "*") {
                Some(VersionComponentKind::Wildcard)
            } else if is_clean_numeral(part) {
                Some(VersionComponentKind::Concrete)
            } else {
                None
            }
        })
        .collect()
}

/// Re-merges a bare `~`/`~>`/`=` operator token with the token immediately following it.
/// `node_semver`-compatible tooling binds internal whitespace right after these operators to
/// the same comparator (`"~ *"` behaves as `"~*"` — verified live against npm's own `semver`
/// package for #1646), but naive whitespace-splitting tokenization otherwise treats them as
/// two independent AND'd tokens, which neither [`classify_token_shape`] recognizes nor
/// `node_semver` can parse (both halves fail: `"~"` alone and `"*"` alone).
///
/// Borrows every token unchanged (`Cow::Borrowed`) and only allocates for the merged pair
/// itself — this runs on every [`parse_range_safe`] call, most of which see an ordinary
/// requirement with nothing to merge, so the common case stays allocation-free (#1646
/// code-review perf note).
fn merge_bare_operator_tokens<'a>(tokens: impl Iterator<Item = &'a str>) -> Vec<Cow<'a, str>> {
    let mut merged = Vec::new();
    let mut pending_operator = None;
    for token in tokens {
        if let Some(operator) = pending_operator.take() {
            merged.push(Cow::Owned(format!("{operator}{token}")));
        } else if matches!(token, "~" | "~>" | "=") {
            pending_operator = Some(token);
        } else {
            merged.push(Cow::Borrowed(token));
        }
    }
    merged.extend(pending_operator.map(Cow::Borrowed));
    merged
}

/// Outcome of [`classify_token_shape`] for a single whitespace-delimited comparator token
/// known to hit one of `node_semver` 2.2.0's `unreachable!()` panics (#1630).
enum TokenShape {
    /// No real narrower value exists to substitute — matches everything (wildcard major, e.g.
    /// `~*`, `~>*`, `=x.x.x-beta`). Rewritten to a bare `*` before re-parsing, which is
    /// `node_semver`'s own always-parseable "any version" token.
    Unresolvable,
    /// Concrete-wildcard-concrete tilde (`~1.x.3`, `~>1.x.3`, #1646): unlike `Unresolvable`,
    /// this has a precise real equivalent, since a wildcard minor already makes the trailing
    /// concrete patch irrelevant to the resulting bound — `~1.x.3` and `~1.x` share the same
    /// npm-verified bound (`>=1.0.0 <2.0.0-0`), and `~>` is npm's own documented synonym for
    /// `~` (live-verified: `~>1.x.3` resolves identically to `~1.x.3`, #1646 impl-critic S1 —
    /// treating it as `Unresolvable` instead would silently substitute "any version" for a
    /// narrower real bound, a *wrong* answer, strictly worse than the pre-#1646 safe `Err`).
    /// Rewritten to `~{major}.x` before re-parsing, dropping the `~>`/`~` distinction since
    /// npm doesn't make one for this shape either.
    TildeWildcardPatch { major: String },
}

/// Classifies a single, already-merged (see [`merge_bare_operator_tokens`]) comparator token
/// against the `node_semver` 2.2.0 `unreachable!()` panic shapes reachable from user input
/// (#1630, confirmed by reading `node_semver`'s own tilde/equals match arms in `range.rs`):
/// a tilde token (plain or `~>` — npm treats them as synonyms) whose partial version has a
/// wildcard major, regardless of trailing components (`~*`, `~x.2.3`, ...) — npm resolves all
/// of these to "any version" (live-verified, #1639); a tilde token whose minor is a wildcard
/// while its patch is concrete (`~1.x.3`, `~>1.x.3`, #1646); or an equals token whose *every*
/// present component is a wildcard (`~x`, `=x.x.x`, `=X.x`, #1639 — unlike tilde, an equals
/// token with a wildcard major but any concrete trailing component, e.g. `=x.2.3`, is a genuine
/// npm parse error, not "any version": live-verified against npm's own `semver` package).
///
/// Returns `None` for anything this can't classify, so [`parse_range_safe`] falls back to
/// `catch_unwind` instead of guessing. Mirrors the `deps-pypi`/`pep508_rs` precedent's shape: a
/// cheap pre-check that keeps the common cases off the panic-unwind-log path, not a full
/// grammar re-implementation — caret (`^`) ranges are not checked here since `node_semver`'s
/// caret match arms have no equivalent gap. Must never return `Some` for a token `node_semver`
/// can actually parse as-is (a false positive would silently rewrite valid input), and for
/// `Unresolvable` specifically — rewritten to `*` and re-parsed rather than rejecting the whole
/// requirement outright, see [`parse_range_safe`] — must never return `Some(Unresolvable)` for
/// a shape that actually has a narrower real bound (that would silently produce a wrong,
/// overly permissive answer instead of a safe `Err`).
fn classify_token_shape(token: &str) -> Option<TokenShape> {
    if let Some(rest) = token.strip_prefix("~>").or_else(|| token.strip_prefix('~')) {
        let unprefixed = rest.strip_prefix('v').unwrap_or(rest);
        if let Some(comps) = partial_version_components(unprefixed)
            && comps.first() == Some(&VersionComponentKind::Wildcard)
        {
            return Some(TokenShape::Unresolvable);
        }
        let comps = partial_version_components(rest)?;
        if matches!(
            comps.as_slice(),
            [
                VersionComponentKind::Concrete,
                VersionComponentKind::Wildcard,
                VersionComponentKind::Concrete
            ]
        ) {
            return Some(TokenShape::TildeWildcardPatch {
                major: rest.split('.').next()?.to_string(),
            });
        }
        return None;
    }
    if let Some(rest) = token.strip_prefix('=') {
        let unprefixed = rest.strip_prefix('v').unwrap_or(rest);
        let comps = partial_version_components(unprefixed)?;
        if comps
            .iter()
            .all(|comp| *comp == VersionComponentKind::Wildcard)
        {
            return Some(TokenShape::Unresolvable);
        }
    }
    None
}

/// Panic-safe wrapper around [`node_semver::Range::parse`].
///
/// `node_semver` 2.2.0 has a reachable `unreachable!()` panic (#1630) for certain short
/// npm range strings instead of returning `Err`, which would otherwise crash the LSP
/// request handling this feeds (hover/completion/diagnostics/inlay hints all resolve
/// dependency requirements through it). Every `node_semver::Range::parse` call in
/// `deps-npm` and `deps-deno` (which delegates its own `npm:`/`jsr:` range parsing here)
/// must route through this wrapper instead of calling `node_semver::Range::parse`
/// directly.
///
/// `classify_token_shape` rejects/rewrites the known panic shapes upfront so the panic
/// path stays a rare backstop rather than the common path for these inputs (avoids a
/// `thread ... panicked at ...` block on stderr, plus a full backtrace under
/// `RUST_BACKTRACE=1`, on every re-diagnose of a manifest containing one) — mirrors why the
/// `deps-pypi`/`pep508_rs` precedent pre-validates before its own `catch_unwind` backstop.
///
/// A bare wildcard-major comparator (`~*`, `=x.x.x`, ...) has no narrower real value to
/// substitute, so it's rewritten to a bare `*` (`node_semver`'s own always-parseable "any
/// version" token) and re-parsed — whether it's the whole requirement on its own (#1639) or
/// combined with another comparator via `||`/whitespace (`*` doesn't narrow an AND'd
/// comparator's bound, and unions to "any version" across `||` — live-verified for #1646),
/// e.g. `"^1.0.0 ~*"` resolves to `^1.0.0`'s own bound rather than failing. `~1.x.3`/`~>1.x.3`
/// (#1646) are unconditionally rewritten to their real bound-equivalent `~1.x` instead — see
/// `TokenShape::TildeWildcardPatch`.
///
/// # Errors
///
/// Returns [`RangeParseError::Malformed`] for an ordinary unparseable range, and
/// [`RangeParseError::Panicked`] when `node_semver` panics (or would panic, per the
/// pre-check above) instead — both are `Err`, so a caller that already treats a malformed
/// range as "unresolved"/"no match" needs no separate panic branch of its own.
///
/// # Examples
///
/// ```
/// use deps_npm::parse_range_safe;
///
/// assert!(parse_range_safe("^1.0.0").is_ok());
/// assert!(parse_range_safe("not a range").is_err());
/// // Previously panicked (#1630), then a safe-but-wrong `Err` (npm actually resolves this to
/// // "any version"); now correctly `Ok` (#1639).
/// assert!(parse_range_safe("~*").is_ok());
/// // #1639: unlike tilde, an equals wildcard-major with any concrete trailing component is a
/// // genuine npm parse error, not "any version" (live-verified against npm's own `semver`).
/// assert!(parse_range_safe("=x.2.3").is_err());
/// assert!(parse_range_safe("=x.x.x").is_ok());
/// // #1646: combined with another comparator, the wildcard half no longer blocks the whole
/// // requirement from resolving.
/// assert!(parse_range_safe("^1.0.0 ~*").is_ok());
/// // #1646: `~1.x.3` now resolves to its real bound-equivalent `~1.x`, rather than failing.
/// assert!(parse_range_safe("~1.x.3").is_ok());
/// // #1646 impl-critic S1: `~>` is npm's own synonym for `~`, so `~>1.x.3` gets the same
/// // precise treatment — critically, `~>1.x.3 || ^3.0.0` must NOT resolve to "any version".
/// assert!(parse_range_safe("~>1.x.3").is_ok());
/// assert!(parse_range_safe("~>1.x.3 || ^3.0.0").is_ok());
/// ```
pub fn parse_range_safe(requirement: &str) -> Result<node_semver::Range, RangeParseError> {
    let branches: Vec<Vec<(Cow<'_, str>, Option<TokenShape>)>> = requirement
        .split("||")
        .map(|branch| {
            merge_bare_operator_tokens(branch.split_whitespace())
                .into_iter()
                .map(|token| {
                    let shape = classify_token_shape(&token);
                    (token, shape)
                })
                .collect()
        })
        .collect();

    let needs_rewrite = branches.iter().flatten().any(|(_, shape)| shape.is_some());
    let rewritten = needs_rewrite.then(|| {
        branches
            .iter()
            .map(|branch| {
                branch
                    .iter()
                    .map(|(token, shape)| match shape {
                        Some(TokenShape::Unresolvable) => "*".to_string(),
                        Some(TokenShape::TildeWildcardPatch { major }) => format!("~{major}.x"),
                        None => token.as_ref().to_string(),
                    })
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .collect::<Vec<_>>()
            .join(" || ")
    });
    let target = rewritten.as_deref().unwrap_or(requirement);

    match std::panic::catch_unwind(|| node_semver::Range::parse(target)) {
        Ok(result) => result.map_err(RangeParseError::from),
        Err(_) => {
            tracing::warn!(
                requirement,
                "node_semver panicked parsing a range, treating it as unparseable (#1630)"
            );
            Err(RangeParseError::Panicked)
        }
    }
}

/// Precise npm semver range matcher, compiled once per dependency by
/// [`compile_node_semver_range`]. `branches` is `range` split on its top-level `||` and
/// individually re-parsed — needed only for [`explicitly_excludes`](Self::explicitly_excludes)'s
/// OR-alternation-gap check (#1601), since `node_semver::Range`'s own internal bound sets are
/// private and can't be walked from outside the crate.
struct NodeSemverMatcher {
    range: node_semver::Range,
    branches: Vec<node_semver::Range>,
}

impl RequirementMatcher for NodeSemverMatcher {
    fn matches(&self, version: &ConcreteVersion) -> Option<bool> {
        let version = version.as_str();
        node_semver::Version::parse(version)
            .ok()
            .map(|v| self.range.satisfies(&v))
    }

    /// `node_semver::Range::satisfies` excludes pre-releases unless `requirement` itself pins
    /// to the same `X.Y.Z` tuple with a pre-release tag — strict SemVer 2.0.0 semantics
    /// (#299). Declared once, here, on the matcher type itself: any formatter that reuses
    /// [`compile_node_semver_range`] (`deps-npm`'s own `NpmFormatter`, and `deps-deno`'s
    /// `DenoFormatter` for both `npm:` and `jsr:` specifiers) inherits this answer for free,
    /// with no separate per-formatter flag to keep in sync (#1478).
    fn strict_prerelease_exclusion(&self) -> bool {
        true
    }

    /// #1601 (same class as Maven's #1590 disjoint-range gap and Composer's `||`-gap): a
    /// version not satisfied by any `||`-branch can still sit strictly between two of them,
    /// with nothing admitted in the gap — the cooldown-fallback safety net
    /// (`fallback_edit_excludes_newer`) has no other way to tell that apart from a fallback
    /// that legitimately exceeds every branch's ceiling.
    fn explicitly_excludes(&self, version: &ConcreteVersion) -> bool {
        node_semver_or_gap_excludes(&self.branches, version.as_str())
    }
}

/// Whether `version` is explicitly excluded by an OR-alternation gap in npm's `||`-joined
/// range grammar (#1601). `node_semver::Range`'s own bound values are private, so each
/// branch's admitted span is probed via its public `allows_any` rather than read as literal
/// edges (`deps-maven`'s/`deps-composer`'s approach) —
/// [`deps_core::interval::union_gap_excludes`] is the shared, representation-agnostic
/// predicate all three route through.
///
/// A branch that admits nothing at all (an internally-contradictory comparator set, e.g.
/// `">1.0.0 <1.0.0"`) is excluded from both the "past" and "before" sides rather than
/// spuriously satisfying both simultaneously — mirroring `deps-maven`'s own
/// [`deps_core::interval::VersionRange::Empty`] handling.
///
/// Each branch's satisfiability (`allows_any(&any)`) is computed once, up front, and paired
/// with the branch itself — not recomputed inside both the `admits_at_or_above` and
/// `admits_at_or_below` closures (code-review perf finding), since `union_gap_excludes` calls
/// each closure once per branch on every invocation.
fn node_semver_or_gap_excludes(branches: &[node_semver::Range], version: &str) -> bool {
    if branches.len() < 2 {
        return false;
    }
    let Ok(candidate) = node_semver::Version::parse(version) else {
        return false;
    };
    let Ok(at_or_above) = parse_range_safe(&format!(">={candidate}")) else {
        return false;
    };
    let Ok(at_or_below) = parse_range_safe(&format!("<={candidate}")) else {
        return false;
    };
    let any = node_semver::Range::any();
    let members: Vec<(&node_semver::Range, bool)> = branches
        .iter()
        .map(|branch| (branch, branch.allows_any(&any)))
        .collect();
    deps_core::interval::union_gap_excludes(
        &members,
        |(branch, _satisfiable)| branch.satisfies(&candidate),
        |(branch, satisfiable)| !satisfiable || branch.allows_any(&at_or_above),
        |(branch, satisfiable)| !satisfiable || branch.allows_any(&at_or_below),
    )
}

/// Compiles `requirement` as a `node_semver::Range`, the grammar npm's registry and JSR both
/// use for matching.
///
/// The single source of truth for `deps-npm`'s own [`NpmFormatter::compile_requirement`] and
/// `deps-deno`'s `DenoFormatter::compile_requirement` (#1478).
///
/// Guards against an unresolved placeholder itself (#1374/#1377): a requirement for which
/// `deps_core::lsp_helpers::requirement_contains_template_placeholder` says `true` never
/// reaches `node_semver::Range::parse`, which might otherwise parse a placeholder-shaped
/// string loosely into an incorrect concrete range instead of failing closed. This internal
/// guard only ever runs that one shared detector — it is *not* equivalent to
/// [`RequirementResolution::requirement_is_unresolved`] in general, only for a formatter
/// whose own override of that method delegates entirely to the shared default (true today of
/// both `NpmFormatter` and `DenoFormatter`, per each one's own doc comment). A formatter that
/// overrides `requirement_is_unresolved`/`requirement_is_placeholder` with additional native
/// placeholder syntax of its own must still call its own `self.requirement_is_unresolved(...)`
/// before reaching this function — that native syntax is invisible to this guard.
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::RequirementMatcher;
/// use deps_core::{ConcreteVersion, VersionReq};
/// use deps_npm::compile_node_semver_range;
///
/// let matcher = compile_node_semver_range(&VersionReq::new("^1.0.0")).unwrap();
/// assert_eq!(matcher.matches(&ConcreteVersion::new("1.5.0")), Some(true));
/// assert_eq!(matcher.matches(&ConcreteVersion::new("2.0.0")), Some(false));
/// assert!(matcher.strict_prerelease_exclusion());
///
/// // An unresolved template placeholder never reaches `node_semver::Range::parse`.
/// assert!(compile_node_semver_range(&VersionReq::new("{{ version }}")).is_none());
/// ```
pub fn compile_node_semver_range(requirement: &VersionReq) -> Option<Box<dyn RequirementMatcher>> {
    if deps_core::lsp_helpers::requirement_contains_template_placeholder(requirement.as_str()) {
        return None;
    }
    let range = parse_range_safe(requirement.as_str()).ok()?;
    let branches = requirement
        .as_str()
        .split("||")
        .filter_map(|branch| parse_range_safe(branch.trim()).ok())
        .collect();
    Some(Box::new(NodeSemverMatcher { range, branches }) as Box<dyn RequirementMatcher>)
}

/// Maximum name length npm's registry accepts.
///
/// npm counts UTF-16 code units; this counts Unicode scalar values
/// (`str::chars().count()`) instead, which undercounts names containing
/// characters outside the Basic Multilingual Plane. Still strictly more
/// accurate than a byte-length check for the common case of non-ASCII names
/// within the BMP.
const MAX_NAME_LENGTH: usize = 214;

/// Names npm's own validator hard-rejects regardless of character content.
const BLOCKED_NAMES: [&str; 2] = ["node_modules", "favicon.ico"];

/// Reports whether every character of `segment` is in npm's unreserved set —
/// the set `encodeURIComponent` leaves untouched (`A-Za-z0-9` plus
/// `! ' ( ) * - . _ ~`). This mirrors npm's actual
/// `encodeURIComponent(segment) === segment` check: any other ASCII
/// punctuation or any non-ASCII character fails it.
fn is_url_friendly_segment(segment: &str) -> bool {
    segment.chars().all(|c| {
        c.is_ascii_alphanumeric()
            || matches!(c, '!' | '\'' | '(' | ')' | '*' | '-' | '.' | '_' | '~')
    })
}

/// [`EcosystemFormatter`](deps_core::lsp_helpers::EcosystemFormatter) implementation for npm.
pub struct NpmFormatter;

impl PackageNaming for NpmFormatter {
    /// Lints `name` against npm's own `validate-npm-package-name` rules.
    ///
    /// Deliberately permissive beyond what npm hard-rejects: uppercase letters are
    /// allowed (npm only warns for legacy packages, never rejects), and any
    /// character in npm's unreserved set (`! ' ( ) * - . _ ~` plus alphanumerics)
    /// is accepted, matching npm's `encodeURIComponent(name) === name` check
    /// exactly rather than an approximation of it.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidPackageName`] if `name` is empty, exceeds 214 characters,
    /// starts with `.` or `_`, is a reserved name (`node_modules`, `favicon.ico`),
    /// has a malformed `@scope/name` structure, or contains a character outside
    /// npm's unreserved set.
    fn validate_package_name(&self, name: &str) -> Result<(), InvalidPackageName> {
        if name.is_empty() {
            return Err(InvalidPackageName::new("name cannot be empty"));
        }
        if name.chars().count() > MAX_NAME_LENGTH {
            return Err(InvalidPackageName::new(format!(
                "name cannot exceed {MAX_NAME_LENGTH} characters"
            )));
        }
        if name.starts_with('.') {
            return Err(InvalidPackageName::new("name cannot start with a period"));
        }
        if name.starts_with('_') {
            return Err(InvalidPackageName::new(
                "name cannot start with an underscore",
            ));
        }
        if BLOCKED_NAMES
            .iter()
            .any(|blocked| name.eq_ignore_ascii_case(blocked))
        {
            return Err(InvalidPackageName::new(format!(
                "'{name}' is a reserved name"
            )));
        }

        // Scoped names are `@scope/name`; anything else with a '/' is invalid.
        let (scope, pkg_name) = match name.split_once('/') {
            Some((scope, pkg_name)) => {
                let Some(scope) = scope.strip_prefix('@') else {
                    return Err(InvalidPackageName::new("unscoped name cannot contain '/'"));
                };
                (Some(scope), pkg_name)
            }
            None => (None, name),
        };

        if let Some(scope) = scope {
            if scope.is_empty() {
                return Err(InvalidPackageName::new("scope cannot be empty"));
            }
            if !is_url_friendly_segment(scope) {
                return Err(InvalidPackageName::new(
                    "scope contains characters that are not URL-friendly",
                ));
            }
        }

        if pkg_name.is_empty() {
            return Err(InvalidPackageName::new("name cannot be empty"));
        }
        if pkg_name.contains('/') {
            return Err(InvalidPackageName::new(
                "name cannot contain more than one '/'",
            ));
        }
        if !is_url_friendly_segment(pkg_name) {
            return Err(InvalidPackageName::new(
                "name contains characters that are not URL-friendly",
            ));
        }

        Ok(())
    }
}

impl PackageRendering for NpmFormatter {
    fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
        let version = version.as_str();
        version.to_string()
    }

    // #1576, impl-critic S1: no override needed here. `format_version_replacing`'s shared
    // default (ignore `current`, always write a bare version) already ignores every
    // requirement shape uniformly — bare, compound, wildcard, single-bound, or an explicit
    // `=`/`~`/`^` operator alike. The original #1576 report modeled npm on Cargo's
    // bare-means-caret convention, but node-semver reads a bare version as an *exact pin*
    // (verified empirically: a bare `node_semver::Range` for `"2.0.6"` matches only that one
    // version), so collapsing ANY requirement shape to bare always narrows what it accepts,
    // never widens it — the shared default was already correct, and a first attempt at this
    // fix that added a Cargo-style refusal override here was itself the actual bug (it
    // silently dropped a real, safe rewrite, including a vulnerability-fix rewrite for a
    // dependency declared as a range). This matches `deps-lsp`'s existing, deliberately tested
    // "Update all outdated" code-lens contract for npm (`code_lens.rs`'s
    // `test_npm_literal_version_is_edited`: `"^4.0.0"` -> `"5.0.0"`, caret dropped) — unlike
    // Dart, whose analogous contract preserves an explicit `^` (see `DartFormatter`'s own
    // override and its doc for why the two ecosystems' policies genuinely differ here).
    fn package_url(&self, name: &PackageName) -> String {
        crate::registry::package_url(name.as_str())
    }
}

impl RequirementResolution for NpmFormatter {
    /// Delegates to [`compile_node_semver_range`] — precise npm semver range semantics,
    /// unlike the default `version_satisfies_requirement` heuristic this method deliberately
    /// does not reuse (see that method's docs). The unresolved-placeholder guard
    /// (#1374/#1377) now lives inside `compile_node_semver_range` itself; see its doc for why
    /// that's safe without an extra `self.requirement_is_unresolved` check here.
    fn compile_requirement(&self, requirement: &VersionReq) -> Option<Box<dyn RequirementMatcher>> {
        compile_node_semver_range(requirement)
    }

    // #1370/#1374/#1379/#1391: npm's requirement grammar has no placeholder syntax of its
    // own — `RequirementResolution::requirement_is_placeholder`'s shared default (the
    // `requirement_contains_template_placeholder` detector) already covers the only
    // unresolved shape npm has, so no override is needed here.
}

impl DiagnosticMessages for NpmFormatter {
    fn yanked_message(&self) -> &'static str {
        "This version is deprecated"
    }

    fn yanked_label(&self) -> &'static str {
        "*(deprecated)*"
    }
}

impl DiagnosticPolicy for NpmFormatter {
    /// Disables the manifest-requirement-level "requirement satisfiable only by a yanked
    /// version" diagnostic entirely (#436, follow-up to #205's plan.md §6): unconditionally
    /// `false`, for every requirement shape, not only ranges.
    ///
    /// npm's `Version::removal_status()` is genuinely per-version data (`npm deprecate` can
    /// target one version), but `npm deprecate` is routinely applied to *every* published
    /// version of a package at once (live-verified: the `request` package has all 126/126
    /// versions marked deprecated) — common enough that this diagnostic would frequently
    /// duplicate the dedicated package-level deprecation diagnostic
    /// ([`deps_core::lsp_helpers::DiagnosticMessages::deprecated_message`], issue #205), including for an exact-pin
    /// requirement (the case this hook used to still allow through). This does not touch
    /// [`Registry::reports_yanked`](deps_core::Registry::reports_yanked), which npm keeps at
    /// its default `true`: the independent in-use-version yanked check (#263,
    /// `crates/deps-core/src/lsp_helpers/diagnostics.rs`) reads real per-version data and
    /// stays live — e.g. a lockfile-pinned old version flagged by `npm deprecate pkg@"<1.2.3"`
    /// while `latest` is clean still surfaces its own "yanked" diagnostic.
    fn yanked_diagnostic_applies_to(
        &self,
        _dep: &dyn Dependency,
        _requirement: &VersionReq,
    ) -> bool {
        false
    }
}

impl SourcePolicy for NpmFormatter {
    /// FR-009: widens [`SourcePolicy::can_resolve_source`] so a `.npmrc`-resolved
    /// `AlternateRegistry` is resolvable alongside the default public `Registry` — gates
    /// hover/diagnostics/code-actions onto the router's per-source dispatch
    /// (`NpmRegistry::get_versions_from`) instead of the source-blind path. `CustomRegistry`
    /// (FR-006's fail-closed state) keeps the default's `false`.
    fn resolves_alternate_registry(&self) -> bool {
        true
    }
}

impl OsvNaming for NpmFormatter {}

#[cfg(test)]
mod tests {
    use super::*;

    /// O2: npm never offers the #205 "Replace with X" rename action — its only
    /// successor signal is free text (`deprecated`'s message), and regex-extracting a
    /// package name from registry-controlled prose to rewrite a manifest is a
    /// typosquatting vector. `supports_package_rename` stays the trait default (`false`).
    #[test]
    fn test_supports_package_rename_false() {
        assert!(!NpmFormatter.supports_package_rename());
    }

    /// npm's deprecation wording reuses the trait default (only Composer overrides it,
    /// to match Packagist's "abandoned" vocabulary).
    #[test]
    fn test_deprecated_message_and_label_use_defaults() {
        let f = NpmFormatter;
        assert_eq!(f.deprecated_message(), "This package is deprecated");
        assert_eq!(f.deprecated_label(), "*(deprecated)*");
    }

    // #758: replaces several hand-written EcosystemFormatter tests. test_validate_package_name_length_boundary
    // below stays separate: its computed (`.repeat(n)`) boundary name doesn't fit the macro's literal-only lists.
    deps_core::formatter_conformance! {
        mod npm_formatter_conformance;
        build: NpmFormatter;
        package_url: {
            "react" => "https://www.npmjs.com/package/react",
            "@types/node" => "https://www.npmjs.com/package/@types/node",
        };
        accepts: [
            "@types/node", "@scope/_private", "@scope/.config", "lodash.debounce", "c8", "-", "a",
            "MyLegacyPackage",
            // encodeURIComponent leaves `!'()*-._~` untouched, so `*` is legitimate here.
            "weird*name"
        ];
        rejects: [
            "", "node_modules", "NODE_MODULES", "favicon.ico", "foo/bar", "a\\b", ".hidden",
            "_private", "@scope", "@/pkg", "@scope/", "@scope/pkg/extra",
            // Well-formed `@scope/name` but the scope segment contains a space.
            "@sco pe/valid-pkg",
            // Well-formed `@scope/name` but the name segment contains a space.
            "@valid-scope/pkg name"
        ];
        version_roundtrip: [
            "1.2.3", "1.2.3" => true,
            "1.2.3", "1" => true,
            "1.2.3", "1.2" => true,
            "1.2.3", "^1.2" => true,
            "1.2.3", "^1.0" => true,
            "1.5.0", "^1.2.3" => true,
            "10.1.3", "^10.1.3" => true,
            "10.2.0", "^10.1.3" => true,
            "1.2.3", "~1.2" => true,
            "1.2.5", "~1.2" => true,
            "1.2.3", "2.0.0" => false,
            "1.2.3", "1.3" => false,
            "2.0.0", "^1.2.3" => false
        ];
    }

    /// Boundary pair for `MAX_NAME_LENGTH`: exactly 214 chars accepted, 215 rejected.
    /// Computed (`.repeat(n)`) lengths, so this doesn't fit `formatter_conformance!`'s
    /// `literal`-only accepts/rejects lists above.
    #[test]
    fn test_validate_package_name_length_boundary() {
        let formatter = NpmFormatter;
        assert!(formatter.validate_package_name(&"a".repeat(214)).is_ok());
        assert!(formatter.validate_package_name(&"a".repeat(215)).is_err());
    }

    /// FR-009 (M7): `can_resolve_source` accepts `Registry` and `AlternateRegistry`, rejects
    /// `CustomRegistry` (FR-006's fail-closed state).
    #[test]
    fn test_can_resolve_source_fr009() {
        let formatter = NpmFormatter;
        assert!(formatter.can_resolve_source(&deps_core::DependencySource::Registry));
        assert!(
            formatter.can_resolve_source(&deps_core::DependencySource::AlternateRegistry {
                index: "https://npm.pkg.github.com".to_string(),
                mirrors_crates_io: false,
            })
        );
        assert!(
            !formatter.can_resolve_source(&deps_core::DependencySource::CustomRegistry {
                url: "not-a-valid-url".to_string(),
            })
        );
    }

    /// FR-015 (M7): no npmjs.com hover link for anything but the plain public registry.
    #[test]
    fn test_suppress_package_url_fr015() {
        let formatter = NpmFormatter;
        assert!(!formatter.suppress_package_url(&deps_core::DependencySource::Registry));
        assert!(
            formatter.suppress_package_url(&deps_core::DependencySource::AlternateRegistry {
                index: "https://npm.pkg.github.com".to_string(),
                mirrors_crates_io: false,
            })
        );
        assert!(
            formatter.suppress_package_url(&deps_core::DependencySource::CustomRegistry {
                url: "not-a-valid-url".to_string(),
            })
        );
    }

    #[test]
    fn test_format_version() {
        let formatter = NpmFormatter;
        assert_eq!(
            formatter.format_version_for_text_edit(&ConcreteVersion::new("1.0.214")),
            "1.0.214"
        );
        assert_eq!(
            formatter.format_version_for_text_edit(&ConcreteVersion::new("18.3.1")),
            "18.3.1"
        );
    }

    /// impl-critic S1: node-semver's bare version is an exact pin, not an implicit caret range
    /// (unlike Cargo) — so collapsing a space-separated AND range (or any other bounded shape)
    /// to a bare version always narrows what it accepts, never widens it, and must be allowed
    /// rather than refused (a refusal here would silently drop a real, safe rewrite, including
    /// a vulnerability-fix rewrite for a dependency declared as a range). No override needed:
    /// the shared default (ignore `current`, always write bare) already does this.
    #[test]
    fn test_format_version_replacing_space_separated_and_range_collapses_to_bare() {
        let formatter = NpmFormatter;
        assert_eq!(
            formatter.format_version_replacing(&ConcreteVersion::new("1.4.0"), ">=1.2.0 <2.0.0"),
            "1.4.0"
        );
    }

    /// A bare requirement has no operator to protect — always rewritten to a plain version
    /// string.
    #[test]
    fn test_format_version_replacing_bare_requirement_stays_bare() {
        let formatter = NpmFormatter;
        assert_eq!(
            formatter.format_version_replacing(&ConcreteVersion::new("2.0.0"), "1.5.0"),
            "2.0.0"
        );
    }

    /// Deliberately the opposite of Dart's/Cargo's behavior: an explicit `^`/`~` is dropped,
    /// not preserved, on npm rewrite — matches `deps-lsp`'s existing, tested "Update all
    /// outdated" code-lens contract for npm (`code_lens.rs`'s `test_npm_literal_version_is_edited`,
    /// which asserts `"^4.0.0"` -> `"5.0.0"`). An earlier version of this fix added
    /// operator-preserving behavior here as a speculative improvement; it broke that existing
    /// test and was reverted.
    #[test]
    fn test_format_version_replacing_explicit_caret_and_tilde_dropped() {
        let formatter = NpmFormatter;
        assert_eq!(
            formatter.format_version_replacing(&ConcreteVersion::new("2.0.0"), "^1.5.0"),
            "2.0.0"
        );
        assert_eq!(
            formatter.format_version_replacing(&ConcreteVersion::new("2.0.0"), "~1.5.0"),
            "2.0.0"
        );
    }

    #[test]
    fn test_default_normalize_is_identity() {
        let formatter = NpmFormatter;
        assert_eq!(
            formatter.normalize_package_name(&PackageName::new("react")),
            "react"
        );
        assert_eq!(
            formatter.normalize_package_name(&PackageName::new("@types/node")),
            "@types/node"
        );
    }

    #[test]
    fn test_deprecated_messages() {
        let formatter = NpmFormatter;
        assert_eq!(formatter.yanked_message(), "This version is deprecated");
        assert_eq!(formatter.yanked_label(), "*(deprecated)*");
    }

    #[test]
    fn test_compile_requirement_satisfiable() {
        let formatter = NpmFormatter;
        let matcher = formatter
            .compile_requirement(&VersionReq::new("^1.0.0"))
            .expect("valid npm range must compile");
        assert_eq!(matcher.matches(&ConcreteVersion::new("1.5.0")), Some(true));
        assert_eq!(matcher.matches(&ConcreteVersion::new("2.0.0")), Some(false));
    }

    /// #1478: the matcher itself carries `strict_prerelease_exclusion`, not a separate
    /// per-formatter flag — proves `deps-npm`'s own compiled matcher opts in; `deps-deno`'s
    /// equivalent behavior is covered by its own end-to-end diagnostic test, since it reuses
    /// this exact matcher via `compile_node_semver_range`.
    #[test]
    fn test_compile_requirement_matcher_opts_into_strict_prerelease_exclusion() {
        let formatter = NpmFormatter;
        let matcher = formatter
            .compile_requirement(&VersionReq::new("^1.0.0"))
            .expect("valid npm range must compile");
        assert!(matcher.strict_prerelease_exclusion());
    }

    #[test]
    fn test_compile_requirement_unparseable_requirement_returns_none() {
        let formatter = NpmFormatter;
        assert!(
            formatter
                .compile_requirement(&VersionReq::new("not a range"))
                .is_none()
        );
    }

    /// #1639: `node_semver` 2.2.0 hits an internal `unreachable!()` (rather than returning
    /// `Err`) for a *bare* tilde requirement whose partial version has a wildcard major
    /// (`~*`/`~x`/`~X`, any trailing components) — reachable straight from `package.json` via
    /// `compile_requirement`. Real npm resolves all of these to "any version" (live-verified),
    /// so `parse_range_safe` now resolves them precisely instead of just catching the panic —
    /// asserted here by confirming the matcher admits an arbitrary version.
    #[test]
    fn test_compile_requirement_wildcard_major_resolves_to_any_version() {
        let formatter = NpmFormatter;
        for requirement in ["~*", "~x", "~X", "~>*", "~>x.2.3", "=*", "=x", "=X"] {
            let matcher = formatter
                .compile_requirement(&VersionReq::new(requirement))
                .unwrap_or_else(|| panic!("{requirement:?} must resolve to a real range"));
            assert_eq!(
                matcher.matches(&ConcreteVersion::new("999.999.999")),
                Some(true),
                "requirement {requirement:?} must match an arbitrary version"
            );
        }
    }

    /// #1639 at the wrapper level: a bare wildcard-major tilde/equals comparator now resolves
    /// to `Ok(Range::any())` instead of `Err(RangeParseError::Panicked)`, whether or not it's
    /// combined with another comparator. Unlike tilde, an equals comparator with a wildcard
    /// major but any *concrete* trailing component (`=x.2.3`) is a genuine npm parse error, not
    /// "any version" — live-verified against npm's own `semver` package — and must stay
    /// `Panicked` (`node_semver`'s equals `unreachable!()` site, `range.rs:782`, fires
    /// regardless of the trailing components, same as the tilde site at `range.rs:982`).
    #[test]
    fn test_parse_range_safe_wildcard_major_resolves_to_any_version() {
        for requirement in ["~*", "~x", "~X", "~>*", "~>x.2.3", "=*", "=x", "=X"] {
            assert!(
                parse_range_safe(requirement).is_ok(),
                "requirement {requirement:?} must resolve to Ok"
            );
        }
        for requirement in ["=x.2.3", "=x.2", "=X.x.2"] {
            assert!(
                matches!(
                    parse_range_safe(requirement),
                    Err(RangeParseError::Panicked)
                ),
                "requirement {requirement:?} (wildcard major, concrete trailing) must stay \
                 RangeParseError::Panicked for equals, unlike tilde"
            );
        }
        assert!(matches!(
            parse_range_safe("not a range"),
            Err(RangeParseError::Malformed(_))
        ));
        assert!(parse_range_safe("^1.0.0").is_ok());
        // `=` (Exact) tolerates a wildcard minor as long as the major is concrete — only a
        // wildcard *major* panics for this operator (unlike plain tilde's extra gap).
        assert!(parse_range_safe("=1.x.3").is_ok());
        // Plain tilde's gap requires patch to be concrete; a wildcard patch is fine.
        assert!(parse_range_safe("~1.x").is_ok());
    }

    /// #1639 impl-critic S1': `node_semver` and real npm both accept only a *lowercase* `v`
    /// prefix (`~v*`, `=v*`, `=vx` resolve to any version, live-verified) — an uppercase `V`
    /// is genuinely invalid in both, and must stay `Panicked`, not be silently accepted as an
    /// equivalent prefix (a v-prefix-case regression caught before merge, see #1639's PR
    /// history).
    #[test]
    fn test_parse_range_safe_lowercase_v_prefix_resolves_uppercase_stays_err() {
        for requirement in ["~v*", "=v*", "=vx"] {
            assert!(
                parse_range_safe(requirement).is_ok(),
                "requirement {requirement:?} (lowercase v) must resolve to Ok"
            );
        }
        for requirement in ["~V*", "=V*", "~Vx.2"] {
            assert!(
                parse_range_safe(requirement).is_err(),
                "requirement {requirement:?} (uppercase V) must stay Err, not be silently \
                 accepted as an equivalent to the lowercase-v shape"
            );
        }
    }

    /// #1646 shape 3: `~1.x.3` (plain tilde, concrete-wildcard-concrete) is rewritten to its
    /// real bound-equivalent `~1.x` instead of failing safe — npm resolves both to the same
    /// `>=1.0.0 <2.0.0-0` (live-verified against npm's own `semver` package). `~>1.x.3`
    /// (#1646 impl-critic S1) gets the identical treatment, since npm defines `~>` as a
    /// synonym for `~` — live-verified: `~>1.x.3` resolves to the exact same bound as
    /// `~1.x.3`, not "any version".
    #[test]
    fn test_compile_requirement_tilde_wildcard_patch_resolves_precisely() {
        let formatter = NpmFormatter;
        for (requirement, equivalent) in [
            ("~1.x.3", "~1.x"),
            ("~10.x.5", "~10.x"),
            ("~1.X.3", "~1.x"),
            ("~>1.x.3", "~1.x"),
            ("~> 1.x.3", "~1.x"),
        ] {
            let matcher = formatter
                .compile_requirement(&VersionReq::new(requirement))
                .unwrap_or_else(|| panic!("{requirement:?} must resolve to a real range"));
            let expected = formatter
                .compile_requirement(&VersionReq::new(equivalent))
                .unwrap();
            for version in ["1.0.0", "1.9.9", "2.0.0", "0.9.9"] {
                assert_eq!(
                    matcher.matches(&ConcreteVersion::new(version)),
                    expected.matches(&ConcreteVersion::new(version)),
                    "{requirement:?} and {equivalent:?} must agree on {version}"
                );
            }
        }
    }

    /// #1646 impl-critic S1 regression: combined via `||`, `~>1.x.3` must union with the
    /// other branch's own bound, not blow the whole requirement open to "any version" (the
    /// bug this fix replaces — `~>1.x.3` was previously misclassified as `Unresolvable` and
    /// so got the `*` substitution meant for genuine wildcard-major shapes).
    #[test]
    fn test_compile_requirement_tilde_wildcard_patch_or_combinator_does_not_widen_to_any() {
        let formatter = NpmFormatter;
        let matcher = formatter
            .compile_requirement(&VersionReq::new("~>1.x.3 || ^3.0.0"))
            .expect("must resolve to a real range, not fail");
        // In-bound for one of the two branches.
        assert_eq!(matcher.matches(&ConcreteVersion::new("1.5.0")), Some(true));
        assert_eq!(matcher.matches(&ConcreteVersion::new("3.5.0")), Some(true));
        // In the gap between `~1.x` (< 2.0.0) and `^3.0.0` (>= 3.0.0): must NOT match, unlike
        // a genuine "any version" resolution which would.
        assert_eq!(matcher.matches(&ConcreteVersion::new("2.5.0")), Some(false));
    }

    /// #1646 shape 2: whitespace right after a bare `~`/`=` operator binds to the same
    /// comparator (`"~ *"` behaves as `"~*"`) rather than splitting into two independent
    /// tokens — live-verified against npm's own `semver` package.
    #[test]
    fn test_parse_range_safe_merges_whitespace_after_bare_operator() {
        for requirement in ["~ *", "= *", "~  *", "=  *"] {
            assert!(
                parse_range_safe(requirement).is_ok(),
                "requirement {requirement:?} must resolve to Ok, matching bare \"~*\"/\"=*\" (#1639)"
            );
        }
        // Combined with a real comparator, the merged wildcard half no longer blocks
        // resolution (shape 1, see below).
        assert!(parse_range_safe("^1.0.0 ~ *").is_ok());
        // #1646 impl-critic M4: whitespace-merging must also feed shape 3's precise rewrite,
        // not just the wildcard-major `Unresolvable` bucket.
        assert!(parse_range_safe("~ 1.x.3").is_ok());
    }

    /// #1646 impl-critic M2: a `-prerelease` suffix on a *middle* component (`~1.x-beta.3`,
    /// not valid npm range grammar — live-verified as a real npm parse error) must not be
    /// silently accepted as a wildcard component the way a *last*-component suffix is
    /// (`=x.x.x-beta`, shape 4). Must not be misresolved to `~1.x`'s bound.
    #[test]
    fn test_compile_requirement_prerelease_suffix_on_middle_component_is_not_wildcard() {
        let formatter = NpmFormatter;
        assert!(
            formatter
                .compile_requirement(&VersionReq::new("~1.x-beta.3"))
                .is_none(),
            "a prerelease suffix on a middle component must not resolve to a range at all"
        );
    }

    /// #1646 code-review finding (post-impl-critic): a malformed or suffixed *patch*
    /// component on an otherwise shape-3-shaped tilde range (`~{major}.x.{patch}`) must not
    /// be silently classified as `Concrete` and rewritten away — that would discard a
    /// differentiating suffix (a prerelease tag, build metadata, garbage, or a 4th dot
    /// segment folded into the patch slot by `splitn(3, '.')`) and misresolve to `~{major}.x`
    /// instead of erroring. All four inputs below are confirmed live to panic
    /// `node_semver::Range::parse` directly, same as a genuine `~1.x.3` — they must fall
    /// through to the same safe `catch_unwind` backstop, not resolve to a range at all.
    #[test]
    fn test_compile_requirement_tilde_wildcard_patch_with_malformed_patch_is_not_narrowed() {
        let formatter = NpmFormatter;
        for requirement in ["~1.x.3-alpha", "~1.x.3+build", "~1.x.3abc", "~1.x.3.4"] {
            assert!(
                formatter
                    .compile_requirement(&VersionReq::new(requirement))
                    .is_none(),
                "requirement {requirement:?} must not silently narrow to ~{{major}}.x's bound"
            );
            assert!(
                matches!(
                    parse_range_safe(requirement),
                    Err(RangeParseError::Panicked)
                ),
                "requirement {requirement:?} must resolve to RangeParseError::Panicked"
            );
        }
    }

    /// #1646 shape 4: a fully-wildcard component set with a `-prerelease` suffix on the last
    /// component still resolves to "any version" in real npm (`=x.x.x-beta` -> `<any>`,
    /// live-verified), matching the plain bare-wildcard resolution (#1639).
    #[test]
    fn test_compile_requirement_prerelease_suffixed_wildcard_resolves_to_any_version() {
        let formatter = NpmFormatter;
        for requirement in ["=x.x.x-beta", "~x.x.x-beta", "~*.*.*-beta", "=X.X.X-beta.1"] {
            let matcher = formatter
                .compile_requirement(&VersionReq::new(requirement))
                .unwrap_or_else(|| panic!("{requirement:?} must resolve to a real range"));
            assert_eq!(
                matcher.matches(&ConcreteVersion::new("999.999.999")),
                Some(true),
                "requirement {requirement:?} must match an arbitrary version"
            );
            assert!(parse_range_safe(requirement).is_ok());
        }
    }

    /// #1646 shape 1: combined via `||` or whitespace, a wildcard-major comparator no longer
    /// blocks the whole requirement — npm's own semantics for this combination were
    /// live-verified against npm's `semver` package: OR-ing a wildcard with anything else
    /// unions to "any version" (since the wildcard branch alone already admits everything),
    /// and AND-ing a wildcard with anything else is a no-op (the wildcard is the identity
    /// element for intersection), leaving the other comparator's own bound.
    #[test]
    fn test_compile_requirement_combined_wildcard_comparator_resolves_precisely() {
        let formatter = NpmFormatter;

        // OR: unions to "any version", same as a bare `*`.
        let or_matcher = formatter
            .compile_requirement(&VersionReq::new("~* || ^1.0.0"))
            .expect("combined OR requirement must resolve");
        let any_matcher = formatter
            .compile_requirement(&VersionReq::new("*"))
            .unwrap();
        for version in ["0.1.0", "1.5.0", "5.0.0"] {
            assert_eq!(
                or_matcher.matches(&ConcreteVersion::new(version)),
                any_matcher.matches(&ConcreteVersion::new(version))
            );
        }

        // AND: the wildcard is a no-op, leaving `^1.0.0`'s own bound.
        let and_matcher = formatter
            .compile_requirement(&VersionReq::new("^1.0.0 ~*"))
            .expect("combined AND requirement must resolve");
        let caret_matcher = formatter
            .compile_requirement(&VersionReq::new("^1.0.0"))
            .unwrap();
        for version in ["0.9.0", "1.0.0", "1.5.0", "2.0.0"] {
            assert_eq!(
                and_matcher.matches(&ConcreteVersion::new(version)),
                caret_matcher.matches(&ConcreteVersion::new(version))
            );
        }
    }

    #[test]
    fn test_compile_requirement_unparseable_candidate_is_skipped() {
        let formatter = NpmFormatter;
        let matcher = formatter
            .compile_requirement(&VersionReq::new("^1.0.0"))
            .unwrap();
        assert_eq!(
            matcher.matches(&ConcreteVersion::new("not-a-version")),
            None
        );
    }

    /// §3.1 worked example counterpart for npm (this formatter also relies on the
    /// default loose `version_satisfies_requirement`).
    #[test]
    fn test_compile_requirement_comparator_list_satisfiable() {
        let formatter = NpmFormatter;
        let matcher = formatter
            .compile_requirement(&VersionReq::new(">=1.0.0 <2.0.0"))
            .unwrap();
        assert_eq!(matcher.matches(&ConcreteVersion::new("1.5.0")), Some(true));
    }

    /// §3.3 case for npm: `^0.2.999` and latest `0.2.14` share the leading zero-major
    /// minor component, so the loose heuristic (and the removed `Outdated` gate) would
    /// call this up to date. The precise matcher must reject it.
    #[test]
    fn test_compile_requirement_caret_zero_mistyped_patch_is_unsatisfiable() {
        let formatter = NpmFormatter;
        let matcher = formatter
            .compile_requirement(&VersionReq::new("^0.2.999"))
            .unwrap();
        assert_eq!(
            matcher.matches(&ConcreteVersion::new("0.2.14")),
            Some(false)
        );
    }

    /// #436: the manifest-requirement-level yanked diagnostic never applies to npm, for
    /// any requirement shape — including an exact pin, which the pre-#436 exact-pin
    /// restriction used to still allow through.
    #[test]
    fn test_yanked_diagnostic_applies_to_always_false() {
        use crate::types::{NpmDependency, NpmDependencySection};

        let formatter = NpmFormatter;
        for requirement in ["1.2.3", "^1.2.3", "~1.2.3", ">=1.0.0 <2.0.0", "*", "1.x"] {
            // Mirrors the sole call site: `requirement` is always `dep.version_requirement().unwrap()`.
            let dep = NpmDependency {
                name: PackageName::new("lodash"),
                name_range: deps_core::Range::default(),
                version_req: Some(VersionReq::new(requirement)),
                version_range: None,
                section: NpmDependencySection::Dependencies,
                source: deps_core::parser::DependencySource::Registry,
                catalog: None,
                package: None,
            };
            assert!(
                !formatter.yanked_diagnostic_applies_to(&dep, &VersionReq::new(requirement)),
                "expected {requirement:?} to be rejected"
            );
        }
    }

    fn explicitly_excludes(requirement: &str, version: &str) -> bool {
        let matcher = compile_node_semver_range(&VersionReq::new(requirement)).unwrap();
        matcher.explicitly_excludes(&ConcreteVersion::new(version))
    }

    /// #1601: a version sitting in the gap between two `||`-branches is explicitly excluded,
    /// mirroring Maven's #1590 disjoint-range gap and Composer's own `||`-gap detection.
    #[test]
    fn test_explicitly_excludes_detects_or_alternation_gap() {
        let req = ">=1.0.0 <1.5.0 || >1.5.0 <2.0.0";
        assert!(explicitly_excludes(req, "1.5.0"));
        assert!(!explicitly_excludes(req, "1.2.0"));
        assert!(!explicitly_excludes(req, "1.8.0"));
        assert!(!explicitly_excludes(req, "0.5.0"));
        assert!(!explicitly_excludes(req, "2.5.0"));
    }

    /// #1601: the same gap, expressed with fully open-ended halves.
    #[test]
    fn test_explicitly_excludes_or_gap_open_ended_halves() {
        let req = "<1.5.0 || >1.5.0 <2.0.0";
        assert!(explicitly_excludes(req, "1.5.0"));
        assert!(!explicitly_excludes(req, "1.2.0"));
        assert!(!explicitly_excludes(req, "1.8.0"));
    }

    /// #1601's issue repro: unlike `deps-composer` (which cannot model a caret-only branch's
    /// bound, see that crate's own documented limitation), npm's probe-based approach handles
    /// this shape because it never needs a literal bound value.
    #[test]
    fn test_explicitly_excludes_or_gap_caret_branches() {
        let req = "^1.0.0 || ^3.0.0";
        assert!(explicitly_excludes(req, "2.5.0"));
        assert!(!explicitly_excludes(req, "1.5.0"));
        assert!(!explicitly_excludes(req, "3.5.0"));
    }

    /// A single branch alone has no "other side" to form a gap against.
    #[test]
    fn test_explicitly_excludes_or_gap_requires_at_least_two_branches() {
        assert!(!explicitly_excludes(">=1.0.0 <2.0.0", "5.0.0"));
    }

    /// A version covered by any branch is never excluded, regardless of how the other
    /// branches are shaped.
    #[test]
    fn test_explicitly_excludes_or_gap_false_when_covered() {
        let req = ">=1.0.0 <1.5.0 || >1.5.0 <2.0.0";
        assert!(!explicitly_excludes(req, "1.2.0"));
        assert!(!explicitly_excludes(req, "1.8.0"));
    }
}
