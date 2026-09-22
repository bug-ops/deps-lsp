use std::collections::HashMap;

use crate::diagnostic::{CodeDescription, Diagnostic, RelatedInformation, Severity};
use crate::licenses::{
    ViolationReason, evaluate as evaluate_license_policy, resolve_license_entries,
};
use crate::osv::{ScanOutcome, diagnostic_severity_for};
use crate::position::{Position, Range};
use crate::redact::{RedactedUrl, redact_declaration_key, sanitize_invisible};
use crate::{
    BlockedRegistryOccurrence, ConcreteVersion, Dependency, Deprecation, FetchFailure, PackageName,
    ParseResult, PublishTime, RemovalStatus, VersionReq, format_relative_age, is_within_cooldown,
};

use super::{
    EcosystemFormatter, PackageVersions, RequirementMatcher, RequirementStatus, VersionData,
    version_range_is_synthetic_empty,
};

/// Stable [`Diagnostic::code`] set on the unsatisfiable-requirement diagnostic.
///
/// Set by `generate_diagnostics_from_cache`, so `build_unsatisfiable_fix_action`'s
/// stashed `CodeAction::data` can name it and the `deps-lsp` handler's diagnostic-binding
/// step can match on it — the same mechanism `build_vulnerability_fix_action` uses with an
/// advisory id, generalized to a constant since this diagnostic has no per-instance
/// identifier.
pub const UNSATISFIABLE_DIAGNOSTIC_CODE: &str = "unsatisfiable-requirement";

/// Stable [`Diagnostic::code`] set on the license-policy-violation diagnostic (issue #661,
/// spec 010 Phase 2). See `apply_license_policy_rule`.
pub const LICENSE_POLICY_VIOLATION_DIAGNOSTIC_CODE: &str = "license-policy-violation";

/// Shared upper bound on an attacker-controlled fragment interpolated into a diagnostic
/// or hover message before truncation (issue #1278).
///
/// Counted in Unicode scalar values, not bytes. Nine call sites across `deps-core` and
/// three ecosystem crates (`deps-github-actions`,
/// `deps-gitlab-ci`, `deps-npm`) each independently declared their own `= 128` constant for
/// this exact concern — most critically, `deps-github-actions` and `deps-gitlab-ci` each
/// declared a byte-for-byte identical `MAX_MUTABLE_REF_PIN_MESSAGE_VALUE_CHARS`, free to
/// drift apart since neither referenced the other. This is the single source of truth all of
/// them now share: `deps-core`'s own blocked-registry/license-policy/license-id sinks, and
/// the three ecosystem crates' mutable-ref-pin / pnpm-catalog sinks (see each call site's own
/// doc for why 128 is the right bound for *its* attacker-controlled value — this constant
/// only centralizes the number, not the reasoning, which differs per sink).
///
/// `MAX_DIAGNOSTIC_PROSE_CHARS`, `MAX_DIAGNOSTIC_NAME_CHARS`, and
/// `MAX_VERSION_DIAGNOSTIC_CHARS` are deliberately *not* folded into this constant despite
/// also equaling 128: each already has exactly one canonical declaration reused by name
/// across several call sites (not independent duplicates), and each name documents a
/// distinct semantic category (free-form prose vs. an identifier vs. a version string) that
/// a caller reading `MAX_DIAGNOSTIC_NAME_CHARS` at a use site depends on — collapsing them
/// into one generically-named constant would trade that self-documentation for no actual
/// deduplication. They do derive their value from this constant, though, so there is one
/// literal `128` shared by the nine sanitize-and-cap-sweep constants #1278 identified.
/// Other unrelated `= 128` consts elsewhere in the workspace — `licenses::MAX_SPDX_ID_CHARS`
/// and `git_ref::MAX_SHA_PIN_TITLE_NAME_CHARS` — are a different bound class, were never
/// part of #1278's list, and are deliberately left untouched; this constant makes no claim
/// about them.
pub const MAX_DIAGNOSTIC_VALUE_CHARS: usize = 128;

/// Maximum number of sibling occurrences a collapsed blocked-registry diagnostic's
/// `related_information` names individually before folding the rest into one "+N more" entry
/// (#944 S2).
///
/// A config-global declaration (a single blocked npm top-level `registry=`, or one
/// `NuGet.Config` `<add key>` source) can affect *every* dependency in the document — without
/// this cap, [`push_collapsed_blocked_registries`] would build up to
/// [`crate::MAX_DEPENDENCIES_PER_DOCUMENT`] `-` `1` `Location`s (each a cloned [`Uri`] plus a
/// message) into one diagnostic, republished on every keystroke, for a group whose size alone
/// already says everything the individual entries would ("every other dependency is affected
/// too").
const MAX_BLOCKED_REGISTRY_RELATED_INFO: usize = 9;

/// Maximum character count of a free-text prose value — an OSV advisory's `id`/`summary`, or
/// a registry-reported deprecation `reason` — interpolated into a diagnostic message before
/// it is truncated with an ellipsis marker (#1262, #1263 follow-up). Shared across both sinks
/// rather than one constant per call site: both go through
/// [`sanitize_advisory_text_for_diagnostic`] for the same reason (narrow-filtered free-form
/// prose that can legitimately carry RTL marks/emoji ZWJ), so a single cap keeps their
/// behavior in lockstep instead of letting two near-duplicate constants drift apart.
///
/// Mirrors [`MAX_DIAGNOSTIC_VALUE_CHARS`]'s bound (issue #1278). `advisory.summary` and
/// `deprecation.reason` are both genuinely untrusted, unbounded-length prose — OSV.dev
/// aggregates GHSA/RustSec/PyPA advisory databases plus community submissions, and
/// `summary`/a registry's deprecation `reason` both pass through unvalidated
/// (`OsvVulnRecord::into_advisory`, resp. the registry client). `advisory.id` is *not*
/// actually unbounded on the real path: `into_advisory` already rejects any record whose id
/// fails `crate::osv::is_valid_osv_id` (ASCII alphanumeric/`.`/`_`/`-`, `<= 128` bytes) before
/// an `Advisory` can exist, so this cap on `id` is defense-in-depth for a state that should
/// already be unreachable, not a fix for a reachable gap.
///
/// `pub(crate)`, not module-private: `lsp_helpers::hover`'s `push_vulnerability_hover_section`
/// (#1272) shares this exact bound for the same `advisory.summary` field rather than declaring
/// its own duplicate constant, per this project's shared-constant DRY rule. Kept as its own
/// named constant rather than folded into [`MAX_DIAGNOSTIC_VALUE_CHARS`] directly at each call
/// site (issue #1278) — its name documents "this is free-form prose" at every use, which a
/// bare `MAX_DIAGNOSTIC_VALUE_CHARS` would not. Deriving its value from that shared constant
/// is numeric convenience today (one literal `128` to change), not a semantic guarantee the
/// two bounds must always match — a future change tightening
/// [`MAX_DIAGNOSTIC_VALUE_CHARS`] for a URL/identifier-shaped value would silently also
/// shrink this prose bound with no test catching the coupling; give this constant its own
/// literal if that ever needs to be decoupled.
pub(crate) const MAX_DIAGNOSTIC_PROSE_CHARS: usize = MAX_DIAGNOSTIC_VALUE_CHARS;

/// Truncates `value` to at most `max_chars` characters, appending `…` when truncated.
///
/// So an attacker-controlled string interpolated into a diagnostic message can never
/// render an unbounded amount of text inline in the editor. Counts characters, not bytes,
/// so a truncation point never lands mid-character (`value` may contain multi-byte
/// UTF-8). `pub`, not module-private: `deps-github-actions`' mutable-ref-pin diagnostic
/// (issue #473) reuses this same chokepoint for its own attacker-controlled `name`/`tag`
/// interpolation, rather than duplicating the truncation logic in a second crate.
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::truncate_for_diagnostic;
///
/// assert_eq!(truncate_for_diagnostic("short", 128), "short");
/// assert_eq!(truncate_for_diagnostic(&"a".repeat(200), 5), "aaaaa…");
/// ```
pub fn truncate_for_diagnostic(value: &str, max_chars: usize) -> std::borrow::Cow<'_, str> {
    if value.chars().count() <= max_chars {
        return std::borrow::Cow::Borrowed(value);
    }
    let mut truncated: String = value.chars().take(max_chars).collect();
    truncated.push('…');
    std::borrow::Cow::Owned(truncated)
}

/// Maximum character count of a dependency name interpolated into an unknown-package
/// diagnostic message (R5a/R5c/R5d), a `deps-cli` finding's `dependency_name` field, or
/// the hover header's link label, before it is truncated with an ellipsis marker
/// (#1242, #1246, #1259 critic S4).
///
/// Mirrors [`MAX_DIAGNOSTIC_VALUE_CHARS`]'s bound (issue #1278): [`PackageName`] itself is
/// deliberately unvalidated (see its own doc), so a manifest key of unbounded length would
/// otherwise reach these sinks unbounded too.
///
/// `pub(crate)`, not module-private: `lsp_helpers::hover`'s header label (#1259 critic
/// S4) shares this exact bound rather than declaring its own duplicate constant, per
/// this project's shared-constant DRY rule — the same reasoning
/// [`MAX_VERSION_DIAGNOSTIC_CHARS`]'s doc gives for its own `inlay_hints` reuse. Kept as its
/// own named constant rather than folded into [`MAX_DIAGNOSTIC_VALUE_CHARS`] directly at each
/// call site — its name documents "this is an identifier" at every use. Deriving its value
/// from that shared constant is numeric convenience today, not a semantic guarantee the two
/// bounds must always match (see [`MAX_DIAGNOSTIC_PROSE_CHARS`]'s doc for the concrete
/// drift scenario this note is guarding against).
pub(crate) const MAX_DIAGNOSTIC_NAME_CHARS: usize = MAX_DIAGNOSTIC_VALUE_CHARS;

/// Maximum character count of a version-shaped string (a manifest-declared requirement,
/// a lockfile-resolved version, or a registry-reported yanked/latest version)
/// interpolated into a diagnostic message or inlay-hint label before it is truncated
/// with an ellipsis marker (#1263, #1268).
///
/// Mirrors [`MAX_DIAGNOSTIC_NAME_CHARS`]'s bound: `req_str` comes from the parsed manifest,
/// `yanked_version`/`latest` come from registry version data, and a lockfile-resolved
/// version comes from a cloned repository's lock file — none of these are validated or
/// length-capped before reaching these sinks, and all are also missing
/// [`sanitize_invisible`]'s bidi/invisible-character neutralization before this fix.
///
/// `pub(crate)`, not module-private: `lsp_helpers::inlay_hints`' "update available"/"up
/// to date"/offline-marker labels (#1268) share this exact bound rather than declaring
/// their own duplicate constant, per this project's shared-constant DRY rule. Kept as its
/// own named constant rather than folded into [`MAX_DIAGNOSTIC_VALUE_CHARS`] directly at
/// each call site (issue #1278) — its name documents "this is a version string" at every
/// use. Deriving its value from that shared bound is numeric convenience today, not a
/// semantic guarantee the two must always match (see [`MAX_DIAGNOSTIC_PROSE_CHARS`]'s doc
/// for the concrete drift scenario this note is guarding against).
pub(crate) const MAX_VERSION_DIAGNOSTIC_CHARS: usize = MAX_DIAGNOSTIC_VALUE_CHARS;

/// Renders `name` safely for a client-visible diagnostic message or `dependency_name`-shaped
/// field (#1242, #1246): redact, then sanitize, then truncate, in that order.
///
/// 1. [`redact_declaration_key`] collapses a credential-shaped value (e.g. a manifest key
///    that turned out to hold `https://user:TOKEN@host/path`) to `***@host/...` first —
///    truncating before this step could cut the string exactly at the boundary the
///    credential-shape scan depends on, leaking a credential that straddles the cut (the
///    same ordering [`crate::redact::redact_parse_error_for_log`] uses, #1240).
/// 2. [`sanitize_invisible`] then neutralizes any remaining control/format character (in the
///    host/path remainder, or on the non-credential branch) that could splice a fabricated
///    line into a table row or forge a bidi-spoofed display name (#1246).
/// 3. [`truncate_for_diagnostic`] bounds the result so an oversized manifest key cannot
///    produce an unbounded diagnostic, JSON, or SARIF payload.
///
/// Takes `&PackageName` rather than `&str` so the type system itself blocks a future call
/// site from reintroducing a raw, unredacted `.as_str()` at one of these sinks.
///
/// # Examples
///
/// ```
/// use deps_core::PackageName;
/// use deps_core::lsp_helpers::redact_name_for_diagnostic;
///
/// let name = PackageName::new("serde");
/// assert_eq!(redact_name_for_diagnostic(&name), "serde");
///
/// let name = PackageName::new("https://svcacct:hunter2@gitlab.corp/g/p");
/// assert_eq!(redact_name_for_diagnostic(&name), "https://***@gitlab.corp/g/p");
/// ```
#[must_use]
pub fn redact_name_for_diagnostic(name: &PackageName) -> String {
    sanitize_and_truncate_for_diagnostic(
        &redact_declaration_key(name.as_str()),
        MAX_DIAGNOSTIC_NAME_CHARS,
    )
}

/// Renders `req` safely for a client-visible diagnostic message or `requirement`-shaped
/// field (#1258, #1300).
///
/// The same redact-then-sanitize-then-truncate pipeline [`redact_name_for_diagnostic`]
/// applies to a package name, reused here for a version requirement so the two sinks can't
/// drift apart. A requirement is not normally credential-bearing, but some ecosystems'
/// requirement syntax can embed a full URL (e.g. a git/VCS-pinned dependency) with an
/// authority-bearing credential in it, so the [`redact_declaration_key`] step stays
/// defense-in-depth here rather than being dropped as unnecessary. Shares
/// `MAX_VERSION_DIAGNOSTIC_CHARS` with `deps-core`'s own `inlay_hints`/diagnostic-message
/// uses of a version-shaped string, rather than a second, ad hoc cap declared at the call
/// site.
///
/// # Examples
///
/// ```
/// use deps_core::VersionReq;
/// use deps_core::lsp_helpers::redact_requirement_for_diagnostic;
///
/// let req = VersionReq::new("^1.0");
/// assert_eq!(redact_requirement_for_diagnostic(&req), "^1.0");
///
/// let req = VersionReq::new("https://svcacct:hunter2@gitlab.corp/g/p.git");
/// assert_eq!(
///     redact_requirement_for_diagnostic(&req),
///     "https://***@gitlab.corp/g/p.git"
/// );
/// ```
#[must_use]
pub fn redact_requirement_for_diagnostic(req: &VersionReq) -> String {
    sanitize_and_truncate_for_diagnostic(
        &redact_declaration_key(req.as_str()),
        MAX_VERSION_DIAGNOSTIC_CHARS,
    )
}

/// Sanitizes then truncates `value` for a client-visible diagnostic message,
/// `CodeAction` title, or similar single-line surface (#1252).
///
/// For a plain `&str` sink that is not a [`PackageName`] (e.g. a mutable-ref tag, a
/// host string) and so cannot go through [`redact_name_for_diagnostic`] — this applies
/// the same [`sanitize_invisible`]-then-[`truncate_for_diagnostic`] tail of that
/// pipeline without the [`redact_declaration_key`] step, which only makes sense for a
/// name-shaped, potentially credential-bearing value.
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::sanitize_and_truncate_for_diagnostic;
///
/// assert_eq!(sanitize_and_truncate_for_diagnostic("v1.0.0", 128), "v1.0.0");
/// assert_eq!(
///     sanitize_and_truncate_for_diagnostic("bidi\u{202E}tag", 128),
///     "bidi tag"
/// );
/// ```
#[must_use]
pub fn sanitize_and_truncate_for_diagnostic(value: &str, max_chars: usize) -> String {
    truncate_for_diagnostic(&sanitize_invisible(value), max_chars).into_owned()
}

/// Narrow-filters, then truncates, `value` for the OSV advisory `id`/`summary` sinks in
/// `push_vulnerability_diagnostics` (#1262).
///
/// Deliberately uses `super::replace_markdown_unsafe_chars`'s narrow, explicit bidi/
/// invisible-character list (shared with [`crate::lsp_helpers::markdown_code_span`], so the
/// two can't drift) instead of [`sanitize_invisible`]'s whole-`Cf`/`Zl`/`Zp` category sweep: an OSV
/// advisory `summary` is free-form prose aggregated from GHSA/RustSec/PyPA plus community
/// submissions, and can legitimately carry right-to-left marks (U+200F, U+061C) or emoji ZWJ
/// sequences (U+200D) that a category-wide strip would mangle — the same rationale
/// [`crate::lsp_helpers::escape_markdown`] documents for reusing that narrower filter on
/// registry-supplied free text.
///
/// `summary` is the genuinely untrusted half of this sink — it passes through
/// `OsvVulnRecord::into_advisory` unvalidated. `id` is run through the same treatment for
/// defense-in-depth, but on the real path it is already constrained by
/// `crate::osv::is_valid_osv_id` (ASCII alphanumeric/`.`/`_`/`-`, `<= 128` bytes) before an
/// `Advisory` can exist at all, so this call is a no-op for `id` in practice.
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::sanitize_advisory_text_for_diagnostic;
///
/// assert_eq!(sanitize_advisory_text_for_diagnostic("RUSTSEC-2024-0001", 128), "RUSTSEC-2024-0001");
/// assert_eq!(
///     sanitize_advisory_text_for_diagnostic("bidi\u{202E}summary", 128),
///     "bidi summary"
/// );
/// ```
#[must_use]
pub fn sanitize_advisory_text_for_diagnostic(value: &str, max_chars: usize) -> String {
    truncate_for_diagnostic(&super::replace_markdown_unsafe_chars(value), max_chars).into_owned()
}

/// Stable [`Diagnostic::code`] set on the package-level deprecation diagnostic (issue #205).
///
/// Mirrors [`UNSATISFIABLE_DIAGNOSTIC_CODE`] — lets `build_replacement_action`'s stashed
/// `CodeAction::data` name it so the `deps-lsp` handler's diagnostic-binding step can
/// attach the "Replace with X" quickfix to the diagnostic it resolves.
pub const DEPRECATED_DIAGNOSTIC_CODE: &str = "deprecated-package";

/// Diagnostic severity levels for the four per-dependency issue categories.
///
/// Threaded from `DiagnosticsConfig` (`deps-lsp`) through
/// [`crate::Ecosystem::generate_diagnostics`] into [`generate_diagnostics_from_cache`].
///
/// Since this type is `#[non_exhaustive]`, `deps_lsp::config::DiagnosticsConfig::to_severities`
/// builds one via [`Self::new`] plus a `with_*` chain rather than a struct literal — adding a
/// field here no longer forces that mapping to update at compile time. A new field must be
/// wired into `to_severities` by hand, or it silently keeps [`Self::new`]'s default forever.
///
/// # Examples
///
/// ```
/// use deps_core::DiagnosticSeverities;
/// use deps_core::diagnostic::Severity;
///
/// let severities = DiagnosticSeverities::default();
/// assert_eq!(severities.outdated, Severity::Hint);
/// assert_eq!(severities.unknown, Severity::Warning);
/// assert_eq!(severities.yanked, Severity::Warning);
/// assert_eq!(severities.unsatisfiable, Severity::Warning);
/// assert_eq!(severities.deprecated, Severity::Warning);
/// assert_eq!(severities.mutable_ref_pin, Severity::Hint);
/// assert!(severities.mutable_ref_pin_enabled);
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiagnosticSeverities {
    /// Severity for a dependency with a newer version available.
    pub outdated: Severity,
    /// Severity for a dependency not found in the registry (or with an invalid name).
    pub unknown: Severity,
    /// Severity for a dependency pinned to a yanked/deprecated version.
    pub yanked: Severity,
    /// Severity for a dependency whose requirement matches zero published versions.
    pub unsatisfiable: Severity,
    /// Severity for a dependency on a package the registry reports as
    /// deprecated/abandoned (issue #205).
    pub deprecated: Severity,
    /// Severity for a dependency pinned to a mutable ref (a tag or branch) instead of a
    /// full commit SHA (issue #473, extended to GitLab CI by issue #634). Unused except by
    /// `deps-github-actions` and `deps-gitlab-ci` today — see each crate's own
    /// `MUTABLE_REF_PIN_DIAGNOSTIC_CODE` for the diagnostic this severity gates.
    /// Tunes loudness only; see [`Self::mutable_ref_pin_enabled`] for the on/off
    /// toggle.
    pub mutable_ref_pin: Severity,
    /// Whether the mutable-ref-pin diagnostic (issue #473, extended to GitLab CI by issue
    /// #634) runs at all, unused except by `deps-github-actions` and `deps-gitlab-ci`.
    /// Unlike every other field in this struct, `mutable_ref_pin` alone cannot silence the
    /// diagnostic — `Severity` has no suppression value, and severity is never
    /// treated as a suppression input anywhere in this codebase — so this diagnostic
    /// additionally needs a real presence toggle, mirroring
    /// `deps_lsp::config::DiagnosticsConfig::vulnerabilities_enabled`'s shape.
    pub mutable_ref_pin_enabled: bool,
}

impl Default for DiagnosticSeverities {
    fn default() -> Self {
        Self::new()
    }
}

impl DiagnosticSeverities {
    /// Builds the default severity set (mirrors [`Self::default`], as an inherent `const fn`
    /// usable in const context — the `Default` trait itself cannot be `const` on stable Rust).
    ///
    /// Needed because [`Self`] is `#[non_exhaustive]`: a struct literal (including
    /// functional-update syntax, e.g. `DiagnosticSeverities { outdated: X, ..Default::default() }`)
    /// only works inside this crate, so every other crate must chain the `with_*` setters onto
    /// this constructor instead.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::DiagnosticSeverities;
    /// use deps_core::diagnostic::Severity;
    ///
    /// let severities = DiagnosticSeverities::new().with_outdated(Severity::Error);
    /// assert_eq!(severities.outdated, Severity::Error);
    /// ```
    #[must_use]
    pub const fn new() -> Self {
        Self {
            outdated: Severity::Hint,
            unknown: Severity::Warning,
            yanked: Severity::Warning,
            unsatisfiable: Severity::Warning,
            deprecated: Severity::Warning,
            mutable_ref_pin: Severity::Hint,
            mutable_ref_pin_enabled: true,
        }
    }

    /// Overrides [`Self::outdated`]. See [`Self::new`] for the baseline every other
    /// field keeps unless also overridden.
    #[must_use]
    pub const fn with_outdated(mut self, outdated: Severity) -> Self {
        self.outdated = outdated;
        self
    }

    /// Overrides [`Self::unknown`]. See [`Self::with_outdated`].
    #[must_use]
    pub const fn with_unknown(mut self, unknown: Severity) -> Self {
        self.unknown = unknown;
        self
    }

    /// Overrides [`Self::yanked`]. See [`Self::with_outdated`].
    #[must_use]
    pub const fn with_yanked(mut self, yanked: Severity) -> Self {
        self.yanked = yanked;
        self
    }

    /// Overrides [`Self::unsatisfiable`]. See [`Self::with_outdated`].
    #[must_use]
    pub const fn with_unsatisfiable(mut self, unsatisfiable: Severity) -> Self {
        self.unsatisfiable = unsatisfiable;
        self
    }

    /// Overrides [`Self::deprecated`]. See [`Self::with_outdated`].
    #[must_use]
    pub const fn with_deprecated(mut self, deprecated: Severity) -> Self {
        self.deprecated = deprecated;
        self
    }

    /// Overrides [`Self::mutable_ref_pin`]. See [`Self::with_outdated`].
    #[must_use]
    pub const fn with_mutable_ref_pin(mut self, mutable_ref_pin: Severity) -> Self {
        self.mutable_ref_pin = mutable_ref_pin;
        self
    }

    /// Overrides [`Self::mutable_ref_pin_enabled`]. See [`Self::with_outdated`].
    #[must_use]
    pub const fn with_mutable_ref_pin_enabled(mut self, mutable_ref_pin_enabled: bool) -> Self {
        self.mutable_ref_pin_enabled = mutable_ref_pin_enabled;
        self
    }
}

/// Shared shape for a [`crate::lsp_helpers::RequirementResolution::compile_requirement`] guarded by one predicate.
///
/// This is the pattern several ecosystems' guards independently re-implemented
/// (`deps-go`'s pseudo-version check, `deps-composer`'s dev-branch/`@dev` check,
/// `deps-bundler`'s exact-pin check, `deps-maven`/`deps-gradle`'s malformed-range check,
/// `deps-nuget`'s malformed-requirement check). See
/// [`crate::lsp_helpers::RequirementResolution::compile_requirement`]'s docs for why `None` is correct in exactly
/// this case: `is_undecidable(requirement)` true means the fetched `available` list
/// structurally cannot contain a version that would decide the match either way, so scanning
/// it would always report `Some(false)` and produce a false "no published version satisfies
/// this requirement" diagnostic.
///
/// Returns `None` when `is_undecidable(requirement)` is `true`. Otherwise builds `matcher`
/// from `requirement`'s owned `String` and boxes it as the trait object
/// [`crate::lsp_helpers::RequirementResolution::compile_requirement`] returns.
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
/// use deps_core::lsp_helpers::{
///     requirement_is_unsatisfiable, DiagnosticMessages, DiagnosticPolicy, OsvNaming,
///     PackageNaming, PackageRendering, RequirementMatcher, RequirementResolution, SourcePolicy,
/// };
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
/// impl PackageNaming for ExactFormatter {}
/// impl PackageRendering for ExactFormatter {
///     fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
///         version.to_string()
///     }
///     fn package_url(&self, name: &PackageName) -> String {
///         name.as_str().to_string()
///     }
/// }
/// impl RequirementResolution for ExactFormatter {
///     fn compile_requirement(
///         &self,
///         requirement: &VersionReq,
///     ) -> Option<Box<dyn RequirementMatcher>> {
///         Some(Box::new(ExactMatcher(requirement.as_str().to_string())))
///     }
/// }
/// impl DiagnosticMessages for ExactFormatter {}
/// impl DiagnosticPolicy for ExactFormatter {}
/// impl SourcePolicy for ExactFormatter {}
/// impl OsvNaming for ExactFormatter {}
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
/// [`crate::lsp_helpers::DiagnosticPolicy::strict_semver_prerelease_exclusion`]), whose registries only
/// publish spec-conformant version strings.
#[expect(
    clippy::string_slice,
    reason = "dash comes from str::find('-'), an ASCII byte, so it is always a char boundary"
)]
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
#[expect(
    clippy::indexing_slicing,
    reason = "i > 0 and i + 1 < bytes.len() guard bytes[i - 1]/bytes[i + 1] respectively"
)]
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
/// [`crate::lsp_helpers::DiagnosticPolicy::strict_semver_prerelease_exclusion`]), finds the newest published,
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
    yanked: &[(ConcreteVersion, RemovalStatus)],
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
        (!yanked.iter().any(|(y, _)| y == candidate)
            && matcher.matches(&ConcreteVersion::new(base)) == Some(true))
        .then(|| candidate.to_string())
    })
}

/// Looks up `candidate`'s [`RemovalStatus`] in `yanked`, preferring `Yanked` over
/// `AdvisoryDeprecated` when more than one entry shares `candidate`'s version string.
///
/// A registry response can carry duplicate entries for the same version string (see
/// `lifecycle.rs`'s in-use-version scan, which guards against exactly this by not stopping
/// at the first same-string match). `RemovalStatus` derives no `Ord`, so this can't be a
/// `.max()` — `Yanked` is explicitly preferred so a mixed-status duplicate never hides a
/// genuine hard yank behind a merely-deprecated entry for the same version (#437 M2).
fn status_for_version(
    yanked: &[(ConcreteVersion, RemovalStatus)],
    candidate: &ConcreteVersion,
) -> Option<RemovalStatus> {
    let mut found: Option<RemovalStatus> = None;
    for (y, status) in yanked {
        if y == candidate {
            if *status == RemovalStatus::Yanked {
                return Some(RemovalStatus::Yanked);
            }
            found = Some(*status);
        }
    }
    found
}

/// Returns the aggregate [`RemovalStatus`] when `requirement` is satisfied by at least one
/// entry in `available`, but every matching entry is yanked/deprecated — i.e. the dependency
/// is currently satisfiable only by a flagged version — and `None` otherwise.
///
/// The aggregate is `Yanked` if any matching entry's status is `Yanked`, else
/// `AdvisoryDeprecated` (the only other status `yanked` entries carry — see
/// [`PackageVersions::yanked`]). This lets the caller apply the same D5 gate #263 uses
/// (see [`crate::lsp_helpers::DependencyOutcome::yanked`]'s docs): suppress the diagnostic for an `AdvisoryDeprecated`
/// aggregate when a package-level deprecation finding co-occurs, but never for a `Yanked`
/// one, even if one of several matching entries is merely deprecated (#437).
///
/// Mutually exclusive with [`requirement_is_unsatisfiable`]: both scan `available` through the
/// same `formatter.compile_requirement` matcher, but this one additionally cross-references
/// `yanked` to distinguish "satisfied, but only by a flagged version" from "satisfied by an
/// ordinary version" or "not satisfied at all". Callers should only invoke this once
/// `requirement_is_unsatisfiable` has returned `false` for the same `requirement`/`available`
/// pair, so a match is already known to exist.
///
/// Shares `requirement_is_unsatisfiable`'s guard cascade (empty `available`/`requirement`,
/// oversized `requirement`, unresolved placeholder `requirement`, uncompilable `requirement`)
/// — each returns `None` here for the identical reason it does there.
///
/// Unlike `requirement_is_unsatisfiable`, an undecided candidate (`matcher.matches` returns
/// `None` — an unparseable candidate string) does not just get skipped: it disqualifies a
/// verdict entirely. That candidate might have been a genuine non-yanked match this scan
/// simply could not evaluate, so claiming "every match is flagged" without accounting for it
/// would be a false positive — the same #206 conservatism (nothing decided means no
/// diagnostic, not a guess) applied to a different question than `requirement_is_unsatisfiable`
/// asks.
fn requirement_matches_only_yanked(
    formatter: &dyn EcosystemFormatter,
    requirement: &VersionReq,
    available: &[ConcreteVersion],
    yanked: &[(ConcreteVersion, RemovalStatus)],
) -> Option<RemovalStatus> {
    if available.is_empty() || yanked.is_empty() || requirement.as_str().trim().is_empty() {
        return None;
    }
    if requirement.as_str().len() > MAX_REQUIREMENT_LEN {
        return None;
    }
    if formatter.requirement_is_unresolved(requirement) {
        return None;
    }
    let matcher = formatter.compile_requirement(requirement)?;

    let mut saw_match = false;
    let mut saw_undecided = false;
    let mut aggregate: Option<RemovalStatus> = None;
    for candidate in available {
        match matcher.matches(candidate) {
            Some(true) => {
                saw_match = true;
                let status = status_for_version(yanked, candidate)?;
                if aggregate != Some(RemovalStatus::Yanked) {
                    aggregate = Some(status);
                }
            }
            Some(false) => {}
            None => saw_undecided = true,
        }
    }
    if saw_match && !saw_undecided {
        aggregate
    } else {
        None
    }
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
/// * `uri` - Document URI, used only to anchor the [`crate::diagnostic::RelatedInformation`]
///   entries attached to a collapsed fetch-failure diagnostic (#479/#480 S2) — every other
///   diagnostic here is scoped to the document it's published under implicitly and doesn't
///   need it
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
    uri: &url::Url,
    freshness: crate::freshness::FreshnessSettings,
    severities: DiagnosticSeverities,
    now: PublishTime,
) -> Vec<Diagnostic> {
    let deps = parse_result.dependencies();
    let mut diagnostics = Vec::with_capacity(deps.len());
    // Buffered separately (#479) so 2+ near-identical fetch failures collapse into one
    // diagnostic while still naming every dependency and keeping any `Actionable` hint (#478/#485).
    let mut fetch_failed: Vec<FetchFailureEntry> = Vec::new();

    dependency_ceiling_notice(&mut diagnostics, parse_result);
    offline_notice(&mut diagnostics, versions, &deps);
    blocked_registry_diagnostics(&mut diagnostics, parse_result, &deps);

    // #394 S2: version-qualified OSV lookup keys, so two occurrences of one name pinned to
    // different versions never share a `Vulnerable`/`Clean` result; `None` falls back to plain-name lookup.
    let vuln_keys = versions.ecosystem.map(|ecosystem| {
        crate::osv::vulnerability_keys(
            parse_result,
            versions.resolved,
            versions.resolved_version_candidates,
            formatter,
            ecosystem,
        )
    });

    for dep in deps {
        // Critic S1 (#905): a synthetic `name_range()` has no real document position, and every
        // rule below anchors on it — skip diagnostics entirely rather than stack on a sentinel range.
        if dep.name_range_is_synthetic() {
            continue;
        }

        let normalized_name = formatter.normalize_package_name(dep.name());
        let ctx = RuleContext {
            dep,
            normalized_name: &normalized_name,
            versions,
            formatter,
            severities,
            freshness,
            now,
        };

        // R2, R3, R4 run before both terminal guards below: an OSV / deprecation / in-use-yanked
        // finding must never be hidden by an unrelated "latest" lookup failure (FR-007/US-004).
        apply_vulnerability_rule(&mut diagnostics, &ctx, vuln_keys.as_ref());
        apply_license_policy_rule(&mut diagnostics, &ctx);
        let deprecation_found = apply_deprecation_rule(&mut diagnostics, &ctx);
        let in_use_yanked_emitted =
            apply_in_use_yanked_rule(&mut diagnostics, &ctx, deprecation_found);

        let Some(package_versions) = ctx.cached_versions() else {
            apply_unknown_package_rule(&mut diagnostics, &mut fetch_failed, &ctx);
            continue;
        };

        // Every rule below anchors its diagnostic on the declared version range.
        let Some(version_range) = dep.version_range() else {
            continue;
        };
        let version_range: Range = version_range;
        let resolved = ResolvedData {
            package_versions,
            version_range,
        };

        if apply_unsatisfiable_rule(&mut diagnostics, &ctx, &resolved) == RuleFlow::Stop {
            continue;
        }
        if apply_yanked_only_rule(
            &mut diagnostics,
            &ctx,
            &resolved,
            YankedOnlyPrior {
                deprecation_found,
                in_use_yanked_emitted,
            },
        ) == RuleFlow::Stop
        {
            continue;
        }
        apply_outdated_rule(&mut diagnostics, &ctx, &resolved);
    }

    push_collapsed_fetch_failures(&mut diagnostics, fetch_failed, uri);
    diagnostics
}

/// Per-dependency inputs every rule in the pipeline reads.
///
/// Bundled so each rule takes one borrow instead of re-threading seven parameters (and so
/// no rule can read state a later refactor forgot to pass it). `VersionData<'a>`,
/// [`crate::freshness::FreshnessSettings`], and [`PublishTime`] are all `Copy`, so
/// `RuleContext` is held by value.
struct RuleContext<'a> {
    dep: &'a dyn Dependency,
    /// `formatter.normalize_package_name(dep.name())`, computed once per dependency
    /// because five rules key their lookups on it.
    normalized_name: &'a str,
    versions: VersionData<'a>,
    formatter: &'a dyn EcosystemFormatter,
    severities: DiagnosticSeverities,
    /// Whether an "outdated" diagnostic's message should differentiate a release
    /// still within its cooldown window (issue #227 §4.3). Read only by
    /// [`apply_outdated_rule`].
    freshness: crate::freshness::FreshnessSettings,
    /// The instant every publish age in this call is aged against. Read only by
    /// [`apply_outdated_rule`].
    now: PublishTime,
}

impl<'a> RuleContext<'a> {
    /// The registry cache entry for this dependency, tried under the normalized name
    /// first and the declared name second. `None` routes the dependency into the
    /// unknown-package family (R5) and ends its evaluation.
    fn cached_versions(&self) -> Option<&'a PackageVersions> {
        self.versions
            .cached
            .get(self.normalized_name)
            .or_else(|| self.versions.cached.get(self.dep.name()))
    }
}

/// The registry-derived inputs the post-lookup rules (R6a, R6b, R7) share.
///
/// Constructing one requires both a cache hit (see [`RuleContext::cached_versions`])
/// and a declared version range, so a rule that reads either cannot be moved above the
/// guards that produce them.
struct ResolvedData<'a> {
    package_versions: &'a PackageVersions,
    version_range: Range,
}

/// Whether the per-dependency pipeline continues past a rule that is allowed to
/// suppress its successors.
///
/// Only rules that end the dependency's evaluation return this. The #263
/// in-use-version-yanked check (R4) deliberately does **not** return it — it must
/// co-emit with the outdated rule (R7) — so it cannot acquire suppression power
/// without a signature change a reviewer will see. With every rule otherwise
/// returning a plain `bool`, "emitted, does not stop" (R4) and "emitted, stops" (R6a/
/// R6b) would be indistinguishable at the call site — the #437-class confusion this
/// type exists to make visible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuleFlow {
    /// Evaluate the next rule for this dependency.
    Continue,
    /// Suppress every remaining rule for this dependency.
    Stop,
}

/// One buffered fetch-failure finding, collapsed by [`push_collapsed_fetch_failures`]
/// (R8).
///
/// `name` and `failure` are kept alongside the built `diagnostic` because the collapse
/// must still name every affected dependency (`related_information`) and must never
/// drop an `Actionable` hint (#478/#485) just because #479's collapse kicked in.
struct FetchFailureEntry {
    name: String,
    diagnostic: Diagnostic,
    failure: Option<FetchFailure>,
}

/// The two upstream-rule facts [`apply_yanked_only_rule`] gates on.
///
/// Bundled solely so its one construction site (in the orchestrator) uses Rust's
/// field-named struct-literal syntax instead of two adjacent positional `bool`
/// arguments — field-name binding is order-independent, so it rules out a silent
/// argument swap the same way [`offline_notice`]'s `versions`/`deps` parameters do for
/// its own two bools. Not threaded any further than that one call site. This is a
/// different fix than the `PriorFindings` struct an earlier draft of this refactor
/// used and the implementation critic had removed (M1): that one was rejected for a
/// false *conflation* safety claim ("mixing up which finding fed which field can't
/// happen"), not for this *argument-order* concern, and it was also passed as a
/// parameter to a second function beyond its one true reader — this type is not.
struct YankedOnlyPrior {
    deprecation_found: bool,
    in_use_yanked_emitted: bool,
}

/// Dependency-count-ceiling notice (#796).
///
/// Not part of the R0-R8 per-dependency pipeline below: a manifest whose dependency
/// count exceeded `deps-lsp`'s per-document ceiling
/// ([`crate::dependency_cap::MAX_DEPENDENCIES_PER_DOCUMENT`]) already had
/// `ParseResult::dependencies` truncated by `ecosystem::parse_manifest_blocking` before
/// this function ever saw it — every rule below only evaluates the retained subset. This
/// surfaces that truncation instead of leaving it silent, using the same file-level
/// `Position(0,0)` placement as [`offline_notice`], and runs first so it precedes every
/// other diagnostic in the returned `Vec`.
///
/// Reads: `parse_result.dependency_truncation()`.
/// Emits: at most one [`Severity::Information`].
fn dependency_ceiling_notice(diagnostics: &mut Vec<Diagnostic>, parse_result: &dyn ParseResult) {
    if let Some((kept, total)) = parse_result.dependency_truncation() {
        diagnostics.push(
            Diagnostic::new(
                Range {
                    start: Position::new(0, 0),
                    end: Position::new(0, 0),
                },
                format!(
                    "manifest declares {total} dependencies, exceeding deps-lsp's per-document \
                     limit of {kept}; only the first {kept} are tracked, fetched, and checked \
                     against the registry"
                ),
            )
            .with_severity(Severity::Information),
        );
    }
}

/// R0 — file-level "offline" notice (#483 S2/I2).
///
/// `network.offline` silently degrades every diagnostic in this pipeline that depends
/// on a registry/OSV fetch — vulnerabilities never queried, "unknown"/"outdated"/
/// deprecation checks all working from whatever was already cached. Absence of a
/// warning must not read as "safe" in this *persistent, user-configured* mode. One
/// file-level diagnostic, not per-dependency: emitting one per affected dependency
/// (the per-dependency fetch-failure arm inside [`apply_unknown_package_rule`] is
/// suppressed while offline for exactly this reason, R5b below) would be strictly
/// noisier than the failure toast this same PR suppresses for being "unusable" — the
/// two must not contradict each other.
///
/// Reads: `versions.offline`, `deps` (only to check non-emptiness — takes the slice
/// itself, not two positional bools, so a caller can never silently swap them).
/// Emits: at most one [`Severity::Information`] at `Position(0,0)`, appended
/// first so it always precedes every other diagnostic in the returned `Vec`.
/// Suppressed by: nothing. Suppresses: R5b (see [`apply_unknown_package_rule`]).
fn offline_notice(
    diagnostics: &mut Vec<Diagnostic>,
    versions: VersionData<'_>,
    deps: &[&dyn Dependency],
) {
    if versions.offline && !deps.is_empty() {
        diagnostics.push(
            Diagnostic::new(
                Range {
                    start: Position::new(0, 0),
                    end: Position::new(0, 0),
                },
                "deps-lsp is offline (network.offline): dependency and vulnerability data \
                 reflects only what was already cached, not the current registry state",
            )
            .with_severity(Severity::Information),
        );
    }
}

/// R1 — blocked-registry notices (#443/plan-1b §1.7).
///
/// A registry index blocked by `registries.workspace_registries` must not degrade silently.
/// Independent of the dependency loop below: a blocked dependency never reaches
/// version resolution, so it would otherwise leave no trace at all in the editor.
///
/// Reads: `parse_result.blocked_registries()`.
/// Emits: one [`Severity::Information`] per **distinct declaration key**, anchored
/// at the first affected dependency's range — message truncated at
/// [`MAX_DIAGNOSTIC_VALUE_CHARS`]. Every *other* dependency sharing that
/// declaration key survives via `related_information` on that same diagnostic, up to
/// [`MAX_BLOCKED_REGISTRY_RELATED_INFO`] named individually plus a trailing "+N more" entry
/// beyond that (#944 M8/S2; see [`push_collapsed_blocked_registries`]) rather than being
/// silently dropped. Pushed after R0, before any per-dependency diagnostic.
/// Suppressed by: nothing. Suppresses: nothing.
///
/// Grouped by declaration key, not by `(host class, raw value)` (#925 S2, then corrected by a
/// later code-review pass): a config-global declaration (e.g. a single blocked npm `.npmrc`
/// top-level `registry=` line, or one `NuGet.Config` `<add key>` source) applies identically
/// to every dependency it affects, so pushing one entry per *dependency* — as each ecosystem's
/// `ParseResult::blocked_registries()` does — can fan out to as many identical `INFORMATION`
/// diagnostics as dependencies affected (up to [`crate::MAX_DEPENDENCIES_PER_DOCUMENT`]) for
/// one underlying declaration. Grouping by `(host class, raw value)` instead of the
/// declaration key looked equivalent but was not: two *independently* declared sources that
/// merely happen to share a raw value and host class (e.g. an npm top-level `registry=` and an
/// unrelated `@scope:registry=`, both blocked to the same URL) would silently collapse to one
/// diagnostic, leaving every dependency routed through the second declaration with no
/// diagnostic at all — see [`ParseResult::blocked_registries`]'s own doc for why the key must
/// identify the declaration, never the value.
fn blocked_registry_diagnostics(
    diagnostics: &mut Vec<Diagnostic>,
    parse_result: &dyn ParseResult,
    deps: &[&dyn Dependency],
) {
    // #944 M3: `HashMap` grouping keeps this O(n); `order` preserves first-seen declaration-key
    // order so output stays deterministic independent of `HashMap` iteration order.
    let mut order: Vec<String> = Vec::new();
    let mut groups: HashMap<String, Vec<BlockedRegistryOccurrence>> = HashMap::new();
    for occurrence in parse_result.blocked_registries() {
        groups
            .entry(occurrence.declaration_key.clone())
            .or_insert_with(|| {
                order.push(occurrence.declaration_key.clone());
                Vec::new()
            })
            .push(occurrence);
    }
    if order.is_empty() {
        // #1242/#1246 perf follow-up: nothing is blocked (the common case) — skip building
        // `dependency_names` below, which would otherwise redact every dependency's name
        // unconditionally for a map no diagnostic will ever read.
        return;
    }

    // Built once, not per sibling occurrence (#944 M3), for `related_information` naming;
    // keyed on `Range` to match `BlockedRegistryOccurrence::range`'s type (#1071 S2). Redacted
    // via `redact_name_for_diagnostic` (#1242, #1246): this name reaches the same client-visible
    // `related_information` text as `FetchFailureEntry.name`.
    let dependency_names: HashMap<Range, String> = deps
        .iter()
        .map(|dep| (dep.name_range(), redact_name_for_diagnostic(dep.name())))
        .collect();

    for key in order {
        if let Some(entries) = groups.remove(&key) {
            push_collapsed_blocked_registries(
                diagnostics,
                entries,
                parse_result.uri(),
                &dependency_names,
            );
        }
    }
}

/// Builds the [`Diagnostic`] for one [`BlockedRegistryOccurrence`], anchored at its own range.
///
/// Includes `declaration_key` alongside `raw_value` (impl-critic M1 on #965/#966): without it,
/// two independently declared sources sharing the same `raw_value` — a real, intended shape,
/// see [`BlockedRegistryOccurrence::raw_value`]'s own doc — render as byte-identical messages,
/// even though each is its own diagnostic anchored at a different declaration.
fn build_blocked_registry_diagnostic(occurrence: &BlockedRegistryOccurrence) -> Diagnostic {
    // #936: redact before truncating so host/path stay identifiable while a query-string
    // credential never reaches this client-visible diagnostic.
    let redacted_value = RedactedUrl::new(&occurrence.raw_value).to_string();
    // `declaration_key` is opaque (e.g. "top-level") for most ecosystems and would be mangled
    // by an unconditional userinfo-scan, so redaction only runs when the key looks like a URL —
    // see `redact_declaration_key`'s own doc comment for the exact gate and its history (#981,
    // #993).
    let redacted_key = redact_declaration_key(&occurrence.declaration_key);
    Diagnostic::new(
        occurrence.range,
        format!(
            "registry index \"{}\" blocked by registries.workspace_registries policy \
             (host class: {}; declaration: {})",
            sanitize_and_truncate_for_diagnostic(&redacted_value, MAX_DIAGNOSTIC_VALUE_CHARS),
            occurrence.class,
            sanitize_and_truncate_for_diagnostic(&redacted_key, MAX_DIAGNOSTIC_VALUE_CHARS),
        ),
    )
    .with_severity(Severity::Information)
}

/// R1 collapse (#944 M8, capped per S2): mirrors [`push_collapsed_fetch_failures`]'s pattern so
/// two dependencies sharing one blocked declaration both stay discoverable, instead of the
/// second silently losing its diagnostic to dedup. `0` -> nothing. `1` -> the single diagnostic
/// verbatim. `n >= 2` -> one diagnostic anchored at the first occurrence's own range, with
/// `related_information` naming up to [`MAX_BLOCKED_REGISTRY_RELATED_INFO`] other affected
/// dependencies at their own range, plus a trailing "+N more" entry beyond that cap.
fn push_collapsed_blocked_registries(
    diagnostics: &mut Vec<Diagnostic>,
    entries: Vec<BlockedRegistryOccurrence>,
    uri: &url::Url,
    dependency_names: &HashMap<Range, String>,
) {
    #[expect(
        clippy::indexing_slicing,
        reason = "the 0/1 arms are matched separately, so this arm only runs with len() >= 2, \
                  making both entries[0] and the entries[1..] slice below valid"
    )]
    match entries.len() {
        0 => {}
        1 => diagnostics.extend(entries.iter().map(build_blocked_registry_diagnostic)),
        _ => {
            let diagnostic = build_blocked_registry_diagnostic(&entries[0]);
            let siblings = &entries[1..];
            let shown = siblings.len().min(MAX_BLOCKED_REGISTRY_RELATED_INFO);
            #[expect(
                clippy::indexing_slicing,
                reason = "shown is siblings.len().min(...), so siblings[..shown] is always \
                          in bounds"
            )]
            let mut related_information: Vec<RelatedInformation> = siblings[..shown]
                .iter()
                .map(|occurrence| {
                    let message = match dependency_names.get(&occurrence.range) {
                        Some(name) => {
                            format!("'{name}' also blocked by the same registry policy")
                        }
                        None => "also blocked by the same registry policy".to_string(),
                    };
                    RelatedInformation::new(uri.clone(), occurrence.range, message)
                })
                .collect();
            let remaining = siblings.len() - shown;
            if remaining > 0 {
                related_information.push(RelatedInformation::new(
                    uri.clone(),
                    diagnostic.range,
                    format!(
                        "and {remaining} more dependencies also blocked by the same registry \
                         policy"
                    ),
                ));
            }
            diagnostics.push(diagnostic.with_related_information(related_information));
        }
    }
}

/// R2 — OSV vulnerability findings (#394 S2, FR-007/US-004).
///
/// Emitted before either terminal guard in the orchestrator (registry outage, no
/// version range) so a registry failure never suppresses an OSV finding — the two are
/// independent data sources.
///
/// Reads: `ctx.versions.vulnerabilities`; `vuln_keys` looked up by `ctx.dep.name_range()`
/// (#394 S2, preferred), falling back to `ctx.normalized_name`, then `ctx.dep.name()` —
/// first `Some(ScanOutcome::Vulnerable(_))` wins.
/// Emits: N advisory diagnostics (in `dv.advisories.items()` order) plus an optional
/// "+N more advisories" entry, via [`push_vulnerability_diagnostics`].
/// Suppressed by: nothing — not gated on `can_resolve_source`.
/// Suppresses: nothing.
fn apply_vulnerability_rule(
    diagnostics: &mut Vec<Diagnostic>,
    ctx: &RuleContext<'_>,
    vuln_keys: Option<&HashMap<Range, String>>,
) {
    if let Some(vulnerabilities) = ctx.versions.vulnerabilities
        && let Some(ScanOutcome::Vulnerable(dv)) = vuln_keys
            .and_then(|keys| keys.get(&ctx.dep.name_range()))
            .and_then(|key| vulnerabilities.get(key))
            .or_else(|| vulnerabilities.get(ctx.normalized_name))
            .or_else(|| vulnerabilities.get(ctx.dep.name().as_str()))
    {
        push_vulnerability_diagnostics(diagnostics, ctx.dep, dv);
    }
}

/// R2a — SPDX license-policy violation (issue #661, spec 010 Phase 2).
///
/// Runs between R2 and R3 in the pipeline (not renumbered as R3 to avoid relabeling every
/// subsequent rule's doc comment) — independent of registry-cache lookup like R2/R3/R4, so
/// it must never be hidden by an unrelated "latest" lookup failure.
///
/// Reads: `ctx.versions.license_policy` — the gate; `None` (no policy configured) or an
/// empty policy means nothing to check. `deps-lsp`'s `handlers/diagnostics.rs::
/// generate_diagnostics_internal` attaches this unconditionally at every diagnostics-
/// generation call site (pull *and* push paths alike — see
/// [`super::VersionData::license_policy`]'s doc comment), so this is a no-op only when no
/// policy is actually configured. `ctx.versions.license_prefetch`, keyed by raw (unnormalized)
/// package name — today populated for tier-3 ecosystems only (Dart/Swift/Gradle/Deno, see
/// that field's own doc comment), but this rule makes no ecosystem-specific assumption and
/// needs no change as coverage widens. A dependency with no entry in `license_prefetch` is
/// silently skipped (NFR-003 graceful degradation) — there is no license data to evaluate,
/// which must never be treated as a violation.
/// Emits: at most one diagnostic (`LICENSE_POLICY_VIOLATION_DIAGNOSTIC_CODE`) on
/// `ctx.dep.name_range()` via [`crate::licenses::evaluate`] — [`ViolationReason::Denied`]
/// renders [`Severity::Error`], [`ViolationReason::NotAllowed`]
/// [`Severity::Warning`] (severity is not user-configurable: spec 010 plan.md's
/// resolved config shape is `{ allow?, deny? }` only).
/// Suppressed by: nothing outright — a [`crate::LicenseSource::PomFreeText`] ecosystem's
/// (Gradle's Maven Central POM) license names are free text (e.g. `"The Apache Software
/// License, Version 2.0"`), never SPDX identifiers, so they are normalized via
/// [`resolve_license_entries`] before evaluation (issue #679/#687/#688; previously
/// Gradle was excluded from this rule entirely, issue #660/#661 critic C2). An entry the
/// normalization table doesn't recognize is dropped rather than guessed at, and if *any*
/// of a dependency's declared license entries fails to normalize, this rule suppresses
/// only a `NotAllowed` conclusion (issue #679 critic S1: the surviving, normalized
/// entries are incomplete evidence — an allow-list check that fires on "no entry
/// matches" would otherwise manufacture a false violation from the entries that happened
/// to drop). A `Denied` conclusion is still emitted even with a partially-unrecognized
/// license list, since a normalized entry matching `deny` is real evidence regardless of
/// what else on the POM wasn't recognized — dropping entries can only ever *miss* a
/// denial, never fabricate one.
/// Suppresses: nothing.
fn apply_license_policy_rule(diagnostics: &mut Vec<Diagnostic>, ctx: &RuleContext<'_>) {
    let Some(policy) = ctx.versions.license_policy else {
        return;
    };
    let Some(license) = ctx
        .versions
        .license_prefetch
        .and_then(|prefetch| prefetch.get(ctx.dep.name()))
    else {
        return;
    };
    let license_source = ctx.versions.license_source.unwrap_or_default();
    let (normalized_license, all_matched) = resolve_license_entries(license_source, license);
    let suppress_not_allowed = !all_matched;
    let Some(violation) = evaluate_license_policy(&normalized_license, policy) else {
        return;
    };
    if suppress_not_allowed && violation.reason == ViolationReason::NotAllowed {
        return;
    }

    let severity = match violation.reason {
        ViolationReason::Denied => Severity::Error,
        ViolationReason::NotAllowed => Severity::Warning,
    };
    diagnostics.push(
        Diagnostic::new(
            ctx.dep.name_range(),
            format!(
                "{}: {} {}",
                redact_name_for_diagnostic(ctx.dep.name()),
                sanitize_and_truncate_for_diagnostic(
                    &violation.license,
                    MAX_DIAGNOSTIC_VALUE_CHARS
                ),
                violation.reason
            ),
        )
        .with_severity(severity)
        .with_code(LICENSE_POLICY_VIOLATION_DIAGNOSTIC_CODE),
    );
}

/// R3 — package-level deprecation finding (#205, I4).
///
/// Emitted independently of the in-use-yanked check (R4), for the same FR-007-style
/// reason as R2 — a registry-reported deprecation must never be suppressed by an
/// unrelated "latest" lookup failure.
///
/// Reads: `ctx.formatter.can_resolve_source(&ctx.dep.source())` **and**
/// `ctx.versions.outcomes.deprecation(ctx.normalized_name)`. I4: the `can_resolve_source`
/// gate is folded into the returned value (not just the push) so this rule, R4's D5
/// gate, and R6b's #437 mirror of it all see the same answer — `versions.outcomes`'
/// deprecation channel is name-keyed, so a git/path/SDK occurrence sharing a name with
/// an unrelated registry-resolved package (the #248 coincidental-namesake hazard) must
/// not surface a diagnostic for a package it doesn't actually resolve against.
/// Emits: 1 deprecation diagnostic (`DEPRECATED_DIAGNOSTIC_CODE`) via
/// [`push_deprecation_diagnostic`].
/// Suppressed by: nothing — never suppressed by a registry outage (same FR-007
/// reasoning as R2).
/// Suppresses: R4 conditionally (D5, see [`apply_in_use_yanked_rule`]), R6b
/// conditionally (#437, see [`apply_yanked_only_rule`]) — both read only this rule's
/// return value (presence), never its content.
fn apply_deprecation_rule(diagnostics: &mut Vec<Diagnostic>, ctx: &RuleContext<'_>) -> bool {
    let deprecation = ctx
        .formatter
        .can_resolve_source(&ctx.dep.source())
        .then(|| {
            ctx.versions
                .outcomes
                .and_then(|o| o.deprecation(ctx.normalized_name))
        })
        .flatten();
    if let Some(dep_info) = deprecation {
        push_deprecation_diagnostic(
            diagnostics,
            ctx.dep,
            ctx.formatter,
            dep_info,
            ctx.severities,
        );
    }
    deprecation.is_some()
}

/// R4 — in-use-version yanked check (#263, #394 S1, D5).
///
/// Two independent yanked-version checks exist in this pipeline: this one (#263)
/// flags the specific in-use version (lockfile-resolved, or an exact manifest pin)
/// when it is yanked, while R6b ([`apply_yanked_only_rule`], #247) flags a declared
/// *range* requirement that can currently only be satisfied by a yanked version, even
/// with no lockfile at all. They answer different questions and neither subsumes the
/// other, but for a dependency pinned to the one version that also happens to be the
/// only version satisfying its own requirement, both would fire on the same
/// dependency — this rule's return value lets R6b dedup that case.
///
/// The two checks deliberately keep different outdated-interaction policies — this is
/// not an oversight. This (#263) check has no `continue`, so it co-emits alongside an
/// "outdated" diagnostic for the same dependency (see
/// `test_generate_diagnostics_from_cache_yanked_and_outdated_both_emitted`). R6b does
/// `continue`, suppressing "outdated" for the same dependency (see
/// `test_yanked_only_match_suppresses_outdated_diagnostic`). Each policy was
/// independently reviewed and tested before this merge; harmonizing them is out of
/// scope here.
///
/// Reads: `ctx.versions.outcomes.yanked(ctx.normalized_name)` -> `(yanked_version,
/// status)`; `ctx.versions.ecosystem`; `super::resolve_in_use_version(...)`.
/// Gate D5 (`deprecation_found`): a package-level deprecation finding suppresses this
/// check — but only when the underlying yanked finding's status is
/// `AdvisoryDeprecated`, never when it is `Yanked`. A genuine hard yank ("the exact
/// version you pinned was withdrawn") is strictly more actionable than a package-level
/// deprecation notice ("the project is archived"), so it must never be hidden behind
/// one. Requires an *actual* yanked (#263) entry with that status — uses
/// `is_some_and`, **not** `is_none_or`: a vacuous `None` (no #263 entry) must NOT count
/// as "suppress". R6b reads a different data source (`package_versions.yanked`) and,
/// as of #437, applies this identical D5 polarity *independently* from its own matched
/// entry's status, regardless of what this check decided — this is deliberately NOT
/// folded into this rule's return value (an earlier version of this fix did that, and
/// thereby let a suppressed-`AdvisoryDeprecated` #263 entry also silently gate off a
/// same-dependency #247 match whose own aggregate was `Yanked` — reintroducing the
/// exact bug #437 exists to close, just through the other branch).
/// Gate #394 S1: when multiple occurrences share `normalized_name`, the finding
/// recorded under it may belong to a *different* occurrence (e.g.
/// `[dependencies] time = "=0.1.43"`, yanked, and `[dev-dependencies] time =
/// "=0.1.44"`, not yanked — both name-keyed to the same `yanked_version`). Emitting
/// unconditionally would push a false-positive "yanked" diagnostic onto the safe
/// occurrence, for a version string that does not even appear on that line. Gated on
/// `ctx.versions.ecosystem` being set (production always sets it; the check is
/// skipped, matching pre-#394 behavior, for the test fixtures that do not) via
/// `is_none_or`.
/// Emits: 1 yanked diagnostic on [`version_anchor_range`]. Message is
/// deliberately `"{yanked_message()} ({version})"` — do not "harmonize" it with R6b's
/// message (`"{yanked_message()}; latest is {latest}"`), which differs on purpose.
/// Suppressed by: D5 above. Not gated on `can_resolve_source`.
/// Suppresses: nothing — deliberately returns `bool`, not [`RuleFlow`], so it
/// structurally cannot stop the pipeline.
///
/// Returns whether a diagnostic was actually **pushed** — never `true` for a
/// D5-suppressed finding, and never merely "a #263 entry existed". [`apply_yanked_only_rule`]
/// reads this as its dedup gate.
fn apply_in_use_yanked_rule(
    diagnostics: &mut Vec<Diagnostic>,
    ctx: &RuleContext<'_>,
    deprecation_found: bool,
) -> bool {
    let deprecation_suppresses_yanked = deprecation_found
        && ctx
            .versions
            .outcomes
            .and_then(|o| o.yanked(ctx.normalized_name))
            .is_some_and(|(_, status)| *status != RemovalStatus::Yanked);

    if deprecation_suppresses_yanked {
        false
    } else if let Some((yanked_version, _status)) = ctx
        .versions
        .outcomes
        .and_then(|o| o.yanked(ctx.normalized_name))
        && ctx.versions.ecosystem.is_none_or(|ecosystem| {
            super::resolve_in_use_version(
                ctx.dep,
                ctx.normalized_name,
                ctx.versions.resolved,
                ctx.versions.resolved_version_candidates,
                ctx.formatter,
                ecosystem,
            )
            .as_deref()
                == Some(yanked_version.as_str())
        })
    {
        let yanked_version = sanitize_and_truncate_for_diagnostic(
            yanked_version.as_str(),
            MAX_VERSION_DIAGNOSTIC_CHARS,
        );
        diagnostics.push(
            Diagnostic::new(
                version_anchor_range(ctx.dep),
                format!("{} ({})", ctx.formatter.yanked_message(), yanked_version),
            )
            .with_severity(ctx.severities.yanked),
        );
        true
    } else {
        false
    }
}

/// R5 — unknown-package family. Reached only when [`RuleContext::cached_versions`]
/// returns `None`. Always terminal — the orchestrator `continue`s unconditionally
/// after calling this.
///
/// R5-guard `in_lockfile` (#248): if `ctx.versions.resolved` contains either key,
/// emits nothing at all — a registry fetch may simply have been rate-limited.
/// Name-syntax validation is unaffected by this guard: it never depends on registry
/// data.
///
/// `fetch_failure = can_resolve_source(&dep.source()) &&
/// outcomes.fetch_failure(normalized_name)` — a fetch error/timeout (#267) is not
/// evidence the package doesn't exist, so it is reported distinctly from a genuine
/// "not found".
///
/// `match formatter.validate_package_name(dep.name())` — **arm order is
/// load-bearing**:
/// 1. `Err(reason)` -> R5a `Invalid package name '{name}': {reason}`. Fires regardless
///    of `can_resolve_source`/`fetch_failure` — a fetch failure must never mask an
///    invalid name.
/// 2. `Ok(())` + `fetch_failure.is_some()` + `versions.offline` -> R5b emits nothing
///    (#483 I2): this is a deliberately configured mode, not a registry outage, and
///    [`offline_notice`]'s file-level notice already covers this dependency.
/// 3. `Ok(())` + `fetch_failure.is_some()` -> R5c: queued into `fetch_failed`
///    (deferred, collapsed by [`push_collapsed_fetch_failures`] — R8) rather than
///    pushed inline, since a fetch failure is a registry-wide condition that can hit
///    many dependencies identically.
/// 4. `Ok(())` + `no_comparable_versions` -> R5e emits nothing (#550): the registry
///    fetch succeeded and the package demonstrably exists, it just has zero versions
///    comparable to the declared requirement (e.g. `dtolnay/rust-toolchain`'s only tag
///    `v1` isn't full semver) — reported by neither R5c ("couldn't be asked") nor R5d
///    ("no evidence it exists"). Checked before R5d so it takes priority over the
///    "absent cache entry" heuristic that would otherwise misclassify it.
/// 5. `Ok(())` + `can_resolve_source` -> R5d `Unknown package '{name}'`.
/// 6. `Ok(())` -> nothing (#248: unresolvable source, absent cache entry means "never
///    fetched").
fn apply_unknown_package_rule(
    diagnostics: &mut Vec<Diagnostic>,
    fetch_failed: &mut Vec<FetchFailureEntry>,
    ctx: &RuleContext<'_>,
) {
    let dep = ctx.dep;
    let in_lockfile = ctx.versions.resolved.contains_key(ctx.normalized_name)
        || ctx.versions.resolved.contains_key(dep.name());
    if in_lockfile {
        return;
    }

    let can_resolve_source = ctx.formatter.can_resolve_source(&dep.source());
    let fetch_failure: Option<&FetchFailure> = can_resolve_source
        .then(|| {
            ctx.versions
                .outcomes
                .and_then(|o| o.fetch_failure(ctx.normalized_name))
        })
        .flatten();
    let no_comparable_versions = can_resolve_source
        && ctx
            .versions
            .outcomes
            .is_some_and(|o| o.no_comparable_versions(ctx.normalized_name));
    match ctx.formatter.validate_package_name(dep.name().as_str()) {
        Err(reason) => {
            diagnostics.push(
                Diagnostic::new(
                    dep.name_range(),
                    format!(
                        "Invalid package name '{}': {reason}",
                        redact_name_for_diagnostic(dep.name())
                    ),
                )
                .with_severity(ctx.severities.unknown),
            );
        }
        Ok(()) if fetch_failure.is_some() && ctx.versions.offline => {}
        Ok(()) if fetch_failure.is_some() => {
            let redacted_name = redact_name_for_diagnostic(dep.name());
            let message = match fetch_failure {
                Some(FetchFailure::Actionable(hint)) => {
                    format!("Registry lookup failed for '{redacted_name}': {hint}")
                }
                Some(FetchFailure::Transient | FetchFailure::NotAttempted) | None => {
                    format!(
                        "Registry lookup failed for '{redacted_name}'; package status could not \
                         be determined"
                    )
                }
            };
            fetch_failed.push(FetchFailureEntry {
                name: redacted_name,
                diagnostic: Diagnostic::new(dep.name_range(), message)
                    .with_severity(ctx.severities.unknown),
                failure: fetch_failure.cloned(),
            });
        }
        Ok(()) if no_comparable_versions => {}
        Ok(()) if can_resolve_source => {
            diagnostics.push(
                Diagnostic::new(
                    dep.name_range(),
                    format!(
                        "Unknown package '{}'",
                        redact_name_for_diagnostic(dep.name())
                    ),
                )
                .with_severity(ctx.severities.unknown),
            );
        }
        Ok(()) => {}
    }
}

/// R6a — unsatisfiable requirement (#206, #299).
///
/// Path/git/URL/SDK/workspace dependencies never resolve against a registry version
/// list at all — `resolved.package_versions` (when present) either came from a
/// coincidentally-matching registry entry of the same name or an entirely unrelated
/// package. Neither is a meaningful "no published version satisfies this" check,
/// hence the `can_resolve_source` gate below.
///
/// Reads: `can_resolve_source(&dep.source())` **and** `dep.version_requirement()`
/// **and** `requirement_is_unsatisfiable(formatter, req,
/// &resolved.package_versions.available)`. Message enriched via
/// `matching_prerelease_would_satisfy` when a non-yanked pre-release whose stable core
/// matches exists (#299).
/// Emits: 1 diagnostic (`UNSATISFIABLE_DIAGNOSTIC_CODE`) on `resolved.version_range`.
/// Suppressed by: nothing.
/// Suppresses: R6b and R7 via the returned `RuleFlow::Stop`. `resolved: &ResolvedData`
/// (carrying `version_range`) is a precondition all three rules share — established by
/// the orchestrator's `version_range` guard *before* this rule runs, not an effect of
/// this rule running — so it is `RuleFlow::Stop` alone, not `version_range`'s
/// existence, that skips R6b and R7 here.
fn apply_unsatisfiable_rule(
    diagnostics: &mut Vec<Diagnostic>,
    ctx: &RuleContext<'_>,
    resolved: &ResolvedData<'_>,
) -> RuleFlow {
    let dep = ctx.dep;
    let package_versions = resolved.package_versions;
    let latest = &package_versions.latest;

    let unsatisfiable = ctx.formatter.can_resolve_source(&dep.source())
        && dep.version_requirement().is_some_and(|version_req| {
            requirement_is_unsatisfiable(ctx.formatter, version_req, &package_versions.available)
        });

    if !unsatisfiable {
        return RuleFlow::Continue;
    }

    let req_str = sanitize_and_truncate_for_diagnostic(
        dep.version_requirement().map_or("", |r| r.as_str()),
        MAX_VERSION_DIAGNOSTIC_CHARS,
    );
    let latest =
        sanitize_and_truncate_for_diagnostic(latest.as_str(), MAX_VERSION_DIAGNOSTIC_CHARS);
    let mut message =
        format!("No published version satisfies requirement '{req_str}'; latest is {latest}");
    if let Some(prerelease) = dep.version_requirement().and_then(|version_req| {
        matching_prerelease_would_satisfy(
            ctx.formatter,
            version_req,
            &package_versions.available,
            &package_versions.yanked,
        )
    }) {
        use std::fmt::Write as _;
        let prerelease =
            sanitize_and_truncate_for_diagnostic(prerelease.as_str(), MAX_VERSION_DIAGNOSTIC_CHARS);
        let _ = write!(
            message,
            " (a pre-release, {prerelease}, is excluded by SemVer's default \
             pre-release-matching rules; require it explicitly to use it)"
        );
    }
    diagnostics.push(
        Diagnostic::new(resolved.version_range, message)
            .with_severity(ctx.severities.unsatisfiable)
            .with_code(UNSATISFIABLE_DIAGNOSTIC_CODE),
    );
    RuleFlow::Stop
}

/// R6b — yanked-only range match (#247, #437, #431, #436).
///
/// Independent of R4 ([`apply_in_use_yanked_rule`]), which reads `versions.outcomes`
/// directly and is unaffected by the gates below.
///
/// Three independent gates, in order:
/// 1. `!in_use_yanked_emitted` (dedup with R4) — **and critically not** "R4 was
///    D5-suppressed" (#437 S1): that suppression pushed nothing, so this rule must
///    still be free to decide for itself.
/// 2. `formatter.can_resolve_source(&dep.source())` (#431) — a source this ecosystem
///    cannot fetch from (e.g. an unresolved Cargo registry alias) is excluded the same
///    way the other diagnostics in this pipeline already are.
/// 3. `formatter.yanked_diagnostic_applies_to(dep, version_req)` — per-ecosystem
///    opt-out (npm unconditionally, #436) for a requirement shape where this
///    diagnostic would duplicate a more specific one or where `removal_status()`
///    isn't a reliable enough per-version signal.
///
/// Then `requirement_matches_only_yanked(...)` -> `Option<RemovalStatus>` (the
/// aggregate: `Yanked` if any matching entry's status is `Yanked`, else
/// `AdvisoryDeprecated`).
///
/// Final D5-mirror (#437): mirrors R4's D5 polarity, applied independently of the
/// #263 `versions.outcomes` yanked channel and of whatever R4 decided — fires iff
/// `status != AdvisoryDeprecated || !deprecation_found`, i.e. a `Yanked` aggregate
/// always fires regardless of a co-occurring deprecation and regardless of what R4
/// decided; an `AdvisoryDeprecated` aggregate yields to a deprecation finding (the
/// PyPI range-satisfiable-only-by-yanked-with-no-exact-pin case this fixes, plus the
/// mixed-status-within-one-package case S1 closes).
/// Emits: 1 yanked diagnostic on `resolved.version_range`. Message is deliberately
/// `"{yanked_message()}; latest is {latest}"` — do not "harmonize" it with R4's
/// message (`"{yanked_message()} ({version})"`), which differs on purpose.
/// Suppressed by: the three gates above.
/// Suppresses: R7 (`RuleFlow::Stop`) — the deliberate asymmetry with R4, which never
/// stops the pipeline (see `test_yanked_only_match_suppresses_outdated_diagnostic`).
fn apply_yanked_only_rule(
    diagnostics: &mut Vec<Diagnostic>,
    ctx: &RuleContext<'_>,
    resolved: &ResolvedData<'_>,
    prior: YankedOnlyPrior,
) -> RuleFlow {
    let YankedOnlyPrior {
        deprecation_found,
        in_use_yanked_emitted,
    } = prior;
    let dep = ctx.dep;
    let package_versions = resolved.package_versions;
    let latest = &package_versions.latest;

    let yanked_only_status = (!in_use_yanked_emitted
        && ctx.formatter.can_resolve_source(&dep.source()))
    .then(|| dep.version_requirement())
    .flatten()
    .filter(|version_req| ctx.formatter.yanked_diagnostic_applies_to(dep, version_req))
    .and_then(|version_req| {
        requirement_matches_only_yanked(
            ctx.formatter,
            version_req,
            &package_versions.available,
            &package_versions.yanked,
        )
    });

    let yanked_only = yanked_only_status
        .is_some_and(|status| status != RemovalStatus::AdvisoryDeprecated || !deprecation_found);

    if !yanked_only {
        return RuleFlow::Continue;
    }

    let latest =
        sanitize_and_truncate_for_diagnostic(latest.as_str(), MAX_VERSION_DIAGNOSTIC_CHARS);
    diagnostics.push(
        Diagnostic::new(
            resolved.version_range,
            format!("{}; latest is {latest}", ctx.formatter.yanked_message()),
        )
        .with_severity(ctx.severities.yanked),
    );
    RuleFlow::Stop
}

/// R7 — outdated (#227 §4.3). Last rule; nothing to suppress, so no [`RuleFlow`].
///
/// As with R6a's `unsatisfiable` check, a non-resolvable source's `latest` (when
/// present at all) comes from an unrelated or coincidental cache entry, not a real
/// lookup against the registry this dependency actually resolves against — so
/// "Outdated" must not be evaluated for it either (#248).
///
/// `status` = `Unresolved` unless `dep.version_requirement()` is `Some` **and**
/// `can_resolve_source` (#248); otherwise `formatter.requirement_status(req, latest)`.
/// Fires on `RequirementStatus::Outdated`. Message-only cooldown differentiation
/// gated on `ctx.freshness.enabled` + `package_versions.published_at` +
/// `is_within_cooldown(age, cooldown_secs)`; **severity is identical in both cases**
/// (already the floor — see the module docs).
fn apply_outdated_rule(
    diagnostics: &mut Vec<Diagnostic>,
    ctx: &RuleContext<'_>,
    resolved: &ResolvedData<'_>,
) {
    let dep = ctx.dep;
    let package_versions = resolved.package_versions;
    let latest = &package_versions.latest;

    let status = match dep.version_requirement() {
        Some(version_req) if ctx.formatter.can_resolve_source(&dep.source()) => ctx
            .formatter
            .requirement_status_for(dep, version_req, latest),
        _ => RequirementStatus::Unresolved,
    };

    if status != RequirementStatus::Outdated {
        return;
    }

    let published_at = ctx
        .freshness
        .enabled
        .then_some(package_versions.published_at)
        .flatten();
    let latest =
        sanitize_and_truncate_for_diagnostic(latest.as_str(), MAX_VERSION_DIAGNOSTIC_CHARS);
    let message = match published_at {
        Some(published_at)
            if is_within_cooldown(
                published_at.age_secs_from(ctx.now),
                ctx.freshness.cooldown_secs,
            ) =>
        {
            format!(
                "Newer version available: {latest} (published {} — still within the release cooldown window)",
                format_relative_age(published_at.age_secs_from(ctx.now))
            )
        }
        _ => format!("Newer version available: {latest}"),
    };
    diagnostics.push(
        Diagnostic::new(resolved.version_range, message).with_severity(ctx.severities.outdated),
    );
}

/// R8 — fetch-failure collapse (#479, #480 S2, #478/#485).
///
/// A single fetch failure keeps its own per-dependency diagnostic (same range as
/// before, though — unlike every other diagnostic in this pipeline — no longer
/// necessarily at the same position in the returned `Vec` in dependency order: it's
/// appended after the main loop rather than interleaved with it, so an assertion keyed
/// on vec index rather than message content could be affected). More than one
/// collapses into one combined diagnostic (on the first failing dependency's range)
/// rather than fanning out N near-duplicates that all trace back to the same
/// registry-wide condition — but every *additional* failing dependency's name and
/// location survive via `related_information` instead of being silently dropped along
/// with their per-line diagnostic marker.
///
/// `0` -> nothing. `1` -> push the single buffered diagnostic verbatim. `n >= 2` -> one
/// diagnostic at entry 0's `range`/`severity`, message using the *first* `Actionable`
/// hint found across the batch (falling back to the generic form), with
/// `related_information` built from entries `[1..]` as `'{name}' also failed` anchored
/// at each entry's own range and `uri`.
fn push_collapsed_fetch_failures(
    diagnostics: &mut Vec<Diagnostic>,
    fetch_failed: Vec<FetchFailureEntry>,
    uri: &url::Url,
) {
    #[expect(
        clippy::indexing_slicing,
        reason = "the 0/1 arms are matched separately, so this arm only runs with len() >= 2, \
                  making both fetch_failed[0] and the fetch_failed[1..] slice below valid"
    )]
    match fetch_failed.len() {
        0 => {}
        1 => diagnostics.extend(fetch_failed.into_iter().map(|entry| entry.diagnostic)),
        n => {
            let first = &fetch_failed[0].diagnostic;
            let range = first.range;
            let severity = first.severity;
            // Surface a shared actionable hint across the batch so collapsing 2+ failures
            // never drops the pre-vetted remedy (#478/#485); fall back to generic otherwise.
            let shared_hint = fetch_failed.iter().find_map(|entry| match &entry.failure {
                Some(FetchFailure::Actionable(hint)) => Some(hint.clone()),
                _ => None,
            });
            let message = match shared_hint {
                Some(hint) => format!("Registry lookup failed for {n} packages: {hint}"),
                None => format!(
                    "Registry lookup failed for {n} packages; package status could not be determined"
                ),
            };
            let related_information = fetch_failed[1..]
                .iter()
                .map(|entry| {
                    RelatedInformation::new(
                        uri.clone(),
                        entry.diagnostic.range,
                        format!("'{}' also failed", entry.name),
                    )
                })
                .collect();
            let mut diagnostic = Diagnostic::new(range, message);
            diagnostic.severity = severity;
            diagnostics.push(diagnostic.with_related_information(related_information));
        }
    }
}

/// The anchor range for a package-level diagnostic (deprecation, vulnerability) that isn't
/// itself about the declared version requirement: `dep.version_range()` when it is a real,
/// non-degenerate position, falling back to `dep.name_range()` otherwise — the same range D4
/// requires so the client's lightbulb gesture lands where `generate_code_actions`'s quickfixes
/// already work (see `EcosystemFormatter::is_position_on_dependency`'s default).
///
/// The `version_range_is_synthetic_empty` gate (#1161 M1 follow-up) is deliberate, not
/// redundant with `version_range()`'s own `Option`: Maven's `<version></version>` gives
/// `version_range()` a real, zero-width position purely so completion can locate the
/// dependency there, but there is no requirement text to visibly anchor a diagnostic against
/// — anchoring there anyway would move a vulnerability/deprecation squiggle off the visible
/// `<artifactId>` text onto an invisible empty span between two tags, contrary to this
/// function's whole purpose of picking a *visible* fallback. A bare `version_requirement().is_some()`
/// check (the M1 fix's first attempt) over-corrected this: Gradle's version-catalog
/// `version.ref` pointing at a dangling/rich-version alias legitimately has a REAL, non-empty
/// `version_range()` (the alias-reference text) with `version_requirement()` still `None` —
/// anchoring diagnostics there worked before #1161 and must keep working (code-review
/// follow-up, second round).
fn version_anchor_range(dep: &dyn Dependency) -> Range {
    if version_range_is_synthetic_empty(dep) {
        dep.name_range()
    } else {
        dep.version_range().unwrap_or_else(|| dep.name_range())
    }
}

/// Pushes the package-level deprecation [`Diagnostic`] for `dep` (issue #205).
///
/// Modeled on `push_vulnerability_diagnostics`: anchored via [`version_anchor_range`].
///
/// `deprecation.reason`/`deprecation.replacement` are registry-supplied, unbounded-length
/// data (#1263 follow-up sweep) — `reason` is free-text prose, sanitized with the same
/// narrow bidi/invisible-character filter as an OSV advisory summary
/// ([`sanitize_advisory_text_for_diagnostic`]); `replacement` is a package-name-shaped
/// field, sanitized like any other name sink ([`sanitize_and_truncate_for_diagnostic`]).
fn push_deprecation_diagnostic(
    diagnostics: &mut Vec<Diagnostic>,
    dep: &dyn Dependency,
    formatter: &dyn EcosystemFormatter,
    deprecation: &Deprecation,
    severities: DiagnosticSeverities,
) {
    use std::fmt::Write as _;

    let range: Range = version_anchor_range(dep);

    let mut message = formatter.deprecated_message().to_string();
    if let Some(reason) = deprecation.reason.as_deref().filter(|r| !r.is_empty()) {
        let reason = sanitize_advisory_text_for_diagnostic(reason, MAX_DIAGNOSTIC_PROSE_CHARS);
        let _ = write!(message, ": {reason}");
    }
    if let Some(replacement) = deprecation.replacement.as_deref().filter(|r| !r.is_empty()) {
        let replacement =
            sanitize_and_truncate_for_diagnostic(replacement, MAX_DIAGNOSTIC_NAME_CHARS);
        let _ = write!(message, " (replacement: {replacement})");
    }

    diagnostics.push(
        Diagnostic::new(range, message)
            .with_severity(severities.deprecated)
            .with_code(DEPRECATED_DIAGNOSTIC_CODE),
    );
}

/// Pushes one [`Diagnostic`] per advisory (each with its own severity, code,
/// and clickable `code_description`), capped at
/// [`crate::osv::ADVISORY_DISPLAY_CAP`] plus a trailing "+N more advisories" entry.
///
/// `N` is derived from [`crate::osv::Capped::remaining`] — the batch result's reported count,
/// never from `dv.advisories.items().len()`, since invariant 3 (`architecture.md` §8)
/// caps the record *fetch* independently of the render cap.
///
/// A [`crate::osv::VulnSeverity::Malicious`] advisory's message is prefixed with the
/// `"[MALWARE]"` tag (SC-002) — deliberately not the word "malicious" again: OSV's own
/// `summary` text for these records routinely already starts with "Malicious code in ..."
/// (impl-critic M3), and prefixing with "Malicious package" produced a redundant
/// "Malicious package — Malicious code in ..." read. `code` is still `advisory.id` like
/// every other advisory (a `MAL-*` id can never collide with a `RUSTSEC-`/`GHSA-`/`CVE-`
/// one), but the message tag means a reader scanning the Problems panel does not need to
/// recognize the `MAL-` id convention (or an alias to one — see `severity::classify`) to
/// tell the two apart. `severity` itself stays capped at `WARNING` either way
/// (`diagnostic_severity_for`).
///
/// A [`crate::osv::VulnSeverity::Informational`] advisory's message gets the analogous
/// `"[INFORMATIONAL]"` prefix (FR-004, issue #1007) — the additional signal for a user
/// filtering/reading by message text or diagnostic code rather than by severity icon,
/// since `INFORMATION` severity alone (`diagnostic_severity_for`) already separates it
/// from an ordinary unscored CVE's `WARNING` severity but may not render distinctly in
/// every client's UI chrome.
///
/// `Diagnostic.code` is passed the raw `advisory.id` here, not the
/// `sanitize_advisory_text_for_diagnostic`-passed copy used in the message text (#1262
/// critic follow-up) — `with_code` (#1280) sanitizes it at the setter, the same
/// defense-in-depth treatment `message` gets, so this is not an unsanitized value reaching
/// a client. It is also already constrained to ASCII alphanumeric/`.`/`_`/`-` at `<= 128`
/// bytes by [`crate::osv::is_valid_osv_id`] — the only non-test construction path of
/// [`crate::osv::Advisory`] — before an `Advisory` can exist at all. The binding agreement
/// between the published `code` and `diagnostic_codes` (this module's `code_actions.rs:214`
/// and `deps-lsp`'s `handlers/code_actions.rs`'s `bind_diagnostics`, which matches `code`
/// against raw `fix.advisory_ids`) rests on `is_valid_osv_id` forbidding unsafe characters
/// at ingest on both sides, not on `code` staying unsanitized.
fn push_vulnerability_diagnostics(
    diagnostics: &mut Vec<Diagnostic>,
    dep: &dyn Dependency,
    dv: &crate::osv::DependencyVulnerabilities,
) {
    let range: Range = version_anchor_range(dep);

    for advisory in dv.advisories.items() {
        let code_description = advisory
            .url()
            .parse::<url::Url>()
            .ok()
            .map(CodeDescription::new);

        let advisory_id =
            sanitize_advisory_text_for_diagnostic(advisory.id.as_str(), MAX_DIAGNOSTIC_PROSE_CHARS);
        let summary = sanitize_advisory_text_for_diagnostic(
            advisory
                .summary
                .as_deref()
                .unwrap_or("(no summary provided)"),
            MAX_DIAGNOSTIC_PROSE_CHARS,
        );
        let message = match advisory.severity {
            crate::osv::VulnSeverity::Malicious => {
                format!("{advisory_id}: [MALWARE] {summary}")
            }
            crate::osv::VulnSeverity::Informational => {
                format!("{advisory_id}: [INFORMATIONAL] {summary}")
            }
            crate::osv::VulnSeverity::Critical
            | crate::osv::VulnSeverity::High
            | crate::osv::VulnSeverity::Medium
            | crate::osv::VulnSeverity::Low
            | crate::osv::VulnSeverity::Unknown => format!("{advisory_id}: {summary}"),
        };

        let mut diagnostic = Diagnostic::new(range, message)
            .with_severity(diagnostic_severity_for(advisory.severity))
            .with_code(advisory.id.clone());
        if let Some(code_description) = code_description {
            diagnostic = diagnostic.with_code_description(code_description);
        }
        diagnostics.push(diagnostic);
    }

    let remaining = dv.advisories.remaining();
    if remaining > 0 {
        diagnostics.push(
            Diagnostic::new(range, format!("+{remaining} more advisories"))
                .with_severity(Severity::Information),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lsp_helpers::test_support::*;
    use crate::lsp_helpers::*;
    use crate::position::{Position, Range};
    use crate::{PackageName, VersionReq};

    use std::collections::HashMap;
    use std::sync::Arc;

    /// #1161 M1 (critic follow-up): a dependency with a real `version_range()` but no
    /// `version_requirement()` — Maven's `<version></version>`, whose zero-width
    /// `version_range()` exists purely so completion can locate the dependency — must anchor
    /// package-level diagnostics (deprecation, vulnerability, in-use-yanked) at the visible
    /// `name_range()`, not the invisible empty span, matching what happens for a manifest
    /// with no `<version>` tag at all (`version_range() == None`).
    #[test]
    fn test_version_anchor_range_falls_back_to_name_range_with_no_requirement() {
        let name_range = Range::new(Position::new(4, 18), Position::new(4, 21));
        let dep = MockNoRequirementDep {
            name: PackageName::new("com.example:foo"),
            name_range,
            version_range: Range::new(Position::new(5, 15), Position::new(5, 15)),
        };

        assert_eq!(version_anchor_range(&dep), name_range);
    }

    /// Counterpart to the above: when `version_requirement()` IS present, the real
    /// `version_range()` is used, unaffected by the #1161 M1 fallback.
    #[test]
    fn test_version_anchor_range_uses_version_range_when_requirement_present() {
        let version_range = Range::new(Position::new(0, 9), Position::new(0, 14));
        let dep = MockDep {
            name: PackageName::new("serde"),
            version_req: VersionReq::new("1.0.0"),
            version_range,
            name_range: Range::new(Position::new(0, 0), Position::new(0, 5)),
        };

        assert_eq!(version_anchor_range(&dep), version_range);
    }

    /// #1161 M1 code-review follow-up (second round): a REAL, non-empty `version_range()`
    /// with no `version_requirement()` — Gradle's version-catalog `version.ref` pointing at a
    /// dangling/rich-version alias — must still anchor diagnostics at that real position, not
    /// fall back to `name_range()`. This worked before #1161 (`version_range().unwrap_or_else`
    /// alone gated it, with no requirement check), and a bare `version_requirement().is_some()`
    /// gate (the M1 fix's first attempt) would have silently broken it.
    #[test]
    fn test_version_anchor_range_uses_non_empty_version_range_with_no_requirement() {
        let version_range = Range::new(Position::new(4, 40), Position::new(4, 45));
        let dep = MockNoRequirementDep {
            name: PackageName::new("com.example:guava"),
            name_range: Range::new(Position::new(4, 18), Position::new(4, 21)),
            version_range,
        };

        assert_eq!(version_anchor_range(&dep), version_range);
    }

    #[test]
    fn test_generate_diagnostics_from_cache_unknown_package() {
        use crate::position::{Position, Range};
        use std::collections::HashMap;

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
            parse_result.uri(),
            crate::freshness::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
            PublishTime::now(),
        );

        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].severity, Some(Severity::Warning));
        assert!(diagnostics[0].message().contains("Unknown package"));
        assert!(diagnostics[0].message().contains("unknown-pkg"));
    }

    /// A credential-shaped manifest key (#1242) must never reach a client-visible
    /// diagnostic verbatim, whichever `apply_unknown_package_rule` arm renders it.
    const CREDENTIAL_SHAPED_NAME: &str = "https://svcacct:glpat-AAAABBBBCCCCDDDD@gitlab.corp/g/p";

    #[test]
    fn test_generate_diagnostics_from_cache_redacts_credential_in_invalid_name() {
        use crate::position::{Position, Range};
        use std::collections::HashMap;

        let formatter = RejectingFormatter;
        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: CREDENTIAL_SHAPED_NAME.into(),
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
            parse_result.uri(),
            crate::freshness::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
            PublishTime::now(),
        );

        assert_eq!(diagnostics.len(), 1);
        assert!(diagnostics[0].message().starts_with("Invalid package name"));
        assert!(diagnostics[0].message().contains("***@"));
        assert!(!diagnostics[0].message().contains("glpat-AAAABBBBCCCCDDDD"));
    }

    #[test]
    fn test_generate_diagnostics_from_cache_redacts_credential_in_fetch_failure_hint() {
        use crate::position::{Position, Range};
        use std::collections::HashMap;

        let formatter = MockFormatter;
        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: CREDENTIAL_SHAPED_NAME.into(),
                version_req: "1.0.0".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 11)),
            }],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let cached_versions = HashMap::new();
        let resolved_versions = HashMap::new();
        let outcomes = DependencyOutcomes::new().with_fetch_failure(
            CREDENTIAL_SHAPED_NAME,
            FetchFailure::Actionable("set GITHUB_TOKEN to increase the rate limit".to_string()),
        );

        let diagnostics = generate_diagnostics_from_cache(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions).with_outcomes(&outcomes),
            &formatter,
            parse_result.uri(),
            crate::freshness::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
            PublishTime::now(),
        );

        assert_eq!(diagnostics.len(), 1);
        assert!(diagnostics[0].message().contains("Registry lookup failed"));
        assert!(diagnostics[0].message().contains("***@"));
        assert!(!diagnostics[0].message().contains("glpat-AAAABBBBCCCCDDDD"));
    }

    #[test]
    fn test_generate_diagnostics_from_cache_redacts_credential_in_unknown_package() {
        use crate::position::{Position, Range};
        use std::collections::HashMap;

        let formatter = MockFormatter;
        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: CREDENTIAL_SHAPED_NAME.into(),
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
            parse_result.uri(),
            crate::freshness::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
            PublishTime::now(),
        );

        assert_eq!(diagnostics.len(), 1);
        assert!(diagnostics[0].message().contains("Unknown package"));
        assert!(diagnostics[0].message().contains("***@"));
        assert!(!diagnostics[0].message().contains("glpat-AAAABBBBCCCCDDDD"));
    }

    /// #1246: `\n`/`\r` embedded in a manifest key must never reach a diagnostic message,
    /// where they could splice a fabricated extra line into a single-line rendering (a CLI
    /// table row, or a forged second finding).
    #[test]
    fn test_generate_diagnostics_from_cache_sanitizes_newlines_in_name() {
        use crate::position::{Position, Range};
        use std::collections::HashMap;

        let formatter = MockFormatter;
        let injected_name =
            "ok\n  [error] 1:1 totally-real-pkg (vulnerable) — CRITICAL RCE, upgrade now";
        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: injected_name.into(),
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
            parse_result.uri(),
            crate::freshness::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
            PublishTime::now(),
        );

        assert_eq!(diagnostics.len(), 1);
        assert!(!diagnostics[0].message().contains('\n'));
        assert!(!diagnostics[0].message().contains('\r'));
    }

    /// #1246: a bidirectional-override or zero-width character embedded in a manifest key
    /// must not survive into a diagnostic message, where it could visually reorder or hide
    /// text (Trojan Source, CVE-2021-42574).
    #[test]
    fn test_generate_diagnostics_from_cache_sanitizes_bidi_override_in_name() {
        use crate::position::{Position, Range};
        use std::collections::HashMap;

        let formatter = MockFormatter;
        let injected_name = "bidi\u{202E}gnp.exe\u{200B}";
        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: injected_name.into(),
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
            parse_result.uri(),
            crate::freshness::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
            PublishTime::now(),
        );

        assert_eq!(diagnostics.len(), 1);
        assert!(!diagnostics[0].message().contains('\u{202E}'));
        assert!(!diagnostics[0].message().contains('\u{200B}'));
    }

    /// Critic follow-up M1 (#1242, #1246): U+2028 LINE SEPARATOR / U+2029 PARAGRAPH
    /// SEPARATOR are neither `Cc` nor `Cf`, but are still line terminators for JS/`eval`
    /// consumers of `--format json` output and are treated as breaks by some editor
    /// renderers — they must not survive into a diagnostic message either.
    #[test]
    fn test_generate_diagnostics_from_cache_sanitizes_line_and_paragraph_separators_in_name() {
        use crate::position::{Position, Range};
        use std::collections::HashMap;

        let formatter = MockFormatter;
        let injected_name = "evil\u{2028}pkg\u{2029}name";
        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: injected_name.into(),
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
            parse_result.uri(),
            crate::freshness::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
            PublishTime::now(),
        );

        assert_eq!(diagnostics.len(), 1);
        assert!(!diagnostics[0].message().contains('\u{2028}'));
        assert!(!diagnostics[0].message().contains('\u{2029}'));
    }

    /// #1246 (medium, unbounded length): a 400 KB manifest key must not produce an
    /// unbounded diagnostic payload — `redact_name_for_diagnostic` truncates it the same
    /// way [`sanitize_and_truncate_for_diagnostic`] already bounds the blocked-registry
    /// sibling message.
    #[test]
    fn test_generate_diagnostics_from_cache_truncates_oversized_name() {
        use crate::position::{Position, Range};
        use std::collections::HashMap;

        let formatter = MockFormatter;
        let oversized_name = "a".repeat(400_000);
        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: oversized_name.as_str().into(),
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
            parse_result.uri(),
            crate::freshness::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
            PublishTime::now(),
        );

        assert_eq!(diagnostics.len(), 1);
        assert!(
            diagnostics[0].message().chars().count() < 200,
            "expected a bounded message, got {} chars",
            diagnostics[0].message().chars().count()
        );
    }

    /// Critic finding S1 (#905): a dependency with a synthetic `name_range()` (e.g.
    /// `deps-dart`'s container-anchor alias resolution) has no reliable position to anchor a
    /// diagnostic on — `generate_diagnostics_from_cache` must skip it entirely rather than
    /// emit one at the shared `Range::default()` sentinel, while a normal sibling dependency
    /// in the same document still gets its diagnostic as usual.
    #[test]
    fn test_generate_diagnostics_from_cache_skips_synthetic_range_dependency() {
        use crate::position::{Position, Range};

        let formatter = MockFormatter;

        let parse_result = MockMixedParseResult {
            deps: vec![
                Box::new(MockSyntheticRangeDep {
                    name: "synthetic-pkg".into(),
                }),
                Box::new(MockDep {
                    name: "unknown-pkg".into(),
                    version_req: "1.0.0".into(),
                    version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                    name_range: Range::new(Position::new(0, 0), Position::new(0, 11)),
                }),
            ],
            uri: crate::test_util::test_uri("/test/pubspec.yaml"),
        };

        let cached_versions = HashMap::new();
        let resolved_versions = HashMap::new();

        let diagnostics = generate_diagnostics_from_cache(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions),
            &formatter,
            parse_result.uri(),
            crate::freshness::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
            PublishTime::now(),
        );

        assert_eq!(
            diagnostics.len(),
            1,
            "the synthetic-range dependency must contribute no diagnostic at all, not one \
             stacked on Range::default()"
        );
        assert!(diagnostics[0].message().contains("unknown-pkg"));
        assert!(!diagnostics[0].message().contains("synthetic-pkg"));
    }

    /// #796: a manifest whose dependency count was truncated by
    /// `deps_core::dependency_cap::cap_dependencies` gets one file-level informational
    /// diagnostic naming the ceiling, and `generate_diagnostics_from_cache` only ever
    /// evaluates the retained (capped) subset.
    #[test]
    fn test_generate_diagnostics_from_cache_reports_dependency_ceiling_truncation() {
        let formatter = MockFormatter;
        let inner = crate::test_util::stub_parse_result_with_dependencies(12);
        let parse_result = crate::dependency_cap::cap_dependencies(inner, 10);

        let cached_versions = HashMap::new();
        let resolved_versions = HashMap::new();

        let diagnostics = generate_diagnostics_from_cache(
            parse_result.as_ref(),
            VersionData::new(&cached_versions, &resolved_versions),
            &formatter,
            parse_result.uri(),
            crate::freshness::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
            PublishTime::now(),
        );

        assert_eq!(
            parse_result.dependencies().len(),
            10,
            "generate_diagnostics_from_cache must only ever see the capped 10 dependencies"
        );

        let ceiling_diagnostics: Vec<_> = diagnostics
            .iter()
            .filter(|d| d.severity == Some(Severity::Information))
            .filter(|d| {
                d.message()
                    .contains("exceeding deps-lsp's per-document limit")
            })
            .collect();
        assert_eq!(
            ceiling_diagnostics.len(),
            1,
            "expected exactly one dependency-ceiling diagnostic, got: {diagnostics:?}"
        );
        assert!(ceiling_diagnostics[0].message().contains("12"));
        assert!(ceiling_diagnostics[0].message().contains("10"));
    }

    /// A document under the ceiling must never get a ceiling notice.
    #[test]
    fn test_generate_diagnostics_from_cache_no_ceiling_notice_under_the_limit() {
        let formatter = MockFormatter;
        let inner = crate::test_util::stub_parse_result_with_dependencies(3);
        let parse_result = crate::dependency_cap::cap_dependencies(inner, 10);

        let cached_versions = HashMap::new();
        let resolved_versions = HashMap::new();

        let diagnostics = generate_diagnostics_from_cache(
            parse_result.as_ref(),
            VersionData::new(&cached_versions, &resolved_versions),
            &formatter,
            parse_result.uri(),
            crate::freshness::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
            PublishTime::now(),
        );

        assert!(
            !diagnostics.iter().any(|d| d
                .message()
                .contains("exceeding deps-lsp's per-document limit")),
            "a document under the ceiling must get no ceiling notice, got: {diagnostics:?}"
        );
    }

    /// Regression for #550: a package whose registry fetch succeeded but produced zero
    /// comparable versions (e.g. `dtolnay/rust-toolchain`, whose only tag `v1` isn't
    /// full semver, so `GithubActionsRegistry::get_versions` returns `Ok(vec![])`) must
    /// not be reported "Unknown package" — the package demonstrably exists; there is
    /// simply nothing derivable from it. No cache entry AND no `no_comparable_versions`
    /// outcome would still (correctly) produce "Unknown package" — this asserts the
    /// outcome alone suppresses it.
    #[test]
    fn test_generate_diagnostics_from_cache_no_comparable_versions_is_not_unknown_package() {
        use crate::position::{Position, Range};

        let formatter = MockFormatter;

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "dtolnay/rust-toolchain".into(),
                version_req: "stable".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 23)),
            }],
            uri: crate::test_util::test_uri("/repo/.github/workflows/ci.yml"),
        };

        let cached_versions = HashMap::new();
        let resolved_versions = HashMap::new();
        let outcomes =
            DependencyOutcomes::new().with_no_comparable_versions("dtolnay/rust-toolchain");

        let diagnostics = generate_diagnostics_from_cache(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions).with_outcomes(&outcomes),
            &formatter,
            parse_result.uri(),
            crate::freshness::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
            PublishTime::now(),
        );

        assert!(
            diagnostics.is_empty(),
            "expected no diagnostic for a package with no comparable versions, got: {diagnostics:?}"
        );
    }

    /// Shared fixture for the `declaration_key`-redaction test family below (#993 M3): builds a
    /// single dependency with one blocked-registry occurrence and returns the resulting
    /// blocked-registry [`Diagnostic`], so each test only states the two values that actually
    /// vary (`declaration_key`, `raw_value`) instead of restating the full
    /// `ParseResult`/`MockDep`/`BlockedRegistryOccurrence` boilerplate.
    fn blocked_diagnostic_for(declaration_key: &str, raw_value: &str) -> Diagnostic {
        use crate::net_policy::HostClass;

        struct BlockedRegistryParseResult {
            deps: Vec<MockDep>,
            uri: url::Url,
            blocked: Vec<BlockedRegistryOccurrence>,
        }

        impl ParseResult for BlockedRegistryParseResult {
            fn dependencies(&self) -> Vec<&dyn Dependency> {
                self.deps.iter().map(|d| d as &dyn Dependency).collect()
            }
            fn workspace_root(&self) -> Option<&std::path::Path> {
                None
            }
            fn uri(&self) -> &url::Url {
                &self.uri
            }
            fn blocked_registries(&self) -> Vec<BlockedRegistryOccurrence> {
                self.blocked.clone()
            }
            fn as_any(&self) -> &dyn std::any::Any {
                self
            }
        }

        let name_range = Range::new(Position::new(0, 0), Position::new(0, 14));
        let formatter = MockFormatter;
        let parse_result = BlockedRegistryParseResult {
            deps: vec![MockDep {
                name: "internal-crate".into(),
                version_req: "1.0.0".into(),
                version_range: Range::new(Position::new(0, 20), Position::new(0, 25)),
                name_range,
            }],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
            blocked: vec![BlockedRegistryOccurrence {
                range: name_range,
                class: HostClass::CloudMetadata,
                raw_value: raw_value.to_string(),
                declaration_key: declaration_key.to_string(),
            }],
        };

        let cached_versions = HashMap::new();
        let resolved_versions = HashMap::new();

        let diagnostics = generate_diagnostics_from_cache(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions),
            &formatter,
            parse_result.uri(),
            crate::freshness::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
            PublishTime::now(),
        );

        diagnostics
            .into_iter()
            .find(|d| d.message().contains("blocked"))
            .expect("expected a blocked-registry diagnostic")
    }

    /// S3 (impl-critic): `generate_diagnostics_from_cache` must actually emit the
    /// `INFORMATION` diagnostic for a `ParseResult::blocked_registries()` entry — the
    /// §1.7 "must not degrade silently" requirement, previously entirely untested.
    #[test]
    fn test_generate_diagnostics_from_cache_emits_blocked_registry_diagnostic() {
        let blocked_diagnostic = blocked_diagnostic_for(
            "https://169.254.169.254/index",
            "https://169.254.169.254/index",
        );
        assert_eq!(
            blocked_diagnostic.range,
            Range::new(Position::new(0, 0), Position::new(0, 14))
        );
        assert_eq!(blocked_diagnostic.severity, Some(Severity::Information));
        assert!(blocked_diagnostic.message().contains("169.254.169.254"));
        assert!(blocked_diagnostic.message().contains("cloud metadata"));
        assert!(
            !blocked_diagnostic.message().contains("CloudMetadata"),
            "message must use the Display form, not the Debug identifier"
        );
    }

    /// #936: `raw_value` can carry a query-string credential (userinfo is rejected earlier
    /// in the pipeline, but a query string is not) — the blocked-registry diagnostic message
    /// must redact it before it reaches the client, while still naming the host so the
    /// message stays identifiable.
    #[test]
    fn test_generate_diagnostics_from_cache_blocked_registry_message_redacts_query_string_credential()
     {
        let blocked_diagnostic = blocked_diagnostic_for(
            "https://index.mycorp.dev/api?api_key=SECRET",
            "https://index.mycorp.dev/api?api_key=SECRET",
        );
        assert!(
            !blocked_diagnostic.message().contains("SECRET"),
            "{blocked_diagnostic:?}"
        );
        assert!(blocked_diagnostic.message().contains("index.mycorp.dev"));
        assert!(blocked_diagnostic.message().contains("/api"));
    }

    /// Impl-critic follow-up on M1 (#965/#966): a scheme-colon, slash-less URL
    /// (`"https:host/path?..."`) still classifies as a blocked host (see
    /// `deps_cargo::parser`'s own raw-value-reused declaration key), but never contains
    /// `"://"` — so gating query-string truncation on that substring, not just the
    /// userinfo-redaction step, would let a query-string credential in `declaration_key` leak
    /// through this field even though `raw_value`'s own redaction still catches it. Both
    /// fields must have the credential stripped.
    #[test]
    fn test_generate_diagnostics_from_cache_blocked_registry_message_redacts_query_string_credential_in_declaration_key_without_scheme_slashes()
     {
        let slash_less = "https:169.254.169.254/v3/index.json?api_key=SECRET";
        let blocked_diagnostic = blocked_diagnostic_for(slash_less, slash_less);
        assert!(
            !blocked_diagnostic.message().contains("SECRET"),
            "declaration_key's query-string credential must be stripped even without \"://\", \
             got: {blocked_diagnostic:?}"
        );
        assert!(blocked_diagnostic.message().contains("169.254.169.254"));
    }

    /// #981: gating `declaration_key`'s userinfo-redaction step on a bare `"://"` substring
    /// check missed a scheme-colon, slash-less credential (`Url::parse` still resolves it to
    /// an authority-bearing URL for a special scheme like `https`, even without the `//`) — it
    /// fell into the query/fragment-only `else` branch and rendered `user:pass@` verbatim.
    /// `is_authority_bearing_url` fixes this: the key parses as a URL with a real host, giving
    /// `redact_userinfo` a genuine authority boundary to work from — not proof of which
    /// internal scan runs — rather than string-matching `"://"` alone.
    #[test]
    fn test_generate_diagnostics_from_cache_blocked_registry_message_redacts_userinfo_in_declaration_key_without_scheme_slashes()
     {
        let slash_less_credential = "https:user:hunter2@10.0.0.1/index";
        let blocked_diagnostic =
            blocked_diagnostic_for(slash_less_credential, slash_less_credential);
        assert!(
            blocked_diagnostic
                .message()
                .contains("declaration: https://***@10.0.0.1/index"),
            "declaration_key's userinfo must be redacted even without \"://\", \
             got: {blocked_diagnostic:?}"
        );
    }

    /// #981: `declaration_key` opaque labels that merely *look* userinfo/credential-shaped
    /// (`"scope:@myorg"`, an npm scoped-registry label; `"source:Blocked"`, a NuGet source
    /// label; plus every other fixed label the remaining ecosystem crates emit) must survive
    /// unredacted — none of them are authority-bearing URLs, and `redact_declaration_key`'s
    /// credential-shape scan finds no genuine `user:pass@`-shaped credential in any of them, so
    /// all take the plain query/fragment-strip branch instead of `url_for_tracing`'s aggressive
    /// text-scan fallbacks, which would otherwise mangle e.g. `"scope:@myorg"` into
    /// `"***@myorg"` or `"source:Blocked"` into `"source:***"`.
    #[test]
    fn test_generate_diagnostics_from_cache_blocked_registry_message_does_not_mangle_opaque_declaration_keys()
     {
        for opaque_key in [
            "scope:@myorg",
            "source:Blocked",
            "top-level",
            "primary",
            "uv-tail",
            "named:internal",
            "goproxy",
            "component-host:10.0.0.1",
        ] {
            let blocked_diagnostic =
                blocked_diagnostic_for(opaque_key, "https://169.254.169.254/index");
            assert!(
                blocked_diagnostic
                    .message()
                    .contains(&format!("declaration: {opaque_key}")),
                "opaque declaration_key {opaque_key:?} must survive unmangled, \
                 got: {blocked_diagnostic:?}"
            );
        }
    }

    /// #981 S1 (impl-critic regression on the first #981 fix): `is_authority_bearing_url`
    /// alone is not a superset of the pre-#981 `.contains("://")` gate. An opaque-label-prefixed
    /// `declaration_key` (`"source:https://user:hunter2@10.0.0.1/v3/index.json"`, the shape
    /// NuGet's `format!("source:{}", entry.key)` or PyPI's `format!("named:{name}")` build from
    /// a user-chosen source name) parses with `Url::parse` treating `"source"` as the scheme
    /// and the rest as an opaque, host-less path — `is_authority_bearing_url` returns `false`
    /// for it — so the gate must still catch this shape another way (now: credential shape, not
    /// `.contains("://")`), the same way the pre-#981 code did.
    #[test]
    fn test_generate_diagnostics_from_cache_blocked_registry_message_still_redacts_opaque_label_prefixed_url_in_declaration_key()
     {
        let blocked_diagnostic = blocked_diagnostic_for(
            "source:https://user:hunter2@10.0.0.1/v3/index.json",
            "https://10.0.0.1/v3/index.json",
        );
        assert!(
            blocked_diagnostic
                .message()
                .contains("declaration: source:https://***@10.0.0.1/v3/index.json"),
            "an opaque-label-prefixed URL's userinfo must still be redacted, \
             got: {blocked_diagnostic:?}"
        );
    }

    /// #993 (residual #981 gap), then S1 from impl-critic on the first #993 fix: gating on a
    /// bare `"//"` substring closed only the exact shape in the original report and left the
    /// identical leak open for any other separator (a single `/`, no slash at all, or a
    /// percent-encoded `"//"`) — all reachable from real config
    /// (`deps-nuget::config::PackageSourceCredentials`'s `format!("source:{}", entry.key)` from
    /// an unvalidated `NuGet.config` `<add key>`, `deps-pypi::config`'s `format!("named:{name}")`,
    /// `deps-gitlab-ci::parser`'s `format!("component-host:{}", host_expr)`).
    /// `redact_declaration_key`'s `find_credential_at`-based shape check has no opinion on
    /// separators at all, so it closes all four uniformly.
    #[test]
    fn test_generate_diagnostics_from_cache_blocked_registry_message_redacts_declaration_key_credential_regardless_of_separator()
     {
        for (declaration_key, expected_declaration) in [
            ("source:feed//user:hunter2@h", "***@h"),
            (
                "source:feed/user:hunter2@nuget.internal",
                "***@nuget.internal",
            ),
            (
                "source:user:ghp_SECRET@nuget.pkg.github.com/OWNER/index.json",
                "***@nuget.pkg.github.com/OWNER/index.json",
            ),
            ("source:feed%2F%2Fuser:hunter2@h", "***@h"),
            ("named:user:hunter2@pypi.internal", "***@pypi.internal"),
            (
                "component-host:user:hunter2@gitlab.internal",
                "***@gitlab.internal",
            ),
        ] {
            let blocked_diagnostic =
                blocked_diagnostic_for(declaration_key, "https://169.254.169.254/index");
            assert!(
                blocked_diagnostic
                    .message()
                    .contains(&format!("declaration: {expected_declaration}")),
                "declaration_key {declaration_key:?} must redact to {expected_declaration:?}, \
                 got: {blocked_diagnostic:?}"
            );
        }
    }

    /// #993 S2 (impl-critic on the first #993 fix): a `declaration_key` merely *containing*
    /// `"//"` with no `@` at all — a plausible custom source/component-host label naming, e.g.
    /// a path-shaped feed or a `host//group` value — must survive unmangled. The credential-shape
    /// gate only fires on an actual [`find_credential_at`] match, never on a bare separator
    /// substring, so a label with no `@` never reaches `url_for_tracing`'s aggressive scans; an
    /// earlier, separator-based version of this gate (a bare `.contains("//")` check) redacted
    /// all three of these to `"***//..."`, destroying the one useful piece of information the
    /// diagnostic exists to show.
    #[test]
    fn test_generate_diagnostics_from_cache_blocked_registry_message_does_not_mangle_double_slash_labels_without_credential()
     {
        for opaque_key in [
            "source:feed//mirror",
            "component-host:gitlab.example.com//group",
            "named:my//index",
        ] {
            let blocked_diagnostic =
                blocked_diagnostic_for(opaque_key, "https://169.254.169.254/index");
            assert!(
                blocked_diagnostic
                    .message()
                    .contains(&format!("declaration: {opaque_key}")),
                "opaque declaration_key {opaque_key:?} must survive unmangled, \
                 got: {blocked_diagnostic:?}"
            );
        }
    }

    /// #925 S2 (then corrected by a later code-review pass, finding #3): a config-global
    /// block (e.g. a single blocked top-level registry override) applies identically to every
    /// dependency in the file — `blocked_registries()` reports one entry per affected
    /// dependency, so without dedup this fans out to as many identical `INFORMATION`
    /// diagnostics as there are dependencies. Two entries sharing the same **declaration
    /// key** must collapse to exactly one diagnostic, kept at the first-reported range — but a
    /// *third* entry sharing the identical `(class, raw_value)` pair through a genuinely
    /// *different* declaration key (two independent declarations that merely coincide on
    /// value — e.g. an npm top-level `registry=` and an unrelated `@scope:registry=`, both
    /// blocked to the same URL) must still get its own diagnostic: deduping by value alone
    /// would have silently dropped it.
    #[test]
    fn test_generate_diagnostics_from_cache_dedups_by_declaration_key_not_by_value() {
        use crate::net_policy::HostClass;
        use crate::position::{Position, Range};

        struct BlockedRegistryParseResult {
            deps: Vec<MockDep>,
            uri: url::Url,
            blocked: Vec<BlockedRegistryOccurrence>,
        }

        impl ParseResult for BlockedRegistryParseResult {
            fn dependencies(&self) -> Vec<&dyn Dependency> {
                self.deps.iter().map(|d| d as &dyn Dependency).collect()
            }
            fn workspace_root(&self) -> Option<&std::path::Path> {
                None
            }
            fn uri(&self) -> &url::Url {
                &self.uri
            }
            fn blocked_registries(&self) -> Vec<BlockedRegistryOccurrence> {
                self.blocked.clone()
            }
            fn as_any(&self) -> &dyn std::any::Any {
                self
            }
        }

        let first_range = Range::new(Position::new(0, 0), Position::new(0, 14));
        let second_range = Range::new(Position::new(1, 0), Position::new(1, 14));
        let third_range = Range::new(Position::new(2, 0), Position::new(2, 14));
        let formatter = MockFormatter;
        let parse_result = BlockedRegistryParseResult {
            deps: vec![
                MockDep {
                    name: "first-crate".into(),
                    version_req: "1.0.0".into(),
                    version_range: Range::new(Position::new(0, 20), Position::new(0, 25)),
                    name_range: first_range,
                },
                MockDep {
                    name: "second-crate".into(),
                    version_req: "1.0.0".into(),
                    version_range: Range::new(Position::new(1, 20), Position::new(1, 25)),
                    name_range: second_range,
                },
                MockDep {
                    name: "third-crate".into(),
                    version_req: "1.0.0".into(),
                    version_range: Range::new(Position::new(2, 20), Position::new(2, 25)),
                    name_range: third_range,
                },
            ],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
            blocked: vec![
                // Same declaration ("top-level"), same value — genuinely the same config-wide
                // block, referenced by two dependencies. Must collapse to one diagnostic.
                BlockedRegistryOccurrence {
                    range: first_range,
                    class: HostClass::CloudMetadata,
                    raw_value: "https://169.254.169.254/index".to_string(),
                    declaration_key: "top-level".to_string(),
                },
                BlockedRegistryOccurrence {
                    range: second_range,
                    class: HostClass::CloudMetadata,
                    raw_value: "https://169.254.169.254/index".to_string(),
                    declaration_key: "top-level".to_string(),
                },
                // A different declaration ("scope:@myorg") that happens to share the exact
                // same (class, raw_value) — must NOT be swallowed by the dedup above.
                BlockedRegistryOccurrence {
                    range: third_range,
                    class: HostClass::CloudMetadata,
                    raw_value: "https://169.254.169.254/index".to_string(),
                    declaration_key: "scope:@myorg".to_string(),
                },
            ],
        };

        let cached_versions = HashMap::new();
        let resolved_versions = HashMap::new();

        let diagnostics = generate_diagnostics_from_cache(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions),
            &formatter,
            parse_result.uri(),
            crate::freshness::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
            PublishTime::now(),
        );

        let blocked_diagnostics: Vec<_> = diagnostics
            .iter()
            .filter(|d| d.message().contains("blocked"))
            .collect();
        assert_eq!(
            blocked_diagnostics.len(),
            2,
            "two entries sharing a declaration key must collapse to one diagnostic, but a \
             third entry with a different declaration key must still get its own, got: \
             {blocked_diagnostics:?}"
        );
        let ranges: Vec<Range> = blocked_diagnostics.iter().map(|d| d.range).collect();
        assert!(ranges.contains(&first_range));
        assert!(ranges.contains(&third_range));
        assert!(
            !ranges.contains(&second_range),
            "the deduped-away entry must be the second occurrence of the same declaration key, \
             not the third (different-declaration) entry"
        );

        // #944 M8: the collapsed-away second occurrence must not vanish outright — it must
        // stay discoverable via `related_information` on the anchor diagnostic, naming the
        // dependency it belongs to.
        let anchor = blocked_diagnostics
            .iter()
            .find(|d| d.range == first_range)
            .expect("anchor diagnostic for the shared declaration key must exist");
        let related = anchor
            .related_information
            .as_ref()
            .expect("anchor diagnostic must carry related_information for the collapsed sibling");
        assert_eq!(related.len(), 1);
        assert_eq!(related[0].range, second_range);
        assert!(
            related[0].message().contains("second-crate"),
            "related_information message must name the collapsed sibling dependency, got: {:?}",
            related[0].message()
        );

        // Impl-critic M1 (#965/#966): the anchor ("top-level") and third entry
        // ("scope:@myorg") share the identical `raw_value`/`class` — without the
        // declaration key in the message, they'd render byte-identical.
        let third = blocked_diagnostics
            .iter()
            .find(|d| d.range == third_range)
            .expect("diagnostic for the differently-declared third occurrence must exist");
        assert_ne!(
            anchor.message(),
            third.message(),
            "two independently-declared blocked sources sharing the same raw_value must not \
             render byte-identical diagnostic messages"
        );
        assert!(anchor.message().contains("top-level"));
        assert!(third.message().contains("scope:@myorg"));
    }

    /// Critic follow-up S2 (#1242, #1246): the collapsed blocked-registry sibling named in
    /// `related_information` (`'{name}' also blocked by the same registry policy`) must be
    /// redacted the same way `FetchFailureEntry.name` is — it is built from the identical
    /// `dep.name().as_str()` shape, just for a different rule.
    #[test]
    fn test_generate_diagnostics_from_cache_redacts_credential_in_blocked_registry_related_info() {
        use crate::net_policy::HostClass;
        use crate::position::{Position, Range};

        struct BlockedRegistryParseResult {
            deps: Vec<MockDep>,
            uri: url::Url,
            blocked: Vec<BlockedRegistryOccurrence>,
        }

        impl ParseResult for BlockedRegistryParseResult {
            fn dependencies(&self) -> Vec<&dyn Dependency> {
                self.deps.iter().map(|d| d as &dyn Dependency).collect()
            }
            fn workspace_root(&self) -> Option<&std::path::Path> {
                None
            }
            fn uri(&self) -> &url::Url {
                &self.uri
            }
            fn blocked_registries(&self) -> Vec<BlockedRegistryOccurrence> {
                self.blocked.clone()
            }
            fn as_any(&self) -> &dyn std::any::Any {
                self
            }
        }

        let first_range = Range::new(Position::new(0, 0), Position::new(0, 14));
        let second_range = Range::new(Position::new(1, 0), Position::new(1, 14));
        let credential_name = "https://svcacct:glpat-AAAABBBBCCCCDDDD@gitlab.corp/g/p";
        let formatter = MockFormatter;
        let parse_result = BlockedRegistryParseResult {
            deps: vec![
                MockDep {
                    name: "first-crate".into(),
                    version_req: "1.0.0".into(),
                    version_range: Range::new(Position::new(0, 20), Position::new(0, 25)),
                    name_range: first_range,
                },
                MockDep {
                    name: credential_name.into(),
                    version_req: "1.0.0".into(),
                    version_range: Range::new(Position::new(1, 20), Position::new(1, 25)),
                    name_range: second_range,
                },
            ],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
            blocked: vec![
                BlockedRegistryOccurrence {
                    range: first_range,
                    class: HostClass::CloudMetadata,
                    raw_value: "https://169.254.169.254/index".to_string(),
                    declaration_key: "top-level".to_string(),
                },
                BlockedRegistryOccurrence {
                    range: second_range,
                    class: HostClass::CloudMetadata,
                    raw_value: "https://169.254.169.254/index".to_string(),
                    declaration_key: "top-level".to_string(),
                },
            ],
        };

        let cached_versions = HashMap::new();
        let resolved_versions = HashMap::new();

        let diagnostics = generate_diagnostics_from_cache(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions),
            &formatter,
            parse_result.uri(),
            crate::freshness::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
            PublishTime::now(),
        );

        let anchor = diagnostics
            .iter()
            .find(|d| d.range == first_range)
            .expect("anchor diagnostic for the shared declaration key must exist");
        let related = anchor
            .related_information
            .as_ref()
            .expect("anchor diagnostic must carry related_information for the collapsed sibling");
        assert_eq!(related.len(), 1);
        assert!(related[0].message().contains("***@"));
        assert!(!related[0].message().contains("glpat-AAAABBBBCCCCDDDD"));
    }

    /// #944 S2/M3 regression: `push_collapsed_blocked_registries` caps individually-named
    /// `related_information` siblings at [`MAX_BLOCKED_REGISTRY_RELATED_INFO`] (9) and folds
    /// everything beyond that into one trailing "and K more..." entry, instead of an unbounded
    /// fan-out. 12 dependencies sharing one declaration key -> 1 anchor + 11 siblings -> 9
    /// individually named, 2 folded.
    #[test]
    fn test_generate_diagnostics_from_cache_blocked_registry_related_info_capped_and_folded() {
        use crate::net_policy::HostClass;
        use crate::position::{Position, Range};

        struct BlockedRegistryParseResult {
            deps: Vec<MockDep>,
            uri: url::Url,
            blocked: Vec<BlockedRegistryOccurrence>,
        }

        impl ParseResult for BlockedRegistryParseResult {
            fn dependencies(&self) -> Vec<&dyn Dependency> {
                self.deps.iter().map(|d| d as &dyn Dependency).collect()
            }
            fn workspace_root(&self) -> Option<&std::path::Path> {
                None
            }
            fn uri(&self) -> &url::Url {
                &self.uri
            }
            fn blocked_registries(&self) -> Vec<BlockedRegistryOccurrence> {
                self.blocked.clone()
            }
            fn as_any(&self) -> &dyn std::any::Any {
                self
            }
        }

        const TOTAL: u32 = 12;
        let ranges: Vec<Range> = (0..TOTAL)
            .map(|i| Range::new(Position::new(i, 0), Position::new(i, 14)))
            .collect();
        let deps: Vec<MockDep> = ranges
            .iter()
            .enumerate()
            .map(|(i, &range)| MockDep {
                name: format!("crate-{i}").into(),
                version_req: "1.0.0".into(),
                version_range: Range::new(
                    Position::new(range.start.line, 20),
                    Position::new(range.start.line, 25),
                ),
                name_range: range,
            })
            .collect();
        let blocked: Vec<BlockedRegistryOccurrence> = ranges
            .iter()
            .map(|&range| BlockedRegistryOccurrence {
                range,
                class: HostClass::CloudMetadata,
                raw_value: "https://169.254.169.254/index".to_string(),
                declaration_key: "top-level".to_string(),
            })
            .collect();

        let formatter = MockFormatter;
        let parse_result = BlockedRegistryParseResult {
            deps,
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
            blocked,
        };

        let cached_versions = HashMap::new();
        let resolved_versions = HashMap::new();

        let diagnostics = generate_diagnostics_from_cache(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions),
            &formatter,
            parse_result.uri(),
            crate::freshness::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
            PublishTime::now(),
        );

        let blocked_diagnostics: Vec<_> = diagnostics
            .iter()
            .filter(|d| d.message().contains("blocked"))
            .collect();
        assert_eq!(
            blocked_diagnostics.len(),
            1,
            "all 12 occurrences share one declaration key and must collapse to one diagnostic"
        );
        let related = blocked_diagnostics[0]
            .related_information
            .as_ref()
            .expect("anchor diagnostic must carry related_information for the siblings");
        assert_eq!(
            related.len(),
            10,
            "9 individually-named siblings plus 1 folded '+N more' entry, got: {related:?}"
        );
        let named_count = related
            .iter()
            .filter(|r| r.message().contains('\''))
            .count();
        assert_eq!(
            named_count, 9,
            "exactly 9 siblings must be individually named, got: {related:?}"
        );
        let fold_entry = &related[9];
        assert!(
            fold_entry.message().contains("and 2 more"),
            "trailing fold entry must report the 2 siblings beyond the 9-entry cap, got: {:?}",
            fold_entry.message()
        );
        assert_eq!(
            fold_entry.range, blocked_diagnostics[0].range,
            "the fold entry must be anchored at the anchor diagnostic's own range"
        );
    }

    #[test]
    fn test_truncate_for_diagnostic_leaves_short_value_untouched() {
        assert_eq!(truncate_for_diagnostic("my-corp", 128), "my-corp");
    }

    #[test]
    fn test_truncate_for_diagnostic_truncates_and_appends_ellipsis() {
        let long_value = "a".repeat(200);
        let truncated = truncate_for_diagnostic(&long_value, 128);
        assert_eq!(truncated.chars().count(), 129); // 128 chars + the ellipsis marker
        assert!(truncated.ends_with('…'));
        assert!(truncated.starts_with(&"a".repeat(128)));
    }

    #[test]
    fn test_truncate_for_diagnostic_never_splits_a_multibyte_character() {
        // Each "日" is a multi-byte UTF-8 character; a byte-based truncation could panic or
        // produce invalid UTF-8 landing mid-character.
        let long_value = "日".repeat(200);
        let truncated = truncate_for_diagnostic(&long_value, 128);
        assert_eq!(truncated.chars().count(), 129);
    }

    /// The reviewer's finding: `raw_value` is attacker-controlled and unbounded upstream (no
    /// TOML string-length cap exists, only nesting-depth/table-count caps) — the diagnostic
    /// message itself must still cap it before interpolation.
    #[test]
    fn test_generate_diagnostics_from_cache_blocked_registry_message_caps_long_raw_value() {
        use crate::net_policy::HostClass;
        use crate::position::{Position, Range};

        struct BlockedRegistryParseResult {
            deps: Vec<MockDep>,
            uri: url::Url,
            blocked: Vec<BlockedRegistryOccurrence>,
        }

        impl ParseResult for BlockedRegistryParseResult {
            fn dependencies(&self) -> Vec<&dyn Dependency> {
                self.deps.iter().map(|d| d as &dyn Dependency).collect()
            }
            fn workspace_root(&self) -> Option<&std::path::Path> {
                None
            }
            fn uri(&self) -> &url::Url {
                &self.uri
            }
            fn blocked_registries(&self) -> Vec<BlockedRegistryOccurrence> {
                self.blocked.clone()
            }
            fn as_any(&self) -> &dyn std::any::Any {
                self
            }
        }

        let name_range = Range::new(Position::new(0, 0), Position::new(0, 14));
        let formatter = MockFormatter;
        let long_alias = "x".repeat(10_000);
        let parse_result = BlockedRegistryParseResult {
            deps: vec![MockDep {
                name: "internal-crate".into(),
                version_req: "1.0.0".into(),
                version_range: Range::new(Position::new(0, 20), Position::new(0, 25)),
                name_range,
            }],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
            blocked: vec![BlockedRegistryOccurrence {
                range: name_range,
                class: HostClass::InternalName,
                raw_value: long_alias.clone(),
                declaration_key: long_alias.clone(),
            }],
        };

        let cached_versions = HashMap::new();
        let resolved_versions = HashMap::new();

        let diagnostics = generate_diagnostics_from_cache(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions),
            &formatter,
            parse_result.uri(),
            crate::freshness::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
            PublishTime::now(),
        );

        let blocked_diagnostic = diagnostics
            .iter()
            .find(|d| d.message().contains("blocked"))
            .expect("expected a blocked-registry diagnostic");
        assert!(
            blocked_diagnostic.message().len() < long_alias.len(),
            "a 10,000-char alias must not render in full inside the diagnostic message"
        );
        assert!(blocked_diagnostic.message().contains('…'));
    }

    /// #1255: a bidirectional-override or other invisible character embedded in a blocked
    /// registry's raw declared value or declaration key must not survive into the client-
    /// visible diagnostic message either — the same Trojan Source / CVE-2021-42574 concern
    /// [`test_generate_diagnostics_from_cache_sanitizes_bidi_override_in_name`] covers for a
    /// dependency name.
    #[test]
    fn test_generate_diagnostics_from_cache_blocked_registry_message_sanitizes_bidi_override() {
        let raw_value = "https://index.mycorp.dev/api\u{202E}evil";
        let declaration_key = "source\u{202E}evil";
        let blocked_diagnostic = blocked_diagnostic_for(declaration_key, raw_value);
        assert!(!blocked_diagnostic.message().contains('\u{202E}'));
        assert!(blocked_diagnostic.message().contains("index.mycorp.dev"));
    }

    /// #1263: a bidirectional-override embedded in the manifest-declared requirement, or in
    /// the registry-reported `latest` version, must not survive into the unsatisfiable-
    /// requirement diagnostic message.
    #[test]
    fn test_generate_diagnostics_from_cache_unsatisfiable_sanitizes_bidi_in_requirement_and_latest()
    {
        struct AlwaysUnsatisfiable;
        struct NeverMatches;
        impl RequirementMatcher for NeverMatches {
            fn matches(&self, _version: &ConcreteVersion) -> Option<bool> {
                Some(false)
            }
        }
        impl PackageNaming for AlwaysUnsatisfiable {}
        impl PackageRendering for AlwaysUnsatisfiable {
            fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
                version.to_string()
            }
            fn package_url(&self, name: &PackageName) -> String {
                name.as_str().to_string()
            }
        }
        impl RequirementResolution for AlwaysUnsatisfiable {
            fn compile_requirement(
                &self,
                _requirement: &VersionReq,
            ) -> Option<Box<dyn RequirementMatcher>> {
                Some(Box::new(NeverMatches))
            }
        }
        impl DiagnosticMessages for AlwaysUnsatisfiable {}
        impl DiagnosticPolicy for AlwaysUnsatisfiable {}
        impl SourcePolicy for AlwaysUnsatisfiable {}
        impl OsvNaming for AlwaysUnsatisfiable {}

        let mut cached_versions = HashMap::new();
        cached_versions.insert(
            "dep".into(),
            PackageVersions {
                latest: "1.0.0\u{202E}evil".into(),
                available: Arc::from(vec!["1.0.0\u{202E}evil".into()]),
                yanked: Arc::from(Vec::new()),
                published_at: None,
            },
        );
        let resolved_versions = HashMap::new();
        let mut dependency = dep_at("dep");
        dependency.version_req = VersionReq::new("^2.0.0\u{202E}evil");
        let parse_result = SingleDepParseResult {
            dep: dependency,
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let diagnostics = generate_diagnostics_from_cache(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions),
            &AlwaysUnsatisfiable,
            parse_result.uri(),
            crate::freshness::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
            PublishTime::now(),
        );

        let message = diagnostics
            .iter()
            .find(|d| d.message().contains("No published version satisfies"))
            .map(|d| d.message())
            .expect("unsatisfiable diagnostic must fire");
        assert!(!message.contains('\u{202E}'));
        assert!(message.contains("2.0.0"));
        assert!(message.contains("1.0.0"));
    }

    /// #1263: a bidirectional-override embedded in a registry-reported yanked version must
    /// not survive into the in-use-yanked diagnostic message.
    #[test]
    fn test_generate_diagnostics_from_cache_in_use_yanked_sanitizes_bidi_in_version() {
        use crate::position::{Position, Range};
        use std::collections::HashMap;

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
        let outcomes = DependencyOutcomes::new()
            .with_yanked("serde", ("1.0.5\u{202E}evil".into(), RemovalStatus::Yanked));

        let diagnostics = generate_diagnostics_from_cache(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions).with_outcomes(&outcomes),
            &formatter,
            parse_result.uri(),
            crate::freshness::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
            PublishTime::now(),
        );

        let yanked_diag = diagnostics
            .iter()
            .find(|d| d.message().starts_with(formatter.yanked_message()))
            .expect("expected a yanked diagnostic");
        assert!(!yanked_diag.message().contains('\u{202E}'));
        assert!(yanked_diag.message().contains("1.0.5"));
    }

    /// #1263: a bidirectional-override embedded in the registry-reported `latest` version
    /// must not survive into the outdated diagnostic message.
    #[test]
    fn test_generate_diagnostics_from_cache_outdated_sanitizes_bidi_in_latest() {
        use crate::position::{Position, Range};
        use std::collections::HashMap;

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
            PackageVersions::latest_only("2.0.0\u{202E}evil"),
        );

        let resolved_versions = HashMap::new();

        let diagnostics = generate_diagnostics_from_cache(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions),
            &formatter,
            parse_result.uri(),
            crate::freshness::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
            PublishTime::now(),
        );

        assert_eq!(diagnostics.len(), 1);
        assert!(!diagnostics[0].message().contains('\u{202E}'));
        assert!(diagnostics[0].message().contains("2.0.0"));
    }

    /// #1263 critic M3: `MAX_VERSION_DIAGNOSTIC_CHARS` must actually truncate an
    /// over-length `latest` version, not just strip bidi characters from a short one.
    #[test]
    fn test_generate_diagnostics_from_cache_outdated_truncates_oversized_latest() {
        use crate::position::{Position, Range};
        use std::collections::HashMap;

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

        let overlong_latest = format!("2.0.0-{}", "X".repeat(MAX_VERSION_DIAGNOSTIC_CHARS + 50));
        let mut cached_versions = HashMap::new();
        cached_versions.insert(
            "serde".into(),
            PackageVersions::latest_only(overlong_latest.clone()),
        );

        let resolved_versions = HashMap::new();

        let diagnostics = generate_diagnostics_from_cache(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions),
            &formatter,
            parse_result.uri(),
            crate::freshness::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
            PublishTime::now(),
        );

        assert_eq!(diagnostics.len(), 1);
        assert!(diagnostics[0].message().contains('…'));
        assert!(
            !diagnostics[0].message().contains(&overlong_latest),
            "expected `latest` to be truncated rather than interpolated verbatim, got: {:?}",
            diagnostics[0].message()
        );
    }

    /// #1263 follow-up sweep: a bidirectional-override or oversized string in a registry-
    /// reported deprecation's `reason`/`replacement` must not survive unsanitized/unbounded
    /// into the deprecation diagnostic message.
    #[test]
    fn test_generate_diagnostics_from_cache_deprecation_sanitizes_bidi_and_caps_reason() {
        use crate::position::{Position, Range};
        use std::collections::HashMap;

        let formatter = MockFormatter;
        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "left-pad".into(),
                version_req: "1.3.0".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)),
            }],
            uri: crate::test_util::test_uri("/test/package.json"),
        };

        let mut cached_versions = HashMap::new();
        cached_versions.insert("left-pad".into(), PackageVersions::latest_only("1.3.0"));
        let resolved_versions = HashMap::new();
        let overlong_reason = "X".repeat(MAX_DIAGNOSTIC_PROSE_CHARS + 50);
        let outcomes = DependencyOutcomes::new().with_deprecation(
            "left-pad",
            Deprecation {
                reason: Some(format!("bidi\u{202E}{overlong_reason}")),
                replacement: Some("left-pad\u{202E}evil".to_string()),
            },
        );

        let diagnostics = generate_diagnostics_from_cache(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions).with_outcomes(&outcomes),
            &formatter,
            parse_result.uri(),
            crate::freshness::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
            PublishTime::now(),
        );

        let deprecation_diag = diagnostics
            .iter()
            .find(|d| d.code() == Some(DEPRECATED_DIAGNOSTIC_CODE))
            .expect("expected a deprecation diagnostic");
        assert!(!deprecation_diag.message().contains('\u{202E}'));
        assert!(deprecation_diag.message().contains('…'));
        assert!(
            !deprecation_diag.message().contains(&overlong_reason),
            "expected the reason to be truncated rather than interpolated verbatim, got: {:?}",
            deprecation_diag.message()
        );
    }

    #[test]
    fn test_generate_diagnostics_from_cache_fetch_failed_not_reported_as_unknown() {
        use crate::position::{Position, Range};
        use std::collections::HashMap;

        // A package missing from `cached` due to a fetch error/timeout (#267) must not be
        // reported as "Unknown package" — it was never successfully asked about.
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
        let outcomes =
            DependencyOutcomes::new().with_fetch_failure("flaky-pkg", FetchFailure::Transient);

        let diagnostics = generate_diagnostics_from_cache(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions).with_outcomes(&outcomes),
            &formatter,
            parse_result.uri(),
            crate::freshness::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
            PublishTime::now(),
        );

        assert_eq!(diagnostics.len(), 1);
        assert!(!diagnostics[0].message().contains("Unknown package"));
        assert!(diagnostics[0].message().contains("Registry lookup failed"));
        assert!(diagnostics[0].message().contains("flaky-pkg"));
    }

    /// Issue #483 I2: while offline, the per-dependency "Registry lookup failed" WARNING
    /// (misattributing a deliberately configured mode to a registry failure) must be
    /// replaced by exactly one file-level INFORMATION diagnostic, not emitted per
    /// dependency — the same noise argument that justified suppressing the failure toast.
    #[test]
    fn test_generate_diagnostics_from_cache_offline_suppresses_per_dependency_warning() {
        use crate::position::{Position, Range};
        use std::collections::HashMap;

        let formatter = MockFormatter;

        let parse_result = MockParseResult {
            deps: vec![
                MockDep {
                    name: "flaky-pkg-a".into(),
                    version_req: "1.0.0".into(),
                    version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                    name_range: Range::new(Position::new(0, 0), Position::new(0, 11)),
                },
                MockDep {
                    name: "flaky-pkg-b".into(),
                    version_req: "1.0.0".into(),
                    version_range: Range::new(Position::new(1, 10), Position::new(1, 20)),
                    name_range: Range::new(Position::new(1, 0), Position::new(1, 11)),
                },
            ],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let cached_versions = HashMap::new();
        let resolved_versions = HashMap::new();
        let outcomes = DependencyOutcomes::new()
            .with_fetch_failure("flaky-pkg-a", FetchFailure::Transient)
            .with_fetch_failure("flaky-pkg-b", FetchFailure::Transient);

        let diagnostics = generate_diagnostics_from_cache(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions)
                .with_outcomes(&outcomes)
                .with_offline(true),
            &formatter,
            parse_result.uri(),
            crate::freshness::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
            PublishTime::now(),
        );

        assert!(
            !diagnostics
                .iter()
                .any(|d| d.message().contains("Registry lookup failed")),
            "the per-dependency WARNING must not fire while offline, got: {diagnostics:?}"
        );
        let offline_diagnostics: Vec<_> = diagnostics
            .iter()
            .filter(|d| d.severity == Some(Severity::Information))
            .filter(|d| d.message().to_lowercase().contains("offline"))
            .collect();
        assert_eq!(
            offline_diagnostics.len(),
            1,
            "expected exactly one file-level offline diagnostic, not one per dependency; \
             got: {diagnostics:?}"
        );
    }

    /// Issue #483 I2: an offline document with no fetch failures at all (everything
    /// served from a warm cache) must still surface the file-level offline signal — S2's
    /// premise is that "no warning" must not read as "safe" in this persistent mode,
    /// independent of whether any individual dependency's lookup happened to fail.
    #[test]
    fn test_generate_diagnostics_from_cache_offline_signal_present_even_with_no_fetch_failures() {
        use crate::position::{Position, Range};
        use std::collections::HashMap;

        let formatter = MockFormatter;

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "serde".into(),
                version_req: "=1.0.0".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)),
            }],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let mut cached_versions = HashMap::new();
        cached_versions.insert("serde".into(), PackageVersions::latest_only("1.0.0"));
        let resolved_versions = HashMap::new();

        let diagnostics = generate_diagnostics_from_cache(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions).with_offline(true),
            &formatter,
            parse_result.uri(),
            crate::freshness::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
            PublishTime::now(),
        );

        assert!(
            diagnostics
                .iter()
                .any(|d| d.severity == Some(Severity::Information)
                    && d.message().to_lowercase().contains("offline")),
            "expected a file-level offline diagnostic even with zero fetch failures; \
             got: {diagnostics:?}"
        );
    }

    #[test]
    fn test_generate_diagnostics_from_cache_fetch_failed_actionable_shows_hint() {
        use crate::position::{Position, Range};
        use std::collections::HashMap;

        // #478: an `Actionable` fetch failure must surface its pre-vetted hint
        // text in the diagnostic, not the generic fallback.
        let formatter = MockFormatter;

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "rate-limited-pkg".into(),
                version_req: "1.0.0".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 16)),
            }],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let cached_versions = HashMap::new();
        let resolved_versions = HashMap::new();
        let outcomes = DependencyOutcomes::new().with_fetch_failure(
            "rate-limited-pkg",
            FetchFailure::Actionable("set GITHUB_TOKEN to increase the rate limit".to_string()),
        );

        let diagnostics = generate_diagnostics_from_cache(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions).with_outcomes(&outcomes),
            &formatter,
            parse_result.uri(),
            crate::freshness::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
            PublishTime::now(),
        );

        assert_eq!(diagnostics.len(), 1);
        assert!(!diagnostics[0].message().contains("Unknown package"));
        assert!(
            diagnostics[0]
                .message()
                .contains("set GITHUB_TOKEN to increase the rate limit")
        );
        assert!(diagnostics[0].message().contains("rate-limited-pkg"));
    }

    #[test]
    fn test_generate_diagnostics_from_cache_multiple_fetch_failed_collapse_into_one_diagnostic() {
        use crate::position::{Position, Range};
        use std::collections::HashMap;

        // #479: a registry-wide condition can fail every remaining dependency identically;
        // asserts the 2+ case collapses onto the first failing dependency's range, with the
        // count in the message.
        let formatter = MockFormatter;

        let name_range_1 = Range::new(Position::new(0, 0), Position::new(0, 8));
        let name_range_2 = Range::new(Position::new(1, 0), Position::new(1, 8));
        let name_range_3 = Range::new(Position::new(2, 0), Position::new(2, 8));

        let parse_result = MockParseResult {
            deps: vec![
                MockDep {
                    name: "flaky-1".into(),
                    version_req: "1.0.0".into(),
                    version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                    name_range: name_range_1,
                },
                MockDep {
                    name: "flaky-2".into(),
                    version_req: "1.0.0".into(),
                    version_range: Range::new(Position::new(1, 10), Position::new(1, 20)),
                    name_range: name_range_2,
                },
                MockDep {
                    name: "flaky-3".into(),
                    version_req: "1.0.0".into(),
                    version_range: Range::new(Position::new(2, 10), Position::new(2, 20)),
                    name_range: name_range_3,
                },
            ],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let cached_versions = HashMap::new();
        let resolved_versions = HashMap::new();
        let outcomes = DependencyOutcomes::new()
            .with_fetch_failure("flaky-1", FetchFailure::Transient)
            .with_fetch_failure("flaky-2", FetchFailure::Transient)
            .with_fetch_failure("flaky-3", FetchFailure::Transient);

        let diagnostics = generate_diagnostics_from_cache(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions).with_outcomes(&outcomes),
            &formatter,
            parse_result.uri(),
            crate::freshness::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
            PublishTime::now(),
        );

        assert_eq!(
            diagnostics.len(),
            1,
            "3 fetch-failed dependencies must collapse into exactly one diagnostic, got: {diagnostics:?}"
        );
        assert!(
            diagnostics[0]
                .message()
                .contains("Registry lookup failed for 3 packages")
        );
        assert_eq!(
            diagnostics[0].range, name_range_1,
            "the combined diagnostic must sit on the first failing dependency's range"
        );

        // #480 S2: the collapse must not silently drop the other failing dependencies —
        // each one beyond the first survives via `related_information`, keyed to its own
        // name and `name_range`.
        let related_information = diagnostics[0]
            .related_information
            .as_ref()
            .expect("collapsed diagnostic must carry related_information for the dropped deps");
        assert_eq!(
            related_information.len(),
            2,
            "expected one related_information entry per additional failing dependency (n - 1)"
        );
        assert_eq!(related_information[0].range, name_range_2);
        assert_eq!(related_information[0].uri, parse_result.uri().clone());
        assert!(related_information[0].message().contains("flaky-2"));
        assert_eq!(related_information[1].range, name_range_3);
        assert_eq!(related_information[1].uri, parse_result.uri().clone());
        assert!(related_information[1].message().contains("flaky-3"));
    }

    #[test]
    fn test_generate_diagnostics_from_cache_two_fetch_failed_collapse_boundary() {
        use crate::position::{Position, Range};
        use std::collections::HashMap;

        // n==2 is the lowest n that collapses at all (n==1 stays per-dependency, see
        // `test_generate_diagnostics_from_cache_fetch_failed_not_reported_as_unknown`);
        // confirms `related_information` is populated right at that threshold.
        let formatter = MockFormatter;

        let name_range_1 = Range::new(Position::new(0, 0), Position::new(0, 8));
        let name_range_2 = Range::new(Position::new(1, 0), Position::new(1, 8));

        let parse_result = MockParseResult {
            deps: vec![
                MockDep {
                    name: "flaky-1".into(),
                    version_req: "1.0.0".into(),
                    version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                    name_range: name_range_1,
                },
                MockDep {
                    name: "flaky-2".into(),
                    version_req: "1.0.0".into(),
                    version_range: Range::new(Position::new(1, 10), Position::new(1, 20)),
                    name_range: name_range_2,
                },
            ],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let cached_versions = HashMap::new();
        let resolved_versions = HashMap::new();
        let outcomes = DependencyOutcomes::new()
            .with_fetch_failure("flaky-1", FetchFailure::Transient)
            .with_fetch_failure("flaky-2", FetchFailure::Transient);

        let diagnostics = generate_diagnostics_from_cache(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions).with_outcomes(&outcomes),
            &formatter,
            parse_result.uri(),
            crate::freshness::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
            PublishTime::now(),
        );

        assert_eq!(
            diagnostics.len(),
            1,
            "2 fetch-failed dependencies must already collapse into one diagnostic, got: {diagnostics:?}"
        );
        assert!(
            diagnostics[0]
                .message()
                .contains("Registry lookup failed for 2 packages")
        );
        let related_information = diagnostics[0]
            .related_information
            .as_ref()
            .expect("the n==2 collapse must already carry related_information");
        assert_eq!(
            related_information.len(),
            1,
            "n==2 collapse must carry exactly one related_information entry (n - 1)"
        );
        assert_eq!(related_information[0].range, name_range_2);
        assert_eq!(related_information[0].uri, parse_result.uri().clone());
        assert!(related_information[0].message().contains("flaky-2"));
    }

    #[test]
    fn test_generate_diagnostics_from_cache_multiple_fetch_failed_shared_actionable_hint() {
        use crate::position::{Position, Range};
        use std::collections::HashMap;

        // #478/#485 + #479: a rate-limit gate fails every remaining dependency with the SAME
        // `Actionable` hint — the #479 collapse must not silently drop it.
        let formatter = MockFormatter;

        let name_range_1 = Range::new(Position::new(0, 0), Position::new(0, 8));
        let name_range_2 = Range::new(Position::new(1, 0), Position::new(1, 8));
        let name_range_3 = Range::new(Position::new(2, 0), Position::new(2, 8));

        let parse_result = MockParseResult {
            deps: vec![
                MockDep {
                    name: "flaky-1".into(),
                    version_req: "1.0.0".into(),
                    version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                    name_range: name_range_1,
                },
                MockDep {
                    name: "flaky-2".into(),
                    version_req: "1.0.0".into(),
                    version_range: Range::new(Position::new(1, 10), Position::new(1, 20)),
                    name_range: name_range_2,
                },
                MockDep {
                    name: "flaky-3".into(),
                    version_req: "1.0.0".into(),
                    version_range: Range::new(Position::new(2, 10), Position::new(2, 20)),
                    name_range: name_range_3,
                },
            ],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let cached_versions = HashMap::new();
        let resolved_versions = HashMap::new();
        let shared_hint = "set GITHUB_TOKEN to increase the rate limit".to_string();
        let outcomes = DependencyOutcomes::new()
            .with_fetch_failure("flaky-1", FetchFailure::Actionable(shared_hint.clone()))
            .with_fetch_failure("flaky-2", FetchFailure::Actionable(shared_hint.clone()))
            .with_fetch_failure("flaky-3", FetchFailure::Actionable(shared_hint.clone()));

        let diagnostics = generate_diagnostics_from_cache(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions).with_outcomes(&outcomes),
            &formatter,
            parse_result.uri(),
            crate::freshness::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
            PublishTime::now(),
        );

        assert_eq!(
            diagnostics.len(),
            1,
            "3 fetch-failed dependencies must still collapse into exactly one diagnostic, got: {diagnostics:?}"
        );
        assert!(
            diagnostics[0].message().contains(&shared_hint),
            "collapsed diagnostic must surface the shared actionable hint, got: {}",
            diagnostics[0].message()
        );
        assert!(
            !diagnostics[0]
                .message()
                .contains("package status could not be determined"),
            "the actionable hint must replace, not accompany, the generic fallback message"
        );
        let related_information = diagnostics[0]
            .related_information
            .as_ref()
            .expect("collapsed diagnostic must carry related_information for the dropped deps");
        assert_eq!(
            related_information.len(),
            2,
            "expected one related_information entry per additional failing dependency (n - 1)"
        );
    }

    #[test]
    fn test_generate_diagnostics_from_cache_fetch_failed_transient_shows_generic_message() {
        use crate::position::{Position, Range};
        use std::collections::HashMap;

        // A `Transient` fetch failure has no safe detail to show, so it must
        // fall back to the generic "package status could not be determined"
        // message rather than leak anything failure-specific.
        let formatter = MockFormatter;

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "transient-pkg".into(),
                version_req: "1.0.0".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 13)),
            }],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let cached_versions = HashMap::new();
        let resolved_versions = HashMap::new();
        let outcomes =
            DependencyOutcomes::new().with_fetch_failure("transient-pkg", FetchFailure::Transient);

        let diagnostics = generate_diagnostics_from_cache(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions).with_outcomes(&outcomes),
            &formatter,
            parse_result.uri(),
            crate::freshness::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
            PublishTime::now(),
        );

        assert_eq!(diagnostics.len(), 1);
        assert!(!diagnostics[0].message().contains("Unknown package"));
        assert!(
            diagnostics[0]
                .message()
                .contains("package status could not be determined")
        );
    }

    #[test]
    fn test_generate_diagnostics_from_cache_fetch_failed_not_attempted_shows_generic_message() {
        use crate::position::{Position, Range};
        use std::collections::HashMap;

        // #478 fix (impl-critic S1): `NotAttempted` (deliberately never queried, e.g.
        // source-collided) must render the SAME generic message as `Transient`, never "Unknown package".
        let formatter = MockFormatter;

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "collided-pkg".into(),
                version_req: "1.0.0".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 12)),
            }],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let cached_versions = HashMap::new();
        let resolved_versions = HashMap::new();
        let outcomes = DependencyOutcomes::new()
            .with_fetch_failure("collided-pkg", FetchFailure::NotAttempted);

        let diagnostics = generate_diagnostics_from_cache(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions).with_outcomes(&outcomes),
            &formatter,
            parse_result.uri(),
            crate::freshness::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
            PublishTime::now(),
        );

        assert_eq!(diagnostics.len(), 1);
        assert!(!diagnostics[0].message().contains("Unknown package"));
        assert!(
            diagnostics[0]
                .message()
                .contains("package status could not be determined")
        );
    }

    #[test]
    fn test_generate_diagnostics_from_cache_fetch_failed_does_not_mask_invalid_name() {
        use crate::position::{Position, Range};
        use std::collections::HashMap;

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
        let outcomes =
            DependencyOutcomes::new().with_fetch_failure("bad name", FetchFailure::Transient);

        let diagnostics = generate_diagnostics_from_cache(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions).with_outcomes(&outcomes),
            &formatter,
            parse_result.uri(),
            crate::freshness::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
            PublishTime::now(),
        );

        assert_eq!(diagnostics.len(), 1);
        assert!(diagnostics[0].message().contains("Invalid package name"));
    }

    #[test]
    fn test_generate_diagnostics_from_cache_invalid_package_name() {
        use crate::position::{Position, Range};
        use std::collections::HashMap;

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
            parse_result.uri(),
            crate::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
            PublishTime::now(),
        );

        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].severity, Some(Severity::Warning));
        assert!(diagnostics[0].message().starts_with("Invalid package name"));
        assert!(!diagnostics[0].message().contains("Unknown package"));
    }

    #[test]
    fn test_generate_diagnostics_from_cache_outdated_version() {
        use crate::position::{Position, Range};
        use std::collections::HashMap;

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
            parse_result.uri(),
            crate::freshness::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
            PublishTime::now(),
        );

        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].severity, Some(Severity::Hint));
        assert!(diagnostics[0].message().contains("Newer version available"));
        assert!(diagnostics[0].message().contains("2.0.0"));
    }

    /// Issue #227 §4.3: an outdated dependency whose `latest` was published within the
    /// configured cooldown window gets the extra context appended, severity unchanged.
    #[test]
    fn test_generate_diagnostics_from_cache_outdated_within_cooldown_appends_context() {
        use crate::position::{Position, Range};
        use std::collections::HashMap;

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
            parse_result.uri(),
            crate::freshness::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
            PublishTime::now(),
        );

        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].severity, Some(Severity::Hint));
        assert_eq!(
            diagnostics[0].message(),
            "Newer version available: 2.0.0 (published 1 hour ago — still within the release cooldown window)"
        );
        // Guards against reintroducing the "ago ago" duplication bug found while
        // writing this test — `format_relative_age` already appends "ago".
        assert!(!diagnostics[0].message().contains("ago ago"));
    }

    /// Same setup, but `latest` was published well outside the cooldown window — the
    /// message must stay exactly the pre-feature text.
    #[test]
    fn test_generate_diagnostics_from_cache_outdated_outside_cooldown_plain_message() {
        use crate::position::{Position, Range};
        use std::collections::HashMap;

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
            parse_result.uri(),
            crate::freshness::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
            PublishTime::now(),
        );

        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].message(), "Newer version available: 2.0.0");
    }

    /// `freshness.enabled: false` suppresses the cooldown differentiation even when the
    /// publish age would otherwise qualify.
    #[test]
    fn test_generate_diagnostics_from_cache_outdated_freshness_disabled_plain_message() {
        use crate::position::{Position, Range};
        use std::collections::HashMap;

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
            parse_result.uri(),
            crate::freshness::FreshnessSettings {
                enabled: false,
                ..crate::freshness::FreshnessSettings::default()
            },
            DiagnosticSeverities::default(),
            PublishTime::now(),
        );

        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].message(), "Newer version available: 2.0.0");
    }

    /// Deterministic boundary test (issue #227 M4): `now` is threaded in as a parameter
    /// rather than read internally, so `published_at`/`now`/`cooldown_secs` can be pinned
    /// to fixed absolute values with no wall-clock dependency. `age == cooldown_secs`
    /// exactly must NOT be within cooldown — the bound is exclusive (`age < cooldown`).
    #[test]
    fn test_generate_diagnostics_from_cache_outdated_cooldown_boundary_is_exclusive() {
        use crate::position::{Position, Range};
        use std::collections::HashMap;

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
            parse_result.uri(),
            crate::freshness::FreshnessSettings {
                enabled: true,
                cooldown_secs: COOLDOWN_SECS,
            },
            DiagnosticSeverities::default(),
            now,
        );

        assert_eq!(diagnostics.len(), 1);
        assert_eq!(
            diagnostics[0].message(),
            "Newer version available: 2.0.0",
            "age exactly equal to cooldown_secs must not be within cooldown"
        );
    }

    /// Same fixture, one second younger — must flip to the within-cooldown message.
    #[test]
    fn test_generate_diagnostics_from_cache_outdated_cooldown_boundary_one_second_inside() {
        use crate::position::{Position, Range};
        use std::collections::HashMap;

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
            parse_result.uri(),
            crate::freshness::FreshnessSettings {
                enabled: true,
                cooldown_secs: COOLDOWN_SECS,
            },
            DiagnosticSeverities::default(),
            now,
        );

        assert_eq!(diagnostics.len(), 1);
        assert_eq!(
            diagnostics[0].message(),
            "Newer version available: 2.0.0 (published 1 minute ago — still within the release cooldown window)",
            "age == cooldown_secs - 1 must be within cooldown"
        );
    }

    #[test]
    fn test_generate_diagnostics_from_cache_up_to_date() {
        use crate::position::{Position, Range};
        use std::collections::HashMap;

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
            parse_result.uri(),
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
        use crate::position::{Position, Range};
        use std::collections::HashMap;

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
            parse_result.uri(),
            crate::freshness::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
            PublishTime::now(),
        );

        assert_eq!(diagnostics.len(), 2);

        // Dependency-loop order (not rule order): "serde" is up to date and emits
        // nothing, so index 0 is "tokio"'s R7 outdated diagnostic and index 1 is
        // "unknown"'s R5d unknown-package diagnostic — the same order as `deps`.
        assert_eq!(diagnostics[0].message(), "Newer version available: 2.0.0");
        assert_eq!(diagnostics[0].code(), None);
        assert_eq!(diagnostics[1].message(), "Unknown package 'unknown'");
        assert_eq!(diagnostics[1].code(), None);
    }

    #[test]
    fn test_generate_diagnostics_from_cache_unresolved_emits_no_diagnostic() {
        use crate::position::{Position, Range};
        use std::collections::HashMap;

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
            parse_result.uri(),
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
        use crate::position::{Position, Range};
        use std::collections::HashMap;

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
        let outcomes =
            DependencyOutcomes::new().with_yanked("serde", ("1.0.5".into(), RemovalStatus::Yanked));

        let severities = DiagnosticSeverities {
            yanked: Severity::Error,
            ..DiagnosticSeverities::default()
        };

        let diagnostics = generate_diagnostics_from_cache(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions).with_outcomes(&outcomes),
            &formatter,
            parse_result.uri(),
            crate::freshness::FreshnessSettings::default(),
            severities,
            PublishTime::now(),
        );

        let yanked_diag = diagnostics
            .iter()
            .find(|d| d.message().starts_with(formatter.yanked_message()))
            .expect("expected a yanked diagnostic");
        assert_eq!(yanked_diag.severity, Some(Severity::Error));
        assert!(yanked_diag.message().contains("1.0.5"));
    }

    #[test]
    fn test_generate_diagnostics_from_cache_yanked_default_severity_unchanged() {
        use crate::position::{Position, Range};
        use std::collections::HashMap;

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
        let outcomes =
            DependencyOutcomes::new().with_yanked("serde", ("1.0.5".into(), RemovalStatus::Yanked));

        let diagnostics = generate_diagnostics_from_cache(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions).with_outcomes(&outcomes),
            &formatter,
            parse_result.uri(),
            crate::freshness::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
            PublishTime::now(),
        );

        let yanked_diag = diagnostics
            .iter()
            .find(|d| d.message().starts_with(formatter.yanked_message()))
            .expect("expected a yanked diagnostic");
        assert_eq!(yanked_diag.severity, Some(Severity::Warning));
    }

    #[test]
    fn test_generate_diagnostics_from_cache_no_yanked_map_emits_no_yanked_diagnostic() {
        use crate::position::{Position, Range};
        use std::collections::HashMap;

        // Regression guard for the four handlers (hover, completion, code_lens,
        // inlay_hints) that keep calling `VersionData::new` without
        // `.with_outcomes(..)` — `outcomes: None` must never produce a diagnostic.
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
            parse_result.uri(),
            crate::freshness::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
            PublishTime::now(),
        );

        assert!(
            !diagnostics
                .iter()
                .any(|d| d.message().starts_with(formatter.yanked_message())),
            "Expected no yanked diagnostic when `yanked` is None, got: {diagnostics:?}"
        );
    }

    #[test]
    fn test_generate_diagnostics_from_cache_yanked_and_outdated_both_emitted() {
        use crate::position::{Position, Range};
        use std::collections::HashMap;

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
        let outcomes =
            DependencyOutcomes::new().with_yanked("serde", ("1.0.5".into(), RemovalStatus::Yanked));

        let diagnostics = generate_diagnostics_from_cache(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions).with_outcomes(&outcomes),
            &formatter,
            parse_result.uri(),
            crate::freshness::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
            PublishTime::now(),
        );

        assert_eq!(
            diagnostics.len(),
            2,
            "expected both diagnostics: {diagnostics:?}"
        );
        // R4 (in-use-yanked, #263) has no `continue` and runs before R7 (outdated) in
        // the orchestrator, so index 0 is always the yanked finding and index 1 is
        // always the outdated finding — never the reverse.
        assert_eq!(
            diagnostics[0].message(),
            format!("{} (1.0.5)", formatter.yanked_message())
        );
        assert_eq!(diagnostics[0].code(), None);
        assert_eq!(diagnostics[1].message(), "Newer version available: 2.0.0");
        assert_eq!(diagnostics[1].code(), None);
    }

    /// T2 (D5 collision): an exact-pin dependency whose package is both package-level
    /// deprecated and whose in-use-version yanked finding carries `AdvisoryDeprecated`
    /// (npm's real shape — its yanked map is always sourced from `from_advisory`, never
    /// `from_yanked`) must produce **exactly one** diagnostic: the deprecation
    /// diagnostic suppresses the yanked one, since the two are one signal.
    #[test]
    fn test_generate_diagnostics_from_cache_deprecation_suppresses_advisory_deprecated_yanked_finding()
     {
        use crate::position::{Position, Range};
        use std::collections::HashMap;

        let formatter = MockFormatter;
        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "left-pad".into(),
                version_req: "1.3.0".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)),
            }],
            uri: crate::test_util::test_uri("/test/package.json"),
        };

        let mut cached_versions = HashMap::new();
        cached_versions.insert("left-pad".into(), PackageVersions::latest_only("1.3.0"));
        let resolved_versions = HashMap::new();
        let outcomes = DependencyOutcomes::new()
            .with_yanked(
                "left-pad",
                ("1.3.0".into(), RemovalStatus::AdvisoryDeprecated),
            )
            .with_deprecation(
                "left-pad",
                Deprecation {
                    reason: Some("use String.prototype.padStart()".to_string()),
                    replacement: None,
                },
            );

        let diagnostics = generate_diagnostics_from_cache(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions).with_outcomes(&outcomes),
            &formatter,
            parse_result.uri(),
            crate::freshness::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
            PublishTime::now(),
        );

        assert_eq!(
            diagnostics.len(),
            1,
            "the deprecation diagnostic must suppress the AdvisoryDeprecated yanked \
             finding, not double-report: {diagnostics:?}"
        );
        assert!(
            diagnostics[0]
                .message()
                .starts_with(formatter.deprecated_message())
        );
    }

    /// T6 (D5 gate): a synthetic `Yanked` finding — unreachable for any Phase-1
    /// ecosystem, but the guard for the PyPI fast-follow, the first ecosystem with both
    /// real yanks and package deprecation — must **never** be suppressed by a
    /// package-level deprecation finding on the same dependency. Both diagnostics fire.
    #[test]
    fn test_generate_diagnostics_from_cache_deprecation_never_suppresses_real_yanked_finding() {
        use crate::position::{Position, Range};
        use std::collections::HashMap;

        let formatter = MockFormatter;
        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "pkg".into(),
                version_req: "1.0.0".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)),
            }],
            uri: crate::test_util::test_uri("/test/pyproject.toml"),
        };

        let mut cached_versions = HashMap::new();
        cached_versions.insert("pkg".into(), PackageVersions::latest_only("1.0.0"));
        let resolved_versions = HashMap::new();
        let outcomes = DependencyOutcomes::new()
            .with_yanked("pkg", ("1.0.0".into(), RemovalStatus::Yanked))
            .with_deprecation(
                "pkg",
                Deprecation {
                    reason: Some("project archived".to_string()),
                    replacement: None,
                },
            );

        let diagnostics = generate_diagnostics_from_cache(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions).with_outcomes(&outcomes),
            &formatter,
            parse_result.uri(),
            crate::freshness::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
            PublishTime::now(),
        );

        assert_eq!(
            diagnostics.len(),
            2,
            "a genuine Yanked finding must never be hidden behind a package-level \
             deprecation notice: {diagnostics:?}"
        );
        // R3 (deprecation) always runs before R4 (in-use-yanked) in the orchestrator,
        // so index 0 is the deprecation finding and index 1 is the yanked finding.
        assert_eq!(
            diagnostics[0].message(),
            format!("{}: project archived", formatter.deprecated_message())
        );
        assert_eq!(diagnostics[0].code(), Some(DEPRECATED_DIAGNOSTIC_CODE));
        assert_eq!(
            diagnostics[1].message(),
            format!("{} (1.0.0)", formatter.yanked_message())
        );
        assert_eq!(diagnostics[1].code(), None);
    }

    /// T6b (D5 gate, severity independence): on an npm-shaped fixture where the two
    /// signals genuinely are one (`AdvisoryDeprecated`), suppression must be identical
    /// regardless of the configured severities — a user setting `deprecated_severity:
    /// hint` cannot thereby silence a `yanked_severity: error` finding, because severity
    /// is not an input to the suppression decision at all.
    #[test]
    fn test_generate_diagnostics_from_cache_deprecation_suppression_is_severity_independent() {
        use crate::position::{Position, Range};
        use std::collections::HashMap;

        let formatter = MockFormatter;
        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "left-pad".into(),
                version_req: "1.3.0".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)),
            }],
            uri: crate::test_util::test_uri("/test/package.json"),
        };

        let mut cached_versions = HashMap::new();
        cached_versions.insert("left-pad".into(), PackageVersions::latest_only("1.3.0"));
        let resolved_versions = HashMap::new();
        let outcomes = DependencyOutcomes::new()
            .with_yanked(
                "left-pad",
                ("1.3.0".into(), RemovalStatus::AdvisoryDeprecated),
            )
            .with_deprecation(
                "left-pad",
                Deprecation {
                    reason: Some("use String.prototype.padStart()".to_string()),
                    replacement: None,
                },
            );
        let versions =
            VersionData::new(&cached_versions, &resolved_versions).with_outcomes(&outcomes);

        let default_severities = DiagnosticSeverities::default();
        let inverted_severities = DiagnosticSeverities {
            deprecated: Severity::Hint,
            yanked: Severity::Error,
            ..DiagnosticSeverities::default()
        };

        for severities in [default_severities, inverted_severities] {
            let diagnostics = generate_diagnostics_from_cache(
                &parse_result,
                versions,
                &formatter,
                parse_result.uri(),
                crate::freshness::FreshnessSettings::default(),
                severities,
                PublishTime::now(),
            );
            assert_eq!(
                diagnostics.len(),
                1,
                "suppression must not depend on severity configuration: {diagnostics:?}"
            );
            assert!(
                diagnostics[0]
                    .message()
                    .starts_with(formatter.deprecated_message())
            );
        }
    }

    /// I4: `versions.outcomes`' deprecation channel is name-keyed, so a git/path/SDK/workspace dependency
    /// whose name coincidentally matches an unrelated registry-resolved package's
    /// deprecation finding must not surface that diagnostic — the same #248 hazard
    /// `unsatisfiable`/`unknown`/`yanked_only` already guard against.
    #[test]
    fn test_generate_diagnostics_from_cache_deprecation_skipped_for_non_registry_sources() {
        use crate::parser::DependencySource;

        let mut cached_versions = HashMap::new();
        cached_versions.insert("dep".into(), PackageVersions::latest_only("1.0.0"));
        let resolved_versions = HashMap::new();
        let outcomes = DependencyOutcomes::new().with_deprecation(
            "dep",
            Deprecation {
                reason: Some("archived".to_string()),
                replacement: None,
            },
        );
        let uri = crate::test_util::test_uri("/test/Cargo.toml");

        for source in [
            DependencySource::Path {
                path: "../local".into(),
            },
            DependencySource::Git {
                url: "https://example.com/repo.git".into(),
                rev: None,
            },
            DependencySource::Sdk {
                sdk: "flutter".into(),
            },
            DependencySource::Workspace,
        ] {
            let parse_result = SingleDepParseResult {
                dep: NonRegistryDep(dep_at("dep"), source.clone()),
                uri: uri.clone(),
            };
            let diagnostics = generate_diagnostics_from_cache(
                &parse_result,
                VersionData::new(&cached_versions, &resolved_versions).with_outcomes(&outcomes),
                &MockFormatter,
                parse_result.uri(),
                crate::freshness::FreshnessSettings::default(),
                DiagnosticSeverities::default(),
                PublishTime::now(),
            );
            assert!(
                diagnostics
                    .iter()
                    .all(|d| !d.message().starts_with(MockFormatter.deprecated_message())),
                "source {source:?} must never surface the deprecation diagnostic for a \
                 coincidentally-named registry package: {diagnostics:?}"
            );
        }

        // Control: the same fixture on a Registry-source dependency DOES produce the
        // diagnostic, proving the loop above isn't vacuously passing.
        let registry_parse_result = SingleDepParseResult {
            dep: dep_at("dep"),
            uri,
        };
        let diagnostics = generate_diagnostics_from_cache(
            &registry_parse_result,
            VersionData::new(&cached_versions, &resolved_versions).with_outcomes(&outcomes),
            &MockFormatter,
            registry_parse_result.uri(),
            crate::freshness::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
            PublishTime::now(),
        );
        assert!(
            diagnostics
                .iter()
                .any(|d| d.message().starts_with(MockFormatter.deprecated_message())),
            "control case: a Registry-source dependency must still produce the diagnostic"
        );
    }

    #[test]
    fn test_generate_diagnostics_from_cache_yanked_no_version_range_uses_name_range() {
        use crate::position::{Position, Range};
        use std::collections::HashMap;

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
        let outcomes =
            DependencyOutcomes::new().with_yanked("serde", ("1.0.5".into(), RemovalStatus::Yanked));

        let diagnostics = generate_diagnostics_from_cache(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions).with_outcomes(&outcomes),
            &formatter,
            parse_result.uri(),
            crate::freshness::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
            PublishTime::now(),
        );

        let yanked_diag = diagnostics
            .iter()
            .find(|d| d.message().starts_with(formatter.yanked_message()))
            .expect("expected a yanked diagnostic even without a version_range");
        assert_eq!(yanked_diag.range, name_range);
    }

    #[test]
    fn test_generate_diagnostics_from_cache_yanked_normalized_name_keying() {
        use crate::position::{Position, Range};
        use std::collections::HashMap;

        /// Mirrors a Composer/NuGet/Swift-shaped formatter whose normalized
        /// name differs from the manifest-declared raw name.
        struct MockLowercaseFormatter;
        impl PackageNaming for MockLowercaseFormatter {
            fn normalize_package_name(&self, name: &PackageName) -> String {
                name.as_str().to_lowercase()
            }
        }

        impl PackageRendering for MockLowercaseFormatter {
            fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
                version.to_string()
            }

            fn package_url(&self, name: &PackageName) -> String {
                format!("https://example.com/{}", name.as_str())
            }
        }

        impl RequirementResolution for MockLowercaseFormatter {}

        impl DiagnosticMessages for MockLowercaseFormatter {}

        impl DiagnosticPolicy for MockLowercaseFormatter {}

        impl SourcePolicy for MockLowercaseFormatter {}

        impl OsvNaming for MockLowercaseFormatter {}

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
        // Keyed by the *normalized* (lowercase) name, not the raw manifest name.
        let outcomes = DependencyOutcomes::new()
            .with_yanked("newtonsoft.json", ("13.0.1".into(), RemovalStatus::Yanked));

        let diagnostics = generate_diagnostics_from_cache(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions).with_outcomes(&outcomes),
            &formatter,
            parse_result.uri(),
            crate::freshness::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
            PublishTime::now(),
        );

        assert!(
            diagnostics
                .iter()
                .any(|d| d.message().starts_with(formatter.yanked_message())),
            "expected normalized-name lookup to resolve the yanked entry, got: {diagnostics:?}"
        );
    }

    #[test]
    fn test_generate_diagnostics_from_cache_yanked_not_shared_across_duplicate_name_occurrences() {
        // #394 S1: two occurrences of `time` pinned to different versions, only one actually
        // yanked. `yanked` is name-keyed and records only "0.1.43" — the occurrence pinned
        // to "0.1.44" must not also render "yanked (0.1.43)" just because it shares the name.
        use crate::position::{Position, Range};
        use std::collections::HashMap;

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
        let outcomes =
            DependencyOutcomes::new().with_yanked("time", ("0.1.43".into(), RemovalStatus::Yanked));

        let diagnostics = generate_diagnostics_from_cache(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions)
                .with_outcomes(&outcomes)
                .with_ecosystem(crate::EcosystemId::Cargo),
            &formatter,
            parse_result.uri(),
            crate::freshness::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
            PublishTime::now(),
        );

        let yanked_diags: Vec<_> = diagnostics
            .iter()
            .filter(|d| d.message().starts_with(formatter.yanked_message()))
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
        assert!(yanked_diags[0].message().contains("0.1.43"));
    }

    #[test]
    fn test_generate_diagnostics_from_cache_yanked_no_ecosystem_keeps_pre_394_behavior() {
        // Without `with_ecosystem` (predates #394), the consistency check is skipped and both
        // occurrences render the shared name-keyed finding — the pre-#394 behavior, preserved
        // deliberately.
        use crate::position::{Position, Range};
        use std::collections::HashMap;

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
        let outcomes =
            DependencyOutcomes::new().with_yanked("time", ("0.1.43".into(), RemovalStatus::Yanked));

        let diagnostics = generate_diagnostics_from_cache(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions).with_outcomes(&outcomes),
            &formatter,
            parse_result.uri(),
            crate::freshness::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
            PublishTime::now(),
        );

        let yanked_diags = diagnostics
            .iter()
            .filter(|d| d.message().starts_with(formatter.yanked_message()))
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
            parse_result.uri(),
            crate::freshness::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
            PublishTime::now(),
        );

        let message = diagnostics
            .iter()
            .find(|d| d.message().contains("No published version satisfies"))
            .map(|d| d.message())
            .expect("unsatisfiable WARNING must fire");
        assert!(
            message.contains("2.0.0-rc.1") && message.contains("pre-release"),
            "message must mention the matching pre-release, got: {message}"
        );
    }

    /// #1263 critic S1: the pre-release enrichment appended to the unsatisfiable message
    /// interpolates `candidate.to_string()` from `package_versions.available` — the same
    /// registry-supplied, untrusted source as `latest`/`req_str` — and was left unsanitized.
    /// A bidi override embedded in the matching pre-release candidate must not survive into
    /// the message either.
    #[test]
    fn test_generate_diagnostics_unsatisfiable_sanitizes_bidi_in_matching_prerelease() {
        let cached_versions = {
            let mut m = HashMap::new();
            m.insert(
                "dep".into(),
                PackageVersions {
                    latest: "1.5.0".into(),
                    available: Arc::from(vec![
                        "2.0.0-rc.1\u{202E}evil".into(),
                        "1.5.0".into(),
                        "1.4.0".into(),
                    ]),
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
            parse_result.uri(),
            crate::freshness::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
            PublishTime::now(),
        );

        let message = diagnostics
            .iter()
            .find(|d| d.message().contains("No published version satisfies"))
            .map(|d| d.message())
            .expect("unsatisfiable WARNING must fire");
        assert!(
            message.contains("pre-release"),
            "message must still mention the matching pre-release, got: {message}"
        );
        assert!(!message.contains('\u{202E}'));
        assert!(message.contains("2.0.0-rc.1"));
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
            parse_result.uri(),
            crate::freshness::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
            PublishTime::now(),
        );

        let message = diagnostics
            .iter()
            .find(|d| d.message().contains("No published version satisfies"))
            .map(|d| d.message())
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
                parse_result.uri(),
                crate::freshness::FreshnessSettings::default(),
                DiagnosticSeverities::default(),
                PublishTime::now(),
            );
            assert!(
                diagnostics
                    .iter()
                    .all(|d| !d.message().contains("No published version satisfies")),
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
            registry_parse_result.uri(),
            crate::freshness::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
            PublishTime::now(),
        );
        assert!(
            diagnostics
                .iter()
                .any(|d| d.message().contains("No published version satisfies")),
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
            parse_result.uri(),
            crate::freshness::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
            PublishTime::now(),
        );
        assert!(
            diagnostics
                .iter()
                .all(|d| !d.message().contains("Unknown package")),
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
            registry_parse_result.uri(),
            crate::freshness::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
            PublishTime::now(),
        );
        assert!(
            diagnostics
                .iter()
                .any(|d| d.message().contains("Unknown package")),
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
            parse_result.uri(),
            crate::freshness::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
            PublishTime::now(),
        );
        assert_eq!(diagnostics.len(), 1);
        assert!(diagnostics[0].message().starts_with("Invalid package name"));
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
            parse_result.uri(),
            crate::freshness::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
            PublishTime::now(),
        );
        assert!(
            diagnostics
                .iter()
                .all(|d| !d.message().contains("Newer version available")),
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
            registry_parse_result.uri(),
            crate::freshness::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
            PublishTime::now(),
        );
        assert!(
            diagnostics
                .iter()
                .any(|d| d.message().contains("Newer version available")),
            "control case: a Registry-source dependency must still produce the WARNING"
        );
    }

    #[test]
    fn test_generate_diagnostics_vulnerable_dependency_emits_advisory_diagnostic_even_without_registry_data()
     {
        use crate::osv::{
            Capped, DependencyVulnerabilities, ScanOutcome, UpgradeStatus, VulnSeverity,
            VulnerabilityMap,
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
                advisories: Capped::new(
                    vec![sample_advisory("RUSTSEC-2020-0071", VulnSeverity::High)],
                    1,
                ),
                fix_target_status: UpgradeStatus::NotChecked,
                upgrade_status: UpgradeStatus::NotChecked,
            }),
        );

        let diagnostics = generate_diagnostics_from_cache(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions).with_vulnerabilities(&vulns),
            &formatter,
            parse_result.uri(),
            crate::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
            PublishTime::now(),
        );

        let vuln_diag = diagnostics
            .iter()
            .find(|d| d.message().contains("RUSTSEC-2020-0071"))
            .expect("vulnerability diagnostic must be emitted even without registry data");
        assert_eq!(vuln_diag.severity, Some(Severity::Warning));
        assert_eq!(vuln_diag.code(), Some("RUSTSEC-2020-0071"));
    }

    #[test]
    fn test_generate_diagnostics_malicious_advisory_is_distinguishable_from_unknown() {
        // SC-002: a MAL-* advisory and an ordinary Unknown-severity advisory on
        // the same dependency must be distinguishable without opening hover.
        use crate::osv::{
            Capped, DependencyVulnerabilities, ScanOutcome, UpgradeStatus, VulnSeverity,
            VulnerabilityMap,
        };

        let formatter = MockFormatter;
        let parse_result = MockParseResult {
            deps: vec![dep_at("vulnerable-pkg")],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };
        let cached_versions = HashMap::new();
        let resolved_versions = HashMap::new();

        let mut vulns: VulnerabilityMap = VulnerabilityMap::new();
        vulns.insert(
            "vulnerable-pkg".to_string(),
            ScanOutcome::Vulnerable(DependencyVulnerabilities {
                advisories: Capped::new(
                    vec![
                        sample_advisory("MAL-2025-47141", VulnSeverity::Malicious),
                        sample_advisory("RUSTSEC-2020-0071", VulnSeverity::Unknown),
                    ],
                    2,
                ),
                fix_target_status: UpgradeStatus::NotChecked,
                upgrade_status: UpgradeStatus::NotChecked,
            }),
        );

        let diagnostics = generate_diagnostics_from_cache(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions).with_vulnerabilities(&vulns),
            &formatter,
            parse_result.uri(),
            crate::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
            PublishTime::now(),
        );

        let malicious_diag = diagnostics
            .iter()
            .find(|d| d.message().contains("MAL-2025-47141"))
            .expect("malicious advisory diagnostic must be emitted");
        let unknown_diag = diagnostics
            .iter()
            .find(|d| d.message().contains("RUSTSEC-2020-0071"))
            .expect("unknown-severity advisory diagnostic must be emitted");

        assert_ne!(malicious_diag.message(), unknown_diag.message());
        assert_ne!(malicious_diag.code(), unknown_diag.code());
        assert!(malicious_diag.message().contains("[MALWARE]"));
        assert!(!unknown_diag.message().contains("[MALWARE]"));
    }

    /// #1262: an OSV advisory `summary` is untrusted, unbounded-length prose (OSV.dev
    /// aggregates GHSA/RustSec/PyPA plus community submissions, and `summary` passes through
    /// `OsvVulnRecord::into_advisory` unvalidated) and must be both sanitized
    /// (bidi/invisible-character override stripped) and capped at
    /// `MAX_DIAGNOSTIC_PROSE_CHARS` before it reaches the client-visible vulnerability
    /// diagnostic message.
    ///
    /// `id` uses a benign, `is_valid_osv_id`-shaped value here rather than a bidi payload
    /// (critic M1): on the real (non-test) construction path, `OsvVulnRecord::into_advisory`
    /// already rejects any record whose id fails that validation before an `Advisory` can
    /// exist at all, so a malformed `id` reaching this function is not a reachable state —
    /// `sanitize_advisory_text_for_diagnostic`'s own doctest covers the id-sanitization
    /// behavior itself as defense-in-depth, independent of reachability.
    #[test]
    fn test_generate_diagnostics_vulnerability_sanitizes_and_caps_advisory_summary() {
        use crate::osv::{
            Capped, DependencyVulnerabilities, ScanOutcome, UpgradeStatus, VulnSeverity,
            VulnerabilityMap,
        };

        let formatter = MockFormatter;
        let parse_result = MockParseResult {
            deps: vec![dep_at("vulnerable-pkg")],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };
        let cached_versions = HashMap::new();
        let resolved_versions = HashMap::new();

        let overlong_summary = "X".repeat(MAX_DIAGNOSTIC_PROSE_CHARS + 50);
        let advisory = crate::osv::Advisory::new(
            "RUSTSEC-2020-0071".to_string(),
            "2023-01-01T00:00:00Z".to_string(),
            VulnSeverity::High,
        )
        .expect("valid osv id")
        .with_summary(format!("bidi\u{202E}{overlong_summary}"));

        let mut vulns: VulnerabilityMap = VulnerabilityMap::new();
        vulns.insert(
            "vulnerable-pkg".to_string(),
            ScanOutcome::Vulnerable(DependencyVulnerabilities {
                advisories: Capped::new(vec![std::sync::Arc::new(advisory)], 1),
                fix_target_status: UpgradeStatus::NotChecked,
                upgrade_status: UpgradeStatus::NotChecked,
            }),
        );

        let diagnostics = generate_diagnostics_from_cache(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions).with_vulnerabilities(&vulns),
            &formatter,
            parse_result.uri(),
            crate::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
            PublishTime::now(),
        );

        let vuln_diag = diagnostics
            .iter()
            .find(|d| d.message().contains("RUSTSEC"))
            .expect("vulnerability diagnostic must be emitted");
        assert!(!vuln_diag.message().contains('\u{202E}'));
        assert!(vuln_diag.message().contains('…'));
        assert!(
            !vuln_diag.message().contains(&overlong_summary),
            "expected the summary to be truncated rather than interpolated verbatim, got: {:?}",
            vuln_diag.message()
        );
        // `Diagnostic.code` stays the raw advisory id (see `push_vulnerability_diagnostics`'s
        // docs) so code-action binding by exact id match keeps working.
        assert_eq!(vuln_diag.code(), Some("RUSTSEC-2020-0071"));
    }

    #[test]
    fn test_generate_diagnostics_informational_advisory_is_distinguishable_from_unknown() {
        // US-002/SC-002 (#1007): an Informational advisory (e.g. "unmaintained") and an
        // ordinary Unknown-severity one must be distinguishable without opening hover.
        use crate::osv::{
            Capped, DependencyVulnerabilities, ScanOutcome, UpgradeStatus, VulnSeverity,
            VulnerabilityMap,
        };

        let formatter = MockFormatter;
        let parse_result = MockParseResult {
            deps: vec![dep_at("vulnerable-pkg")],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };
        let cached_versions = HashMap::new();
        let resolved_versions = HashMap::new();

        let mut vulns: VulnerabilityMap = VulnerabilityMap::new();
        vulns.insert(
            "vulnerable-pkg".to_string(),
            ScanOutcome::Vulnerable(DependencyVulnerabilities {
                advisories: Capped::new(
                    vec![
                        sample_advisory("RUSTSEC-2024-0320", VulnSeverity::Informational),
                        sample_advisory("RUSTSEC-2020-0071", VulnSeverity::Unknown),
                    ],
                    2,
                ),
                fix_target_status: UpgradeStatus::NotChecked,
                upgrade_status: UpgradeStatus::NotChecked,
            }),
        );

        let diagnostics = generate_diagnostics_from_cache(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions).with_vulnerabilities(&vulns),
            &formatter,
            parse_result.uri(),
            crate::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
            PublishTime::now(),
        );

        let informational_diag = diagnostics
            .iter()
            .find(|d| d.message().contains("RUSTSEC-2024-0320"))
            .expect("informational advisory diagnostic must be emitted");
        let unknown_diag = diagnostics
            .iter()
            .find(|d| d.message().contains("RUSTSEC-2020-0071"))
            .expect("unknown-severity advisory diagnostic must be emitted");

        assert_ne!(informational_diag.message(), unknown_diag.message());
        assert_ne!(informational_diag.severity, unknown_diag.severity);
        assert_eq!(informational_diag.severity, Some(Severity::Information));
        assert_eq!(unknown_diag.severity, Some(Severity::Warning));
        assert!(informational_diag.message().contains("[INFORMATIONAL]"));
        assert!(!unknown_diag.message().contains("[INFORMATIONAL]"));
    }

    #[test]
    fn test_generate_diagnostics_malicious_message_does_not_repeat_the_word_malicious() {
        // M3 (impl-critic): OSV's own summary for MAL-* records routinely
        // already starts with "Malicious code in ..." — the message must not
        // also prefix "Malicious package", which read redundantly.
        use crate::osv::{
            Advisory, Capped, DependencyVulnerabilities, ScanOutcome, UpgradeStatus, VulnSeverity,
            VulnerabilityMap,
        };
        use std::sync::Arc;

        let formatter = MockFormatter;
        let parse_result = MockParseResult {
            deps: vec![dep_at("bad-pkg")],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };
        let cached_versions = HashMap::new();
        let resolved_versions = HashMap::new();

        let advisory = Arc::new(
            Advisory::new(
                "MAL-2025-47141".to_string(),
                "2025-09-17T06:23:36Z".to_string(),
                VulnSeverity::Malicious,
            )
            .expect("valid osv id")
            .with_summary("Malicious code in @ctrl/tinycolor (npm)".to_string())
            .with_aliases(vec!["GHSA-qjqf-7j6f-82c4".to_string()]),
        );

        let mut vulns: VulnerabilityMap = VulnerabilityMap::new();
        vulns.insert(
            "bad-pkg".to_string(),
            ScanOutcome::Vulnerable(DependencyVulnerabilities {
                advisories: Capped::new(vec![advisory], 1),
                fix_target_status: UpgradeStatus::NotChecked,
                upgrade_status: UpgradeStatus::NotChecked,
            }),
        );

        let diagnostics = generate_diagnostics_from_cache(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions).with_vulnerabilities(&vulns),
            &formatter,
            parse_result.uri(),
            crate::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
            PublishTime::now(),
        );

        let diag = diagnostics
            .iter()
            .find(|d| d.message().contains("MAL-2025-47141"))
            .expect("malicious advisory diagnostic must be emitted");
        assert!(
            diag.message().contains("[MALWARE]"),
            "message must carry the distinguishing [MALWARE] tag, got: {}",
            diag.message()
        );
        assert!(
            !diag.message().contains("Malicious package"),
            "message must not also prefix the redundant 'Malicious package' wording \
             on top of OSV's own \"Malicious ...\" summary text, got: {}",
            diag.message()
        );
    }

    #[test]
    fn test_generate_diagnostics_advisory_cap_emits_more_count_from_total_known() {
        use crate::osv::{
            ADVISORY_DISPLAY_CAP, Capped, DependencyVulnerabilities, ScanOutcome, UpgradeStatus,
            VulnSeverity, VulnerabilityMap,
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
                advisories: Capped::new(advisories, 40),
                fix_target_status: UpgradeStatus::NotChecked,
                upgrade_status: UpgradeStatus::NotChecked,
            }),
        );

        let diagnostics = generate_diagnostics_from_cache(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions).with_vulnerabilities(&vulns),
            &formatter,
            parse_result.uri(),
            crate::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
            PublishTime::now(),
        );

        let more_diag = diagnostics
            .iter()
            .find(|d| d.message().contains("more advisories"))
            .expect("expected a trailing +N more advisories diagnostic");
        assert!(
            more_diag.message().contains("+35"),
            "got: {}",
            more_diag.message()
        );
    }

    #[test]
    fn test_generate_diagnostics_vulnerability_not_shared_across_duplicate_name_occurrences() {
        // #394 S2: two occurrences of `pkg` pinned to different versions — one vulnerable, one
        // patched. Built via `vulnerability_keys` (as `deps-lsp`'s `build_scan_targets` would)
        // so each occurrence's OSV result lands under its own key.
        use crate::osv::{
            Capped, DependencyVulnerabilities, ScanOutcome, UpgradeStatus, VulnSeverity,
            VulnerabilityMap, vulnerability_keys,
        };
        use crate::position::{Position, Range};

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
            None,
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
                advisories: Capped::new(
                    vec![sample_advisory("RUSTSEC-2020-0071", VulnSeverity::High)],
                    1,
                ),
                fix_target_status: UpgradeStatus::NotChecked,
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
            parse_result.uri(),
            crate::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
            PublishTime::now(),
        );

        let advisory_diags: Vec<_> = diagnostics
            .iter()
            .filter(|d| d.message().contains("RUSTSEC-2020-0071"))
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

    /// Issue #649 US-002/SC-002, end-to-end through `generate_diagnostics_from_cache` with a
    /// real `resolved_version_candidates` map — the largest gap flagged by the pre-review
    /// test-coverage audit: every prior duplicate-name test disambiguated via a concrete
    /// manifest pin (`=1.0.0`/`=2.0.0`) with `resolved_versions` empty, never exercising the
    /// lockfile-candidates path at all. This mirrors the actual serde/serde_old rename
    /// scenario: two occurrences share the resolved name `serde`, one plain (`"1.0"`,
    /// resolving via the candidates map to `1.0.219`) and one renamed to an older major
    /// (`"0.9"`, resolving to `0.9.15`) — an advisory affecting only `1.0.219` must anchor
    /// solely on the plain occurrence.
    #[test]
    fn test_generate_diagnostics_vulnerability_attributed_via_resolved_version_candidates() {
        use crate::osv::{
            Capped, DependencyVulnerabilities, ScanOutcome, UpgradeStatus, VulnSeverity,
            VulnerabilityMap, vulnerability_keys,
        };
        use crate::position::{Position, Range};

        let formatter = MockFormatter;

        let current_major = MockDep {
            name: "serde".into(),
            version_req: "1.0".into(),
            version_range: Range::new(Position::new(0, 8), Position::new(0, 13)),
            name_range: Range::new(Position::new(0, 0), Position::new(0, 5)),
        };
        let renamed_old_major = MockDep {
            name: "serde".into(),
            version_req: "0.9".into(),
            version_range: Range::new(Position::new(1, 8), Position::new(1, 13)),
            name_range: Range::new(Position::new(1, 0), Position::new(1, 9)),
        };
        let parse_result = MockParseResult {
            deps: vec![current_major, renamed_old_major],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let cached_versions = HashMap::new();
        let mut resolved_versions = HashMap::new();
        resolved_versions.insert("serde".into(), ConcreteVersion::from("1.0.219"));
        let mut resolved_version_candidates = HashMap::new();
        resolved_version_candidates.insert(
            "serde".into(),
            vec![
                ConcreteVersion::from("0.9.15"),
                ConcreteVersion::from("1.0.219"),
            ],
        );

        let keys = vulnerability_keys(
            &parse_result,
            &resolved_versions,
            Some(&resolved_version_candidates),
            &formatter,
            crate::EcosystemId::Cargo,
        );
        let deps = parse_result.dependencies();
        let current_key = keys.get(&deps[0].name_range()).unwrap().clone();
        let renamed_key = keys.get(&deps[1].name_range()).unwrap().clone();
        assert_ne!(
            current_key, renamed_key,
            "occurrences resolving to different lockfile candidates must get distinct keys"
        );

        let mut vulns: VulnerabilityMap = VulnerabilityMap::new();
        vulns.insert(
            current_key,
            ScanOutcome::Vulnerable(DependencyVulnerabilities {
                advisories: Capped::new(
                    vec![sample_advisory("RUSTSEC-2020-0071", VulnSeverity::High)],
                    1,
                ),
                fix_target_status: UpgradeStatus::NotChecked,
                upgrade_status: UpgradeStatus::NotChecked,
            }),
        );
        vulns.insert(renamed_key, ScanOutcome::Clean);

        let diagnostics = generate_diagnostics_from_cache(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions)
                .with_resolved_version_candidates(&resolved_version_candidates)
                .with_vulnerabilities(&vulns)
                .with_ecosystem(crate::EcosystemId::Cargo),
            &formatter,
            parse_result.uri(),
            crate::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
            PublishTime::now(),
        );

        let advisory_diags: Vec<_> = diagnostics
            .iter()
            .filter(|d| d.message().contains("RUSTSEC-2020-0071"))
            .collect();
        assert_eq!(
            advisory_diags.len(),
            1,
            "exactly one occurrence must get the advisory diagnostic, got: {diagnostics:?}"
        );
        assert_eq!(
            advisory_diags[0].range.start.line, 0,
            "the advisory affecting 1.0.219 must land on the plain (1.0) occurrence's line, \
             not the renamed (0.9) occurrence sharing the same resolved name"
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
            parse_result.uri(),
            crate::FreshnessSettings::default(),
            DiagnosticSeverities::default(),
            PublishTime::now(),
        );

        assert!(
            diagnostics.iter().all(|d| d.code().is_none()),
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

        impl PackageNaming for TableFormatter {}

        impl PackageRendering for TableFormatter {
            fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
                version.to_string()
            }

            fn package_url(&self, name: &PackageName) -> String {
                name.as_str().to_string()
            }
        }

        impl RequirementResolution for TableFormatter {
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

        impl DiagnosticMessages for TableFormatter {}

        impl DiagnosticPolicy for TableFormatter {}

        impl SourcePolicy for TableFormatter {}

        impl OsvNaming for TableFormatter {}

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
        impl PackageNaming for NonStrictFormatter {}

        impl PackageRendering for NonStrictFormatter {
            fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
                version.to_string()
            }

            fn package_url(&self, name: &PackageName) -> String {
                name.as_str().to_string()
            }
        }

        impl RequirementResolution for NonStrictFormatter {
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

        impl DiagnosticMessages for NonStrictFormatter {}

        impl DiagnosticPolicy for NonStrictFormatter {}

        impl SourcePolicy for NonStrictFormatter {}

        impl OsvNaming for NonStrictFormatter {}

        fn versions(strs: &[&str]) -> Vec<ConcreteVersion> {
            strs.iter().map(|s| (*s).into()).collect()
        }

        fn yanked_versions(strs: &[&str]) -> Vec<(ConcreteVersion, RemovalStatus)> {
            strs.iter()
                .map(|s| ((*s).into(), RemovalStatus::Yanked))
                .collect()
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
                    &yanked_versions(&["2.0.0-rc.1"]),
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
                    &yanked_versions(&["2.0.0-rc.2"]),
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

        impl PackageNaming for TableFormatter {}

        impl PackageRendering for TableFormatter {
            fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
                version.to_string()
            }

            fn package_url(&self, name: &PackageName) -> String {
                name.as_str().to_string()
            }
        }

        impl RequirementResolution for TableFormatter {
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

        impl DiagnosticMessages for TableFormatter {}

        impl DiagnosticPolicy for TableFormatter {}

        impl SourcePolicy for TableFormatter {}

        impl OsvNaming for TableFormatter {}

        fn versions(strs: &[&str]) -> Vec<ConcreteVersion> {
            strs.iter().map(|s| (*s).into()).collect()
        }

        fn yanked_versions(strs: &[&str]) -> Vec<(ConcreteVersion, RemovalStatus)> {
            strs.iter()
                .map(|s| ((*s).into(), RemovalStatus::Yanked))
                .collect()
        }

        #[test]
        fn test_yanked_only_match_is_true() {
            let formatter = TableFormatter::new(|v| Some(v == "1.2.1"));
            assert_eq!(
                requirement_matches_only_yanked(
                    &formatter,
                    &VersionReq::new("modelled"),
                    &versions(&["1.2.1"]),
                    &yanked_versions(&["1.2.1"]),
                ),
                Some(RemovalStatus::Yanked)
            );
        }

        /// #437 M2 regression: a registry response can carry duplicate entries sharing the
        /// same version string (see `lifecycle.rs`'s in-use-version scan, which guards
        /// against exactly this). If such a pair has mixed statuses, the aggregate must
        /// prefer `Yanked`, not just take whichever entry happens to come first.
        #[test]
        fn test_duplicate_version_prefers_yanked_status_regardless_of_order() {
            let formatter = TableFormatter::new(|v| Some(v == "1.2.1"));

            let advisory_then_yanked = vec![
                ("1.2.1".into(), RemovalStatus::AdvisoryDeprecated),
                ("1.2.1".into(), RemovalStatus::Yanked),
            ];
            assert_eq!(
                requirement_matches_only_yanked(
                    &formatter,
                    &VersionReq::new("modelled"),
                    &versions(&["1.2.1"]),
                    &advisory_then_yanked,
                ),
                Some(RemovalStatus::Yanked),
                "Yanked must win when it comes after AdvisoryDeprecated in the duplicate list"
            );

            let yanked_then_advisory = vec![
                ("1.2.1".into(), RemovalStatus::Yanked),
                ("1.2.1".into(), RemovalStatus::AdvisoryDeprecated),
            ];
            assert_eq!(
                requirement_matches_only_yanked(
                    &formatter,
                    &VersionReq::new("modelled"),
                    &versions(&["1.2.1"]),
                    &yanked_then_advisory,
                ),
                Some(RemovalStatus::Yanked),
                "Yanked must win when it comes before AdvisoryDeprecated in the duplicate list"
            );
        }

        #[test]
        fn test_no_match_is_false() {
            let formatter = TableFormatter::new(|_v| Some(false));
            assert!(
                requirement_matches_only_yanked(
                    &formatter,
                    &VersionReq::new("modelled"),
                    &versions(&["1.2.1"]),
                    &yanked_versions(&["1.2.1"]),
                )
                .is_none()
            );
        }

        #[test]
        fn test_match_on_non_yanked_alongside_yanked_is_false() {
            // "^1.0" matches both a yanked 1.0.0 and a non-yanked 1.0.1 — a non-yanked
            // alternative exists, so this must not be reported as "yanked-only".
            let formatter = TableFormatter::new(|v| Some(v == "1.0.0" || v == "1.0.1"));
            assert!(
                requirement_matches_only_yanked(
                    &formatter,
                    &VersionReq::new("modelled"),
                    &versions(&["1.0.1", "1.0.0"]),
                    &yanked_versions(&["1.0.0"]),
                )
                .is_none()
            );
        }

        #[test]
        fn test_scan_continues_past_a_yanked_match_to_find_a_non_yanked_alternative() {
            // Same as above but with the yanked candidate ordered first, so a scan that
            // stopped at the first `Some(true)` (as `requirement_is_unsatisfiable` does) would
            // wrongly report "yanked-only" here.
            let formatter = TableFormatter::new(|v| Some(v == "1.0.0" || v == "1.0.1"));
            assert!(
                requirement_matches_only_yanked(
                    &formatter,
                    &VersionReq::new("modelled"),
                    &versions(&["1.0.0", "1.0.1"]),
                    &yanked_versions(&["1.0.0"]),
                )
                .is_none()
            );
        }

        #[test]
        fn test_empty_yanked_list_is_false_without_compiling() {
            let formatter =
                TableFormatter::new(|_v| panic!("must not compile/scan when yanked is empty"));
            assert!(
                requirement_matches_only_yanked(
                    &formatter,
                    &VersionReq::new("modelled"),
                    &versions(&["1.0.0"]),
                    &[],
                )
                .is_none()
            );
        }

        #[test]
        fn test_empty_available_list_is_false() {
            let formatter = TableFormatter::new(|_v| Some(true));
            assert!(
                requirement_matches_only_yanked(
                    &formatter,
                    &VersionReq::new("modelled"),
                    &[],
                    &yanked_versions(&["1.0.0"]),
                )
                .is_none()
            );
        }

        #[test]
        fn test_unresolved_requirement_is_false() {
            let formatter = TableFormatter::new(|_v| Some(true));
            assert!(
                requirement_matches_only_yanked(
                    &formatter,
                    &VersionReq::new("unresolved"),
                    &versions(&["1.0.0"]),
                    &yanked_versions(&["1.0.0"]),
                )
                .is_none()
            );
        }

        #[test]
        fn test_compile_requirement_none_is_false() {
            let formatter = TableFormatter::new(|_v| Some(true));
            assert!(
                requirement_matches_only_yanked(
                    &formatter,
                    &VersionReq::new("not-modelled"),
                    &versions(&["1.0.0"]),
                    &yanked_versions(&["1.0.0"]),
                )
                .is_none()
            );
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
                    yanked: Arc::from(vec![("1.2.1".into(), RemovalStatus::Yanked)]),
                    published_at: None,
                },
            );
            let resolved_versions = HashMap::new();

            let diagnostics = generate_diagnostics_from_cache(
                &parse_result,
                VersionData::new(&cached_versions, &resolved_versions),
                &formatter,
                parse_result.uri(),
                crate::freshness::FreshnessSettings::default(),
                DiagnosticSeverities::default(),
                PublishTime::now(),
            );

            assert_eq!(diagnostics.len(), 1, "expected exactly one diagnostic");
            assert_eq!(diagnostics[0].severity, Some(Severity::Warning));
            assert_eq!(
                diagnostics[0].message(),
                format!("{}; latest is 2.0.0", formatter.yanked_message())
            );
        }

        /// #437 (formerly I1, D5 gate regression): a package-level deprecation finding must
        /// NOT suppress the #247 `requirement_matches_only_yanked` check when there is no
        /// corresponding #263 (`versions.outcomes` yanked) entry to justify it AND the #247 match's own
        /// status is `Yanked` — a genuine hard yank must never be hidden behind a deprecation
        /// notice, exactly like D5 guards for #263. #247 now reads its own `RemovalStatus` per
        /// entry from `package_versions.yanked` (see `PackageVersions::yanked`), so "no #263
        /// finding for this name" is no longer a reason to fire unconditionally — it's simply
        /// evidence that #247 must decide for itself, from its own matched entry's status
        /// (the PyPI range-satisfiable-only-by-a-real-yank-with-no-exact-pin case).
        #[test]
        fn test_generate_diagnostics_from_cache_deprecation_never_suppresses_yanked_only_match_without_263_entry()
         {
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
                    yanked: Arc::from(vec![("1.2.1".into(), RemovalStatus::Yanked)]),
                    published_at: None,
                },
            );
            let resolved_versions = HashMap::new();
            // Deliberately no yanked entry: no #263 (in-use-version) finding for "serde" —
            // the bug this test guards against is suppression that vacuously fires on this
            // case.
            let outcomes = DependencyOutcomes::new().with_deprecation(
                "serde",
                Deprecation {
                    reason: Some("archived".to_string()),
                    replacement: None,
                },
            );

            let diagnostics = generate_diagnostics_from_cache(
                &parse_result,
                VersionData::new(&cached_versions, &resolved_versions).with_outcomes(&outcomes),
                &formatter,
                parse_result.uri(),
                crate::freshness::FreshnessSettings::default(),
                DiagnosticSeverities::default(),
                PublishTime::now(),
            );

            assert_eq!(
                diagnostics.len(),
                2,
                "expected exactly the deprecation diagnostic plus the #247 yanked-only \
                 match, got: {diagnostics:?}"
            );
            // R3 always runs before R6b (#247), so index 0 is deprecation and index 1 is the
            // #247 match — R6b fires regardless of `deprecation_found`, unlike R4's D5 gate.
            assert_eq!(
                diagnostics[0].message(),
                format!("{}: archived", formatter.deprecated_message()),
                "a genuine Yanked #247 match must still fire, without a #263 entry: {diagnostics:?}"
            );
            assert_eq!(diagnostics[0].code(), Some(DEPRECATED_DIAGNOSTIC_CODE));
            assert_eq!(
                diagnostics[1].message(),
                format!("{}; latest is 2.0.0", formatter.yanked_message())
            );
            assert_eq!(diagnostics[1].code(), None);
        }

        /// #437 companion: unlike the `Yanked` case above, a #247 match whose own status is
        /// `AdvisoryDeprecated` DOES yield to a co-occurring package-level deprecation
        /// finding, even with no #263 entry — mirroring D5's exact polarity for the #263
        /// check, now applied independently by #247 from its own matched entry's status.
        #[test]
        fn test_generate_diagnostics_from_cache_deprecation_suppresses_yanked_only_match_without_263_entry()
         {
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
                    yanked: Arc::from(vec![("1.2.1".into(), RemovalStatus::AdvisoryDeprecated)]),
                    published_at: None,
                },
            );
            let resolved_versions = HashMap::new();
            // Deliberately no yanked entry: no #263 (in-use-version) finding for "serde" —
            // proves the suppression decision comes from #247's own matched-entry status,
            // not the #263 map.
            let outcomes = DependencyOutcomes::new().with_deprecation(
                "serde",
                Deprecation {
                    reason: Some("archived".to_string()),
                    replacement: None,
                },
            );

            let diagnostics = generate_diagnostics_from_cache(
                &parse_result,
                VersionData::new(&cached_versions, &resolved_versions).with_outcomes(&outcomes),
                &formatter,
                parse_result.uri(),
                crate::freshness::FreshnessSettings::default(),
                DiagnosticSeverities::default(),
                PublishTime::now(),
            );

            assert!(
                diagnostics
                    .iter()
                    .all(|d| !d.message().starts_with(formatter.yanked_message())),
                "an AdvisoryDeprecated #247 match must yield to the co-occurring deprecation \
                 finding, got: {diagnostics:?}"
            );
            assert!(
                diagnostics
                    .iter()
                    .any(|d| d.message().starts_with(formatter.deprecated_message())),
                "the deprecation finding must still fire: {diagnostics:?}"
            );
        }

        /// #437 S1 regression: a D5-suppressed #263 finding (in-use version is
        /// `AdvisoryDeprecated`, deprecation co-occurs, so #263 pushes nothing) must NOT gate
        /// off a same-dependency #247 finding whose own matched entry is genuinely `Yanked`.
        /// An earlier version of this fix folded `deprecation_suppresses_yanked` into the same
        /// sentinel used for #247's dedup guard, which reintroduced #437's exact failure mode
        /// through this branch: the in-use version ("2.0.0") is merely deprecated and its own
        /// diagnostic is correctly suppressed, but the requirement ("modelled") is separately
        /// satisfiable only by a different, genuinely yanked version ("1.2.1") — that must
        /// still fire.
        #[test]
        fn test_generate_diagnostics_from_cache_suppressed_263_entry_does_not_gate_off_yanked_247_match()
         {
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
                    yanked: Arc::from(vec![("1.2.1".into(), RemovalStatus::Yanked)]),
                    published_at: None,
                },
            );
            let resolved_versions = HashMap::new();
            // #263 entry for a *different* version ("2.0.0") than the one #247 matches
            // ("1.2.1"), with status `AdvisoryDeprecated` — this is the D5-suppressed case.
            let outcomes = DependencyOutcomes::new()
                .with_yanked("serde", ("2.0.0".into(), RemovalStatus::AdvisoryDeprecated))
                .with_deprecation(
                    "serde",
                    Deprecation {
                        reason: Some("archived".to_string()),
                        replacement: None,
                    },
                );

            let diagnostics = generate_diagnostics_from_cache(
                &parse_result,
                VersionData::new(&cached_versions, &resolved_versions).with_outcomes(&outcomes),
                &formatter,
                parse_result.uri(),
                crate::freshness::FreshnessSettings::default(),
                DiagnosticSeverities::default(),
                PublishTime::now(),
            );

            assert_eq!(
                diagnostics.len(),
                2,
                "expected exactly the deprecation diagnostic plus the #247 yanked-only \
                 match — the D5-suppressed #263 in-use-version diagnostic (for the \
                 deprecated 2.0.0) must stay suppressed and contribute nothing, got: \
                 {diagnostics:?}"
            );
            // R3 always runs before R6b (#247), so index 0 is deprecation and index 1 is the
            // #247 match against the genuinely Yanked 1.2.1 — independent of R4's
            // D5-suppressed #263 finding for the unrelated 2.0.0 entry.
            assert_eq!(
                diagnostics[0].message(),
                format!("{}: archived", formatter.deprecated_message()),
                "the package-level deprecation finding must still fire: {diagnostics:?}"
            );
            assert_eq!(diagnostics[0].code(), Some(DEPRECATED_DIAGNOSTIC_CODE));
            assert_eq!(
                diagnostics[1].message(),
                format!("{}; latest is 2.0.0", formatter.yanked_message()),
                "the #247 match against the genuinely Yanked 1.2.1 must still fire even though \
                 the unrelated #263 in-use-version finding was D5-suppressed, got: {diagnostics:?}"
            );
            assert_eq!(diagnostics[1].code(), None);
        }

        /// #247 vs. #263 dedup: a dependency whose in-use version (lock-file-resolved, or an
        /// exact pin) is yanked *and* is the only version satisfying its own requirement
        /// triggers both the in-use-version check (`versions.outcomes` yanked, #263) and the
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
                    yanked: Arc::from(vec![("1.2.1".into(), RemovalStatus::Yanked)]),
                    published_at: None,
                },
            );
            let resolved_versions = HashMap::new();
            let outcomes = DependencyOutcomes::new()
                .with_yanked("serde", ("1.2.1".into(), RemovalStatus::Yanked));

            let diagnostics = generate_diagnostics_from_cache(
                &parse_result,
                VersionData::new(&cached_versions, &resolved_versions).with_outcomes(&outcomes),
                &formatter,
                parse_result.uri(),
                crate::freshness::FreshnessSettings::default(),
                DiagnosticSeverities::default(),
                PublishTime::now(),
            );

            // Two diagnostics expected: #263 (in-use-version) has no `continue`, so it
            // co-emits with "outdated". This proves the narrower claim that #247's
            // `yanked_only` check does not also fire.
            assert_eq!(
                diagnostics.len(),
                2,
                "expected exactly the yanked diagnostic plus the co-emitted outdated \
                 diagnostic (#263's policy), got: {diagnostics:?}"
            );
            // R4 (#263) runs before R7 (outdated); R6b (#247) is dedup-suppressed by R4
            // having already emitted, so index 0 is in-use-yanked and index 1 is outdated.
            assert_eq!(
                diagnostics[0].message(),
                format!("{} (1.2.1)", formatter.yanked_message()),
                "expected the in-use-version check (#263) to run first and win, got: {diagnostics:?}"
            );
            assert_eq!(diagnostics[0].code(), None);
            assert_eq!(
                diagnostics[1].message(),
                "Newer version available: 2.0.0",
                "expected the co-emitted outdated diagnostic, got: {diagnostics:?}"
            );
            assert_eq!(diagnostics[1].code(), None);
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
                    yanked: Arc::from(vec![("1.2.1".into(), RemovalStatus::Yanked)]),
                    published_at: None,
                },
            );
            let resolved_versions = HashMap::new();

            let severities = DiagnosticSeverities {
                yanked: Severity::Error,
                ..DiagnosticSeverities::default()
            };

            let diagnostics = generate_diagnostics_from_cache(
                &parse_result,
                VersionData::new(&cached_versions, &resolved_versions),
                &formatter,
                parse_result.uri(),
                crate::freshness::FreshnessSettings::default(),
                severities,
                PublishTime::now(),
            );

            assert_eq!(diagnostics.len(), 1);
            assert_eq!(diagnostics[0].severity, Some(Severity::Error));
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
                    yanked: Arc::from(vec![("1.0.0".into(), RemovalStatus::Yanked)]),
                    published_at: None,
                },
            );
            let resolved_versions = HashMap::new();

            let diagnostics = generate_diagnostics_from_cache(
                &parse_result,
                VersionData::new(&cached_versions, &resolved_versions),
                &formatter,
                parse_result.uri(),
                crate::freshness::FreshnessSettings::default(),
                DiagnosticSeverities::default(),
                PublishTime::now(),
            );

            assert!(
                !diagnostics
                    .iter()
                    .any(|d| d.message().starts_with(formatter.yanked_message())),
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
            assert!(
                requirement_matches_only_yanked(
                    &formatter,
                    &VersionReq::new("modelled"),
                    &versions(&["1.2.1", "unparseable"]),
                    &yanked_versions(&["1.2.1"]),
                )
                .is_none()
            );
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
            assert!(
                requirement_matches_only_yanked(
                    &formatter,
                    &VersionReq::new("modelled"),
                    &versions(&["unparseable", "1.2.1"]),
                    &yanked_versions(&["1.2.1"]),
                )
                .is_none()
            );
        }

        #[test]
        fn test_oversized_requirement_is_false_without_compiling() {
            let formatter =
                TableFormatter::new(|_v| panic!("must not compile/scan an oversized requirement"));
            let oversized = "1".repeat(MAX_REQUIREMENT_LEN + 1);
            assert!(
                requirement_matches_only_yanked(
                    &formatter,
                    &VersionReq::new(oversized),
                    &versions(&["1.0.0"]),
                    &yanked_versions(&["1.0.0"]),
                )
                .is_none()
            );
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
                    yanked: Arc::from(vec![("1.2.1".into(), RemovalStatus::Yanked)]),
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
                parse_result.uri(),
                crate::freshness::FreshnessSettings::default(),
                DiagnosticSeverities::default(),
                PublishTime::now(),
            );

            assert!(
                diagnostics
                    .iter()
                    .all(|d| !d.message().starts_with(formatter.yanked_message())),
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
                    yanked: Arc::from(vec![("1.2.1".into(), RemovalStatus::Yanked)]),
                    published_at: None,
                },
            );
            let resolved_versions = HashMap::new();

            let diagnostics = generate_diagnostics_from_cache(
                &parse_result,
                VersionData::new(&cached_versions, &resolved_versions),
                &formatter,
                parse_result.uri(),
                crate::freshness::FreshnessSettings::default(),
                DiagnosticSeverities::default(),
                PublishTime::now(),
            );

            assert!(
                !diagnostics
                    .iter()
                    .any(|d| d.message().contains("Newer version available")),
                "the yanked diagnostic must suppress the outdated hint, not add to it, got: {diagnostics:?}"
            );
        }
    }

    // apply_license_policy_rule / R2a tests (issue #661)
    mod license_policy_tests {
        use super::*;
        use crate::LicensePolicy;
        use crate::position::{Position, Range};

        fn single_dep_parse_result() -> MockParseResult {
            MockParseResult {
                deps: vec![MockDep {
                    name: "serde".into(),
                    version_req: "1.0.0".into(),
                    version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                    name_range: Range::new(Position::new(0, 0), Position::new(0, 5)),
                }],
                uri: crate::test_util::test_uri("/test/Cargo.toml"),
            }
        }

        #[test]
        fn no_policy_configured_produces_no_diagnostic() {
            let formatter = MockFormatter;
            let parse_result = single_dep_parse_result();
            let mut cached_versions = HashMap::new();
            cached_versions.insert(
                PackageName::from("serde"),
                PackageVersions::latest_only("1.0.0"),
            );
            let resolved_versions = HashMap::new();
            let mut license_prefetch = HashMap::new();
            license_prefetch.insert(PackageName::from("serde"), vec!["GPL-3.0".to_string()]);

            let diagnostics = generate_diagnostics_from_cache(
                &parse_result,
                VersionData::new(&cached_versions, &resolved_versions)
                    .with_license_prefetch(&license_prefetch),
                &formatter,
                parse_result.uri(),
                crate::freshness::FreshnessSettings::default(),
                DiagnosticSeverities::default(),
                PublishTime::now(),
            );

            assert!(
                diagnostics.is_empty(),
                "no VersionData::license_policy attached must produce no license diagnostic, got: {diagnostics:?}"
            );
        }

        #[test]
        fn policy_configured_but_no_prefetch_data_produces_no_diagnostic() {
            let formatter = MockFormatter;
            let parse_result = single_dep_parse_result();
            let mut cached_versions = HashMap::new();
            cached_versions.insert(
                PackageName::from("serde"),
                PackageVersions::latest_only("1.0.0"),
            );
            let resolved_versions = HashMap::new();
            let policy = LicensePolicy::new(vec![], vec!["GPL-3.0".to_string()]);

            let diagnostics = generate_diagnostics_from_cache(
                &parse_result,
                VersionData::new(&cached_versions, &resolved_versions).with_license_policy(&policy),
                &formatter,
                parse_result.uri(),
                crate::freshness::FreshnessSettings::default(),
                DiagnosticSeverities::default(),
                PublishTime::now(),
            );

            assert!(
                diagnostics.is_empty(),
                "a dependency with no known license (NFR-003) must never be treated as a \
                 violation, got: {diagnostics:?}"
            );
        }

        #[test]
        fn denied_license_emits_error_diagnostic() {
            let formatter = MockFormatter;
            let parse_result = single_dep_parse_result();
            let mut cached_versions = HashMap::new();
            cached_versions.insert(
                PackageName::from("serde"),
                PackageVersions::latest_only("1.0.0"),
            );
            let resolved_versions = HashMap::new();
            let mut license_prefetch = HashMap::new();
            license_prefetch.insert(PackageName::from("serde"), vec!["GPL-3.0".to_string()]);
            let policy = LicensePolicy::new(vec![], vec!["GPL-3.0".to_string()]);

            let diagnostics = generate_diagnostics_from_cache(
                &parse_result,
                VersionData::new(&cached_versions, &resolved_versions)
                    .with_license_prefetch(&license_prefetch)
                    .with_license_policy(&policy),
                &formatter,
                parse_result.uri(),
                crate::freshness::FreshnessSettings::default(),
                DiagnosticSeverities::default(),
                PublishTime::now(),
            );

            assert_eq!(diagnostics.len(), 1);
            assert_eq!(diagnostics[0].severity, Some(Severity::Error));
            assert_eq!(diagnostics[0].message(), "serde: GPL-3.0 denied by policy");
            assert_eq!(
                diagnostics[0].code(),
                Some(LICENSE_POLICY_VIOLATION_DIAGNOSTIC_CODE)
            );
            assert_eq!(
                diagnostics[0].range,
                Range::new(Position::new(0, 0), Position::new(0, 5))
            );
        }

        /// Critic follow-up S1 (#1242, #1246): the license-policy diagnostic already
        /// truncates the *license* (`MAX_DIAGNOSTIC_VALUE_CHARS`) but, before
        /// this fix, interpolated the raw dependency *name* — same client-visible
        /// `Diagnostic.message()`, same CWE-532/CWE-117 exposure as R5a/R5c/R5d.
        #[test]
        fn denied_license_diagnostic_redacts_credential_shaped_name() {
            let formatter = MockFormatter;
            let credential_name = "https://svcacct:glpat-AAAABBBBCCCCDDDD@gitlab.corp/g/p";
            let parse_result = MockParseResult {
                deps: vec![MockDep {
                    name: credential_name.into(),
                    version_req: "1.0.0".into(),
                    version_range: Range::new(Position::new(0, 10), Position::new(0, 20)),
                    name_range: Range::new(Position::new(0, 0), Position::new(0, 11)),
                }],
                uri: crate::test_util::test_uri("/test/Cargo.toml"),
            };
            let mut cached_versions = HashMap::new();
            cached_versions.insert(
                PackageName::from(credential_name),
                PackageVersions::latest_only("1.0.0"),
            );
            let resolved_versions = HashMap::new();
            let mut license_prefetch = HashMap::new();
            license_prefetch.insert(
                PackageName::from(credential_name),
                vec!["GPL-3.0".to_string()],
            );
            let policy = LicensePolicy::new(vec![], vec!["GPL-3.0".to_string()]);

            let diagnostics = generate_diagnostics_from_cache(
                &parse_result,
                VersionData::new(&cached_versions, &resolved_versions)
                    .with_license_prefetch(&license_prefetch)
                    .with_license_policy(&policy),
                &formatter,
                parse_result.uri(),
                crate::freshness::FreshnessSettings::default(),
                DiagnosticSeverities::default(),
                PublishTime::now(),
            );

            assert_eq!(diagnostics.len(), 1);
            assert!(diagnostics[0].message().contains("***@"));
            assert!(!diagnostics[0].message().contains("glpat-AAAABBBBCCCCDDDD"));
        }

        #[test]
        fn not_allowed_license_emits_warning_diagnostic() {
            let formatter = MockFormatter;
            let parse_result = single_dep_parse_result();
            let mut cached_versions = HashMap::new();
            cached_versions.insert(
                PackageName::from("serde"),
                PackageVersions::latest_only("1.0.0"),
            );
            let resolved_versions = HashMap::new();
            let mut license_prefetch = HashMap::new();
            license_prefetch.insert(PackageName::from("serde"), vec!["ISC".to_string()]);
            let policy = LicensePolicy::new(vec!["MIT".to_string()], vec![]);

            let diagnostics = generate_diagnostics_from_cache(
                &parse_result,
                VersionData::new(&cached_versions, &resolved_versions)
                    .with_license_prefetch(&license_prefetch)
                    .with_license_policy(&policy),
                &formatter,
                parse_result.uri(),
                crate::freshness::FreshnessSettings::default(),
                DiagnosticSeverities::default(),
                PublishTime::now(),
            );

            assert_eq!(diagnostics.len(), 1);
            assert_eq!(diagnostics[0].severity, Some(Severity::Warning));
            assert_eq!(
                diagnostics[0].message(),
                "serde: ISC not on the allowed license list"
            );
        }

        /// #1257: registry-supplied license text is untrusted, free-form data — a
        /// bidirectional-override or other invisible character embedded in it must not
        /// survive into the client-visible diagnostic message (Trojan Source,
        /// CVE-2021-42574), the same concern [`redact_name_for_diagnostic`] already covers
        /// for the dependency name on this same message.
        #[test]
        fn not_allowed_license_diagnostic_sanitizes_bidi_override_in_license_text() {
            let formatter = MockFormatter;
            let parse_result = single_dep_parse_result();
            let mut cached_versions = HashMap::new();
            cached_versions.insert(
                PackageName::from("serde"),
                PackageVersions::latest_only("1.0.0"),
            );
            let resolved_versions = HashMap::new();
            let mut license_prefetch = HashMap::new();
            license_prefetch.insert(
                PackageName::from("serde"),
                vec!["ISC\u{202E}evil".to_string()],
            );
            let policy = LicensePolicy::new(vec!["MIT".to_string()], vec![]);

            let diagnostics = generate_diagnostics_from_cache(
                &parse_result,
                VersionData::new(&cached_versions, &resolved_versions)
                    .with_license_prefetch(&license_prefetch)
                    .with_license_policy(&policy),
                &formatter,
                parse_result.uri(),
                crate::freshness::FreshnessSettings::default(),
                DiagnosticSeverities::default(),
                PublishTime::now(),
            );

            assert_eq!(diagnostics.len(), 1);
            assert!(!diagnostics[0].message().contains('\u{202E}'));
            assert!(diagnostics[0].message().contains("ISC"));
        }

        #[test]
        fn compliant_license_produces_no_diagnostic() {
            let formatter = MockFormatter;
            let parse_result = single_dep_parse_result();
            let mut cached_versions = HashMap::new();
            cached_versions.insert(
                PackageName::from("serde"),
                PackageVersions::latest_only("1.0.0"),
            );
            let resolved_versions = HashMap::new();
            let mut license_prefetch = HashMap::new();
            license_prefetch.insert(PackageName::from("serde"), vec!["MIT".to_string()]);
            let policy = LicensePolicy::new(vec!["MIT".to_string()], vec!["GPL-3.0".to_string()]);

            let diagnostics = generate_diagnostics_from_cache(
                &parse_result,
                VersionData::new(&cached_versions, &resolved_versions)
                    .with_license_prefetch(&license_prefetch)
                    .with_license_policy(&policy),
                &formatter,
                parse_result.uri(),
                crate::freshness::FreshnessSettings::default(),
                DiagnosticSeverities::default(),
                PublishTime::now(),
            );

            assert!(diagnostics.is_empty());
        }

        /// The license-policy rule must fire independently of registry-cache state (like
        /// R2/R3/R4) — an unknown package (no cache entry) still gets its "Unknown package"
        /// diagnostic *and* the license-policy diagnostic, not one instead of the other.
        #[test]
        fn fires_alongside_unknown_package_diagnostic() {
            let formatter = MockFormatter;
            let parse_result = single_dep_parse_result();
            let cached_versions = HashMap::new();
            let resolved_versions = HashMap::new();
            let mut license_prefetch = HashMap::new();
            license_prefetch.insert(PackageName::from("serde"), vec!["GPL-3.0".to_string()]);
            let policy = LicensePolicy::new(vec![], vec!["GPL-3.0".to_string()]);

            let diagnostics = generate_diagnostics_from_cache(
                &parse_result,
                VersionData::new(&cached_versions, &resolved_versions)
                    .with_license_prefetch(&license_prefetch)
                    .with_license_policy(&policy),
                &formatter,
                parse_result.uri(),
                crate::freshness::FreshnessSettings::default(),
                DiagnosticSeverities::default(),
                PublishTime::now(),
            );

            assert_eq!(
                diagnostics.len(),
                2,
                "expected both diagnostics, got: {diagnostics:?}"
            );
            assert!(
                diagnostics
                    .iter()
                    .any(|d| d.message().contains("Unknown package"))
            );
            assert!(
                diagnostics
                    .iter()
                    .any(|d| d.message().contains("denied by policy"))
            );
        }

        /// Issue #679: a Gradle POM free-text license recognized by
        /// [`crate::licenses::normalize_pom_license_names_checked`] normalizes to its
        /// SPDX id before evaluation, so a compliant dependency produces no diagnostic — Gradle
        /// is no longer unconditionally excluded from this rule (issue #660/#661 critic
        /// C2's original gate).
        #[test]
        fn gradle_dependency_with_recognized_license_is_evaluated_and_compliant() {
            let formatter = MockFormatter;
            let parse_result = single_dep_parse_result();
            let mut cached_versions = HashMap::new();
            cached_versions.insert(
                PackageName::from("serde"),
                PackageVersions::latest_only("1.0.0"),
            );
            let resolved_versions = HashMap::new();
            let mut license_prefetch = HashMap::new();
            license_prefetch.insert(
                PackageName::from("serde"),
                vec!["The Apache Software License, Version 2.0".to_string()],
            );
            let policy = LicensePolicy::new(vec!["Apache-2.0".to_string()], vec![]);

            let diagnostics = generate_diagnostics_from_cache(
                &parse_result,
                VersionData::new(&cached_versions, &resolved_versions)
                    .with_license_prefetch(&license_prefetch)
                    .with_license_policy(&policy)
                    .with_ecosystem(crate::EcosystemId::Gradle)
                    .with_license_source(crate::LicenseSource::PomFreeText),
                &formatter,
                parse_result.uri(),
                crate::freshness::FreshnessSettings::default(),
                DiagnosticSeverities::default(),
                PublishTime::now(),
            );

            assert!(
                diagnostics.is_empty(),
                "normalized Apache-2.0 must be compliant with an Apache-2.0 allow-list, \
                 got: {diagnostics:?}"
            );
        }

        /// Issue #679: a Gradle POM free-text license that normalizes to a denied SPDX
        /// id must produce a violation diagnostic — normalization re-enables real policy
        /// enforcement for Gradle, not just a no-op pass-through.
        #[test]
        fn gradle_dependency_with_recognized_license_is_denied() {
            let formatter = MockFormatter;
            let parse_result = single_dep_parse_result();
            let mut cached_versions = HashMap::new();
            cached_versions.insert(
                PackageName::from("serde"),
                PackageVersions::latest_only("1.0.0"),
            );
            let resolved_versions = HashMap::new();
            let mut license_prefetch = HashMap::new();
            license_prefetch.insert(
                PackageName::from("serde"),
                vec!["GNU General Public License v3".to_string()],
            );
            let policy = LicensePolicy::new(vec![], vec!["GPL-3.0".to_string()]);

            let diagnostics = generate_diagnostics_from_cache(
                &parse_result,
                VersionData::new(&cached_versions, &resolved_versions)
                    .with_license_prefetch(&license_prefetch)
                    .with_license_policy(&policy)
                    .with_ecosystem(crate::EcosystemId::Gradle)
                    .with_license_source(crate::LicenseSource::PomFreeText),
                &formatter,
                parse_result.uri(),
                crate::freshness::FreshnessSettings::default(),
                DiagnosticSeverities::default(),
                PublishTime::now(),
            );

            assert!(
                diagnostics
                    .iter()
                    .any(|d| d.message().contains("denied by policy")),
                "normalized GPL-3.0 must be denied by a GPL-3.0 deny-list, got: {diagnostics:?}"
            );
        }

        /// Issue #679 fail-closed contract: a Gradle POM free-text license the
        /// normalization table doesn't recognize must never be flagged as a violation —
        /// it is dropped before evaluation, the same as a dependency with no license
        /// data at all (NFR-003 graceful degradation), not guessed at.
        #[test]
        fn gradle_dependency_with_unrecognized_license_fails_closed() {
            let formatter = MockFormatter;
            let parse_result = single_dep_parse_result();
            let mut cached_versions = HashMap::new();
            cached_versions.insert(
                PackageName::from("serde"),
                PackageVersions::latest_only("1.0.0"),
            );
            let resolved_versions = HashMap::new();
            let mut license_prefetch = HashMap::new();
            license_prefetch.insert(
                PackageName::from("serde"),
                vec!["Some Bespoke Corporate License".to_string()],
            );
            let policy = LicensePolicy::new(vec!["Apache-2.0".to_string()], vec![]);

            let diagnostics = generate_diagnostics_from_cache(
                &parse_result,
                VersionData::new(&cached_versions, &resolved_versions)
                    .with_license_prefetch(&license_prefetch)
                    .with_license_policy(&policy)
                    .with_ecosystem(crate::EcosystemId::Gradle)
                    .with_license_source(crate::LicenseSource::PomFreeText),
                &formatter,
                parse_result.uri(),
                crate::freshness::FreshnessSettings::default(),
                DiagnosticSeverities::default(),
                PublishTime::now(),
            );

            assert!(
                diagnostics.is_empty(),
                "unrecognized free-text license must never be flagged, got: {diagnostics:?}"
            );
        }

        /// Issue #679 critic S1: a Gradle POM with one recognized and one unrecognized
        /// license entry must never manufacture a `NotAllowed` violation from the
        /// recognized entry alone — the unrecognized entry might have been the one that
        /// actually satisfied the allow-list, and dropping it silently shrinks the
        /// evidence. General form of the critic's `EPL-2.0` + `Eclipse Distribution
        /// License` repro (the exact EDL string is now in the table, so this test uses
        /// a still-unrecognized second entry to keep exercising the suppression path).
        #[test]
        fn gradle_partial_normalization_never_manufactures_false_not_allowed() {
            let formatter = MockFormatter;
            let parse_result = single_dep_parse_result();
            let mut cached_versions = HashMap::new();
            cached_versions.insert(
                PackageName::from("serde"),
                PackageVersions::latest_only("1.0.0"),
            );
            let resolved_versions = HashMap::new();
            let mut license_prefetch = HashMap::new();
            license_prefetch.insert(
                PackageName::from("serde"),
                vec![
                    "Eclipse Public License 2.0".to_string(),
                    "Some Custom OEM License Addendum".to_string(),
                ],
            );
            // The recognized entry (EPL-2.0) does not itself satisfy this allow-list —
            // only the dropped, unrecognized entry could have, and this rule cannot
            // know whether it would have.
            let policy = LicensePolicy::new(vec!["BSD-3-Clause".to_string()], vec![]);

            let diagnostics = generate_diagnostics_from_cache(
                &parse_result,
                VersionData::new(&cached_versions, &resolved_versions)
                    .with_license_prefetch(&license_prefetch)
                    .with_license_policy(&policy)
                    .with_ecosystem(crate::EcosystemId::Gradle)
                    .with_license_source(crate::LicenseSource::PomFreeText),
                &formatter,
                parse_result.uri(),
                crate::freshness::FreshnessSettings::default(),
                DiagnosticSeverities::default(),
                PublishTime::now(),
            );

            assert!(
                diagnostics.is_empty(),
                "partial normalization must never manufacture a NotAllowed violation, \
                 got: {diagnostics:?}"
            );
        }

        /// Issue #679 critic S1: unlike `NotAllowed`, a `Denied` conclusion must still
        /// fire even when another entry on the same POM failed to normalize — a
        /// recognized entry matching `deny` is real evidence regardless of what else
        /// wasn't recognized (dropping entries can only ever miss a denial, never
        /// fabricate one).
        #[test]
        fn gradle_partial_normalization_still_allows_denied_to_fire() {
            let formatter = MockFormatter;
            let parse_result = single_dep_parse_result();
            let mut cached_versions = HashMap::new();
            cached_versions.insert(
                PackageName::from("serde"),
                PackageVersions::latest_only("1.0.0"),
            );
            let resolved_versions = HashMap::new();
            let mut license_prefetch = HashMap::new();
            license_prefetch.insert(
                PackageName::from("serde"),
                vec![
                    "GNU General Public License v3".to_string(),
                    "Some Custom OEM License Addendum".to_string(),
                ],
            );
            let policy = LicensePolicy::new(vec![], vec!["GPL-3.0".to_string()]);

            let diagnostics = generate_diagnostics_from_cache(
                &parse_result,
                VersionData::new(&cached_versions, &resolved_versions)
                    .with_license_prefetch(&license_prefetch)
                    .with_license_policy(&policy)
                    .with_ecosystem(crate::EcosystemId::Gradle)
                    .with_license_source(crate::LicenseSource::PomFreeText),
                &formatter,
                parse_result.uri(),
                crate::freshness::FreshnessSettings::default(),
                DiagnosticSeverities::default(),
                PublishTime::now(),
            );

            assert!(
                diagnostics
                    .iter()
                    .any(|d| d.message().contains("denied by policy")),
                "a recognized denied entry must still fire despite a sibling \
                 unrecognized entry, got: {diagnostics:?}"
            );
        }

        /// Tester gap: a genuinely dual-licensed Gradle POM (two distinct, both
        /// recognized, free-text license entries) must flow through the full pipeline —
        /// normalization inside `apply_license_policy_rule` feeding
        /// `evaluate_license_policy`'s "any entry matches allow" logic — not just a
        /// single-entry POM.
        #[test]
        fn gradle_dual_licensed_pom_is_compliant_if_any_normalized_entry_matches_allow() {
            let formatter = MockFormatter;
            let parse_result = single_dep_parse_result();
            let mut cached_versions = HashMap::new();
            cached_versions.insert(
                PackageName::from("serde"),
                PackageVersions::latest_only("1.0.0"),
            );
            let resolved_versions = HashMap::new();
            let mut license_prefetch = HashMap::new();
            license_prefetch.insert(
                PackageName::from("serde"),
                vec![
                    "Apache License, Version 2.0".to_string(),
                    "GNU General Public License v3".to_string(),
                ],
            );
            let policy = LicensePolicy::new(vec!["Apache-2.0".to_string()], vec![]);

            let diagnostics = generate_diagnostics_from_cache(
                &parse_result,
                VersionData::new(&cached_versions, &resolved_versions)
                    .with_license_prefetch(&license_prefetch)
                    .with_license_policy(&policy)
                    .with_ecosystem(crate::EcosystemId::Gradle)
                    .with_license_source(crate::LicenseSource::PomFreeText),
                &formatter,
                parse_result.uri(),
                crate::freshness::FreshnessSettings::default(),
                DiagnosticSeverities::default(),
                PublishTime::now(),
            );

            assert!(
                diagnostics.is_empty(),
                "dual-licensed dependency must be compliant when the Apache-2.0 side \
                 matches the allow-list, got: {diagnostics:?}"
            );
        }

        /// Tester gap (continued): the same dual-licensed POM is denied when the GPL-3.0
        /// side matches a deny-list — deny wins over allow even though the Apache-2.0
        /// side would otherwise be compliant.
        #[test]
        fn gradle_dual_licensed_pom_denied_wins_over_allow() {
            let formatter = MockFormatter;
            let parse_result = single_dep_parse_result();
            let mut cached_versions = HashMap::new();
            cached_versions.insert(
                PackageName::from("serde"),
                PackageVersions::latest_only("1.0.0"),
            );
            let resolved_versions = HashMap::new();
            let mut license_prefetch = HashMap::new();
            license_prefetch.insert(
                PackageName::from("serde"),
                vec![
                    "Apache License, Version 2.0".to_string(),
                    "GNU General Public License v3".to_string(),
                ],
            );
            let policy =
                LicensePolicy::new(vec!["Apache-2.0".to_string()], vec!["GPL-3.0".to_string()]);

            let diagnostics = generate_diagnostics_from_cache(
                &parse_result,
                VersionData::new(&cached_versions, &resolved_versions)
                    .with_license_prefetch(&license_prefetch)
                    .with_license_policy(&policy)
                    .with_ecosystem(crate::EcosystemId::Gradle)
                    .with_license_source(crate::LicenseSource::PomFreeText),
                &formatter,
                parse_result.uri(),
                crate::freshness::FreshnessSettings::default(),
                DiagnosticSeverities::default(),
                PublishTime::now(),
            );

            assert!(
                diagnostics
                    .iter()
                    .any(|d| d.message().contains("denied by policy")),
                "GPL-3.0 side must be denied even though Apache-2.0 is also present and \
                 allow-listed, got: {diagnostics:?}"
            );
        }

        /// Issue #660/#661 critic security P2: a registry-declared license entry longer
        /// than `MAX_DIAGNOSTIC_VALUE_CHARS` must be truncated in the
        /// rendered diagnostic message rather than interpolated verbatim. Uses the
        /// `NotAllowed` branch (not `Denied`): an entry long enough to matter here can
        /// never also be a `policy.deny` match, since `LicensePolicy::new` itself caps
        /// every *configured* SPDX identifier at 128 chars — only the untrusted
        /// `license_prefetch` side is unbounded.
        #[test]
        fn overlong_not_allowed_license_is_truncated_in_message() {
            let formatter = MockFormatter;
            let parse_result = single_dep_parse_result();
            let mut cached_versions = HashMap::new();
            cached_versions.insert(
                PackageName::from("serde"),
                PackageVersions::latest_only("1.0.0"),
            );
            let resolved_versions = HashMap::new();
            let overlong = "X".repeat(MAX_DIAGNOSTIC_VALUE_CHARS + 50);
            let mut license_prefetch = HashMap::new();
            license_prefetch.insert(PackageName::from("serde"), vec![overlong.clone()]);
            let policy = LicensePolicy::new(vec!["MIT".to_string()], vec![]);

            let diagnostics = generate_diagnostics_from_cache(
                &parse_result,
                VersionData::new(&cached_versions, &resolved_versions)
                    .with_license_prefetch(&license_prefetch)
                    .with_license_policy(&policy),
                &formatter,
                parse_result.uri(),
                crate::freshness::FreshnessSettings::default(),
                DiagnosticSeverities::default(),
                PublishTime::now(),
            );

            assert_eq!(diagnostics.len(), 1);
            assert!(
                diagnostics[0].message().len() < overlong.len(),
                "expected the message to be truncated, got: {:?}",
                diagnostics[0].message()
            );
            assert!(diagnostics[0].message().contains('…'));
        }

        /// Issue #660/#661 critic security P2: a `NotAllowed` violation against a
        /// dependency declaring many license entries must cap the number of entries
        /// joined into the message, not render an unbounded list.
        #[test]
        fn many_license_entries_are_capped_in_not_allowed_message() {
            let formatter = MockFormatter;
            let parse_result = single_dep_parse_result();
            let mut cached_versions = HashMap::new();
            cached_versions.insert(
                PackageName::from("serde"),
                PackageVersions::latest_only("1.0.0"),
            );
            let resolved_versions = HashMap::new();
            let many: Vec<String> = (0..50).map(|i| format!("License-{i}")).collect();
            let mut license_prefetch = HashMap::new();
            license_prefetch.insert(PackageName::from("serde"), many);
            let policy = LicensePolicy::new(vec!["MIT".to_string()], vec![]);

            let diagnostics = generate_diagnostics_from_cache(
                &parse_result,
                VersionData::new(&cached_versions, &resolved_versions)
                    .with_license_prefetch(&license_prefetch)
                    .with_license_policy(&policy),
                &formatter,
                parse_result.uri(),
                crate::freshness::FreshnessSettings::default(),
                DiagnosticSeverities::default(),
                PublishTime::now(),
            );

            assert_eq!(diagnostics.len(), 1);
            assert!(
                diagnostics[0].message().contains("more)"),
                "expected the entry list to be capped with a '(+N more)' suffix, got: {:?}",
                diagnostics[0].message()
            );
        }
    }
}
