//! Shared LSP response builders.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use crate::error::DepsError;
use crate::licenses::LicensePolicy;
use crate::osv::{
    CandidateStatusMap, CandidateStatuses, LatestStatusMap, ScanOutcome, StructuralSkipReason,
    UpgradeStatus, VulnKey, VulnSeverity, VulnerabilityMap,
};
use crate::position::{Position, Range};
use crate::{
    ConcreteVersion, CooldownWindow, Dependency, Deprecation, DepsDevClient, EcosystemId,
    FetchFailure, GossipFindings, LicenseSource, PackageName, PublishTime, RemovalStatus,
    TyposquatSignal, VersionReq,
};

mod candidate_tags;
#[cfg(feature = "lsp-responses")]
mod code_actions;
#[cfg(feature = "lsp-responses")]
mod code_lenses;
mod diagnostics;
mod formatter;
mod git_pin;
mod git_ref;
#[cfg(feature = "lsp-responses")]
mod hover;
#[cfg(feature = "lsp-responses")]
mod hover_markdown;
mod in_use_version;
#[cfg(feature = "lsp-responses")]
mod inlay_hints;
mod sha_comment;
#[cfg(test)]
pub(crate) mod test_support;
#[cfg(test)]
#[cfg(feature = "lsp-responses")]
pub(crate) mod test_support_lsp;
mod unknown_ref;

/// Generic replacement for this module's former `TextEdit`-only `dedup_overlapping_edits`
/// (#1329) — re-exported here so every existing `lsp_helpers::dedup_overlapping_edits(edits,
/// caller)` call site (e.g. `deps_github_actions::collect_pin_all_to_sha_edits`) keeps
/// compiling unchanged, with `E = ls_types::TextEdit` inferred from the call's own argument
/// type.
#[cfg(feature = "lsp-responses")]
pub use crate::edit::dedup_overlapping_edits;
pub use candidate_tags::{
    CandidateSiblings, CandidateSiblingsUnknown, CandidateTagSource, TaggedVersions,
};
#[cfg(feature = "lsp-responses")]
pub use code_actions::generate_code_actions;
#[cfg(feature = "lsp-responses")]
pub use code_lenses::{
    PIN_ALL_TO_SHA_COMMAND_ID, PinNoun, build_pin_all_to_sha_lens, collect_update_all_edits,
    generate_code_lenses,
};
pub use diagnostics::{
    BoundedVersionReq, DEPRECATED_DIAGNOSTIC_CODE, DiagnosticSeverities,
    LICENSE_POLICY_VIOLATION_DIAGNOSTIC_CODE, MAX_DIAGNOSTIC_VALUE_CHARS, MAX_REQUIREMENT_LEN,
    SiblingMatchNote, TYPOSQUAT_DIAGNOSTIC_CODE, TyposquatFetchOutcome,
    UNSATISFIABLE_DIAGNOSTIC_CODE, advisory_text, compile_requirement_unless,
    fetch_gossip_findings_batch, fetch_typosquat_signals, force_refresh_gossip_findings,
    generate_diagnostics_from_cache, redact_name_for_diagnostic, redact_requirement_for_diagnostic,
    requirement_is_unsatisfiable, requirement_len_exceeds_cap,
    sanitize_advisory_text_for_diagnostic, sanitize_and_truncate_for_diagnostic,
    truncate_for_diagnostic,
};
// `pub` (#1578): `edit.rs`/`in_use_version.rs` share this in-crate, and it is also reused by
// callers outside `deps-core` that need this same size gate before compiling a requirement
// (mirroring `requirement_len_exceeds_cap`'s own `pub` rationale) rather than duplicating the
// length check at their own `compile_bounded_requirement` call site (#1472).
pub use diagnostics::requirement_is_oversized;
// `pub(crate)` (not `pub`, matching the constant's own visibility) so `completion.rs` can
// share this bound with `inlay_hints`/`hover` rather than declaring a duplicate cap.
// `completion` is itself `#[cfg(feature = "lsp-responses")]` (see `lib.rs`) and is this
// re-export's only consumer outside `lsp_helpers`, so without this gate a default-features
// build (e.g. `fuzz`'s workspace check) sees it as unused.
#[cfg(feature = "lsp-responses")]
pub(crate) use diagnostics::MAX_VERSION_DIAGNOSTIC_CHARS;
pub use formatter::{
    BareMeaning, BuildMetadataPolicy, DiagnosticMessages, DiagnosticPolicy, EcosystemFormatter,
    OsvNameAvailability, OsvNaming, PackageNaming, PackageRendering, RequirementGate,
    RequirementResolution, RequirementRewriteShape, SourcePolicy, bare_meaning,
    classify_requirement_rewrite_shape, format_version_replacing_by_shape, requirement_is_compound,
    up_to_date_for_comparators_via_compiled_matcher, up_to_date_via_compiled_matcher,
};
pub use git_pin::{
    GitPinView, git_candidate_tag_source, git_commit_rewrite, git_tag_replacement, resolve_git_pin,
};
pub use git_ref::{
    CommitRewrite, CommitSha, MAX_FALLBACK_SCAN_BYTES, MarkedScalar, PartialTagPolicy,
    PinResolution, ResolvedPin, ShaPinLookup, SiblingScope, SiblingTags, TagIndex, TagPosition,
    UnpublishedRef, byte_span_to_range, extends_tag, is_full_sha, is_null_tag,
    is_partial_semver_shaped, is_plain_null, is_tag_shaped, locate_value_span, marker_byte_offset,
    match_v_prefix_style, short_sha, tag_has_precedence, tag_pin_is_up_to_date,
};
#[cfg(feature = "lsp-responses")]
pub use git_ref::{
    ResolvedShaPin, ShaPinning, build_sha_pin_action, sha_pin_text_edit, splice_hover_line,
    splice_resolved_line,
};
#[cfg(feature = "lsp-responses")]
pub use hover::{CMD_DOT_FOOTER, generate_hover};
#[cfg(feature = "lsp-responses")]
pub use hover_markdown::{FieldKind, HoverMarkdown, SafeNumber};
pub use in_use_version::{
    InUseVersions, concrete_pin_version, has_unqueryable_resolved_pin, is_full_semver_shape,
    resolve_in_use_version, resolve_in_use_versions,
};
#[cfg(feature = "lsp-responses")]
pub use inlay_hints::generate_inlay_hints;
#[cfg(feature = "lsp-responses")]
pub use sha_comment::build_sha_comment_fix_action;
pub use sha_comment::{
    ClosingDelimiters, CommentCheck, CommentMismatch, CommentRemainder, CommentSlot, CommentTag,
    SHA_COMMENT_MISMATCH_DIAGNOSTIC_CODE, ShaPinComment, ShaPinTail, ShaPinTailRead,
    comment_slot_after, position_past_sha, read_sha_pin_tail, ref_is_last_on_line,
    sha_comment_mismatch_diagnostic, sha_comment_mismatch_hover_line, sha_pin_rewrite,
};
#[cfg(feature = "lsp-responses")]
pub use unknown_ref::build_unknown_ref_fix_action;
pub use unknown_ref::{
    UNKNOWN_REF_DIAGNOSTIC_CODE, UnknownRefTarget, dependency_at_position, unknown_ref_diagnostic,
    unknown_ref_diagnostic_for, unknown_ref_diagnostics,
};

/// Maximum number of recent versions hover's "Recent versions" section renders.
///
/// Also the walk target for registries (NuGet, npm) that must fetch publish times for
/// only the versions actually rendered, rather than the entire version history.
pub const HOVER_RECENT_VERSIONS: usize = 8;

/// A cooldown-cleared, ecosystem-safe, floor-protected fallback candidate (spec 075
/// `deps-cli update` fallback, FR-001/FR-002).
///
/// Computed once, at fetch time, by `deps-engine::classify::fetch::fetch_and_classify_package`
/// — never at read time (see [`cooldown_disposition`] for the read-time side). [`Self::published_at`]
/// is never `None`: a candidate without a known publish time is never stored (OQ2's fail-closed
/// rule for a non-`latest` candidate).
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CooldownFallback {
    /// The fallback candidate's version.
    pub version: ConcreteVersion,
    /// When the fallback candidate was published. Never `None` — see the type's own doc.
    pub published_at: PublishTime,
}

impl CooldownFallback {
    /// Constructs a `CooldownFallback`.
    ///
    /// Needed because [`Self`] is `#[non_exhaustive]`: a struct literal only works inside
    /// this crate, so every other crate must go through this constructor instead.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::PublishTime;
    /// use deps_core::lsp_helpers::CooldownFallback;
    ///
    /// let fallback = CooldownFallback::new("1.1.0".into(), PublishTime::from_unix_secs(1_000));
    /// assert_eq!(fallback.version, "1.1.0");
    /// ```
    #[must_use]
    pub const fn new(version: ConcreteVersion, published_at: PublishTime) -> Self {
        Self {
            version,
            published_at,
        }
    }
}

/// What blocked [`PackageVersions::latest`] from being usable as-is — drives
/// check/hover/diagnostics wording. Carried by [`CooldownDisposition::Blocked`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CooldownBlocker {
    /// GOSSIP reported an active cooldown for this exact version (spec 072 FR-005).
    Gossip,
    /// The local [`CooldownWindow`] heuristic reports this version as
    /// recently published, with no authoritative GOSSIP answer available for it.
    Local {
        /// When `latest` was published, per the registry.
        published_at: PublishTime,
    },
}

/// Read-time-only outcome of [`cooldown_disposition`] — never stored on [`PackageVersions`].
///
/// Spec 075 NFR-002: a stored disposition would be a fetch-time snapshot, violating spec 072
/// FR-011's read-time evaluation requirement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CooldownDisposition<'a> {
    /// The freshness feature is disabled — cooldown has no effect at all.
    NotEvaluated,
    /// `latest` is not blocked by cooldown (no GOSSIP verdict, or a past one; no active local
    /// heuristic result).
    Cleared,
    /// `latest` is currently blocked. `fallback`, when present, is the newest
    /// cooldown-cleared, ecosystem-safe, floor-protected alternative a caller may offer
    /// instead (spec 075) — `None` when no such candidate was found at fetch time.
    Blocked {
        /// What blocked `latest`.
        by: CooldownBlocker,
        /// The fallback candidate, if one was computed and stored for this dependency.
        fallback: Option<&'a CooldownFallback>,
    },
}

/// Outcome of [`cooldown_precedence`]: whether a single version is currently blocked by the
/// freshness cooldown, and by what.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CooldownPrecedence {
    /// Not blocked (no active GOSSIP verdict, or a past one; no active local heuristic result).
    Cleared,
    /// Currently blocked, and by what.
    Blocked(CooldownBlocker),
}

/// The GOSSIP-vs-local cooldown precedence rule for a single `(name, version)` pair.
///
/// An authoritative GOSSIP verdict wins outright, and only when GOSSIP has none does the local
/// heuristic ([`local_cooldown_precedence`]) apply.
///
/// Extracted from [`cooldown_disposition`] (spec 075 FR-004) so `deps-engine`'s fetch-time
/// fallback-candidate search (`compute_cooldown_fallback`) can share the exact same rule
/// without first needing a full [`PackageVersions`] — that type doesn't exist yet at fetch
/// time for any version other than the one being classified (issue #1551).
///
/// Takes a [`CooldownWindow`] rather than the [`FreshnessSettings`
/// enum](crate::FreshnessSettings) so callers naturally go through
/// [`FreshnessSettings::Enabled`](crate::FreshnessSettings::Enabled) — the only place a window
/// value is produced — though `CooldownWindow::from_secs` being `pub` means this is a
/// convention, not a hard type-level guarantee.
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::{CooldownPrecedence, cooldown_precedence};
/// use deps_core::{CooldownWindow, PackageName, PublishTime};
///
/// let cleared = cooldown_precedence(
///     None,
///     &PackageName::new("left-pad"),
///     "2.0.0",
///     Some(PublishTime::from_unix_secs(1_000)),
///     CooldownWindow::from_secs(500),
///     PublishTime::from_unix_secs(2_000),
/// );
/// assert_eq!(cleared, CooldownPrecedence::Cleared);
///
/// let blocked = cooldown_precedence(
///     None,
///     &PackageName::new("left-pad"),
///     "2.0.0",
///     Some(PublishTime::from_unix_secs(1_000)),
///     CooldownWindow::from_secs(5_000),
///     PublishTime::from_unix_secs(2_000),
/// );
/// assert!(matches!(blocked, CooldownPrecedence::Blocked(_)));
/// ```
#[must_use]
pub fn cooldown_precedence(
    gossip_prefetch: Option<&HashMap<PackageName, GossipFindings>>,
    name: &PackageName,
    version: &str,
    published_at: Option<PublishTime>,
    cooldown: CooldownWindow,
    now: PublishTime,
) -> CooldownPrecedence {
    match gossip_cooldown_for(gossip_prefetch, name, version, now) {
        GossipCooldownLookup::Active => CooldownPrecedence::Blocked(CooldownBlocker::Gossip),
        GossipCooldownLookup::NotActive => CooldownPrecedence::Cleared,
        GossipCooldownLookup::Unavailable => local_cooldown_precedence(published_at, cooldown, now),
    }
}

/// The local freshness heuristic alone (`published_at` age against `cooldown`), without GOSSIP.
///
/// Extracted from [`cooldown_precedence`]'s `Unavailable` arm so every site that evaluates the
/// local rule by itself — that arm, and [`cooldown_disposition`]'s read-time fallback
/// re-evaluation — shares one implementation rather than reimplementing the age comparison.
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::{CooldownPrecedence, local_cooldown_precedence};
/// use deps_core::{CooldownWindow, PublishTime};
///
/// let now = PublishTime::from_unix_secs(2_000);
/// let cooldown = CooldownWindow::from_secs(500);
///
/// // No known publish time: never blocked.
/// assert_eq!(
///     local_cooldown_precedence(None, cooldown, now),
///     CooldownPrecedence::Cleared
/// );
///
/// // Published recently: blocked.
/// let recent = PublishTime::from_unix_secs(1_900);
/// assert!(matches!(
///     local_cooldown_precedence(Some(recent), cooldown, now),
///     CooldownPrecedence::Blocked(_)
/// ));
///
/// // Age exactly equal to the window: cleared (the bound is exclusive).
/// let at_boundary = PublishTime::from_unix_secs(1_500);
/// assert_eq!(
///     local_cooldown_precedence(Some(at_boundary), cooldown, now),
///     CooldownPrecedence::Cleared
/// );
/// ```
#[must_use]
pub fn local_cooldown_precedence(
    published_at: Option<PublishTime>,
    cooldown: CooldownWindow,
    now: PublishTime,
) -> CooldownPrecedence {
    match published_at {
        Some(published_at) if cooldown.contains(published_at.age_secs_from(now)) => {
            CooldownPrecedence::Blocked(CooldownBlocker::Local { published_at })
        }
        _ => CooldownPrecedence::Cleared,
    }
}

/// Evaluates, at read time, whether [`PackageVersions::latest`] is blocked by the freshness
/// cooldown and whether a stored [`PackageVersions::cooldown_fallback`] candidate is available.
///
/// Spec 075 FR-004's single precedence function, shared by `apply_outdated_rule`
/// (check/diagnostics wording) and `deps-cli update`'s planner so the two commands can no
/// longer disagree (spec 075 NFR-001 steps 0-4; OSV verification is deliberately NOT this
/// function's job — see spec 075 FR-010/FR-011). The GOSSIP-vs-local precedence itself is
/// [`cooldown_precedence`]; this function adds the read-time fallback re-evaluation on top.
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::{CooldownDisposition, PackageVersions, cooldown_disposition};
/// use deps_core::{FreshnessSettings, PackageName, PublishTime};
/// use std::sync::Arc;
///
/// let versions = PackageVersions::new(
///     "2.0.0".into(),
///     Arc::from(vec!["2.0.0".into(), "1.0.0".into()]),
/// )
/// .with_published_at(PublishTime::from_unix_secs(1_000));
///
/// let disposition = cooldown_disposition(
///     &versions,
///     &PackageName::new("left-pad"),
///     FreshnessSettings::Enabled {
///         cooldown: deps_core::CooldownWindow::from_secs(500),
///     },
///     None,
///     PublishTime::from_unix_secs(2_000),
/// );
/// assert_eq!(disposition, CooldownDisposition::Cleared);
///
/// let blocked = cooldown_disposition(
///     &versions,
///     &PackageName::new("left-pad"),
///     FreshnessSettings::Enabled {
///         cooldown: deps_core::CooldownWindow::from_secs(5_000),
///     },
///     None,
///     PublishTime::from_unix_secs(2_000),
/// );
/// assert!(matches!(blocked, CooldownDisposition::Blocked { .. }));
/// ```
#[must_use]
pub fn cooldown_disposition<'a>(
    versions: &'a PackageVersions,
    name: &PackageName,
    freshness: crate::freshness::FreshnessSettings,
    gossip_prefetch: Option<&HashMap<PackageName, GossipFindings>>,
    now: PublishTime,
) -> CooldownDisposition<'a> {
    let crate::freshness::FreshnessSettings::Enabled { cooldown } = freshness else {
        return CooldownDisposition::NotEvaluated;
    };

    // NFR-002 (M3): the stored fallback candidate is itself re-evaluated at read time — a
    // cooldown window narrowed between fetch and read (or, for a long-lived LSP cache, simply
    // enough wall-clock time passing that the fetch-time computation has gone stale in the
    // *other* direction the caller didn't ask about) must never let a candidate that no
    // longer clears the window keep reading as usable. This can only make the outcome
    // stricter, never less safe — a `None` fallback stays `None`.
    let fallback = versions.cooldown_fallback.as_ref().filter(|fallback| {
        matches!(
            local_cooldown_precedence(Some(fallback.published_at), cooldown, now),
            CooldownPrecedence::Cleared
        )
    });

    match cooldown_precedence(
        gossip_prefetch,
        name,
        versions.latest.as_str(),
        versions.published_at,
        cooldown,
        now,
    ) {
        CooldownPrecedence::Cleared => CooldownDisposition::Cleared,
        CooldownPrecedence::Blocked(by) => CooldownDisposition::Blocked { by, fallback },
    }
}

/// Result of [`fallback_edit_excludes_newer`] (spec 076 FR-023): whether the ecosystem's
/// default-rendered fallback edit is safe to write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FallbackEditVerdict {
    /// The edit is safe: applying and re-parsing it still excludes every known `available`
    /// version newer than the fallback candidate.
    Writable,
    /// The edit was rejected — see [`FallbackEditRejection`] for which check failed.
    Rejected(FallbackEditRejection),
}

/// Which [`fallback_edit_excludes_newer`] check rejected the fallback edit, in evaluation
/// order (first failure wins; phase 2 is only reached once every phase-1 check passes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FallbackEditRejection {
    /// Precondition (round-4 critic D5, fix-cycle M2): `candidate`'s span does not equal this
    /// occurrence's own `Dependency::version_range()` — the edit was built for a different
    /// occurrence (or a stale one), so nothing below is meaningful for THIS dependency.
    /// Production always passes equality (the edit is always built from the same dependency's
    /// own `version_range()`); this guards the public API against a caller passing a
    /// mismatched edit.
    CandidateSpanMismatch,
    /// Fix-cycle (issue #1561/CWE-1284 class): `fallback` itself is absent from `available` —
    /// a stale or inconsistent candidate computed against a version list that has since
    /// changed. Checked once, shared by both d0 and d1, before either can read `fallback`'s
    /// position: never infer "not a downgrade" from the absence of evidence.
    FallbackUnlisted,
    /// Phase 1, a0 pre-check (issue #1580, CWE-400 defense-in-depth mirroring #1472/#1578):
    /// R0's raw string exceeds [`crate::lsp_helpers::MAX_REQUIREMENT_LEN`] —
    /// `compile_bounded_requirement` is never called for it. A size-based fail-closed guard, distinct
    /// from [`Self::OriginalUncompilable`] (a confirmed parse failure on an attempted compile).
    OriginalOversized,
    /// Phase 1, a0: the ORIGINAL declared requirement has no compiled matcher (e.g. GitHub
    /// Actions/GitLab CI tag pins) — unchanged from spec 075.
    OriginalUncompilable,
    /// Phase 1, c0: the original requirement already reads the fallback as current (a
    /// below-floor fallback, e.g. NuGet's bare-floor shape).
    OriginalAlreadyUpToDate,
    /// Phase 1, d0: the original requirement's own floor (the OLDEST `available` entry it
    /// still matches) is newer than `fallback` — writing it would be a downgrade below what R0
    /// already resolves to, or no listed entry evidences the floor at all (issues #1564/#1561:
    /// fixed from an earlier "reject if anything newer also matches" reading, which rejected
    /// nearly every permissive/auto-following requirement, and from a "no evidence means safe"
    /// vacuous accept on an unlisted declared pin).
    OriginalResolvesPastFallback,
    /// Fix-cycle (#1571): the original declared requirement admits some entry strictly newer
    /// than `fallback`, or a matcher-reported `!=`-style term explicitly bans `fallback`
    /// (`RequirementMatcher::explicitly_excludes`), yet `fallback` itself fails
    /// `r0_matcher.matches` — `fallback` sits inside R0's nominal span (or one of its `||`
    /// branches, for an ecosystem with alternation) but is punched out of it (a `!=` term, or a
    /// `||`-alternation gap), which a bare floor-position comparison (d0 above) cannot see since
    /// neither hole shape moves the floor. Distinct from the legitimate case where `fallback`
    /// fails `r0_matcher.matches` only because it exceeds every branch's ceiling entirely
    /// (FR-025's out-of-range acceptance).
    OriginalExcludesFallback,
    /// The edited manifest could not be re-parsed (FR-024) — [`crate::edit::ManifestReparse`]
    /// returned `None`, e.g. an `Ecosystem::parse_manifest_sync` override or default that itself
    /// fails to parse the edited scratch copy.
    ReparseFailed,
    /// The re-parsed manifest did not contain exactly one dependency matching this occurrence's
    /// `(normalized name, version_range.start)`.
    OccurrenceNotUnique,
    /// Phase 2, a1 pre-check: same guard as [`Self::OriginalOversized`], applied to R1 (the
    /// re-parsed EDITED requirement) before its own `compile_bounded_requirement` attempt.
    EditedOversized,
    /// Phase 2, a1: the re-parsed, EDITED requirement has no compiled matcher.
    EditedUncompilable,
    /// Phase 2, b1: the edited requirement's matcher does not accept the fallback itself — the
    /// written edit does not actually express the fallback version.
    EditedExcludesFallback,
    /// Phase 2, d1: the edited (WRITTEN) requirement admits some `available` entry strictly
    /// newer than the fallback — the edit auto-follows back into an in-cooldown version. Unlike
    /// d0, this is NOT a floor comparison: an auto-following range (Cargo's caret, Dart's caret,
    /// PyPI's default `>=X,<next`) has its floor AT the fallback itself by construction (the
    /// edit was rendered FROM `fallback`), so a floor check alone would never catch a range that
    /// also admits something newer above it — exactly the case round-1 critic S1 exists to
    /// reject (spec 076 §1's documented, intentional fail-closed outcome for these ecosystems).
    EditedAdmitsNewer,
}

/// Spec 076 FR-023/FR-024: THE uniform guard deciding whether a cooldown-fallback candidate's
/// default-rendered edit is safe to write.
///
/// Applied identically to spec 075's lockfile-resolved path and spec 076's no-lockfile path —
/// no per-ecosystem override or retry (FR-025).
///
/// Two phases, evaluated in this exact order, first failure wins:
///
/// - **Phase 1**, on `R0 = dep.version_requirement()` (the ORIGINAL declared requirement, no
///   parse needed): a0-pre (issue #1580, CWE-400 defense-in-depth) R0 must not be
///   [`BoundedVersionReq::new`] (i.e. not [`requirement_is_oversized`]) — `compile_bounded_requirement`
///   is never called for an oversized requirement; a0 `compile_bounded_requirement(R0)` must be
///   `Some`; c0 `is_bounded_requirement_up_to_date(R0, fallback)` must be `false` (closes a NuGet bare-floor gap,
///   spec 076 round-1 critic S2); d0 no `available` entry STRICTLY newer than `fallback` may
///   satisfy `bounded_requirement_already_resolves_to(R0, entry)` (anti-downgrade — writing `fallback`
///   must not move resolution backward relative to what R0 already resolves to); fix-cycle #1571:
///   when `fallback` itself does not match R0's compiled matcher, R0 must not directly report
///   `fallback` as `!=`-excluded ([`RequirementMatcher::explicitly_excludes`]) and it must not
///   be the case that some entry strictly newer than `fallback` still matches R0 — otherwise
///   `fallback` sits inside R0's nominal span (or a `||` branch's) but not R0 itself (a `!=`
///   term or a `||`-alternation gap), which the floor comparison alone cannot see
///   ([`FallbackEditRejection::OriginalExcludesFallback`]).
/// - **Re-parse** (only if phase 1 passes, FR-024): `candidate` is applied to a scratch copy of
///   `content`, the copy is re-parsed via `reparse`, and the edited occurrence is located by
///   `(formatter.normalize_package_name(dep.name()), version_range().start)` — NOT `name_range`,
///   since some grammars (NuGet's `Version`-before-`Include` attribute order, Maven's XML
///   element order, Gradle's map notation) put the version before the name, so `name_range`
///   would shift under the edit and silently fail closed. Exactly one match is required; zero
///   or more than one is [`FallbackEditRejection::OccurrenceNotUnique`].
/// - **Phase 2**, on `R1` = the located occurrence's re-parsed requirement: a1-pre, the same
///   [`BoundedVersionReq::new`] guard as a0-pre, applied to R1 before its own
///   `compile_bounded_requirement` attempt; a1 `compile_bounded_requirement(R1)` must be `Some`; b1 R1's
///   matcher must accept `fallback` itself
///   (`Some(true)`) — proving the written edit actually expresses `fallback`, failing closed for
///   an unmodellable/unsatisfiable written requirement; d1 no `available` entry STRICTLY newer
///   than `fallback` may satisfy `bounded_requirement_already_resolves_to(R1, entry)` (the edit must not
///   auto-follow back into a known newer, still-in-cooldown version).
///
/// Yanked entries in `available` are NOT excluded from the d0/d1 scans — conservative,
/// fail-closed: a yanked newer version admitted by the requirement still rejects the fallback.
///
/// # Examples
///
/// ```
/// use deps_core::edit::ManifestEdit;
/// use deps_core::lsp_helpers::{
///     BoundedVersionReq, DiagnosticMessages, DiagnosticPolicy, FallbackEditRejection, FallbackEditVerdict,
///     OsvNaming, PackageNaming, PackageRendering, RequirementMatcher, RequirementResolution,
///     SourcePolicy, fallback_edit_excludes_newer,
/// };
/// use deps_core::position::{Position, Range};
/// use deps_core::{ConcreteVersion, Dependency, PackageName, ParseResult, VersionReq};
///
/// struct ExactMatcher(String);
/// impl RequirementMatcher for ExactMatcher {
///     fn matches(&self, version: &ConcreteVersion) -> Option<bool> {
///         Some(version.as_str() == self.0)
///     }
///     fn strict_prerelease_exclusion(&self) -> bool {
///         false
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
///     fn compile_bounded_requirement(
///         &self,
///         requirement: BoundedVersionReq<'_>,
///     ) -> Option<Box<dyn RequirementMatcher>> {
///         Some(Box::new(ExactMatcher(requirement.as_str().to_string())))
///     }
/// }
/// impl DiagnosticMessages for ExactFormatter {}
/// impl DiagnosticPolicy for ExactFormatter {}
/// impl SourcePolicy for ExactFormatter {}
/// impl OsvNaming for ExactFormatter {}
///
/// struct ExactDependency;
/// impl Dependency for ExactDependency {
///     fn name(&self) -> &PackageName {
///         static NAME: std::sync::LazyLock<PackageName> =
///             std::sync::LazyLock::new(|| PackageName::new("pkg"));
///         &NAME
///     }
///     fn name_range(&self) -> Range {
///         Range::default()
///     }
///     fn version_requirement(&self) -> Option<&VersionReq> {
///         static REQ: std::sync::LazyLock<VersionReq> =
///             std::sync::LazyLock::new(|| VersionReq::new("1.0.0"));
///         Some(&REQ)
///     }
///     fn version_range(&self) -> Option<Range> {
///         Some(Range::new(Position::new(0, 0), Position::new(0, 6)))
///     }
///     fn source(&self) -> deps_core::parser::DependencySource {
///         deps_core::parser::DependencySource::Registry
///     }
///     fn as_any(&self) -> &dyn std::any::Any {
///         self
///     }
/// }
///
/// let formatter = ExactFormatter;
/// let dep = ExactDependency;
/// let candidate = ManifestEdit {
///     range: Range::new(Position::new(0, 0), Position::new(0, 6)),
///     new_text: "1.1.0".to_string(),
/// };
/// let fallback = ConcreteVersion::new("1.1.0");
/// let available = [ConcreteVersion::new("1.1.0"), ConcreteVersion::new("1.0.0")];
/// // A stub `ManifestReparse` that always fails — demonstrates the fail-closed re-parse gate.
/// let reparse = |_content: &str| -> Option<Box<dyn ParseResult>> { None };
///
/// let verdict = fallback_edit_excludes_newer(
///     &formatter,
///     &reparse,
///     "1.0.0",
///     &dep,
///     &candidate,
///     &fallback,
///     &available,
/// );
/// assert_eq!(
///     verdict,
///     FallbackEditVerdict::Rejected(FallbackEditRejection::ReparseFailed)
/// );
/// ```
#[must_use]
pub fn fallback_edit_excludes_newer(
    formatter: &dyn crate::lsp_helpers::EcosystemFormatter,
    reparse: &dyn crate::edit::ManifestReparse,
    content: &str,
    dep: &dyn Dependency,
    candidate: &crate::edit::ManifestEdit,
    fallback: &ConcreteVersion,
    available: &[ConcreteVersion],
) -> FallbackEditVerdict {
    use FallbackEditRejection::{
        CandidateSpanMismatch, EditedAdmitsNewer, EditedExcludesFallback, EditedOversized,
        EditedUncompilable, FallbackUnlisted, OccurrenceNotUnique, OriginalAlreadyUpToDate,
        OriginalExcludesFallback, OriginalOversized, OriginalResolvesPastFallback,
        OriginalUncompilable, ReparseFailed,
    };

    // Precondition (D5, fix-cycle M2): `candidate` must target THIS occurrence's own span.
    if Some(candidate.range) != dep.version_range() {
        return FallbackEditVerdict::Rejected(CandidateSpanMismatch);
    }

    // Phase 1: R0, the ORIGINAL declared requirement — no parse needed.
    let Some(r0) = dep.version_requirement() else {
        return FallbackEditVerdict::Rejected(OriginalUncompilable);
    };
    // a0-pre (issue #1580, CWE-400 defense-in-depth mirroring #1472/#1578): fail closed before
    // `compile_bounded_requirement` ever sees an oversized requirement string.
    let Some(r0) = BoundedVersionReq::new(r0) else {
        return FallbackEditVerdict::Rejected(OriginalOversized);
    };
    let Some(r0_matcher) = formatter.compile_bounded_requirement(r0) else {
        return FallbackEditVerdict::Rejected(OriginalUncompilable);
    };

    // Fix-cycle (issues #1564/#1561, CWE-1284 class): `fallback`'s own position is looked up
    // ONCE here and shared by d0/d1 below — fails closed instead of letting a "no evidence"
    // absence read as "safe" the way `available.iter().take_while(|v| *v != fallback)` did when
    // `fallback` was never found at all (it would scan to the end without ever short-circuiting,
    // silently changing what the scan even means). Ordered after a0 so an ecosystem with no
    // compiled requirement model (GitHub Actions, GitLab CI) logs the more informative
    // `OriginalUncompilable` instead of `FallbackUnlisted` — same final `Rejected` outcome either
    // way, this only affects the `tracing::debug!` reason.
    let Some(fallback_pos) = available.iter().position(|v| v == fallback) else {
        return FallbackEditVerdict::Rejected(FallbackUnlisted);
    };

    if formatter.is_bounded_requirement_up_to_date(r0, fallback) {
        return FallbackEditVerdict::Rejected(OriginalAlreadyUpToDate);
    }
    // d0 (issues #1564/#1561 fix, matching #1565's shipped floor-comparison exactly): a FLOOR
    // comparison over R0's raw admitted-set membership (`compile_bounded_requirement(..).matches`), not
    // "does anything newer also match" and NOT `bounded_requirement_already_resolves_to` — that stricter
    // predicate is deliberately always `false` for a floor-shaped requirement (NuGet's bare
    // `Version="1.0.0"`, see its `bounded_requirement_already_resolves_to` doc), which would make this
    // scan find no floor at all and fail closed on every floor-type ecosystem. `available` is
    // newest-first, so the requirement's own floor — the OLDEST entry it still admits — sits at
    // the LARGEST matching index. Accept iff that floor is at or after `fallback`'s own index
    // (`fallback` is not older than what R0, left unedited, already resolves to); `None`
    // (nothing evidences the floor at all, e.g. an unlisted declared pin) fails closed the same
    // as a floor strictly newer than `fallback`.
    let r0_floor = available
        .iter()
        .rposition(|v| r0_matcher.matches(v) == Some(true));
    if r0_floor.is_none_or(|floor| floor < fallback_pos) {
        return FallbackEditVerdict::Rejected(OriginalResolvesPastFallback);
    }
    // Fix-cycle (#1571): R0 admitting `fallback` inside its nominal span yet not `fallback`
    // itself — a `!=`-style exclusion (PyPI/Composer/Bundler) or a `||`-alternation gap
    // (Composer) punches a hole rather than shifting the floor, so the floor comparison above
    // alone cannot see it. Two independent signals, either one rejects. `r0_floor ==
    // Some(fallback_pos)` (code-review perf finding) means the floor scan above already proved
    // `fallback` matches R0 — the floor is BY DEFINITION a matching index, so no need to call
    // `matches` on `fallback` again for that common case.
    let fallback_matches_r0 =
        r0_floor == Some(fallback_pos) || r0_matcher.matches(fallback) == Some(true);
    if !fallback_matches_r0 {
        // (i) Intensional: the matcher itself names `fallback` as explicitly banned (critic
        // fix-cycle S1 — `r0_matcher.explicitly_excludes` is the only way to tell a `!=` hole
        // apart from a legitimate ceiling-exceeding fallback when NO listed `available` entry
        // happens to evidence the hole either, e.g. `>=1.0,!=1.5.0,<2.0` with `fallback` ==
        // 1.5.0 and `available` = [2.0.0, 1.5.0, 1.0.0] — 2.0.0 fails `matches` too (it's past
        // the `<2.0` ceiling), so (ii) below is vacuous and only this direct check catches it).
        if r0_matcher.explicitly_excludes(fallback) {
            return FallbackEditVerdict::Rejected(OriginalExcludesFallback);
        }
        // (ii) Extensional, structural fallback net: some LISTED entry strictly newer than
        // `fallback` still matches R0 (e.g. `r0_floor` (4) >= `fallback_pos` (2) passed above
        // even though R0 explicitly excludes `fallback`, or a `||`-alternation gap like
        // `^1.0 || ^3.0` with `fallback` = 2.5.0). A legitimate out-of-range fallback (e.g.
        // Cargo's `^1.0` with fallback 2.5.0) has no R0-matching entry newer than it at all —
        // FR-025's intentional ceiling-exceeding acceptance — so this never misfires on that
        // case.
        #[allow(clippy::indexing_slicing)]
        let newer_than_fallback = &available[..fallback_pos];
        if newer_than_fallback
            .iter()
            .any(|v| r0_matcher.matches(v) == Some(true))
        {
            return FallbackEditVerdict::Rejected(OriginalExcludesFallback);
        }
    }

    // Re-parse (FR-024): apply the candidate edit to a scratch copy and re-parse it.
    let edited_content = crate::edit::apply_edits(content, std::slice::from_ref(candidate));
    let Some(parsed) = reparse.reparse(&edited_content) else {
        return FallbackEditVerdict::Rejected(ReparseFailed);
    };

    // Locate the edited occurrence by (normalized name, version_range().start) — invariant
    // under an edit that only changes text at or after it, unlike `name_range` (round-4 critic
    // M3: NuGet/Maven/Gradle grammars can put the version before the name).
    let key = formatter.normalize_package_name(dep.name());
    let orig_start = dep.version_range().map(|r| r.start);
    let mut candidates = parsed.dependencies().into_iter().filter(|edited_dep| {
        formatter.normalize_package_name(edited_dep.name()) == key
            && edited_dep.version_range().map(|r| r.start) == orig_start
    });
    let Some(edited_dep) = candidates.next() else {
        return FallbackEditVerdict::Rejected(OccurrenceNotUnique);
    };
    if candidates.next().is_some() {
        return FallbackEditVerdict::Rejected(OccurrenceNotUnique);
    }

    // Phase 2: R1, the re-parsed EDITED requirement.
    let Some(r1) = edited_dep.version_requirement() else {
        return FallbackEditVerdict::Rejected(EditedUncompilable);
    };
    // a1-pre: same guard as a0-pre, applied to R1.
    let Some(r1) = BoundedVersionReq::new(r1) else {
        return FallbackEditVerdict::Rejected(EditedOversized);
    };
    let Some(matcher) = formatter.compile_bounded_requirement(r1) else {
        return FallbackEditVerdict::Rejected(EditedUncompilable);
    };
    if matcher.matches(fallback) != Some(true) {
        return FallbackEditVerdict::Rejected(EditedExcludesFallback);
    }
    // d1 (round-1 critic S1) is deliberately NOT the d0 floor comparison: an auto-following
    // range's floor sits at `fallback` itself by construction (the edit was rendered FROM
    // `fallback`), so a floor check alone would never see that the SAME range also admits an
    // entry strictly newer — the auto-follow case this check exists to catch. `fallback_pos` is
    // `available.iter().position(..)`'s own result, so it is always `<= available.len()` and the
    // slice below (every entry strictly newer than `fallback`, since `available` is newest-first)
    // never panics — exact, not the fragile `take_while(|v| *v != fallback)` this replaced.
    #[allow(clippy::indexing_slicing)]
    let strictly_newer = &available[..fallback_pos];
    if strictly_newer
        .iter()
        .any(|v| formatter.bounded_requirement_already_resolves_to(r1, v))
    {
        return FallbackEditVerdict::Rejected(EditedAdmitsNewer);
    }

    FallbackEditVerdict::Writable
}

/// Registry version data for one package, fetched together in a single round trip.
///
/// `latest` and `available` are deliberately asymmetric — this is load-bearing, not an
/// oversight:
/// - `latest` comes from this ecosystem's own `Registry::select_latest_matching(.., "*")`
///   pick, which excludes yanked (and, for semver/node-semver `*`, prerelease) versions —
///   the same value `get_latest_matching` returned before this type existed.
/// - `available` is the **unfiltered** `get_versions` output: every published version,
///   newest-first, yanked and prerelease entries included.
///
/// The unsatisfiable-requirement check (see `crate::lsp_helpers::requirement_is_unsatisfiable`)
/// scans `available` and deliberately does not filter it: a requirement that only matches a
/// yanked or prerelease version is still satisfied, so filtering `available` the same way
/// `latest` is filtered would produce false "no published version satisfies" warnings.
///
/// `yanked` is the subset of `available` (same version-string encoding) that the registry
/// reported as yanked/deprecated, paired with each entry's [`RemovalStatus`]. It exists
/// because `Registry::get_latest_matching` — the call that used to populate this cache —
/// filters yanked entries out by contract on every current registry implementation, so a
/// per-version yanked flag threaded through *that* call would always read `false` (see
/// #233). `available` now comes from the unfiltered `get_versions` instead, which does
/// observe yanked entries, so `yanked` is derived from that same fetch rather than
/// discarded.
///
/// The status rides alongside each version (rather than a bare membership list) so
/// [`crate::lsp_helpers::generate_diagnostics_from_cache`]'s #247 "requirement satisfiable
/// only by a yanked version" check can gate its own package-level-deprecation suppression
/// on `AdvisoryDeprecated` specifically, never on a genuine `Yanked` finding — mirroring
/// [`VersionData::outcomes`]'s D5 gate for the #263 in-use-version check (see #437).
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageVersions {
    /// Latest usable version for this package.
    pub latest: ConcreteVersion,
    /// Every published version, newest-first, unfiltered.
    pub available: Arc<[ConcreteVersion]>,
    /// Subset of `available` reported as yanked/deprecated by the registry, each paired
    /// with its [`RemovalStatus`].
    pub yanked: Arc<[(ConcreteVersion, RemovalStatus)]>,
    /// When `latest` was published, if the registry exposes it. `None` when
    /// the ecosystem doesn't wire [`crate::Version::published_at`] or the fetch
    /// never ran.
    ///
    /// Deliberately a field on this single per-package struct rather than a
    /// second parallel map keyed alongside `latest` — the earlier two-map
    /// design (issue #227 critique C3) let `latest` and its age drift apart
    /// silently whenever one map was updated (e.g. lockfile-resolved
    /// overwrite) without the other. Bundling them here makes that
    /// desync impossible: whoever sets `latest` sets `published_at` too.
    pub published_at: Option<crate::freshness::PublishTime>,
    /// Set when a version was excluded from being [`Self::latest`] solely because of an
    /// active GOSSIP cooldown finding whose version was strictly newer than the dependency's
    /// already-in-use version (`deps-cli` spec 074, FR-003/FR-005's floor-protected filter —
    /// round 1 correction: there is no local [`CooldownWindow`]-based
    /// exclusion this unions with, the freshness cooldown window only ever rewords a
    /// downstream diagnostic message).
    /// `None` in the common case (GOSSIP disabled, no matching finding, or no active
    /// cooldown), and in four further no-op cases where nothing was actually held back: the
    /// protect floor fully neutralized the exclusion because the flagged version was itself
    /// already in use and still the best available (C1a); no in-use version could be
    /// resolved at all, so no floor could be constructed and GOSSIP deliberately excludes
    /// nothing this fetch (C1b — the common case for a range requirement with no lockfile);
    /// a floor exists but the ecosystem's own selection rules reject every remaining
    /// candidate above it (S1); or a floor exists and a filtered pick is found, but that
    /// pick's original (pre-filter) position is older than the floor itself — the floor
    /// version survived filtering yet was rejected by the ecosystem's own selection rules
    /// (e.g. an in-use prerelease/yanked version), leaving only an even-older release to be
    /// picked, which would be a downgrade below the floor (S4). In all four cases the
    /// unfiltered pick is reused instead. Purely an in-process outcome-reporting field: no
    /// wire/schema format carries it.
    pub gossip_excluded_version: Option<ConcreteVersion>,
    /// The newest cooldown-cleared, ecosystem-safe, floor-protected candidate found for this
    /// dependency when `latest` may be cooldown-blocked (`deps-cli update`'s fallback, spec
    /// 075 FR-001/FR-002). Computed unconditionally whenever freshness is enabled, regardless
    /// of whether `latest` itself is currently blocked — see [`cooldown_disposition`] for the
    /// read-time decision of whether it is actually needed (spec 075 NFR-002). `None` when
    /// freshness is disabled, no lockfile-resolved in-use version exists to floor the search
    /// (spec 075 OQ1), or no candidate passed every guard.
    pub cooldown_fallback: Option<CooldownFallback>,
}

impl PackageVersions {
    /// Constructs a `PackageVersions` from its two required fields, with [`Self::yanked`] and
    /// [`Self::published_at`] left empty/`None` — chain [`Self::with_yanked`] and/or
    /// [`Self::with_published_at`] to attach them.
    ///
    /// Needed because [`Self`] is `#[non_exhaustive]`: a struct literal only works inside
    /// this crate, so every other crate (including test code) must go through this
    /// constructor instead.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::{ConcreteVersion, PackageVersions};
    /// use std::sync::Arc;
    ///
    /// let versions = PackageVersions::new(
    ///     ConcreteVersion::new("2.0.0"),
    ///     Arc::from(vec![ConcreteVersion::new("2.0.0"), ConcreteVersion::new("1.0.0")]),
    /// );
    /// assert_eq!(versions.latest, "2.0.0");
    /// assert_eq!(versions.available.len(), 2);
    /// assert!(versions.yanked.is_empty());
    /// ```
    #[must_use]
    pub fn new(latest: ConcreteVersion, available: Arc<[ConcreteVersion]>) -> Self {
        Self {
            latest,
            available,
            yanked: Arc::from(Vec::new()),
            published_at: None,
            gossip_excluded_version: None,
            cooldown_fallback: None,
        }
    }

    /// Attaches the registry's yanked/deprecated-version findings. See [`Self::yanked`].
    #[must_use]
    pub fn with_yanked(mut self, yanked: Arc<[(ConcreteVersion, RemovalStatus)]>) -> Self {
        self.yanked = yanked;
        self
    }

    /// Attaches when `latest` was published. See [`Self::published_at`].
    #[must_use]
    pub const fn with_published_at(mut self, published_at: crate::freshness::PublishTime) -> Self {
        self.published_at = Some(published_at);
        self
    }

    /// Attaches the version a GOSSIP cooldown finding excluded from being [`Self::latest`].
    /// See [`Self::gossip_excluded_version`].
    #[must_use]
    pub fn with_gossip_excluded_version(mut self, excluded: ConcreteVersion) -> Self {
        self.gossip_excluded_version = Some(excluded);
        self
    }

    /// Attaches the computed cooldown-fallback candidate. See [`Self::cooldown_fallback`].
    #[must_use]
    pub fn with_cooldown_fallback(mut self, fallback: CooldownFallback) -> Self {
        self.cooldown_fallback = Some(fallback);
        self
    }

    /// Builds a `PackageVersions` from only the "latest" version string, with `available`
    /// populated as the single-element list `[latest]`.
    ///
    /// **Test-only in intent.** The one-element `available` this produces is a real, if
    /// small, version list — it is not "empty/unknown", so `requirement_is_unsatisfiable`
    /// will evaluate a requirement against it. Do **not** use this for a lock-file-only
    /// population path that has no real version list to offer (use
    /// [`latest_without_list`](Self::latest_without_list) there instead, which leaves
    /// `available` genuinely empty) — that exact substitution is the false-positive N5 was
    /// written to prevent: it would let the unsatisfiable-requirement check produce a
    /// verdict against a fabricated one-entry list before any registry fetch has run. Real
    /// registry fetches always populate `available` from the full `get_versions` result
    /// instead of using either constructor.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::{ConcreteVersion, PackageVersions};
    ///
    /// let versions = PackageVersions::latest_only("1.0.214");
    /// assert_eq!(versions.latest, "1.0.214");
    /// assert_eq!(&*versions.available, &[ConcreteVersion::new("1.0.214")]);
    /// ```
    pub fn latest_only(latest: impl Into<ConcreteVersion>) -> Self {
        let latest = latest.into();
        let available = Arc::from(vec![latest.clone()]);
        Self {
            latest,
            available,
            yanked: Arc::from(Vec::new()),
            published_at: None,
            gossip_excluded_version: None,
            cooldown_fallback: None,
        }
    }

    /// Builds a `PackageVersions` with no version list — used where only the "latest" value
    /// is known and probing further would be misleading, notably the lock-file population
    /// path (`crates/deps-lsp/src/document/lifecycle.rs`), which must not populate a
    /// plausible-looking one-element `available` list before any registry fetch has run: the
    /// unsatisfiable-requirement check treats an empty `available` as "still loading, skip".
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::PackageVersions;
    ///
    /// let versions = PackageVersions::latest_without_list("1.0.195");
    /// assert_eq!(versions.latest, "1.0.195");
    /// assert!(versions.available.is_empty());
    /// ```
    pub fn latest_without_list(latest: impl Into<ConcreteVersion>) -> Self {
        Self {
            latest: latest.into(),
            available: Arc::from(Vec::new()),
            yanked: Arc::from(Vec::new()),
            published_at: None,
            gossip_excluded_version: None,
            cooldown_fallback: None,
        }
    }
}

/// Everything the lifecycle fetch learned about one package, keyed by its normalized name.
///
/// All three channels can hold simultaneously for the same package — this is load-bearing,
/// not an incidental shape. The D5 status gate in
/// [`generate_diagnostics_from_cache`] reads the [`Self::deprecation`] and [`Self::yanked`]
/// entries for the same normalized name together and compares their [`RemovalStatus`], and on
/// the didChange path a surviving deprecation can coexist with a later fetch failure. A single
/// enum variant per package could not express that overlap.
#[non_exhaustive]
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DependencyOutcome {
    /// The version found yanked (the in-use version, or `latest` when only `latest` itself is
    /// yanked), paired with its [`RemovalStatus`]. See [`VersionData::outcomes`]'s prior
    /// semantics (#233/#263).
    pub yanked: Option<(ConcreteVersion, RemovalStatus)>,
    /// Package-level deprecation finding (#205). See [`Deprecation`].
    pub deprecation: Option<Deprecation>,
    /// Registry fetch errored, timed out, or was never attempted (#267). See [`FetchFailure`].
    pub fetch_failure: Option<FetchFailure>,
    /// The registry fetch succeeded (no [`Self::fetch_failure`]) but produced zero
    /// comparable versions — e.g. a real GitHub repository whose only tags don't parse
    /// as full `major.minor.patch` semver (`dtolnay/rust-toolchain`'s sole tag `v1`,
    /// issue #550). Distinct from both an absent [`DependencyOutcome`] entry ("never
    /// fetched") and [`Self::fetch_failure`] ("couldn't be asked"): this package
    /// demonstrably exists, so [R5](crate::lsp_helpers::generate_diagnostics_from_cache)
    /// must not claim it is unknown.
    pub no_comparable_versions: bool,
}

impl DependencyOutcome {
    /// True when none of the four channels are set.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.yanked.is_none()
            && self.deprecation.is_none()
            && self.fetch_failure.is_none()
            && !self.no_comparable_versions
    }
}

/// Normalized-package-name -> [`DependencyOutcome`] map.
///
/// A newtype rather than a bare `HashMap` so the empty-entry pruning invariant (an entry is
/// removed once all three of its channels are cleared) lives in one place, and so test
/// fixtures get chainable `with_*` constructors instead of building three ad-hoc `HashMap`s.
/// Keyed by plain normalized name — unlike [`crate::osv::VulnerabilityMap`], which is keyed by
/// [`crate::osv::VulnKey`] to disambiguate multiple occurrences of one name.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DependencyOutcomes(HashMap<String, DependencyOutcome>);

impl DependencyOutcomes {
    /// Creates an empty map.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Looks up the full outcome recorded for `name`.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&DependencyOutcome> {
        self.0.get(name)
    }

    /// Looks up the yanked-version finding for `name`.
    #[must_use]
    pub fn yanked(&self, name: &str) -> Option<&(ConcreteVersion, RemovalStatus)> {
        self.0.get(name)?.yanked.as_ref()
    }

    /// Looks up the package-level deprecation finding for `name`.
    #[must_use]
    pub fn deprecation(&self, name: &str) -> Option<&Deprecation> {
        self.0.get(name)?.deprecation.as_ref()
    }

    /// Looks up the fetch-failure finding for `name`.
    #[must_use]
    pub fn fetch_failure(&self, name: &str) -> Option<&FetchFailure> {
        self.0.get(name)?.fetch_failure.as_ref()
    }

    /// True when the registry fetch for `name` succeeded but produced zero comparable
    /// versions (#550). See [`DependencyOutcome::no_comparable_versions`].
    #[must_use]
    pub fn no_comparable_versions(&self, name: &str) -> bool {
        self.0.get(name).is_some_and(|o| o.no_comparable_versions)
    }

    /// Records a yanked-version finding for `name`, creating the entry if absent.
    pub fn set_yanked(&mut self, name: String, yanked: (ConcreteVersion, RemovalStatus)) {
        self.0.entry(name).or_default().yanked = Some(yanked);
    }

    /// Records a package-level deprecation finding for `name`, creating the entry if absent.
    pub fn set_deprecation(&mut self, name: String, deprecation: Deprecation) {
        self.0.entry(name).or_default().deprecation = Some(deprecation);
    }

    /// Records a fetch-failure finding for `name`, creating the entry if absent.
    pub fn set_fetch_failure(&mut self, name: String, failure: FetchFailure) {
        self.0.entry(name).or_default().fetch_failure = Some(failure);
    }

    /// Records a fetch-failure finding for `name` only if one is not already recorded,
    /// creating the entry if absent.
    pub fn set_fetch_failure_if_absent(&mut self, name: String, failure: FetchFailure) {
        self.0
            .entry(name)
            .or_default()
            .fetch_failure
            .get_or_insert(failure);
    }

    /// Records that `name`'s registry fetch succeeded but produced zero comparable
    /// versions (#550), creating the entry if absent.
    pub fn set_no_comparable_versions(&mut self, name: String) {
        self.0.entry(name).or_default().no_comparable_versions = true;
    }

    /// Clears the no-comparable-versions channel for `name`, pruning the entry if it
    /// becomes empty.
    pub fn clear_no_comparable_versions(&mut self, name: &str) {
        if let Some(entry) = self.0.get_mut(name) {
            entry.no_comparable_versions = false;
            self.prune(name);
        }
    }

    /// Clears the yanked-version channel for `name`, pruning the entry if it becomes empty.
    pub fn clear_yanked(&mut self, name: &str) {
        if let Some(entry) = self.0.get_mut(name) {
            entry.yanked = None;
            self.prune(name);
        }
    }

    /// Clears the deprecation channel for `name`, pruning the entry if it becomes empty.
    pub fn clear_deprecation(&mut self, name: &str) {
        if let Some(entry) = self.0.get_mut(name) {
            entry.deprecation = None;
            self.prune(name);
        }
    }

    /// Clears the fetch-failure channel for `name`, pruning the entry if it becomes empty.
    pub fn clear_fetch_failure(&mut self, name: &str) {
        if let Some(entry) = self.0.get_mut(name) {
            entry.fetch_failure = None;
            self.prune(name);
        }
    }

    /// Removes the whole entry for `name`, regardless of which channels are set.
    pub fn remove(&mut self, name: &str) {
        self.0.remove(name);
    }

    /// Clears the fetch-failure channel for every entry, pruning any that become empty.
    ///
    /// Used when a forced re-fetch (e.g. a live-reloaded registry-routing setting, deps-lsp
    /// issue #592) makes every previously recorded fetch-failure finding untrustworthy: the
    /// routing itself changed, so a failure recorded under the old routing must not survive
    /// to be merged with results fetched under the new one.
    pub fn clear_all_fetch_failures(&mut self) {
        let names: Vec<String> = self.0.keys().cloned().collect();
        for name in names {
            self.clear_fetch_failure(&name);
        }
    }

    fn prune(&mut self, name: &str) {
        if self.0.get(name).is_some_and(DependencyOutcome::is_empty) {
            self.0.remove(name);
        }
    }

    /// Number of entries currently stored.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// True when no entries are stored.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Number of entries with a yanked-version finding, for logging/`Debug`.
    #[must_use]
    pub fn yanked_count(&self) -> usize {
        self.0.values().filter(|o| o.yanked.is_some()).count()
    }

    /// Number of entries with a deprecation finding, for logging/`Debug`.
    #[must_use]
    pub fn deprecation_count(&self) -> usize {
        self.0.values().filter(|o| o.deprecation.is_some()).count()
    }

    /// Number of entries with a fetch-failure finding, for logging/`Debug`.
    #[must_use]
    pub fn fetch_failure_count(&self) -> usize {
        self.0
            .values()
            .filter(|o| o.fetch_failure.is_some())
            .count()
    }

    /// Chainable builder recording a yanked-version finding. Test/fixture ergonomics.
    #[must_use]
    pub fn with_yanked(
        mut self,
        name: impl Into<String>,
        yanked: (ConcreteVersion, RemovalStatus),
    ) -> Self {
        self.set_yanked(name.into(), yanked);
        self
    }

    /// Chainable builder recording a package-level deprecation finding. Test/fixture
    /// ergonomics.
    #[must_use]
    pub fn with_deprecation(mut self, name: impl Into<String>, deprecation: Deprecation) -> Self {
        self.set_deprecation(name.into(), deprecation);
        self
    }

    /// Chainable builder recording a fetch-failure finding. Test/fixture ergonomics.
    #[must_use]
    pub fn with_fetch_failure(mut self, name: impl Into<String>, failure: FetchFailure) -> Self {
        self.set_fetch_failure(name.into(), failure);
        self
    }

    /// Chainable builder recording a no-comparable-versions finding (#550). Test/fixture
    /// ergonomics.
    #[must_use]
    pub fn with_no_comparable_versions(mut self, name: impl Into<String>) -> Self {
        self.set_no_comparable_versions(name.into());
        self
    }
}

/// Bundles the two per-package version maps (`cached`, `resolved`) that LSP handlers pass
/// together everywhere.
///
/// Grouping them prevents accidentally swapping the two map arguments at a call site, since
/// the compiler can no longer typecheck them positionally.
///
/// # Examples
///
/// ```
/// use deps_core::{ConcreteVersion, PackageName, PackageVersions, VersionData};
/// use std::collections::HashMap;
///
/// let mut cached = HashMap::new();
/// cached.insert(PackageName::new("serde"), PackageVersions::latest_only("1.0.214"));
///
/// let mut resolved = HashMap::new();
/// resolved.insert(PackageName::new("serde"), ConcreteVersion::new("1.0.200"));
///
/// let versions = VersionData::new(&cached, &resolved);
///
/// assert_eq!(versions.cached.get("serde").map(|v| v.latest.as_str()), Some("1.0.214"));
/// assert_eq!(versions.resolved.get("serde").map(ConcreteVersion::as_str), Some("1.0.200"));
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, Copy)]
pub struct VersionData<'a> {
    /// Latest known versions and full version lists from the registry, keyed by package name.
    pub cached: &'a HashMap<PackageName, PackageVersions>,
    /// Versions actually resolved in the lock file, keyed by package name.
    pub resolved: &'a HashMap<PackageName, ConcreteVersion>,
    /// Every lock-file-resolved version for a package name, when more than one is retained
    /// (issue #649) — additive alongside [`Self::resolved`], which stays the single
    /// collapsed value for the common case. `None` by default (most call sites have no such
    /// map); [`crate::lsp_helpers::resolve_in_use_version`] and [`crate::osv::vulnerability_keys`]
    /// consult it to disambiguate two manifest occurrences of one resolved name (e.g. a
    /// Cargo `package = "..."` rename pinning an older major) by each occurrence's own
    /// `version_requirement()`, falling back to [`Self::resolved`] when a name has at most
    /// one candidate.
    pub resolved_version_candidates: Option<&'a HashMap<PackageName, Vec<ConcreteVersion>>>,
    /// OSV scan results, keyed by normalized package name. `None` when no
    /// scan has run yet (e.g. the feature is disabled) — distinct from an
    /// empty map, which would mean "scanned, nothing found".
    pub vulnerabilities: Option<&'a VulnerabilityMap>,
    /// Yanked, deprecation, and fetch-failure findings from the most recent lifecycle fetch,
    /// keyed by normalized package name — see [`DependencyOutcome`] for what each channel
    /// means and why they must stay readable together off one lookup (D5 in
    /// [`generate_diagnostics_from_cache`], #233/#263/#205/#267). `None` when no fetch has run
    /// yet — distinct from an empty map, which would mean "checked, nothing found".
    pub outcomes: Option<&'a DependencyOutcomes>,
    /// This document's ecosystem, when the caller has one to give. `None` in
    /// most test fixtures and a handful of ecosystem-crate self-tests that
    /// predate this field.
    ///
    /// Enables two occurrence-aware refinements added for #394 (duplicate
    /// dependency names no longer collapsing into one shared finding):
    /// [`generate_diagnostics_from_cache`] only emits a yanked-version
    /// diagnostic on the occurrence whose own in-use version actually
    /// matches the recorded finding (S1), and the vulnerability lookups in
    /// `generate_diagnostics_from_cache`, [`generate_hover`], and
    /// `generate_code_actions` prefer a version-qualified
    /// [`crate::osv::VulnerabilityMap`] key over the plain name when more
    /// than one occurrence of a name has a distinct in-use version (S2).
    /// When `None`, both fall back to their pre-#394 name-only behavior.
    pub ecosystem: Option<EcosystemId>,
    /// The current [`NetworkMode`](crate::NetworkMode) (issue #483). When
    /// [`NetworkMode::Offline`](crate::NetworkMode::Offline), [`generate_hover`] appends a
    /// footer stating that version *and vulnerability* data were not checked — deliberately
    /// more specific than a bare "showing cached data" notice, since `hover.rs`'s
    /// `Some(ScanOutcome::Skipped(_)) | None` arm renders nothing for an offline OSV skip,
    /// which would otherwise look identical to a scanned-and-clean dependency.
    pub network: crate::NetworkMode,
    /// The deps.dev client to fetch a supply-chain trust signal through
    /// (spec 037), when the caller wants hover to attempt one. `None` by
    /// default and left `None` by every surface but `handlers/hover.rs`
    /// (deps-lsp) — diagnostics, code actions, inlay hints, and code lenses
    /// never set this, which is what makes FR-010's hover-only scope
    /// structural rather than convention: those surfaces cannot reach
    /// deps.dev because they are never handed a client. `&'a Arc<..>`, not
    /// `&'a DepsDevClient`, so [`generate_hover`] can clone the `Arc` into a
    /// detached background task.
    pub trust: Option<&'a Arc<DepsDevClient>>,
    /// Background-pre-fetched license data for ecosystems `deps_dev_system` doesn't
    /// cover and whose hot-path registry response carries no license field — Dart,
    /// Swift, Gradle, Deno (issue #660, spec 010 plan §1 tier 3), keyed by raw
    /// (unnormalized) package name. `None` by default. Populated from `DocumentState`'s
    /// per-document pre-fetch cache (`document::osv_scan::run_license_prefetch` on
    /// document open/change — mirrors [`Self::vulnerabilities`]'s "populated by a
    /// background task, read synchronously here" shape) by `handlers/hover.rs` (deps-lsp)
    /// for hover, and by `handlers/diagnostics.rs`'s `textDocument/diagnostic` pull path
    /// for [`generate_diagnostics_from_cache`]'s license-policy rule (issue #661) — see
    /// [`Self::license_policy`].
    ///
    /// **What version this actually reflects is per-ecosystem, not uniformly the
    /// resolved version** (critic S1 — corrects a previous blanket claim here that it
    /// "only ever covers the resolved version"): Gradle's Maven Central POM fetch and
    /// Deno's JSR per-version API are genuinely fetched at the dependency's resolved/
    /// in-use version. Dart's pub.dev `/score` endpoint is per-*package*, not
    /// per-version — it reflects pana's detection on whatever pub.dev most recently
    /// scored, unrelated to which version is resolved. Swift's GitHub
    /// `GET /repos/{owner}/{repo}` reflects the repository's default branch, not the
    /// resolved version's tag. Every source here is still a background pre-fetch gated
    /// on a version having been resolved at all (no in-use version means nothing to
    /// look up), but only Gradle/Deno are actually version-*specific* in what they
    /// return.
    pub license_prefetch: Option<&'a HashMap<PackageName, Vec<String>>>,
    /// How [`Self::license_prefetch`]'s (and, for a resolved-version match, the
    /// registry-declared) license strings are sourced (issue #688), consulted by
    /// [`generate_hover`] for the "(detected)" qualifier and by
    /// [`generate_diagnostics_from_cache`]'s license-policy rule to decide whether
    /// [`crate::licenses::resolve_license_entries`] must normalize free text before
    /// evaluation. `None` in most test fixtures and any handler that doesn't go through
    /// [`crate::Ecosystem::generate_hover`]/[`crate::Ecosystem::generate_diagnostics`]'s
    /// default implementation, which is what actually attaches this field via
    /// `self.license_source()` — falls back to
    /// [`LicenseSource::RegistryDeclaredSpdx`] (`Default`) wherever consumed.
    pub license_source: Option<LicenseSource>,
    /// SPDX allow-list/deny-list license policy (issue #661, spec 010 Phase 2), when the
    /// caller wants diagnostics evaluated against one. `None` by default.
    ///
    /// Unlike [`Self::trust`], this is **not** hover-only-scoped: `deps-lsp`'s
    /// `handlers/diagnostics.rs::generate_diagnostics_internal` attaches the currently
    /// configured policy (cached on `ServerState`, kept live-updated by
    /// `Backend::initialize`/`did_change_configuration`) unconditionally, so every
    /// diagnostics-generation call site — the `textDocument/diagnostic` pull path *and*
    /// every push-path background refresh (fetch-completion, watched-config reparse,
    /// lock-file change) — evaluates the same policy. An earlier revision scoped this
    /// field to the pull path only, following `Self::trust`'s hover-only precedent; that
    /// was a false analogy (issue #660/#661 critic C1) — `trust` is safe hover-only
    /// because hover has exactly one producer per request, but diagnostics has multiple
    /// producers all replacing the same client-visible `publish_diagnostics` set, so a
    /// caller-scoped policy meant the license diagnostic flickered in and out on every
    /// edit and was invisible to push-only clients.
    /// [`generate_diagnostics_from_cache`]'s license-policy rule reads this alongside
    /// [`Self::license_prefetch`] — so today it only actually fires for tier-3 ecosystems
    /// (Dart/Swift/Deno; Gradle is explicitly excluded, see that rule's doc comment), the
    /// only ones `license_prefetch` covers; this field and the rule are otherwise
    /// ecosystem-agnostic and need no change as `license_prefetch`'s coverage widens.
    pub license_policy: Option<&'a LicensePolicy>,
    /// Background-pre-fetched typosquat-suspect signal per declared dependency (issue
    /// #1437, spec 071), keyed by raw (unnormalized) package name — mirrors
    /// [`Self::license_prefetch`]'s exact shape and rationale (NFR-002: this must never be
    /// an inline `.await` on the diagnostics-generation path, so it is resolved ahead of
    /// time by a document-lifecycle background task,
    /// `deps-lsp::document::typosquat::run_typosquat_prefetch`, and merely read
    /// synchronously here — see that function's doc). Consumed directly inside
    /// [`generate_diagnostics_from_cache`] itself (not gated behind
    /// `Ecosystem::generate_diagnostics`'s default impl), the same way
    /// [`Self::license_prefetch`] is, so every ecosystem's `generate_diagnostics`
    /// override — not just the shared default — picks up the diagnostic automatically
    /// (issue #1437 security-review finding: an override that calls
    /// [`generate_diagnostics_from_cache`] directly, as `deps-npm`'s catalog-diagnostics
    /// override does, must never be able to silently bypass this). `None` when the feature
    /// is disabled, the ecosystem isn't deps.dev-covered, offline, or no dependency in the
    /// document cleared the ratio gate.
    pub typosquat_prefetch: Option<&'a HashMap<PackageName, TyposquatSignal>>,
    /// Background-pre-fetched deps.dev GOSSIP cooldown/low-usage findings per declared
    /// dependency (issue #1456, spec 072), keyed by raw (unnormalized) package name —
    /// mirrors [`Self::typosquat_prefetch`]'s exact shape and rationale: populated by
    /// `deps-lsp::document::gossip_prefetch`, via `DocumentState::signals.gossip_findings`, and
    /// merely read synchronously here — never fetched inline on the hover/diagnostics-
    /// generation path itself.
    ///
    /// A lookup hit is only trustworthy for the version it was resolved against
    /// (spec 072 FR-008) — the entry's own [`crate::GossipFindings::version`] field must
    /// be compared against the version actually being displayed at each call site (hover's
    /// `latest_line`, diagnostics' `package_versions.latest`) before use; a mismatch is
    /// treated as a cache miss and falls back to [`local_cooldown_precedence`]. `None`
    /// when the feature is disabled, offline, the ecosystem isn't deps.dev-covered, or no
    /// dependency in the document has a prefetch result yet.
    pub gossip_prefetch: Option<&'a HashMap<PackageName, GossipFindings>>,
    /// The deps.dev client to fetch hover's live GOSSIP low-usage signal through (issue
    /// #1456, spec 072 FR-005/FR-009), when the caller wants hover to attempt one. `None`
    /// by default, mirroring [`Self::trust`]'s exact "presence is the gate" shape (FR-010's
    /// structural pattern) — set only by `handlers/hover.rs` (deps-lsp) when
    /// `GossipConfig.enabled` is set and not offline. Deliberately a **separate** field
    /// from [`Self::trust`], not reused: `SupplyChainConfig.enabled` (opt-out, default
    /// `true`) and `GossipConfig.enabled` (opt-in, default `false`) are independently
    /// switchable — conflating the two fields would let disabling supply-chain trust
    /// signals silently disable GOSSIP's low-usage fetch too, or vice versa. `&'a Arc<..>`,
    /// not `&'a DepsDevClient`, for the same "clone into a detached background task"
    /// reason [`Self::trust`]'s doc gives.
    pub gossip_client: Option<&'a Arc<DepsDevClient>>,
    /// Phase B's per-key "latest" check result (issue #1517), keyed the same way as
    /// [`Self::vulnerabilities`] — see [`crate::osv::LatestStatusMap`]. `None` means OSV
    /// checking is disabled or offline for this scan entirely, distinct from `Some(map)` with a
    /// missing/`Unverified` entry for one dependency (which [`latest_verdict`] treats as
    /// fail-closed, not "not applicable"). Every renderer that surfaces a dependency's `latest`
    /// as an upgrade recommendation (hover, diagnostics, code actions, code lens, inlay hints,
    /// completion) must consult [`latest_verdict`] with this field before treating that `latest`
    /// as safe.
    pub latest_status: Option<&'a LatestStatusMap>,
    /// Phase B's per-(dependency, candidate-version) OSV check result (#1524) — see
    /// [`crate::osv::CandidateStatusMap`]. `None` means OSV checking is disabled or offline for
    /// this scan entirely, mirroring [`Self::latest_status`]'s identical distinction. A
    /// candidate-offering surface (code actions' "update to X" list, completion's version
    /// items) must consult [`candidate_verdict`] with this field for every version it is about
    /// to offer, not only the one [`Self::latest_status`] already covers.
    pub candidate_status: Option<&'a CandidateStatusMap>,
}

impl<'a> VersionData<'a> {
    /// Creates a new `VersionData` from the cached and resolved version maps.
    ///
    /// `vulnerabilities` starts `None`; chain [`Self::with_vulnerabilities`]
    /// to attach a scan result.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::VersionData;
    /// use std::collections::HashMap;
    ///
    /// let cached = HashMap::new();
    /// let resolved = HashMap::new();
    /// let versions = VersionData::new(&cached, &resolved);
    /// assert!(versions.cached.is_empty());
    /// assert!(versions.vulnerabilities.is_none());
    /// ```
    pub fn new(
        cached: &'a HashMap<PackageName, PackageVersions>,
        resolved: &'a HashMap<PackageName, ConcreteVersion>,
    ) -> Self {
        Self {
            cached,
            resolved,
            resolved_version_candidates: None,
            vulnerabilities: None,
            outcomes: None,
            ecosystem: None,
            network: crate::NetworkMode::Online,
            trust: None,
            license_prefetch: None,
            license_source: None,
            license_policy: None,
            typosquat_prefetch: None,
            gossip_prefetch: None,
            gossip_client: None,
            latest_status: None,
            candidate_status: None,
        }
    }

    /// Attaches the per-name lock-file candidates map, enabling the per-occurrence
    /// disambiguation described on [`Self::resolved_version_candidates`].
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::VersionData;
    /// use std::collections::HashMap;
    ///
    /// let cached = HashMap::new();
    /// let resolved = HashMap::new();
    /// let candidates = HashMap::new();
    /// let versions =
    ///     VersionData::new(&cached, &resolved).with_resolved_version_candidates(&candidates);
    /// assert!(versions.resolved_version_candidates.is_some());
    /// ```
    #[must_use]
    pub const fn with_resolved_version_candidates(
        mut self,
        candidates: &'a HashMap<PackageName, Vec<ConcreteVersion>>,
    ) -> Self {
        self.resolved_version_candidates = Some(candidates);
        self
    }

    /// Attaches an OSV scan result to this `VersionData`.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::VersionData;
    /// use deps_core::osv::VulnerabilityMap;
    /// use std::collections::HashMap;
    ///
    /// let cached = HashMap::new();
    /// let resolved = HashMap::new();
    /// let vulns = VulnerabilityMap::new();
    /// let versions = VersionData::new(&cached, &resolved).with_vulnerabilities(&vulns);
    /// assert!(versions.vulnerabilities.is_some());
    /// ```
    #[must_use]
    pub fn with_vulnerabilities(mut self, vulnerabilities: &'a VulnerabilityMap) -> Self {
        self.vulnerabilities = Some(vulnerabilities);
        self
    }

    /// Attaches phase B's per-key "latest" check result to this `VersionData`. See
    /// [`Self::latest_status`].
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::VersionData;
    /// use deps_core::osv::LatestStatusMap;
    /// use std::collections::HashMap;
    ///
    /// let cached = HashMap::new();
    /// let resolved = HashMap::new();
    /// let latest_status = LatestStatusMap::new();
    /// let versions = VersionData::new(&cached, &resolved).with_latest_status(&latest_status);
    /// assert!(versions.latest_status.is_some());
    /// ```
    #[must_use]
    pub fn with_latest_status(mut self, latest_status: &'a LatestStatusMap) -> Self {
        self.latest_status = Some(latest_status);
        self
    }

    /// Attaches phase B's per-candidate-version check result to this `VersionData`. See
    /// [`Self::candidate_status`].
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::VersionData;
    /// use deps_core::osv::CandidateStatusMap;
    /// use std::collections::HashMap;
    ///
    /// let cached = HashMap::new();
    /// let resolved = HashMap::new();
    /// let candidate_status = CandidateStatusMap::new();
    /// let versions =
    ///     VersionData::new(&cached, &resolved).with_candidate_status(&candidate_status);
    /// assert!(versions.candidate_status.is_some());
    /// ```
    #[must_use]
    pub fn with_candidate_status(mut self, candidate_status: &'a CandidateStatusMap) -> Self {
        self.candidate_status = Some(candidate_status);
        self
    }

    /// Attaches yanked, deprecation, and fetch-failure findings to this `VersionData`. See
    /// [`Self::outcomes`].
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::VersionData;
    /// use deps_core::lsp_helpers::DependencyOutcomes;
    /// use std::collections::HashMap;
    ///
    /// let cached = HashMap::new();
    /// let resolved = HashMap::new();
    /// let outcomes = DependencyOutcomes::new();
    /// let versions = VersionData::new(&cached, &resolved).with_outcomes(&outcomes);
    /// assert!(versions.outcomes.is_some());
    /// ```
    #[must_use]
    pub fn with_outcomes(mut self, outcomes: &'a DependencyOutcomes) -> Self {
        self.outcomes = Some(outcomes);
        self
    }

    /// Attaches this document's ecosystem, enabling the occurrence-aware
    /// refinements described on [`Self::ecosystem`].
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::{EcosystemId, VersionData};
    /// use std::collections::HashMap;
    ///
    /// let cached = HashMap::new();
    /// let resolved = HashMap::new();
    /// let versions = VersionData::new(&cached, &resolved).with_ecosystem(EcosystemId::Cargo);
    /// assert_eq!(versions.ecosystem, Some(EcosystemId::Cargo));
    /// ```
    #[must_use]
    pub const fn with_ecosystem(mut self, ecosystem: EcosystemId) -> Self {
        self.ecosystem = Some(ecosystem);
        self
    }

    /// Marks this `VersionData` as built while `network.offline` was set, so
    /// [`generate_hover`] appends its offline footer.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::VersionData;
    /// use std::collections::HashMap;
    ///
    /// let cached = HashMap::new();
    /// let resolved = HashMap::new();
    /// let versions = VersionData::new(&cached, &resolved).with_network(deps_core::NetworkMode::Offline);
    /// assert_eq!(versions.network, deps_core::NetworkMode::Offline);
    /// ```
    #[must_use]
    pub const fn with_network(mut self, network: crate::NetworkMode) -> Self {
        self.network = network;
        self
    }

    /// Attaches a deps.dev client, enabling [`generate_hover`] to attempt a
    /// supply-chain trust signal for the hovered dependency. See
    /// [`Self::trust`].
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::{DepsDevClient, HttpCache, VersionData};
    /// use std::collections::HashMap;
    /// use std::sync::Arc;
    ///
    /// let cached = HashMap::new();
    /// let resolved = HashMap::new();
    /// let client = Arc::new(DepsDevClient::new(Arc::new(HttpCache::new())));
    /// let versions = VersionData::new(&cached, &resolved).with_trust(&client);
    /// assert!(versions.trust.is_some());
    /// ```
    #[must_use]
    pub const fn with_trust(mut self, client: &'a Arc<DepsDevClient>) -> Self {
        self.trust = Some(client);
        self
    }

    /// Attaches tier-3 pre-fetched license data. See [`Self::license_prefetch`].
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::VersionData;
    /// use std::collections::HashMap;
    ///
    /// let cached = HashMap::new();
    /// let resolved = HashMap::new();
    /// let licenses = HashMap::new();
    /// let versions = VersionData::new(&cached, &resolved).with_license_prefetch(&licenses);
    /// assert!(versions.license_prefetch.is_some());
    /// ```
    #[must_use]
    pub const fn with_license_prefetch(
        mut self,
        licenses: &'a HashMap<PackageName, Vec<String>>,
    ) -> Self {
        self.license_prefetch = Some(licenses);
        self
    }

    /// Attaches this ecosystem's license source. See [`Self::license_source`].
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::{LicenseSource, VersionData};
    /// use std::collections::HashMap;
    ///
    /// let cached = HashMap::new();
    /// let resolved = HashMap::new();
    /// let versions =
    ///     VersionData::new(&cached, &resolved).with_license_source(LicenseSource::PomFreeText);
    /// assert_eq!(versions.license_source, Some(LicenseSource::PomFreeText));
    /// ```
    #[must_use]
    pub const fn with_license_source(mut self, source: LicenseSource) -> Self {
        self.license_source = Some(source);
        self
    }

    /// Attaches a license policy for diagnostics evaluation. See [`Self::license_policy`].
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::{LicensePolicy, VersionData};
    /// use std::collections::HashMap;
    ///
    /// let cached = HashMap::new();
    /// let resolved = HashMap::new();
    /// let policy = LicensePolicy::new(vec!["MIT".to_string()], vec![]);
    /// let versions = VersionData::new(&cached, &resolved).with_license_policy(&policy);
    /// assert!(versions.license_policy.is_some());
    /// ```
    #[must_use]
    pub const fn with_license_policy(mut self, policy: &'a LicensePolicy) -> Self {
        self.license_policy = Some(policy);
        self
    }

    /// Attaches background-pre-fetched typosquat signals. See [`Self::typosquat_prefetch`].
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::VersionData;
    /// use std::collections::HashMap;
    ///
    /// let cached = HashMap::new();
    /// let resolved = HashMap::new();
    /// let typosquat = HashMap::new();
    /// let versions = VersionData::new(&cached, &resolved).with_typosquat_prefetch(&typosquat);
    /// assert!(versions.typosquat_prefetch.is_some());
    /// ```
    #[must_use]
    pub const fn with_typosquat_prefetch(
        mut self,
        typosquat_prefetch: &'a HashMap<PackageName, TyposquatSignal>,
    ) -> Self {
        self.typosquat_prefetch = Some(typosquat_prefetch);
        self
    }

    /// Attaches background-pre-fetched GOSSIP findings. See [`Self::gossip_prefetch`].
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::VersionData;
    /// use std::collections::HashMap;
    ///
    /// let cached = HashMap::new();
    /// let resolved = HashMap::new();
    /// let gossip = HashMap::new();
    /// let versions = VersionData::new(&cached, &resolved).with_gossip_prefetch(&gossip);
    /// assert!(versions.gossip_prefetch.is_some());
    /// ```
    #[must_use]
    pub const fn with_gossip_prefetch(
        mut self,
        gossip_prefetch: &'a HashMap<PackageName, GossipFindings>,
    ) -> Self {
        self.gossip_prefetch = Some(gossip_prefetch);
        self
    }

    /// Attaches a deps.dev client, enabling hover to attempt a live GOSSIP low-usage fetch.
    /// See [`Self::gossip_client`].
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::{DepsDevClient, HttpCache, VersionData};
    /// use std::collections::HashMap;
    /// use std::sync::Arc;
    ///
    /// let cached = HashMap::new();
    /// let resolved = HashMap::new();
    /// let client = Arc::new(DepsDevClient::new(Arc::new(HttpCache::new())));
    /// let versions = VersionData::new(&cached, &resolved).with_gossip_client(&client);
    /// assert!(versions.gossip_client.is_some());
    /// ```
    #[must_use]
    pub const fn with_gossip_client(mut self, client: &'a Arc<DepsDevClient>) -> Self {
        self.gossip_client = Some(client);
        self
    }
}

/// The three states [`gossip_cooldown_for`] can resolve to — deliberately distinct from a
/// plain `Option<&GossipCooldown>` (issue #1456 security/impl-critic review, S2).
///
/// A bare `Option` conflates "no GOSSIP data available for this version at all" with "GOSSIP
/// has data and it authoritatively says this version is not in cooldown", and both used to
/// fall through to the unattributed local heuristic — which can then show a cooldown callout
/// that directly contradicts what GOSSIP already knows, violating FR-002's "authoritative when
/// available" requirement.
///
/// Spec 075 FR-005 (R-S3) redefined [`Self::NotActive`] to require a parsed, past `end` —
/// a missing COOLDOWN finding is [`Self::Unavailable`], not [`Self::NotActive`]. The earlier
/// definition conflated "no data" with "confirmed clear", which was fail-open for a write
/// path (`deps-cli update`'s cooldown-fallback candidate, spec 075).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GossipCooldownLookup {
    /// No GOSSIP data for this exact version — an absent entry, an FR-008 version mismatch,
    /// or a COOLDOWN finding with no cooldown at all (`findings.cooldown == None`, including
    /// a missing/unparseable `end`, spec 075 FR-005) — the caller falls back to
    /// [`local_cooldown_precedence`], unattributed.
    Unavailable,
    /// GOSSIP data is present for this exact version and confirms an active cooldown as of
    /// `now` (spec 072 FR-011's read-time `end > now` check) — the caller renders a
    /// GOSSIP-attributed callout. Carries no payload: no caller renders the cooldown's own
    /// `end`/`risk` today, only whether one is active — see [`gossip_cooldown_for`] for
    /// where that data is still available (`GossipFindings.cooldown`) if a future caller
    /// needs it.
    Active,
    /// GOSSIP data is present for this exact version and authoritatively reports a cooldown
    /// that has already ended (a parsed, past `end`) — the caller must render nothing here,
    /// never falling back to the local heuristic, which could contradict this answer.
    NotActive,
}

/// Looks up the GOSSIP cooldown state for `name` in `gossip_prefetch`, applying spec 072
/// FR-008's version-equality gate against `comparand` and FR-011's read-time `end > now` check.
///
/// `comparand` is the version actually being displayed at this call site — hover's
/// `latest_line`, diagnostics' `package_versions.latest` — shared by
/// `hover::push_latest_hover_section`, `diagnostics::apply_outdated_rule`,
/// [`crate::lsp_helpers::cooldown_disposition`], and `deps-engine`'s fallback-candidate
/// computation (spec 075) so no call site can diverge on this gate.
///
/// See [`GossipCooldownLookup`]'s doc for why this returns a three-state enum rather than
/// `Option<&GossipCooldown>`.
///
/// # Examples
///
/// ```
/// use deps_core::PackageName;
/// use deps_core::deps_dev::{GossipCooldown, GossipRiskLevel};
/// use deps_core::lsp_helpers::{GossipCooldownLookup, gossip_cooldown_for};
/// use deps_core::test_util::stub_gossip_findings;
/// use deps_core::PublishTime;
/// use std::collections::HashMap;
///
/// let name = PackageName::new("left-pad");
/// let mut prefetch = HashMap::new();
/// prefetch.insert(
///     name.clone(),
///     stub_gossip_findings(
///         "1.3.0",
///         Some(GossipCooldown::new(
///             PublishTime::from_unix_secs(2_000),
///             GossipRiskLevel::High,
///         )),
///     ),
/// );
///
/// assert_eq!(
///     gossip_cooldown_for(Some(&prefetch), &name, "1.3.0", PublishTime::from_unix_secs(1_000)),
///     GossipCooldownLookup::Active
/// );
/// assert_eq!(
///     gossip_cooldown_for(Some(&prefetch), &name, "1.3.0", PublishTime::from_unix_secs(3_000)),
///     GossipCooldownLookup::NotActive
/// );
/// assert_eq!(
///     gossip_cooldown_for(None, &name, "1.3.0", PublishTime::now()),
///     GossipCooldownLookup::Unavailable
/// );
/// ```
#[must_use]
pub fn gossip_cooldown_for(
    gossip_prefetch: Option<&HashMap<PackageName, GossipFindings>>,
    name: &PackageName,
    comparand: &str,
    now: PublishTime,
) -> GossipCooldownLookup {
    let Some(findings) = gossip_prefetch.and_then(|m| m.get(name)) else {
        return GossipCooldownLookup::Unavailable;
    };
    if findings.version != comparand {
        return GossipCooldownLookup::Unavailable;
    }
    match findings.cooldown.as_ref() {
        Some(cooldown) if cooldown.is_active(now) => GossipCooldownLookup::Active,
        Some(_) => GossipCooldownLookup::NotActive,
        None => GossipCooldownLookup::Unavailable,
    }
}

/// Wall-clock budget `deps-lsp`'s completion handler gives an ecosystem's
/// `generate_completions` before treating it as a timeout.
///
/// Past this, the handler skips the fallback search rather than treating a
/// fast-but-empty result as "genuinely no results"
/// (`crates/deps-lsp/src/handlers/completion.rs`).
///
/// A registry-backed completion path that retries internally on failure (e.g.
/// `deps-maven`'s `search`, #274) must size its own total retry budget to
/// exceed this constant: finishing sooner with an empty/error result is
/// indistinguishable, at the call site, from a query that legitimately has no
/// matches, and triggers a wasted (and, for a struggling registry, likely to also
/// fail) fallback search rather than the handler's existing skip-on-timeout path.
///
/// Lives here (ungated), not in [`crate::completion`] (`#[cfg(feature =
/// "lsp-responses")]`), and is re-exported from there for that feature's consumers:
/// a registry-backed completion path's own retry-budget constant (e.g. `deps-maven`'s
/// `RECENT_FAILURE_TTL`) is genuine `Registry::search` behavior, not LSP-response-shaped,
/// and must stay available under `--no-default-features` too (issue #1083 critic M1) —
/// one definition, not a hand-copied duplicate per feature state.
pub const COMPLETION_SEARCH_TIMEOUT: Duration = Duration::from_secs(2);

/// Wall-clock budget hover and code-action generation give the primary
/// `Registry::get_versions_from` fetch for the dependency under the cursor.
///
/// Unlike completion, code lens, inlay hints, and the background fetch task, hover
/// and code actions previously awaited this call with no deadline at all — an
/// ecosystem whose registry client retries across several candidate URLs
/// sequentially (e.g. `deps-maven`'s Gradle Plugin Portal fallback) could multiply
/// `HttpCache`'s own per-request timeout into tens of seconds of blocked, user-facing
/// latency on a single hover or lightbulb request (issue #1204). This is the *only*
/// deadline needed to fix that: it wraps the whole `get_versions_from` future,
/// cancelling it — candidate-URL loop included — at the ecosystem-registry level, so
/// no per-ecosystem inner budget is required on top of it. On elapse, hover falls back
/// to its existing `.ok()`-based basic-card degradation (the same path a genuine fetch
/// error takes); code actions instead drop the speculative fix/unsat actions outright
/// (see `await_versions_fetch`'s `timed_out` flag) rather than reusing that same
/// fail-open path, since an unverified yank check must not be treated as "not yanked".
pub const REGISTRY_FETCH_BUDGET: Duration = Duration::from_secs(10);

/// Awaits `fetch` bounded by [`REGISTRY_FETCH_BUDGET`], logging a `tracing::warn!` naming
/// `package` and `context` if the budget elapses first.
///
/// Shared by hover and code-action generation to avoid duplicating this
/// timeout/log/degrade shape at both call sites. Returns `(None, false)` for a
/// fetch-level error exactly like the pre-#1204 `.ok()` degrade, and `(None, true)` on
/// timeout — the `bool` lets a caller (code actions) tell the two apart when a fetch
/// failure and a fetch timeout must not be treated the same way (impl-critic S1: a
/// timeout is not a verified "not yanked" answer, so it must not fail open the way a
/// genuine registry outage does).
#[cfg(feature = "lsp-responses")]
async fn await_versions_fetch<T, E>(
    fetch: impl std::future::Future<Output = Result<T, E>>,
    package: &PackageName,
    context: &'static str,
) -> (Option<T>, bool) {
    match tokio::time::timeout(REGISTRY_FETCH_BUDGET, fetch).await {
        Ok(result) => (result.ok(), false),
        Err(_) => {
            tracing::warn!(
                package = %package.for_tracing(),
                context,
                timeout_secs = REGISTRY_FETCH_BUDGET.as_secs(),
                "primary registry version fetch timed out"
            );
            (None, true)
        }
    }
}

/// Converts UTF-16 offset to byte offset in a string.
///
/// LSP uses UTF-16 code units for character positions (for compatibility with
/// JavaScript and other languages). This function converts from UTF-16 offset
/// to byte offset for Rust string indexing.
///
/// # Arguments
///
/// * `s` - The string to index into
/// * `utf16_offset` - UTF-16 code unit offset (from LSP Position.character)
///
/// # Returns
///
/// Byte offset if valid, `None` if the UTF-16 offset is out of bounds.
///
/// # Examples
///
/// ```
/// # use deps_core::lsp_helpers::utf16_to_byte_offset;
/// // ASCII: UTF-16 offset equals byte offset
/// assert_eq!(utf16_to_byte_offset("hello", 2), Some(2));
///
/// // Unicode: "日本語" - each char is 3 bytes but 1 UTF-16 code unit
/// assert_eq!(utf16_to_byte_offset("日本語", 0), Some(0));
/// assert_eq!(utf16_to_byte_offset("日本語", 1), Some(3));
/// assert_eq!(utf16_to_byte_offset("日本語", 2), Some(6));
///
/// // Emoji: "😀" is 4 bytes but 2 UTF-16 code units (surrogate pair)
/// assert_eq!(utf16_to_byte_offset("😀test", 2), Some(4));
/// ```
pub fn utf16_to_byte_offset(s: &str, utf16_offset: u32) -> Option<usize> {
    let mut utf16_count = 0u32;
    for (byte_idx, ch) in s.char_indices() {
        if utf16_count >= utf16_offset {
            return Some(byte_idx);
        }
        #[expect(
            clippy::cast_possible_truncation,
            reason = "char::len_utf16 always returns 1 or 2, so this cast never truncates"
        )]
        {
            utf16_count += ch.len_utf16() as u32;
        }
    }
    if utf16_count == utf16_offset {
        return Some(s.len());
    }
    None
}

/// Converts a byte offset within `s` to a UTF-16 code unit offset (LSP `Position.character`).
///
/// `byte_offset` may be an arbitrary caller-supplied value: it is clamped to `s.len()` and
/// floored down to the nearest UTF-8 char boundary before use, so this never panics.
///
/// # Examples
///
/// ```
/// # use deps_core::lsp_helpers::byte_to_utf16_offset;
/// // ASCII: byte offset equals UTF-16 offset
/// assert_eq!(byte_to_utf16_offset("hello", 2), 2);
///
/// // Unicode: "日本語" - each char is 3 bytes but 1 UTF-16 code unit
/// assert_eq!(byte_to_utf16_offset("日本語", 0), 0);
/// assert_eq!(byte_to_utf16_offset("日本語", 3), 1);
/// assert_eq!(byte_to_utf16_offset("日本語", 6), 2);
///
/// // Emoji: "😀" is 4 bytes but 2 UTF-16 code units (surrogate pair)
/// assert_eq!(byte_to_utf16_offset("😀test", 4), 2);
///
/// // Never panics: an offset landing mid-character floors down to the start of that
/// // character, and an offset past the end saturates to the string's length.
/// assert_eq!(byte_to_utf16_offset("日本語", 1), 0); // inside the first character
/// assert_eq!(byte_to_utf16_offset("日本語", 999), 3); // past the end
/// ```
#[expect(
    clippy::string_slice,
    reason = "end is floor_char_boundary-clamped just above, mirroring the already-hardened \
              LineOffsetTable::byte_offset_to_position (lsp_helpers/mod.rs)"
)]
pub fn byte_to_utf16_offset(s: &str, byte_offset: usize) -> u32 {
    // Saturate rather than silently wrap: an LSP `Position.character` past `u32::MAX` UTF-16
    // units is already meaningless, but a wrapped value would be a wrong-but-plausible one
    // (#673 — the exact offset-math bug class #244 shipped).
    //
    // `byte_offset` is not guaranteed to be in bounds or on a char boundary (a caller-supplied
    // offset can be past `s.len()` or land mid-character); `floor_char_boundary` clamps both
    // — past-the-end saturates to `s.len()` and any other in-bounds index floors to the
    // nearest char boundary — mirroring `LineOffsetTable::byte_offset_to_position`
    // (lsp_helpers/mod.rs).
    let end = s.floor_char_boundary(byte_offset);
    u32::try_from(s[..end].encode_utf16().count()).unwrap_or(u32::MAX)
}

/// Checks whether a cursor position falls within an LSP range (inclusive on both ends).
pub fn position_in_range(pos: Position, range: Range) -> bool {
    if pos.line < range.start.line || pos.line > range.end.line {
        return false;
    }
    if pos.line == range.start.line && pos.character < range.start.character {
        return false;
    }
    if pos.line == range.end.line && pos.character > range.end.character {
        return false;
    }
    true
}

/// Whether `dep`'s `version_range()` is a degenerate, completion-only position with no
/// requirement behind it (e.g. Maven's `<version></version>`/self-closing `<version/>`) rather
/// than a real, non-empty range that happens to have no requirement (e.g. Gradle's
/// `version.ref` pointing at a dangling or rich-version alias, which spans the real
/// alias-reference text). Zero-width (`start == end`) is the discriminating signal —
/// `version_requirement().is_none()` alone is not, since both shapes share it.
pub(crate) fn version_range_is_synthetic_empty(dep: &dyn Dependency) -> bool {
    dep.version_requirement().is_none() && dep.version_range().is_some_and(|r| r.start == r.end)
}

/// Resolves the [`ScanOutcome`] for one dependency occurrence.
///
/// Tries `keys`' version-qualified lookup key for `dep` first (from
/// `crate::osv::vulnerability_keys`, #394 S2 — distinguishes two occurrences of one name
/// pinned to different versions), then the ecosystem-normalized name, then `dep`'s declared
/// name.
///
/// The single shared fallback chain for every OSV-outcome consumer
/// (`diagnostics::apply_vulnerability_rule`, `diagnostics::skip_reason_notice`,
/// `hover::generate_hover`'s vulnerability section) — previously written out four times
/// independently (issue #1400), risking a future change to the fallback priority landing in
/// only some of them. `keys` is `Option` because a caller with no [`EcosystemId`] to give
/// `crate::osv::vulnerability_keys` (most test
/// fixtures) has none to pass. `normalized_name` stays a caller-supplied parameter rather than
/// being derived here: `diagnostics` precomputes it once per name range and shares it across
/// both this lookup and its own per-dependency loop, so `normalize_package_name` (an
/// allocating call) never runs twice for the same dependency.
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::{
///     DiagnosticMessages, DiagnosticPolicy, OsvNaming, PackageNaming, PackageRendering,
///     RequirementResolution, SourcePolicy, resolve_scan_outcome,
/// };
/// use deps_core::osv::{ScanOutcome, VulnerabilityMap};
/// use deps_core::position::{Position, Range};
/// use deps_core::{ConcreteVersion, Dependency, PackageName, VersionReq};
/// use std::any::Any;
///
/// struct SimpleDep {
///     name: PackageName,
///     name_range: Range,
/// }
///
/// impl Dependency for SimpleDep {
///     fn name(&self) -> &PackageName {
///         &self.name
///     }
///     fn name_range(&self) -> Range {
///         self.name_range
///     }
///     fn version_requirement(&self) -> Option<&VersionReq> {
///         None
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
/// let dep = SimpleDep {
///     name: PackageName::new("time"),
///     name_range: Range::new(Position::new(0, 0), Position::new(0, 4)).into(),
/// };
///
/// let mut vulnerabilities = VulnerabilityMap::new();
/// vulnerabilities.insert(deps_core::test_util::vuln_key("time"), ScanOutcome::Clean);
///
/// // No `VulnKeys` map: falls back straight to the normalized name.
/// let outcome = resolve_scan_outcome(&vulnerabilities, &dep, None, "time");
/// assert!(matches!(outcome, Some(ScanOutcome::Clean)));
/// ```
pub fn resolve_scan_outcome<'a>(
    vulnerabilities: &'a VulnerabilityMap,
    dep: &dyn Dependency,
    keys: Option<&crate::osv::VulnKeys>,
    normalized_name: &str,
) -> Option<&'a ScanOutcome> {
    resolve_by_vuln_key(vulnerabilities, dep, keys, normalized_name)
}

/// Shared per-occurrence [`VulnKey`] lookup chain (version-qualified key, then normalized name,
/// then declared name) underlying both [`resolve_scan_outcome`] and [`resolve_latest_status`] —
/// the two maps [`VulnerabilityMap`] and [`crate::osv::LatestStatusMap`] share this exact key
/// space (#1517), so the fallback chain only needs writing once.
fn resolve_by_vuln_key<'a, V>(
    map: &'a HashMap<VulnKey, V>,
    dep: &dyn Dependency,
    keys: Option<&crate::osv::VulnKeys>,
    normalized_name: &str,
) -> Option<&'a V> {
    keys.and_then(|k| k.get(&dep.name_range()))
        .and_then(|key| map.get(key))
        .or_else(|| map.get(&VulnKey::from_name(normalized_name.to_string())))
        .or_else(|| map.get(&VulnKey::from_name(dep.name().as_str().to_string())))
}

/// Looks up `dep`'s entry in phase B's per-key "latest" status map, using the same
/// version-qualified-key-then-normalized-name-then-declared-name fallback chain as
/// [`resolve_scan_outcome`] (#1517).
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::resolve_latest_status;
/// use deps_core::osv::{LatestStatusMap, UpgradeStatus};
/// use deps_core::position::{Position, Range};
/// use deps_core::{Dependency, PackageName, VersionReq};
/// use std::any::Any;
///
/// struct SimpleDep {
///     name: PackageName,
///     name_range: Range,
/// }
///
/// impl Dependency for SimpleDep {
///     fn name(&self) -> &PackageName {
///         &self.name
///     }
///     fn name_range(&self) -> Range {
///         self.name_range
///     }
///     fn version_requirement(&self) -> Option<&VersionReq> {
///         None
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
/// let dep = SimpleDep {
///     name: PackageName::new("time"),
///     name_range: Range::new(Position::new(0, 0), Position::new(0, 4)).into(),
/// };
///
/// let mut latest_status = LatestStatusMap::new();
/// latest_status.insert(
///     deps_core::test_util::vuln_key("time"),
///     UpgradeStatus::CandidateClean {
///         version: deps_core::ConcreteVersion::new("1.0.0"),
///     },
/// );
///
/// let status = resolve_latest_status(&latest_status, &dep, None, "time");
/// assert!(matches!(status, Some(UpgradeStatus::CandidateClean { .. })));
/// ```
pub fn resolve_latest_status<'a>(
    latest_status: &'a LatestStatusMap,
    dep: &dyn Dependency,
    keys: Option<&crate::osv::VulnKeys>,
    normalized_name: &str,
) -> Option<&'a UpgradeStatus> {
    resolve_by_vuln_key(latest_status, dep, keys, normalized_name)
}

/// Whether a dependency's currently-displayed "latest" upgrade recommendation is safe to
/// surface as such (issue #1517).
///
/// The single gate every renderer (hover, diagnostics, code actions, code lens, inlay hints,
/// completion) and `deps-cli update`/`check` must consult before treating `latest` as an
/// endorsed upgrade target.
// Exhaustive: a new "verdict" is a deliberate design decision about how a fifth case should
// render everywhere at once, never a silent default — mirrors `EcosystemId`'s exhaustive-match
// convention (project rule, see #118).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LatestVerdict {
    /// OSV's latest-check does not apply here: OSV is disabled/offline for this scan entirely
    /// (no [`crate::osv::LatestStatusMap`] was ever attached), or this dependency's skip reason
    /// is structural ([`crate::osv::SkipReason::is_structural`] — its source/ecosystem is never
    /// checked against OSV, e.g. a git dependency or an OSV-unsupported ecosystem).
    NotApplicable,
    /// The exact version currently displayed as "latest" was checked and found clean (or
    /// affected only by [`VulnSeverity::Informational`]-only advisories, e.g. an "unmaintained"
    /// notice with no genuine security content).
    Verified,
    /// The exact version currently displayed as "latest" was checked and found affected by at
    /// least one non-informational advisory (or a record whose severity could not be
    /// determined, which is treated as blocking rather than silently passed through).
    Flagged {
        /// Advisory ids affecting the checked version, for display.
        advisory_ids: Vec<crate::osv::OsvId>,
        /// Whether the worst affecting advisory is a confirmed-malicious-package record
        /// ([`VulnSeverity::Malicious`]) — renderers use this to escalate wording/severity.
        malicious: bool,
        /// The sibling release tags through which the checked version is affected, when every
        /// advisory matched through siblings alone; `None` makes no claim about how.
        via_sibling_tags: Option<crate::osv::MatchedTags>,
    },
    /// The version was never definitively checked against OSV: no entry for this dependency
    /// (including the pre-phase-B window, where an empty map is attached deliberately so this
    /// case fires instead of [`Self::NotApplicable`]), a transient skip (timeout, query
    /// failure, truncation), or the checked version has since diverged from what's now
    /// displayed as `latest`. Renderers must treat this the same as [`Self::Flagged`] for the
    /// purpose of *not* recommending the upgrade — the two are kept distinct only so wording can
    /// differ ("not yet verified" vs. "flagged unsafe").
    Unverified,
}

/// Computes `dep`'s [`LatestVerdict`] against `displayed_latest` (the exact version string a
/// renderer is about to show as "latest") from `latest_status` (typically
/// [`VersionData::latest_status`]).
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::{LatestVerdict, latest_verdict};
/// use deps_core::osv::{LatestStatusMap, UpgradeStatus};
/// use deps_core::position::{Position, Range};
/// use deps_core::{Dependency, PackageName, VersionReq};
/// use std::any::Any;
///
/// struct SimpleDep {
///     name: PackageName,
///     name_range: Range,
/// }
///
/// impl Dependency for SimpleDep {
///     fn name(&self) -> &PackageName {
///         &self.name
///     }
///     fn name_range(&self) -> Range {
///         self.name_range
///     }
///     fn version_requirement(&self) -> Option<&VersionReq> {
///         None
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
/// let dep = SimpleDep {
///     name: PackageName::new("left-pad"),
///     name_range: Range::new(Position::new(0, 0), Position::new(0, 8)).into(),
/// };
/// let formatter = deps_core::test_util::StubFormatter::new();
///
/// // No map attached at all (OSV disabled/offline) — not applicable, today's behavior.
/// assert_eq!(
///     latest_verdict(None, &dep, None, "left-pad", "1.0.8", &formatter),
///     LatestVerdict::NotApplicable
/// );
///
/// // A map with no entry for this dependency (e.g. before phase B first completes) must fail
/// // closed, never pass through as safe.
/// let empty = LatestStatusMap::new();
/// assert_eq!(
///     latest_verdict(Some(&empty), &dep, None, "left-pad", "1.0.8", &formatter),
///     LatestVerdict::Unverified
/// );
/// ```
#[must_use]
pub fn latest_verdict(
    latest_status: Option<&LatestStatusMap>,
    dep: &dyn Dependency,
    keys: Option<&crate::osv::VulnKeys>,
    normalized_name: &str,
    displayed_latest: &str,
    formatter: &dyn EcosystemFormatter,
) -> LatestVerdict {
    let Some(map) = latest_status else {
        return LatestVerdict::NotApplicable;
    };
    upgrade_status_to_verdict(
        resolve_latest_status(map, dep, keys, normalized_name),
        displayed_latest,
        dep,
        formatter,
    )
}

/// Shared `UpgradeStatus -> LatestVerdict` mapping behind both [`latest_verdict`] and
/// [`candidate_verdict`] (#1524) — factored out so the two never drift on what "clean" vs.
/// "vulnerable" vs. "unverified"/"not applicable" means for a checked candidate.
///
/// A [`SkipReason::NonRegistrySource`] structural entry is cached under `dep`'s plain
/// [`crate::osv::VulnKey`] (name, not source), so it survives untouched if `dep`'s source later
/// changes from e.g. path/git to registry — until the next phase B run overwrites it. Since that
/// window would otherwise read as the fail-open [`LatestVerdict::NotApplicable`] for a dependency
/// that is now registry-resolvable and simply hasn't been checked yet, this re-checks `dep`'s
/// *current* source before trusting a cached `NonRegistrySource` skip (issue #1531). The check
/// goes through `formatter.source_is_public_registry_content` — the same predicate phase B itself
/// uses to classify `NonRegistrySource` in the first place (`deps-engine`'s `classify::osv`) —
/// rather than a bare `DependencySource::Registry` match, so an ecosystem that widens what counts
/// as registry content (e.g. `deps-cargo`'s `AlternateRegistry { mirrors_crates_io: true }` for a
/// configured crates.io mirror) is not itself misread as still-non-registry and wrongly kept
/// stale. A mismatch means the entry is stale, so it fails closed to
/// [`LatestVerdict::Unverified`] instead.
fn upgrade_status_to_verdict(
    status: Option<&UpgradeStatus>,
    expected_version: &str,
    dep: &dyn Dependency,
    formatter: &dyn EcosystemFormatter,
) -> LatestVerdict {
    match status {
        None | Some(UpgradeStatus::NotChecked) => LatestVerdict::Unverified,
        Some(UpgradeStatus::StructurallyUnchecked(reason)) => {
            let stale_non_registry_skip = *reason == StructuralSkipReason::NonRegistrySource
                && formatter.source_is_public_registry_content(&dep.source());
            if stale_non_registry_skip {
                LatestVerdict::Unverified
            } else {
                LatestVerdict::NotApplicable
            }
        }
        Some(UpgradeStatus::CandidateUnverified { reason, .. }) => {
            if reason.is_structural() {
                LatestVerdict::NotApplicable
            } else {
                LatestVerdict::Unverified
            }
        }
        Some(UpgradeStatus::CandidateClean { version }) => {
            if version == expected_version {
                LatestVerdict::Verified
            } else {
                LatestVerdict::Unverified
            }
        }
        Some(UpgradeStatus::CandidateVulnerable {
            version,
            advisory_ids,
            worst_severity,
            via_sibling_tags,
        }) => {
            if version != expected_version {
                return LatestVerdict::Unverified;
            }
            if *worst_severity == Some(VulnSeverity::Informational) {
                LatestVerdict::Verified
            } else {
                LatestVerdict::Flagged {
                    advisory_ids: advisory_ids.items().to_vec(),
                    malicious: *worst_severity == Some(VulnSeverity::Malicious),
                    via_sibling_tags: via_sibling_tags.clone(),
                }
            }
        }
    }
}

/// Resolves `dep`'s per-version candidate status from `candidate_status` (typically
/// [`VersionData::candidate_status`]), using the same three-tier `VulnKey` resolution
/// [`resolve_latest_status`] uses.
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::resolve_candidate_status;
/// use deps_core::osv::{CandidateStatusMap, UpgradeStatus};
/// use deps_core::position::{Position, Range};
/// use deps_core::{Dependency, PackageName, VersionReq};
/// use std::any::Any;
///
/// struct SimpleDep {
///     name: PackageName,
///     name_range: Range,
/// }
///
/// impl Dependency for SimpleDep {
///     fn name(&self) -> &PackageName {
///         &self.name
///     }
///     fn name_range(&self) -> Range {
///         self.name_range
///     }
///     fn version_requirement(&self) -> Option<&VersionReq> {
///         None
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
/// let dep = SimpleDep {
///     name: PackageName::new("time"),
///     name_range: Range::new(Position::new(0, 0), Position::new(0, 4)).into(),
/// };
///
/// let mut candidate_status = CandidateStatusMap::new();
/// candidate_status.insert(
///     deps_core::test_util::vuln_key("time"),
///     deps_core::osv::CandidateStatuses::PerVersion(
///         std::iter::once((
///             deps_core::ConcreteVersion::new("0.1.43"),
///             UpgradeStatus::CandidateClean {
///                 version: deps_core::ConcreteVersion::new("0.1.43"),
///             },
///         ))
///         .collect(),
///     ),
/// );
///
/// let statuses = resolve_candidate_status(&candidate_status, &dep, None, "time").unwrap();
/// let deps_core::osv::CandidateStatuses::PerVersion(per_version) = statuses else {
///     unreachable!()
/// };
/// assert!(matches!(
///     per_version.get(&deps_core::ConcreteVersion::new("0.1.43")),
///     Some(UpgradeStatus::CandidateClean { .. })
/// ));
/// ```
#[must_use]
pub fn resolve_candidate_status<'a>(
    candidate_status: &'a CandidateStatusMap,
    dep: &dyn Dependency,
    keys: Option<&crate::osv::VulnKeys>,
    normalized_name: &str,
) -> Option<&'a CandidateStatuses> {
    resolve_by_vuln_key(candidate_status, dep, keys, normalized_name)
}

/// Computes `dep`'s [`LatestVerdict`] for one specific candidate version (#1524).
///
/// The sibling of [`latest_verdict`] for a candidate-offering surface (code actions' "update
/// to X" list, completion's version items) that needs a verdict for more than just the
/// registry's single "latest" pick.
///
/// A dependency with no entry at all in `candidate_status` (phase B's candidate-check round
/// never covered it) resolves to [`LatestVerdict::Unverified`], matching [`latest_verdict`]'s
/// identical fail-closed default. A structural skip is recorded once per dependency as
/// [`crate::osv::CandidateStatuses::Structural`] (see that type's doc) and applies uniformly to
/// every candidate version, never mixed with real per-version data for the same dependency.
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::{LatestVerdict, candidate_verdict};
/// use deps_core::osv::{CandidateStatusMap, UpgradeStatus};
/// use deps_core::position::{Position, Range};
/// use deps_core::{Dependency, PackageName, VersionReq};
/// use std::any::Any;
///
/// struct SimpleDep {
///     name: PackageName,
///     name_range: Range,
/// }
///
/// impl Dependency for SimpleDep {
///     fn name(&self) -> &PackageName {
///         &self.name
///     }
///     fn name_range(&self) -> Range {
///         self.name_range
///     }
///     fn version_requirement(&self) -> Option<&VersionReq> {
///         None
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
/// let dep = SimpleDep {
///     name: PackageName::new("left-pad"),
///     name_range: Range::new(Position::new(0, 0), Position::new(0, 8)).into(),
/// };
/// let formatter = deps_core::test_util::StubFormatter::new();
///
/// // No map attached at all (OSV disabled/offline) — not applicable, mirrors `latest_verdict`.
/// assert_eq!(
///     candidate_verdict(None, &dep, None, "left-pad", "1.0.6", &formatter),
///     LatestVerdict::NotApplicable
/// );
///
/// // A map with an entry for this dependency, but not for this exact version — fails closed
/// // to `Unverified`, never silently treated as safe.
/// let mut candidate_status = CandidateStatusMap::new();
/// candidate_status.insert(
///     deps_core::test_util::vuln_key("left-pad"),
///     deps_core::osv::CandidateStatuses::PerVersion(std::collections::HashMap::new()),
/// );
/// assert_eq!(
///     candidate_verdict(Some(&candidate_status), &dep, None, "left-pad", "1.0.6", &formatter),
///     LatestVerdict::Unverified
/// );
/// ```
#[must_use]
pub fn candidate_verdict(
    candidate_status: Option<&CandidateStatusMap>,
    dep: &dyn Dependency,
    keys: Option<&crate::osv::VulnKeys>,
    normalized_name: &str,
    version: &str,
    formatter: &dyn EcosystemFormatter,
) -> LatestVerdict {
    let Some(map) = candidate_status else {
        return LatestVerdict::NotApplicable;
    };
    match resolve_candidate_status(map, dep, keys, normalized_name) {
        None => LatestVerdict::Unverified,
        Some(CandidateStatuses::Structural(reason)) => upgrade_status_to_verdict(
            Some(&UpgradeStatus::StructurallyUnchecked(*reason)),
            version,
            dep,
            formatter,
        ),
        Some(CandidateStatuses::PerVersion(per_version)) => {
            let status = per_version.get(&ConcreteVersion::from(version));
            upgrade_status_to_verdict(status, version, dep, formatter)
        }
    }
}

/// Converts byte offsets in source text to LSP `Position` values.
///
/// Precomputes line-start byte offsets once, then maps any byte offset to a
/// `(line, character)` position. Characters are counted as UTF-16 code units
/// as required by the LSP specification.
///
/// Also precomputes, per line, whether that line is pure ASCII (`line_is_ascii`): for an
/// ASCII-only line, byte offset and UTF-16 code-unit
/// offset are always equal, so [`byte_offset_to_position`](Self::byte_offset_to_position)
/// can skip the `chars().map(char::len_utf16).sum()` scan entirely and compute the
/// character offset in O(1). This matters because a single minified manifest line (e.g. a
/// `package.json` with hundreds of dependencies on one line) turns per-offset lookups into
/// an O(n) scan each, and O(n) lookups across the line's length make the whole document
/// O(n^2) (#742) — the common case of an ASCII-only line now stays O(1) per lookup; a
/// non-ASCII line still takes an O(1) lookup too, via a lazily-built per-line index (#882) —
/// see `with_non_ascii_line_index`.
///
/// Interior mutability: this type is `Send` but not `Sync` (the non-ASCII line index cache
/// uses a `RefCell`). Build one per document parse and never share it across threads.
pub struct LineOffsetTable {
    line_starts: Vec<usize>,
    line_is_ascii: Vec<bool>,
    // Lazily populated, keyed by line number. A `HashMap` rather than a `Vec` sized to the
    // line count so cost is proportional to lines actually queried non-ASCII (#882).
    non_ascii_line_index_cache:
        std::cell::RefCell<std::collections::HashMap<usize, NonAsciiLineIndex>>,
}

/// A non-ASCII line's char-boundary index, lazily built and cached by
/// `LineOffsetTable::with_non_ascii_line_index`.
///
/// `entries[i]` is `(byte_offset, utf16_units_before)` for the line's `i`-th char boundary
/// (`byte_offset` relative to the line's own start, `utf16_units_before` the cumulative UTF-16
/// code-unit count of every char *before* it). A final sentinel entry for the end of the line
/// (`byte_offset == line.len()`, `utf16_units_before` = the line's total UTF-16 length) makes
/// end-of-line byte offsets resolvable the same way as any other char boundary.
///
/// Serves both directions #882 needs on a non-ASCII line, from one build pass: char index ->
/// byte offset (`entries.get(col)`, what [`marker_byte_offset`] needs) and byte offset ->
/// UTF-16 units (`entries.binary_search_by_key`, what
/// [`byte_offset_to_position`](LineOffsetTable::byte_offset_to_position) needs) — a second,
/// independent cache would duplicate the exact `char_indices()` walk this one pass already
/// performs.
struct NonAsciiLineIndex {
    entries: Vec<(u32, u32)>,
}

impl NonAsciiLineIndex {
    /// Builds the index for one line's text via a single `char_indices()` walk.
    fn build(line_text: &str) -> Self {
        let mut entries = Vec::with_capacity(line_text.len() + 1);
        let mut utf16_units = 0u32;
        for (byte_offset, c) in line_text.char_indices() {
            entries.push((u32::try_from(byte_offset).unwrap_or(u32::MAX), utf16_units));
            utf16_units = utf16_units.saturating_add(u32::try_from(c.len_utf16()).unwrap_or(2));
        }
        entries.push((
            u32::try_from(line_text.len()).unwrap_or(u32::MAX),
            utf16_units,
        ));
        // The initial `line_text.len() + 1` capacity over-reserves 3-4x on a multi-byte-heavy
        // line (CJK, Devanagari, ...): it reserves per byte but pushes one entry per char.
        entries.shrink_to_fit();
        Self { entries }
    }
}

impl LineOffsetTable {
    /// Builds the table for `content`.
    pub fn new(content: &str) -> Self {
        let mut line_starts = vec![0];
        let mut line_is_ascii = Vec::new();
        let mut current_ascii = true;
        for (i, c) in content.char_indices() {
            if !c.is_ascii() {
                current_ascii = false;
            }
            if c == '\n' {
                line_starts.push(i + 1);
                line_is_ascii.push(current_ascii);
                current_ascii = true;
            }
        }
        line_is_ascii.push(current_ascii);
        debug_assert_eq!(
            line_starts.len(),
            line_is_ascii.len(),
            "line_starts and line_is_ascii must stay in lockstep — one entry per line"
        );
        Self {
            line_starts,
            line_is_ascii,
            non_ascii_line_index_cache: std::cell::RefCell::new(std::collections::HashMap::new()),
        }
    }

    /// Runs `f` against the cached (building it on first call) [`NonAsciiLineIndex`] for the
    /// non-ASCII line starting at `line0` (0-indexed), given that line's own text.
    ///
    /// Callers must pass the exact text of line `line0` as sliced from the same `content` this
    /// table was built from — the cache trusts its first-seen `line_text` for every later
    /// lookup of the same `line0` and never re-validates it. Building a line's index the first
    /// time it is looked up is still O(line length) (one `char_indices()` walk); only repeat
    /// lookups on an already-cached line become O(1) — a huge non-ASCII line's *first* lookup
    /// is not free, it is the same one-time cost `LineOffsetTable::new` always paid.
    ///
    /// Takes a closure rather than returning a `Ref` so the `RefCell` borrow never outlives one
    /// call — a caller cannot accidentally hold it open across an unrelated later borrow.
    #[expect(
        clippy::expect_used,
        reason = "borrow_mut() is dropped before borrow() runs, and the inserted entry is \
                  never removed, so the lookup below always succeeds"
    )]
    fn with_non_ascii_line_index<R>(
        &self,
        line0: usize,
        line_text: &str,
        f: impl FnOnce(&NonAsciiLineIndex) -> R,
    ) -> R {
        self.non_ascii_line_index_cache
            .borrow_mut()
            .entry(line0)
            .or_insert_with(|| NonAsciiLineIndex::build(line_text));
        let cache = self.non_ascii_line_index_cache.borrow();
        let index = cache
            .get(&line0)
            .expect("just inserted above if it was missing");
        f(index)
    }

    /// Byte offset (relative to the line's own start) of the `col`-th char boundary within the
    /// non-ASCII line starting at `line0`, given that line's text. Clamps to `line_text.len()`
    /// if `col` is past the line's char count, matching a plain `char_indices().nth(col)` walk.
    fn non_ascii_char_byte_offset(&self, line0: usize, line_text: &str, col: usize) -> usize {
        self.with_non_ascii_line_index(line0, line_text, |index| {
            index
                .entries
                .get(col)
                .map_or(line_text.len(), |&(byte_offset, _)| byte_offset as usize)
        })
    }

    /// UTF-16 code-unit count preceding `byte_offset` (relative to the line's own start) within
    /// the non-ASCII line starting at `line0`, given that line's text.
    ///
    /// `byte_offset` must be a char boundary within the line (guaranteed by
    /// [`byte_offset_to_position`](Self::byte_offset_to_position)'s `floor_char_boundary` clamp
    /// before calling this) — every char boundary, including end-of-line, has an exact entry in
    /// the index, so this never needs to interpolate between two boundaries.
    fn non_ascii_utf16_units_before(
        &self,
        line0: usize,
        line_text: &str,
        byte_offset: usize,
    ) -> u32 {
        self.with_non_ascii_line_index(line0, line_text, |index| {
            let byte_offset = u32::try_from(byte_offset).unwrap_or(u32::MAX);
            let found = index
                .entries
                .binary_search_by_key(&byte_offset, |&(b, _)| b);
            // `Err` shouldn't happen given the caller's `floor_char_boundary` guarantee, but
            // falls back to the nearest preceding entry rather than panicking.
            let i = found.unwrap_or_else(|i| i.saturating_sub(1));
            index.entries.get(i).map_or(0, |&(_, units)| units)
        })
    }

    /// Absolute byte offset where `line` (0-indexed) starts, or `None` if
    /// `line` is out of range.
    ///
    /// Prefer this over re-deriving a line's start via cursor arithmetic
    /// (`cursor += line.len() + 1`): `str::lines()` strips a trailing `\r`,
    /// so that approach under-counts by one byte per CRLF line and corrupts
    /// every subsequent offset in the file. This table is built by scanning
    /// `char_indices()` for `\n` (see [`new`](Self::new)), which counts the
    /// `\r`, so it stays correct for LF, CRLF and mixed line endings alike.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::lsp_helpers::LineOffsetTable;
    ///
    /// let table = LineOffsetTable::new("a\r\nb\r\nc");
    /// assert_eq!(table.line_start(0), Some(0));
    /// assert_eq!(table.line_start(1), Some(3));
    /// assert_eq!(table.line_start(2), Some(6));
    /// assert_eq!(table.line_start(3), None);
    /// ```
    pub fn line_start(&self, line: usize) -> Option<usize> {
        self.line_starts.get(line).copied()
    }

    /// Converts a byte offset into an LSP `Position`.
    pub fn byte_offset_to_position(&self, content: &str, offset: usize) -> Position {
        let offset = offset.min(content.len());
        // The requirements.txt line parser derives offsets via hand-rolled byte arithmetic,
        // which can land inside a multi-byte character — clamp to the nearest char boundary
        // rather than panicking on the slice below.
        let offset = content.floor_char_boundary(offset);
        let line = self
            .line_starts
            .partition_point(|&start| start <= offset)
            .saturating_sub(1);
        #[expect(
            clippy::indexing_slicing,
            reason = "line_starts always has at least one element (vec![0] at construction), \
                      so partition_point().saturating_sub(1) is always a valid index into it"
        )]
        let line_start = self.line_starts[line];
        // #673 M1: `line`/`character` aren't bounded by any size cap for editor-sent
        // full-document-sync text, so this saturates rather than assuming an upstream cap
        // (mirrors `completion::byte_to_utf16_offset`'s identical fix).
        //
        // #742: an ASCII-only line has 1 UTF-16 unit per byte, so no need to walk `chars()`.
        let character = if self.line_is_ascii.get(line).copied().unwrap_or(false) {
            u32::try_from(offset - line_start).unwrap_or(u32::MAX)
        } else {
            // #882: a naive `chars().map(len_utf16).sum()` per call is O(line length); N
            // lookups on the same wide line made this O(N x line length). The cached
            // per-line index (`with_non_ascii_line_index`) makes repeat lookups O(1).
            let line_end = self
                .line_starts
                .get(line + 1)
                .copied()
                .unwrap_or(content.len());
            let line_text = content.get(line_start..line_end).unwrap_or_default();
            self.non_ascii_utf16_units_before(line, line_text, offset - line_start)
        };
        Position::new(u32::try_from(line).unwrap_or(u32::MAX), character)
    }

    /// Converts an LSP `Position` back into a byte offset — the inverse of
    /// [`byte_offset_to_position`](Self::byte_offset_to_position). Out-of-range lines or
    /// UTF-16 characters clamp to `content.len()` rather than panicking, matching the
    /// forward conversion's `.min(content.len())` guard.
    ///
    /// A `character` landing inside a surrogate pair rounds up to the next char boundary, and
    /// one past the line's end (including its `\n`) resolves to the line's end — the same
    /// results as [`utf16_to_byte_offset`] on the line, but O(1) on an ASCII line and
    /// O(log line length) on a non-ASCII one via the cached per-line index (#1711).
    #[expect(
        clippy::string_slice,
        reason = "line_start/line_end come from line_starts (post-newline offsets, always \
                  char boundaries) or content.len()"
    )]
    pub fn position_to_byte_offset(&self, content: &str, position: Position) -> usize {
        let line0 = position.line as usize;
        let Some(&line_start) = self.line_starts.get(line0) else {
            return content.len();
        };
        let line_end = self
            .line_starts
            .get(line0 + 1)
            .copied()
            .unwrap_or(content.len());
        let line_len = line_end - line_start;
        let relative = if self.line_is_ascii.get(line0).copied().unwrap_or(false) {
            let character = position.character as usize;
            if character <= line_len {
                character
            } else {
                line_len
            }
        } else {
            let line_text = &content[line_start..line_end];
            self.with_non_ascii_line_index(line0, line_text, |index| {
                let i = index
                    .entries
                    .partition_point(|&(_, units)| units < position.character);
                index
                    .entries
                    .get(i)
                    .map_or(line_len, |&(byte_offset, _)| byte_offset as usize)
            })
        };
        (line_start + relative).min(content.len())
    }
}

/// Escapes Markdown syntax characters so untrusted text cannot break out of the
/// Markdown structure it is embedded in.
///
/// Applied to manifest-controlled text (dependency names) before it is written into
/// hover markdown link labels, and to registry-controlled completion metadata
/// (package name/version, description, repository/documentation URLs) before it is
/// written into completion-item link labels and link destinations. Every ASCII
/// punctuation character is backslash-escaped (CommonMark's full escapable set — not
/// just brackets/parens, which would still leave e.g. `<https://evil.example>`
/// autolinks live), and control characters (including newlines) plus a narrow set of
/// invisible/bidi-override characters (see `is_markdown_unsafe`, #1248) are replaced
/// with a space so the text cannot terminate the single-line block it is embedded in,
/// splice in new content, or visually spoof the rendered name via a Trojan Source
/// (CVE-2021-42574) bidi override.
///
/// Backslash-escaping is valid in link destinations as well as regular text, so this
/// also neutralizes `)`/`]` breakout attempts in a `[label](destination)` URL. It does
/// *not* block dangerous URI schemes (e.g. `javascript:`) in a destination — that is a
/// separate concern from breaking out of the surrounding Markdown structure.
///
/// Backslash-escaping does *not* work inside inline code spans (CommonMark §6.1) —
/// use [`markdown_code_span`] for text embedded in `` `...` `` instead.
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::escape_markdown;
///
/// assert_eq!(escape_markdown("pkg](evil)[pkg"), r"pkg\]\(evil\)\[pkg");
/// assert_eq!(escape_markdown("a\nb"), "a b");
/// ```
pub fn escape_markdown(s: &str) -> String {
    let mut escaped = String::with_capacity(s.len());
    for c in s.chars() {
        if is_markdown_unsafe(c) {
            escaped.push(' ');
            continue;
        }
        if c.is_ascii_punctuation() {
            escaped.push('\\');
        }
        escaped.push(c);
    }
    escaped
}

/// Predicate for a character that must not survive [`escape_markdown`]/
/// [`markdown_code_span`] unescaped (#1248, widened #1323): every Unicode `Cc`/`Cf`/`Zl`/`Zp`
/// character except a small, named exempt set with genuine mid-string use in real-world free
/// text — RTL/ZWNJ/ZWJ marks and Arabic/Syriac/Kaithi prefixed-format signs (see individual
/// `matches!` arms below, and `EXEMPT_CHARS` in
/// `test_is_markdown_unsafe_exempt_set_matches_sanitize_invisible_drift_guard` for the exact
/// list). Deliberately narrower than [`crate::redact::sanitize_invisible`]'s full sweep for
/// that reason; a name/version-shaped caller with no such legitimate-mark concern should
/// layer `sanitize_invisible` on top for full parity, as
/// `deps_npm::catalog::CatalogOrigin::hover_detail` does (#1266) — this crate's own
/// `deprecation.replacement` hover field does not yet (#1311).
///
/// The drift-guard test above scans the full Unicode code space and enforces that the
/// exempt set is exact. Do not widen or narrow this function without updating that test's
/// `EXEMPT_CHARS`, and do not fold in `sanitize_invisible`'s RTL/ZWNJ/ZWJ exemption without
/// also revisiting #1248.
fn is_markdown_unsafe(c: char) -> bool {
    c.is_control()
        || matches!(c,
            '\u{202A}'..='\u{202E}'    // LRE RLE PDF LRO RLO
          | '\u{2060}'..='\u{206F}'    // WORD JOINER, invisible math ops, bidi isolates,
                                       // deprecated format-control block (U+2065 unassigned,
                                       // deliberately included)
          | '\u{200B}'                // ZWSP
          | '\u{2028}' | '\u{2029}'   // LS, PS
          | '\u{FEFF}'                // ZWNBSP / BOM
          | '\u{FFF9}'..='\u{FFFB}'   // interlinear annotation anchor/separator/terminator
          | '\u{E0000}'..='\u{E007F}' // Unicode tag characters
          | '\u{00AD}'                // SOFT HYPHEN
          | '\u{180E}'                // MONGOLIAN VOWEL SEPARATOR
          | '\u{13430}'..='\u{1343F}' // Egyptian Hieroglyph format controls
          | '\u{1BCA0}'..='\u{1BCA3}' // Shorthand format controls
          | '\u{1D173}'..='\u{1D17A}' // Musical symbol format controls
        )
}

/// Replaces every [`is_markdown_unsafe`] character in `s` with a single space.
///
/// Shared by [`markdown_code_span`] and `diagnostics::sanitize_advisory_text_for_diagnostic`
/// (#1262 code-review follow-up) so the narrow bidi/invisible-character filter has exactly
/// one loop to keep in sync with [`is_markdown_unsafe`]'s policy, instead of two copies that
/// could silently drift. Also called from `crate::diagnostic::Diagnostic::new` and
/// `crate::diagnostic::RelatedInformation::new` as a defense-in-depth backstop on their
/// constructor path (#1276) — `pub(crate)` rather than private for that, but still not
/// reachable from outside `deps-core`.
///
/// Idempotent: `' '` is not itself [`is_markdown_unsafe`], so re-applying this to
/// already-sanitized input is a no-op — safe to double-apply through both a producer-side
/// call and the constructor-path backstop.
///
/// Only correct for a text/label sink or an inline code span, where a stray space is
/// harmless — **not** for a Markdown link *destination*: per CommonMark, an unbracketed
/// `[label](destination)` destination cannot contain a literal space at all, so
/// substituting one would turn a fired hazard into a broken (non-)link instead of a
/// sanitized one. [`strip_markdown_unsafe_chars`] is the destination-safe sibling.
pub(crate) fn replace_markdown_unsafe_chars(s: &str) -> String {
    s.chars()
        .map(|c| if is_markdown_unsafe(c) { ' ' } else { c })
        .collect()
}

/// Same filter as [`replace_markdown_unsafe_chars`], except `\n` is never replaced.
///
/// [`is_markdown_unsafe`] starts with `c.is_control()`, which classifies `\n` as unsafe —
/// correct for a single-line diagnostic message, but wrong for hover content: a hover card
/// is a multi-section Markdown document that relies on structural newlines between
/// sections, so running it through [`replace_markdown_unsafe_chars`] verbatim would
/// collapse the whole card onto one line. Used as `crate::hover::Hover`'s constructor-path
/// sanitization backstop (#1277), the hover equivalent of `Diagnostic::new`'s use of
/// [`replace_markdown_unsafe_chars`] (#1276).
///
/// Idempotent for the same reason [`replace_markdown_unsafe_chars`] is: neither `' '` nor
/// `'\n'` is itself [`is_markdown_unsafe`], so re-applying this to already-sanitized input
/// (or to input already sanitized by [`replace_markdown_unsafe_chars`], which is strictly
/// more aggressive) is a no-op.
///
/// Same **not destination-safe** caveat as [`replace_markdown_unsafe_chars`], but more load-
/// bearing here: this filter runs over the *entire* hover document on every construction and
/// mutation, so unlike the sibling's narrow, hand-picked call sites, it always spans any
/// Markdown link destination the document happens to contain — a substituted space there
/// would break the link (CommonMark forbids a literal space in an unbracketed destination)
/// rather than neutralize a hazard. This is not a gap in practice: every hover-rendered URL
/// is already stripped (not space-substituted) per-site via
/// [`crate::lsp_helpers::strip_markdown_unsafe_chars`] before it reaches this filter (see
/// `push_header_hover_section` in `lsp_helpers/hover.rs`), so this document-wide pass finds
/// nothing left to fire on a correctly-sanitized destination — but a future call site that
/// skips the per-site strip would silently break instead of just risking a hazard.
#[cfg(feature = "lsp-responses")]
pub(crate) fn replace_markdown_unsafe_chars_keep_newlines(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c != '\n' && is_markdown_unsafe(c) {
                ' '
            } else {
                c
            }
        })
        .collect()
}

/// Removes every `is_markdown_unsafe` character from `s` outright, rather than
/// substituting a space (`replace_markdown_unsafe_chars`'s behavior).
///
/// Used for a Markdown link *destination* (#1259 critic S3): CommonMark forbids a
/// literal, unescaped space inside an unbracketed `[label](destination)` destination,
/// so replacing a stripped character with a space there would break the link (render it
/// as non-link literal text) instead of sanitizing it in place. Dropping the character
/// keeps the surrounding URL syntactically intact — the removed character carried no
/// meaningful display information to begin with (it is invisible/bidi-control by
/// definition), so there is nothing worth preserving a placeholder for.
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::strip_markdown_unsafe_chars;
///
/// assert_eq!(strip_markdown_unsafe_chars("https://example.com/pkg"), "https://example.com/pkg");
/// assert_eq!(
///     strip_markdown_unsafe_chars("https://example.com/real\u{202E}gnp.sj"),
///     "https://example.com/realgnp.sj"
/// );
/// ```
pub fn strip_markdown_unsafe_chars(s: &str) -> String {
    s.chars().filter(|c| !is_markdown_unsafe(*c)).collect()
}

/// Wraps `content` in a Markdown inline code span (backticks included) that safely
/// contains arbitrary untrusted text, regardless of embedded backticks.
///
/// Backslash-escaping does not work inside code spans (CommonMark §6.1), so instead
/// this fences with one more backtick than the longest run found in `content`, and
/// pads with a single space on each side when `content` starts or ends with a
/// backtick or space (required by CommonMark to keep the fence unambiguous). Control
/// characters (including newlines) plus the same narrow invisible/bidi-override subset
/// `escape_markdown` neutralizes (see `is_markdown_unsafe`, #1248) are replaced with a
/// space first, since the raw hover string is otherwise free to merge into an adjacent
/// Markdown block or carry a Trojan Source bidi override into the rendered code span.
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::markdown_code_span;
///
/// assert_eq!(markdown_code_span("1.0.0"), "`1.0.0`");
/// assert_eq!(markdown_code_span("a`b"), "``a`b``");
/// ```
pub fn markdown_code_span(content: &str) -> String {
    let sanitized = replace_markdown_unsafe_chars(content);

    let max_backtick_run = sanitized
        .split(|c| c != '`')
        .map(str::len)
        .max()
        .unwrap_or(0);
    let fence = "`".repeat(max_backtick_run + 1);

    if sanitized.is_empty() {
        format!("{fence} {fence}")
    } else if sanitized.starts_with(['`', ' ']) || sanitized.ends_with(['`', ' ']) {
        format!("{fence} {sanitized} {fence}")
    } else {
        format!("{fence}{sanitized}{fence}")
    }
}

/// Checks if two version strings have the same major and minor version.
pub fn is_same_major_minor(v1: &str, v2: &str) -> bool {
    if v1.is_empty() || v2.is_empty() {
        return false;
    }

    let mut parts1 = v1.split('.');
    let mut parts2 = v2.split('.');

    if parts1.next() != parts2.next() {
        return false;
    }

    match (parts1.next(), parts2.next()) {
        (Some(m1), Some(m2)) => m1 == m2,
        _ => true,
    }
}

/// The length of the maximal `[a-zA-Z_][a-zA-Z0-9_]*`-shaped identifier starting at `start` in
/// `bytes`, or `None` if `bytes[start]` does not start one — the identifier grammar shared by
/// shell/envsubst-style variable expansion (`$VAR`, `${VAR}`) and the `@VAR@`/`%VAR%` forms
/// below.
fn template_placeholder_identifier_end(bytes: &[u8], start: usize) -> Option<usize> {
    let first = *bytes.get(start)?;
    if !(first.is_ascii_alphabetic() || first == b'_') {
        return None;
    }
    let mut end = start + 1;
    while bytes
        .get(end)
        .is_some_and(|&c| c.is_ascii_alphanumeric() || c == b'_')
    {
        end += 1;
    }
    Some(end)
}

/// Like [`template_placeholder_identifier_end`], but also allows `-` (never `.`) in the
/// identifier's tail — the `$(...)` Makefile/MSBuild form's own grammar (spec 070, issue
/// #1421): MSBuild property names may contain a hyphen in subsequent positions
/// (`$(MOD-VERSION)`) but never a period, unlike the `@VAR@` form's
/// [`dotted_identifier_end`], which permits both. Deliberately not reused verbatim for
/// `$(...)` — doing so would silently admit the dotted `$(A.VERSION)` form this project's
/// prevalence research rejected as unsupported by real tooling.
fn hyphenated_identifier_end(bytes: &[u8], start: usize) -> Option<usize> {
    let first = *bytes.get(start)?;
    if !(first.is_ascii_alphabetic() || first == b'_') {
        return None;
    }
    let mut end = start + 1;
    while bytes
        .get(end)
        .is_some_and(|&c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-'))
    {
        end += 1;
    }
    Some(end)
}

/// Like [`template_placeholder_identifier_end`], but also allows `.`/`-` in the identifier's
/// tail (never as the leading character) — the shape a CMake/Autotools `configure_file`
/// placeholder needs (`@project.version@`, `@some-flag@`), which is the actual common
/// real-world `@..@` form (impl-critic M1, #1379 follow-up): the stricter
/// `[a-zA-Z_][a-zA-Z0-9_]*` grammar the `$VAR`/`%VAR%` forms use never matches it, since those
/// forms' own real-world identifiers (shell/environment variable names, Windows env vars)
/// never contain `.`/`-` to begin with.
fn dotted_identifier_end(bytes: &[u8], start: usize) -> Option<usize> {
    let first = *bytes.get(start)?;
    if !(first.is_ascii_alphabetic() || first == b'_') {
        return None;
    }
    let mut end = start + 1;
    while bytes
        .get(end)
        .is_some_and(|&c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b'-'))
    {
        end += 1;
    }
    Some(end)
}

/// Whether `text` contains a `delim IDENT delim`-shaped placeholder (`@VAR@`/`@project.version@`
/// autoconf/CMake `configure_file`, `%VAR%` Windows batch/NSIS), anywhere in `text`. Unlike the
/// `$`-prefixed forms, both delimiters are required — `@`/`%` are common enough in ordinary text
/// (email addresses, percentages) that a bare opening delimiter alone would be too permissive.
fn contains_delimited_identifier_placeholder(
    text: &str,
    delim: u8,
    identifier_end: impl Fn(&[u8], usize) -> Option<usize>,
) -> bool {
    let bytes = text.as_bytes();
    bytes.iter().enumerate().any(|(i, &b)| {
        b == delim && identifier_end(bytes, i + 1).is_some_and(|end| bytes.get(end) == Some(&delim))
    })
}

/// Whether `text` contains an `open ... close`-shaped placeholder with non-blank content
/// between the delimiters (`{{ VAR }}` Liquid/Jinja2/Mustache/Go `text/template`, `<%= VAR %>`
/// ERB/lodash/Yeoman) — content is not restricted to a single identifier, since these grammars
/// commonly carry dotted field access (`{{ .NetVersion }}`), filters, or an `=`/`-` modifier
/// right after `open`.
///
/// The closing delimiter is not required (failing safe on an unclosed `{{VAR` — still treating
/// it as a placeholder — mirrors the `${VAR` precedent below): only `open` followed by
/// whitespace-then-non-blank content is checked, so a stray, immediately-closed `open` (`{{}}`,
/// `{{ }}`) is deliberately NOT flagged, matching `${}`'s empty-placeholder carve-out.
fn contains_bracketed_placeholder(text: &str, open: &str, close_or_skip: &[u8]) -> bool {
    let bytes = text.as_bytes();
    text.match_indices(open).any(|(pos, _)| {
        let mut i = pos + open.len();
        if close_or_skip.contains(bytes.get(i).unwrap_or(&0)) {
            i += 1;
        }
        while bytes.get(i).is_some_and(|b| b.is_ascii_whitespace()) {
            i += 1;
        }
        bytes.get(i).is_some_and(|&b| b != b'}' && b != b'%')
    })
}

/// Whether `requirement` contains an unresolved external-templating placeholder.
///
/// Recognizes several common generator syntaxes: `$VAR`/`${VAR}` (shell/envsubst), `$(VAR)`
/// (Makefile/MSBuild variable reference), `{{ VAR }}` (Liquid/Jinja2/Mustache/Go `text/template`
/// expression tags), `{% ... %}` (Jinja2/Liquid statement tags), `@VAR@`/`@project.version@`
/// (autoconf/CMake `configure_file`), `%VAR%` (Windows batch/NSIS), or `<%= VAR %>`
/// (ERB/lodash/Yeoman templates).
///
/// Detected anywhere in the text, not just as the whole value: `"${REACT_VERSION}"`, `"$VUE"`,
/// `"$(LODASH_VERSION)"`, `"{{ .NetVersion }}"`, `"{% if x %}"`, `"@PACKAGE_VERSION@"`,
/// `"%VERSION%"`, `"<%= version %>"`, and an embedded form like `"1.0.0-$BUILD"` are all
/// detected.
///
/// Issues #1374/#1379/#1417: manifests pre-processed by external templating (`envsubst`, CI
/// templating, cookiecutter/Yeoman-style generators, `configure_file`, `Makefile`-orchestrated
/// codegen) commonly carry one of these shapes in a version-requirement slot. npm, Cargo, Dart,
/// Poetry (`[tool.poetry.dependencies]`), Deno and Go have no expansion syntax of their own for
/// any of them — unlike Maven's `${property}` or Gradle's `$var`/`${var}`, which their own build
/// tools resolve — so this crate can never expand one either, and a requirement containing it
/// must never be classified as outdated/unsatisfiable or rewritten to a literal version.
///
/// The `$`/`{{`/`{%`/`<%` forms do not require a closing delimiter (failing safe on an unclosed
/// `${VAR`/`{{VAR`/`{%VAR`/`<%VAR` — still treating it as a placeholder — mirrors the GitLab
/// precedent this predicate was originally extracted alongside); `@VAR@`/`%VAR%` require both
/// delimiters, since a bare `@`/`%` is too common in ordinary text to treat as an opening
/// delimiter alone. `$(VAR)` also requires both delimiters (unlike `${VAR`'s fail-open
/// precedent): an unclosed `$(` is far more likely to be a real, unrelated `$` immediately
/// followed by literal `(text...` (parenthetical prose, a pasted shell command-substitution
/// snippet) than an unterminated Makefile reference (#1417).
///
/// NuGet's `.csproj`/`.fsproj`/`.vbproj`/`Directory.Packages.props` MSBuild Central Package
/// Management references (also `$(VAR)`-shaped, plus `%(VAR)`/`@(VAR)`) are natively recognized
/// by that crate's own, independent `is_msbuild_reference` guard — `NuGetFormatter`'s
/// `requirement_is_placeholder` ORs this function with that guard (`shared || native`), so this
/// function is still reachable and consulted for NuGet, but its own `$(VAR)` extension is not
/// load-bearing there: `is_msbuild_reference` already covered NuGet's `$(VAR)` case before this
/// function did.
///
/// The `$(VAR)` identifier grammar additionally accepts `-` in subsequent (never leading)
/// positions (`$(MOD-VERSION)`), matching real MSBuild property-name syntax (spec 070, issue
/// #1421). A `.` anywhere before the closing `)` (`$(A.VERSION)`) is a deliberate, researched
/// exclusion — not valid MSBuild syntax and not a documented real-world convention — and is
/// never matched, even in combination with a hyphen (`$(MOD.SUB-VERSION)`).
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::requirement_contains_template_placeholder;
///
/// assert!(requirement_contains_template_placeholder("${REACT_VERSION}"));
/// assert!(requirement_contains_template_placeholder("$VUE"));
/// assert!(requirement_contains_template_placeholder("1.0.0-$BUILD"));
/// assert!(requirement_contains_template_placeholder("$(LODASH_VERSION)"));
/// assert!(requirement_contains_template_placeholder("1.0.0-$(BUILD_SUFFIX)"));
/// assert!(requirement_contains_template_placeholder("$(MOD-VERSION)"));
/// assert!(requirement_contains_template_placeholder("1.0.0-$(BUILD-SUFFIX)"));
/// assert!(requirement_contains_template_placeholder("{{ .NetVersion }}"));
/// assert!(requirement_contains_template_placeholder("{% if x %}"));
/// assert!(requirement_contains_template_placeholder("@PACKAGE_VERSION@"));
/// assert!(requirement_contains_template_placeholder("@project.version@"));
/// assert!(requirement_contains_template_placeholder("%VERSION%"));
/// assert!(requirement_contains_template_placeholder("<%= version %>"));
/// assert!(!requirement_contains_template_placeholder("1.2.3"));
/// assert!(!requirement_contains_template_placeholder("price-is-$5"));
/// assert!(!requirement_contains_template_placeholder("price-is-$(five"));
/// assert!(!requirement_contains_template_placeholder("me@example.com"));
/// assert!(!requirement_contains_template_placeholder("100%"));
/// assert!(!requirement_contains_template_placeholder("$(A.VERSION)"));
/// assert!(!requirement_contains_template_placeholder("$(MOD.SUB-VERSION)"));
/// assert!(!requirement_contains_template_placeholder("$(-VERSION)"));
/// ```
pub fn requirement_contains_template_placeholder(requirement: &str) -> bool {
    let bytes = requirement.as_bytes();
    let has_dollar_form = bytes.iter().enumerate().any(|(i, &b)| {
        b == b'$'
            && match bytes.get(i + 1) {
                Some(b'{') => template_placeholder_identifier_end(bytes, i + 2).is_some(),
                // #1421: `[a-zA-Z_][a-zA-Z0-9_-]*` — a hyphen is accepted in subsequent
                // positions (real MSBuild property-name syntax, `$(MOD-VERSION)`); a dot
                // (`$(A.VERSION)`) remains a deliberate, researched exclusion (spec 070).
                Some(b'(') => hyphenated_identifier_end(bytes, i + 2)
                    .is_some_and(|end| bytes.get(end) == Some(&b')')),
                _ => template_placeholder_identifier_end(bytes, i + 1).is_some(),
            }
    });
    has_dollar_form
        || contains_delimited_identifier_placeholder(requirement, b'@', dotted_identifier_end)
        || contains_delimited_identifier_placeholder(
            requirement,
            b'%',
            template_placeholder_identifier_end,
        )
        || contains_bracketed_placeholder(requirement, "{{", b"")
        || contains_bracketed_placeholder(requirement, "{%", b"-")
        || contains_bracketed_placeholder(requirement, "<%", b"=-")
}

/// Result of checking whether a dependency's declared requirement is already satisfied by
/// the latest known version.
///
/// Diagnostics and inlay hints read this result differently: diagnostics only need to know
/// whether it is safe to skip the "Newer version available" warning, so both `UpToDate` and
/// `Unresolved` suppress it. Inlay hints additionally need to distinguish `Unresolved` from
/// `UpToDate`, since an unresolved requirement (e.g. a dangling Gradle version-catalog
/// `version.ref` alias, or an unexpanded Maven `${property}`) must not render an "up to
/// date" badge that was never actually verified.
// Exhaustive: a wildcard arm at any consuming match site would silently render the wrong
// label for a new variant instead of failing to compile (#769).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequirementStatus {
    /// The latest version satisfies the declared requirement.
    UpToDate,
    /// The latest version does not satisfy the declared requirement — a newer version is
    /// available.
    Outdated,
    /// The requirement could not be resolved to a concrete constraint, so no comparison
    /// could be made.
    Unresolved,
}

impl RequirementStatus {
    /// Maps [`Self::UpToDate`] to [`Self::Unresolved`], leaving every other status.
    ///
    /// The one definition of the cap applied to a status read from text that a truncated tag
    /// list cannot confirm (#1769): such a pin may be older than the text claims, but an
    /// outdated text status stays outdated.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::lsp_helpers::RequirementStatus::{Outdated, UpToDate, Unresolved};
    ///
    /// assert_eq!(UpToDate.never_up_to_date(), Unresolved);
    /// assert_eq!(Outdated.never_up_to_date(), Outdated);
    /// assert_eq!(Unresolved.never_up_to_date(), Unresolved);
    /// ```
    #[must_use]
    pub const fn never_up_to_date(self) -> Self {
        match self {
            Self::UpToDate => Self::Unresolved,
            Self::Outdated | Self::Unresolved => self,
        }
    }
}

/// A `requirement` compiled by one ecosystem, ready to test candidate versions against.
///
/// Produced by [`formatter::RequirementResolution::compile_bounded_requirement`]. Kept as a separate object
/// (rather than a single "does any version match" function) so the requirement is parsed
/// once per dependency, and so the scanning loop — including the empty-list guard, the
/// early-exit on first match, and the "skip an unparseable candidate" rule — lives once in
/// [`requirement_is_unsatisfiable`] instead of being reimplemented by all eleven ecosystems.
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::RequirementMatcher;
/// use deps_core::ConcreteVersion;
///
/// struct ExactMatch(String);
///
/// impl RequirementMatcher for ExactMatch {
///     fn matches(&self, version: &ConcreteVersion) -> Option<bool> {
///         Some(version.as_str() == self.0)
///     }
///
///     fn strict_prerelease_exclusion(&self) -> bool {
///         false
///     }
/// }
///
/// let matcher = ExactMatch("1.0.0".to_string());
/// assert_eq!(matcher.matches(&ConcreteVersion::new("1.0.0")), Some(true));
/// assert_eq!(matcher.matches(&ConcreteVersion::new("2.0.0")), Some(false));
/// ```
pub trait RequirementMatcher: Send + Sync {
    /// Tests one candidate version string against the compiled requirement.
    ///
    /// `Some(true)` / `Some(false)`: this candidate provably does / does not satisfy the
    /// requirement. `None`: this candidate *string* could not be parsed by this ecosystem's
    /// version format (e.g. a PyPI legacy release identifier, a Maven timestamped snapshot
    /// qualifier) — the caller skips it and keeps scanning the rest of the list. Never
    /// return `None` to mean "the requirement itself is unusable"; that is
    /// [`formatter::RequirementResolution::compile_bounded_requirement`]'s job, via returning `None` from that
    /// method instead of constructing a matcher at all.
    fn matches(&self, version: &ConcreteVersion) -> Option<bool>;

    /// Whether this compiled matcher follows strict SemVer 2.0.0 pre-release semantics: a
    /// pre-release version (`X.Y.Z-pre`) is excluded from matching unless the compiled
    /// requirement itself pins to the same `X.Y.Z` tuple with a pre-release tag — the rule
    /// `semver::VersionReq` and `node_semver::Range` both implement.
    ///
    /// `matching_prerelease_would_satisfy`'s "requirement is unsatisfiable only because of
    /// default pre-release exclusion" enrichment (#299) is gated on this, read from the
    /// already-compiled matcher instance rather than from a separate per-formatter flag
    /// (#1478) — so a formatter that reuses an existing matcher implementation (e.g.
    /// `deps-npm`'s shared `compile_node_semver_range`, also used by `deps-deno`) inherits the
    /// correct answer for free; only a formatter introducing a genuinely new matcher type
    /// needs to decide this at all, and only in the one place that type is defined.
    ///
    /// No default: a new matcher type must decide this explicitly rather than silently
    /// inheriting `false` by omission (#1478) — the whole point of moving this property off a
    /// per-formatter flag and onto the matcher type is that the answer can no longer go
    /// unconsidered. Return `true` only for a matcher whose underlying comparator itself
    /// implements this exclusion ([`compile_semver_requirement`]'s shared `semver::VersionReq`
    /// wrapper, used by `deps-cargo` and `deps-swift`; `deps-npm`'s shared
    /// `compile_node_semver_range`/`node_semver::Range` wrapper, used by `deps-npm` and
    /// `deps-deno`). Maven/NuGet/Composer/Gradle/PyPI/Go/Bundler/Dart's own matchers use
    /// non-strict, ecosystem-specific range models where this premise does not hold — they must
    /// return `false`.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::ConcreteVersion;
    /// use deps_core::lsp_helpers::RequirementMatcher;
    ///
    /// struct NonStrictMatcher;
    /// impl RequirementMatcher for NonStrictMatcher {
    ///     fn matches(&self, _version: &ConcreteVersion) -> Option<bool> {
    ///         Some(true)
    ///     }
    ///
    ///     fn strict_prerelease_exclusion(&self) -> bool {
    ///         false
    ///     }
    /// }
    ///
    /// assert!(!NonStrictMatcher.strict_prerelease_exclusion());
    /// ```
    fn strict_prerelease_exclusion(&self) -> bool;

    /// Whether this requirement's own grammar punches a hole that individually bans exactly
    /// `version`, independent of whether `version` would otherwise fall inside the
    /// requirement's nominal range — whether via a literal exclusion term (PyPI's `!=`/`!=X.*`,
    /// Composer's `!=`, Bundler's `!=`) or, for a grammar with no such operator, a gap between
    /// two segments of a disjoint range union (Maven's `[1.0,1.5),(1.5,2.0)`, which bans exactly
    /// `1.5.0`).
    ///
    /// Fix-cycle (#1571, generalized by #1590): [`crate::lsp_helpers::fallback_edit_excludes_newer`]'s
    /// `OriginalExcludesFallback` check needs this as an intensional signal — scanning
    /// `available` for "does some newer entry also match" cannot distinguish a punched-out
    /// hole from a fallback that legitimately exceeds the requirement's ceiling, since both
    /// produce the same `matches(fallback) == Some(false)` result and, when no newer entry
    /// happens to be listed in `available` either, the identical "nothing newer matches" scan
    /// outcome (critic-reproduced: `>=1.0,!=1.5.0,<2.0` and `>=1.0,<1.5` give the same verdict
    /// over `available = [2.0.0, 1.5.0, 1.0.0]` unless the matcher is asked directly).
    ///
    /// Default `false` — most ecosystems have no such shape (range/caret/tilde bounds only ever
    /// exclude by falling outside an interval, never by naming or gapping out one banned value
    /// inside it). A matcher overrides this exactly when its grammar CAN express such a hole —
    /// via a literal `!=`-style term, or, lacking one, via a gap between disjoint range/union
    /// segments — something `matches()` alone cannot surface as "explicitly banned" rather than
    /// "merely out of range".
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::ConcreteVersion;
    /// use deps_core::lsp_helpers::RequirementMatcher;
    ///
    /// struct RangeOnlyMatcher;
    /// impl RequirementMatcher for RangeOnlyMatcher {
    ///     fn matches(&self, _version: &ConcreteVersion) -> Option<bool> {
    ///         Some(true)
    ///     }
    ///     fn strict_prerelease_exclusion(&self) -> bool {
    ///         false
    ///     }
    /// }
    ///
    /// assert!(!RangeOnlyMatcher.explicitly_excludes(&ConcreteVersion::new("1.5.0")));
    /// ```
    fn explicitly_excludes(&self, _version: &ConcreteVersion) -> bool {
        false
    }
}

/// Parses `version` as [`semver::Version`] and tests it against `req`, `None` on parse failure.
/// Shared by [`SemverReqMatcher::matches`] and the test-only `NonStrictSemverMatcher` in
/// `diagnostics.rs` (identical logic, differing only in `strict_prerelease_exclusion()`).
pub(crate) fn semver_req_matches(
    req: &semver::VersionReq,
    version: &ConcreteVersion,
) -> Option<bool> {
    version
        .as_str()
        .parse::<semver::Version>()
        .ok()
        .map(|v| req.matches(&v))
}

/// Precise [`semver::VersionReq`] matcher, constructed only through [`compile_semver_requirement`].
/// Named to avoid shadowing the public `crate::version_matcher::SemverMatcher`.
struct SemverReqMatcher(semver::VersionReq);

impl RequirementMatcher for SemverReqMatcher {
    fn matches(&self, version: &ConcreteVersion) -> Option<bool> {
        semver_req_matches(&self.0, version)
    }

    /// `semver::VersionReq::matches` excludes pre-releases unless `requirement` itself pins to
    /// the same `X.Y.Z` tuple with a pre-release tag — strict SemVer 2.0.0 semantics (#299).
    /// Declared once, here, on the matcher type itself: any formatter that reuses
    /// [`compile_semver_requirement`] (`deps-cargo`'s `CargoFormatter`, `deps-swift`'s
    /// `SwiftFormatter`) inherits this answer for free, with no separate per-formatter flag to
    /// keep in sync (#1478, #1495).
    fn strict_prerelease_exclusion(&self) -> bool {
        true
    }
}

/// Compiles `requirement` as a plain [`semver::VersionReq`], the range grammar Cargo's registry
/// and Swift Package Manager's `from:`/closed-range/`upToNextMajor` translations both use for
/// matching.
///
/// The single source of truth for `deps-cargo`'s `CargoFormatter::compile_bounded_requirement` and
/// `deps-swift`'s `SwiftFormatter::compile_bounded_requirement` (#1495) — mirroring how #1478 unified
/// the analogous `node_semver::Range` case into `deps_npm::compile_node_semver_range`.
///
/// Unlike that npm/JSR case, this function has no built-in unresolved-placeholder guard: Cargo
/// and Swift's [`formatter::RequirementResolution::bounded_requirement_is_unresolved`] overrides
/// diverge (Swift additionally rejects its own native `\(...)` string-interpolation syntax), so
/// each formatter must run its own `self.bounded_requirement_is_unresolved(requirement)` guard before
/// calling this function, rather than the guard being hardcoded here.
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::{RequirementMatcher, compile_semver_requirement};
/// use deps_core::{ConcreteVersion, VersionReq};
///
/// let matcher = compile_semver_requirement(&VersionReq::new("^1.0.0")).unwrap();
/// assert_eq!(matcher.matches(&ConcreteVersion::new("1.5.0")), Some(true));
/// assert_eq!(matcher.matches(&ConcreteVersion::new("2.0.0")), Some(false));
/// assert!(matcher.strict_prerelease_exclusion());
///
/// assert!(compile_semver_requirement(&VersionReq::new("not a semver req")).is_none());
/// ```
pub fn compile_semver_requirement(requirement: &VersionReq) -> Option<Box<dyn RequirementMatcher>> {
    requirement
        .as_str()
        .parse::<semver::VersionReq>()
        .ok()
        .map(|req| Box::new(SemverReqMatcher(req)) as Box<dyn RequirementMatcher>)
}

#[cfg(test)]
mod semver_req_matcher_tests {
    use super::compile_semver_requirement;
    use crate::{ConcreteVersion, VersionReq};

    /// #299/#1495: `semver::VersionReq::matches` itself excludes a pre-release candidate unless
    /// the requirement pins to that exact `X.Y.Z` tuple with a pre-release tag — this is the
    /// actual behavior `strict_prerelease_exclusion() == true` promises callers, not just a flag
    /// value. `1.5.0-alpha.1` falls inside `>=1.0.0, <2.0.0`'s stable range but must still be
    /// rejected, since the requirement never pins to `1.5.0` specifically.
    #[test]
    fn matches_rejects_prerelease_candidate_not_pinned_by_requirement() {
        let matcher = compile_semver_requirement(&VersionReq::new(">=1.0.0, <2.0.0"))
            .expect("valid semver requirement must compile");
        assert_eq!(
            matcher.matches(&ConcreteVersion::new("1.5.0")),
            Some(true),
            "a stable candidate in range must match"
        );
        assert_eq!(
            matcher.matches(&ConcreteVersion::new("1.5.0-alpha.1")),
            Some(false),
            "a pre-release candidate must be rejected unless the requirement pins to its exact \
             X.Y.Z tuple with a pre-release tag"
        );
    }

    /// The one documented exception: a requirement that itself pins to the same `X.Y.Z` tuple
    /// with a pre-release tag does admit that exact pre-release.
    #[test]
    fn matches_accepts_prerelease_candidate_pinned_by_requirement() {
        let matcher = compile_semver_requirement(&VersionReq::new("=1.5.0-alpha.1"))
            .expect("valid semver requirement must compile");
        assert_eq!(
            matcher.matches(&ConcreteVersion::new("1.5.0-alpha.1")),
            Some(true)
        );
    }
}

/// Whether `segment` is exactly `.` or `..`.
///
/// Unlike ordinary path characters, a literal `.`/`..` segment is not neutralized by
/// percent-encoding: `.` is an unreserved character (RFC 3986), so `urlencoding::encode`
/// leaves it untouched, and the URL parser's dot-segment removal (RFC 3986 §5.2.4) still
/// collapses it after encoding — `%2E` decodes back to `.` before that normalization runs.
/// A registry-fetch URL built as `{base}/{prefix}/{name}` (no fixed suffix after `name`)
/// must reject a `name`/path segment satisfying this predicate rather than encode it,
/// since encoding alone does not stop the collapse (#341, #349).
///
/// Shared by `deps-npm`'s scope/package segment guard and `deps-dart`'s package-name
/// guard — both ecosystems' registry APIs key a fetch on a bare, suffix-less path segment.
///
/// **Scope**: this predicate (and the `#365` regression sweep built around it) guards
/// registry-*fetch* URL builders — the sink is a request this process actually
/// dereferences, so a retargeted URL can make it fetch attacker-chosen data. It
/// deliberately does *not* extend to a "docs link"/`package_url`-style builder (the
/// per-ecosystem hover/display link, e.g. `deps_cargo::crate_url`, `deps_go::package_url`):
/// those interpolate the name into a link rendered in hover text and never fetched by
/// this process, so an unrejected `.`/`..` name there produces at worst a misleading
/// same-host link (the registry's package-listing root), not a traversal off-host (#379).
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::is_dot_segment;
///
/// assert!(is_dot_segment(".."));
/// assert!(is_dot_segment("."));
/// assert!(!is_dot_segment("left-pad"));
/// ```
pub fn is_dot_segment(segment: &str) -> bool {
    segment == "." || segment == ".."
}

/// Whether `version` is safe to embed in a manifest `TextEdit` or completion item.
///
/// Guards every call into
/// [`formatter::PackageRendering::format_version_replacing`]/[`formatter::PackageRendering::format_version_for_text_edit`]
/// and every completion item's `insert_text`/`text_edit`.
///
/// Must be applied to the raw version string *before* formatting, never to a
/// formatter's output: some formatters legitimately produce structural
/// characters in their output from an already-validated version plus fixed,
/// trusted operators (e.g. PyPI's `>=1.2.3,<2`), so validating the output
/// would wrongly reject those.
///
/// An allowlist, not a denylist: `version` must be non-empty, at most 64
/// bytes, and contain only `[A-Za-z0-9.+_~:*^!-]` — the character set real
/// version strings use across every ecosystem this workspace supports
/// (SemVer, PEP 440 including epochs like `1!2.0`, Maven qualifiers, npm's
/// `^`/`~`/`*` range tokens, Go's `+incompatible` suffix). A denylist here
/// would need to anticipate every dangerous token a target manifest format
/// (or a build tool evaluating it, e.g. Gradle's Kotlin/Groovy DSL
/// interpolating `${...}` inside a version literal) could ever act on;
/// failing closed on an unrecognized character is cheaper and safer.
///
/// This is the single validation chokepoint shared by every producer of a
/// version-derived `TextEdit`/completion item in this workspace, including
/// OSV advisory data (an `Advisory.fixed_versions` entry is exactly as
/// untrusted as a registry-reported version).
///
/// # Examples
///
/// ```
/// use deps_core::is_safe_version_string;
///
/// assert!(is_safe_version_string("1.2.3-alpha.1+build"));
/// assert!(!is_safe_version_string("1.2.3\", git = \"https://evil"));
/// ```
pub fn is_safe_version_string(version: &str) -> bool {
    !version.is_empty()
        && version.len() <= 64
        && version.chars().all(|c| {
            c.is_ascii_alphanumeric()
                || matches!(c, '.' | '+' | '_' | '~' | ':' | '*' | '^' | '!' | '-')
        })
}

/// Whether `segment` is safe to embed as a Maven `groupId`/`artifactId` value in a
/// pom.xml `TextEdit` or completion item.
///
/// Guards Maven's group/artifact completion producer, which builds a completion item's
/// `insert_text`/`text_edit` from one field of a Maven Central search result — a value
/// type distinct from a version string (see [`is_safe_version_string`]'s doc comment for
/// why version-derived and non-version-derived sinks each get their own allowlist).
///
/// An allowlist, not a denylist: `segment` must be non-empty, at most 128 bytes, not
/// exactly `.`/`..` (see [`is_dot_segment`]), and contain only `[A-Za-z0-9._-]` — the
/// character set real Maven Central group ids (reverse-DNS style, e.g.
/// `org.apache.commons`) and artifact ids (hyphen/underscore separated, e.g.
/// `commons-lang3`) use. Deliberately excludes `:` — the `groupId:artifactId` separator —
/// because this validates one already-split coordinate field at a time, never the joined
/// pair. Failing closed on an unrecognized character (e.g. `<`, `"`, a newline) keeps a
/// malicious/compromised search result from restructuring the pom.xml it's inserted into;
/// the dedicated `.`/`..` rejection closes the same dot-segment URL-normalization gap
/// [`is_dot_segment`] guards elsewhere (`artifactId` reaches a registry-fetch URL as a bare
/// path segment in `deps-maven::registry::metadata_urls`, unlike `groupId`, whose `.`→`/`
/// expansion can never itself produce a literal `..` component).
///
/// # Examples
///
/// ```
/// use deps_core::is_safe_maven_coordinate_segment;
///
/// assert!(is_safe_maven_coordinate_segment("org.apache.commons"));
/// assert!(is_safe_maven_coordinate_segment("commons-lang3"));
/// assert!(!is_safe_maven_coordinate_segment("commons</artifactId><parent>"));
/// assert!(!is_safe_maven_coordinate_segment(".."));
/// ```
pub fn is_safe_maven_coordinate_segment(segment: &str) -> bool {
    !segment.is_empty()
        && segment.len() <= 128
        && !is_dot_segment(segment)
        && segment
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
}

/// Builds the Maven repository URL path (`"group/path/segments/artifact"`) for a
/// `groupId`/`artifactId` coordinate pair, or `None` if either fails validation.
///
/// The single shared home for `groupId:artifactId` -> URL-path construction (#702):
/// validates `group_id` and `artifact_id` as whole strings via
/// [`is_safe_maven_coordinate_segment`] (preserving its 128-byte total-length cap per
/// segment) *and* validates every `.`-separated component of `group_id` individually,
/// rejecting an empty component outright. The whole-string check alone is not enough —
/// it permits internal `.` characters, so a naive `group_id.replace('.', "/")` on a
/// coordinate like `"com..evil"` would produce the empty path segment `"com//evil"`; the
/// per-component check closes that gap without dropping the whole-string length bound a
/// pure per-segment `split('.')` validation would lose (a 10-segment, 128-byte-each group
/// would otherwise pass at 1280 bytes total).
///
/// # Examples
///
/// ```
/// use deps_core::maven_coordinate_path;
///
/// assert_eq!(
///     maven_coordinate_path("com.example", "artifact").as_deref(),
///     Some("com/example/artifact")
/// );
/// assert_eq!(
///     maven_coordinate_path("junit", "junit").as_deref(),
///     Some("junit/junit")
/// );
/// assert_eq!(maven_coordinate_path("com..evil", "artifact"), None);
/// ```
pub fn maven_coordinate_path(group_id: &str, artifact_id: &str) -> Option<String> {
    if !is_safe_maven_coordinate_segment(group_id) || !is_safe_maven_coordinate_segment(artifact_id)
    {
        return None;
    }
    let group_segments: Vec<&str> = group_id.split('.').collect();
    if group_segments
        .iter()
        .any(|segment| !is_safe_maven_coordinate_segment(segment))
    {
        return None;
    }
    Some(format!("{}/{artifact_id}", group_segments.join("/")))
}

/// Whether `url` is safe to embed as a Swift Package Manager repository URL in a
/// Package.swift `TextEdit` or completion item.
///
/// Guards Swift's URL-completion producer, which builds a `.package(url: "...")`
/// string-literal replacement from a package registry search result's URL — a value
/// type distinct from a version string (see [`is_safe_version_string`]'s doc comment for
/// why version-derived and non-version-derived sinks each get their own allowlist).
///
/// An allowlist, not a denylist: `url` must be non-empty, at most 2048 bytes, start with
/// `https://` — every real Swift package registry response is HTTPS (GitHub's `html_url`
/// never downgrades), so accepting plain `http://` would only hand a
/// compromised/malicious registry a transport-downgrade lever for zero legitimate
/// benefit — and otherwise contain only RFC 3986 URL characters (`A-Za-z0-9` plus
/// `` -._~:/?#[]@!$&'()*+,;=% ``). Deliberately excludes `"`, `\`, control characters,
/// and whitespace — none of those are valid unencoded URL characters, and any of them
/// could close the surrounding Swift string literal or otherwise corrupt the manifest.
/// Failing closed on an unrecognized character keeps a malicious/compromised search
/// result from breaking out of the string it's inserted into.
///
/// # Examples
///
/// ```
/// use deps_core::is_safe_registry_url;
///
/// assert!(is_safe_registry_url("https://github.com/apple/swift-nio"));
/// assert!(!is_safe_registry_url("https://evil.example\", .exact(\"1\")) // "));
/// ```
pub fn is_safe_registry_url(url: &str) -> bool {
    !url.is_empty()
        && url.len() <= 2048
        && url.starts_with("https://")
        && url.chars().all(|c| {
            c.is_ascii_alphanumeric()
                || matches!(
                    c,
                    '-' | '.'
                        | '_'
                        | '~'
                        | ':'
                        | '/'
                        | '?'
                        | '#'
                        | '['
                        | ']'
                        | '@'
                        | '!'
                        | '$'
                        | '&'
                        | '\''
                        | '('
                        | ')'
                        | '*'
                        | '+'
                        | ','
                        | ';'
                        | '='
                        | '%'
                )
        })
}

/// Whether `name` is safe to embed as a package name in a manifest `TextEdit` or
/// completion item.
///
/// Guards every arm of `create_package_completion_item`
/// (`crates/deps-lsp/src/handlers/completion.rs`) as a single upfront check, applied
/// before the raw `name` reaches any ecosystem-specific snippet — including Maven and
/// Swift, which additionally validate a *derived* value on top of this gate
/// ([`is_safe_maven_coordinate_segment`] on each split coordinate segment,
/// [`is_safe_registry_url`] on the constructed URL) because a value type distinct from
/// the raw name needs its own allowlist — see [`is_safe_version_string`]'s doc comment
/// for why version-derived and non-version-derived sinks each get their own allowlist.
/// [`PackageName::new`](crate::PackageName::new) is documented as never validating or
/// modifying its input, so this predicate is the first gate a registry-reported name
/// passes through before reaching a manifest. Two sinks that key a bare TOML/YAML
/// entry by `name` (Cargo/PyPI, Dart) additionally quote that key in the snippet, since
/// `.` and `@` are legal here but would otherwise be read as TOML's dotted-key
/// separator or break a YAML plain scalar.
///
/// An allowlist, not a denylist: `name` must be non-empty, at most 256 bytes, and
/// contain only `[A-Za-z0-9._@:/~-]` — the character set real package names use across
/// every ecosystem this predicate guards: Cargo/PyPI/Dart/NuGet/Bundler
/// (alphanumeric, `-`, `_`, `.`), npm/Deno scoped names (`@scope/name`, adding `@` and
/// `/`), Composer (`vendor/package`, `/`), Go module paths (domain-qualified paths like
/// `github.com/org/repo`, `/`, `.`, and `~` — legal in a Go path element and already
/// allowed by [`is_safe_version_string`]/[`is_safe_registry_url`]), and Gradle's
/// colon-delimited `group:artifact` short form (`:`). A denylist here would need to
/// anticipate every dangerous token a target manifest format (TOML/JSON/YAML/XML
/// string literals, a live Kotlin/Groovy build-script DSL) could ever act on; failing
/// closed on an unrecognized character — notably `"`, `'`, `<`, `>`, `` ` ``, and all
/// control characters/newlines — is cheaper and safer.
///
/// # Examples
///
/// ```
/// use deps_core::is_safe_package_name;
///
/// assert!(is_safe_package_name("serde"));
/// assert!(is_safe_package_name("@scope/name"));
/// assert!(is_safe_package_name("org.apache.commons:commons-lang3"));
/// assert!(!is_safe_package_name("evil\"\nbackdoor = \"9.9.9"));
/// ```
pub fn is_safe_package_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 256
        && name.chars().all(|c| {
            c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '@' | ':' | '/' | '-' | '~')
        })
}

/// Whether `name` is safe to embed as a Cargo feature name in a manifest `TextEdit` or
/// completion item.
///
/// Guards [`crate::completion::build_feature_completion`] the same way
/// [`is_safe_package_name`] guards [`crate::completion::build_package_completion`]:
/// `feature_name` there is registry-supplied (a key of `Version::features()`, read from
/// the index JSON's `features`/`features2` maps), not user-typed, so it must pass this
/// allowlist before reaching `label`/`insert_text`/`text_edit`/`sort_text`.
///
/// An allowlist, narrower than [`is_safe_package_name`]: Cargo's own feature-name grammar
/// (<https://doc.rust-lang.org/cargo/reference/features.html#the-features-section>) permits
/// Unicode `XID_Start`/`XID_Continue` characters, but crates.io's publish-time check — the
/// registry `deps-cargo` actually talks to — is stricter and only accepts ASCII
/// alphanumerics, `_`, `-`, and `+`; this predicate matches that stricter, ASCII-only set
/// (plus `.`, this predicate's own addition, not part of crates.io's check, allowed because
/// it's already permitted in [`is_safe_package_name`] and carries the same low risk here).
/// `dep:`, `?`, and `/` are never part of a feature *name* (an index JSON map key) either
/// way — they only ever appear inside a feature's *value* list (e.g.
/// `"avif" = ["dep:ravif", "rgb?/serde"]`), which this predicate never sees. A
/// registry-supplied string containing any of those characters is therefore not a
/// plausible feature name regardless of intent, so it is rejected the same as any other
/// out-of-allowlist character.
///
/// Tradeoff, accepted rather than incidental: a legitimate feature name published with a
/// Unicode `XID` character to an *alternate* (non-crates.io) registry — which Cargo's own
/// grammar permits but crates.io's check does not — would fail this allowlist and be
/// silently dropped rather than rendered. Failing closed on a character class this
/// predicate cannot cheaply distinguish from a homograph/bidi-spoofing attempt is judged
/// safer than accepting the full Cargo grammar, consistent with [`is_safe_package_name`]'s
/// own ASCII-only rationale.
///
/// # Examples
///
/// ```
/// use deps_core::is_safe_feature_name;
///
/// assert!(is_safe_feature_name("derive"));
/// assert!(is_safe_feature_name("std_alloc-v2+extra"));
/// assert!(!is_safe_feature_name("dep:ravif"));
/// assert!(!is_safe_feature_name("rgb?/serde"));
/// assert!(!is_safe_feature_name("evil\"\nbackdoor = \"9.9.9"));
/// ```
pub fn is_safe_feature_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 256
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '+' | '.'))
}

/// Logs a `tracing::warn!` for a value rejected by an `is_safe_*` predicate (or an
/// equivalent value-rejecting gate) before it reaches a manifest edit or registry URL.
///
/// Deliberately logs only `value`'s byte length, never its content: `value` is
/// registry-controlled and, by construction, already failed an allowlist — logging it
/// verbatim at `warn` would let a malicious/compromised registry response inject arbitrary
/// content into this project's own log stream (a second-order log-injection concern),
/// mirroring why `deps-pypi`'s `truncate_for_log` bounds a logged excerpt instead of
/// logging a value verbatim. This is this helper's own contract, not a claim that every
/// `tracing` call site in the workspace avoids logging a raw value — e.g. an OSV
/// malformed-`fixed`-version warning predates this helper and logs its rejected value
/// directly; that is an unrelated call site, not a place this helper is used.
///
/// `gate` names the predicate/guard that rejected `value` (e.g.
/// `"is_safe_maven_coordinate_segment"`); `context` is a short description of the call site
/// (e.g. `"maven groupId completion"`).
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::warn_rejected_value;
///
/// warn_rejected_value("is_safe_version_string", "code lens latest version", "1.0.0\"; evil");
/// ```
pub fn warn_rejected_value(gate: &str, context: &str, value: &str) {
    tracing::warn!(
        gate,
        context,
        len = value.len(),
        "rejected unsafe value before manifest/registry sink"
    );
}

/// Logs a [`warn_rejected_value`] warning and builds the [`DepsError::PackageNotFound`] a
/// caller returns after its own `is_dot_segment`/`has_dot_segment` predicate rejects `name`.
///
/// Extracted from four equivalent `warn_rejected_value` + `PackageNotFound`
/// constructions in `deps-dart`, `deps-composer`, `deps-nuget`, and `deps-npm`
/// (deps-lsp#929 item 2) — `deps-npm`'s `gate` label was `"npm_dot_segment_guard"` rather
/// than the other three's `"is_dot_segment"` before this extraction normalized it. Each
/// crate keeps its own dot-segment *predicate* and the call to it exactly where it is
/// today; only this trailing boilerplate is shared. Deliberately does **not** fold in
/// `deps-go`'s guard, which returns `DepsError::InvalidPackageName`, not `PackageNotFound`.
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::dot_segment_rejection_error;
/// use deps_core::DepsError;
///
/// let err = dot_segment_rejection_error(
///     "is_dot_segment",
///     "example package metadata request URL",
///     "..",
///     "example",
/// );
/// assert!(matches!(err, DepsError::PackageNotFound { .. }));
/// ```
#[must_use]
pub fn dot_segment_rejection_error(
    gate: &str,
    context: &str,
    name: &str,
    registry: &'static str,
) -> DepsError {
    warn_rejected_value(gate, context, name);
    DepsError::PackageNotFound {
        package: name.into(),
        registry,
    }
}

/// Converts a domain [`url::Url`] back into a `tower_lsp_server::ls_types::Uri` for
/// embedding into an actual LSP response object (`WorkspaceEdit`, `Location`, a code-lens
/// command argument, ...).
///
/// This is the one blessed conversion path from `deps-core`'s internal `url::Url` domain
/// type to `tower_lsp_server`'s `Uri` — ecosystem crates and `deps-core` itself must route
/// through it rather than re-deriving the conversion (e.g. `uri.as_str().parse()`) locally,
/// so a future change to how URLs round-trip through the LSP wire format only needs fixing
/// in one place. It mirrors `deps-lsp`'s own `lsp_types_interop::to_lsp_uri` (issue #1071):
/// `deps-core` cannot reuse that function (the dependency direction points the other way)
/// or express this as a `From` impl (neither `url::Url` nor `ls_types::Uri` is local to
/// `deps-core` — the same orphan-rule constraint that makes the `deps-lsp` boundary a pair
/// of free functions instead of a trait impl), so this is `deps-core`'s independent
/// counterpart, needed because `lsp_helpers` still builds real `ls_types` response objects
/// directly even though `Dependency`/`ParseResult` no longer carry an `ls_types::Uri` (see
/// `lib.rs`'s "LSP type stability" doc section).
///
/// # Panics
///
/// Panics if `url`'s string form does not round-trip into an `Uri`. In practice this
/// never happens: every `url::Url` reaching `lsp_helpers` originates from a real
/// editor-opened document (an `ls_types::Uri` converted to `Url` at the `deps-lsp`
/// boundary), so failing to convert it back indicates upstream corruption, not
/// attacker-controlled manifest content.
///
/// # Examples
///
/// ```
/// use deps_core::to_ls_uri;
/// use url::Url;
///
/// let url = Url::parse("file:///tmp/Cargo.toml").unwrap();
/// let uri = to_ls_uri(&url);
/// assert_eq!(uri.as_str(), "file:///tmp/Cargo.toml");
/// ```
#[cfg(feature = "lsp-responses")]
#[must_use]
pub fn to_ls_uri(url: &url::Url) -> tower_lsp_server::ls_types::Uri {
    url.as_str()
        .parse()
        .unwrap_or_else(|e| panic!("document URL {url} did not round-trip to an LSP Uri: {e}"))
}

/// Builds a single-entry [`tower_lsp_server::ls_types::WorkspaceEdit::changes`] map replacing `range` in `uri`
/// with `new_text`.
///
/// Shared by every quickfix/refactor code action in `code_actions` that edits exactly
/// one span in the current document (`build_vulnerability_fix_action`,
/// `build_unsatisfiable_fix_action`, and the plain "update to `<version>`" loop in
/// [`generate_code_actions`]) — and by any ecosystem crate hand-building a
/// `WorkspaceEdit` for a single-span fix instead of reimplementing this map shape
/// locally.
///
/// # Panics
///
/// Panics if `uri` does not round-trip through [`to_ls_uri`] — see that function's own
/// `# Panics` section.
///
/// # Examples
///
/// ```
/// use deps_core::single_file_edit;
/// use deps_core::position::{Position, Range};
/// use url::Url;
///
/// let url = Url::parse("file:///tmp/Cargo.toml").unwrap();
/// let range = Range::new(Position::new(0, 0), Position::new(0, 5));
/// let edits = single_file_edit(&url, range, "1.2.3".to_string());
///
/// assert_eq!(edits.len(), 1);
/// ```
#[cfg(feature = "lsp-responses")]
#[must_use]
pub fn single_file_edit(
    uri: &url::Url,
    range: Range,
    new_text: String,
) -> HashMap<tower_lsp_server::ls_types::Uri, Vec<tower_lsp_server::ls_types::TextEdit>> {
    let mut edits = HashMap::new();
    edits.insert(
        to_ls_uri(uri),
        vec![tower_lsp_server::ls_types::TextEdit {
            range: range.into(),
            new_text,
        }],
    );
    edits
}

/// Strips every whitespace character from `s`, so two textually-equivalent strings that
/// differ only in spacing compare equal.
///
/// Shared by every no-op/literal-match guard across `code_actions` and `code_lenses`
/// (`build_vulnerability_fix_action`'s N1 guard, `generate_code_actions`'s REFACTOR-loop
/// guard, `literal_span_matches`, and `collect_update_all_edits`'s no-op guard), all of
/// which compare a declared requirement
/// string against a differently-normalized counterpart — e.g. pep508's `>=1.7, <2.0` vs. a
/// formatter's `>=1.7,<2.0`.
pub(crate) fn strip_whitespace(s: &str) -> String {
    s.chars().filter(|c| !c.is_whitespace()).collect()
}

/// Slices `content` over an LSP `Range` using a pre-built `LineOffsetTable`, returning
/// `""` for an inverted or out-of-bounds range instead of panicking.
///
/// `table` is document-invariant — callers iterating over multiple dependencies in the
/// same document must build it once and reuse it, rather than rebuilding it (an O(n)
/// scan of `content`) per dependency.
pub(crate) fn slice_for_range<'a>(
    content: &'a str,
    table: &LineOffsetTable,
    range: Range,
) -> &'a str {
    let start = table.position_to_byte_offset(content, range.start);
    let end = table.position_to_byte_offset(content, range.end);
    if start > end {
        return "";
    }
    content.get(start..end).unwrap_or("")
}

/// Checks whether `slice` — `content` sliced over a dependency's `version_range` — still
/// holds the literal version text declared by `requirement`.
///
/// Whitespace is stripped from both sides before comparison, since pep508's normalized
/// requirement string can diverge from the original source spacing (PyPI's `>=1.7,<2.0`
/// renders as `>=1.7, <2.0`) while `version_range` still spans the un-normalized source.
///
/// The second branch accepts `slice` wrapped in brackets matching `requirement` — the
/// exact inverse of NuGet's parser wrapping a bare source version as `format!("[{v}]")`
/// (`crates/deps-nuget/src/parser.rs`). This is deliberately **not** a symmetric bracket
/// strip: NuGet's `Version="1.0.0"` produces requirement `[1.0.0]` over a bare-literal
/// span, so a *symmetric* strip (stripping one bracket pair from both operands) would
/// compare `1.0.0` against `1.0.0` — coincidentally correct there, but the same strip
/// applied to `Version="[1.0.0]"` (requirement `[[1.0.0]]`, a spelling
/// `crates/deps-nuget/src/formatter.rs` explicitly supports) leaves `[1.0.0]` vs
/// `1.0.0` and **falsely rejects** an editable dependency. Wrapping only the slice side
/// handles both spellings without that false reject.
pub(crate) fn literal_span_matches(slice: &str, requirement: &str) -> bool {
    let norm_slice = strip_whitespace(slice);
    let norm_req = strip_whitespace(requirement);
    norm_slice == norm_req || format!("[{norm_slice}]") == norm_req
}

/// Whether `version_range`'s slice of `content` still holds `dep`'s own declared literal
/// version text.
///
/// The same literal-span discipline [`generate_code_actions`] and
/// `collect_update_all_edits` already apply before writing a `TextEdit` there, generalized
/// (issue #919) for any caller about to treat `version_range` as an editable literal: a
/// completion context, or a raw-text-scanning ecosystem's own completion dispatch (Maven,
/// Gradle) that never goes through [`crate::completion::detect_completion_context`] at all.
///
/// Returns `false` — not editable — when the slice is syntactically reference-shaped (see
/// below), or the slice doesn't textually match the declared literal. When `dep` has no
/// [`Dependency::version_requirement`] at all, an empty (or whitespace-only) slice is admitted
/// — e.g. Maven's `<version></version>`, which has no text for its parser to capture and thus
/// nothing that could be misread as a reference/wildcard (#1161) — but a *non-empty* slice is
/// still rejected, since there is then no requirement to validate it against.
///
/// The reference-shape check runs **independently** of the text comparison (#919 C1): an
/// *unresolved* Maven `${property}` or Gradle `$var`/`${var}` interpolation is left by its
/// parser exactly as-is in both `version_range`'s slice and `version_requirement` (there is
/// nothing else to put there), so the two would otherwise textually agree and wrongly pass —
/// this is precisely the corruption #919 was filed over, and the dominant real-world Maven
/// case (a version inherited from a parent/BOM POM this crate cannot resolve) always lands
/// here. A slice containing `$` anywhere is rejected up front, before ever comparing text —
/// this single check subsumes both a whole-value `$var`/`${var}` interpolation and a Gradle
/// GString with the reference embedded mid-string (`1.0.$patch`), which `resolve_variable_ref`
/// only ever resolves in its whole-value form, leaving the mid-string case byte-identical
/// between slice and requirement and otherwise invisible to a `starts_with`-only check. A
/// slice that starts with `*` is rejected the same way *unless* [`crate::is_existence_wildcard_str`]
/// recognizes it as the project-wide existence-wildcard spelling (synthesized by `deps-npm`,
/// `deps-composer`, ...) — that case must keep offering a full version list at the exact
/// moment a user wants to replace the wildcard with a pin, while a `*anchor` YAML alias (any
/// other leading-`*` shape) still gets rejected.
///
/// An empty `version_requirement` is deliberately **not** special-cased here (unlike
/// `generate_code_actions`'s "nothing to update" early return, which does not apply to
/// completion): `serde = ""` / `"lodash": ""` — what an editor's auto-closing quotes produce
/// the instant the opening quote is typed — must still offer the full version list.
/// `literal_span_matches` alone already handles this correctly: `("", "")` matches (empty
/// slice, empty requirement — admitted), while a non-empty non-literal slice against an empty
/// requirement still fails to match (rejected).
///
/// Compares against [`Dependency::version_literal`] when the ecosystem provides one, falling
/// back to `version_requirement` otherwise (see that method's doc for why).
///
/// Builds its own [`LineOffsetTable`] for `content` on every call rather than accepting a
/// caller-built one — unlike `slice_for_range`'s multi-dependency callers (`generate_code_actions`,
/// `code_lenses`), every current call site invokes this at most once per request (a single
/// matched dependency), so a table-accepting overload would add API surface with no caller to
/// exercise it.
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::dependency_version_range_is_literal;
/// use deps_core::{Dependency, PackageName, VersionReq};
/// use std::any::Any;
/// use tower_lsp_server::ls_types::{Position, Range};
///
/// struct MockDep {
///     name: PackageName,
///     version_req: VersionReq,
///     version_range: deps_core::position::Range,
/// }
/// impl Dependency for MockDep {
///     fn name(&self) -> &PackageName {
///         &self.name
///     }
///     fn name_range(&self) -> deps_core::position::Range {
///         deps_core::position::Range::default()
///     }
///     fn version_requirement(&self) -> Option<&VersionReq> {
///         Some(&self.version_req)
///     }
///     fn version_range(&self) -> Option<deps_core::position::Range> {
///         Some(self.version_range)
///     }
///     fn source(&self) -> deps_core::parser::DependencySource {
///         deps_core::parser::DependencySource::Registry
///     }
///     fn as_any(&self) -> &dyn Any {
///         self
///     }
/// }
///
/// // A plain literal version is admitted.
/// let content = r#"serde = "1.0.0""#;
/// let dep = MockDep {
///     name: PackageName::new("serde"),
///     version_req: VersionReq::new("1.0.0"),
///     version_range: Range::new(Position::new(0, 9), Position::new(0, 14)).into(),
/// };
/// assert!(dependency_version_range_is_literal(&dep, content, dep.version_range.into()));
///
/// // A Maven `${property}` interpolation is rejected even when unresolved — slice and
/// // requirement are byte-identical raw reference text, which the shape check catches
/// // independently of the (otherwise-matching) text comparison.
/// let content = r"<version>${slf4j.version}</version>";
/// let dep = MockDep {
///     name: PackageName::new("slf4j-api"),
///     version_req: VersionReq::new("${slf4j.version}"),
///     version_range: Range::new(Position::new(0, 9), Position::new(0, 25)).into(),
/// };
/// assert!(!dependency_version_range_is_literal(&dep, content, dep.version_range.into()));
/// ```
#[must_use]
pub fn dependency_version_range_is_literal(
    dep: &dyn Dependency,
    content: &str,
    version_range: Range,
) -> bool {
    if version_range == Range::default() {
        // `Range::default()` ((0,0)-(0,0)) is a purely syntactic "not a real position"
        // sentinel, never a genuine in-document location — `deps-gradle`'s catalog context
        // deliberately returns it for a `version.ref = "alias"` reference (#931), including a
        // dangling or still-being-typed one, so this function must always reject it
        // unconditionally, before the `version_requirement()` check below ever runs.
        return false;
    }

    let table = LineOffsetTable::new(content);
    let slice = slice_for_range(content, &table, version_range);
    let trimmed = slice.trim();

    let Some(version_req) = dep.version_requirement() else {
        // No parsed requirement at all — e.g. Maven's `<version></version>`, which has no
        // text for its parser to capture. An empty span here has no existing text that could
        // be misread as a reference/wildcard, so it is always safe to offer completion
        // (#1161) — now that the `Range::default()` sentinel above is rejected first, this can
        // only be a genuine in-document position.
        return trimmed.is_empty();
    };
    if trimmed.contains('$')
        || (trimmed.starts_with('*') && !crate::is_existence_wildcard_str(trimmed))
    {
        return false;
    }
    let literal_target = dep
        .version_literal()
        .unwrap_or_else(|| version_req.as_str());
    literal_span_matches(slice, literal_target)
}

#[cfg(test)]
#[expect(
    clippy::string_slice,
    reason = "fixtures are single-line ASCII literals with hand-computed byte offsets"
)]
mod tests {
    use super::*;
    use crate::lsp_helpers::test_support::*;
    use crate::osv::SkipReason;
    use crate::{DependencySource, PackageName, VersionReq};
    use std::assert_matches;

    // --- gossip_cooldown_for (issue #1456, spec 072 FR-008/FR-011, S2 tri-state) ---

    fn gossip_findings_fixture(version: &str, end_unix_secs: i64) -> GossipFindings {
        GossipFindings {
            version: version.to_string(),
            cooldown: Some(crate::GossipCooldown {
                end: PublishTime::from_unix_secs(end_unix_secs),
                risk: crate::GossipRiskLevel::High,
            }),
            low_usage: None,
        }
    }

    fn gossip_findings_fixture_not_in_cooldown(version: &str) -> GossipFindings {
        GossipFindings {
            version: version.to_string(),
            cooldown: None,
            low_usage: None,
        }
    }

    #[test]
    fn gossip_cooldown_for_none_prefetch_is_unavailable() {
        let name = PackageName::new("vite");
        assert_matches!(
            gossip_cooldown_for(None, &name, "8.3.1", PublishTime::now()),
            GossipCooldownLookup::Unavailable
        );
    }

    #[test]
    fn gossip_cooldown_for_matching_active_version_is_active() {
        let name = PackageName::new("vite");
        let mut prefetch = HashMap::new();
        prefetch.insert(name.clone(), gossip_findings_fixture("8.3.1", 2_000));

        let lookup = gossip_cooldown_for(
            Some(&prefetch),
            &name,
            "8.3.1",
            PublishTime::from_unix_secs(1_000),
        );
        assert_eq!(lookup, GossipCooldownLookup::Active);
    }

    #[test]
    fn gossip_cooldown_for_version_mismatch_is_unavailable() {
        let name = PackageName::new("vite");
        let mut prefetch = HashMap::new();
        prefetch.insert(name.clone(), gossip_findings_fixture("8.3.1", 2_000));

        // FR-008: the prefetch entry is for 8.3.1, but the caller is displaying 8.4.0 (a
        // newer release the prefetch hasn't caught up with yet) — must be `Unavailable`,
        // not the stale 8.3.1 answer.
        let lookup = gossip_cooldown_for(
            Some(&prefetch),
            &name,
            "8.4.0",
            PublishTime::from_unix_secs(1_000),
        );
        assert_matches!(lookup, GossipCooldownLookup::Unavailable);
    }

    #[test]
    fn gossip_cooldown_for_ended_cooldown_self_clears_to_not_active_at_read_time() {
        let name = PackageName::new("vite");
        let mut prefetch = HashMap::new();
        prefetch.insert(name.clone(), gossip_findings_fixture("8.3.1", 1_000));

        // FR-011: `end` compared against `now` at read time, never a stored bool — a `now`
        // past `end` must self-clear to `NotActive` (GOSSIP data is present and version-
        // matched, it just no longer reports an active cooldown), never `Unavailable`
        // (which would wrongly let the caller fall back to the local heuristic).
        let lookup = gossip_cooldown_for(
            Some(&prefetch),
            &name,
            "8.3.1",
            PublishTime::from_unix_secs(2_000),
        );
        assert_matches!(lookup, GossipCooldownLookup::NotActive);
    }

    /// Spec 075 FR-005 (R-S3), inverting the earlier `..._is_not_active` expectation: GOSSIP
    /// data present, version-matched, but explicitly reporting no cooldown at all
    /// (`cooldown: None` — no `COOLDOWN` finding and no `cooldownEnd` fallback) must be
    /// `Unavailable`, not `NotActive` — `NotActive` now means only "a parsed, past `end` was
    /// found", so the caller falls back to the local heuristic instead of reading this as an
    /// authoritative "not in cooldown" answer (the old mapping was fail-open for a write path).
    #[test]
    fn gossip_cooldown_for_present_but_no_cooldown_data_is_unavailable() {
        let name = PackageName::new("vite");
        let mut prefetch = HashMap::new();
        prefetch.insert(
            name.clone(),
            gossip_findings_fixture_not_in_cooldown("8.3.1"),
        );

        let lookup = gossip_cooldown_for(Some(&prefetch), &name, "8.3.1", PublishTime::now());
        assert_matches!(lookup, GossipCooldownLookup::Unavailable);
    }

    #[test]
    fn gossip_cooldown_for_absent_name_is_unavailable() {
        let name = PackageName::new("vite");
        let other = PackageName::new("left-pad");
        let mut prefetch = HashMap::new();
        prefetch.insert(other, gossip_findings_fixture("1.3.0", 2_000));

        assert_matches!(
            gossip_cooldown_for(Some(&prefetch), &name, "8.3.1", PublishTime::now()),
            GossipCooldownLookup::Unavailable
        );
    }

    // --- cooldown_disposition (spec 075 FR-004/NFR-002) ---

    /// Fix-cycle item 8 (M3/NFR-002): a stored fallback candidate is re-evaluated against
    /// read-time `now`/cooldown window, not trusted as a fetch-time snapshot. A
    /// fallback whose own `published_at` no longer clears a (narrower, read-time)
    /// cooldown window must read as absent, not as a stale "still usable" answer.
    #[test]
    fn cooldown_disposition_read_time_reevaluates_the_stored_fallback() {
        let now = PublishTime::from_unix_secs(10_000);
        let versions = PackageVersions::new("2.0.0".into(), Arc::from(vec!["2.0.0".into()]))
            .with_published_at(PublishTime::from_unix_secs(9_900)) // 100s old
            .with_cooldown_fallback(CooldownFallback::new(
                "1.9.0".into(),
                PublishTime::from_unix_secs(9_800), // 200s old at read time
            ));
        let name = PackageName::new("pkg");

        // At fetch time, a 150s cooldown window: latest (100s old) is blocked, the fallback
        // (200s old) already clears it.
        let disposition = cooldown_disposition(
            &versions,
            &name,
            crate::freshness::FreshnessSettings::Enabled {
                cooldown: CooldownWindow::from_secs(150),
            },
            None,
            now,
        );
        assert_matches!(
            disposition,
            CooldownDisposition::Blocked {
                fallback: Some(_),
                ..
            },
            "got: {disposition:?}"
        );

        // Read time later widens the configured cooldown to 10_000s (e.g. a stricter
        // `--cooldown` override) — the SAME stored fallback (still only 200s old) no longer
        // clears it and must read as absent, never as the earlier fetch-time answer.
        let disposition = cooldown_disposition(
            &versions,
            &name,
            crate::freshness::FreshnessSettings::Enabled {
                cooldown: CooldownWindow::from_secs(10_000),
            },
            None,
            now,
        );
        assert_matches!(
            disposition,
            CooldownDisposition::Blocked { fallback: None, .. },
            "a fallback that no longer clears cooldown at read time must not be surfaced: {disposition:?}"
        );
    }

    /// #919: a plain literal version — `version_range`'s slice equals the declared
    /// requirement exactly — must be admitted as editable.
    #[test]
    fn test_dependency_version_range_is_literal_plain_literal_admitted() {
        let content = r#"serde = "1.0.0""#;
        let dep = MockDep {
            name: PackageName::new("serde"),
            version_req: VersionReq::new("1.0.0"),
            version_range: Range::new(Position::new(0, 9), Position::new(0, 14)),
            name_range: Range::new(Position::new(0, 0), Position::new(0, 5)),
        };

        assert!(dependency_version_range_is_literal(
            &dep,
            content,
            dep.version_range,
        ));
    }

    /// #919: a Maven-style `${property}` interpolation — `version_range` slices to the raw
    /// placeholder text while the parser resolves `version_requirement` to the property's
    /// value (a different string) — must be rejected, since a completion/edit there would
    /// splice text into the interpolation instead of updating a version.
    #[test]
    fn test_dependency_version_range_is_literal_rejects_property_interpolation() {
        let content = r"<version>${slf4j.version}</version>";
        let dep = MockDep {
            name: PackageName::new("slf4j-api"),
            version_req: VersionReq::new("2.0.16"), // resolved property value
            version_range: Range::new(Position::new(0, 9), Position::new(0, 25)), // "${slf4j.version}"
            name_range: Range::new(Position::new(0, 0), Position::new(0, 0)),
        };

        assert!(!dependency_version_range_is_literal(
            &dep,
            content,
            dep.version_range,
        ));
    }

    /// #919: a YAML alias-shaped value (`*anchor`, e.g. GitLab CI/GitHub Actions `ref: *pin`
    /// job reuse) never textually equals a declared literal requirement — rejected the same
    /// way as the property-interpolation case.
    #[test]
    fn test_dependency_version_range_is_literal_rejects_yaml_alias() {
        let content = "ref: *pin";
        let dep = MockDep {
            name: PackageName::new("job"),
            version_req: VersionReq::new("1.0.0"),
            version_range: Range::new(Position::new(0, 5), Position::new(0, 9)), // "*pin"
            name_range: Range::new(Position::new(0, 0), Position::new(0, 0)),
        };

        assert!(!dependency_version_range_is_literal(
            &dep,
            content,
            dep.version_range,
        ));
    }

    /// S1 (critic follow-up): an empty `version_requirement` over an equally-empty slice —
    /// exactly what an editor's auto-closing quotes produce the instant `serde = "` is typed
    /// — must be **admitted**, not rejected. `generate_code_actions`'s "nothing to update"
    /// semantics for an empty requirement do not apply to completion, where an empty value is
    /// the single most common moment to offer the full version list.
    #[test]
    fn test_dependency_version_range_is_literal_admits_empty_requirement_with_empty_slice() {
        let content = r#"serde = """#;
        let dep = MockDep {
            name: PackageName::new("serde"),
            version_req: VersionReq::new(""),
            version_range: Range::new(Position::new(0, 9), Position::new(0, 9)),
            name_range: Range::new(Position::new(0, 0), Position::new(0, 5)),
        };

        assert!(dependency_version_range_is_literal(
            &dep,
            content,
            dep.version_range,
        ));
    }

    /// S1 (critic follow-up): an empty `version_requirement` paired with a *non-empty*
    /// non-literal slice must still be rejected — dropping the old `is_empty()` early return
    /// must not also drop this case, which the plain text comparison already handles on its
    /// own (`"1.0" != ""`).
    #[test]
    fn test_dependency_version_range_is_literal_rejects_empty_requirement_with_mismatched_slice() {
        let content = r#"x = "1.0""#;
        let dep = MockDep {
            name: PackageName::new("x"),
            version_req: VersionReq::new(""),
            version_range: Range::new(Position::new(0, 5), Position::new(0, 8)), // "1.0"
            name_range: Range::new(Position::new(0, 0), Position::new(0, 1)),
        };

        assert!(!dependency_version_range_is_literal(
            &dep,
            content,
            dep.version_range,
        ));
    }

    /// C1 (critic finding): the headline #919 case — an *unresolved* Maven `${property}`
    /// reference. The parser leaves an unresolved property as-is in both `version_range`'s
    /// slice and `version_requirement` (there is nothing else to put there), so the two
    /// textually agree — `literal_span_matches` alone would wrongly admit this. The
    /// reference-shape check must reject it independently of that text comparison.
    #[test]
    fn test_dependency_version_range_is_literal_rejects_unresolved_maven_property() {
        let content = r"<version>${slf4j.version}</version>";
        let dep = MockDep {
            name: PackageName::new("slf4j-api"),
            version_req: VersionReq::new("${slf4j.version}"), // left unresolved by the parser
            version_range: Range::new(Position::new(0, 9), Position::new(0, 25)), // "${slf4j.version}"
            name_range: Range::new(Position::new(0, 0), Position::new(0, 0)),
        };

        assert!(!dependency_version_range_is_literal(
            &dep,
            content,
            dep.version_range,
        ));
    }

    /// C1 (critic finding): the Gradle sibling of the unresolved-property case — a `$var`
    /// reference `resolve_variable_ref` could not resolve, left as raw text in both the slice
    /// and `version_requirement`.
    #[test]
    fn test_dependency_version_range_is_literal_rejects_unresolved_gradle_variable() {
        let content = "implementation 'com.example:lib:$libVersion'";
        let dep = MockDep {
            name: PackageName::new("com.example:lib"),
            version_req: VersionReq::new("$libVersion"), // left unresolved by the parser
            version_range: Range::new(Position::new(0, 32), Position::new(0, 43)), // "$libVersion"
            name_range: Range::new(Position::new(0, 0), Position::new(0, 0)),
        };

        assert!(!dependency_version_range_is_literal(
            &dep,
            content,
            dep.version_range,
        ));
    }

    /// C1 (critic finding): a partial interpolation embedded mid-string (`1.0-${suffix}`)
    /// does not start with `$`, but must still be rejected — the `contains("${")` arm of the
    /// reference-shape check, not just the `starts_with` arms.
    #[test]
    fn test_dependency_version_range_is_literal_rejects_embedded_interpolation() {
        let content = r#"x = "1.0-${suffix}""#;
        let dep = MockDep {
            name: PackageName::new("x"),
            version_req: VersionReq::new("1.0-${suffix}"),
            version_range: Range::new(Position::new(0, 5), Position::new(0, 18)), // "1.0-${suffix}"
            name_range: Range::new(Position::new(0, 0), Position::new(0, 1)),
        };

        assert!(!dependency_version_range_is_literal(
            &dep,
            content,
            dep.version_range,
        ));
    }

    /// M2 (critic follow-up): `"*"` — the project-wide existence-wildcard spelling
    /// (`deps_core::registry::is_existence_wildcard`, synthesized by `deps-npm`,
    /// `deps-composer`, ...) — must be **admitted**, not caught by the `*`-prefix arm meant
    /// for a `*anchor` YAML alias. Rejecting it would silently disable version completion at
    /// the exact moment a user wants to replace `"lodash": "*"` with a pinned version.
    #[test]
    fn test_dependency_version_range_is_literal_admits_existence_wildcard() {
        let content = r#"x = "*""#;
        let dep = MockDep {
            name: PackageName::new("x"),
            version_req: VersionReq::new("*"),
            version_range: Range::new(Position::new(0, 5), Position::new(0, 6)), // "*"
            name_range: Range::new(Position::new(0, 0), Position::new(0, 1)),
        };

        assert!(dependency_version_range_is_literal(
            &dep,
            content,
            dep.version_range,
        ));
    }

    /// M3 (critic follow-up): a `*anchor`-shaped slice that is *not exactly* `"*"` — e.g. a
    /// multi-char alias name — must still be rejected. Distinguishes the wildcard exemption
    /// above from a genuine leading-`*` reference.
    #[test]
    fn test_dependency_version_range_is_literal_rejects_multi_char_alias_despite_wildcard_exemption()
     {
        let content = "ref: *pinned-anchor";
        let dep = MockDep {
            name: PackageName::new("job"),
            version_req: VersionReq::new("1.0.0"),
            version_range: Range::new(Position::new(0, 5), Position::new(0, 19)), // "*pinned-anchor"
            name_range: Range::new(Position::new(0, 0), Position::new(0, 0)),
        };

        assert!(!dependency_version_range_is_literal(
            &dep,
            content,
            dep.version_range,
        ));
    }

    /// M3 (critic follow-up): a Gradle GString with a `$var` reference embedded mid-string
    /// (`1.0.$patch`, no braces, not at the start) is not resolved by
    /// `resolve_variable_ref` (whole-value only) — the slice stays byte-identical to the raw
    /// `version_requirement`, so only the shape check (not the text comparison) can reject
    /// it. This is #919 C1 in a narrower spelling than the whole-value `$var`/`${var}` case.
    #[test]
    fn test_dependency_version_range_is_literal_rejects_gradle_mid_string_variable() {
        let content = r#"implementation "com.example:lib:1.0.$patch""#;
        let dep = MockDep {
            name: PackageName::new("com.example:lib"),
            version_req: VersionReq::new("1.0.$patch"), // left unresolved by the parser
            version_range: Range::new(Position::new(0, 32), Position::new(0, 42)), // "1.0.$patch"
            name_range: Range::new(Position::new(0, 0), Position::new(0, 0)),
        };

        assert!(!dependency_version_range_is_literal(
            &dep,
            content,
            dep.version_range,
        ));
    }

    /// #1161: a dependency with no `version_requirement()` at all — Maven's parser never
    /// sets one for a genuinely empty `<version></version>` tag, since there is no text to
    /// capture — must still be admitted when `version_range`'s slice is empty. There is no
    /// existing text at that position that could be misread as a reference/wildcard, so
    /// offering completion is always safe regardless of whether a requirement was parsed.
    #[test]
    fn test_dependency_version_range_is_literal_admits_empty_slice_with_no_requirement_at_all() {
        let content = "<version></version>";
        let dep = MockSyntheticRangeDep {
            name: PackageName::new("com.example:foo"),
        };
        let empty_range = Range::new(Position::new(0, 9), Position::new(0, 9));

        assert!(dep.version_requirement().is_none());
        assert!(dependency_version_range_is_literal(
            &dep,
            content,
            empty_range
        ));
    }

    /// Critic follow-up (C1, second round) to #1161: a DANGLING or still-being-typed
    /// `version.ref` alias (e.g. `version.ref = "gu"` while typing "guava") has
    /// `version_requirement() == None` — the exact same shape as Maven's genuinely empty
    /// `<version></version>` tag — but its range is `deps-gradle`'s `Range::default()`
    /// sentinel, not a real in-document position. This is the *normal* interactive state on
    /// every keystroke while typing an alias, not an edge case: admitting it here would offer
    /// the full unfiltered version list and splice a version literal into the alias name.
    /// Must be rejected regardless of `version_requirement()` being absent.
    #[test]
    fn test_dependency_version_range_is_literal_rejects_default_range_with_no_requirement_at_all() {
        let content = r#"version.ref = "gu""#;
        let dep = MockSyntheticRangeDep {
            name: PackageName::new("com.example:guava"),
        };

        assert!(dep.version_requirement().is_none());
        assert!(!dependency_version_range_is_literal(
            &dep,
            content,
            Range::default(),
        ));
    }

    /// Critic follow-up (C1) to #1161: an empty slice must NOT be admitted merely because it
    /// is empty — only when `version_requirement()` is also absent. `deps-gradle`'s catalog
    /// context deliberately returns `Range::default()` (which slices to `""`) for a
    /// `version.ref = "alias"` reference while `version_requirement()` still holds the
    /// alias's real, non-empty resolved value (#931) — the "always reject" guarantee that
    /// sentinel relies on comes from comparing that non-empty value against the empty slice,
    /// not from any special-casing of the empty slice itself. A version that checks
    /// `trimmed.is_empty()` before/independent of `version_requirement()` would invert this
    /// into an always-accept and let a full completion list splice a version literal into
    /// the alias name.
    #[test]
    fn test_dependency_version_range_is_literal_rejects_default_range_with_nonempty_requirement() {
        let content = r#"version.ref = "guavaVersion""#;
        let dep = MockDep {
            name: PackageName::new("com.example:guava"),
            version_req: VersionReq::new("32.0.1"), // the alias's resolved value
            version_range: Range::default(), // deps-gradle's deliberate always-reject sentinel
            name_range: Range::default(),
        };

        assert!(!dependency_version_range_is_literal(
            &dep,
            content,
            dep.version_range,
        ));
    }

    /// The empty-entry pruning invariant: an entry is removed once its last set channel
    /// is cleared, one channel at a time, in every order — never left behind as a
    /// vacuous `Some(DependencyOutcome::default())` that would inflate `len()`.
    #[test]
    fn test_dependency_outcomes_prunes_entry_once_all_channels_cleared() {
        let mut outcomes = DependencyOutcomes::new()
            .with_yanked("pkg", ("1.0.0".into(), RemovalStatus::Yanked))
            .with_deprecation(
                "pkg",
                Deprecation {
                    reason: None,
                    replacement: None,
                },
            )
            .with_fetch_failure("pkg", FetchFailure::Transient);
        assert_eq!(outcomes.len(), 1);

        outcomes.clear_yanked("pkg");
        assert!(
            outcomes.get("pkg").is_some(),
            "entry must survive while other channels are still set"
        );

        outcomes.clear_deprecation("pkg");
        assert!(
            outcomes.get("pkg").is_some(),
            "entry must survive while the fetch-failure channel is still set"
        );

        outcomes.clear_fetch_failure("pkg");
        assert!(
            outcomes.is_empty(),
            "entry must be pruned once its last channel is cleared, not left as a vacuous Some"
        );
        assert_eq!(outcomes.len(), 0);
    }

    /// Clearing a channel that was never set on an existing entry must not spuriously
    /// prune channels that ARE still set (each `clear_*` only nulls its own field).
    #[test]
    fn test_dependency_outcomes_clear_on_unset_channel_is_a_no_op_for_others() {
        let mut outcomes = DependencyOutcomes::new()
            .with_yanked("pkg", ("1.0.0".into(), RemovalStatus::AdvisoryDeprecated));

        outcomes.clear_deprecation("pkg");
        outcomes.clear_fetch_failure("pkg");

        assert!(
            outcomes.yanked("pkg").is_some(),
            "clearing unset channels must not touch the still-set yanked channel"
        );
        assert_eq!(outcomes.len(), 1);
    }

    /// `remove` drops the whole entry regardless of which channels are set, unlike the
    /// per-channel `clear_*` methods.
    #[test]
    fn test_dependency_outcomes_remove_drops_entry_with_multiple_channels_set() {
        let mut outcomes = DependencyOutcomes::new()
            .with_yanked("pkg", ("1.0.0".into(), RemovalStatus::Yanked))
            .with_fetch_failure("pkg", FetchFailure::Transient);

        outcomes.remove("pkg");

        assert!(outcomes.get("pkg").is_none());
        assert!(outcomes.is_empty());
    }

    /// `clear_all_fetch_failures` (deps-lsp issue #592) drops the fetch-failure channel for
    /// every entry, pruning an entry that becomes empty, while leaving other channels
    /// (yanked/deprecation/no-comparable-versions) on a still-mixed entry untouched.
    #[test]
    fn test_dependency_outcomes_clear_all_fetch_failures() {
        let mut outcomes = DependencyOutcomes::new()
            .with_fetch_failure("only-failure", FetchFailure::Transient)
            .with_yanked("mixed", ("1.0.0".into(), RemovalStatus::Yanked))
            .with_fetch_failure("mixed", FetchFailure::Transient);

        outcomes.clear_all_fetch_failures();

        assert!(
            outcomes.get("only-failure").is_none(),
            "an entry whose only channel was fetch-failure must be pruned"
        );
        assert!(outcomes.fetch_failure("mixed").is_none());
        assert!(
            outcomes.yanked("mixed").is_some(),
            "clearing fetch-failure must not touch a mixed entry's other channels"
        );
    }

    /// `clear_all_fetch_failures` on an empty map is a no-op, not a panic.
    #[test]
    fn test_dependency_outcomes_clear_all_fetch_failures_on_empty_map() {
        let mut outcomes = DependencyOutcomes::new();
        outcomes.clear_all_fetch_failures();
        assert!(outcomes.is_empty());
    }

    /// `set_fetch_failure_if_absent` (impl-critic M2) must never clobber a genuine
    /// `Actionable`/`Transient` failure already recorded for the name — only `set_fetch_failure`
    /// unconditionally overwrites.
    #[test]
    fn test_dependency_outcomes_set_fetch_failure_if_absent_does_not_clobber_existing() {
        let mut outcomes = DependencyOutcomes::new().with_fetch_failure(
            "pkg",
            FetchFailure::Actionable("set GITHUB_TOKEN".to_string()),
        );

        outcomes.set_fetch_failure_if_absent("pkg".to_string(), FetchFailure::NotAttempted);

        assert_eq!(
            outcomes.fetch_failure("pkg"),
            Some(&FetchFailure::Actionable("set GITHUB_TOKEN".to_string())),
            "an existing genuine failure must survive a collided-name NotAttempted marker"
        );
    }

    /// The mirror case: when no failure is recorded yet, `set_fetch_failure_if_absent` does
    /// populate the entry.
    #[test]
    fn test_dependency_outcomes_set_fetch_failure_if_absent_populates_when_unset() {
        let mut outcomes = DependencyOutcomes::new();

        outcomes.set_fetch_failure_if_absent("pkg".to_string(), FetchFailure::NotAttempted);

        assert_eq!(
            outcomes.fetch_failure("pkg"),
            Some(&FetchFailure::NotAttempted)
        );
    }

    #[test]
    fn test_line_offset_table_line_start_crlf() {
        let table = LineOffsetTable::new("a\r\nbb\r\nc");
        assert_eq!(table.line_start(0), Some(0));
        assert_eq!(table.line_start(1), Some(3));
        assert_eq!(table.line_start(2), Some(7));
        assert_eq!(table.line_start(3), None);
    }

    #[test]
    fn test_byte_offset_to_position_clamps_to_char_boundary_instead_of_panicking() {
        // "é" is a 2-byte UTF-8 sequence; offset 1 lands inside it.
        let content = "é";
        let table = LineOffsetTable::new(content);
        // Must not panic; clamps down to the nearest boundary (offset 0).
        let pos = table.byte_offset_to_position(content, 1);
        assert_eq!(pos, Position::new(0, 0));
    }

    #[test]
    fn test_byte_offset_to_position_multi_byte_boundary_in_longer_line() {
        let content = "ab é cd";
        let table = LineOffsetTable::new(content);
        // Byte 3 is 'é's leading byte (boundary); byte 4 is its continuation
        // byte (not a boundary) and must clamp back to 3 rather than panic.
        assert!(content.is_char_boundary(3));
        assert!(!content.is_char_boundary(4));
        let pos = table.byte_offset_to_position(content, 4);
        assert_eq!(pos, table.byte_offset_to_position(content, 3));
    }

    /// Covers the ASCII/non-ASCII fast-path split introduced for #742: an ASCII-only line
    /// (line 0), a non-ASCII line mixing a BMP accented character with a surrogate-pair
    /// emoji (line 1), and a mixed line (line 2) must all still resolve to the same
    /// `Position`s as the original `chars().map(char::len_utf16).sum()` scan would produce.
    #[test]
    fn test_byte_offset_to_position_ascii_and_non_ascii_lines_agree() {
        let content = "abcde\nhéllo 😀\nab café end";
        let table = LineOffsetTable::new(content);

        // Line 0 ("abcde"): ASCII fast path, byte offset == UTF-16 character offset.
        assert_eq!(
            table.byte_offset_to_position(content, 3),
            Position::new(0, 3)
        );
        assert_eq!(
            table.byte_offset_to_position(content, 5),
            Position::new(0, 5)
        );

        // Line 1 ("héllo 😀"): non-ASCII scan path.
        // Offset after "h\u{e9}" (1 + 2 bytes into the line): 'h' + 'é' = 2 UTF-16 units.
        assert_eq!(
            table.byte_offset_to_position(content, 6 + 3),
            Position::new(1, 2)
        );
        // Offset at the end of the line: "héllo 😀" = 8 UTF-16 units (emoji is a surrogate pair).
        assert_eq!(
            table.byte_offset_to_position(content, 6 + 11),
            Position::new(1, 8)
        );

        // Line 2 ("ab café end"): mixed line, still takes the non-ASCII scan path.
        // Offset after "ab café" (8 bytes into the line): 7 UTF-16 units ('é' is 1 BMP unit).
        assert_eq!(
            table.byte_offset_to_position(content, 18 + 8),
            Position::new(2, 7)
        );
    }

    fn reference_position_to_byte_offset(
        table: &LineOffsetTable,
        content: &str,
        position: Position,
    ) -> usize {
        let Some(line_start) = table.line_start(position.line as usize) else {
            return content.len();
        };
        let line_end = table
            .line_start(position.line as usize + 1)
            .unwrap_or(content.len());
        utf16_to_byte_offset(&content[line_start..line_end], position.character)
            .map_or(line_end, |offset| line_start + offset)
            .min(content.len())
    }

    /// #1711: the indexed inverse conversion must match the old per-call line scan for every
    /// position, including out-of-range lines/characters and ones splitting a surrogate pair.
    #[test]
    fn test_position_to_byte_offset_matches_line_scan_reference() {
        for content in [
            "",
            "abc",
            "abc\n",
            "a\r\nbb\r\nc",
            "h\u{e9}llo \u{1f600}\nascii\n\u{65e5}\u{672c}\u{8a9e}x\n",
            "\u{1f600}\u{1f600}",
            "\n\n\u{e9}",
        ] {
            let table = LineOffsetTable::new(content);
            for line in 0..6 {
                for character in 0..24 {
                    let position = Position::new(line, character);
                    assert_eq!(
                        table.position_to_byte_offset(content, position),
                        reference_position_to_byte_offset(&table, content, position),
                        "content {content:?} position {position:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn test_position_to_byte_offset_surrogate_split_rounds_up_and_overshoot_clamps() {
        let content = "a\u{1f600}b\nzz";
        let table = LineOffsetTable::new(content);
        assert_eq!(
            table.position_to_byte_offset(content, Position::new(0, 2)),
            5
        );
        assert_eq!(
            table.position_to_byte_offset(content, Position::new(0, 4)),
            6
        );
        assert_eq!(
            table.position_to_byte_offset(content, Position::new(0, 99)),
            7
        );
        assert_eq!(
            table.position_to_byte_offset(content, Position::new(1, 99)),
            content.len()
        );
        assert_eq!(
            table.position_to_byte_offset(content, Position::new(9, 0)),
            content.len()
        );
    }

    /// #1711: many edits on one long non-ASCII line must round-trip through the cached index.
    #[test]
    fn test_position_to_byte_offset_long_non_ascii_line_round_trips() {
        let content = "\u{e9}\u{1f600}dep = \"1.0.0\", ".repeat(5000);
        let table = LineOffsetTable::new(&content);
        for (offset, _) in content.char_indices().step_by(7) {
            let position = table.byte_offset_to_position(&content, offset);
            assert_eq!(table.position_to_byte_offset(&content, position), offset);
        }
    }

    #[test]
    fn test_position_to_byte_offset_round_trips_across_mixed_ascii_and_non_ascii_lines() {
        let content = "plain = 1\r\nh\u{e9}llo \u{1f600}\nascii again\n\u{65e5}\u{672c}\n\nend";
        let table = LineOffsetTable::new(content);
        let offsets: Vec<usize> = content
            .char_indices()
            .map(|(i, _)| i)
            .chain([content.len()])
            .collect();
        for &offset in offsets.iter().rev().chain(offsets.iter()) {
            let position = table.byte_offset_to_position(content, offset);
            assert_eq!(
                table.position_to_byte_offset(content, position),
                offset,
                "offset {offset}"
            );
        }
    }

    /// Regression guard for #742: `byte_offset_to_position` on a large single-line
    /// (minified) manifest must stay near-instant. The pre-fix implementation rescanned
    /// the line from its start on every call, making repeated lookups over such a line
    /// O(n^2) in the line's length (~350ms for 8000 calls on an ~180KB line on the
    /// reporter's machine); the ASCII fast path makes each call O(1), so this generous
    /// wall-clock bound leaves wide margin without being flaky.
    #[test]
    fn test_byte_offset_to_position_minified_line_stays_fast() {
        let mut content = String::from("{\"dependencies\":{");
        for i in 0..8000 {
            content.push_str(&format!("\"dep{i}\":\"1.0.{i}\","));
        }
        content.push_str("}}");

        let table = LineOffsetTable::new(&content);
        let step = (content.len() / 8000).max(1);
        let start = std::time::Instant::now();
        for offset in (0..content.len()).step_by(step) {
            std::hint::black_box(table.byte_offset_to_position(&content, offset));
        }
        let elapsed = start.elapsed();

        assert!(
            elapsed < std::time::Duration::from_millis(100),
            "8000 byte_offset_to_position calls on a minified line took {elapsed:?}, expected < 100ms"
        );
    }

    /// Regression guard for #882 (widened scope): `byte_offset_to_position`'s non-ASCII branch
    /// used to walk `chars().map(len_utf16).sum()` from the line's start on every call, so N
    /// lookups on the same wide non-ASCII line cost O(N x line length) — the same shape #882
    /// reported for `marker_byte_offset`, and, per the #882 review, ~300x its cost since
    /// `make_range` calls this twice per dependency. The shared per-line index makes every
    /// lookup after the first on a given line O(1).
    #[test]
    fn test_byte_offset_to_position_non_ascii_line_cache_stays_fast_on_a_huge_single_line() {
        let filler = "x".repeat(200 * 1024);
        let content = format!("{filler}\u{2014}{filler}");
        let table = LineOffsetTable::new(&content);
        let step = (content.len() / 5000).max(1);
        let start = std::time::Instant::now();
        for offset in (0..content.len()).step_by(step) {
            std::hint::black_box(table.byte_offset_to_position(&content, offset));
        }
        assert!(
            start.elapsed() < std::time::Duration::from_secs(1),
            "byte_offset_to_position took {:?} for ~5000 lookups on a huge non-ASCII line, \
             expected well under 1s",
            start.elapsed()
        );
    }

    /// Differential test: the cached non-ASCII path must agree with a plain reimplemented
    /// `chars().map(len_utf16).sum()` walk for every char-boundary offset on a non-ASCII line,
    /// including offsets on more than one non-ASCII line in the same document (cache isolation
    /// across lines, sharing the same underlying index `marker_byte_offset` populates).
    #[test]
    fn test_byte_offset_to_position_non_ascii_cache_matches_char_sum_result_across_lines() {
        fn slow_path(content: &str, line_start: usize, offset: usize) -> u32 {
            u32::try_from(
                content[line_start..offset]
                    .chars()
                    .map(char::len_utf16)
                    .sum::<usize>(),
            )
            .unwrap_or(u32::MAX)
        }

        let content = "\u{1f680}rocket \u{2014} dash\nascii line\n\u{3000}ideographic \u{e9}nd";
        let table = LineOffsetTable::new(content);
        let line_starts = [
            table.line_start(0).unwrap(),
            table.line_start(1).unwrap(),
            table.line_start(2).unwrap(),
        ];
        let line_ends = [line_starts[1] - 1, line_starts[2] - 1, content.len()];

        for (line, (&line_start, &line_end)) in line_starts.iter().zip(&line_ends).enumerate() {
            let line_text = &content[line_start..line_end];
            for (byte_offset, _) in line_text
                .char_indices()
                .chain(std::iter::once((line_text.len(), '\0')))
            {
                let offset = line_start + byte_offset;
                assert_eq!(
                    table.byte_offset_to_position(content, offset).character,
                    slow_path(content, line_start, offset),
                    "line {line} byte offset {byte_offset} desynced from the char-sum walk"
                );
            }
        }
    }

    #[test]
    fn test_position_in_range_inside() {
        let range = Range::new(Position::new(5, 10), Position::new(5, 20));
        let position = Position::new(5, 15);
        assert!(position_in_range(position, range));
    }

    #[test]
    fn test_position_in_range_at_start() {
        let range = Range::new(Position::new(5, 10), Position::new(5, 20));
        let position = Position::new(5, 10);
        assert!(position_in_range(position, range));
    }

    #[test]
    fn test_position_in_range_at_end() {
        let range = Range::new(Position::new(5, 10), Position::new(5, 20));
        let position = Position::new(5, 20);
        assert!(position_in_range(position, range));
    }

    #[test]
    fn test_position_in_range_before() {
        let range = Range::new(Position::new(5, 10), Position::new(5, 20));
        let position = Position::new(5, 5);
        assert!(!position_in_range(position, range));
    }

    #[test]
    fn test_position_in_range_after() {
        let range = Range::new(Position::new(5, 10), Position::new(5, 20));
        let position = Position::new(5, 25);
        assert!(!position_in_range(position, range));
    }

    #[test]
    fn test_position_in_range_different_line_before() {
        let range = Range::new(Position::new(5, 10), Position::new(5, 20));
        let position = Position::new(4, 15);
        assert!(!position_in_range(position, range));
    }

    #[test]
    fn test_position_in_range_different_line_after() {
        let range = Range::new(Position::new(5, 10), Position::new(5, 20));
        let position = Position::new(6, 15);
        assert!(!position_in_range(position, range));
    }

    #[test]
    fn test_position_in_range_multiline() {
        let range = Range::new(Position::new(5, 10), Position::new(7, 5));
        let position = Position::new(6, 0);
        assert!(position_in_range(position, range));
    }

    #[test]
    fn test_escape_markdown_link_breakout_payload() {
        let payload = "real-pkg](https://legit-looking-typosquat.example/download)[real-pkg";
        let escaped = escape_markdown(payload);
        assert_eq!(
            escaped,
            r"real\-pkg\]\(https\:\/\/legit\-looking\-typosquat\.example\/download\)\[real\-pkg"
        );
        assert!(!escaped.contains("]("));
    }

    #[test]
    fn test_escape_markdown_backslash_and_backtick() {
        assert_eq!(escape_markdown(r"a\b`c"), r"a\\b\`c");
    }

    #[test]
    fn test_escape_markdown_autolink_angle_brackets() {
        // `<...>` around a bare URL is a CommonMark autolink; `<`/`>` must be escaped
        // so it cannot render as a live link independent of the `[]`/`()` escaping.
        let escaped = escape_markdown("pkg <https://evil.example>");
        assert_eq!(escaped, r"pkg \<https\:\/\/evil\.example\>");
        assert!(!escaped.contains('<') || escaped.contains(r"\<"));
    }

    #[test]
    fn test_escape_markdown_control_chars_become_spaces() {
        assert_eq!(escape_markdown("a\nb"), "a b");
        assert_eq!(escape_markdown("a\r\nb"), "a  b");
        assert_eq!(escape_markdown("a\tb"), "a b");
        assert_eq!(escape_markdown("a\0b"), "a b");
    }

    #[test]
    fn test_escape_markdown_newline_cannot_break_out_of_heading() {
        // A raw newline used to terminate the ATX heading line early, letting the
        // rest of the name (potentially another "# [...](...)" sequence) render as
        // separate, unescaped Markdown blocks.
        let escaped = escape_markdown("react\n# [fake](https://evil.example)");
        assert!(!escaped.contains('\n'));
    }

    #[test]
    fn test_escape_markdown_hyphenated_name_round_trips_visually() {
        // Escaping a hyphen (ASCII punctuation) is visually inert on render — CommonMark
        // renders `\-` as a literal `-` — so common package names are unaffected in
        // practice even though the raw Markdown source now escapes them.
        assert_eq!(escape_markdown("tokio-util"), r"tokio\-util");
    }

    #[test]
    fn test_markdown_code_span_plain_content() {
        assert_eq!(markdown_code_span("1.0.0"), "`1.0.0`");
    }

    #[test]
    fn test_markdown_code_span_widens_fence_for_embedded_backticks() {
        assert_eq!(markdown_code_span("a`b"), "``a`b``");
        assert_eq!(markdown_code_span("``double``"), "``` ``double`` ```");
    }

    #[test]
    fn test_markdown_code_span_pads_when_content_starts_or_ends_with_backtick() {
        let span = markdown_code_span("`leading");
        assert!(span.starts_with("`` `"));
    }

    #[test]
    fn test_markdown_code_span_replaces_control_chars() {
        let span = markdown_code_span("1.0\n[evil](https://evil.example)");
        assert!(!span.contains('\n'));
    }

    #[test]
    fn test_markdown_code_span_empty_content() {
        assert_eq!(markdown_code_span(""), "` `");
    }

    #[test]
    fn test_markdown_code_span_backtick_payload_cannot_break_span() {
        // A payload closing the code span early to splice in a live link must not succeed.
        let payload = "1.0` <https://evil.example>` more";
        let span = markdown_code_span(payload);
        // The fence must be strictly longer than any backtick run in the content, so no
        // substring after the opening fence can act as a closing fence before the real one.
        let opening_fence_len = span.chars().take_while(|&c| c == '`').count();
        let inner = &span[opening_fence_len..span.len() - opening_fence_len];
        assert!(
            !inner.contains(&"`".repeat(opening_fence_len)),
            "content contains a run of backticks as long as the fence: {span}"
        );
    }

    #[test]
    fn test_escape_markdown_replaces_bidi_and_invisible_characters() {
        for c in [
            '\u{202E}',  // RLO — the Trojan Source vector
            '\u{2066}',  // LRI
            '\u{200B}',  // ZWSP
            '\u{2060}',  // WORD JOINER
            '\u{2028}',  // LS
            '\u{FEFF}',  // BOM
            '\u{FFFA}',  // interlinear annotation separator
            '\u{E0041}', // Unicode tag character ("A")
        ] {
            let escaped = escape_markdown(&format!("a{c}b"));
            assert_eq!(escaped, "a b", "{c:?} must be replaced with a space");
        }
    }

    /// #1323: `sanitize_invisible` already stripped these `Cf` characters while
    /// `is_markdown_unsafe`'s hand-picked list let them through.
    #[test]
    fn test_escape_markdown_replaces_1323_gap_characters() {
        for c in [
            '\u{00AD}',  // SOFT HYPHEN
            '\u{180E}',  // MONGOLIAN VOWEL SEPARATOR
            '\u{2061}',  // FUNCTION APPLICATION
            '\u{2062}',  // INVISIBLE TIMES
            '\u{2063}',  // INVISIBLE SEPARATOR
            '\u{2064}',  // INVISIBLE PLUS
            '\u{206A}',  // INHIBIT SYMMETRIC SWAPPING
            '\u{206B}',  // ACTIVATE SYMMETRIC SWAPPING
            '\u{206C}',  // INHIBIT ARABIC FORM SHAPING
            '\u{206D}',  // ACTIVATE ARABIC FORM SHAPING
            '\u{206E}',  // NATIONAL DIGIT SHAPES
            '\u{206F}',  // NOMINAL DIGIT SHAPES
            '\u{13430}', // Egyptian Hieroglyph format control (first)
            '\u{1343F}', // Egyptian Hieroglyph format control (last)
            '\u{1BCA0}', // Shorthand format control (first)
            '\u{1BCA3}', // Shorthand format control (last)
            '\u{1D173}', // Musical symbol format control (first)
            '\u{1D17A}', // Musical symbol format control (last)
        ] {
            let escaped = escape_markdown(&format!("a{c}b"));
            assert_eq!(escaped, "a b", "{c:?} must be replaced with a space");
        }
    }

    /// #1323 M1: U+2065 (unassigned, sitting inside the consolidated U+2060-U+206F range)
    /// is now deliberately swept in by the range rather than carved out, so a future
    /// Unicode assignment of it can't silently open a hole.
    #[test]
    fn test_escape_markdown_now_blocks_unassigned_u2065() {
        assert_eq!(escape_markdown("a\u{2065}b"), "a b");
    }

    /// #1323 must not regress #1248: legitimate directional marks and ZWNJ/ZWJ survive.
    #[test]
    fn test_escape_markdown_still_preserves_legitimate_bidi_marks_after_1323() {
        for c in ['\u{200F}', '\u{061C}', '\u{200E}', '\u{200C}', '\u{200D}'] {
            let escaped = escape_markdown(&format!("a{c}b"));
            assert_eq!(
                escaped,
                format!("a{c}b"),
                "{c:?} must survive verbatim (legitimate RTL/emoji use, #1248)"
            );
        }
    }

    /// #1323 M2/critic S2: prefixed-format signs with genuine Arabic/Syriac/Kaithi
    /// mid-string use must also survive — they were exempt before #1323 and remain so.
    #[test]
    fn test_escape_markdown_preserves_prefixed_format_signs() {
        for c in [
            '\u{0600}',
            '\u{0601}',
            '\u{0602}',
            '\u{0603}',
            '\u{0604}',
            '\u{0605}',
            '\u{06DD}',
            '\u{070F}',
            '\u{0890}',
            '\u{0891}',
            '\u{08E2}',
            '\u{110BD}',
            '\u{110CD}',
        ] {
            let escaped = escape_markdown(&format!("a{c}b"));
            assert_eq!(
                escaped,
                format!("a{c}b"),
                "{c:?} must survive verbatim (legitimate Arabic/Syriac/Kaithi use, #1248)"
            );
        }
    }

    /// #1323 critic S3: exhaustive drift guard. Scans the full Unicode code space and
    /// asserts that every character `sanitize_invisible` strips but `is_markdown_unsafe`
    /// does not is exactly the documented, named exempt set (#1248's RTL/ZWNJ/ZWJ marks
    /// plus the prefixed-format signs) — not a superset (an undocumented, silently
    /// widened exemption) and not a subset (a stale exempt-set constant hiding a real
    /// gap). Fails CI if `unicode-general-category` changes classification for any code
    /// point, or if either function's character list is hand-edited without updating the
    /// other.
    #[test]
    fn test_is_markdown_unsafe_exempt_set_matches_sanitize_invisible_drift_guard() {
        const EXEMPT_CHARS: &[char] = &[
            // #1248: RTL/ZWNJ/ZWJ marks, load-bearing in Persian/Arabic/Indic text shaping
            // and emoji ZWJ sequences.
            '\u{200E}',
            '\u{200F}',
            '\u{061C}',
            '\u{200C}',
            '\u{200D}',
            // #1248/critic S2: prefixed-format signs with genuine Arabic/Syriac/Kaithi
            // mid-string annotation use.
            '\u{0600}',
            '\u{0601}',
            '\u{0602}',
            '\u{0603}',
            '\u{0604}',
            '\u{0605}',
            '\u{06DD}',
            '\u{070F}',
            '\u{0890}',
            '\u{0891}',
            '\u{08E2}',
            '\u{110BD}',
            '\u{110CD}',
        ];

        let mut undocumented_exemptions = Vec::new();
        for cp in 0..=0x0010_FFFFu32 {
            let Some(c) = char::from_u32(cp) else {
                continue;
            };
            if crate::redact::is_invisible(c)
                && !is_markdown_unsafe(c)
                && !EXEMPT_CHARS.contains(&c)
            {
                undocumented_exemptions.push(c);
            }
        }
        assert!(
            undocumented_exemptions.is_empty(),
            "is_markdown_unsafe silently exempts characters sanitize_invisible strips, \
             outside the documented #1248/#1323 exempt set: {undocumented_exemptions:?}"
        );

        for &c in EXEMPT_CHARS {
            assert!(
                crate::redact::is_invisible(c) && !is_markdown_unsafe(c),
                "{c:?} is listed in the exempt set but is either not stripped by \
                 sanitize_invisible or is already blocked by is_markdown_unsafe — the \
                 exempt-set constant is stale"
            );
        }
    }

    /// #1276: `Diagnostic::new`/`RelatedInformation::new` apply `replace_markdown_unsafe_chars`
    /// on top of producer-side sanitization that may have already called it —
    /// double-application must be a no-op, since `' '` (the substitution) is not itself
    /// `is_markdown_unsafe`.
    #[test]
    fn test_replace_markdown_unsafe_chars_is_idempotent() {
        for c in [
            '\u{202E}',
            '\u{2066}',
            '\u{200B}',
            '\u{2060}',
            '\u{2028}',
            '\u{2029}',
            '\u{FEFF}',
            '\u{FFFA}',
            '\u{E0041}',
            '\n',
            '\t',
        ] {
            let input = format!("a{c}b");
            let once = replace_markdown_unsafe_chars(&input);
            assert_eq!(once, "a b", "{c:?} must be replaced with a single space");
            let twice = replace_markdown_unsafe_chars(&once);
            assert_eq!(twice, once, "{c:?} must not change on re-application");
        }
        assert!(
            !is_markdown_unsafe(' '),
            "substituted space must be stable under re-application"
        );
    }

    #[test]
    fn test_escape_markdown_preserves_legitimate_bidi_marks() {
        for c in [
            '\u{200F}', // RLM
            '\u{061C}', // ALM
            '\u{200E}', // LRM
            '\u{200D}', // ZWJ
        ] {
            let escaped = escape_markdown(&format!("a{c}b"));
            assert_eq!(
                escaped,
                format!("a{c}b"),
                "{c:?} must survive verbatim (legitimate RTL/emoji use)"
            );
        }
    }

    #[test]
    fn test_markdown_code_span_replaces_bidi_and_invisible_characters() {
        for c in [
            '\u{202E}',
            '\u{2066}',
            '\u{200B}',
            '\u{2060}',
            '\u{2029}',
            '\u{FEFF}',
            '\u{FFFA}',
            '\u{E0041}',
        ] {
            let span = markdown_code_span(&format!("a{c}b"));
            assert_eq!(span, "`a b`", "{c:?} must be replaced with a space");
        }
    }

    #[test]
    fn test_markdown_code_span_preserves_legitimate_bidi_marks() {
        for c in ['\u{200F}', '\u{061C}', '\u{200E}', '\u{200D}'] {
            let span = markdown_code_span(&format!("a{c}b"));
            assert_eq!(
                span,
                format!("`a{c}b`"),
                "{c:?} must survive verbatim (legitimate RTL/emoji use)"
            );
        }
    }

    #[test]
    fn test_is_same_major_minor_full_match() {
        assert!(is_same_major_minor("1.2.3", "1.2.9"));
    }

    #[test]
    fn test_is_same_major_minor_exact_match() {
        assert!(is_same_major_minor("1.2.3", "1.2.3"));
    }

    #[test]
    fn test_is_same_major_minor_major_only_match() {
        assert!(is_same_major_minor("1", "1.2.3"));
        assert!(is_same_major_minor("1.2.3", "1"));
    }

    #[test]
    fn test_is_same_major_minor_no_match_different_minor() {
        assert!(!is_same_major_minor("1.2.3", "1.3.0"));
    }

    #[test]
    fn test_is_same_major_minor_no_match_different_major() {
        assert!(!is_same_major_minor("1.2.3", "2.2.3"));
    }

    #[test]
    fn test_is_same_major_minor_empty_strings() {
        assert!(!is_same_major_minor("", ""));
        assert!(!is_same_major_minor("1.2.3", ""));
        assert!(!is_same_major_minor("", "1.2.3"));
    }

    #[test]
    fn test_requirement_contains_template_placeholder_bare_and_braced() {
        assert!(requirement_contains_template_placeholder("$REACT_VERSION"));
        assert!(requirement_contains_template_placeholder(
            "${REACT_VERSION}"
        ));
        assert!(requirement_contains_template_placeholder("1.0.0-$BUILD"));
        assert!(requirement_contains_template_placeholder(
            "v${MAJOR}.${MINOR}"
        ));
    }

    #[test]
    fn test_requirement_contains_template_placeholder_lowercase_and_mixed_case() {
        assert!(requirement_contains_template_placeholder("$react_version"));
        assert!(requirement_contains_template_placeholder(
            "${React_Version}"
        ));
    }

    #[test]
    fn test_requirement_contains_template_placeholder_ordinary_requirements_not_flagged() {
        assert!(!requirement_contains_template_placeholder("1.2.3"));
        assert!(!requirement_contains_template_placeholder("^1.2.3"));
        assert!(!requirement_contains_template_placeholder("~1.2.3"));
        assert!(!requirement_contains_template_placeholder(">=1.0.0 <2.0.0"));
        assert!(!requirement_contains_template_placeholder(""));
        assert!(!requirement_contains_template_placeholder("price-is-$5"));
        assert!(!requirement_contains_template_placeholder("trailing-$"));
        assert!(!requirement_contains_template_placeholder("empty-${}"));
        assert!(!requirement_contains_template_placeholder("${123}"));
    }

    #[test]
    fn test_requirement_contains_template_placeholder_unclosed_brace_fails_safe() {
        assert!(requirement_contains_template_placeholder("${VAR"));
    }

    #[test]
    fn test_requirement_contains_template_placeholder_dollar_paren_form() {
        assert!(requirement_contains_template_placeholder(
            "$(LODASH_VERSION)"
        ));
        assert!(requirement_contains_template_placeholder(
            "require golang.org/x/net $(NET_VERSION)"
        ));
    }

    /// #1417: unlike `${VAR`'s fail-open precedent, `$(` requires the closing `)` — an
    /// unclosed `$(VAR` must NOT be classified as a placeholder on that basis alone.
    #[test]
    fn test_requirement_contains_template_placeholder_dollar_paren_unclosed_not_matched() {
        assert!(!requirement_contains_template_placeholder("$(VAR"));
        assert!(!requirement_contains_template_placeholder(
            "price-is-$(five"
        ));
    }

    #[test]
    fn test_requirement_contains_template_placeholder_dollar_paren_no_identifier_not_matched() {
        assert!(!requirement_contains_template_placeholder("$()"));
        assert!(!requirement_contains_template_placeholder("$(123)"));
        assert!(!requirement_contains_template_placeholder(
            "$(SERDE VERSION)"
        ));
    }

    /// Spec 070 / issue #1421: `-` is accepted in subsequent positions inside `$(...)`, real
    /// MSBuild property-name syntax (`$(MOD-VERSION)`).
    #[test]
    fn test_requirement_contains_template_placeholder_dollar_paren_hyphen_form() {
        assert!(requirement_contains_template_placeholder("$(MOD-VERSION)"));
        assert!(requirement_contains_template_placeholder(
            "$(SERDE-VERSION)"
        ));
        assert!(requirement_contains_template_placeholder(
            "1.0.0-$(BUILD-SUFFIX)"
        ));
        assert!(!requirement_contains_template_placeholder("$(-VERSION)"));
    }

    /// Spec 070 / issue #1421 impl-critic M2: a trailing hyphen, consecutive hyphens, and a
    /// leading underscore followed by a hyphen are all still valid subsequent-position
    /// characters and must match; a bracketed content consisting of only a hyphen fails the
    /// first-character constraint (never a valid leading character) and must NOT match.
    #[test]
    fn test_requirement_contains_template_placeholder_dollar_paren_hyphen_edge_cases() {
        assert!(requirement_contains_template_placeholder("$(VERSION-)"));
        assert!(requirement_contains_template_placeholder("$(MOD--VERSION)"));
        assert!(requirement_contains_template_placeholder("$(_-X)"));
        assert!(!requirement_contains_template_placeholder("$(-)"));
    }

    /// Spec 070 / issue #1421: `.` anywhere before the closing `)` remains a deliberate,
    /// researched exclusion (not valid MSBuild syntax) — never matched, even combined with a
    /// hyphen.
    #[test]
    fn test_requirement_contains_template_placeholder_dollar_paren_dotted_form_not_matched() {
        assert!(!requirement_contains_template_placeholder("$(A.VERSION)"));
        assert!(!requirement_contains_template_placeholder(
            "$(MOD.SUB-VERSION)"
        ));
    }

    /// #1391 fixture/detector drift guard: every entry in
    /// [`crate::conformance::GENERIC_TEMPLATE_PLACEHOLDERS`] (the mandatory conformance
    /// fixture every ecosystem's `formatter_conformance!` invocation is checked against) must
    /// actually be recognized by the shared detector itself — otherwise a fixture entry that
    /// silently stopped matching would make every crate's conformance test pass vacuously
    /// instead of proving anything about that form.
    #[test]
    fn test_generic_template_placeholders_fixture_matches_detector() {
        for &placeholder in crate::conformance::GENERIC_TEMPLATE_PLACEHOLDERS {
            assert!(
                requirement_contains_template_placeholder(placeholder),
                "{placeholder:?} (from GENERIC_TEMPLATE_PLACEHOLDERS) must be recognized by \
                 requirement_contains_template_placeholder"
            );
        }
    }

    #[test]
    fn test_requirement_contains_template_placeholder_mustache_form() {
        assert!(requirement_contains_template_placeholder(
            "{{ STD_VERSION }}"
        ));
        assert!(requirement_contains_template_placeholder("{{STD_VERSION}}"));
        assert!(requirement_contains_template_placeholder(
            "{{ .NetVersion }}"
        ));
        assert!(requirement_contains_template_placeholder(
            "v1.2-{{ BUILD | default }}"
        ));
        // Unclosed still fails safe, mirroring the `${VAR` precedent.
        assert!(requirement_contains_template_placeholder("{{ VAR"));
    }

    #[test]
    fn test_requirement_contains_template_placeholder_mustache_empty_not_flagged() {
        assert!(!requirement_contains_template_placeholder("{{}}"));
        assert!(!requirement_contains_template_placeholder("{{ }}"));
    }

    /// Security M1 follow-up (impl-critic M1): `{% ... %}` Jinja2/Liquid statement tags
    /// alongside `{{ ... }}` expression tags.
    #[test]
    fn test_requirement_contains_template_placeholder_jinja_statement_tag() {
        assert!(requirement_contains_template_placeholder("{% if x %}"));
        assert!(requirement_contains_template_placeholder("{%if x%}"));
        assert!(requirement_contains_template_placeholder("{%- if x -%}"));
        assert!(requirement_contains_template_placeholder(
            "v1.2-{% BUILD %}"
        ));
        assert!(requirement_contains_template_placeholder("{% VAR"));
        assert!(!requirement_contains_template_placeholder("{%}"));
        assert!(!requirement_contains_template_placeholder("{% %}"));
    }

    #[test]
    fn test_requirement_contains_template_placeholder_autoconf_form() {
        assert!(requirement_contains_template_placeholder(
            "@PACKAGE_VERSION@"
        ));
        assert!(requirement_contains_template_placeholder("v1.2-@BUILD@"));
        // No closing '@' — not flagged (unlike the '$'/'{{' forms, both delimiters required).
        assert!(!requirement_contains_template_placeholder(
            "@PACKAGE_VERSION"
        ));
        assert!(!requirement_contains_template_placeholder("me@example.com"));
    }

    /// impl-critic M1: the dotted/hyphenated CMake/Autotools `configure_file` form — the
    /// actual common real-world `@..@` shape, unlike the bare-identifier form above.
    #[test]
    fn test_requirement_contains_template_placeholder_autoconf_dotted_form() {
        assert!(requirement_contains_template_placeholder(
            "@project.version@"
        ));
        assert!(requirement_contains_template_placeholder(
            "@PACKAGE_VERSION_MAJOR@"
        ));
        assert!(requirement_contains_template_placeholder("@some-flag@"));
        assert!(requirement_contains_template_placeholder(
            "v@project.version@"
        ));
        // No closing '@' — still not flagged, even with dots in the tail.
        assert!(!requirement_contains_template_placeholder(
            "@project.version"
        ));
    }

    #[test]
    fn test_requirement_contains_template_placeholder_percent_form() {
        assert!(requirement_contains_template_placeholder("%VERSION%"));
        assert!(requirement_contains_template_placeholder("v1.2-%BUILD%"));
        assert!(!requirement_contains_template_placeholder("%VERSION"));
        assert!(!requirement_contains_template_placeholder("100%"));
    }

    #[test]
    fn test_requirement_contains_template_placeholder_erb_form() {
        assert!(requirement_contains_template_placeholder("<%= version %>"));
        assert!(requirement_contains_template_placeholder("<%version%>"));
        assert!(requirement_contains_template_placeholder("<%- version %>"));
        assert!(!requirement_contains_template_placeholder("<%%>"));
        assert!(!requirement_contains_template_placeholder("<% %>"));
    }

    #[test]
    fn test_is_safe_version_string_accepts_ordinary_versions() {
        assert!(is_safe_version_string("1.2.3"));
        assert!(is_safe_version_string("1.2.3-beta.1+build"));
        assert!(is_safe_version_string("v1.2.3"));
    }

    #[test]
    fn test_is_safe_version_string_rejects_empty_or_whitespace() {
        assert!(!is_safe_version_string(""));
        assert!(!is_safe_version_string("   "));
        assert!(!is_safe_version_string("\t\n"));
    }

    #[test]
    fn test_is_safe_version_string_rejects_control_and_structural_characters() {
        for bad in [
            "1.2.3\n",
            "1.2.3\t",
            "1.2.3\"",
            "1.2.3'",
            "1.2.3<",
            "1.2.3>",
            "1.2.3&",
            "1.2.3\\",
            "1.0.0\", \"malicious\": \"true",
        ] {
            assert!(
                !is_safe_version_string(bad),
                "expected {bad:?} to be rejected"
            );
        }
    }

    #[test]
    fn test_is_safe_version_string_rejects_gradle_interpolation_payload() {
        // Regression (critic S2): `$`/`{`/`}` are outside the allowlist, so a Gradle
        // `${...}` interpolation payload can never reach a version literal via this gate.
        for bad in ["1.0${System.getenv(\"X\")}", "1.0$var", "${evil}"] {
            assert!(
                !is_safe_version_string(bad),
                "expected {bad:?} to be rejected"
            );
        }
    }

    #[test]
    fn test_is_safe_version_string_rejects_invisible_unicode() {
        // Regression (critic M1): `char::is_control()` alone only covers category Cc — the
        // bidi override U+202E, zero-width space U+200B, and JS/JSON5 line terminators
        // U+2028/U+2029 must also be rejected.
        for bad in ["1.2.3\u{202E}", "1.2.3\u{200B}", "1.2.3\u{2028}"] {
            assert!(
                !is_safe_version_string(bad),
                "expected {bad:?} to be rejected"
            );
        }
    }

    #[test]
    fn test_is_safe_version_string_accepts_pep440_epoch() {
        // PEP 440 epochs (`1!2.0`) are legitimate PyPI versions.
        assert!(is_safe_version_string("1!2.0"));
    }

    #[test]
    fn test_is_safe_version_string_length_cap() {
        assert!(is_safe_version_string(&"1".repeat(64)));
        assert!(!is_safe_version_string(&"1".repeat(65)));
    }

    #[test]
    fn test_is_safe_maven_coordinate_segment_accepts_real_ids() {
        assert!(is_safe_maven_coordinate_segment("org.apache.commons"));
        assert!(is_safe_maven_coordinate_segment("commons-lang3"));
        assert!(is_safe_maven_coordinate_segment("jackson-core_2.13"));
    }

    #[test]
    fn test_is_safe_maven_coordinate_segment_rejects_empty() {
        assert!(!is_safe_maven_coordinate_segment(""));
    }

    #[test]
    fn test_is_safe_maven_coordinate_segment_rejects_xml_structural_characters() {
        for bad in [
            "commons</artifactId><parent>",
            "commons\"",
            "commons'",
            "commons&amp;",
            "commons\nlang3",
            "commons\tlang3",
        ] {
            assert!(
                !is_safe_maven_coordinate_segment(bad),
                "expected {bad:?} to be rejected"
            );
        }
    }

    #[test]
    fn test_is_safe_maven_coordinate_segment_rejects_group_artifact_colon() {
        assert!(!is_safe_maven_coordinate_segment(
            "org.apache.commons:commons-lang3"
        ));
    }

    #[test]
    fn test_is_safe_maven_coordinate_segment_length_cap() {
        assert!(is_safe_maven_coordinate_segment(&"a".repeat(128)));
        assert!(!is_safe_maven_coordinate_segment(&"a".repeat(129)));
    }

    #[test]
    fn test_is_safe_registry_url_accepts_real_urls() {
        assert!(is_safe_registry_url("https://github.com/apple/swift-nio"));
        assert!(is_safe_registry_url(
            "https://github.com/apple/swift-nio.git"
        ));
        assert!(is_safe_registry_url("https://github.com/apple/swift%2Dnio"));
    }

    #[test]
    fn test_is_safe_registry_url_rejects_non_https_scheme() {
        // Every real Swift package registry response is HTTPS; accepting `http://` would
        // only hand a compromised registry a transport-downgrade lever.
        assert!(!is_safe_registry_url("http://example.com/repo"));
        assert!(!is_safe_registry_url("file:///etc/passwd"));
        assert!(!is_safe_registry_url("javascript:alert(1)"));
        assert!(!is_safe_registry_url("ftp://example.com/repo"));
        assert!(!is_safe_registry_url(""));
    }

    #[test]
    fn test_is_safe_registry_url_rejects_swift_string_literal_breakout() {
        for bad in [
            "https://evil.example\", .exact(\"1.0.0\")), .package(url: \"https://real",
            "https://evil.example\\",
            "https://evil.example\nlet x = 1",
            "https://evil.example`echo`",
            "https://evil.example<script>",
        ] {
            assert!(
                !is_safe_registry_url(bad),
                "expected {bad:?} to be rejected"
            );
        }
    }

    #[test]
    fn test_is_safe_registry_url_length_cap() {
        let prefix = "https://example.com/";
        let at_cap = format!("{prefix}{}", "a".repeat(2048 - prefix.len()));
        assert_eq!(at_cap.len(), 2048);
        assert!(is_safe_registry_url(&at_cap));

        let over_cap = format!("{at_cap}a");
        assert_eq!(over_cap.len(), 2049);
        assert!(!is_safe_registry_url(&over_cap));
    }

    #[test]
    fn test_is_safe_package_name_accepts_real_names_across_ecosystems() {
        for good in [
            "serde",                            // Cargo
            "requests",                         // PyPI
            "@scope/name",                      // npm/Deno scoped
            "monolog/monolog",                  // Composer vendor/package
            "github.com/org/repo",              // Go module path
            "path",                             // Dart
            "org.apache.commons:commons-lang3", // Gradle group:artifact
            "Newtonsoft.Json",                  // NuGet
            "rails",                            // Bundler
            "npm:react",                        // Deno npm-scheme specifier
            "jsr:@std/fs",                      // Deno jsr-scheme specifier
            "github.com/foo/bar~compat",        // Go path element with `~`
        ] {
            assert!(
                is_safe_package_name(good),
                "expected {good:?} to be accepted"
            );
        }
    }

    #[test]
    fn test_is_safe_package_name_rejects_empty() {
        assert!(!is_safe_package_name(""));
    }

    #[test]
    fn test_is_safe_package_name_rejects_non_ascii() {
        // Deliberately excluded: the allowlist is ASCII-only, so a legacy non-ASCII
        // npm package name (a handful exist, e.g. Unicode-normalized scopes) is
        // rejected rather than risking homograph/normalization tricks in a manifest.
        assert!(!is_safe_package_name("café"));
        assert!(!is_safe_package_name("пакет"));
    }

    #[test]
    fn test_is_safe_package_name_accepts_dot_dot_shapes() {
        // `.`/`/` are individually legal (PyPI dotted names, npm/Composer scopes), so
        // `..`/`../..` pass the charset too. This is not a path-traversal risk: every
        // sink treats `name` as manifest text (a TOML/JSON/YAML/XML value or a
        // string-literal argument), never as a filesystem path.
        assert!(is_safe_package_name(".."));
        assert!(is_safe_package_name("../.."));
    }

    #[test]
    fn test_is_safe_package_name_rejects_structural_breakout_characters() {
        for bad in [
            "evil\"\nbackdoor = \"9.9.9",
            "evil\", git = \"https://evil",
            "evil\\",
            "evil'",
            "evil<script>",
            "evil`echo`",
            "evil\ninjected = true",
            "evil\tname",
        ] {
            assert!(
                !is_safe_package_name(bad),
                "expected {bad:?} to be rejected"
            );
        }
    }

    #[test]
    fn test_is_safe_package_name_length_cap() {
        assert!(is_safe_package_name(&"a".repeat(256)));
        assert!(!is_safe_package_name(&"a".repeat(257)));
    }

    #[test]
    fn test_is_safe_feature_name_accepts_real_names() {
        for good in ["derive", "std_alloc-v2+extra"] {
            assert!(
                is_safe_feature_name(good),
                "expected {good:?} to be accepted"
            );
        }
    }

    #[test]
    fn test_is_safe_feature_name_rejects_empty() {
        assert!(!is_safe_feature_name(""));
    }

    #[test]
    fn test_is_safe_feature_name_rejects_non_ascii() {
        // ASCII-only, so homograph/bidi-spoofing characters are rejected outright.
        assert!(!is_safe_feature_name("café"));
        // U+202E RIGHT-TO-LEFT OVERRIDE.
        assert!(!is_safe_feature_name("evil\u{202E}reversed"));
    }

    #[test]
    fn test_is_safe_feature_name_rejects_enable_syntax() {
        // `dep:`/`?`/`/` are enable-syntax, only in a feature's value list, never in its name key.
        for bad in ["dep:ravif", "rgb?/serde"] {
            assert!(
                !is_safe_feature_name(bad),
                "expected {bad:?} to be rejected"
            );
        }
    }

    #[test]
    fn test_is_safe_feature_name_length_cap() {
        assert!(is_safe_feature_name(&"a".repeat(256)));
        assert!(!is_safe_feature_name(&"a".repeat(257)));
    }

    #[test]
    fn test_is_same_major_minor_partial_versions() {
        assert!(is_same_major_minor("1.2", "1.2.3"));
        assert!(is_same_major_minor("1.2.3", "1.2"));
    }

    #[test]
    fn test_ecosystem_formatter_defaults() {
        let formatter = MOCK_FORMATTER;
        assert_eq!(
            formatter.normalize_package_name(&pkg("test-pkg")),
            "test-pkg"
        );
        assert_eq!(formatter.yanked_message(), "This version has been yanked");
        assert_eq!(formatter.yanked_label(), "*(yanked)*");
    }

    #[test]
    fn test_format_version_replacing_for_default_delegates_to_format_version_replacing() {
        let formatter = MOCK_FORMATTER;
        let dep = MockDep {
            name: pkg("test-pkg"),
            version_req: VersionReq::new("1.0.0"),
            version_range: Range::default(),
            name_range: Range::default(),
        };
        assert_eq!(
            formatter.format_version_replacing_for(&dep, &ConcreteVersion::new("1.2.3"), "1.0.0"),
            formatter.format_version_replacing(&ConcreteVersion::new("1.2.3"), "1.0.0")
        );
    }

    #[test]
    fn test_ecosystem_formatter_version_satisfies() {
        let formatter = MOCK_FORMATTER;

        assert!(formatter.version_satisfies_requirement(
            &ConcreteVersion::new("1.2.3"),
            &VersionReq::new("1.2.3")
        ));

        assert!(formatter.version_satisfies_requirement(
            &ConcreteVersion::new("1.2.3"),
            &VersionReq::new("^1.2")
        ));
        assert!(formatter.version_satisfies_requirement(
            &ConcreteVersion::new("1.2.3"),
            &VersionReq::new("~1.2")
        ));

        assert!(
            formatter.version_satisfies_requirement(
                &ConcreteVersion::new("1.2.3"),
                &VersionReq::new("1")
            )
        );
        assert!(formatter.version_satisfies_requirement(
            &ConcreteVersion::new("1.2.3"),
            &VersionReq::new("1.2")
        ));

        assert!(!formatter.version_satisfies_requirement(
            &ConcreteVersion::new("1.2.3"),
            &VersionReq::new("2.0.0")
        ));
        assert!(!formatter.version_satisfies_requirement(
            &ConcreteVersion::new("1.2.3"),
            &VersionReq::new("1.3")
        ));
    }

    #[test]
    fn test_ecosystem_formatter_custom_normalize() {
        struct PyPIFormatter;

        impl PackageNaming for PyPIFormatter {
            fn normalize_package_name(&self, name: &PackageName) -> String {
                name.as_str().to_lowercase().replace('-', "_")
            }
        }

        impl PackageRendering for PyPIFormatter {
            fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
                format!(
                    ">={},<{}",
                    version,
                    version.as_str().split('.').next().unwrap_or("0")
                )
            }

            fn package_url(&self, name: &PackageName) -> String {
                format!("https://pypi.org/project/{}", name.as_str())
            }
        }

        impl RequirementResolution for PyPIFormatter {}

        impl DiagnosticMessages for PyPIFormatter {}

        impl DiagnosticPolicy for PyPIFormatter {}

        impl SourcePolicy for PyPIFormatter {}

        impl OsvNaming for PyPIFormatter {}

        let formatter = PyPIFormatter;
        assert_eq!(
            formatter.normalize_package_name(&pkg("Test-Package")),
            "test_package"
        );
        assert_eq!(
            formatter.format_version_for_text_edit(&ConcreteVersion::new("1.2.3")),
            ">=1.2.3,<1"
        );
        assert_eq!(
            formatter.package_url(&pkg("requests")),
            "https://pypi.org/project/requests"
        );
    }

    // --- upgrade_status_to_verdict structural staleness (issue #1531) ---

    /// A [`Dependency`] whose `source()` is configurable, for exercising the
    /// `NonRegistrySource` structural-skip staleness gate — [`MockDep`] always reports
    /// [`DependencySource::Registry`], which can't represent "started non-registry, source
    /// changed to registry".
    struct DepWithSource {
        name: PackageName,
        name_range: crate::position::Range,
        source: DependencySource,
    }

    impl Dependency for DepWithSource {
        fn name(&self) -> &PackageName {
            &self.name
        }
        fn name_range(&self) -> crate::position::Range {
            self.name_range
        }
        fn version_requirement(&self) -> Option<&VersionReq> {
            None
        }
        fn version_range(&self) -> Option<crate::position::Range> {
            None
        }
        fn source(&self) -> DependencySource {
            self.source.clone()
        }
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    fn structural_skip_entry() -> UpgradeStatus {
        UpgradeStatus::StructurallyUnchecked(StructuralSkipReason::NonRegistrySource)
    }

    /// Mirrors `deps-cargo`'s `CargoFormatter::source_is_public_registry_content` override
    /// (impl-critic S1, #1531): a verified crates.io mirror (`AlternateRegistry {
    /// mirrors_crates_io: true, .. }`, reached via a `[source.crates-io] replace-with` chain)
    /// counts as public-registry content alongside plain `Registry`. A local double rather than
    /// depending on `deps-cargo` from `deps-core` (wrong dependency direction).
    struct MockMirrorFormatter;
    impl PackageNaming for MockMirrorFormatter {}
    impl PackageRendering for MockMirrorFormatter {
        fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
            version.to_string()
        }
        fn package_url(&self, name: &PackageName) -> String {
            name.as_str().to_string()
        }
    }
    impl RequirementResolution for MockMirrorFormatter {}
    impl DiagnosticMessages for MockMirrorFormatter {}
    impl DiagnosticPolicy for MockMirrorFormatter {}
    impl SourcePolicy for MockMirrorFormatter {
        fn source_is_public_registry_content(&self, source: &DependencySource) -> bool {
            matches!(
                source,
                DependencySource::Registry
                    | DependencySource::AlternateRegistry {
                        mirrors_crates_io: true,
                        ..
                    }
            )
        }
    }
    impl OsvNaming for MockMirrorFormatter {}

    /// #1531 regression: a dependency whose source is *still* non-registry keeps the existing
    /// structural-fallback behavior — the cached `NonRegistrySource` skip is not stale, so it
    /// resolves to `NotApplicable` for both the "latest" and per-candidate verdicts.
    #[test]
    fn structural_skip_same_source_stays_not_applicable() {
        let dep = DepWithSource {
            name: pkg("vendored-lib"),
            name_range: crate::position::Range::default(),
            source: DependencySource::Path {
                path: "../vendored-lib".to_string(),
            },
        };
        let formatter = crate::test_util::StubFormatter::new();

        let mut latest_status = LatestStatusMap::new();
        latest_status.insert(
            crate::test_util::vuln_key("vendored-lib"),
            structural_skip_entry(),
        );
        assert_eq!(
            latest_verdict(
                Some(&latest_status),
                &dep,
                None,
                "vendored-lib",
                "1.0.0",
                &formatter
            ),
            LatestVerdict::NotApplicable
        );

        let mut candidate_status = CandidateStatusMap::new();
        candidate_status.insert(
            crate::test_util::vuln_key("vendored-lib"),
            CandidateStatuses::Structural(StructuralSkipReason::NonRegistrySource),
        );
        assert_eq!(
            candidate_verdict(
                Some(&candidate_status),
                &dep,
                None,
                "vendored-lib",
                "1.0.0",
                &formatter
            ),
            LatestVerdict::NotApplicable
        );
    }

    /// #1531: a dependency that *started* with a non-registry source (git/path) picks up a
    /// `CandidateUnverified{NonRegistrySource}` structural entry under its plain name key. If
    /// the manifest is then edited so the same dependency now resolves to a registry source,
    /// that cached entry is stale until the next phase B run overwrites it — the verdict must
    /// fail closed to `Unverified` for the new registry version, never silently pass through
    /// as `NotApplicable` ("safe to offer").
    #[test]
    fn structural_skip_source_changed_to_registry_is_not_stale_safe() {
        let dep = DepWithSource {
            name: pkg("vendored-lib"),
            name_range: crate::position::Range::default(),
            source: DependencySource::Registry,
        };
        let formatter = crate::test_util::StubFormatter::new();

        let mut latest_status = LatestStatusMap::new();
        latest_status.insert(
            crate::test_util::vuln_key("vendored-lib"),
            structural_skip_entry(),
        );
        assert_eq!(
            latest_verdict(
                Some(&latest_status),
                &dep,
                None,
                "vendored-lib",
                "2.0.0",
                &formatter
            ),
            LatestVerdict::Unverified
        );

        let mut candidate_status = CandidateStatusMap::new();
        candidate_status.insert(
            crate::test_util::vuln_key("vendored-lib"),
            CandidateStatuses::Structural(StructuralSkipReason::NonRegistrySource),
        );
        assert_eq!(
            candidate_verdict(
                Some(&candidate_status),
                &dep,
                None,
                "vendored-lib",
                "2.0.0",
                &formatter
            ),
            LatestVerdict::Unverified
        );
    }

    /// #1531 impl-critic S1: phase B classifies `NonRegistrySource` via
    /// `formatter.source_is_public_registry_content`, not a bare `DependencySource::Registry`
    /// match — an ecosystem like `deps-cargo` widens that predicate to also accept a verified
    /// crates.io mirror (`AlternateRegistry { mirrors_crates_io: true, .. }`). A path dependency
    /// edited to such a mirrored registry dependency must be recognized as a source change too,
    /// not stay wrongly `NotApplicable` just because it isn't the literal `Registry` variant.
    #[test]
    fn structural_skip_source_changed_to_mirrored_alternate_registry_is_not_stale_safe() {
        let dep = DepWithSource {
            name: pkg("vendored-lib"),
            name_range: crate::position::Range::default(),
            source: DependencySource::AlternateRegistry {
                index: "https://crates-mirror.example.com/index".to_string(),
                mirrors_crates_io: true,
            },
        };
        let formatter = MockMirrorFormatter;

        let mut latest_status = LatestStatusMap::new();
        latest_status.insert(
            crate::test_util::vuln_key("vendored-lib"),
            structural_skip_entry(),
        );
        assert_eq!(
            latest_verdict(
                Some(&latest_status),
                &dep,
                None,
                "vendored-lib",
                "2.0.0",
                &formatter
            ),
            LatestVerdict::Unverified
        );

        let mut candidate_status = CandidateStatusMap::new();
        candidate_status.insert(
            crate::test_util::vuln_key("vendored-lib"),
            CandidateStatuses::Structural(StructuralSkipReason::NonRegistrySource),
        );
        assert_eq!(
            candidate_verdict(
                Some(&candidate_status),
                &dep,
                None,
                "vendored-lib",
                "2.0.0",
                &formatter
            ),
            LatestVerdict::Unverified
        );
    }

    /// #1624 critique M3: `UnmappableName` is structural but — unlike `NonRegistrySource` —
    /// [`LatestStatusMap`] still records a real candidate version for it (see
    /// `deps_engine::classify::osv::build_latest_check_targets`), so it stays a
    /// `CandidateUnverified{version, reason}` entry there while [`CandidateStatusMap`] (which
    /// has no single-version slot for the whole dependency) represents the identical skip as
    /// `CandidateStatuses::Structural`. Both must resolve to `NotApplicable`.
    #[test]
    fn unmappable_name_resolves_to_not_applicable_for_latest_and_candidate() {
        let dep = DepWithSource {
            name: pkg("jsr-pinned"),
            name_range: crate::position::Range::default(),
            source: DependencySource::Registry,
        };
        let formatter = crate::test_util::StubFormatter::new();

        let mut latest_status = LatestStatusMap::new();
        latest_status.insert(
            crate::test_util::vuln_key("jsr-pinned"),
            UpgradeStatus::CandidateUnverified {
                version: ConcreteVersion::new("1.0.0"),
                reason: SkipReason::UnmappableName,
            },
        );
        assert_eq!(
            latest_verdict(
                Some(&latest_status),
                &dep,
                None,
                "jsr-pinned",
                "1.0.0",
                &formatter
            ),
            LatestVerdict::NotApplicable
        );

        let mut candidate_status = CandidateStatusMap::new();
        candidate_status.insert(
            crate::test_util::vuln_key("jsr-pinned"),
            CandidateStatuses::Structural(StructuralSkipReason::UnmappableName),
        );
        assert_eq!(
            candidate_verdict(
                Some(&candidate_status),
                &dep,
                None,
                "jsr-pinned",
                "1.0.0",
                &formatter
            ),
            LatestVerdict::NotApplicable
        );
    }

    /// Spec 076 SC-014: `fallback_edit_excludes_newer`, one test per [`FallbackEditRejection`]
    /// variant plus `Writable`. `deps-core` cannot depend on the ecosystem crates, so this
    /// module uses two stub formatters (a semver-backed stub mirroring Cargo's real semantics,
    /// and a NuGet-floor stub) — the same probe values are pinned against REAL formatters in
    /// `deps-cargo`/`deps-nuget` as part of T005/SC-018.
    mod fallback_edit_excludes_newer_tests {
        use super::*;
        use crate::ParseResult;
        use crate::edit::{ManifestEdit, ManifestReparse};
        use crate::position::Position;

        /// Real-semver-backed matcher, mirroring Cargo's actual resolution semantics.
        struct SemverMatcher(semver::VersionReq);
        impl RequirementMatcher for SemverMatcher {
            fn matches(&self, version: &ConcreteVersion) -> Option<bool> {
                semver::Version::parse(version.as_str())
                    .ok()
                    .map(|v| self.0.matches(&v))
            }
            fn strict_prerelease_exclusion(&self) -> bool {
                true
            }
        }

        /// SC-014's "semver-backed stub": real `semver::VersionReq` compilation, default
        /// `is_bounded_requirement_up_to_date`/`bounded_requirement_already_resolves_to` (Cargo-like).
        struct SemverFormatter;
        impl PackageNaming for SemverFormatter {}
        impl PackageRendering for SemverFormatter {
            fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
                version.to_string()
            }
            fn package_url(&self, name: &PackageName) -> String {
                name.as_str().to_string()
            }
        }
        impl RequirementResolution for SemverFormatter {
            fn compile_bounded_requirement(
                &self,
                requirement: BoundedVersionReq<'_>,
            ) -> Option<Box<dyn RequirementMatcher>> {
                semver::VersionReq::parse(requirement.as_str())
                    .ok()
                    .map(|req| Box::new(SemverMatcher(req)) as Box<dyn RequirementMatcher>)
            }
        }
        impl DiagnosticMessages for SemverFormatter {}
        impl DiagnosticPolicy for SemverFormatter {}
        impl SourcePolicy for SemverFormatter {}
        impl OsvNaming for SemverFormatter {}

        /// Same as [`SemverFormatter`], but `compile_bounded_requirement` fails for the literal text
        /// `"uncompilable"` — isolates the a1 `EditedUncompilable` check from a0, which a
        /// formatter that always fails to compile could not do (phase 1 would reject first).
        struct SelectivelyUncompilableFormatter;
        impl PackageNaming for SelectivelyUncompilableFormatter {}
        impl PackageRendering for SelectivelyUncompilableFormatter {
            fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
                version.to_string()
            }
            fn package_url(&self, name: &PackageName) -> String {
                name.as_str().to_string()
            }
        }
        impl RequirementResolution for SelectivelyUncompilableFormatter {
            fn compile_bounded_requirement(
                &self,
                requirement: BoundedVersionReq<'_>,
            ) -> Option<Box<dyn RequirementMatcher>> {
                if requirement.as_str() == "uncompilable" {
                    return None;
                }
                semver::VersionReq::parse(requirement.as_str())
                    .ok()
                    .map(|req| Box::new(SemverMatcher(req)) as Box<dyn RequirementMatcher>)
            }
        }
        impl DiagnosticMessages for SelectivelyUncompilableFormatter {}
        impl DiagnosticPolicy for SelectivelyUncompilableFormatter {}
        impl SourcePolicy for SelectivelyUncompilableFormatter {}
        impl OsvNaming for SelectivelyUncompilableFormatter {}

        /// A formatter with no `compile_bounded_requirement` override at all (trait default `None`) —
        /// for the a0 `OriginalUncompilable` check.
        struct NoCompileFormatter;
        impl PackageNaming for NoCompileFormatter {}
        impl PackageRendering for NoCompileFormatter {
            fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
                version.to_string()
            }
            fn package_url(&self, name: &PackageName) -> String {
                name.as_str().to_string()
            }
        }
        impl RequirementResolution for NoCompileFormatter {}
        impl DiagnosticMessages for NoCompileFormatter {}
        impl DiagnosticPolicy for NoCompileFormatter {}
        impl SourcePolicy for NoCompileFormatter {}
        impl OsvNaming for NoCompileFormatter {}

        /// Issue #1580 (CWE-400 defense-in-depth mirroring #1472/#1578): otherwise
        /// semver-backed like [`SemverFormatter`] — a real compiling matcher, so the a0-pre/a1-pre
        /// gates in `fallback_edit_excludes_newer` are the only thing rejecting an oversized
        /// requirement (`compile_bounded_requirement` cannot even receive one).
        struct SemverBackedFormatter;
        impl PackageNaming for SemverBackedFormatter {}
        impl PackageRendering for SemverBackedFormatter {
            fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
                version.to_string()
            }
            fn package_url(&self, name: &PackageName) -> String {
                name.as_str().to_string()
            }
        }
        impl RequirementResolution for SemverBackedFormatter {
            fn compile_bounded_requirement(
                &self,
                requirement: BoundedVersionReq<'_>,
            ) -> Option<Box<dyn RequirementMatcher>> {
                semver::VersionReq::parse(requirement.as_str())
                    .ok()
                    .map(|req| Box::new(SemverMatcher(req)) as Box<dyn RequirementMatcher>)
            }
        }
        impl DiagnosticMessages for SemverBackedFormatter {}
        impl DiagnosticPolicy for SemverBackedFormatter {}
        impl SourcePolicy for SemverBackedFormatter {}
        impl OsvNaming for SemverBackedFormatter {}

        /// A floor matcher: `matches` is membership at-or-above the floor (mirrors NuGet's
        /// bare `Version="X"` shape), but resolution never goes below OR above the floor
        /// itself — a floor always resolves to its own lowest member.
        struct NugetFloorMatcher(semver::Version);
        impl RequirementMatcher for NugetFloorMatcher {
            fn matches(&self, version: &ConcreteVersion) -> Option<bool> {
                semver::Version::parse(version.as_str())
                    .ok()
                    .map(|v| v >= self.0)
            }
            fn strict_prerelease_exclusion(&self) -> bool {
                false
            }
        }

        /// SC-014's "NuGet-floor stub" (spec 076 M2): `is_bounded_requirement_up_to_date` and
        /// `bounded_requirement_already_resolves_to` overridden with the floor rule — floor at or
        /// above target is up to date; a floor resolves ONLY to itself, never forward.
        struct NugetFloorFormatter;
        impl PackageNaming for NugetFloorFormatter {}
        impl PackageRendering for NugetFloorFormatter {
            fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
                version.to_string()
            }
            fn package_url(&self, name: &PackageName) -> String {
                name.as_str().to_string()
            }
        }
        impl RequirementResolution for NugetFloorFormatter {
            fn compile_bounded_requirement(
                &self,
                requirement: BoundedVersionReq<'_>,
            ) -> Option<Box<dyn RequirementMatcher>> {
                semver::Version::parse(requirement.as_str())
                    .ok()
                    .map(|floor| Box::new(NugetFloorMatcher(floor)) as Box<dyn RequirementMatcher>)
            }
            fn is_bounded_requirement_up_to_date(
                &self,
                requirement: BoundedVersionReq<'_>,
                latest: &ConcreteVersion,
            ) -> bool {
                semver::Version::parse(requirement.as_str())
                    .ok()
                    .zip(semver::Version::parse(latest.as_str()).ok())
                    .is_some_and(|(floor, latest)| floor >= latest)
            }
            fn bounded_requirement_already_resolves_to(
                &self,
                requirement: BoundedVersionReq<'_>,
                target: &ConcreteVersion,
            ) -> bool {
                semver::Version::parse(requirement.as_str())
                    .ok()
                    .zip(semver::Version::parse(target.as_str()).ok())
                    .is_some_and(|(floor, target)| floor == target)
            }
        }
        impl DiagnosticMessages for NugetFloorFormatter {}
        impl DiagnosticPolicy for NugetFloorFormatter {}
        impl SourcePolicy for NugetFloorFormatter {}
        impl OsvNaming for NugetFloorFormatter {}

        /// Fix-cycle (#1571) stub matcher for a `!=`-exclusion requirement grammar
        /// (PyPI/Composer/Bundler all support one): `requirement` is `"<range>,!=<excluded>"`,
        /// `<range>` compiled with real `semver::VersionReq` and `<excluded>` an exact,
        /// string-compared exclusion — mirrors the shape enough to prove the guard's floor
        /// comparison alone cannot see a hole punched inside an otherwise-matching span.
        struct ExclusionMatcher {
            range: semver::VersionReq,
            excluded: String,
        }
        impl RequirementMatcher for ExclusionMatcher {
            fn matches(&self, version: &ConcreteVersion) -> Option<bool> {
                if version.as_str() == self.excluded {
                    return Some(false);
                }
                semver::Version::parse(version.as_str())
                    .ok()
                    .map(|v| self.range.matches(&v))
            }
            fn strict_prerelease_exclusion(&self) -> bool {
                true
            }
            // Fix-cycle (#1571 critic S1): the intensional signal a real `!=` matcher
            // (PyPI/Composer/Bundler) provides — mirrors this stub's own `excluded` field
            // directly, the same way `Pep440Matcher`/`ComposerMatcher`/`RubygemsMatcher` read
            // their own parsed `!=` term instead of inferring it from `available`.
            fn explicitly_excludes(&self, version: &ConcreteVersion) -> bool {
                version.as_str() == self.excluded
            }
        }

        struct ExclusionFormatter;
        impl PackageNaming for ExclusionFormatter {}
        impl PackageRendering for ExclusionFormatter {
            fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
                version.to_string()
            }
            fn package_url(&self, name: &PackageName) -> String {
                name.as_str().to_string()
            }
        }
        impl RequirementResolution for ExclusionFormatter {
            fn compile_bounded_requirement(
                &self,
                requirement: BoundedVersionReq<'_>,
            ) -> Option<Box<dyn RequirementMatcher>> {
                let (range, excluded) = requirement.as_str().split_once(",!=")?;
                let range = semver::VersionReq::parse(range).ok()?;
                Some(Box::new(ExclusionMatcher {
                    range,
                    excluded: excluded.to_string(),
                }) as Box<dyn RequirementMatcher>)
            }
            // Never "already up to date" — isolates the new check from c0, mirroring how
            // `SemverFormatter`'s own default already keeps c0/d0 independent for its tests.
            fn is_bounded_requirement_up_to_date(
                &self,
                _requirement: BoundedVersionReq<'_>,
                _latest: &ConcreteVersion,
            ) -> bool {
                false
            }
        }
        impl DiagnosticMessages for ExclusionFormatter {}
        impl DiagnosticPolicy for ExclusionFormatter {}
        impl SourcePolicy for ExclusionFormatter {}
        impl OsvNaming for ExclusionFormatter {}

        struct StubDep {
            name: PackageName,
            requirement: Option<VersionReq>,
            version_start: Position,
        }
        impl Dependency for StubDep {
            fn name(&self) -> &PackageName {
                &self.name
            }
            fn name_range(&self) -> Range {
                Range::default()
            }
            fn version_requirement(&self) -> Option<&VersionReq> {
                self.requirement.as_ref()
            }
            fn version_range(&self) -> Option<Range> {
                Some(Range::new(self.version_start, self.version_start))
            }
            fn source(&self) -> crate::parser::DependencySource {
                crate::parser::DependencySource::Registry
            }
            fn as_any(&self) -> &dyn std::any::Any {
                self
            }
        }

        struct StubParseResult {
            deps: Vec<StubDep>,
            uri: url::Url,
        }
        impl ParseResult for StubParseResult {
            fn dependencies(&self) -> Vec<&dyn Dependency> {
                self.deps.iter().map(|d| d as &dyn Dependency).collect()
            }
            fn workspace_root(&self) -> Option<&std::path::Path> {
                None
            }
            fn uri(&self) -> &url::Url {
                &self.uri
            }
            fn as_any(&self) -> &dyn std::any::Any {
                self
            }
        }

        fn dep(requirement: &str) -> StubDep {
            StubDep {
                name: pkg("pkg"),
                requirement: Some(VersionReq::new(requirement)),
                version_start: Position::new(0, 0),
            }
        }

        /// Matches `dep()`'s own `version_range()` (a zero-width span at `version_start`) so
        /// the D5 `CandidateSpanMismatch` precondition passes for every test that isn't
        /// specifically exercising it.
        fn edit() -> ManifestEdit {
            ManifestEdit {
                range: Range::new(Position::new(0, 0), Position::new(0, 0)),
                new_text: "x".to_string(),
            }
        }

        fn versions(strs: &[&str]) -> Vec<ConcreteVersion> {
            strs.iter().map(|s| ConcreteVersion::new(*s)).collect()
        }

        fn reparsed_to(requirement: &str) -> impl ManifestReparse {
            let requirement = requirement.to_string();
            move |_content: &str| -> Option<Box<dyn ParseResult>> {
                Some(Box::new(StubParseResult {
                    deps: vec![StubDep {
                        name: pkg("pkg"),
                        requirement: Some(VersionReq::new(requirement.as_str())),
                        version_start: Position::new(0, 0),
                    }],
                    uri: crate::test_util::test_uri("/test/manifest.toml"),
                }))
            }
        }

        /// Issue #1580: R0 exceeds `MAX_REQUIREMENT_LEN` — the a0-pre gate must reject before
        /// `compile_bounded_requirement` is ever called; `SemverBackedFormatter`
        /// compiles normally, so only the gate can produce `Rejected`.
        #[test]
        fn original_oversized_a0_pre() {
            let oversized = "1".repeat(MAX_REQUIREMENT_LEN + 1);
            let verdict = fallback_edit_excludes_newer(
                &SemverBackedFormatter,
                &reparsed_to("1.1.0"),
                "content",
                &dep(&oversized),
                &edit(),
                &ConcreteVersion::new("1.1.0"),
                &versions(&["1.1.0"]),
            );
            assert_eq!(
                verdict,
                FallbackEditVerdict::Rejected(FallbackEditRejection::OriginalOversized)
            );
        }

        #[test]
        fn original_uncompilable_a0() {
            let verdict = fallback_edit_excludes_newer(
                &NoCompileFormatter,
                &reparsed_to("1.1.0"),
                "content",
                &dep("^1.0"),
                &edit(),
                &ConcreteVersion::new("1.1.0"),
                &versions(&["1.1.0"]),
            );
            assert_eq!(
                verdict,
                FallbackEditVerdict::Rejected(FallbackEditRejection::OriginalUncompilable)
            );
        }

        #[test]
        fn original_already_up_to_date_c0() {
            // NuGet-shaped floor `2.0.0`; a fallback below the floor is already "up to date".
            let verdict = fallback_edit_excludes_newer(
                &NugetFloorFormatter,
                &reparsed_to("1.9.0"),
                "content",
                &dep("2.0.0"),
                &edit(),
                &ConcreteVersion::new("1.9.0"),
                &versions(&["1.9.0"]),
            );
            assert_eq!(
                verdict,
                FallbackEditVerdict::Rejected(FallbackEditRejection::OriginalAlreadyUpToDate)
            );
        }

        #[test]
        fn original_resolves_past_fallback_d0() {
            // Absent-path downgrade: unedited `^2.0` already resolves to 2.0.0, strictly newer
            // than the 1.9.0 fallback.
            let verdict = fallback_edit_excludes_newer(
                &SemverFormatter,
                &reparsed_to("1.9.0"),
                "content",
                &dep("^2.0"),
                &edit(),
                &ConcreteVersion::new("1.9.0"),
                &versions(&["2.0.0", "1.9.0"]),
            );
            assert_eq!(
                verdict,
                FallbackEditVerdict::Rejected(FallbackEditRejection::OriginalResolvesPastFallback)
            );
        }

        #[test]
        fn original_excludes_fallback_via_not_equal() {
            // R0 ">=1.0.0,<2.0.0,!=1.5.0" (PyPI/Composer/Bundler `!=` shape): 1.5.0 sits inside
            // the nominal `[1.0.0,2.0.0)` span but is punched out by the exclusion, while 1.6.0
            // still matches and is strictly newer — the floor comparison alone (d0) would pass
            // this (the floor, 1.0.0, is not newer than 1.5.0), so only the #1571 check catches
            // it.
            let verdict = fallback_edit_excludes_newer(
                &ExclusionFormatter,
                &reparsed_to("1.5.0"),
                "content",
                &dep(">=1.0.0,<2.0.0,!=1.5.0"),
                &edit(),
                &ConcreteVersion::new("1.5.0"),
                &versions(&["1.6.0", "1.5.0", "1.0.0"]),
            );
            assert_eq!(
                verdict,
                FallbackEditVerdict::Rejected(FallbackEditRejection::OriginalExcludesFallback)
            );
        }

        #[test]
        fn original_excludes_fallback_via_not_equal_is_caught_even_when_vacuous() {
            // Critic fix-cycle S1: NO listed `available` entry strictly newer than `fallback`
            // matches R0 here (2.0.0 fails the `<2.0.0` ceiling too), so the purely structural
            // "some newer entry still matches" heuristic alone is vacuous — it cannot tell this
            // apart from `>=1.0.0,<1.5.0` (a legitimate ceiling) over the identical `available`
            // list. Only `RequirementMatcher::explicitly_excludes` catches it.
            let verdict = fallback_edit_excludes_newer(
                &ExclusionFormatter,
                &reparsed_to("1.5.0"),
                "content",
                &dep(">=1.0.0,<2.0.0,!=1.5.0"),
                &edit(),
                &ConcreteVersion::new("1.5.0"),
                &versions(&["2.0.0", "1.5.0", "1.0.0"]),
            );
            assert_eq!(
                verdict,
                FallbackEditVerdict::Rejected(FallbackEditRejection::OriginalExcludesFallback)
            );
        }

        #[test]
        fn ceiling_exceeding_fallback_is_not_excluded_via_not_equal_check() {
            // Cargo-shaped out-of-range acceptance (FR-025): `^1.0` fails `matches` for a
            // fallback of 2.5.0 too, but no R0-matching entry is newer than it — the #1571
            // check must not fire here, or it would reject spec 076's intentional
            // ceiling-exceeding case.
            let verdict = fallback_edit_excludes_newer(
                &SemverFormatter,
                &reparsed_to("^2.5.0"),
                "content",
                &dep("^1.0"),
                &edit(),
                &ConcreteVersion::new("2.5.0"),
                &versions(&["3.0.0", "2.5.0", "1.0.0"]),
            );
            assert_eq!(verdict, FallbackEditVerdict::Writable);
        }

        #[test]
        fn reparse_failed() {
            // R0 "1.0" is a caret [1.0.0,2.0.0) — fallback 1.5.0 sits at its own floor (the
            // only listed entry, matching), so phase 1 passes and re-parse is actually reached.
            let reparse = |_content: &str| -> Option<Box<dyn ParseResult>> { None };
            let verdict = fallback_edit_excludes_newer(
                &SemverFormatter,
                &reparse,
                "content",
                &dep("1.0"),
                &edit(),
                &ConcreteVersion::new("1.5.0"),
                &versions(&["1.5.0"]),
            );
            assert_eq!(
                verdict,
                FallbackEditVerdict::Rejected(FallbackEditRejection::ReparseFailed)
            );
        }

        #[test]
        fn occurrence_not_unique() {
            let reparse = |_content: &str| -> Option<Box<dyn ParseResult>> {
                Some(Box::new(StubParseResult {
                    deps: vec![
                        StubDep {
                            name: pkg("pkg"),
                            requirement: Some(VersionReq::new("1.5.0")),
                            version_start: Position::new(0, 0),
                        },
                        StubDep {
                            name: pkg("pkg"),
                            requirement: Some(VersionReq::new("1.5.0")),
                            version_start: Position::new(0, 0),
                        },
                    ],
                    uri: crate::test_util::test_uri("/test/manifest.toml"),
                }) as Box<dyn ParseResult>)
            };
            let verdict = fallback_edit_excludes_newer(
                &SemverFormatter,
                &reparse,
                "content",
                &dep("1.0"),
                &edit(),
                &ConcreteVersion::new("1.5.0"),
                &versions(&["1.5.0"]),
            );
            assert_eq!(
                verdict,
                FallbackEditVerdict::Rejected(FallbackEditRejection::OccurrenceNotUnique)
            );
        }

        /// Issue #1580: R1 (the re-parsed EDITED requirement) exceeds `MAX_REQUIREMENT_LEN` —
        /// R0 ("1.0") is small and compiles fine, so phase 1 passes and phase 2 is reached; the
        /// a1-pre gate must then reject before `compile_bounded_requirement(R1)` is ever called.
        #[test]
        fn edited_oversized_a1_pre() {
            let oversized = "1".repeat(MAX_REQUIREMENT_LEN + 1);
            let verdict = fallback_edit_excludes_newer(
                &SemverBackedFormatter,
                &reparsed_to(&oversized),
                "content",
                &dep("1.0"),
                &edit(),
                &ConcreteVersion::new("1.5.0"),
                &versions(&["1.5.0"]),
            );
            assert_eq!(
                verdict,
                FallbackEditVerdict::Rejected(FallbackEditRejection::EditedOversized)
            );
        }

        #[test]
        fn edited_uncompilable_a1() {
            let verdict = fallback_edit_excludes_newer(
                &SelectivelyUncompilableFormatter,
                &reparsed_to("uncompilable"),
                "content",
                &dep("1.0"),
                &edit(),
                &ConcreteVersion::new("1.5.0"),
                &versions(&["1.5.0"]),
            );
            assert_eq!(
                verdict,
                FallbackEditVerdict::Rejected(FallbackEditRejection::EditedUncompilable)
            );
        }

        #[test]
        fn edited_excludes_fallback_b1() {
            // The re-parse stub yields an unsatisfiable-for-the-fallback `^5` — round-1 critic
            // M5: the written edit must actually express the fallback, not merely compile.
            let verdict = fallback_edit_excludes_newer(
                &SemverFormatter,
                &reparsed_to("^5"),
                "content",
                &dep("1.0"),
                &edit(),
                &ConcreteVersion::new("1.5.0"),
                &versions(&["1.5.0"]),
            );
            assert_eq!(
                verdict,
                FallbackEditVerdict::Rejected(FallbackEditRejection::EditedExcludesFallback)
            );
        }

        #[test]
        fn edited_admits_newer_d1() {
            // R0 "2.0.0" is a caret [2.0.0,3.0.0), whose floor (2.0.1, the only listed match
            // at or above the fallback's own position) is at the fallback — phase 1 passes.
            // The re-parsed edit "2.0.1" is ALSO a caret ([2.0.1,3.0.0)), which still admits
            // the fresh 2.1.0 — d1 must reject that auto-follow regardless of d0's own verdict.
            let verdict = fallback_edit_excludes_newer(
                &SemverFormatter,
                &reparsed_to("2.0.1"),
                "content",
                &dep("2.0.0"),
                &edit(),
                &ConcreteVersion::new("2.0.1"),
                &versions(&["2.1.0", "2.0.1"]),
            );
            assert_eq!(
                verdict,
                FallbackEditVerdict::Rejected(FallbackEditRejection::EditedAdmitsNewer)
            );
        }

        #[test]
        fn writable() {
            let verdict = fallback_edit_excludes_newer(
                &SemverFormatter,
                &reparsed_to("^2.5.0"),
                "content",
                &dep("2.0"),
                &edit(),
                &ConcreteVersion::new("2.5.0"),
                &versions(&["3.0.0", "2.5.0"]),
            );
            assert_eq!(verdict, FallbackEditVerdict::Writable);
        }

        /// Spec 076 M2: the d0 `resolves_to` loosening for a NuGet `Located` floor. Spec 075
        /// rejected this (raw `matches` sees the floor as admitting the fresh version); this
        /// guard writes it, since a floor resolves only to its own lowest member.
        #[test]
        fn nuget_located_floor_loosening_is_writable() {
            // The floor's own value ("1.0.0") must be listed for the fix-cycle floor-comparison
            // scan to find it — realistic for production `available` (every published version,
            // unfiltered), since the floor is the user's own already-published declared pin.
            let verdict = fallback_edit_excludes_newer(
                &NugetFloorFormatter,
                &reparsed_to("1.1.0"),
                "content",
                &dep("1.0.0"),
                &edit(),
                &ConcreteVersion::new("1.1.0"),
                &versions(&["1.2.0", "1.1.0", "1.0.0"]),
            );
            assert_eq!(verdict, FallbackEditVerdict::Writable);
        }

        /// Fix-cycle (impl-critic M2, D5 precondition): a `candidate` whose range does not
        /// equal this occurrence's own `version_range()` (e.g. an edit built for a different
        /// line) must be rejected before any check reads it — not silently treated as
        /// `Writable` just because R0/R1 happen to agree (a NuGet-floor R0 that already equals
        /// its own fallback resolves to `Writable` under every other check here).
        #[test]
        fn candidate_span_mismatch_is_rejected() {
            let mismatched_candidate = ManifestEdit {
                range: Range::new(Position::new(1, 0), Position::new(1, 0)),
                new_text: "1.1.0".to_string(),
            };
            let verdict = fallback_edit_excludes_newer(
                &NugetFloorFormatter,
                &reparsed_to("1.1.0"),
                "content",
                &dep("1.0.0"),
                &mismatched_candidate,
                &ConcreteVersion::new("1.1.0"),
                &versions(&["1.2.0", "1.1.0"]),
            );
            assert_eq!(
                verdict,
                FallbackEditVerdict::Rejected(FallbackEditRejection::CandidateSpanMismatch)
            );
        }
    }
}
