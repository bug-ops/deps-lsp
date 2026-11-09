use tower_lsp_server::ls_types::{InlayHint, InlayHintKind, InlayHintLabel, InlayHintTooltip};

use crate::error::FetchFailure;
use crate::osv::{MatchOrigin, ScanOutcome};
use crate::{ConcreteVersion, Dependency, EcosystemConfig, PackageKey, TypedParseResult};

use super::diagnostics::{MAX_VERSION_DIAGNOSTIC_CHARS, flagged_detail};
use super::{
    DependencyFormatter, DependencyGate, EcosystemFormatter, LatestVerdict, LookupMiss,
    RequirementStatus, SiblingMatchNote, VersionData, in_use_version, latest_verdict,
    resolve_scan_outcome, sanitize_and_truncate_for_diagnostic,
};

/// Sanitizes and caps a version-shaped string (`latest` or `resolved_version`) for
/// interpolation into an inlay-hint label (#1268, code-review follow-up).
///
/// One small wrapper around `sanitize_and_truncate_for_diagnostic(_, MAX_VERSION_DIAGNOSTIC_CHARS)`
/// shared by all four sibling call sites in [`generate_inlay_hints`] (the offline
/// marker, the no-cached-latest up-to-date label, the `UpToDate` match arm, and the
/// `Outdated` match arm) rather than repeating the pair inline at each one — the exact
/// "fixed one sink, missed the sibling" pattern this PR's own S1 finding already
/// flagged once; a single call site here means a future change to the treatment only
/// needs updating in one place.
fn sanitize_hint_version(version: &str) -> String {
    sanitize_and_truncate_for_diagnostic(version, MAX_VERSION_DIAGNOSTIC_CHARS)
}

/// Fixed glyph and tooltip of a no-latest-version status marker.
struct StatusMarker {
    glyph: &'static str,
    tooltip: &'static str,
}

const INFO_GLYPH: &str = "ℹ";
const WARNING_GLYPH: &str = "⚠";

const NOT_LOOKED_UP_MARKER: StatusMarker = StatusMarker {
    glyph: INFO_GLYPH,
    tooltip: "Package not looked up; latest version unknown",
};

/// Which registry a [`LookupMiss`] came from; it picks the tooltip wording.
#[derive(Clone, Copy)]
enum MissRoute {
    Default,
    Alternate,
}

/// The marker for `miss` on `route`, shown with `glyph`.
///
/// [`LookupMiss::NotLookedUp`] is route-independent and always the neutral
/// [`NOT_LOOKED_UP_MARKER`].
const fn miss_marker(glyph: &'static str, route: MissRoute, miss: LookupMiss) -> StatusMarker {
    let tooltip = match (route, miss) {
        (_, LookupMiss::NotLookedUp) => return NOT_LOOKED_UP_MARKER,
        (MissRoute::Default, LookupMiss::NotFound) => {
            "Package not found in the registry; latest version unknown"
        }
        (MissRoute::Default, LookupMiss::NoComparableVersions) => {
            "No comparable registry version; latest version unknown"
        }
        (MissRoute::Alternate, LookupMiss::NotFound) => {
            "Package not found on the alternate registry; latest version unknown"
        }
        (MissRoute::Alternate, LookupMiss::NoComparableVersions) => {
            "No comparable version on the alternate registry; latest version unknown"
        }
    };
    StatusMarker { glyph, tooltip }
}

/// The neutral marker that replaces the up-to-date check mark when no latest version was verified.
///
/// Covers a `CustomRegistry` source the registry never queried (#1949) and an
/// `AlternateRegistry` source whose lookup miss diagnostics suppress (#1957): the miss is
/// expected there, but "up to date" was never confirmed, so it must not read as verified.
fn unverified_latest_marker(
    dep: &dyn crate::ecosystem::Dependency,
    key: &PackageKey,
    versions: VersionData<'_>,
    formatter: &dyn EcosystemFormatter,
) -> Option<StatusMarker> {
    use crate::parser::DependencySource;
    let source = dep.source();
    match source {
        DependencySource::CustomRegistry { .. } => {
            (!formatter.can_resolve_source(&source)).then_some(NOT_LOOKED_UP_MARKER)
        }
        DependencySource::AlternateRegistry { .. } => versions
            .lookup_miss_for(key)
            .map(|miss| miss_marker(INFO_GLYPH, MissRoute::Alternate, miss)),
        DependencySource::Registry
        | DependencySource::Git { .. }
        | DependencySource::Path { .. }
        | DependencySource::Url { .. }
        | DependencySource::Sdk { .. }
        | DependencySource::Workspace => None,
    }
}

/// The marker for a dependency whose registry lookup produced no latest version, or `None`.
///
/// A [`LookupMiss::NotLookedUp`] is a local decision (a bypassed or unroutable source), so it
/// reads the raw miss and renders the neutral `ℹ`: [`VersionData::reportable_lookup_miss`]
/// drops it, and its `AlternateRegistry` filter would drop the Go bypass too. The other
/// misses stay behind that gate and render `⚠`, matching diagnostics.
fn lookup_miss_marker(
    dep: &dyn crate::ecosystem::Dependency,
    key: &PackageKey,
    versions: VersionData<'_>,
    formatter: &dyn EcosystemFormatter,
) -> Option<StatusMarker> {
    if versions.lookup_miss_for(key) == Some(LookupMiss::NotLookedUp) {
        return Some(NOT_LOOKED_UP_MARKER);
    }
    let miss = versions.reportable_lookup_miss(dep, key, formatter)?;
    Some(miss_marker(WARNING_GLYPH, MissRoute::Default, miss))
}

/// Builds inlay hints showing the latest/in-use version next to each dependency's declaration.
///
/// Shared by every ecosystem's default
/// [`crate::TypedEcosystem::inlay_hints`] implementation: one hint is
/// emitted per dependency that has a version range, using `versions` and
/// `loading_state` to decide whether cached data is ready to render yet.
///
/// Status markers (the offline `📴`, the `⚠ {resolved}` shown when the registry lookup
/// failed for a lock-file dependency, #1884, and the neutral `ℹ {resolved}` for a dependency
/// that was never looked up, #1935) are fixed text, not configurable through
/// [`EcosystemConfig`], and appear regardless of `show_up_to_date_hints`. The one exception
/// is the `ℹ {resolved}` for a `CustomRegistry` dependency the registry never queried
/// (#1949) or an `AlternateRegistry` dependency with a suppressed lookup miss (#1957): it
/// replaces the up-to-date check mark, so it renders only when `show_up_to_date_hints` is on.
pub fn generate_inlay_hints<P, F>(
    parse_result: &P,
    versions: VersionData<'_>,
    loading_state: crate::LoadingState,
    config: &EcosystemConfig,
    formatter: &F,
) -> Vec<InlayHint>
where
    P: TypedParseResult,
    F: DependencyFormatter<Dep = P::Dep>,
{
    let deps = parse_result.own_dependencies();
    // Issue #1517: shared per-occurrence OSV lookup keys, mirroring every other renderer's
    // identical pattern — needed so `latest_verdict` can tell one duplicated-name occurrence's
    // latest-check result apart from another's.
    let ctx = HintContext {
        versions,
        loading_state,
        config,
        formatter,
        vuln_keys: super::hover::vuln_keys_for(parse_result, &versions, formatter),
    };
    let mut hints = Vec::with_capacity(deps.len());
    hints.extend(deps.iter().filter_map(|dep| inlay_hint_for(dep, &ctx)));
    hints
}

/// What every dependency's hint is rendered against.
struct HintContext<'a, F> {
    versions: VersionData<'a>,
    loading_state: crate::LoadingState,
    config: &'a EcosystemConfig,
    formatter: &'a F,
    vuln_keys: Option<crate::osv::VulnKeys>,
}

/// A hint at `position` carrying `label` and an optional plain-text `tooltip`.
fn type_hint(
    position: tower_lsp_server::ls_types::Position,
    label: String,
    tooltip: Option<String>,
) -> InlayHint {
    InlayHint {
        position,
        label: InlayHintLabel::String(label),
        kind: Some(InlayHintKind::TYPE),
        tooltip: tooltip.map(InlayHintTooltip::String),
        padding_left: Some(true),
        padding_right: None,
        text_edits: None,
        data: None,
    }
}

/// How the dependency's own OSV scan relates to the version its hint shows (#2003).
enum InUseAdvisoryState {
    /// No advisory, or the scan did not complete; the hint is unchanged.
    Clean,
    /// An advisory matches the shown version itself, or the list is a lower bound so an
    /// alternative-only claim cannot be made. Carries the advisory ids shown by the diagnostic.
    Primary(Vec<crate::osv::OsvId>),
    /// Every advisory matches only other lock-file entries, named by the tags.
    LockAlternativeOnly(crate::osv::MatchedTags),
}

fn in_use_advisory_state<F: DependencyFormatter>(
    dep: &F::Dep,
    key: &PackageKey,
    ctx: &HintContext<'_, F>,
) -> InUseAdvisoryState {
    let Some(vulnerabilities) = ctx.versions.vulnerabilities else {
        return InUseAdvisoryState::Clean;
    };
    let Some(ScanOutcome::Vulnerable(dv)) =
        resolve_scan_outcome(vulnerabilities, dep, ctx.vuln_keys.as_ref(), key)
    else {
        return InUseAdvisoryState::Clean;
    };
    match dv.sibling_only_tags() {
        Some(tags) if tags.origin() == MatchOrigin::LockEntry => {
            InUseAdvisoryState::LockAlternativeOnly(tags)
        }
        Some(_) | None => InUseAdvisoryState::Primary(
            dv.advisories_for_display()
                .items()
                .iter()
                .map(|advisory| advisory.id().clone())
                .collect(),
        ),
    }
}

/// The hint for one dependency, or `None` when it shows nothing.
///
/// A dependency with an OSV advisory gets a warning glyph and a tooltip: naming the other lock
/// entries when it is vulnerable only through them, naming the advisories otherwise. The hint
/// never shows a clean check mark the diagnostic contradicts.
fn inlay_hint_for<F: DependencyFormatter>(
    dep: &F::Dep,
    ctx: &HintContext<'_, F>,
) -> Option<InlayHint> {
    let mut hint = base_hint_for(dep, ctx)?;
    let key = PackageKey::new(dep.name(), ctx.formatter);
    match in_use_advisory_state(dep, &key, ctx) {
        InUseAdvisoryState::Clean => {}
        InUseAdvisoryState::Primary(ids) => flag_advisory(
            &mut hint,
            format!("Flagged by OSV.dev{}", flagged_detail(&ids, None)),
        ),
        InUseAdvisoryState::LockAlternativeOnly(tags) => flag_advisory(
            &mut hint,
            format!(
                "OSV.dev flags an advisory on another lock entry ({})",
                SiblingMatchNote::new(ctx.formatter, &tags)
            ),
        ),
    }
    Some(hint)
}

fn flag_advisory(hint: &mut InlayHint, detail: String) {
    let InlayHintLabel::String(label) = &mut hint.label else {
        return;
    };
    if !label.starts_with(['⚠', '🚫']) {
        *label = format!("⚠ {label}");
    }
    hint.tooltip = Some(InlayHintTooltip::String(match hint.tooltip.take() {
        Some(InlayHintTooltip::String(existing)) => format!("{existing}. {detail}"),
        Some(other) => {
            hint.tooltip = Some(other);
            return;
        }
        None => detail,
    }));
}

fn base_hint_for<F: DependencyFormatter>(
    dep: &F::Dep,
    ctx: &HintContext<'_, F>,
) -> Option<InlayHint> {
    let HintContext {
        versions,
        loading_state,
        config,
        formatter,
        ..
    } = ctx;
    let version_range: tower_lsp_server::ls_types::Range = dep.version_range()?.into();

    let key = PackageKey::new(dep.name(), *formatter);
    let latest_version = versions.cached_for(&key).map(|v| &v.latest);
    let resolved_version: Option<ConcreteVersion> =
        if (*formatter).manifest_requirement_is_resolved_version(dep) {
            dep.version_requirement()
                .map(|r| ConcreteVersion::new(r.as_str()))
        } else {
            in_use_version::resolve_occurrence_version(
                dep,
                &key,
                versions.resolved_map(),
                versions.candidates_map(),
                *formatter,
            )
            .cloned()
        };

    if super::version_range_is_synthetic_empty(dep) && resolved_version.is_none() {
        // Maven's `<version></version>` (#1161 M1 follow-up): `version_range()` is `Some`
        // purely so completion can locate the dependency at that position, but there is no
        // declared requirement to show a version hint against — skip, the same way a
        // manifest with no `<version>` tag at all (`version_range() == None`, caught by the
        // gate above) is already skipped. Without this, a dependency here would flash a
        // "Loading…" hint at the empty tag's position while `versions` is being fetched,
        // then vanish once `RequirementStatus::Unresolved` is reached.
        //
        // `version_range_is_synthetic_empty`, not a bare `version_requirement().is_none()`
        // (code-review follow-up, second round): Gradle's version-catalog `version.ref`
        // pointing at a dangling/rich-version alias legitimately has a REAL, non-empty
        // `version_range()` with `version_requirement()` still `None` — inlay hints
        // rendered for it before #1161, and a blanket check would have silently broken
        // that. Checked AFTER `resolved_version` is computed, not before (critic follow-up,
        // second round): a lockfile-derived `resolved_version` can be present even when
        // `version_requirement()` is `None` for a currently-unreached ecosystem/shape, and
        // the #483 I5/SEC-2 guarantee below never discards a purely-local, offline
        // `resolved_version` — skipping earlier would silently drop that hint instead.
        return None;
    }

    let position = version_range.end;
    if *loading_state == crate::LoadingState::Loading
        && config.show_loading_hints
        && latest_version.is_none()
    {
        return Some(type_hint(
            position,
            config.loading_text.clone(),
            Some("Fetching latest version...".to_string()),
        ));
    }

    let Some(latest) = latest_version else {
        return hint_without_latest(dep, &key, resolved_version.as_ref(), position, ctx);
    };

    let status = if let Some(resolved) = &resolved_version {
        if formatter
            .build_metadata_policy()
            .versions_equal(resolved.as_str(), latest.as_str())
        {
            RequirementStatus::UpToDate
        } else {
            RequirementStatus::Outdated
        }
    } else {
        match dep.version_requirement() {
            // `requirement_status_for`, matching `diagnostics.rs`'s `apply_outdated_rule`
            // (#907): lets e.g. `GithubActionsFormatter` prefer a SHA pin's
            // registry-confirmed tag over trusting its own comment text.
            Some(version_req) => (*formatter).requirement_status_for(dep, version_req, latest),
            // No declared requirement at all (e.g. a dangling alias/reference the
            // parser couldn't resolve to any string) — nothing was verified.
            None => RequirementStatus::Unresolved,
        }
    };

    let (label_text, flagged_tooltip) =
        hint_label(status, dep, &key, latest, resolved_version.as_ref(), ctx)?;

    // Issue #483 I5/SEC-2: `latest` here may be a warm-cache value fetched before an
    // online -> offline flip — without this, the badge is indistinguishable from live
    // data on this always-visible inline surface.
    let label_text = if config.network.is_offline() {
        format!("{label_text} 📴")
    } else {
        label_text
    };

    Some(type_hint(position, label_text, flagged_tooltip))
}

/// The hint for a dependency with no cached latest version: an offline or failed-lookup marker
/// over its locally known version, the up-to-date text, or nothing.
fn hint_without_latest<F: DependencyFormatter>(
    dep: &F::Dep,
    key: &PackageKey,
    resolved_version: Option<&ConcreteVersion>,
    position: tower_lsp_server::ls_types::Position,
    ctx: &HintContext<'_, F>,
) -> Option<InlayHint> {
    let HintContext {
        versions,
        config,
        formatter,
        ..
    } = ctx;
    // Issue #483 I5/SEC-2: never discard a purely-local, lockfile-derived
    // `resolved_version` just because the registry side is unknown while
    // offline — show it alongside the marker rather than replacing it.
    if config.network.is_offline() {
        let label = resolved_version.map_or_else(
            || "📴".to_string(),
            |resolved| format!("📴 {}", sanitize_hint_version(resolved.as_str())),
        );
        return Some(type_hint(
            position,
            label,
            Some("Offline: registry not checked".to_string()),
        ));
    }

    let resolved = resolved_version?;
    // #1884: an attempted-but-failed registry lookup must not read as "up to date".
    // Hardcoded status marker (like the offline `📴`), shown regardless of
    // `show_up_to_date_hints`; `NotAttempted` placeholders stay silent.
    if formatter.can_resolve_source(&dep.source())
        && versions
            .fetch_failure_for(key)
            .is_some_and(FetchFailure::was_attempted)
    {
        return Some(type_hint(
            position,
            format!("⚠ {}", sanitize_hint_version(resolved.as_str())),
            Some("Registry lookup failed; latest version unknown".to_string()),
        ));
    }

    if let Some(marker) = lookup_miss_marker(dep, key, *versions, *formatter) {
        return Some(type_hint(
            position,
            format!(
                "{} {}",
                marker.glyph,
                sanitize_hint_version(resolved.as_str())
            ),
            Some(marker.tooltip.to_string()),
        ));
    }

    config.show_up_to_date_hints.then(|| {
        match unverified_latest_marker(dep, key, *versions, *formatter) {
            Some(marker) => type_hint(
                position,
                format!(
                    "{} {}",
                    marker.glyph,
                    sanitize_hint_version(resolved.as_str())
                ),
                Some(marker.tooltip.to_string()),
            ),
            None => type_hint(
                position,
                format!(
                    "{} {}",
                    config.up_to_date_text,
                    sanitize_hint_version(resolved.as_str())
                ),
                None,
            ),
        }
    })
}

/// The label of a hint whose latest version is known, with the tooltip of a flagged one, or
/// `None` when the status shows nothing.
fn hint_label<F: DependencyFormatter>(
    status: RequirementStatus,
    dep: &F::Dep,
    key: &PackageKey,
    latest: &ConcreteVersion,
    resolved_version: Option<&ConcreteVersion>,
    ctx: &HintContext<'_, F>,
) -> Option<(String, Option<String>)> {
    let HintContext {
        versions,
        config,
        formatter,
        vuln_keys,
        ..
    } = ctx;
    match status {
        RequirementStatus::UpToDate => {
            if !config.show_up_to_date_hints {
                return None;
            }
            // #1526: a requirement can already admit `latest` (so `UpToDate`, not
            // `Outdated`) while `latest` itself is flagged — mirrors the `Outdated` arm's
            // identical `latest_verdict` check below, so this always-visible surface never
            // shows a plain checkmark for a range that already admits an OSV-flagged
            // version. Deliberately gated on `Flagged` only (not `Unverified`) — see
            // `diagnostics.rs`'s `push_flagged_latest_admitted_by_requirement` for why.
            let verdict = latest_verdict(
                versions.latest_status,
                dep,
                vuln_keys.as_ref(),
                key,
                latest.as_str(),
                *formatter,
            );
            if let LatestVerdict::Flagged {
                advisory_ids,
                malicious,
                via_sibling_tags,
            } = verdict
            {
                let icon = if malicious { "🚫" } else { "⚠️" };
                let note = via_sibling_tags
                    .as_ref()
                    .map(|tags| SiblingMatchNote::new(*formatter, tags));
                let tooltip = format!(
                    "This requirement already admits a version OSV.dev flags{} — do not \
                     rely on it being safe",
                    flagged_detail(&advisory_ids, note.as_ref())
                );
                Some((
                    format!("{icon} {}", sanitize_hint_version(latest.as_str())),
                    Some(tooltip),
                ))
            } else if let Some(resolved) = resolved_version {
                Some((
                    format!(
                        "{} {}",
                        config.up_to_date_text,
                        sanitize_hint_version(resolved.as_str())
                    ),
                    None,
                ))
            } else {
                Some((config.up_to_date_text.clone(), None))
            }
        }
        RequirementStatus::Outdated => {
            // Issue #1517: an OSV-flagged/malicious latest must never render with the same
            // plain "needs update" icon as an ordinary outdated version — that icon alone
            // reads as a routine, safe-to-click upgrade nudge on this always-visible surface.
            let verdict = latest_verdict(
                versions.latest_status,
                dep,
                vuln_keys.as_ref(),
                key,
                latest.as_str(),
                *formatter,
            );
            if let LatestVerdict::Flagged {
                advisory_ids,
                malicious,
                via_sibling_tags,
            } = verdict
            {
                let icon = if malicious { "🚫" } else { "⚠️" };
                let note = via_sibling_tags
                    .as_ref()
                    .map(|tags| SiblingMatchNote::new(*formatter, tags));
                let tooltip = format!(
                    "Flagged by OSV.dev{} — do not upgrade to this version",
                    flagged_detail(&advisory_ids, note.as_ref())
                );
                Some((
                    format!("{icon} {} flagged", sanitize_hint_version(latest.as_str())),
                    Some(tooltip),
                ))
            } else {
                Some((
                    config
                        .needs_update_text
                        .replace("{}", &sanitize_hint_version(latest.as_str())),
                    None,
                ))
            }
        }
        // Resolution failed (e.g. dangling alias/unexpanded variable) — neither
        // "up to date" nor "outdated" was actually verified, so show nothing.
        RequirementStatus::Unresolved => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lsp_helpers::test_support::*;
    use crate::lsp_helpers::test_support_lsp::*;
    use crate::lsp_helpers::*;

    /// #1161 M1 (critic follow-up): a dependency whose `version_range()` is `Some` but which
    /// has no `version_requirement()` — Maven's `<version></version>`, whose zero-width
    /// `version_range()` exists purely so completion can locate the dependency — must emit no
    /// hint at all, including no transient "Loading…" hint while `versions` is still being
    /// fetched. Without the `version_requirement().is_none()` skip, this dependency would
    /// flash a loading hint at the empty tag's position and then vanish once steady state
    /// (`RequirementStatus::Unresolved`) is reached, unlike every other "no version" shape
    /// (a manifest with no `<version>` tag at all, `version_range() == None`), which the
    /// gate right above already skips outright.
    #[test]
    fn test_generate_inlay_hints_skips_dependency_with_no_requirement_even_while_loading() {
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

        let formatter = MOCK_FORMATTER;
        let config = EcosystemConfig {
            show_up_to_date_hints: true,
            up_to_date_text: "✅".to_string(),
            needs_update_text: "❌ {}".to_string(),
            loading_text: "⏳".to_string(),
            show_loading_hints: true,
            network: crate::NetworkMode::Online,
        };

        let parse_result = MockMixedParseResult {
            deps: vec![Box::new(MockNoRequirementDep {
                name: "com.example:foo".into(),
                name_range: Range::new(Position::new(4, 18), Position::new(4, 21)).into(),
                version_range: Range::new(Position::new(5, 15), Position::new(5, 15)).into(),
            })],
            uri: crate::test_util::test_uri("/test/pom.xml"),
        };

        let hints_while_loading = generate_inlay_hints(
            &parse_result,
            VersionData::new(&HashMap::new(), &HashMap::new()),
            crate::LoadingState::Loading,
            &config,
            &formatter.for_dependency(),
        );
        assert!(
            hints_while_loading.is_empty(),
            "must not flash a Loading… hint for a dependency with no version_requirement"
        );

        let hints_loaded = generate_inlay_hints(
            &parse_result,
            VersionData::new(&HashMap::new(), &HashMap::new()),
            crate::LoadingState::Loaded,
            &config,
            &formatter.for_dependency(),
        );
        assert!(hints_loaded.is_empty());
    }

    /// Critic follow-up (M1, second round) to #1161: the `version_requirement().is_none()`
    /// skip must be checked AFTER `resolved_version` is computed, and must not fire when a
    /// lockfile-derived `resolved_version` is present even without a `version_requirement` —
    /// this is the #483 I5/SEC-2 guarantee ("never discard a purely-local, lockfile-derived
    /// `resolved_version`") applied to a dependency shape #1161 introduced. Uses the offline,
    /// no-`latest`-cached path so a hint renders purely from `resolved_version`.
    #[test]
    fn test_generate_inlay_hints_shows_resolved_version_hint_despite_no_requirement() {
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

        let formatter = MOCK_FORMATTER;
        let config = EcosystemConfig {
            show_up_to_date_hints: true,
            up_to_date_text: "✅".to_string(),
            needs_update_text: "❌ {}".to_string(),
            loading_text: "⏳".to_string(),
            show_loading_hints: true,
            network: crate::NetworkMode::Offline,
        };

        let parse_result = MockMixedParseResult {
            deps: vec![Box::new(MockNoRequirementDep {
                name: "com.example:foo".into(),
                name_range: Range::new(Position::new(4, 18), Position::new(4, 21)).into(),
                version_range: Range::new(Position::new(5, 15), Position::new(5, 15)).into(),
            })],
            uri: crate::test_util::test_uri("/test/pom.xml"),
        };

        let mut resolved_versions = HashMap::new();
        resolved_versions.insert(NormalizedName::for_test("com.example:foo"), "1.2.3".into());

        let hints = generate_inlay_hints(
            &parse_result,
            VersionData::new(&HashMap::new(), &resolved_versions),
            crate::LoadingState::Loaded,
            &config,
            &formatter.for_dependency(),
        );

        assert_eq!(
            hints.len(),
            1,
            "resolved_version alone must still produce a hint"
        );
        match &hints[0].label {
            InlayHintLabel::String(text) => assert_eq!(text, "📴 1.2.3"),
            _ => panic!("expected string label"),
        }
    }

    /// #1161 M1 code-review follow-up (second round): a REAL, non-empty `version_range()`
    /// with no `version_requirement()` — Gradle's version-catalog `version.ref` pointing at a
    /// dangling/rich-version alias — must still show the transient "Loading…" hint while
    /// `versions` is being fetched, exactly as it did before #1161 (this shape's
    /// `version_range()` alone gated inlay hints then, with no requirement check at all). A
    /// bare `version_requirement().is_none()` skip (the M1 fix's first attempt) would have
    /// suppressed this legitimate Gradle case identically to Maven's genuinely degenerate one.
    #[test]
    fn test_generate_inlay_hints_shows_loading_hint_for_non_empty_range_with_no_requirement() {
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

        let formatter = MOCK_FORMATTER;
        let config = EcosystemConfig {
            show_up_to_date_hints: true,
            up_to_date_text: "✅".to_string(),
            needs_update_text: "❌ {}".to_string(),
            loading_text: "⏳".to_string(),
            show_loading_hints: true,
            network: crate::NetworkMode::Online,
        };

        let parse_result = MockMixedParseResult {
            deps: vec![Box::new(MockNoRequirementDep {
                name: "com.example:guava".into(),
                name_range: Range::new(Position::new(1, 0), Position::new(1, 5)).into(),
                version_range: Range::new(Position::new(4, 40), Position::new(4, 45)).into(),
            })],
            uri: crate::test_util::test_uri("/test/libs.versions.toml"),
        };

        let hints = generate_inlay_hints(
            &parse_result,
            VersionData::new(&HashMap::new(), &HashMap::new()),
            crate::LoadingState::Loading,
            &config,
            &formatter.for_dependency(),
        );

        assert_eq!(
            hints.len(),
            1,
            "must still show the Loading… hint for a real, non-empty version_range"
        );
        match &hints[0].label {
            InlayHintLabel::String(text) => assert_eq!(text, "⏳"),
            _ => panic!("expected string label"),
        }
    }

    #[test]
    fn test_inlay_hint_exact_version_shows_update_needed() {
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

        let formatter = MOCK_FORMATTER;
        let config = EcosystemConfig {
            show_up_to_date_hints: true,
            up_to_date_text: "✅".to_string(),
            needs_update_text: "❌ {}".to_string(),
            loading_text: "⏳".to_string(),
            show_loading_hints: true,
            network: crate::NetworkMode::Online,
        };

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "serde".into(),
                version_req: "=2.0.12".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)).into(),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)).into(),
            }],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let mut cached_versions = HashMap::new();
        cached_versions.insert(
            NormalizedName::for_test("serde"),
            PackageVersions::latest_only("2.1.1"),
        );

        let mut resolved_versions = HashMap::new();
        resolved_versions.insert(NormalizedName::for_test("serde"), "2.0.12".into());

        let hints = generate_inlay_hints(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions),
            crate::LoadingState::Loaded,
            &config,
            &formatter,
        );

        assert_eq!(hints.len(), 1);
        match &hints[0].label {
            InlayHintLabel::String(text) => {
                assert_eq!(text, "❌ 2.1.1");
            }
            _ => panic!("Expected string label"),
        }
    }

    fn resolved_vs_latest_label<F: DependencyFormatter<Dep = MockDep>>(
        formatter: &F,
        resolved: &str,
        latest: &str,
    ) -> String {
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

        let config = EcosystemConfig {
            show_up_to_date_hints: true,
            up_to_date_text: "✅".to_string(),
            needs_update_text: "❌ {}".to_string(),
            loading_text: "⏳".to_string(),
            show_loading_hints: true,
            network: crate::NetworkMode::Online,
        };
        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "pkg".into(),
                version_req: "^0.8.0".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)).into(),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)).into(),
            }],
            uri: crate::test_util::test_uri("/test/pubspec.yaml"),
        };
        let mut cached_versions = HashMap::new();
        cached_versions.insert(
            NormalizedName::for_test("pkg"),
            PackageVersions::latest_only(latest),
        );
        let mut resolved_versions = HashMap::new();
        resolved_versions.insert(NormalizedName::for_test("pkg"), resolved.into());

        let hints = generate_inlay_hints(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions),
            crate::LoadingState::Loaded,
            &config,
            formatter,
        );
        assert_eq!(hints.len(), 1);
        match &hints[0].label {
            InlayHintLabel::String(text) => text.clone(),
            _ => panic!("expected string label"),
        }
    }

    /// #1687: a formatter whose build metadata is significant (Dart) must not render a
    /// lock-resolved `+1` build as up to date against a newer `+23` build.
    #[test]
    fn test_inlay_hint_significant_build_metadata_resolved_older_build_is_outdated() {
        let label = resolved_vs_latest_label(&MockBuildAwareFormatter, "0.8.13+1", "0.8.13+23");
        assert_eq!(label, "❌ 0.8.13+23");
        let label = resolved_vs_latest_label(&MockBuildAwareFormatter, "0.8.13+23", "0.8.13+23");
        assert!(label.starts_with("✅"), "got: {label}");
    }

    /// SemVer ecosystems keep ignoring build metadata (#1671).
    #[test]
    fn test_inlay_hint_ignored_build_metadata_resolved_build_difference_is_up_to_date() {
        let label = resolved_vs_latest_label(&MOCK_FORMATTER, "1.2.3+1", "1.2.3+23");
        assert!(label.starts_with("✅"), "got: {label}");
    }

    /// Issue #1517 (the P0 this fix addresses): an OSV-flagged/malicious latest must render
    /// with a distinct icon and tooltip, never the plain "needs update" `❌` badge that reads
    /// as a routine, safe-to-click upgrade nudge.
    #[test]
    fn test_inlay_hint_outdated_flagged_by_osv_uses_distinct_label_and_tooltip() {
        use crate::osv::{Capped, LatestStatusMap, UpgradeStatus, VulnSeverity};
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

        let formatter = MOCK_FORMATTER;
        let config = EcosystemConfig {
            show_up_to_date_hints: true,
            up_to_date_text: "✅".to_string(),
            needs_update_text: "❌ {}".to_string(),
            loading_text: "⏳".to_string(),
            show_loading_hints: true,
            network: crate::NetworkMode::Online,
        };

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "feed-widget-helper".into(),
                version_req: "1.0.4".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)).into(),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)).into(),
            }],
            uri: crate::test_util::test_uri("/test/package.json"),
        };

        let mut cached_versions = HashMap::new();
        cached_versions.insert(
            NormalizedName::for_test("feed-widget-helper"),
            PackageVersions::latest_only("1.0.8"),
        );
        let resolved_versions = HashMap::new();

        let mut latest_status = LatestStatusMap::new();
        latest_status.insert(
            crate::test_util::vuln_key("feed-widget-helper"),
            UpgradeStatus::CandidateVulnerable {
                version: ConcreteVersion::new("1.0.8"),
                advisory_ids: Capped::new(vec![crate::test_util::osv_id("MAL-2026-16332")], 1),
                worst_severity: Some(VulnSeverity::Malicious),
                via_sibling_tags: None,
            },
        );

        let hints = generate_inlay_hints(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions)
                .with_latest_status(&latest_status),
            crate::LoadingState::Loaded,
            &config,
            &formatter,
        );

        assert_eq!(hints.len(), 1);
        match &hints[0].label {
            InlayHintLabel::String(text) => {
                assert!(
                    !text.starts_with('❌'),
                    "must not use the plain badge: {text}"
                );
                assert!(text.contains("1.0.8"), "got: {text}");
                assert!(text.contains("flagged"), "got: {text}");
            }
            InlayHintLabel::LabelParts(_) => panic!("Expected string label"),
        }
        match &hints[0].tooltip {
            Some(InlayHintTooltip::String(tooltip)) => {
                assert!(tooltip.contains("MAL-2026-16332"), "got: {tooltip}");
            }
            other => panic!("expected a tooltip naming the advisory, got: {other:?}"),
        }
    }

    /// The tooltip of the single inlay hint for a `version_req` dependency whose cached latest
    /// `1.0.8` is OSV-flagged through the sibling tag `v4.9.0`.
    fn sibling_flagged_latest_tooltip(version_req: &str) -> String {
        use crate::osv::{Capped, LatestStatusMap, MatchedTags, UpgradeStatus, VulnSeverity};
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

        let config = EcosystemConfig {
            show_up_to_date_hints: true,
            up_to_date_text: "✅".to_string(),
            needs_update_text: "❌ {}".to_string(),
            loading_text: "⏳".to_string(),
            show_loading_hints: true,
            network: crate::NetworkMode::Online,
        };
        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "widget".into(),
                version_req: version_req.into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)).into(),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)).into(),
            }],
            uri: crate::test_util::test_uri("/test/package.json"),
        };
        let mut cached_versions = HashMap::new();
        cached_versions.insert(
            NormalizedName::for_test("widget"),
            PackageVersions::latest_only("1.0.8"),
        );
        let resolved_versions = HashMap::new();
        let mut latest_status = LatestStatusMap::new();
        latest_status.insert(
            crate::test_util::vuln_key("widget"),
            UpgradeStatus::CandidateVulnerable {
                version: ConcreteVersion::new("1.0.8"),
                advisory_ids: Capped::new(vec![crate::test_util::osv_id("A-1")], 1),
                worst_severity: Some(VulnSeverity::High),
                via_sibling_tags: Some(MatchedTags::new(ConcreteVersion::new("v4.9.0"), vec![])),
            },
        );

        let hints = generate_inlay_hints(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions)
                .with_latest_status(&latest_status),
            crate::LoadingState::Loaded,
            &config,
            &MOCK_FORMATTER,
        );
        assert_eq!(hints.len(), 1);
        match &hints[0].tooltip {
            Some(InlayHintTooltip::String(tooltip)) => tooltip.clone(),
            other => panic!("expected a string tooltip, got: {other:?}"),
        }
    }

    /// #1782: the flagged-latest tooltip names the sibling tags in the `Outdated` arm.
    #[test]
    fn test_inlay_hint_outdated_flagged_tooltip_names_sibling_tags() {
        let tooltip = sibling_flagged_latest_tooltip("1.0.4");
        assert!(
            tooltip.contains("A-1; matched tag v4.9.0"),
            "got: {tooltip}"
        );
        assert!(tooltip.starts_with("Flagged by OSV.dev"), "got: {tooltip}");
    }

    /// #1782: the flagged-latest tooltip names the sibling tags in the `UpToDate` arm.
    #[test]
    fn test_inlay_hint_up_to_date_flagged_tooltip_names_sibling_tags() {
        let tooltip = sibling_flagged_latest_tooltip("^1.0.4");
        assert!(
            tooltip.contains("A-1; matched tag v4.9.0"),
            "got: {tooltip}"
        );
        assert!(
            tooltip.starts_with("This requirement already admits"),
            "got: {tooltip}"
        );
    }

    /// Issue #1526: a caret requirement already admits `latest` (`UpToDate`, not `Outdated`),
    /// but `latest` itself is OSV-flagged malicious — the inlay hint must not render a plain
    /// up-to-date checkmark for it.
    #[test]
    fn test_inlay_hint_up_to_date_admitted_latest_flagged_by_osv_uses_distinct_label_and_tooltip() {
        use crate::osv::{Capped, LatestStatusMap, UpgradeStatus, VulnSeverity};
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

        let formatter = MOCK_FORMATTER;
        let config = EcosystemConfig {
            show_up_to_date_hints: true,
            up_to_date_text: "✅".to_string(),
            needs_update_text: "❌ {}".to_string(),
            loading_text: "⏳".to_string(),
            show_loading_hints: true,
            network: crate::NetworkMode::Online,
        };

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "feed-widget-helper".into(),
                version_req: "^1.0.4".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)).into(),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)).into(),
            }],
            uri: crate::test_util::test_uri("/test/package.json"),
        };

        let mut cached_versions = HashMap::new();
        cached_versions.insert(
            NormalizedName::for_test("feed-widget-helper"),
            PackageVersions::latest_only("1.0.8"),
        );
        // No lock file / resolved version — status comes from `requirement_status_for`
        // admitting `1.0.8` under `^1.0.4`, not from a resolved==latest comparison.
        let resolved_versions = HashMap::new();

        let mut latest_status = LatestStatusMap::new();
        latest_status.insert(
            crate::test_util::vuln_key("feed-widget-helper"),
            UpgradeStatus::CandidateVulnerable {
                version: ConcreteVersion::new("1.0.8"),
                advisory_ids: Capped::new(vec![crate::test_util::osv_id("MAL-2026-16332")], 1),
                worst_severity: Some(VulnSeverity::Malicious),
                via_sibling_tags: None,
            },
        );

        let hints = generate_inlay_hints(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions)
                .with_latest_status(&latest_status),
            crate::LoadingState::Loaded,
            &config,
            &formatter,
        );

        assert_eq!(hints.len(), 1);
        match &hints[0].label {
            InlayHintLabel::String(text) => {
                assert!(
                    !text.starts_with('✅'),
                    "must not use the plain up-to-date badge: {text}"
                );
                assert!(text.contains("1.0.8"), "got: {text}");
            }
            InlayHintLabel::LabelParts(_) => panic!("Expected string label"),
        }
        match &hints[0].tooltip {
            Some(InlayHintTooltip::String(tooltip)) => {
                assert!(tooltip.contains("MAL-2026-16332"), "got: {tooltip}");
            }
            other => panic!("expected a tooltip naming the advisory, got: {other:?}"),
        }
    }

    /// #2003: an advisory on another lock entry only must not leave a clean check mark.
    #[test]
    fn test_inlay_hint_lock_alternative_only_advisory_shows_warning_and_tooltip() {
        use crate::osv::{
            Capped, DependencyVulnerabilities, MatchedTags, OsvVersion, ScanOutcome, VulnSeverity,
            VulnerabilityMap,
        };
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

        let formatter = MOCK_FORMATTER;
        let config = EcosystemConfig {
            show_up_to_date_hints: true,
            up_to_date_text: "✅".to_string(),
            needs_update_text: "❌ {}".to_string(),
            loading_text: "⏳".to_string(),
            show_loading_hints: true,
            network: crate::NetworkMode::Online,
        };
        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "pkg".into(),
                version_req: "^1.0.0".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)).into(),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)).into(),
            }],
            uri: crate::test_util::test_uri("/test/package.json"),
        };
        let mut cached_versions = HashMap::new();
        cached_versions.insert(
            NormalizedName::for_test("pkg"),
            PackageVersions::latest_only("1.0.8"),
        );
        let resolved_versions = HashMap::new();

        let advisory = sample_advisory("GHSA-aaaa-bbbb-cccc", VulnSeverity::High);
        let id = advisory.id().clone();
        let hints_for = |dv: DependencyVulnerabilities| {
            let mut vulns = VulnerabilityMap::new();
            vulns.insert(
                crate::test_util::vuln_key("pkg"),
                ScanOutcome::Vulnerable(dv),
            );
            generate_inlay_hints(
                &parse_result,
                VersionData::new(&cached_versions, &resolved_versions).with_vulnerabilities(&vulns),
                crate::LoadingState::Loaded,
                &config,
                &formatter,
            )
        };

        let primary = hints_for(DependencyVulnerabilities::new(Capped::new(
            vec![advisory.clone()],
            1,
        )));
        assert_eq!(primary.len(), 1);
        assert!(
            matches!(&primary[0].label, InlayHintLabel::String(t) if t.starts_with("⚠ ")),
            "got: {:?}",
            primary[0].label
        );
        assert!(matches!(
            &primary[0].tooltip,
            Some(InlayHintTooltip::String(t)) if t.contains("GHSA-aaaa-bbbb-cccc")
        ));

        let lower_bound = hints_for(DependencyVulnerabilities::new(
            Capped::new(vec![advisory.clone()], 1).with_total_as_lower_bound(),
        ));
        assert!(
            matches!(&lower_bound[0].label, InlayHintLabel::String(t) if t.starts_with("⚠ ")),
            "an incomplete union must not keep the check mark: {:?}",
            lower_bound[0].label
        );

        let clean = generate_inlay_hints(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions),
            crate::LoadingState::Loaded,
            &config,
            &formatter,
        );
        assert!(matches!(&clean[0].label, InlayHintLabel::String(t) if t.starts_with('✅')));
        assert!(clean[0].tooltip.is_none());

        let alternative_only = hints_for(
            DependencyVulnerabilities::new(Capped::new(vec![advisory], 1))
                .with_sibling_matches_for_test(
                    OsvVersion::new("1.0.8"),
                    [(
                        id,
                        MatchedTags::lock_entries_for_test(ConcreteVersion::new("1.0.2"), vec![]),
                    )],
                ),
        );
        assert_eq!(alternative_only.len(), 1);
        assert!(
            matches!(&alternative_only[0].label, InlayHintLabel::String(t) if t.starts_with("⚠ ")),
            "got: {:?}",
            alternative_only[0].label
        );
        match &alternative_only[0].tooltip {
            Some(InlayHintTooltip::String(tooltip)) => {
                assert!(tooltip.contains("also locked at 1.0.2"), "got: {tooltip}");
            }
            other => panic!("expected a tooltip naming the lock entry, got: {other:?}"),
        }
    }

    #[test]
    fn test_inlay_hint_caret_version_up_to_date() {
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

        let formatter = MOCK_FORMATTER;
        let config = EcosystemConfig {
            show_up_to_date_hints: true,
            up_to_date_text: "✅".to_string(),
            needs_update_text: "❌ {}".to_string(),
            loading_text: "⏳".to_string(),
            show_loading_hints: true,
            network: crate::NetworkMode::Online,
        };

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "serde".into(),
                version_req: "^2.0".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)).into(),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)).into(),
            }],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let mut cached_versions = HashMap::new();
        cached_versions.insert(
            NormalizedName::for_test("serde"),
            PackageVersions::latest_only("2.1.1"),
        );

        let mut resolved_versions = HashMap::new();
        resolved_versions.insert(NormalizedName::for_test("serde"), "2.1.1".into());

        let hints = generate_inlay_hints(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions),
            crate::LoadingState::Loaded,
            &config,
            &formatter,
        );

        assert_eq!(hints.len(), 1);
        match &hints[0].label {
            InlayHintLabel::String(text) => {
                assert!(
                    text.starts_with("✅"),
                    "Expected up-to-date hint, got: {}",
                    text
                );
            }
            _ => panic!("Expected string label"),
        }
    }

    #[test]
    fn test_inlay_hint_go_prefers_manifest_requirement_over_stale_resolved_version() {
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

        let formatter = MOCK_GO_FORMATTER;
        let config = EcosystemConfig {
            show_up_to_date_hints: true,
            up_to_date_text: "✅".to_string(),
            needs_update_text: "❌ {}".to_string(),
            loading_text: "⏳".to_string(),
            show_loading_hints: true,
            network: crate::NetworkMode::Online,
        };

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "example.com/mod".into(),
                version_req: "v0.8.1".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)).into(),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)).into(),
            }],
            uri: crate::test_util::test_uri("/test/go.mod"),
        };

        let mut cached_versions = HashMap::new();
        cached_versions.insert(
            NormalizedName::for_test("example.com/mod"),
            PackageVersions::latest_only("v0.9.1"),
        );

        // Stale go.sum entry left behind by a downgrade: go.sum is sorted ascending by
        // semver, so it sorts last and would win naive last-occurrence-wins parsing
        // even though go.mod's `require` line was downgraded back to v0.8.1 (#235).
        let mut resolved_versions = HashMap::new();
        resolved_versions.insert(NormalizedName::for_test("example.com/mod"), "v0.9.1".into());

        let hints = generate_inlay_hints(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions),
            crate::LoadingState::Loaded,
            &config,
            &formatter,
        );

        assert_eq!(hints.len(), 1);
        match &hints[0].label {
            InlayHintLabel::String(text) => {
                // Bug: using the stale go.sum "v0.9.1" as resolved would equal latest
                // ("v0.9.1") and wrongly report up-to-date. The fix takes go.mod's
                // pinned "v0.8.1", which is genuinely outdated relative to latest.
                assert!(
                    text.starts_with("❌"),
                    "expected outdated hint driven by go.mod pin, got: {text}"
                );
            }
            _ => panic!("Expected string label"),
        }
    }

    #[test]
    fn test_inlay_hint_non_go_formatter_uses_resolved_lockfile_version() {
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

        let formatter = MOCK_FORMATTER;
        let config = EcosystemConfig {
            show_up_to_date_hints: true,
            up_to_date_text: "✅".to_string(),
            needs_update_text: "❌ {}".to_string(),
            loading_text: "⏳".to_string(),
            show_loading_hints: true,
            network: crate::NetworkMode::Online,
        };

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "serde".into(),
                version_req: "1.0.0".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)).into(),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)).into(),
            }],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let mut cached_versions = HashMap::new();
        cached_versions.insert(
            NormalizedName::for_test("serde"),
            PackageVersions::latest_only("1.2.0"),
        );

        let mut resolved_versions = HashMap::new();
        resolved_versions.insert(NormalizedName::for_test("serde"), "1.2.0".into());

        let hints = generate_inlay_hints(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions),
            crate::LoadingState::Loaded,
            &config,
            &formatter,
        );

        assert_eq!(hints.len(), 1);
        match &hints[0].label {
            InlayHintLabel::String(text) => {
                // Non-Go formatters must keep using the lockfile-resolved "1.2.0" (matching
                // latest), not the raw "1.0.0" requirement — confirms the Go override doesn't leak.
                assert!(
                    text.starts_with("✅"),
                    "expected up-to-date hint from resolved lockfile version, got: {text}"
                );
            }
            _ => panic!("Expected string label"),
        }
    }

    /// #1674: a lockfile-resolved version differing from `latest` only by build metadata is up to date.
    #[test]
    fn test_inlay_hint_resolved_differing_only_by_build_metadata_is_up_to_date() {
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

        let config = EcosystemConfig {
            show_up_to_date_hints: true,
            up_to_date_text: "✅".to_string(),
            needs_update_text: "❌ {}".to_string(),
            loading_text: "⏳".to_string(),
            show_loading_hints: true,
            network: crate::NetworkMode::Online,
        };
        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "serde".into(),
                version_req: "1.0.0".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)).into(),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)).into(),
            }],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };
        let mut cached_versions = HashMap::new();
        cached_versions.insert(
            NormalizedName::for_test("serde"),
            PackageVersions::latest_only("1.2.0+build.7"),
        );
        let mut resolved_versions = HashMap::new();
        resolved_versions.insert(NormalizedName::for_test("serde"), "1.2.0+build.3".into());

        let hints = generate_inlay_hints(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions),
            crate::LoadingState::Loaded,
            &config,
            &MOCK_FORMATTER,
        );

        assert_eq!(hints.len(), 1);
        std::assert_matches!(&hints[0].label, InlayHintLabel::String(text) if text.starts_with("✅"));
    }

    #[test]
    fn test_inlay_hint_resolved_vs_latest_build_metadata_matrix() {
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

        let config = EcosystemConfig {
            show_up_to_date_hints: true,
            up_to_date_text: "✅".to_string(),
            needs_update_text: "❌ {}".to_string(),
            loading_text: "⏳".to_string(),
            show_loading_hints: true,
            network: crate::NetworkMode::Online,
        };
        for (resolved, latest, up_to_date) in [
            ("1.2.0", "1.2.0", true),
            ("1.2.0+build.3", "1.2.0", true),
            ("1.2.0", "1.2.0+build.7", true),
            ("1.2.0+a", "1.2.0+b", true),
            ("1.2.0+build.3", "1.3.0+build.3", false),
            ("1.2.0-beta.1", "1.2.0+build.7", false),
        ] {
            let parse_result = MockParseResult {
                deps: vec![MockDep {
                    name: "serde".into(),
                    version_req: "1.0.0".into(),
                    version_range: Range::new(Position::new(0, 10), Position::new(0, 20)).into(),
                    name_range: Range::new(Position::new(0, 0), Position::new(0, 5)).into(),
                }],
                uri: crate::test_util::test_uri("/test/Cargo.toml"),
            };
            let mut cached_versions = HashMap::new();
            cached_versions.insert(
                NormalizedName::for_test("serde"),
                PackageVersions::latest_only(latest),
            );
            let mut resolved_versions = HashMap::new();
            resolved_versions.insert(NormalizedName::for_test("serde"), resolved.into());

            let hints = generate_inlay_hints(
                &parse_result,
                VersionData::new(&cached_versions, &resolved_versions),
                crate::LoadingState::Loaded,
                &config,
                &MOCK_FORMATTER,
            );

            assert_eq!(hints.len(), 1, "{resolved} vs {latest}");
            let InlayHintLabel::String(text) = &hints[0].label else {
                panic!("expected string label");
            };
            if up_to_date {
                assert!(text.starts_with("✅"), "{resolved} vs {latest}: {text}");
            } else {
                assert_eq!(text, &format!("❌ {latest}"), "{resolved} vs {latest}");
            }
        }
    }

    #[test]
    fn test_loading_hint_shows_when_no_cached_version() {
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

        let formatter = MOCK_FORMATTER;
        let config = EcosystemConfig {
            show_up_to_date_hints: true,
            up_to_date_text: "✅".to_string(),
            needs_update_text: "❌ {}".to_string(),
            loading_text: "⏳".to_string(),
            show_loading_hints: true,
            network: crate::NetworkMode::Online,
        };

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "tokio".into(),
                version_req: "1.0".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)).into(),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)).into(),
            }],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let cached_versions = HashMap::new();
        let resolved_versions = HashMap::new();

        let hints = generate_inlay_hints(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions),
            crate::LoadingState::Loading,
            &config,
            &formatter,
        );

        assert_eq!(hints.len(), 1);
        match &hints[0].label {
            InlayHintLabel::String(text) => {
                assert_eq!(text, "⏳", "Expected loading hint");
            }
            _ => panic!("Expected string label"),
        }

        if let Some(InlayHintTooltip::String(tooltip)) = &hints[0].tooltip {
            assert_eq!(tooltip, "Fetching latest version...");
        } else {
            panic!("Expected tooltip");
        }
    }

    #[test]
    fn test_loading_hint_disabled_when_config_false() {
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

        let formatter = MOCK_FORMATTER;
        let config = EcosystemConfig {
            show_up_to_date_hints: true,
            up_to_date_text: "✅".to_string(),
            needs_update_text: "❌ {}".to_string(),
            loading_text: "⏳".to_string(),
            show_loading_hints: false,
            network: crate::NetworkMode::Online,
        };

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "tokio".into(),
                version_req: "1.0".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)).into(),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)).into(),
            }],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let cached_versions = HashMap::new();
        let resolved_versions = HashMap::new();

        let hints = generate_inlay_hints(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions),
            crate::LoadingState::Loading,
            &config,
            &formatter,
        );

        assert_eq!(
            hints.len(),
            0,
            "Expected no hints when loading hints disabled"
        );
    }

    #[test]
    fn test_caret_version_0x_edge_cases() {
        let formatter = MOCK_FORMATTER;

        // ^0.2 should only allow 0.2.x
        assert!(formatter.version_satisfies_requirement(
            &ConcreteVersion::new("0.2.0"),
            &VersionReq::new("^0.2")
        ));
        assert!(formatter.version_satisfies_requirement(
            &ConcreteVersion::new("0.2.5"),
            &VersionReq::new("^0.2")
        ));
        assert!(formatter.version_satisfies_requirement(
            &ConcreteVersion::new("0.2.99"),
            &VersionReq::new("^0.2")
        ));

        // ^0.2 should NOT allow 0.3.x or 0.1.x
        assert!(!formatter.version_satisfies_requirement(
            &ConcreteVersion::new("0.3.0"),
            &VersionReq::new("^0.2")
        ));
        assert!(!formatter.version_satisfies_requirement(
            &ConcreteVersion::new("0.1.0"),
            &VersionReq::new("^0.2")
        ));
        assert!(!formatter.version_satisfies_requirement(
            &ConcreteVersion::new("1.0.0"),
            &VersionReq::new("^0.2")
        ));

        // ^0.0.3 should only allow 0.0.3 (left-most non-zero is patch)
        assert!(formatter.version_satisfies_requirement(
            &ConcreteVersion::new("0.0.3"),
            &VersionReq::new("^0.0.3")
        ));
        assert!(formatter.version_satisfies_requirement(
            &ConcreteVersion::new("0.0.3"),
            &VersionReq::new("^0.0")
        ));
        // ^0.0.3 should NOT allow 0.0.2 (below the floor) or 0.0.4 (past the ceiling).
        assert!(!formatter.version_satisfies_requirement(
            &ConcreteVersion::new("0.0.2"),
            &VersionReq::new("^0.0.3")
        ));
        assert!(!formatter.version_satisfies_requirement(
            &ConcreteVersion::new("0.0.4"),
            &VersionReq::new("^0.0.3")
        ));

        // ^0 should only allow 0.x.y (major is 0)
        assert!(
            formatter.version_satisfies_requirement(
                &ConcreteVersion::new("0.0.0"),
                &VersionReq::new("^0")
            )
        );
        assert!(
            formatter.version_satisfies_requirement(
                &ConcreteVersion::new("0.5.0"),
                &VersionReq::new("^0")
            )
        );
        assert!(
            !formatter.version_satisfies_requirement(
                &ConcreteVersion::new("1.0.0"),
                &VersionReq::new("^0")
            )
        );

        // ^0.0 should NOT allow 0.1.0 (past the ceiling).
        assert!(!formatter.version_satisfies_requirement(
            &ConcreteVersion::new("0.1.0"),
            &VersionReq::new("^0.0")
        ));
    }

    #[test]
    fn test_caret_version_non_zero_major() {
        let formatter = MOCK_FORMATTER;

        // ^1.2 allows [1.2.0, 2.0.0) — same major, but never below the requirement's own
        // minor floor (#1622).
        assert!(formatter.version_satisfies_requirement(
            &ConcreteVersion::new("1.2.0"),
            &VersionReq::new("^1.2")
        ));
        assert!(formatter.version_satisfies_requirement(
            &ConcreteVersion::new("1.9.9"),
            &VersionReq::new("^1.2")
        ));

        // ^1.2 should NOT allow 2.x.x, nor a same-major version below the minor floor.
        assert!(!formatter.version_satisfies_requirement(
            &ConcreteVersion::new("2.0.0"),
            &VersionReq::new("^1.2")
        ));
        assert!(!formatter.version_satisfies_requirement(
            &ConcreteVersion::new("0.9.0"),
            &VersionReq::new("^1.2")
        ));
        assert!(!formatter.version_satisfies_requirement(
            &ConcreteVersion::new("1.0.0"),
            &VersionReq::new("^1.2")
        ));
        assert!(!formatter.version_satisfies_requirement(
            &ConcreteVersion::new("1.1.9"),
            &VersionReq::new("^1.2")
        ));
    }

    /// #1622 regression: `^X.Y` must enforce its own minor/patch lower bound, not just the
    /// major component — mirroring #1619's fix for `deps-composer`'s `satisfies_caret`.
    #[test]
    fn test_caret_requirement_enforces_minor_lower_bound() {
        let formatter = MOCK_FORMATTER;

        assert!(!formatter.version_satisfies_requirement(
            &ConcreteVersion::new("1.1.0"),
            &VersionReq::new("^1.5")
        ));
        assert!(formatter.version_satisfies_requirement(
            &ConcreteVersion::new("1.5.0"),
            &VersionReq::new("^1.5")
        ));
        assert!(formatter.version_satisfies_requirement(
            &ConcreteVersion::new("1.9.0"),
            &VersionReq::new("^1.5")
        ));
        assert!(!formatter.version_satisfies_requirement(
            &ConcreteVersion::new("2.0.0"),
            &VersionReq::new("^1.5")
        ));
    }

    #[test]
    fn test_loading_hint_not_shown_when_cached_version_exists() {
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

        let formatter = MOCK_FORMATTER;
        let config = EcosystemConfig {
            show_up_to_date_hints: true,
            up_to_date_text: "✅".to_string(),
            needs_update_text: "❌ {}".to_string(),
            loading_text: "⏳".to_string(),
            show_loading_hints: true,
            network: crate::NetworkMode::Online,
        };

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "serde".into(),
                version_req: "1.0".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)).into(),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)).into(),
            }],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let mut cached_versions = HashMap::new();
        cached_versions.insert(
            NormalizedName::for_test("serde"),
            PackageVersions::latest_only("1.0.214"),
        );

        // Lock file has the latest version
        let mut resolved_versions = HashMap::new();
        resolved_versions.insert(NormalizedName::for_test("serde"), "1.0.214".into());

        let hints = generate_inlay_hints(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions),
            crate::LoadingState::Loading,
            &config,
            &formatter,
        );

        assert_eq!(hints.len(), 1);
        match &hints[0].label {
            InlayHintLabel::String(text) => {
                assert_eq!(
                    text, "✅ 1.0.214",
                    "Expected up-to-date hint, not loading hint, got: {}",
                    text
                );
            }
            _ => panic!("Expected string label"),
        }
    }

    #[test]
    fn test_inlay_hint_not_in_lockfile_but_satisfies_requirement() {
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

        let formatter = MOCK_FORMATTER;
        let config = EcosystemConfig {
            show_up_to_date_hints: true,
            up_to_date_text: "✅".to_string(),
            needs_update_text: "❌ {}".to_string(),
            loading_text: "⏳".to_string(),
            show_loading_hints: true,
            network: crate::NetworkMode::Online,
        };

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "criterion".into(),
                version_req: "0.5".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)).into(),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 9)).into(),
            }],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let mut cached_versions = HashMap::new();
        cached_versions.insert(
            NormalizedName::for_test("criterion"),
            PackageVersions::latest_only("0.5.1"),
        );

        // Not in lock file (empty resolved_versions)
        let resolved_versions = HashMap::new();

        let hints = generate_inlay_hints(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions),
            crate::LoadingState::Loaded,
            &config,
            &formatter,
        );

        assert_eq!(hints.len(), 1);
        match &hints[0].label {
            InlayHintLabel::String(text) => {
                assert!(
                    text.starts_with("✅"),
                    "Expected up-to-date hint for satisfied requirement, got: {}",
                    text
                );
            }
            _ => panic!("Expected string label"),
        }
    }

    #[test]
    fn test_inlay_hint_not_in_lockfile_and_outdated() {
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

        let formatter = MOCK_FORMATTER;
        let config = EcosystemConfig {
            show_up_to_date_hints: true,
            up_to_date_text: "✅".to_string(),
            needs_update_text: "❌ {}".to_string(),
            loading_text: "⏳".to_string(),
            show_loading_hints: true,
            network: crate::NetworkMode::Online,
        };

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "criterion".into(),
                version_req: "0.4".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)).into(),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 9)).into(),
            }],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let mut cached_versions = HashMap::new();
        cached_versions.insert(
            NormalizedName::for_test("criterion"),
            PackageVersions::latest_only("0.5.1"),
        );

        // Not in lock file (empty resolved_versions)
        let resolved_versions = HashMap::new();

        let hints = generate_inlay_hints(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions),
            crate::LoadingState::Loaded,
            &config,
            &formatter,
        );

        assert_eq!(hints.len(), 1);
        match &hints[0].label {
            InlayHintLabel::String(text) => {
                assert!(
                    text.starts_with("❌"),
                    "Expected needs-update hint for unsatisfied requirement, got: {}",
                    text
                );
                assert!(text.contains("0.5.1"), "Expected latest version in hint");
            }
            _ => panic!("Expected string label"),
        }
    }

    #[test]
    fn test_inlay_hint_unresolved_requirement_emits_no_hint() {
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

        let config = EcosystemConfig {
            show_up_to_date_hints: true,
            up_to_date_text: "✅".to_string(),
            needs_update_text: "❌ {}".to_string(),
            loading_text: "⏳".to_string(),
            show_loading_hints: true,
            network: crate::NetworkMode::Online,
        };

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "spring-boot-starter".into(),
                version_req: "$missing".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)).into(),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)).into(),
            }],
            uri: crate::test_util::test_uri("/test/libs.versions.toml"),
        };

        let mut cached_versions = HashMap::new();
        cached_versions.insert(
            NormalizedName::for_test("spring-boot-starter"),
            PackageVersions::latest_only("3.2.0"),
        );

        // Not in lock file, so status is derived from `requirement_status` on the
        // formatter (which the caller sets to `Unresolved`) rather than a resolved-vs-latest
        // comparison.
        let resolved_versions = HashMap::new();

        let hints = generate_inlay_hints(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions),
            crate::LoadingState::Loaded,
            &config,
            &MockUnresolvedFormatter,
        );

        assert!(
            hints.is_empty(),
            "Expected no inlay hint at all for an unresolved requirement (not even 'up to date'), got: {hints:?}"
        );
    }

    /// #1884: labels for one lock-file-resolved dependency with no cached `latest`, given the
    /// recorded fetch `failure` and `show_up_to_date_hints`.
    fn lockfile_no_latest_labels(
        failure: Option<FetchFailure>,
        show_up_to_date_hints: bool,
    ) -> Vec<String> {
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

        let config = EcosystemConfig {
            show_up_to_date_hints,
            up_to_date_text: "✅".to_string(),
            needs_update_text: "❌ {}".to_string(),
            loading_text: "⏳".to_string(),
            show_loading_hints: true,
            network: crate::NetworkMode::Online,
        };
        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "locked-pkg".into(),
                version_req: "1.0.0".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)).into(),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 10)).into(),
            }],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };
        let name = NormalizedName::for_test("locked-pkg");
        let cached_versions = HashMap::new();
        let resolved_versions = HashMap::from([(name.clone(), ConcreteVersion::new("1.0.0"))]);
        let mut outcomes = DependencyOutcomes::new();
        if let Some(failure) = failure {
            outcomes = outcomes.with_fetch_failure(name, failure);
        }
        generate_inlay_hints(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions).with_outcomes(&outcomes),
            crate::LoadingState::Loaded,
            &config,
            &MOCK_FORMATTER,
        )
        .into_iter()
        .map(|hint| match hint.label {
            InlayHintLabel::String(text) => text,
            InlayHintLabel::LabelParts(_) => panic!("expected string label"),
        })
        .collect()
    }

    #[test]
    fn test_inlay_hint_lockfile_attempted_fetch_failure_shows_warning_marker() {
        for show_up_to_date_hints in [true, false] {
            for failure in [
                FetchFailure::Transient,
                FetchFailure::Actionable("x".into()),
            ] {
                assert_eq!(
                    lockfile_no_latest_labels(Some(failure), show_up_to_date_hints),
                    vec!["⚠ 1.0.0".to_string()]
                );
            }
        }
    }

    #[test]
    fn test_inlay_hint_lockfile_not_attempted_keeps_up_to_date_label() {
        assert_eq!(
            lockfile_no_latest_labels(Some(FetchFailure::NotAttempted), true),
            vec!["✅ 1.0.0".to_string()]
        );
        assert!(lockfile_no_latest_labels(Some(FetchFailure::NotAttempted), false).is_empty());
    }

    fn lockfile_labels_with_miss(
        miss: Option<LookupMiss>,
        network: crate::NetworkMode,
        source: crate::parser::DependencySource,
    ) -> Vec<String> {
        lockfile_labels_with_miss_and_flag(miss, network, source, true)
    }

    fn lockfile_hints_with_miss_and_flag(
        miss: Option<LookupMiss>,
        network: crate::NetworkMode,
        source: crate::parser::DependencySource,
        show_up_to_date_hints: bool,
    ) -> Vec<InlayHint> {
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

        let config = EcosystemConfig {
            show_up_to_date_hints,
            up_to_date_text: "✅".to_string(),
            needs_update_text: "❌ {}".to_string(),
            loading_text: "⏳".to_string(),
            show_loading_hints: true,
            network,
        };
        let parse_result = MockMixedParseResult {
            deps: vec![Box::new(MockSourcedDep {
                inner: MockDep {
                    name: "locked-pkg".into(),
                    version_req: "1.0.0".into(),
                    version_range: Range::new(Position::new(0, 10), Position::new(0, 20)).into(),
                    name_range: Range::new(Position::new(0, 0), Position::new(0, 10)).into(),
                },
                source,
            })],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };
        let name = NormalizedName::for_test("locked-pkg");
        let cached_versions = HashMap::new();
        let resolved_versions = HashMap::from([(name.clone(), ConcreteVersion::new("1.0.0"))]);
        let mut outcomes = DependencyOutcomes::new();
        if let Some(miss) = miss {
            outcomes = outcomes.with_lookup_miss(name, miss);
        }
        generate_inlay_hints(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions)
                .with_outcomes(&outcomes)
                .with_network(network),
            crate::LoadingState::Loaded,
            &config,
            &MOCK_FORMATTER.for_dependency(),
        )
    }

    fn lockfile_labels_with_miss_and_flag(
        miss: Option<LookupMiss>,
        network: crate::NetworkMode,
        source: crate::parser::DependencySource,
        show_up_to_date_hints: bool,
    ) -> Vec<String> {
        lockfile_hints_with_miss_and_flag(miss, network, source, show_up_to_date_hints)
            .into_iter()
            .map(|hint| match hint.label {
                InlayHintLabel::String(text) => text,
                InlayHintLabel::LabelParts(_) => panic!("expected string label"),
            })
            .collect()
    }

    #[test]
    fn test_inlay_hint_alternate_registry_miss_tooltip_matches_miss_kind() {
        let tooltips: Vec<String> = [
            LookupMiss::NotFound,
            LookupMiss::NoComparableVersions,
            LookupMiss::NotLookedUp,
        ]
        .into_iter()
        .map(|miss| {
            let hints = lockfile_hints_with_miss_and_flag(
                Some(miss),
                crate::NetworkMode::Online,
                crate::parser::DependencySource::AlternateRegistry {
                    index: "https://index.example.internal".to_string(),
                    mirrors_public_registry: false,
                },
                true,
            );
            match hints.into_iter().next().and_then(|hint| hint.tooltip) {
                Some(InlayHintTooltip::String(text)) => text,
                other => panic!("expected string tooltip, got {other:?}"),
            }
        })
        .collect();
        assert_eq!(
            tooltips,
            vec![
                "Package not found on the alternate registry; latest version unknown".to_string(),
                "No comparable version on the alternate registry; latest version unknown"
                    .to_string(),
                NOT_LOOKED_UP_MARKER.tooltip.to_string(),
            ]
        );
    }

    #[test]
    fn test_inlay_hint_lockfile_lookup_miss_shows_warning_marker() {
        for miss in [LookupMiss::NotFound, LookupMiss::NoComparableVersions] {
            assert_eq!(
                lockfile_labels_with_miss(
                    Some(miss),
                    crate::NetworkMode::Online,
                    crate::parser::DependencySource::Registry
                ),
                vec!["⚠ 1.0.0".to_string()]
            );
        }
    }

    #[test]
    fn test_inlay_hint_lockfile_custom_registry_shows_neutral_marker_not_checkmark() {
        let custom = || crate::parser::DependencySource::CustomRegistry {
            url: "https://registry.example.internal".to_string(),
        };
        assert_eq!(
            lockfile_labels_with_miss(None, crate::NetworkMode::Online, custom()),
            vec!["ℹ 1.0.0".to_string()]
        );
        assert!(
            lockfile_labels_with_miss_and_flag(None, crate::NetworkMode::Online, custom(), false)
                .is_empty()
        );
    }

    #[test]
    fn test_inlay_hint_lockfile_lookup_miss_suppressed_for_alternate_registry_and_offline() {
        let alternate = || crate::parser::DependencySource::AlternateRegistry {
            index: "https://index.example.internal".to_string(),
            mirrors_public_registry: false,
        };
        assert_eq!(
            lockfile_labels_with_miss(
                Some(LookupMiss::NotFound),
                crate::NetworkMode::Online,
                alternate()
            ),
            vec!["ℹ 1.0.0".to_string()]
        );
        assert!(
            lockfile_labels_with_miss_and_flag(
                Some(LookupMiss::NotFound),
                crate::NetworkMode::Online,
                alternate(),
                false
            )
            .is_empty()
        );
        assert_eq!(
            lockfile_labels_with_miss(
                Some(LookupMiss::NotFound),
                crate::NetworkMode::Offline,
                crate::parser::DependencySource::Registry
            ),
            vec!["📴 1.0.0".to_string()]
        );
    }

    /// Issue #483 I5/SEC-2 (cold, no resolved version): with no cached `latest` and no
    /// lockfile-resolved version, offline mode shows the bare marker alone.
    #[test]
    fn test_inlay_hint_offline_cold_no_resolved_shows_bare_marker() {
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

        let formatter = MOCK_FORMATTER;
        let config = EcosystemConfig {
            show_up_to_date_hints: true,
            up_to_date_text: "✅".to_string(),
            needs_update_text: "❌ {}".to_string(),
            loading_text: "⏳".to_string(),
            show_loading_hints: true,
            network: crate::NetworkMode::Offline,
        };

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "serde".into(),
                version_req: "^2.0".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)).into(),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)).into(),
            }],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let cached_versions = HashMap::new();
        let resolved_versions = HashMap::new();

        let hints = generate_inlay_hints(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions),
            crate::LoadingState::Loaded,
            &config,
            &formatter,
        );

        assert_eq!(hints.len(), 1);
        match &hints[0].label {
            InlayHintLabel::String(text) => assert_eq!(text, "📴"),
            _ => panic!("Expected string label"),
        }
    }

    /// Issue #483 I5/SEC-2 (cold, with a lockfile-resolved version): offline mode must not
    /// discard purely-local, lockfile-derived version information — show it alongside the
    /// marker rather than replacing it with a bare 📴.
    #[test]
    fn test_inlay_hint_offline_cold_with_resolved_shows_marker_and_version() {
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

        let formatter = MOCK_FORMATTER;
        let config = EcosystemConfig {
            show_up_to_date_hints: true,
            up_to_date_text: "✅".to_string(),
            needs_update_text: "❌ {}".to_string(),
            loading_text: "⏳".to_string(),
            show_loading_hints: true,
            network: crate::NetworkMode::Offline,
        };

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "serde".into(),
                version_req: "^2.0".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)).into(),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)).into(),
            }],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let cached_versions = HashMap::new();
        let mut resolved_versions = HashMap::new();
        resolved_versions.insert(NormalizedName::for_test("serde"), "2.0.12".into());

        let hints = generate_inlay_hints(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions),
            crate::LoadingState::Loaded,
            &config,
            &formatter,
        );

        assert_eq!(hints.len(), 1);
        match &hints[0].label {
            InlayHintLabel::String(text) => assert_eq!(text, "📴 2.0.12"),
            _ => panic!("Expected string label"),
        }
    }

    /// Issue #483 I5/SEC-2 (warm cache): a normal up-to-date/outdated badge built from a
    /// warm-cache `latest` value (possibly fetched before an online -> offline flip) must
    /// carry the offline marker too, or it is indistinguishable from live data on this
    /// always-visible inline surface.
    #[test]
    fn test_inlay_hint_offline_warm_cache_appends_marker_to_outdated_badge() {
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

        let formatter = MOCK_FORMATTER;
        let config = EcosystemConfig {
            show_up_to_date_hints: true,
            up_to_date_text: "✅".to_string(),
            needs_update_text: "❌ {}".to_string(),
            loading_text: "⏳".to_string(),
            show_loading_hints: true,
            network: crate::NetworkMode::Offline,
        };

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "serde".into(),
                version_req: "=2.0.12".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)).into(),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)).into(),
            }],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let mut cached_versions = HashMap::new();
        cached_versions.insert(
            NormalizedName::for_test("serde"),
            PackageVersions::latest_only("2.1.1"),
        );

        let mut resolved_versions = HashMap::new();
        resolved_versions.insert(NormalizedName::for_test("serde"), "2.0.12".into());

        let hints = generate_inlay_hints(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions),
            crate::LoadingState::Loaded,
            &config,
            &formatter,
        );

        assert_eq!(hints.len(), 1);
        match &hints[0].label {
            InlayHintLabel::String(text) => assert_eq!(text, "❌ 2.1.1 📴"),
            _ => panic!("Expected string label"),
        }
    }

    /// #1268 critic S1: a lockfile-resolved version is exactly as untrusted as a
    /// registry-reported one (both are attacker-controllable in a cloned repository),
    /// so a bidi override embedded in it must not survive into the offline-marker
    /// label's `resolved` interpolation either — the sibling sink to the `Outdated`
    /// arm's `latest`, on the same always-visible inline surface.
    #[test]
    fn test_inlay_hint_offline_marker_strips_bidi_override_from_resolved_version() {
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

        let formatter = MOCK_FORMATTER;
        let config = EcosystemConfig {
            show_up_to_date_hints: true,
            up_to_date_text: "✅".to_string(),
            needs_update_text: "❌ {}".to_string(),
            loading_text: "⏳".to_string(),
            show_loading_hints: true,
            network: crate::NetworkMode::Offline,
        };

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "serde".into(),
                version_req: "^2.0".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)).into(),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)).into(),
            }],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let malicious_resolved = "2.0.12\u{202E}deifidom ton";
        let cached_versions = HashMap::new();
        let mut resolved_versions = HashMap::new();
        resolved_versions.insert(NormalizedName::for_test("serde"), malicious_resolved.into());

        let hints = generate_inlay_hints(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions),
            crate::LoadingState::Loaded,
            &config,
            &formatter,
        );

        assert_eq!(hints.len(), 1);
        match &hints[0].label {
            InlayHintLabel::String(text) => {
                assert!(
                    !text.contains('\u{202E}'),
                    "bidi override must not survive into the offline-marker label; got: {text}"
                );
            }
            _ => panic!("Expected string label"),
        }
    }

    /// #1268 critic S1: same sink concern as the offline-marker test above, for the
    /// online, no-cached-`latest`, `show_up_to_date_hints` arm's `resolved`
    /// interpolation.
    #[test]
    fn test_inlay_hint_no_cached_latest_up_to_date_strips_bidi_override_from_resolved_version() {
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

        let formatter = MOCK_FORMATTER;
        let config = EcosystemConfig {
            show_up_to_date_hints: true,
            up_to_date_text: "✅".to_string(),
            needs_update_text: "❌ {}".to_string(),
            loading_text: "⏳".to_string(),
            show_loading_hints: true,
            network: crate::NetworkMode::Online,
        };

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "criterion".into(),
                version_req: "0.5".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)).into(),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 9)).into(),
            }],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let malicious_resolved = "0.5.1\u{202E}deifidom ton";
        // Not in the registry cache (empty), only lockfile-resolved.
        let cached_versions = HashMap::new();
        let mut resolved_versions = HashMap::new();
        resolved_versions.insert(
            NormalizedName::for_test("criterion"),
            malicious_resolved.into(),
        );

        let hints = generate_inlay_hints(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions),
            crate::LoadingState::Loaded,
            &config,
            &formatter,
        );

        assert_eq!(hints.len(), 1);
        match &hints[0].label {
            InlayHintLabel::String(text) => {
                assert!(
                    !text.contains('\u{202E}'),
                    "bidi override must not survive into the up-to-date label; got: {text}"
                );
            }
            _ => panic!("Expected string label"),
        }
    }

    /// #1268 critic S1: same sink concern once more, for the `RequirementStatus::UpToDate`
    /// arm reached via the normal (non-offline, cached-`latest`-present) path, three
    /// lines above the fixed `Outdated` arm in the same `match`.
    #[test]
    fn test_inlay_hint_up_to_date_label_strips_bidi_override_from_resolved_version() {
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

        let formatter = MOCK_FORMATTER;
        let config = EcosystemConfig {
            show_up_to_date_hints: true,
            up_to_date_text: "✅".to_string(),
            needs_update_text: "❌ {}".to_string(),
            loading_text: "⏳".to_string(),
            show_loading_hints: true,
            network: crate::NetworkMode::Online,
        };

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "serde".into(),
                version_req: "^2.0".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)).into(),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)).into(),
            }],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let malicious_resolved = "2.1.1\u{202E}deifidom ton";
        let mut cached_versions = HashMap::new();
        cached_versions.insert(
            NormalizedName::for_test("serde"),
            PackageVersions::latest_only(malicious_resolved),
        );
        let mut resolved_versions = HashMap::new();
        resolved_versions.insert(NormalizedName::for_test("serde"), malicious_resolved.into());

        let hints = generate_inlay_hints(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions),
            crate::LoadingState::Loaded,
            &config,
            &formatter,
        );

        assert_eq!(hints.len(), 1);
        match &hints[0].label {
            InlayHintLabel::String(text) => {
                assert!(
                    !text.contains('\u{202E}'),
                    "bidi override must not survive into the up-to-date label; got: {text}"
                );
            }
            _ => panic!("Expected string label"),
        }
    }

    /// #1268: a bidi-override embedded in the registry-reported `latest` version must
    /// not survive into the "update available" inlay-hint label, which — unlike a
    /// diagnostic — is an always-visible inline editor surface.
    #[test]
    fn test_inlay_hint_outdated_label_strips_bidi_override_from_latest_version() {
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

        let formatter = MOCK_FORMATTER;
        let config = EcosystemConfig {
            show_up_to_date_hints: true,
            up_to_date_text: "✅".to_string(),
            needs_update_text: "❌ {}".to_string(),
            loading_text: "⏳".to_string(),
            show_loading_hints: true,
            network: crate::NetworkMode::Online,
        };

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "serde".into(),
                version_req: "=2.0.12".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)).into(),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)).into(),
            }],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let malicious_latest = "2.1.1\u{202E}live.tsr";
        let mut cached_versions = HashMap::new();
        cached_versions.insert(
            NormalizedName::for_test("serde"),
            PackageVersions::latest_only(malicious_latest),
        );

        let mut resolved_versions = HashMap::new();
        resolved_versions.insert(NormalizedName::for_test("serde"), "2.0.12".into());

        let hints = generate_inlay_hints(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions),
            crate::LoadingState::Loaded,
            &config,
            &formatter,
        );

        assert_eq!(hints.len(), 1);
        match &hints[0].label {
            InlayHintLabel::String(text) => {
                assert!(
                    !text.contains('\u{202E}'),
                    "bidi override must not survive into the inlay hint label; got: {text}"
                );
            }
            _ => panic!("Expected string label"),
        }
    }

    /// #1268: an oversized `latest` version string must be capped, not interpolated
    /// unbounded into the always-visible inlay-hint label.
    #[test]
    fn test_inlay_hint_outdated_label_caps_oversized_latest_version() {
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

        let formatter = MOCK_FORMATTER;
        let config = EcosystemConfig {
            show_up_to_date_hints: true,
            up_to_date_text: "✅".to_string(),
            needs_update_text: "❌ {}".to_string(),
            loading_text: "⏳".to_string(),
            show_loading_hints: true,
            network: crate::NetworkMode::Online,
        };

        let parse_result = MockParseResult {
            deps: vec![MockDep {
                name: "serde".into(),
                version_req: "=2.0.12".into(),
                version_range: Range::new(Position::new(0, 10), Position::new(0, 20)).into(),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 5)).into(),
            }],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let oversized_latest = format!("2.0.0-{}", "X".repeat(MAX_VERSION_DIAGNOSTIC_CHARS + 50));
        let mut cached_versions = HashMap::new();
        cached_versions.insert(
            NormalizedName::for_test("serde"),
            PackageVersions::latest_only(oversized_latest),
        );

        let mut resolved_versions = HashMap::new();
        resolved_versions.insert(NormalizedName::for_test("serde"), "2.0.12".into());

        let hints = generate_inlay_hints(
            &parse_result,
            VersionData::new(&cached_versions, &resolved_versions),
            crate::LoadingState::Loaded,
            &config,
            &formatter,
        );

        assert_eq!(hints.len(), 1);
        match &hints[0].label {
            InlayHintLabel::String(text) => {
                // "❌ " (2 chars) + the truncated version (MAX_VERSION_DIAGNOSTIC_CHARS chars
                // + 1 ellipsis marker) — an exact bound, not just "< input length", so a cap
                // that truncates at the wrong point (e.g. loosely under the input length but
                // still oversized) cannot pass this assertion (critic M1).
                assert_eq!(
                    text.chars().count(),
                    2 + MAX_VERSION_DIAGNOSTIC_CHARS + 1,
                    "expected exact capped length; got: {text}"
                );
                assert!(
                    text.ends_with('…'),
                    "expected truncation marker; got: {text}"
                );
            }
            _ => panic!("Expected string label"),
        }
    }
}
