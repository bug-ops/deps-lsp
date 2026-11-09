use std::collections::HashSet;
use std::sync::Arc;
use tower_lsp_server::ls_types::{CodeAction, CodeActionKind, Position, Range, WorkspaceEdit};

use crate::edit::{FixTargetContext, replacement_text, requirement_is_placeholder_for};
use crate::osv::ScanOutcome;
use crate::{
    ConcreteVersion, Dependency, PackageKey, Registry, TypedParseResult, Version, VersionReq,
};

use super::{
    BoundedVersionReq, DEPRECATED_DIAGNOSTIC_CODE, DependencyFormatter, EcosystemFormatter,
    FetchContext, InteractiveFetch, InteractiveFetchRequest, LatestVerdict, LineOffsetTable,
    NoLiveList, RequirementGate, UNSATISFIABLE_DIAGNOSTIC_CODE, VersionData,
    await_interactive_versions, candidate_verdict, is_safe_version_string, latest_verdict,
    literal_span_matches, requirement_is_unsatisfiable, requirement_len_exceeds_cap,
    resolve_latest_status, resolve_scan_outcome, single_file_edit, slice_for_range,
    strip_whitespace, warn_rejected_value,
};

/// Whether REFACTOR "Update to X" items may offer pre-release versions (#1885).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PrereleasePolicy {
    /// Only the registry's own pick may be a pre-release; every other item must be stable.
    StableOnly,
    /// The dependency is already on a pre-release line, so pre-release items stay offered.
    IncludePrereleases,
}

impl PrereleasePolicy {
    /// Resolves the policy from ecosystem semantics rather than a blanket text check, so a
    /// dependency already on a pre-release line never loses its pre-release offers:
    ///
    /// 1. the registry pick is itself a pre-release (Composer `minimum-stability`, npm's
    ///    all-prerelease fallback);
    /// 2. the in-use version (lock file, or a concrete pin) is a published pre-release;
    /// 3. a lower-bound/exact comparator of the requirement names a published pre-release;
    /// 4. a strict-SemVer matcher's requirement carries a pre-release tag on such a comparator.
    ///
    /// 5. the ecosystem's own grammar says the requirement opts in
    ///    (`RequirementResolution::requirement_opts_into_prereleases`: Composer stability
    ///    flags, Maven/NuGet intervals, PEP 440 spellings).
    ///
    /// Upper bounds (`<2.0.0-0`) never opt in: they exist to exclude pre-releases.
    fn for_dependency(
        prereleases: &HashSet<&str>,
        pick: Option<&ConcreteVersion>,
        in_use: Option<&ConcreteVersion>,
        requirement: &VersionReq,
        formatter: &dyn EcosystemFormatter,
    ) -> Self {
        if requirement_len_exceeds_cap(requirement.as_str()) {
            return Self::StableOnly;
        }
        let published_prerelease = |text: &str| prereleases.contains(text);
        let pick_is_prerelease = pick.is_some_and(|v| published_prerelease(v.as_str()));
        let in_use_is_prerelease = in_use.is_some_and(|v| published_prerelease(v.as_str()));
        let comparators = opt_in_comparator_versions(requirement.as_str());
        let names_published_prerelease = comparators.iter().any(|c| published_prerelease(c));
        let strict_tag = || {
            formatter
                .compile_requirement(requirement)
                .is_some_and(|m| m.strict_prerelease_exclusion())
                && comparators
                    .iter()
                    .any(|c| c.split('+').next().is_some_and(|core| core.contains('-')))
        };
        let ecosystem_opt_in = || {
            BoundedVersionReq::new(requirement)
                .is_some_and(|bounded| formatter.requirement_opts_into_prereleases(bounded))
        };
        if pick_is_prerelease
            || in_use_is_prerelease
            || names_published_prerelease
            || strict_tag()
            || ecosystem_opt_in()
        {
            Self::IncludePrereleases
        } else {
            Self::StableOnly
        }
    }
}

/// Version texts of the comparators in `requirement` that can opt a dependency in to
/// pre-releases: exact, lower-bound, caret and tilde comparators. `<`, `<=` and `!=` bounds
/// (and the upper end of a hyphen range) are skipped, since they never admit a pre-release.
fn opt_in_comparator_versions(requirement: &str) -> Vec<&str> {
    const OPERATOR_CHARS: &[char] = &['<', '>', '=', '~', '^', '!'];
    let mut versions = Vec::new();
    let mut pending_operator = "";
    let mut skip_next = false;
    for token in requirement.split(|c: char| c.is_whitespace() || c == ',' || c == '|') {
        if token.is_empty() {
            continue;
        }
        if token == "-" {
            skip_next = true;
            continue;
        }
        let split_at = token
            .find(|c: char| !OPERATOR_CHARS.contains(&c))
            .unwrap_or(token.len());
        let (own_operator, rest) = token.split_at(split_at);
        if rest.is_empty() {
            pending_operator = own_operator;
            continue;
        }
        let operator = if own_operator.is_empty() {
            std::mem::take(&mut pending_operator)
        } else {
            pending_operator = "";
            own_operator
        };
        if std::mem::take(&mut skip_next) || operator.starts_with(['<', '!']) {
            continue;
        }
        versions.push(rest);
    }
    versions
}

/// The vulnerability-fix quickfix built by [`build_vulnerability_fix_action`],
/// bundled with the native-namespace version it targets so callers can dedup
/// display items and check the registry's yank flag against it without
/// re-parsing the action's title.
struct VulnerabilityFixAction {
    /// `fix.version`, converted to this ecosystem's namespace via
    /// [`crate::lsp_helpers::OsvNaming::osv_version_to_native`].
    version_native: String,
    /// The formatted edit text this action's own `TextEdit` writes — the exact
    /// value `action.edit` carries, kept alongside it so callers (the REFACTOR-loop
    /// dedup in [`generate_code_actions`]) can compare against it without
    /// recomputing `format_version_replacing` and risking the copy silently
    /// drifting from the actual edit if that computation ever changes.
    new_text: String,
    action: CodeAction,
}

/// Builds the "fix vulnerability" quickfix for `dep`, if OSV data recommends
/// one AND that recommendation's target version F has itself been verified
/// against OSV (#462) — see `deps_core::edit::plan_vulnerability_fix`'s internal
/// `fix_target_is_verified` gate, which this action's edit now goes through.
///
/// Registry-independent by construction (FR-007, mirroring the rule already
/// enforced in [`crate::lsp_helpers::generate_diagnostics_from_cache`]): computed entirely from
/// `versions.vulnerabilities` and `version_req` (the caller's already-fetched
/// `dep.version_requirement()`), never from a registry fetch. The caller still drops it
/// when the interactive registry lookup is unverified (timeout, known failure, concurrency
/// cap): only a registry error returned to the request itself keeps it. It is not
/// OSV-independent, though: F's verification is computed in `deps-lsp`'s phase B and handed
/// in via `dv.fix_target_status`, so an OSV outage (or a code-action request that races
/// ahead of phase B completing) leaves that unresolved and suppresses this action — the
/// intended fail-safe degradation, not a bug. Callers must still reconcile the result against a successful registry fetch when one
/// is available — see the yank check in [`generate_code_actions`].
fn build_vulnerability_fix_action<P, F>(
    parse_result: &P,
    dep: &P::Dep,
    uri: &url::Url,
    version_range: Range,
    versions: VersionData<'_>,
    version_req: &str,
    formatter: &F,
) -> Option<VulnerabilityFixAction>
where
    P: TypedParseResult,
    F: DependencyFormatter<Dep = P::Dep>,
{
    let key = PackageKey::new(dep.name(), formatter);
    // #394 S2: prefer the version-qualified key so a fix action for one
    // occurrence of a duplicated name is never built from another
    // occurrence's OSV result. See `crate::osv::vulnerability_keys`.
    let vuln_keys = versions.ecosystem.map(|ecosystem| {
        crate::osv::vulnerability_keys(
            parse_result,
            versions.resolved_map(),
            versions.candidates_map(),
            formatter,
            ecosystem,
        )
    });
    let outcome = versions
        .vulnerabilities
        .and_then(|m| resolve_scan_outcome(m, dep, vuln_keys.as_ref(), &key))?;
    let ScanOutcome::Vulnerable(dv) = outcome else {
        return None;
    };
    // Issue #1517: the same per-key "latest" status `recommended_fix` needs to exclude ids
    // phase B's latest-check found still applying — looked up once and threaded through both
    // calls below rather than re-deriving it twice.
    let latest = versions
        .latest_status
        .and_then(|m| resolve_latest_status(m, dep, vuln_keys.as_ref(), &key));

    // Planning core (the no-op guard, `is_safe_version_string`, `osv_version_to_native`,
    // `format_version_replacing_for`, and the #462 fix-target-verification gate) lives in
    // `deps_core::edit::plan_vulnerability_fix` — moved there so `deps-cli update
    // --security-only` (#1329) reuses the identical decision logic instead of
    // reimplementing it.
    let planned = crate::edit::plan_vulnerability_fix(
        dep,
        version_range.into(),
        version_req,
        dv,
        FixTargetContext::new(latest).with_registry(versions.cached_for(&key)),
        formatter,
    )
    .ok()?;
    let version_native = planned.target.as_str().to_string();
    let new_text = planned.edit.new_text;

    // Recomputed for the title/data payload below only — `plan_vulnerability_fix` already
    // confirmed a fix exists and F is verified; `recommended_fix` is a pure, deterministic
    // function of `dv`/`latest` alone, so calling it again here is not a second decision.
    let fix = dv.recommended_fix(latest)?;

    // #1422 follow-up: `fix.advisory_ids` is computed over the full `MAX_ADVISORY_RECORDS`-capped
    // fetch set, but only `dv.advisories_for_display()`'s ids are ever published as `Diagnostic`s
    // (`push_vulnerability_diagnostics`). Restrict the ids handed to `bind_diagnostics` via
    // `data.diagnostic_codes` to their intersection with the displayed set, so this action only
    // ever claims a code the client could actually have a matching `Diagnostic` for. When the
    // true fix targets only advisories beyond the display cap, the intersection is empty —
    // `data` is then omitted entirely (below) rather than set to ids that can never match, so
    // `bind_diagnostics` treats this as "no binding to attempt" instead of "matched nothing";
    // the action is still returned, just not diagnostic-bound (title/edit are unaffected — they
    // report the true fix regardless of what's displayed).
    let display_advisories = dv.advisories_for_display();
    let displayed_ids: HashSet<&str> = display_advisories
        .items()
        .iter()
        .map(|a| a.id().as_str())
        .collect();
    let diagnostic_codes: Vec<&crate::osv::OsvId> = fix
        .advisory_ids
        .iter()
        .filter(|id| displayed_ids.contains(id.as_str()))
        .collect();

    // S3: the scan target may have been the lockfile-resolved version, not
    // the declared requirement — rewriting the manifest alone would then not
    // clear the diagnostic until the lockfile is regenerated. Say so in the
    // title rather than silently overclaiming.
    let lockfile_hit = versions.is_resolved(&key);

    // Names only the first (worst-severity, per `recommended_fix`'s sort)
    // advisory id and summarizes the rest — `recommended_fix` can return an
    // unbounded number of ids (up to `MAX_ADVISORY_RECORDS`), and a title
    // listing every one of them would overflow an editor's code-action menu.
    let (first_id, rest_ids) = fix.advisory_ids.split_first()?;
    let fixes = if rest_ids.is_empty() {
        first_id.to_string()
    } else {
        format!("{first_id} +{} more", rest_ids.len())
    };
    let title = if lockfile_hit {
        format!("Update to {version_native} (fixes {fixes}; update lockfile to apply)")
    } else {
        format!("Update to {version_native} (fixes {fixes})")
    };

    let edits = single_file_edit(uri, version_range.into(), new_text.clone());

    Some(VulnerabilityFixAction {
        version_native,
        new_text,
        action: CodeAction {
            title,
            kind: Some(CodeActionKind::QUICKFIX),
            edit: Some(WorkspaceEdit {
                changes: Some(edits),
                ..Default::default()
            }),
            is_preferred: None,
            // Stashes the resolved advisory ids and edit range so the `deps-lsp` handler can
            // bind this action to matching client-supplied diagnostics without deps-core
            // needing to know about LSP request context. Shape shared with
            // `build_unsatisfiable_fix_action`'s payload — `bind_diagnostics` matches on
            // `diagnostic_codes` regardless of producer. `diagnostic_codes` is
            // `fix.advisory_ids` restricted to the displayed set (see above, #1422) — never the
            // unrestricted full claim.
            data: (!diagnostic_codes.is_empty()).then(|| {
                serde_json::json!({
                    "diagnostic_codes": diagnostic_codes,
                    "diagnostic_range": version_range,
                })
            }),
            ..Default::default()
        },
    })
}

/// The unsatisfiable-requirement quickfix built by [`build_unsatisfiable_fix_action`],
/// bundled with the native-namespace target version it carries so callers can dedup
/// display items and check the registry's yank flag against it, mirroring
/// [`VulnerabilityFixAction`]'s shape.
struct UnsatisfiableFixAction {
    /// The cached `latest` version this action targets (see the function doc for why
    /// this is the cached rather than the live value).
    version_native: String,
    /// The formatted edit text this action's own `TextEdit` writes, kept alongside it
    /// for the same reason [`VulnerabilityFixAction::new_text`] is.
    new_text: String,
    action: CodeAction,
}

/// Builds the "fix unsatisfiable requirement" quickfix for `dep`, if its declared
/// requirement currently matches no published version.
///
/// Mirrors [`build_vulnerability_fix_action`]'s shape: computed entirely from the cached
/// `versions` snapshot and the dependency's declared requirement, before any registry
/// fetch (the same FR-007 rationale); like that action, it is dropped by the caller when the
/// interactive registry lookup is unverified. Gated by
/// [`requirement_is_unsatisfiable`] evaluated against the identical inputs
/// [`crate::lsp_helpers::generate_diagnostics_from_cache`] uses, so this action can never appear without —
/// or be missing despite — the diagnostic it resolves.
///
/// Targets `versions.cached[..].latest`, the **cached** value, not a freshly fetched one:
/// that is the exact value the diagnostic's "latest is X" message names, so the action's
/// title and the diagnostic text agree on what "the latest" is. A display item further
/// down in [`generate_code_actions`] built from the same call's *live* registry response
/// can disagree with a stale cache, and that is accepted deliberately — see that
/// function's doc comment.
///
/// The rewritten requirement is re-checked with the same predicate before the action is
/// returned (`format_version_replacing` is overridden by `deps-pypi` and `deps-gradle` to
/// preserve operator style, which can leave a rewritten range still unsatisfiable). This
/// is best-effort, not a proof: [`requirement_is_unsatisfiable`] also returns `false` for
/// a rewrite this ecosystem's matcher cannot evaluate at all (uncompilable or unresolved),
/// so an unverifiable rewrite passes through unrejected. That is the safe direction — a
/// rewrite this scan cannot judge is not evidence it is bad — but it means the guard holds
/// only "for every rewrite the ecosystem can evaluate", not unconditionally.
fn build_unsatisfiable_fix_action<F: DependencyFormatter>(
    dep: &F::Dep,
    uri: &url::Url,
    version_range: Range,
    versions: VersionData<'_>,
    version_req: &VersionReq,
    formatter: &F,
) -> Option<UnsatisfiableFixAction> {
    // #1370: central placeholder gate — an unexpanded placeholder has no concrete version
    // text a fix action could ever replace, independent of whether `compile_bounded_requirement`
    // happens to also return `None` for it.
    if requirement_is_placeholder_for(formatter, dep, version_req.as_str()) {
        return None;
    }
    if !formatter.can_resolve_source(&dep.source()) {
        return None;
    }

    let package_versions = versions.cached_for(&PackageKey::new(dep.name(), formatter))?;

    if !requirement_is_unsatisfiable(formatter, version_req, &package_versions.available) {
        return None;
    }

    let latest = package_versions.latest.clone();
    if !is_safe_version_string(latest.as_str()) {
        warn_rejected_value(
            "is_safe_version_string",
            "unsatisfiable-requirement fix code action",
            latest.as_str(),
        );
        return None;
    }
    // Unreachable after the gate above; fails closed rather than unwrapping.
    let new_text = replacement_text(formatter, dep, &latest, version_req.as_str())?;

    // Mirrors `build_vulnerability_fix_action`'s N1 guard: compares against
    // `dep.version_literal()` rather than `version_req` when the ecosystem provides one,
    // so a synthesized comparator requirement doesn't mask a genuine no-op edit.
    let literal_target = dep.version_literal().unwrap_or(version_req.as_str());
    if strip_whitespace(literal_target) == strip_whitespace(&new_text) {
        return None;
    }

    let verification_req = VersionReq::new(new_text.clone());
    if requirement_is_unsatisfiable(formatter, &verification_req, &package_versions.available) {
        return None;
    }

    let edits = single_file_edit(uri, version_range.into(), new_text.clone());

    Some(UnsatisfiableFixAction {
        version_native: latest.to_string(),
        new_text,
        action: CodeAction {
            title: format!("Fix unsatisfiable requirement: update to {latest}"),
            kind: Some(CodeActionKind::QUICKFIX),
            edit: Some(WorkspaceEdit {
                changes: Some(edits),
                ..Default::default()
            }),
            is_preferred: None,
            // Same payload shape `build_vulnerability_fix_action` stashes — see that
            // function's doc comment. This diagnostic has no per-instance id, so
            // `diagnostic_codes` names the shared constant instead.
            data: Some(serde_json::json!({
                "diagnostic_codes": [UNSATISFIABLE_DIAGNOSTIC_CODE],
                "diagnostic_range": version_range,
            })),
            ..Default::default()
        },
    })
}

/// The registry-supplied replacement name for `dep`'s deprecated package, when the ecosystem
/// opts in to package renames and the name is valid. The part of the rename quickfix that
/// does not depend on document content, shared with the hover footer.
fn offered_replacement_name<'a>(
    dep: &dyn Dependency,
    versions: VersionData<'a>,
    formatter: &dyn EcosystemFormatter,
) -> Option<&'a str> {
    if !formatter.supports_package_rename() {
        return None;
    }
    let key = PackageKey::new(dep.name(), formatter);
    let replacement = versions
        .outcomes
        .and_then(|o| o.deprecation(key.normalized()))
        .and_then(|dep_info| dep_info.replacement.as_deref())
        .filter(|r| !r.is_empty())?;
    formatter
        .validate_package_name(replacement)
        .ok()
        .map(|()| replacement)
}

/// Builds the "Replace with X" package-rename quickfix for `dep` (issue #205), if this
/// ecosystem opts in via [`crate::lsp_helpers::DiagnosticPolicy::supports_package_rename`] and a
/// registry-supplied replacement name is on record.
///
/// **Composer-only in Phase 1** — see `EcosystemFormatter::supports_package_rename`'s
/// docs for why this must not be enabled for an ecosystem whose replacement name is
/// regex-extracted free text (a typosquatting vector).
///
/// D7(a): guarded by the same literal-span discipline `generate_code_actions` applies to
/// `version_range` — several parsers (Composer's `find_positions` included, when a
/// legal escaped-solidus key like `"vendor\/package"` never matches the raw-text search)
/// fall back to `Range::default()` for `name_range` on a lookup miss. Comparing the
/// slice at `name_range` against `dep.name()` rejects that sentinel automatically: an
/// empty (or wrong) slice never equals the declared name, so no edit is ever written at
/// `(0,0)`.
fn build_replacement_action(
    dep: &dyn Dependency,
    uri: &url::Url,
    version_range: Range,
    versions: VersionData<'_>,
    content: &str,
    line_offsets: &LineOffsetTable,
    formatter: &dyn EcosystemFormatter,
) -> Option<CodeAction> {
    let replacement = offered_replacement_name(dep, versions, formatter)?;

    let name_range: Range = dep.name_range().into();
    let name_slice = slice_for_range(content, line_offsets, name_range.into());
    // I7: reuses `literal_span_matches` for its sentinel-rejecting, whitespace-insensitive
    // comparison (see D7(a) above). Its NuGet-bracket branch is inert here — a package name
    // never contains `[`/`]` — so it never changes this call's outcome.
    if !literal_span_matches(name_slice, dep.name().as_str()) {
        return None;
    }

    let edits = single_file_edit(uri, name_range.into(), replacement.to_string());

    Some(CodeAction {
        title: format!("Replace with {replacement}"),
        kind: Some(CodeActionKind::QUICKFIX),
        edit: Some(WorkspaceEdit {
            changes: Some(edits),
            ..Default::default()
        }),
        is_preferred: None,
        // Same binding mechanism `build_vulnerability_fix_action`/`build_unsatisfiable_fix_action`
        // use: `diagnostic_range` names D4's deprecation-diagnostic range (`version_range`,
        // not `name_range`) so `bind_diagnostics` attaches this action to the diagnostic the
        // client's lightbulb gesture actually surfaces.
        data: Some(serde_json::json!({
            "diagnostic_codes": [DEPRECATED_DIAGNOSTIC_CODE],
            "diagnostic_range": version_range,
        })),
        ..Default::default()
    })
}

/// Whether [`generate_code_actions`] would offer at least one action for `dep`, decided by the
/// same builders and gates it runs, given the registry's answer in `fetched`.
///
/// The hover footer advertises `Cmd+.` through this, so it cannot promise an action
/// `codeAction` then withholds (#1988). The one gate it cannot apply is the document-content
/// literal-span check, which a hover has no text for.
pub(super) fn code_actions_offered<P, F, R>(
    parse_result: &P,
    dep: &P::Dep,
    versions: VersionData<'_>,
    fetched: &FetchedVersions,
    registry: &R,
    formatter: &F,
) -> bool
where
    P: TypedParseResult,
    F: DependencyFormatter<Dep = P::Dep>,
    R: Registry + ?Sized,
{
    let uri = parse_result.uri();
    if offered_replacement_name(dep, versions, formatter).is_some() {
        return true;
    }
    let (Some(version_range), Some(version_req)) = (dep.version_range(), dep.version_requirement())
    else {
        return false;
    };
    if version_req.as_str().is_empty() {
        return false;
    }
    let version_range: Range = version_range.into();

    let vulnerability_fix = build_vulnerability_fix_action(
        parse_result,
        dep,
        uri,
        version_range,
        versions,
        version_req.as_str(),
        formatter,
    )
    .filter(|f| !fetched.rules_out(&f.version_native));
    let unsatisfiable_fix =
        build_unsatisfiable_fix_action(dep, uri, version_range, versions, version_req, formatter)
            .filter(|f| !fetched.rules_out(&f.version_native));
    if vulnerability_fix.is_some() || unsatisfiable_fix.is_some() {
        return true;
    }

    let proven_ahead = matches!(
        formatter.hover_provenance(dep),
        Some(crate::lsp_helpers::HoverProvenance::CommitAheadOfLatestRelease { .. })
    );
    if proven_ahead
        || requirement_is_placeholder_for(formatter, dep, version_req.as_str())
        || !formatter.can_resolve_source(&dep.source())
    {
        return false;
    }
    let Some(registry_versions) = &fetched.live else {
        return false;
    };
    let literal_target = strip_whitespace(
        dep.version_literal()
            .unwrap_or_else(|| version_req.as_str()),
    );
    let refactor = RefactorContext {
        parse_result,
        dep,
        uri,
        version_range,
        version_req,
        versions: &versions,
        formatter,
    };
    refactor_targets(&refactor, registry, registry_versions)
        .iter()
        .any(|target| strip_whitespace(&target.new_text) != literal_target)
}

/// Generates the code actions offered for the dependency at `position`.
///
/// Finds the dependency whose declared version `position` falls on
/// (`formatter.is_position_on_dependency`). Returns an empty `Vec`
/// immediately if no dependency is at `position`, it has no `version_range`
/// to edit, it has no declared (or an empty) `version_requirement`, or the
/// **literal-span guard** rejects it — `content` sliced over `version_range`
/// no longer holds the literal text (see `literal_span_matches`, compared
/// against [`Dependency::version_literal`] when the ecosystem provides one,
/// falling back to `version_requirement` otherwise — e.g. a Maven
/// `${property}` reference or a Gradle DSL variable/alias). Writing a
/// `TextEdit` at that range would corrupt the manifest instead of fixing it,
/// so this mirrors the guard `collect_update_all_edits` already applies on
/// the bulk-edit path, and gates every kind of action below since any of
/// them could write there.
///
/// Otherwise returns up to three kinds of action, in this order:
///
/// 1. At most one `QUICKFIX` "fix vulnerability" action, if `versions`
///    carries an OSV scan result flagging this dependency,
///    [`crate::osv::DependencyVulnerabilities::recommended_fix`] has a
///    claimable target F, and F's own `fix_target_status` (populated by
///    `deps-lsp`'s phase B, #462) clears it as a verified fix — see the
///    private `build_vulnerability_fix_action` helper just above. This action
///    is computed entirely from `versions` and the dependency's declared
///    requirement, deliberately *before* the `registry.get_versions` call
///    below — a registry *error* returned to this request must not hide a
///    known-vulnerable dependency's fix (FR-007), so this action is still
///    returned when the registry fetch that produces the plain list below
///    fails. An *unverified* lookup (timeout, a failure already known from
///    the background fetch or the interactive memo, or the concurrency cap)
///    drops it: its yank check cannot run (#1830). This does
///    not extend to an *OSV* outage or unavailability: F's verification is an
///    OSV-derived precondition (`fix_target_status`), not a registry one, so
///    an OSV outage — or a code-action request racing ahead of phase B
///    completing — degrades to omitting this action entirely rather than
///    presenting an unverified F as verified (FR-004, fail-safe). When the
///    registry fetch does succeed, a fix target the registry reports as
///    yanked is dropped rather than offered.
/// 2. At most one `QUICKFIX` "fix unsatisfiable requirement" action, computed the same
///    registry-independent way (see the private `build_unsatisfiable_fix_action` helper
///    just above) for the same FR-007 reason. If its rewritten text collides with the
///    vulnerability fix's (both yank-filtered first), it is dropped in favor of the
///    vulnerability fix, whose title is the more informative of the two.
/// 3. Up to five plain `REFACTOR` "update to `<version>`" actions, one per
///    non-yanked version [`crate::completion::prepare_version_display_items`]
///    selects from the registry response. Each action's edit text
///    comes from [`crate::lsp_helpers::PackageRendering::format_version_replacing`], which
///    preserves the manifest's existing pin/operator style where an
///    ecosystem overrides it (e.g. PyPI's `==1.0.1` stays `==1.0.2` rather
///    than expanding to a `>=,<` range). Every entry's formatted edit text is
///    checked against a running set seeded with the declared requirement and
///    the two fix actions' own formatted text (whitespace-insensitive); an entry
///    is skipped, and never added to the set, when its text is already
///    present. This is the common case, not a rare edge case:
///    [`crate::completion::prepare_version_display_items`] normally lists the newest 5
///    non-yanked registry versions in raw order, so whenever the declared version is
///    already within 5 releases of latest, it is itself one of the display items being
///    offered as an "update" — and when the registry-selected latest falls outside that
///    raw-order window, it is bumped in as the final display item instead (#956), so the
///    declared version can also collide with *that* entry rather than one of the top 5.
///    The same set also
///    catches two display items whose formatted text coincides — e.g. an
///    ecosystem formatter that truncates precision (PyPI's
///    `truncate_release_to_match`) can map several distinct registry
///    versions to the same rewritten text — and a display item matching a
///    fix action's target even when their *raw* versions differ (formatting
///    can normalize two distinct inputs to the same text). Textual (not
///    semantic) equality is deliberate: `formatter.is_requirement_up_to_date`
///    answers "does `latest` already satisfy this requirement", which is
///    true for e.g. `is_requirement_up_to_date("^1.0", "1.2.0")` and would
///    wrongly suppress every explicit-bump action for a range-style
///    requirement; it also can't detect a pinned no-op like `==1.0.0` ->
///    `==1.0.0`, since it never compares the formatted edit text at all.
///
/// Every action above is built with `is_preferred: None`; exactly one is promoted to
/// `Some(true)` in a single post-pass once all three kinds have been considered, in
/// priority order: the vulnerability fix, then the unsatisfiable fix, then the REFACTOR
/// item whose `item.is_latest` is set. LSP's `isPreferred` is a flat per-response boolean
/// with no per-diagnostic scoping, so "at most one preferred action" must hold across all
/// producers, not per producer — building every action with `None` and resolving the flag
/// once here, rather than at each construction site, is what keeps that invariant
/// structural (checkable with one `filter().count() <= 1` assertion) instead of something
/// every future producer has to remember to uphold by hand. A vulnerability is silent and
/// security-relevant; an unsatisfiable requirement is loud (the package manager already
/// fails the build) but merely inconvenient; both outrank a routine "update to latest".
/// This resolution runs on every return path below that can carry a fix action, including
/// the registry-outage path, so an outage never silently drops `isPreferred` from an
/// already-built fix.
///
/// Returns an empty `Vec` also when no fix action applies and the registry fetch fails.
///
/// No `# Examples` here: exercising this meaningfully needs a `Registry`
/// impl plus `ParseResult`/`Dependency` mocks, which live as private test
/// fixtures in the sibling `test_support` module rather than as public
/// API — see the `generate_code_actions_*` tests here for realistic calls.
pub async fn generate_code_actions<P, F, R>(
    parse_result: &P,
    position: Position,
    uri: &url::Url,
    versions: VersionData<'_>,
    content: &str,
    registry: &R,
    formatter: &F,
) -> Vec<CodeAction>
where
    P: TypedParseResult,
    F: DependencyFormatter<Dep = P::Dep>,
    R: Registry + ?Sized,
{
    let deps = parse_result.own_dependencies();
    let mut actions = Vec::with_capacity(deps.len().min(5) + 1);

    let Some(ActionTarget {
        dep,
        version_range,
        version_req,
        literal_target,
        line_offsets,
    }) = locate_action_target(deps, position, content, formatter)
    else {
        return actions;
    };

    // Both fix actions are built before the registry fetch below so a registry outage
    // never suppresses an OSV-derived fix (FR-007) or a known-unsatisfiable one.
    let fix = build_vulnerability_fix_action(
        parse_result,
        dep,
        uri,
        version_range,
        versions,
        version_req.as_str(),
        formatter,
    );
    let unsat_fix =
        build_unsatisfiable_fix_action(dep, uri, version_range, versions, version_req, formatter);
    // Registry-independent for the same FR-007 reason as the two fix actions above —
    // `versions.outcomes`' deprecation channel is cache-derived, not a fresh registry call.
    let replacement_action = build_replacement_action(
        dep,
        uri,
        version_range,
        versions,
        content,
        &line_offsets,
        formatter,
    );

    let fetched = fetch_fix_versions(registry, dep, uri, versions, formatter).await;

    // A fix target the registry reports as yanked is dropped entirely rather than offered —
    // see `FetchedVersions::rules_out`. Yank-filtering both actions before the collision check
    // below matters: PyPI's `truncate_release_to_match` can map a yanked and a live version to
    // identical rewritten text, so checking collision first could drop the unsat action against
    // a vuln fix the yank filter was about to drop anyway, leaving neither behind.
    let fix = fix.filter(|f| !fetched.rules_out(&f.version_native));
    let unsat_fix = unsat_fix
        .filter(|f| !fetched.rules_out(&f.version_native))
        .filter(|u| {
            fix.as_ref()
                .is_none_or(|f| strip_whitespace(&f.new_text) != strip_whitespace(&u.new_text))
        });

    // Captured before each action's `.action` moves into `actions` below, so the dedup
    // seeding and the `is_preferred` post-pass read back the exact text/index without
    // recomputing or re-deriving them (see `VulnerabilityFixAction::new_text`'s doc comment).
    let fix_new_text = fix.as_ref().map(|f| strip_whitespace(&f.new_text));
    let unsat_new_text = unsat_fix.as_ref().map(|f| strip_whitespace(&f.new_text));

    let mut vuln_idx = None;
    if let Some(fix) = fix {
        vuln_idx = Some(actions.len());
        actions.push(fix.action);
    }
    let mut unsat_idx = None;
    if let Some(unsat_fix) = unsat_fix {
        unsat_idx = Some(actions.len());
        actions.push(unsat_fix.action);
    }
    if let Some(replacement_action) = replacement_action {
        actions.push(replacement_action);
    }

    // De-dups every REFACTOR edit's formatted text against the declared literal and both fix
    // actions', so no two actions carry a byte-identical `WorkspaceEdit`. Seeded with
    // `literal_target` (not `version_req`) for the same reason as the literal-span guard — e.g.
    // `deps-swift`'s synthesized `"=2.61.0"` requirement never equals the formatted edit text.
    let mut emitted_texts: HashSet<String> = HashSet::new();
    emitted_texts.insert(strip_whitespace(literal_target));
    emitted_texts.extend(fix_new_text);
    emitted_texts.extend(unsat_new_text);

    let mut latest_refactor_idx = None;
    // A pin proved ahead of the latest release would be downgraded by "Update to X".
    let proven_ahead = matches!(
        formatter.hover_provenance(dep),
        Some(crate::lsp_helpers::HoverProvenance::CommitAheadOfLatestRelease { .. })
    );
    // #1370: central placeholder gate — an unexpanded placeholder has no concrete version
    // text a REFACTOR "Update to X" action could ever replace, so the whole loop is skipped
    // rather than relying on every generated edit happening to dedup away as a no-op.
    if !proven_ahead
        && !requirement_is_placeholder_for(formatter, dep, version_req.as_str())
        && let Some(registry_versions) = &fetched.live
    {
        let refactor = RefactorContext {
            parse_result,
            dep,
            uri,
            version_range,
            version_req,
            versions: &versions,
            formatter,
        };
        latest_refactor_idx = push_refactor_actions(
            &refactor,
            registry,
            registry_versions,
            &mut emitted_texts,
            &mut actions,
        );
    }

    // Single post-pass resolving `isPreferred`, priority order vuln fix -> unsat fix -> latest
    // REFACTOR item, run unconditionally (including the registry-outage path) so an outage
    // never drops `isPreferred` from an already-built fix action.
    #[expect(
        clippy::indexing_slicing,
        reason = "each *_idx was captured as actions.len() immediately before its matching \
                  push, so it stays a valid index here"
    )]
    if let Some(i) = vuln_idx.or(unsat_idx).or(latest_refactor_idx) {
        actions[i].is_preferred = Some(true);
    }

    actions
}

/// The dependency a code action request lands on, with the version text it would rewrite.
struct ActionTarget<'a, D> {
    dep: &'a D,
    version_range: Range,
    version_req: &'a VersionReq,
    literal_target: &'a str,
    line_offsets: LineOffsetTable,
}

/// The dependency at `position` whose version literal still sits at its recorded range, or
/// `None` when no code action can safely target it.
fn locate_action_target<'a, F: DependencyFormatter>(
    deps: &'a [F::Dep],
    position: Position,
    content: &str,
    formatter: &F,
) -> Option<ActionTarget<'a, F::Dep>> {
    let dep = deps
        .iter()
        .find(|d| formatter.is_position_on_dependency(d, position.into()))?;
    let version_range: Range = dep.version_range()?.into();
    let version_req = dep.version_requirement()?;
    if version_req.as_str().is_empty() {
        // Defense-in-depth, mirroring `collect_update_all_edits`: an empty
        // requirement would trivially satisfy the guard below.
        return None;
    }
    let line_offsets = LineOffsetTable::new(content);
    let slice = slice_for_range(content, &line_offsets, version_range.into());
    let literal_target = dep
        .version_literal()
        .unwrap_or_else(|| version_req.as_str());
    // Literal-span guard — see `generate_code_actions`'s doc comment.
    literal_span_matches(slice, literal_target).then_some(ActionTarget {
        dep,
        version_range,
        version_req,
        literal_target,
        line_offsets,
    })
}

/// The registry's answer for a code action's dependency.
pub(super) struct FetchedVersions {
    live: Option<Arc<[Box<dyn Version>]>>,
    unverified: bool,
}

impl FetchedVersions {
    /// The live version list, when the registry answered with one.
    pub(super) const fn live(&self) -> Option<&Arc<[Box<dyn Version>]>> {
        self.live.as_ref()
    }

    /// Whether the lookup ended without the registry having answered either way (a timeout, a
    /// shed request): the case in which `codeAction` withholds every speculative action.
    pub(super) const fn is_unverified(&self) -> bool {
        self.unverified
    }

    /// The registry's answer as `codeAction` reads it, from an interactive lookup's outcome.
    pub(super) fn from_interactive(fetch: InteractiveFetch<Arc<[Box<dyn Version>]>>) -> Self {
        match fetch {
            InteractiveFetch::Live(list) => Self {
                live: Some(list),
                unverified: false,
            },
            InteractiveFetch::Degraded(NoLiveList::Failed) => Self {
                live: None,
                unverified: false,
            },
            InteractiveFetch::Degraded(NoLiveList::Unverified) => Self {
                live: None,
                unverified: true,
            },
        }
    }

    /// Whether a fix targeting `version_native` must be dropped.
    ///
    /// On a genuine registry outage (`NoLiveList::Failed`) both fix actions still pass through
    /// unfiltered, unchanged from before #1204. An *unverified* answer is treated differently
    /// (checked first): a timeout, a failure only inferred from the background fetch, or the
    /// interactive concurrency cap means the registry never said no, so a live answer
    /// confirming or denying the yank may well have been moments away — failing open here would
    /// let a slow registry silently suppress the very yank check this exists for. Both
    /// speculative actions are dropped outright instead.
    fn rules_out(&self, version_native: &str) -> bool {
        self.unverified
            || self.live.as_ref().is_some_and(|versions_list| {
                versions_list
                    .iter()
                    .find(|v| v.version_string() == version_native)
                    .is_some_and(|v| v.removal_status().blocks_resolution())
            })
    }
}

/// Fetches the dependency's versions, gated on `can_resolve_source` (#248/FR-001): a
/// Git/Path/unresolved-custom-registry dependency must never be looked up against this
/// ecosystem's default registry client, which would offer bogus "update to X" actions for an
/// unrelated package.
async fn fetch_fix_versions<R: Registry + ?Sized>(
    registry: &R,
    dep: &dyn Dependency,
    uri: &url::Url,
    versions: VersionData<'_>,
    formatter: &dyn EcosystemFormatter,
) -> FetchedVersions {
    if !formatter.can_resolve_source(&dep.source()) {
        return FetchedVersions {
            live: None,
            unverified: false,
        };
    }
    FetchedVersions::from_interactive(
        await_interactive_versions(
            registry,
            InteractiveFetchRequest::for_dependency(
                versions,
                uri,
                dep,
                formatter,
                FetchContext::CodeAction,
            ),
            crate::freshness::FreshnessSettings::Disabled,
        )
        .await,
    )
}

/// What [`push_refactor_actions`] needs to know about the targeted dependency.
struct RefactorContext<'a, 'v, P: TypedParseResult, F> {
    parse_result: &'a P,
    dep: &'a P::Dep,
    uri: &'a url::Url,
    version_range: Range,
    version_req: &'a VersionReq,
    versions: &'a VersionData<'v>,
    formatter: &'a F,
}

/// A display version that passed every gate of [`refactor_targets`], with the requirement text
/// that replaces the dependency's current one.
struct RefactorTarget {
    item: crate::completion::VersionDisplayItem,
    new_text: String,
}

/// The display versions an "Update to X" REFACTOR action may target: stable-policy filtered,
/// safe to write, OSV-verified, and rendered into a requirement by the ecosystem. Shared by
/// [`push_refactor_actions`] and [`code_actions_offered`], so the hover footer and `codeAction`
/// agree on whether any exist.
fn refactor_targets<P, F, R>(
    ctx: &RefactorContext<'_, '_, P, F>,
    registry: &R,
    registry_versions: &[Box<dyn Version>],
) -> Vec<RefactorTarget>
where
    P: TypedParseResult,
    F: DependencyFormatter<Dep = P::Dep>,
    R: Registry + ?Sized,
{
    use crate::completion::prepare_version_display_items;

    let RefactorContext {
        parse_result,
        dep,
        version_req,
        versions,
        formatter,
        ..
    } = *ctx;
    let key = PackageKey::new(dep.name(), formatter);
    // Issue #1517/#1524: computed once, shared by both the `item.is_latest` gate (via
    // `latest_verdict`) and every other display item's own gate (via `candidate_verdict`)
    // below.
    let latest_vuln_keys = super::hover::vuln_keys_for(parse_result, versions, formatter);

    // Same registry-delegated pick hover's `live_latest_idx` uses (see
    // `prepare_version_display_items`'s doc comment) — not a re-derived `is_stable()` scan.
    // Threads `parse_result`'s own `SelectionContext` (e.g. Composer's
    // `minimum-stability`, #1433) so this action never disagrees with hover/diagnostics
    // about what "latest" means for the same dependency.
    let latest_idx = registry.select_latest_matching(
        registry_versions,
        &crate::existence_wildcard_req(),
        &parse_result.selection_context(),
    );
    let mut display_items =
        prepare_version_display_items(registry_versions, dep.name(), latest_idx);
    let in_use = versions.ecosystem.and_then(|ecosystem| {
        super::resolve_in_use_version(
            dep,
            &key,
            versions.resolved_map(),
            versions.candidates_map(),
            formatter,
            ecosystem,
        )
    });
    let prereleases: HashSet<&str> = registry_versions
        .iter()
        .filter(|v| v.is_prerelease())
        .map(|v| v.version_string().as_str())
        .collect();
    let pick = latest_idx
        .and_then(|i| registry_versions.get(i))
        .map(|v| v.version_string());
    // The registry pick (`is_latest`) is exempt: it already carries the ecosystem's
    // stability policy, and hover must agree with this action about "latest" (#952).
    if PrereleasePolicy::for_dependency(&prereleases, pick, in_use.as_ref(), version_req, formatter)
        == PrereleasePolicy::StableOnly
    {
        display_items.retain(|item| item.is_latest || !prereleases.contains(item.version.as_str()));
    }

    let mut targets = Vec::new();
    for item in display_items {
        if !is_safe_version_string(item.version.as_str()) {
            warn_rejected_value(
                "is_safe_version_string",
                "update-to-version refactor code action",
                item.version.as_str(),
            );
            continue;
        }
        // Issue #1517/#1524: never offer an "update to X" quickfix unless OSV has
        // actually verified this exact version (or does not apply at all) — a
        // Flagged/Unverified candidate must never be one keystroke away from landing in
        // the manifest. `latest_verdict` (phase B's single "latest" check) covers the
        // `is_latest` item; every other display item is covered by `candidate_verdict`
        // (phase B's separate multi-candidate check, #1524).
        let verdict = if item.is_latest {
            latest_verdict(
                versions.latest_status,
                dep,
                latest_vuln_keys.as_ref(),
                &key,
                item.version.as_str(),
                formatter,
            )
        } else {
            candidate_verdict(
                versions.candidate_status,
                dep,
                latest_vuln_keys.as_ref(),
                &key,
                item.version.as_str(),
                formatter,
            )
        };
        if !matches!(
            verdict,
            LatestVerdict::Verified | LatestVerdict::NotApplicable
        ) {
            continue;
        }
        // Unreachable after the gate above; fails closed rather than unwrapping.
        let Some(new_text) = replacement_text(formatter, dep, &item.version, version_req.as_str())
        else {
            continue;
        };
        targets.push(RefactorTarget { item, new_text });
    }
    targets
}

/// Pushes one REFACTOR "Update to X" action per distinct, OSV-verified display version, and
/// returns the index of the one for the registry's latest pick, if any.
fn push_refactor_actions<P, F, R>(
    ctx: &RefactorContext<'_, '_, P, F>,
    registry: &R,
    registry_versions: &[Box<dyn Version>],
    emitted_texts: &mut HashSet<String>,
    actions: &mut Vec<CodeAction>,
) -> Option<usize>
where
    P: TypedParseResult,
    F: DependencyFormatter<Dep = P::Dep>,
    R: Registry + ?Sized,
{
    let mut latest_refactor_idx = None;
    for RefactorTarget { item, new_text } in refactor_targets(ctx, registry, registry_versions) {
        if !emitted_texts.insert(strip_whitespace(&new_text)) {
            continue;
        }

        let edits = single_file_edit(ctx.uri, ctx.version_range.into(), new_text);

        if item.is_latest {
            latest_refactor_idx = Some(actions.len());
        }
        actions.push(CodeAction {
            title: item.label,
            kind: Some(CodeActionKind::REFACTOR),
            edit: Some(WorkspaceEdit {
                changes: Some(edits),
                ..Default::default()
            }),
            // Resolved once by `generate_code_actions`, for every producer at once.
            is_preferred: None,
            ..Default::default()
        });
    }
    latest_refactor_idx
}

#[cfg(test)]
#[expect(
    clippy::cast_possible_truncation,
    reason = "#673: fixed test-fixture lengths cast to u32 for Position/Range fixtures never \
              approach truncation range"
)]
mod tests {
    use super::*;
    use crate::lsp_helpers::test_support::*;
    use crate::lsp_helpers::test_support_lsp::*;
    use crate::lsp_helpers::*;
    use crate::position::{Position, Range};
    use crate::{ConcreteVersion, Dependency, PackageName, ParseResult, VersionReq};
    use std::collections::HashMap;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_generate_code_actions_combines_advisories_sharing_the_highest_fix() {
        use crate::osv::{
            Advisory, Capped, DependencyVulnerabilities, OsvVersion, UpgradeStatus, VulnSeverity,
        };
        use std::collections::HashMap;

        let (dep, version_range, content) = vulnerable_dep("1.0.0");
        let parse_result = MockParseResult {
            deps: vec![dep],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let mut vulnerabilities = crate::osv::VulnerabilityMap::new();
        vulnerabilities.insert(
            crate::test_util::vuln_key("pkg"),
            ScanOutcome::Vulnerable(DependencyVulnerabilities {
                sibling_matches: None,
                advisories: Capped::new(
                    vec![
                        std::sync::Arc::new(
                            Advisory::new(
                                "A1".to_string(),
                                "2023-01-01T00:00:00Z".to_string(),
                                VulnSeverity::High,
                            )
                            .expect("valid osv id")
                            .with_fixed_versions(vec![OsvVersion::new("1.1.0")]),
                        ),
                        std::sync::Arc::new(
                            Advisory::new(
                                "A2".to_string(),
                                "2023-01-01T00:00:00Z".to_string(),
                                VulnSeverity::Critical,
                            )
                            .expect("valid osv id")
                            .with_fixed_versions(vec![OsvVersion::new("1.2.0")]),
                        ),
                    ],
                    2,
                ),
                fix_target_status: UpgradeStatus::CandidateClean {
                    version: ConcreteVersion::new("1.2.0"),
                },
            }),
        );

        let cached = HashMap::new();
        let resolved = HashMap::new();
        let versions = VersionData::new(&cached, &resolved).with_vulnerabilities(&vulnerabilities);

        let actions = generate_code_actions(
            &parse_result,
            version_range.start,
            parse_result.uri(),
            versions,
            &content,
            &MockRegistry,
            &MOCK_FORMATTER,
        )
        .await;

        let titles = quickfix_titles(&actions);
        assert_eq!(titles, vec!["Update to 1.2.0 (fixes A2 +1 more)"]);
        assert_eq!(actions[0].kind, Some(CodeActionKind::QUICKFIX));
        assert_eq!(actions[0].is_preferred, Some(true));
        // Both A1 and A2 are within the display cap (only 2 advisories total) here, so the
        // full claimed id list travels in `data` for the diagnostics binding — see the
        // `_diagnostic_codes_restricted_to_displayed_advisories` tests below for the case
        // where a claimed id sits beyond the display cap and must be excluded from `data`.
        assert_eq!(
            actions[0].data,
            Some(serde_json::json!({
                "diagnostic_codes": ["A2", "A1"],
                "diagnostic_range": version_range,
            }))
        );
    }

    /// #1422 follow-up (lead-side review finding): `recommended_fix()`'s `advisory_ids` is
    /// computed over the full `MAX_ADVISORY_RECORDS`-capped fetch set, but
    /// `push_vulnerability_diagnostics` only ever publishes `Diagnostic`s for
    /// `advisories_for_display()`'s `ADVISORY_DISPLAY_CAP`-truncated set. When some — but not
    /// all — of a fix's claimed ids fall outside the displayed set, `data.diagnostic_codes`
    /// must list only the displayed ones, so `bind_diagnostics` never carries an id the client
    /// could never have a matching `Diagnostic` for.
    #[tokio::test]
    async fn test_generate_code_actions_diagnostic_codes_restricted_to_displayed_advisories_partial_overlap()
     {
        use crate::osv::{
            Advisory, Capped, DependencyVulnerabilities, OsvVersion, UpgradeStatus, VulnSeverity,
        };
        use std::collections::HashMap;

        let (dep, version_range, content) = vulnerable_dep("1.0.0");
        let parse_result = MockParseResult {
            deps: vec![dep],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        // A1..A5 (High, displayed — ties break by id) plus A6 (Low, beyond the 5-item display
        // cap). Only A1 (displayed) and A6 (not displayed) carry a known fix; A6's is higher.
        let mut advisories: Vec<Arc<Advisory>> = vec![Arc::new(
            Advisory::new(
                "A1".to_string(),
                "2023-01-01T00:00:00Z".to_string(),
                VulnSeverity::High,
            )
            .expect("valid osv id")
            .with_fixed_versions(vec![OsvVersion::new("1.5.0")]),
        )];
        advisories.extend((2..=5).map(|i| {
            Arc::new(
                Advisory::new(
                    format!("A{i}"),
                    "2023-01-01T00:00:00Z".to_string(),
                    VulnSeverity::High,
                )
                .expect("valid osv id"),
            )
        }));
        advisories.push(Arc::new(
            Advisory::new(
                "A6".to_string(),
                "2023-01-01T00:00:00Z".to_string(),
                VulnSeverity::Low,
            )
            .expect("valid osv id")
            .with_fixed_versions(vec![OsvVersion::new("2.0.0")]),
        ));
        let total = advisories.len();

        let mut vulnerabilities = crate::osv::VulnerabilityMap::new();
        vulnerabilities.insert(
            crate::test_util::vuln_key("pkg"),
            ScanOutcome::Vulnerable(DependencyVulnerabilities {
                sibling_matches: None,
                advisories: Capped::new(advisories, total),
                fix_target_status: UpgradeStatus::CandidateClean {
                    version: ConcreteVersion::new("2.0.0"),
                },
            }),
        );

        let cached = HashMap::new();
        let resolved = HashMap::new();
        let versions = VersionData::new(&cached, &resolved).with_vulnerabilities(&vulnerabilities);

        let actions = generate_code_actions(
            &parse_result,
            version_range.start,
            parse_result.uri(),
            versions,
            &content,
            &MockRegistry,
            &MOCK_FORMATTER,
        )
        .await;

        let titles = quickfix_titles(&actions);
        assert_eq!(
            titles,
            vec!["Update to 2.0.0 (fixes A1 +1 more)"],
            "the title still names the true fix, unrestricted"
        );
        assert_eq!(
            actions[0].data,
            Some(serde_json::json!({
                "diagnostic_codes": ["A1"],
                "diagnostic_range": version_range,
            })),
            "A6 is claimed but never displayed as a Diagnostic, so it must not appear in \
             diagnostic_codes even though the title/edit still report the true A1+A6 fix"
        );
    }

    /// Same follow-up as the partial-overlap test above, but for the case none of a fix's
    /// claimed ids are displayed at all — `data` must be omitted entirely (not set to an id
    /// list that can never match any client-supplied `Diagnostic`), while the action itself
    /// (title, edit, target version) is still returned correctly.
    #[tokio::test]
    async fn test_generate_code_actions_diagnostic_codes_omitted_when_fix_is_entirely_beyond_display_cap()
     {
        use crate::osv::{
            Advisory, Capped, DependencyVulnerabilities, OsvVersion, UpgradeStatus, VulnSeverity,
        };
        use std::collections::HashMap;

        let (dep, version_range, content) = vulnerable_dep("1.0.0");
        let parse_result = MockParseResult {
            deps: vec![dep],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        // A1..A5 (Critical, displayed, no known fix) plus A6 (Low, beyond the display cap, the
        // only advisory with a known fix) — the exact #1422 repro shape (golang.org/x/net-style:
        // the highest-severity, displayed advisories have no fix; the fix lives beyond the cap).
        let mut advisories: Vec<Arc<Advisory>> = (1..=5)
            .map(|i| {
                Arc::new(
                    Advisory::new(
                        format!("A{i}"),
                        "2023-01-01T00:00:00Z".to_string(),
                        VulnSeverity::Critical,
                    )
                    .expect("valid osv id"),
                )
            })
            .collect();
        advisories.push(Arc::new(
            Advisory::new(
                "A6".to_string(),
                "2023-01-01T00:00:00Z".to_string(),
                VulnSeverity::Low,
            )
            .expect("valid osv id")
            .with_fixed_versions(vec![OsvVersion::new("2.0.0")]),
        ));
        let total = advisories.len();

        let mut vulnerabilities = crate::osv::VulnerabilityMap::new();
        vulnerabilities.insert(
            crate::test_util::vuln_key("pkg"),
            ScanOutcome::Vulnerable(DependencyVulnerabilities {
                sibling_matches: None,
                advisories: Capped::new(advisories, total),
                fix_target_status: UpgradeStatus::CandidateClean {
                    version: ConcreteVersion::new("2.0.0"),
                },
            }),
        );

        let cached = HashMap::new();
        let resolved = HashMap::new();
        let versions = VersionData::new(&cached, &resolved).with_vulnerabilities(&vulnerabilities);

        let actions = generate_code_actions(
            &parse_result,
            version_range.start,
            parse_result.uri(),
            versions,
            &content,
            &MockRegistry,
            &MOCK_FORMATTER,
        )
        .await;

        let titles = quickfix_titles(&actions);
        assert_eq!(
            titles,
            vec!["Update to 2.0.0 (fixes A6)"],
            "the true fix (A6, beyond the display cap) must still be recommended"
        );
        assert!(
            actions[0].data.is_none(),
            "no claimed id is displayed, so data must be omitted rather than set to an id \
             list bind_diagnostics could never match: {:?}",
            actions[0].data
        );
    }

    #[tokio::test]
    async fn test_generate_code_actions_fix_target_is_not_inflated_by_a_subtracted_advisory() {
        // Critic S1 counterexample: A1 (fixed 3.0.0) still applies at the checked candidate
        // and is excluded from the claim; A2 (fixed 1.2.0) is claimed. Recommended target
        // must be 1.2.0 — what's actually claimed — not 3.0.0, an unnecessary major-version
        // jump that doesn't even resolve A1.
        //
        // #462 critic S1: `fix_target_status` is deliberately `CandidateVulnerable{1.2.0,
        // [A1]}`, not `CandidateClean`, since A1 (fixed only at 3.0.0) still applies at F=1.2.0
        // — this must still present as a fix for A2, the honest #216 partial-fix contract.
        use crate::osv::{
            Advisory, Capped, DependencyVulnerabilities, OsvVersion, UpgradeStatus, VulnSeverity,
        };
        use std::collections::HashMap;

        let (dep, version_range, content) = vulnerable_dep("1.0.0");
        let parse_result = MockParseResult {
            deps: vec![dep],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let mut vulnerabilities = crate::osv::VulnerabilityMap::new();
        vulnerabilities.insert(
            crate::test_util::vuln_key("pkg"),
            ScanOutcome::Vulnerable(DependencyVulnerabilities {
                sibling_matches: None,
                advisories: Capped::new(
                    vec![
                        std::sync::Arc::new(
                            Advisory::new(
                                "A1".to_string(),
                                "2023-01-01T00:00:00Z".to_string(),
                                VulnSeverity::High,
                            )
                            .expect("valid osv id")
                            .with_fixed_versions(vec![OsvVersion::new("3.0.0")]),
                        ),
                        std::sync::Arc::new(
                            Advisory::new(
                                "A2".to_string(),
                                "2023-01-01T00:00:00Z".to_string(),
                                VulnSeverity::Medium,
                            )
                            .expect("valid osv id")
                            .with_fixed_versions(vec![OsvVersion::new("1.2.0")]),
                        ),
                    ],
                    2,
                ),
                fix_target_status: UpgradeStatus::CandidateVulnerable {
                    version: ConcreteVersion::new("1.2.0"),
                    advisory_ids: Capped::new(vec![crate::test_util::osv_id("A1")], 1),
                    worst_severity: Some(VulnSeverity::High),
                    via_sibling_tags: None,
                },
            }),
        );
        let mut latest_status = crate::osv::LatestStatusMap::new();
        latest_status.insert(
            crate::test_util::vuln_key("pkg"),
            UpgradeStatus::CandidateVulnerable {
                version: ConcreteVersion::new("3.0.0"),
                advisory_ids: Capped::new(vec![crate::test_util::osv_id("A1")], 1),
                worst_severity: Some(VulnSeverity::High),
                via_sibling_tags: None,
            },
        );

        let cached = HashMap::new();
        let resolved = HashMap::new();
        let versions = VersionData::new(&cached, &resolved)
            .with_vulnerabilities(&vulnerabilities)
            .with_latest_status(&latest_status);

        let actions = generate_code_actions(
            &parse_result,
            version_range.start,
            parse_result.uri(),
            versions,
            &content,
            &MockRegistry,
            &MOCK_FORMATTER,
        )
        .await;

        let titles = quickfix_titles(&actions);
        assert_eq!(titles, vec!["Update to 1.2.0 (fixes A2)"]);
    }

    #[tokio::test]
    async fn test_generate_code_actions_fix_target_is_not_suppressed_by_an_open_ended_advisory() {
        // #462 critic re-critique: a dependency with an open-ended advisory (A1, no known fix)
        // must not lose its quickfix. `recommended_fix()` excludes A1 from `claimed` for
        // having no `fixed_versions` (unlike the still-applying-at-latest subtraction the
        // `..._subtracted_advisory` test above exercises), so F is computed from A2 alone —
        // still presented as a fix for A2, the honest #216 partial-fix contract.
        use crate::osv::{
            Advisory, Capped, DependencyVulnerabilities, OsvVersion, UpgradeStatus, VulnSeverity,
        };
        use std::collections::HashMap;

        let (dep, version_range, content) = vulnerable_dep("1.0.0");
        let parse_result = MockParseResult {
            deps: vec![dep],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let mut vulnerabilities = crate::osv::VulnerabilityMap::new();
        vulnerabilities.insert(
            crate::test_util::vuln_key("pkg"),
            ScanOutcome::Vulnerable(DependencyVulnerabilities {
                sibling_matches: None,
                advisories: Capped::new(
                    vec![
                        std::sync::Arc::new(
                            Advisory::new(
                                "A1".to_string(),
                                "2023-01-01T00:00:00Z".to_string(),
                                VulnSeverity::High,
                            )
                            .expect("valid osv id"),
                        ),
                        std::sync::Arc::new(
                            Advisory::new(
                                "A2".to_string(),
                                "2023-01-01T00:00:00Z".to_string(),
                                VulnSeverity::Medium,
                            )
                            .expect("valid osv id")
                            .with_fixed_versions(vec![OsvVersion::new("1.2.0")]),
                        ),
                    ],
                    2,
                ),
                fix_target_status: UpgradeStatus::CandidateVulnerable {
                    version: ConcreteVersion::new("1.2.0"),
                    advisory_ids: Capped::new(vec![crate::test_util::osv_id("A1")], 1),
                    worst_severity: Some(VulnSeverity::High),
                    via_sibling_tags: None,
                },
            }),
        );

        let cached = HashMap::new();
        let resolved = HashMap::new();
        let versions = VersionData::new(&cached, &resolved).with_vulnerabilities(&vulnerabilities);

        let actions = generate_code_actions(
            &parse_result,
            version_range.start,
            parse_result.uri(),
            versions,
            &content,
            &MockRegistry,
            &MOCK_FORMATTER,
        )
        .await;

        let titles = quickfix_titles(&actions);
        assert_eq!(titles, vec!["Update to 1.2.0 (fixes A2)"]);
    }

    #[tokio::test]
    async fn test_generate_code_actions_omits_fix_when_fix_target_status_reports_still_vulnerable()
    {
        // #462 critic C1 repro (smallvec 0.6.0 -> F=0.6.13, still affected by
        // RUSTSEC-2021-0003, an advisory phase A's declared-version-only query never saw):
        // the live verification of F reports an id (A2) this dependency's `advisories` never
        // recorded at all. Unlike an already-known-and-excluded advisory, a brand-new unknown
        // advisory must always suppress the fix — not #216's honest partial-fix case, exactly
        // the gap #462 closes.
        use crate::osv::{
            Advisory, Capped, DependencyVulnerabilities, OsvVersion, UpgradeStatus, VulnSeverity,
        };
        use std::collections::HashMap;

        let (dep, version_range, content) = vulnerable_dep("1.0.0");
        let parse_result = MockParseResult {
            deps: vec![dep],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let mut vulnerabilities = crate::osv::VulnerabilityMap::new();
        vulnerabilities.insert(
            crate::test_util::vuln_key("pkg"),
            ScanOutcome::Vulnerable(DependencyVulnerabilities {
                sibling_matches: None,
                advisories: Capped::new(
                    vec![std::sync::Arc::new(
                        Advisory::new(
                            "A1".to_string(),
                            "2023-01-01T00:00:00Z".to_string(),
                            VulnSeverity::High,
                        )
                        .expect("valid osv id")
                        .with_fixed_versions(vec![OsvVersion::new("1.2.0")]),
                    )],
                    1,
                ),
                fix_target_status: UpgradeStatus::CandidateVulnerable {
                    version: ConcreteVersion::new("1.2.0"),
                    advisory_ids: Capped::new(vec![crate::test_util::osv_id("A2")], 1),
                    worst_severity: Some(VulnSeverity::High),
                    via_sibling_tags: None,
                },
            }),
        );

        let cached = HashMap::new();
        let resolved = HashMap::new();
        let versions = VersionData::new(&cached, &resolved).with_vulnerabilities(&vulnerabilities);

        let actions = generate_code_actions(
            &parse_result,
            version_range.start,
            parse_result.uri(),
            versions,
            &content,
            &MockRegistry,
            &MOCK_FORMATTER,
        )
        .await;

        assert!(
            quickfix_titles(&actions).is_empty(),
            "a fix target OSV found still vulnerable must never be presented as a verified fix"
        );
    }

    #[tokio::test]
    async fn test_generate_code_actions_omits_fix_when_fix_target_status_reports_a_claimed_advisory_still_applies()
     {
        // #462 FR-003, the other half of the S1 fix: unlike an already-excluded known
        // advisory, a live check reporting that a *claimed* advisory (one `fix.advisory_ids`
        // actually names) still applies to F means the fix doesn't do what its own title
        // says — this must suppress the action even though the id is known, distinguishing
        // it from the `..._subtracted_advisory` test's honest-partial-fix case.
        use crate::osv::{
            Advisory, Capped, DependencyVulnerabilities, OsvVersion, UpgradeStatus, VulnSeverity,
        };
        use std::collections::HashMap;

        let (dep, version_range, content) = vulnerable_dep("1.0.0");
        let parse_result = MockParseResult {
            deps: vec![dep],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let mut vulnerabilities = crate::osv::VulnerabilityMap::new();
        vulnerabilities.insert(
            crate::test_util::vuln_key("pkg"),
            ScanOutcome::Vulnerable(DependencyVulnerabilities {
                sibling_matches: None,
                advisories: Capped::new(
                    vec![std::sync::Arc::new(
                        Advisory::new(
                            "A1".to_string(),
                            "2023-01-01T00:00:00Z".to_string(),
                            VulnSeverity::High,
                        )
                        .expect("valid osv id")
                        .with_fixed_versions(vec![OsvVersion::new("1.2.0")]),
                    )],
                    1,
                ),
                // A1 is claimed (it's the only advisory, with a known fix, and nothing
                // excludes it), yet the live check of F=1.2.0 reports A1 itself still
                // applies — a claim the verification actually contradicts.
                fix_target_status: UpgradeStatus::CandidateVulnerable {
                    version: ConcreteVersion::new("1.2.0"),
                    advisory_ids: Capped::new(vec![crate::test_util::osv_id("A1")], 1),
                    worst_severity: Some(VulnSeverity::High),
                    via_sibling_tags: None,
                },
            }),
        );

        let cached = HashMap::new();
        let resolved = HashMap::new();
        let versions = VersionData::new(&cached, &resolved).with_vulnerabilities(&vulnerabilities);

        let actions = generate_code_actions(
            &parse_result,
            version_range.start,
            parse_result.uri(),
            versions,
            &content,
            &MockRegistry,
            &MOCK_FORMATTER,
        )
        .await;

        assert!(
            quickfix_titles(&actions).is_empty(),
            "a fix must never claim to resolve an advisory the live check found it doesn't"
        );
    }

    #[tokio::test]
    async fn test_generate_code_actions_omits_fix_when_fix_target_status_advisory_ids_are_truncated()
     {
        // #462 critic M1: `advisory_ids` is capped at `MAX_ADVISORY_RECORDS`, so a shorter-than-
        // `total_known` list is not the complete set still affecting F — a truncated-away id
        // could be the one that should suppress this fix. Here the single reported id (A2) is
        // known and unclaimed, but `total_known: 2` proves an unreported advisory exists, so
        // this must still be rejected rather than trusting a partial list as exhaustive.
        use crate::osv::{
            Advisory, Capped, DependencyVulnerabilities, OsvVersion, UpgradeStatus, VulnSeverity,
        };
        use std::collections::HashMap;

        let (dep, version_range, content) = vulnerable_dep("1.0.0");
        let parse_result = MockParseResult {
            deps: vec![dep],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let mut vulnerabilities = crate::osv::VulnerabilityMap::new();
        vulnerabilities.insert(
            crate::test_util::vuln_key("pkg"),
            ScanOutcome::Vulnerable(DependencyVulnerabilities {
                sibling_matches: None,
                advisories: Capped::new(
                    vec![
                        std::sync::Arc::new(
                            Advisory::new(
                                "A1".to_string(),
                                "2023-01-01T00:00:00Z".to_string(),
                                VulnSeverity::High,
                            )
                            .expect("valid osv id")
                            .with_fixed_versions(vec![OsvVersion::new("1.2.0")]),
                        ),
                        std::sync::Arc::new(
                            Advisory::new(
                                "A2".to_string(),
                                "2023-01-01T00:00:00Z".to_string(),
                                VulnSeverity::Medium,
                            )
                            .expect("valid osv id"),
                        ),
                    ],
                    2,
                ),
                // Only A2 is reported (known, unclaimed — A1 is the sole claimed advisory),
                // but `total_known: 2` says the live check actually found 2 advisories still
                // affecting F; the second one was truncated out of `advisory_ids` and could be
                // anything, including the still-applying A1 itself.
                fix_target_status: UpgradeStatus::CandidateVulnerable {
                    version: ConcreteVersion::new("1.2.0"),
                    advisory_ids: Capped::new(vec![crate::test_util::osv_id("A2")], 2),
                    worst_severity: Some(VulnSeverity::High),
                    via_sibling_tags: None,
                },
            }),
        );

        let cached = HashMap::new();
        let resolved = HashMap::new();
        let versions = VersionData::new(&cached, &resolved).with_vulnerabilities(&vulnerabilities);

        let actions = generate_code_actions(
            &parse_result,
            version_range.start,
            parse_result.uri(),
            versions,
            &content,
            &MockRegistry,
            &MOCK_FORMATTER,
        )
        .await;

        assert!(
            quickfix_titles(&actions).is_empty(),
            "a truncated advisory_ids list must never be trusted as exhaustive"
        );
    }

    #[tokio::test]
    async fn test_generate_code_actions_omits_fix_when_fix_target_status_is_unresolved() {
        // #462 FR-004/NFR-002: `fix_target_status: NotChecked` covers both "verification never
        // ran yet" and "verification timed out" — either way, an unverified F must never be
        // offered as a fix, the fail-safe default (no "unverified" qualifier, just omission).
        use crate::osv::{
            Advisory, Capped, DependencyVulnerabilities, OsvVersion, UpgradeStatus, VulnSeverity,
        };
        use std::collections::HashMap;

        let (dep, version_range, content) = vulnerable_dep("1.0.0");
        let parse_result = MockParseResult {
            deps: vec![dep],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let mut vulnerabilities = crate::osv::VulnerabilityMap::new();
        vulnerabilities.insert(
            crate::test_util::vuln_key("pkg"),
            ScanOutcome::Vulnerable(DependencyVulnerabilities {
                sibling_matches: None,
                advisories: Capped::new(
                    vec![std::sync::Arc::new(
                        Advisory::new(
                            "A1".to_string(),
                            "2023-01-01T00:00:00Z".to_string(),
                            VulnSeverity::High,
                        )
                        .expect("valid osv id")
                        .with_fixed_versions(vec![OsvVersion::new("1.2.0")]),
                    )],
                    1,
                ),
                fix_target_status: UpgradeStatus::NotChecked,
            }),
        );

        let cached = HashMap::new();
        let resolved = HashMap::new();
        let versions = VersionData::new(&cached, &resolved).with_vulnerabilities(&vulnerabilities);

        let actions = generate_code_actions(
            &parse_result,
            version_range.start,
            parse_result.uri(),
            versions,
            &content,
            &MockRegistry,
            &MOCK_FORMATTER,
        )
        .await;

        assert!(
            quickfix_titles(&actions).is_empty(),
            "an unverified fix target must never be presented as a fix, timed out or not yet checked"
        );
    }

    #[tokio::test]
    async fn test_generate_code_actions_drops_yanked_fix_target() {
        use crate::osv::{
            Advisory, Capped, DependencyVulnerabilities, OsvVersion, UpgradeStatus, VulnSeverity,
        };
        use std::collections::HashMap;

        let (dep, version_range, content) = vulnerable_dep("1.0.0");
        let parse_result = MockParseResult {
            deps: vec![dep],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let mut vulnerabilities = crate::osv::VulnerabilityMap::new();
        vulnerabilities.insert(
            crate::test_util::vuln_key("pkg"),
            ScanOutcome::Vulnerable(DependencyVulnerabilities {
                sibling_matches: None,
                advisories: Capped::new(
                    vec![std::sync::Arc::new(
                        Advisory::new(
                            "A1".to_string(),
                            "2023-01-01T00:00:00Z".to_string(),
                            VulnSeverity::High,
                        )
                        .expect("valid osv id")
                        .with_fixed_versions(vec![OsvVersion::new("2.0.0")]),
                    )],
                    1,
                ),
                fix_target_status: UpgradeStatus::CandidateClean {
                    version: ConcreteVersion::new("2.0.0"),
                },
            }),
        );

        let cached = HashMap::new();
        let resolved = HashMap::new();
        let versions = VersionData::new(&cached, &resolved).with_vulnerabilities(&vulnerabilities);
        let registry = FixedVersionRegistry {
            versions: vec![("2.0.0", true), ("1.5.0", false)],
        };

        let actions = generate_code_actions(
            &parse_result,
            version_range.start,
            parse_result.uri(),
            versions,
            &content,
            &registry,
            &MOCK_FORMATTER,
        )
        .await;

        assert!(quickfix_titles(&actions).is_empty());
        assert!(
            actions
                .iter()
                .any(|a| a.kind == Some(CodeActionKind::REFACTOR))
        );
    }

    #[tokio::test]
    async fn test_generate_code_actions_no_op_edit_is_skipped() {
        use crate::osv::{
            Advisory, Capped, DependencyVulnerabilities, OsvVersion, UpgradeStatus, VulnSeverity,
        };
        use std::collections::HashMap;

        // Manifest already declares exactly the fixed version.
        let (dep, version_range, content) = vulnerable_dep("1.2.0");
        let parse_result = MockParseResult {
            deps: vec![dep],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let mut vulnerabilities = crate::osv::VulnerabilityMap::new();
        vulnerabilities.insert(
            crate::test_util::vuln_key("pkg"),
            ScanOutcome::Vulnerable(DependencyVulnerabilities {
                sibling_matches: None,
                advisories: Capped::new(
                    vec![std::sync::Arc::new(
                        Advisory::new(
                            "A1".to_string(),
                            "2023-01-01T00:00:00Z".to_string(),
                            VulnSeverity::High,
                        )
                        .expect("valid osv id")
                        .with_fixed_versions(vec![OsvVersion::new("1.2.0")]),
                    )],
                    1,
                ),
                fix_target_status: UpgradeStatus::NotChecked,
            }),
        );

        let cached = HashMap::new();
        let resolved = HashMap::new();
        let versions = VersionData::new(&cached, &resolved).with_vulnerabilities(&vulnerabilities);

        let actions = generate_code_actions(
            &parse_result,
            version_range.start,
            parse_result.uri(),
            versions,
            &content,
            &MockRegistry,
            &IDENTITY_FORMATTER,
        )
        .await;

        assert!(quickfix_titles(&actions).is_empty());
    }

    #[tokio::test]
    async fn test_generate_code_actions_no_op_guard_compares_formatted_text_not_bare_version() {
        // Critic S3: the manifest already declares "^1.2.0" — exactly what
        // `CaretWrappingFormatter::format_version_for_text_edit` produces for
        // the fixed version "1.2.0" (mirroring `deps-dart`'s real `^{v}`
        // wrap). A guard comparing the bare version ("1.2.0" != "^1.2.0")
        // would miss this and offer a no-op edit; the guard must compare
        // against the formatted text instead.
        use crate::osv::{
            Advisory, Capped, DependencyVulnerabilities, OsvVersion, UpgradeStatus, VulnSeverity,
        };
        use std::collections::HashMap;

        let (dep, version_range, content) = vulnerable_dep("^1.2.0");
        let parse_result = MockParseResult {
            deps: vec![dep],
            uri: crate::test_util::test_uri("/test/pubspec.yaml"),
        };

        let mut vulnerabilities = crate::osv::VulnerabilityMap::new();
        vulnerabilities.insert(
            crate::test_util::vuln_key("pkg"),
            ScanOutcome::Vulnerable(DependencyVulnerabilities {
                sibling_matches: None,
                advisories: Capped::new(
                    vec![std::sync::Arc::new(
                        Advisory::new(
                            "A1".to_string(),
                            "2023-01-01T00:00:00Z".to_string(),
                            VulnSeverity::High,
                        )
                        .expect("valid osv id")
                        .with_fixed_versions(vec![OsvVersion::new("1.2.0")]),
                    )],
                    1,
                ),
                fix_target_status: UpgradeStatus::NotChecked,
            }),
        );

        let cached = HashMap::new();
        let resolved = HashMap::new();
        let versions = VersionData::new(&cached, &resolved).with_vulnerabilities(&vulnerabilities);

        let actions = generate_code_actions(
            &parse_result,
            version_range.start,
            parse_result.uri(),
            versions,
            &content,
            &MockRegistry,
            &CaretWrappingFormatter,
        )
        .await;

        assert!(quickfix_titles(&actions).is_empty());
    }

    #[tokio::test]
    async fn test_generate_code_actions_refactor_loop_skips_no_op_entry_but_keeps_real_update() {
        // Regression for #238: no OSV vulnerabilities are present, isolating the plain
        // REFACTOR loop's own no-op guard from `build_vulnerability_fix_action`'s separate N1
        // guard. The registry lists the already-declared version among the top-5 display
        // items (the common case), plus one genuinely newer version.
        let (dep, version_range, content) = vulnerable_dep("1.2.0");
        let parse_result = MockParseResult {
            deps: vec![dep],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let cached = HashMap::new();
        let resolved = HashMap::new();
        let versions = VersionData::new(&cached, &resolved);
        let registry = FixedVersionRegistry {
            versions: vec![("1.2.0", false), ("1.1.0", false)],
        };

        let actions = generate_code_actions(
            &parse_result,
            version_range.start,
            parse_result.uri(),
            versions,
            &content,
            &registry,
            &IDENTITY_FORMATTER,
        )
        .await;

        let titles = refactor_titles(&actions);
        assert!(
            !titles.iter().any(|t| t.starts_with("1.2.0")),
            "the already-declared version must not be offered as an update: {titles:?}"
        );
        assert!(
            titles.contains(&"1.1.0"),
            "a genuinely different version must still be offered: {titles:?}"
        );
    }

    /// A formatter differing from the identity one only in what it says about the pin.
    struct ProvenAheadFormatter {
        proven: bool,
    }

    impl PackageNaming for ProvenAheadFormatter {}

    impl PackageRendering for ProvenAheadFormatter {
        fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
            version.to_string()
        }

        fn package_url(&self, name: &PackageName) -> String {
            format!("https://example.com/{}", name.as_str())
        }
    }

    impl RequirementResolution for ProvenAheadFormatter {}
    impl DiagnosticMessages for ProvenAheadFormatter {}
    impl DiagnosticPolicy for ProvenAheadFormatter {}
    impl SourcePolicy for ProvenAheadFormatter {}
    impl OsvNaming for ProvenAheadFormatter {}

    impl DependencyFormatter for ProvenAheadFormatter {
        type Dep = MockDep;

        fn hover_provenance(&self, _dep: &MockDep) -> Option<HoverProvenance> {
            self.proven
                .then(|| HoverProvenance::CommitAheadOfLatestRelease {
                    ahead_by: Some(2),
                    latest_tag: "1.2.0".into(),
                })
        }
    }

    /// Spec 087 SC-004 at code-action level: the plain update is offered for an ordinary pin and
    /// withheld for one proven ahead of the latest release.
    #[tokio::test]
    async fn test_generate_code_actions_withholds_update_for_a_proven_ahead_pin() {
        for (proven, offered) in [(false, true), (true, false)] {
            let (dep, version_range, content) = vulnerable_dep("1.0.0");
            let parse_result = MockParseResult {
                deps: vec![dep],
                uri: crate::test_util::test_uri("/test/Cargo.toml"),
            };
            let cached = HashMap::new();
            let resolved = HashMap::new();
            let registry = FixedVersionRegistry {
                versions: vec![("1.2.0", false), ("1.1.0", false)],
            };

            let actions = generate_code_actions(
                &parse_result,
                version_range.start,
                parse_result.uri(),
                VersionData::new(&cached, &resolved),
                &content,
                &registry,
                &ProvenAheadFormatter { proven },
            )
            .await;

            let titles = refactor_titles(&actions);
            assert_eq!(
                titles.iter().any(|t| t.starts_with("1.2.0")),
                offered,
                "proven={proven}: {titles:?}"
            );
            if proven {
                assert!(
                    actions.iter().all(|a| a.is_preferred != Some(true)),
                    "no preferred update for a proven pin"
                );
            }
        }
    }

    #[tokio::test]
    async fn test_generate_code_actions_refactor_loop_no_op_guard_ignores_whitespace() {
        // Whitespace-only divergence between the declared requirement and the
        // formatter's edit text must still be treated as a no-op, mirroring
        // `build_vulnerability_fix_action`'s N1 guard and `literal_span_matches`'s
        // `test_guard_accepts_whitespace_only_difference`.
        let (dep, version_range, content) = vulnerable_dep("1.2.0");
        let parse_result = MockParseResult {
            deps: vec![dep],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let cached = HashMap::new();
        let resolved = HashMap::new();
        let versions = VersionData::new(&cached, &resolved);
        let registry = FixedVersionRegistry {
            versions: vec![("1.2.0", false)],
        };

        let actions = generate_code_actions(
            &parse_result,
            version_range.start,
            parse_result.uri(),
            versions,
            &content,
            &registry,
            &TrailingSpaceFormatter,
        )
        .await;

        assert!(
            refactor_titles(&actions).is_empty(),
            "a whitespace-only edit-text divergence must still be skipped as a no-op"
        );
    }

    #[tokio::test]
    async fn test_generate_code_actions_refactor_loop_skips_unsafe_version_string() {
        // Regression for #302: a registry version containing manifest-structural
        // characters must never be offered as a REFACTOR quickfix, since its raw
        // text would otherwise be written verbatim into the `TextEdit`.
        let (dep, version_range, content) = vulnerable_dep("1.0.0");
        let parse_result = MockParseResult {
            deps: vec![dep],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let cached = HashMap::new();
        let resolved = HashMap::new();
        let versions = VersionData::new(&cached, &resolved);
        let registry = FixedVersionRegistry {
            versions: vec![("1.1.0\", \"evil\": \"true", false), ("1.1.0", false)],
        };

        let actions = generate_code_actions(
            &parse_result,
            version_range.start,
            parse_result.uri(),
            versions,
            &content,
            &registry,
            &IDENTITY_FORMATTER,
        )
        .await;

        let titles = refactor_titles(&actions);
        assert!(
            !titles.iter().any(|t| t.contains("evil")),
            "an unsafe version string must never be offered as an update: {titles:?}"
        );
        assert!(
            titles.contains(&"1.1.0"),
            "a safe version must still be offered: {titles:?}"
        );
    }

    #[tokio::test]
    async fn test_build_vulnerability_fix_action_skips_unsafe_fix_version() {
        // Regression for #302: an OSV advisory's `fixed_versions` entry is
        // external, untrusted data — a manifest-structural character in it must
        // never reach a `TextEdit` via the vulnerability quickfix.
        use crate::osv::{
            Advisory, Capped, DependencyVulnerabilities, OsvVersion, UpgradeStatus, VulnSeverity,
        };
        use std::collections::HashMap;

        let (dep, version_range, content) = vulnerable_dep("1.0.0");
        let parse_result = MockParseResult {
            deps: vec![dep],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let mut vulnerabilities = crate::osv::VulnerabilityMap::new();
        vulnerabilities.insert(
            crate::test_util::vuln_key("pkg"),
            ScanOutcome::Vulnerable(DependencyVulnerabilities {
                sibling_matches: None,
                advisories: Capped::new(
                    vec![std::sync::Arc::new(
                        Advisory::new(
                            "A1".to_string(),
                            "2023-01-01T00:00:00Z".to_string(),
                            VulnSeverity::High,
                        )
                        .expect("valid osv id")
                        .with_fixed_versions(vec![OsvVersion::new("1.2.0\", \"evil\": \"true")]),
                    )],
                    1,
                ),
                fix_target_status: UpgradeStatus::NotChecked,
            }),
        );

        let cached = HashMap::new();
        let resolved = HashMap::new();
        let versions = VersionData::new(&cached, &resolved).with_vulnerabilities(&vulnerabilities);

        let actions = generate_code_actions(
            &parse_result,
            version_range.start,
            parse_result.uri(),
            versions,
            &content,
            &MockRegistry,
            &IDENTITY_FORMATTER,
        )
        .await;

        assert!(
            quickfix_titles(&actions).is_empty(),
            "an unsafe fix version must never produce a vulnerability-fix quickfix"
        );
    }

    fn steer_fixture(
        dep_name: &str,
        verified_target: &str,
    ) -> (
        MockParseResult,
        tower_lsp_server::ls_types::Range,
        String,
        crate::osv::VulnerabilityMap,
    ) {
        use crate::osv::{
            Advisory, Capped, DependencyVulnerabilities, OsvVersion, UpgradeStatus, VulnSeverity,
        };

        let (mut dep, version_range, content) = vulnerable_dep("1.0.0");
        dep.name = PackageName::new(dep_name);
        let parse_result = MockParseResult {
            deps: vec![dep],
            uri: crate::test_util::test_uri("/test/package.json"),
        };
        let mut vulnerabilities = crate::osv::VulnerabilityMap::new();
        vulnerabilities.insert(
            crate::test_util::vuln_key("pkg"),
            ScanOutcome::Vulnerable(
                DependencyVulnerabilities::new(Capped::new(
                    vec![Arc::new(
                        Advisory::new(
                            "A1".to_string(),
                            "2023-01-01T00:00:00Z".to_string(),
                            VulnSeverity::High,
                        )
                        .expect("valid osv id")
                        .with_fixed_versions(vec![OsvVersion::new("4.18.0")]),
                    )],
                    1,
                ))
                .with_fix_target_status(UpgradeStatus::CandidateClean {
                    version: ConcreteVersion::new(verified_target),
                }),
            ),
        );
        (parse_result, version_range, content, vulnerabilities)
    }

    fn deprecated_4_18_0() -> HashMap<NormalizedName, PackageVersions> {
        let flagged: Arc<[(ConcreteVersion, RemovalStatus)]> = Arc::from(vec![(
            ConcreteVersion::new("4.18.0"),
            RemovalStatus::AdvisoryDeprecated,
        )]);
        let available: Arc<[ConcreteVersion]> = Arc::from(vec![
            ConcreteVersion::new("4.18.1"),
            ConcreteVersion::new("4.18.0"),
        ]);
        HashMap::from([(
            NormalizedName::for_test("pkg"),
            PackageVersions::new(ConcreteVersion::new("4.18.1"), available).with_yanked(flagged),
        )])
    }

    async fn vulnerability_fix_titles(
        dep_name: &str,
        verified_target: &str,
        formatter: &impl DependencyFormatter<Dep = MockDep>,
    ) -> Vec<String> {
        let (parse_result, version_range, content, vulnerabilities) =
            steer_fixture(dep_name, verified_target);
        let cached = deprecated_4_18_0();
        let resolved = HashMap::new();
        let versions = VersionData::new(&cached, &resolved).with_vulnerabilities(&vulnerabilities);
        let actions = generate_code_actions(
            &parse_result,
            version_range.start,
            parse_result.uri(),
            versions,
            &content,
            &ErrorRegistry,
            formatter,
        )
        .await;
        quickfix_titles(&actions)
            .into_iter()
            .map(str::to_owned)
            .collect()
    }

    /// #1832: a fix target the registry marks deprecated is steered to the next fresh release.
    #[tokio::test]
    async fn test_vulnerability_fix_steers_past_a_deprecated_target() {
        assert_eq!(
            vulnerability_fix_titles("pkg", "4.18.1", &IDENTITY_FORMATTER).await,
            vec!["Update to 4.18.1 (fixes A1)"]
        );
    }

    /// #1832: phase B verified the unsteered target, so the steered one is unverified and the
    /// action is omitted rather than recommending a deprecated release.
    #[tokio::test]
    async fn test_vulnerability_fix_with_a_stale_unsteered_verification_fails_closed() {
        assert!(
            vulnerability_fix_titles("pkg", "4.18.0", &IDENTITY_FORMATTER)
                .await
                .is_empty()
        );
    }

    /// #1832 S6: a case-folding ecosystem's declared name misses the cache under its raw
    /// spelling; the shared lookup still finds the normalized entry, so the action steers.
    #[tokio::test]
    async fn test_vulnerability_fix_steers_for_a_mixed_case_declared_name() {
        let formatter = crate::test_util::StubFormatter::DEFAULT
            .with_lowercase_names()
            .for_dependency();
        assert_eq!(
            vulnerability_fix_titles("Pkg", "4.18.1", &formatter).await,
            vec!["Update to 4.18.1 (fixes A1)"]
        );
    }

    #[tokio::test]
    async fn test_generate_code_actions_vulnerability_fix_not_offered_on_patched_duplicate_occurrence()
     {
        // #394 S2 (security-relevant): the vulnerability quickfix mutates the manifest, so
        // offering it on the wrong occurrence of a duplicated name is worse than cosmetic.
        // `log4j-core` appears twice — one vulnerable, one patched — the quickfix must appear
        // only at the vulnerable occurrence's position.
        use crate::osv::{
            Advisory, Capped, DependencyVulnerabilities, OsvVersion, UpgradeStatus, VulnSeverity,
        };
        use tower_lsp_server::ls_types::{Position, Range};

        let vulnerable_line = "log4j-core = \"=2.14.1\"";
        let patched_line = "log4j-core = \"=2.17.1\"";
        let content = format!("{vulnerable_line}\n{patched_line}\n");

        let name_start = 0u32;
        let name_end = "log4j-core".len() as u32;
        let version_start = "log4j-core = \"".len() as u32;

        let vulnerable_dep = MockDep {
            name: pkg("log4j-core"),
            version_req: VersionReq::new("=2.14.1"),
            version_range: Range::new(
                Position::new(0, version_start),
                Position::new(0, version_start + "=2.14.1".len() as u32),
            )
            .into(),
            name_range: Range::new(Position::new(0, name_start), Position::new(0, name_end)).into(),
        };
        let patched_dep = MockDep {
            name: pkg("log4j-core"),
            version_req: VersionReq::new("=2.17.1"),
            version_range: Range::new(
                Position::new(1, version_start),
                Position::new(1, version_start + "=2.17.1".len() as u32),
            )
            .into(),
            name_range: Range::new(Position::new(1, name_start), Position::new(1, name_end)).into(),
        };
        let parse_result = MockParseResult {
            deps: vec![vulnerable_dep, patched_dep],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let cached = HashMap::new();
        let resolved = HashMap::new();

        let keys = crate::osv::vulnerability_keys(
            &parse_result,
            &resolved,
            None,
            &IDENTITY_FORMATTER,
            crate::EcosystemId::Cargo,
        );
        let deps = parse_result.dependencies();
        let vulnerable_key = keys.get(&deps[0].name_range()).unwrap().clone();
        let patched_key = keys.get(&deps[1].name_range()).unwrap().clone();
        assert_ne!(vulnerable_key, patched_key);

        let mut vulnerabilities = crate::osv::VulnerabilityMap::new();
        vulnerabilities.insert(
            vulnerable_key,
            ScanOutcome::Vulnerable(DependencyVulnerabilities {
                sibling_matches: None,
                advisories: Capped::new(
                    vec![std::sync::Arc::new(
                        Advisory::new(
                            "GHSA-log4j".to_string(),
                            "2023-01-01T00:00:00Z".to_string(),
                            VulnSeverity::Critical,
                        )
                        .expect("valid osv id")
                        .with_fixed_versions(vec![OsvVersion::new("2.17.1")]),
                    )],
                    1,
                ),
                fix_target_status: UpgradeStatus::CandidateClean {
                    version: ConcreteVersion::new("2.17.1"),
                },
            }),
        );
        vulnerabilities.insert(patched_key, ScanOutcome::Clean);

        let versions = VersionData::new(&cached, &resolved)
            .with_vulnerabilities(&vulnerabilities)
            .with_ecosystem(crate::EcosystemId::Cargo);

        let actions_on_vulnerable = generate_code_actions(
            &parse_result,
            Position::new(0, version_start),
            parse_result.uri(),
            versions,
            &content,
            &MockRegistry,
            &IDENTITY_FORMATTER,
        )
        .await;
        assert!(
            !quickfix_titles(&actions_on_vulnerable).is_empty(),
            "the vulnerable occurrence must get a fix quickfix"
        );

        let actions_on_patched = generate_code_actions(
            &parse_result,
            Position::new(1, version_start),
            parse_result.uri(),
            versions,
            &content,
            &MockRegistry,
            &IDENTITY_FORMATTER,
        )
        .await;
        assert!(
            quickfix_titles(&actions_on_patched).is_empty(),
            "the already-patched occurrence must NOT get a fix quickfix, \
             even though it shares a name with the vulnerable one: {:?}",
            quickfix_titles(&actions_on_patched)
        );
    }

    #[tokio::test]
    async fn test_generate_code_actions_refactor_loop_dedups_item_matching_fix_text_by_different_raw_version()
     {
        // Regression for #242 (gap 1): the old guard compared `item.version` against
        // `fix.version_native` verbatim, so a display item whose *formatted* text
        // matched the fix action's edit but whose *raw* version differed slipped
        // through undeduped. Here the fix targets "1.2.5" (formatted "==1.2") and the
        // registry also offers "1.2.9" — a different raw version that formats to the
        // same "==1.2" text — which must be skipped.
        use crate::osv::{
            Advisory, Capped, DependencyVulnerabilities, OsvVersion, UpgradeStatus, VulnSeverity,
        };
        use std::collections::HashMap;

        let (dep, version_range, content) = vulnerable_dep("==1.0.0");
        let parse_result = MockParseResult {
            deps: vec![dep],
            uri: crate::test_util::test_uri("/test/requirements.txt"),
        };

        let mut vulnerabilities = crate::osv::VulnerabilityMap::new();
        vulnerabilities.insert(
            crate::test_util::vuln_key("pkg"),
            ScanOutcome::Vulnerable(DependencyVulnerabilities {
                sibling_matches: None,
                advisories: Capped::new(
                    vec![std::sync::Arc::new(
                        Advisory::new(
                            "A1".to_string(),
                            "2023-01-01T00:00:00Z".to_string(),
                            VulnSeverity::High,
                        )
                        .expect("valid osv id")
                        .with_fixed_versions(vec![OsvVersion::new("1.2.5")]),
                    )],
                    1,
                ),
                fix_target_status: UpgradeStatus::CandidateClean {
                    version: ConcreteVersion::new("1.2.5"),
                },
            }),
        );

        let cached = HashMap::new();
        let resolved = HashMap::new();
        let versions = VersionData::new(&cached, &resolved).with_vulnerabilities(&vulnerabilities);
        let registry = FixedVersionRegistry {
            versions: vec![("1.2.9", false), ("1.1.0", false)],
        };

        let actions = generate_code_actions(
            &parse_result,
            version_range.start,
            parse_result.uri(),
            versions,
            &content,
            &registry,
            &TruncatingFormatter,
        )
        .await;

        assert_eq!(quickfix_titles(&actions).len(), 1);

        let titles = refactor_titles(&actions);
        assert!(
            !titles.iter().any(|t| t.starts_with("1.2.9")),
            "an item whose formatted text matches the fix action's text must be \
             skipped even though its raw version differs from the fix's: {titles:?}"
        );
        assert!(titles.iter().any(|t| t.starts_with("1.1.0")));

        for action in actions
            .iter()
            .filter(|a| a.kind == Some(CodeActionKind::REFACTOR))
        {
            let ls_uri = crate::lsp_helpers::to_ls_uri(parse_result.uri());
            let edit_text =
                &action.edit.as_ref().unwrap().changes.as_ref().unwrap()[&ls_uri][0].new_text;
            for other in actions.iter() {
                if std::ptr::eq(action, other) {
                    continue;
                }
                let other_text =
                    &other.edit.as_ref().unwrap().changes.as_ref().unwrap()[&ls_uri][0].new_text;
                assert_ne!(
                    edit_text, other_text,
                    "no two actions may carry a byte-identical edit"
                );
            }
        }
    }

    #[tokio::test]
    async fn test_generate_code_actions_refactor_loop_dedups_item_matching_another_items_text() {
        // Regression for #242 (gap 2): two display items whose formatted text
        // coincides (e.g. PyPI's release-segment truncation) must not both be
        // offered as REFACTOR actions, even with no fix action in play at all.
        // Registry-native order is newest-first, so "1.1.9" is `is_latest`; both
        // "1.1.9" and "1.1.5" truncate to "==1.1" and must collapse into one action.
        let (dep, version_range, content) = vulnerable_dep("==1.0.*");
        let parse_result = MockParseResult {
            deps: vec![dep],
            uri: crate::test_util::test_uri("/test/requirements.txt"),
        };

        let cached = HashMap::new();
        let resolved = HashMap::new();
        let versions = VersionData::new(&cached, &resolved);
        let registry = FixedVersionRegistry {
            versions: vec![("1.1.9", false), ("1.1.5", false), ("1.1.0", false)],
        };

        let actions = generate_code_actions(
            &parse_result,
            version_range.start,
            parse_result.uri(),
            versions,
            &content,
            &registry,
            &TruncatingFormatter,
        )
        .await;

        assert!(quickfix_titles(&actions).is_empty());

        let titles = refactor_titles(&actions);
        assert_eq!(
            titles,
            vec!["1.1.9 (latest)"],
            "identical-text items after the first must be deduped: {titles:?}"
        );
    }

    #[tokio::test]
    async fn test_generate_code_actions_lockfile_hit_gets_title_suffix() {
        use crate::osv::{
            Advisory, Capped, DependencyVulnerabilities, OsvVersion, UpgradeStatus, VulnSeverity,
        };
        use std::collections::HashMap;

        let (dep, version_range, content) = vulnerable_dep("^1.0");
        let parse_result = MockParseResult {
            deps: vec![dep],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let mut vulnerabilities = crate::osv::VulnerabilityMap::new();
        vulnerabilities.insert(
            crate::test_util::vuln_key("pkg"),
            ScanOutcome::Vulnerable(DependencyVulnerabilities {
                sibling_matches: None,
                advisories: Capped::new(
                    vec![std::sync::Arc::new(
                        Advisory::new(
                            "A1".to_string(),
                            "2023-01-01T00:00:00Z".to_string(),
                            VulnSeverity::High,
                        )
                        .expect("valid osv id")
                        .with_fixed_versions(vec![OsvVersion::new("1.0.2")]),
                    )],
                    1,
                ),
                fix_target_status: UpgradeStatus::CandidateClean {
                    version: ConcreteVersion::new("1.0.2"),
                },
            }),
        );

        let cached = HashMap::new();
        let mut resolved = HashMap::new();
        resolved.insert(NormalizedName::for_test("pkg"), "1.0.1".into());
        let versions = VersionData::new(&cached, &resolved).with_vulnerabilities(&vulnerabilities);

        let actions = generate_code_actions(
            &parse_result,
            version_range.start,
            parse_result.uri(),
            versions,
            &content,
            &MockRegistry,
            &MOCK_FORMATTER,
        )
        .await;

        let titles = quickfix_titles(&actions);
        assert_eq!(
            titles,
            vec!["Update to 1.0.2 (fixes A1; update lockfile to apply)"]
        );
    }

    #[tokio::test]
    async fn test_generate_code_actions_fix_action_survives_registry_error() {
        // FR-007 / registry-independence: a registry outage must never
        // suppress an OSV-derived fix. The fix action is computed before the
        // `registry.get_versions` call, but this test exercises the early
        // return on `Err` specifically, which no prior test reached.
        use crate::osv::{
            Advisory, Capped, DependencyVulnerabilities, OsvVersion, UpgradeStatus, VulnSeverity,
        };
        use std::collections::HashMap;

        let (dep, version_range, content) = vulnerable_dep("1.0.0");
        let parse_result = MockParseResult {
            deps: vec![dep],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let mut vulnerabilities = crate::osv::VulnerabilityMap::new();
        vulnerabilities.insert(
            crate::test_util::vuln_key("pkg"),
            ScanOutcome::Vulnerable(DependencyVulnerabilities {
                sibling_matches: None,
                advisories: Capped::new(
                    vec![std::sync::Arc::new(
                        Advisory::new(
                            "A1".to_string(),
                            "2023-01-01T00:00:00Z".to_string(),
                            VulnSeverity::High,
                        )
                        .expect("valid osv id")
                        .with_fixed_versions(vec![OsvVersion::new("1.2.0")]),
                    )],
                    1,
                ),
                fix_target_status: UpgradeStatus::CandidateClean {
                    version: ConcreteVersion::new("1.2.0"),
                },
            }),
        );

        let cached = HashMap::new();
        let resolved = HashMap::new();
        let versions = VersionData::new(&cached, &resolved).with_vulnerabilities(&vulnerabilities);

        let actions = generate_code_actions(
            &parse_result,
            version_range.start,
            parse_result.uri(),
            versions,
            &content,
            &ErrorRegistry,
            &MOCK_FORMATTER,
        )
        .await;

        let titles = quickfix_titles(&actions);
        assert_eq!(titles, vec!["Update to 1.2.0 (fixes A1)"]);
        // No plain "update to X" items either, since the registry fetch that
        // would produce them failed.
        assert_eq!(actions.len(), 1);
        // S1: the single-exit restructure must not drop `isPreferred` from an
        // already-built fix action on the registry-outage path.
        assert_eq!(actions[0].is_preferred, Some(true));
    }

    /// #1204: same guarantee as
    /// `test_generate_code_actions_fix_action_survives_registry_error`, but for the
    /// `tokio::time::timeout` wrap around the primary `registry_versions` fetch — a
    /// registry that never returns must not suppress the OSV-derived fix either.
    /// `start_paused` lets `REGISTRY_FETCH_BUDGET` elapse without a real wait.
    #[tokio::test(start_paused = true)]
    async fn test_generate_code_actions_fix_action_dropped_on_registry_timeout() {
        use crate::osv::{
            Advisory, Capped, DependencyVulnerabilities, OsvVersion, UpgradeStatus, VulnSeverity,
        };
        use std::collections::HashMap;

        let (dep, version_range, content) = vulnerable_dep("1.0.0");
        let parse_result = MockParseResult {
            deps: vec![dep],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let mut vulnerabilities = crate::osv::VulnerabilityMap::new();
        vulnerabilities.insert(
            crate::test_util::vuln_key("pkg"),
            ScanOutcome::Vulnerable(DependencyVulnerabilities {
                sibling_matches: None,
                advisories: Capped::new(
                    vec![std::sync::Arc::new(
                        Advisory::new(
                            "A1".to_string(),
                            "2023-01-01T00:00:00Z".to_string(),
                            VulnSeverity::High,
                        )
                        .expect("valid osv id")
                        .with_fixed_versions(vec![OsvVersion::new("1.2.0")]),
                    )],
                    1,
                ),
                fix_target_status: UpgradeStatus::CandidateClean {
                    version: ConcreteVersion::new("1.2.0"),
                },
            }),
        );

        let cached = HashMap::new();
        let resolved = HashMap::new();
        let versions = VersionData::new(&cached, &resolved).with_vulnerabilities(&vulnerabilities);
        let registry = SlowRegistry {
            delay: REGISTRY_FETCH_BUDGET + std::time::Duration::from_secs(1),
        };

        let actions = generate_code_actions(
            &parse_result,
            version_range.start,
            parse_result.uri(),
            versions,
            &content,
            &registry,
            &MOCK_FORMATTER,
        )
        .await;

        // The fix action is dropped outright rather than offered unfiltered (impl-critic
        // S1, issue #1204 follow-up): a timed-out fetch means the deadline, not the
        // registry, decided to stop waiting, so a live answer about whether "1.2.0" is
        // yanked may well have been moments away — unlike a genuine registry outage, this
        // must not fail open.
        assert!(quickfix_titles(&actions).is_empty());
        assert!(actions.is_empty());
    }

    fn fixable_vulnerabilities() -> crate::osv::VulnerabilityMap {
        use crate::osv::{
            Advisory, Capped, DependencyVulnerabilities, OsvVersion, UpgradeStatus, VulnSeverity,
        };

        let mut vulnerabilities = crate::osv::VulnerabilityMap::new();
        vulnerabilities.insert(
            crate::test_util::vuln_key("pkg"),
            ScanOutcome::Vulnerable(DependencyVulnerabilities {
                sibling_matches: None,
                advisories: Capped::new(
                    vec![std::sync::Arc::new(
                        Advisory::new(
                            "A1".to_string(),
                            "2023-01-01T00:00:00Z".to_string(),
                            VulnSeverity::High,
                        )
                        .expect("valid osv id")
                        .with_fixed_versions(vec![OsvVersion::new("1.2.0")]),
                    )],
                    1,
                ),
                fix_target_status: UpgradeStatus::CandidateClean {
                    version: ConcreteVersion::new("1.2.0"),
                },
            }),
        );
        vulnerabilities
    }

    /// Runs `generate_code_actions` on the `pkg = "1.0.0"` fixture with the interactive-fetch
    /// gate attached and returns the quick-fix titles.
    async fn gated_fix_titles(
        gate: &InteractiveFetchGate,
        outcomes: &DependencyOutcomes,
        registry: &CountingRegistry,
    ) -> Vec<String> {
        let (dep, version_range, content) = vulnerable_dep("1.0.0");
        let parse_result = MockParseResult {
            deps: vec![dep],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };
        let vulnerabilities = fixable_vulnerabilities();
        let (cached, resolved) = (HashMap::new(), HashMap::new());
        let versions = VersionData::new(&cached, &resolved)
            .with_vulnerabilities(&vulnerabilities)
            .with_ecosystem(crate::EcosystemId::Cargo)
            .with_outcomes(outcomes)
            .with_interactive_fetch_gate(gate);

        let actions = generate_code_actions(
            &parse_result,
            version_range.start,
            parse_result.uri(),
            versions,
            &content,
            registry,
            &MOCK_FORMATTER,
        )
        .await;
        quickfix_titles(&actions)
            .into_iter()
            .map(str::to_owned)
            .collect()
    }

    /// #1830: a failure inferred from the background fetch is unverified, so the speculative
    /// fix is dropped — like a live timeout — without touching the registry.
    #[tokio::test(start_paused = true)]
    async fn test_generate_code_actions_seeded_failure_drops_fix_without_live_call() {
        let gate = InteractiveFetchGate::new(std::num::NonZeroUsize::new(4).unwrap());
        let outcomes = DependencyOutcomes::new().with_fetch_failure(
            crate::NormalizedName::for_test("pkg"),
            crate::FetchFailure::Transient,
        );
        let registry = CountingRegistry::new(CountingMode::Succeed);

        let titles = gated_fix_titles(&gate, &outcomes, &registry).await;

        assert!(titles.is_empty());
        assert_eq!(registry.calls(), 0);
    }

    /// #1830: the request that receives a registry error stays fail-open (the fix survives,
    /// as before #1204); the memoized replay is fail-closed, so the fix is dropped without a
    /// live call.
    #[tokio::test(start_paused = true)]
    async fn test_generate_code_actions_interactive_error_keeps_fix_then_replays_unverified() {
        let gate = InteractiveFetchGate::new(std::num::NonZeroUsize::new(4).unwrap());
        let none = DependencyOutcomes::new();
        let registry = CountingRegistry::new(CountingMode::Fail);

        let first = gated_fix_titles(&gate, &none, &registry).await;
        let second = gated_fix_titles(&gate, &none, &registry).await;

        assert_eq!(first, vec!["Update to 1.2.0 (fixes A1)"]);
        assert!(second.is_empty());
        assert_eq!(registry.calls(), 1);
    }

    /// #1830: an elapse is unverified and memoized — the fix is dropped both times, the second
    /// request without waiting out the budget again.
    #[tokio::test(start_paused = true)]
    async fn test_generate_code_actions_elapse_is_memoized_and_drops_fix() {
        let gate = InteractiveFetchGate::new(std::num::NonZeroUsize::new(4).unwrap());
        let none = DependencyOutcomes::new();
        let registry = CountingRegistry::new(CountingMode::Stall);

        let first = gated_fix_titles(&gate, &none, &registry).await;
        let second = gated_fix_titles(&gate, &none, &registry).await;

        assert!(first.is_empty() && second.is_empty());
        assert_eq!(registry.calls(), 1);
    }

    #[tokio::test]
    async fn test_generate_code_actions_coexistence_dedups_fix_version_and_demotes_preferred() {
        // Exercises the branch where the registry fetch succeeds *and*
        // returns the fix's own target version alongside other non-yanked
        // versions: the display item for that exact version must not be
        // duplicated, and no plain item may claim `is_preferred` once a fix
        // action exists.
        use crate::osv::{
            Advisory, Capped, DependencyVulnerabilities, OsvVersion, UpgradeStatus, VulnSeverity,
        };
        use std::collections::HashMap;

        let (dep, version_range, content) = vulnerable_dep("1.0.0");
        let parse_result = MockParseResult {
            deps: vec![dep],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let mut vulnerabilities = crate::osv::VulnerabilityMap::new();
        vulnerabilities.insert(
            crate::test_util::vuln_key("pkg"),
            ScanOutcome::Vulnerable(DependencyVulnerabilities {
                sibling_matches: None,
                advisories: Capped::new(
                    vec![std::sync::Arc::new(
                        Advisory::new(
                            "A1".to_string(),
                            "2023-01-01T00:00:00Z".to_string(),
                            VulnSeverity::High,
                        )
                        .expect("valid osv id")
                        .with_fixed_versions(vec![OsvVersion::new("1.2.0")]),
                    )],
                    1,
                ),
                fix_target_status: UpgradeStatus::CandidateClean {
                    version: ConcreteVersion::new("1.2.0"),
                },
            }),
        );

        let cached = HashMap::new();
        let resolved = HashMap::new();
        let versions = VersionData::new(&cached, &resolved).with_vulnerabilities(&vulnerabilities);
        // Registry-native order is descending (index 0 = latest); the fix's
        // own target (1.2.0) is present and not yanked, alongside others.
        let registry = FixedVersionRegistry {
            versions: vec![("1.2.0", false), ("1.1.0", false), ("1.0.0", false)],
        };

        let actions = generate_code_actions(
            &parse_result,
            version_range.start,
            parse_result.uri(),
            versions,
            &content,
            &registry,
            &MOCK_FORMATTER,
        )
        .await;

        assert_eq!(quickfix_titles(&actions).len(), 1);

        let refactor_titles: Vec<&str> = actions
            .iter()
            .filter(|a| a.kind == Some(CodeActionKind::REFACTOR))
            .map(|a| a.title.as_str())
            .collect();
        assert!(
            !refactor_titles.iter().any(|t| t.starts_with("1.2.0")),
            "the display item duplicating the fix's own target must be skipped: {refactor_titles:?}"
        );
        assert!(refactor_titles.iter().any(|t| t.starts_with("1.1.0")));

        assert!(
            actions
                .iter()
                .filter(|a| a.kind == Some(CodeActionKind::REFACTOR))
                .all(|a| a.is_preferred.is_none()),
            "only the fix action may be preferred once it exists"
        );
    }

    #[tokio::test]
    async fn test_generate_code_actions_latest_refactor_is_preferred_when_no_fix_exists() {
        // Critic C1: the most common production path — no vulnerability, no unsatisfiable
        // requirement, just a satisfiable dependency with newer versions — must still mark
        // `item.is_latest` as preferred. This moved to the shared `is_preferred` post-pass
        // indexed by `latest_refactor_idx`; a wrong index or broken `.or()` chain would
        // silently strip `isPreferred` from every "update to latest" action.
        let (dep, version_range, content) = vulnerable_dep("1.0.0");
        let parse_result = MockParseResult {
            deps: vec![dep],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let cached = HashMap::new();
        let resolved = HashMap::new();
        let versions = VersionData::new(&cached, &resolved);
        let registry = FixedVersionRegistry {
            versions: vec![("2.0.0", false), ("1.5.0", false)],
        };

        let actions = generate_code_actions(
            &parse_result,
            version_range.start,
            parse_result.uri(),
            versions,
            &content,
            &registry,
            &MOCK_FORMATTER,
        )
        .await;

        assert!(
            quickfix_titles(&actions).is_empty(),
            "no vuln/unsat fix should exist: {actions:?}"
        );
        let refactor_titles = refactor_titles(&actions);
        assert_eq!(refactor_titles.len(), 2, "{refactor_titles:?}");

        let preferred: Vec<&str> = actions
            .iter()
            .filter(|a| a.is_preferred == Some(true))
            .map(|a| a.title.as_str())
            .collect();
        assert_eq!(
            preferred.len(),
            1,
            "exactly one action must be preferred: {actions:?}"
        );
        assert!(
            preferred[0].starts_with("2.0.0"),
            "the newest (item.is_latest) REFACTOR action must be preferred: {preferred:?}"
        );
        assert!(
            actions
                .iter()
                .filter(|a| !a.title.starts_with("2.0.0"))
                .all(|a| a.is_preferred.is_none()),
            "every other action must be None, not Some(false): {actions:?}"
        );
    }

    /// Issue #1517 (the P0 this fix addresses): OSV flagged the registry's "latest" as
    /// malicious — the "Update to 2.0.0" quickfix must never be offered, even though nothing
    /// about the pinned version itself (1.0.0) is vulnerable.
    #[tokio::test]
    async fn test_generate_code_actions_omits_latest_refactor_when_osv_flags_it() {
        use crate::osv::{Capped, LatestStatusMap, UpgradeStatus, VulnSeverity};

        let (dep, version_range, content) = vulnerable_dep("1.0.0");
        let parse_result = MockParseResult {
            deps: vec![dep],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let cached = HashMap::new();
        let resolved = HashMap::new();
        let mut latest_status = LatestStatusMap::new();
        latest_status.insert(
            crate::test_util::vuln_key("pkg"),
            UpgradeStatus::CandidateVulnerable {
                version: ConcreteVersion::new("2.0.0"),
                advisory_ids: Capped::new(vec![crate::test_util::osv_id("MAL-2026-00001")], 1),
                worst_severity: Some(VulnSeverity::Malicious),
                via_sibling_tags: None,
            },
        );
        let versions = VersionData::new(&cached, &resolved).with_latest_status(&latest_status);
        let registry = FixedVersionRegistry {
            versions: vec![("2.0.0", false), ("1.5.0", false)],
        };

        let actions = generate_code_actions(
            &parse_result,
            version_range.start,
            parse_result.uri(),
            versions,
            &content,
            &registry,
            &MOCK_FORMATTER,
        )
        .await;

        let refactor_titles = refactor_titles(&actions);
        assert!(
            !refactor_titles.iter().any(|t| t.starts_with("2.0.0")),
            "a malicious-flagged latest must never be offered as an update target: {refactor_titles:?}"
        );
        assert!(
            refactor_titles.iter().any(|t| t.starts_with("1.5.0")),
            "no `candidate_status` map is attached in this fixture, so `candidate_verdict` \
             resolves to `NotApplicable` and 1.5.0 passes the gate unchecked — see the \
             sibling test below for the populated-map, flagged-intermediate-candidate case: \
             {refactor_titles:?}"
        );
        assert!(
            actions.iter().all(|a| a.is_preferred.is_none()),
            "no action may claim isPreferred once the only latest candidate was dropped: \
             {actions:?}"
        );
    }

    /// Issue #1524: unlike the sibling test above (no `candidate_status` map attached at
    /// all, so every non-latest item resolves to `NotApplicable` and passes unchecked), a
    /// populated `candidate_status` map with a `Flagged` verdict for a non-latest candidate
    /// must exclude exactly that candidate from the REFACTOR list, while the clean latest
    /// and any other unflagged candidate stay offered.
    #[tokio::test]
    async fn test_generate_code_actions_omits_flagged_intermediate_candidate_refactor() {
        use crate::osv::{
            CandidateStatusMap, CandidateStatuses, Capped, LatestStatusMap, UpgradeStatus,
            VulnSeverity,
        };

        let (dep, version_range, content) = vulnerable_dep("1.0.0");
        let parse_result = MockParseResult {
            deps: vec![dep],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let cached = HashMap::new();
        let resolved = HashMap::new();
        let mut latest_status = LatestStatusMap::new();
        latest_status.insert(
            crate::test_util::vuln_key("pkg"),
            UpgradeStatus::CandidateClean {
                version: ConcreteVersion::new("2.0.0"),
            },
        );
        let mut candidate_status = CandidateStatusMap::new();
        let mut per_version = HashMap::new();
        per_version.insert(
            ConcreteVersion::new("1.5.0"),
            UpgradeStatus::CandidateVulnerable {
                version: ConcreteVersion::new("1.5.0"),
                advisory_ids: Capped::new(vec![crate::test_util::osv_id("MAL-2026-00002")], 1),
                worst_severity: Some(VulnSeverity::Malicious),
                via_sibling_tags: None,
            },
        );
        candidate_status.insert(
            crate::test_util::vuln_key("pkg"),
            CandidateStatuses::PerVersion(per_version),
        );

        let versions = VersionData::new(&cached, &resolved)
            .with_latest_status(&latest_status)
            .with_candidate_status(&candidate_status);
        let registry = FixedVersionRegistry {
            versions: vec![("2.0.0", false), ("1.5.0", false), ("1.2.0", false)],
        };

        let actions = generate_code_actions(
            &parse_result,
            version_range.start,
            parse_result.uri(),
            versions,
            &content,
            &registry,
            &MOCK_FORMATTER,
        )
        .await;

        let refactor_titles = refactor_titles(&actions);
        assert!(
            !refactor_titles.iter().any(|t| t.starts_with("1.5.0")),
            "a malicious-flagged intermediate candidate must never be offered as an update \
             target: {refactor_titles:?}"
        );
        assert!(
            refactor_titles.iter().any(|t| t.starts_with("2.0.0")),
            "the clean, verified latest must stay offered: {refactor_titles:?}"
        );
        assert!(
            !refactor_titles.iter().any(|t| t.starts_with("1.2.0")),
            "once a `candidate_status` map is attached for this dependency, a candidate with \
             no entry of its own (outside the bounded check round, and no structural-skip \
             sentinel either) must fail closed to `Unverified` and be excluded — never read \
             as silently safe just because it wasn't the one flagged: {refactor_titles:?}"
        );
    }

    #[tokio::test]
    async fn test_generate_code_actions_latest_refactor_skips_prerelease_at_raw_top() {
        // Regression for #952 (sibling of #313, hover-only): the raw registry-fetch-order
        // top entry is a pre-release (Maven spring-boot-starter-web 4.2.0-M1, NuGet
        // Newtonsoft.Json 13.0.5-beta1 shape). The `(latest)`-labeled, preferred REFACTOR
        // action must land on the first stable entry instead, matching hover/diagnostics.
        let (dep, version_range, content) = vulnerable_dep("1.0.0");
        let parse_result = MockParseResult {
            deps: vec![dep],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let cached = HashMap::new();
        let resolved = HashMap::new();
        let versions = VersionData::new(&cached, &resolved);
        let registry = FixedVersionRegistry {
            versions: vec![("2.0.0-beta1", false), ("1.5.0", false), ("1.0.0", false)],
        };

        let actions = generate_code_actions(
            &parse_result,
            version_range.start,
            parse_result.uri(),
            versions,
            &content,
            &registry,
            &MOCK_FORMATTER,
        )
        .await;

        assert!(quickfix_titles(&actions).is_empty());
        let refactor_titles = refactor_titles(&actions);
        assert!(
            !refactor_titles.contains(&"2.0.0-beta1"),
            "a non-pick pre-release is not offered for a stable requirement (#1885): \
             {refactor_titles:?}"
        );
        assert!(
            refactor_titles.contains(&"1.5.0 (latest)"),
            "the first stable entry must carry the latest marker: {refactor_titles:?}"
        );

        let preferred: Vec<&str> = actions
            .iter()
            .filter(|a| a.is_preferred == Some(true))
            .map(|a| a.title.as_str())
            .collect();
        assert_eq!(
            preferred,
            vec!["1.5.0 (latest)"],
            "the stable version must be preferred, not the raw-top pre-release: {actions:?}"
        );
    }

    /// Runs the code-action pipeline for a one-dependency manifest and returns the REFACTOR
    /// titles (#1885 prerelease-policy fixtures).
    async fn refactor_titles_for(
        requirement: &str,
        registry_versions: Vec<(&'static str, bool)>,
        lockfile_version: Option<&str>,
        formatter: &impl DependencyFormatter<Dep = MockDep>,
    ) -> Vec<String> {
        let (dep, version_range, content) = vulnerable_dep(requirement);
        let parse_result = MockParseResult {
            deps: vec![dep],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };
        let cached = HashMap::new();
        let mut resolved = HashMap::new();
        if let Some(version) = lockfile_version {
            resolved.insert(NormalizedName::for_test("pkg"), version.into());
        }
        let versions =
            VersionData::new(&cached, &resolved).with_ecosystem(crate::EcosystemId::Cargo);
        let registry = FixedVersionRegistry {
            versions: registry_versions,
        };
        let actions = generate_code_actions(
            &parse_result,
            version_range.start,
            parse_result.uri(),
            versions,
            &content,
            &registry,
            formatter,
        )
        .await;
        refactor_titles(&actions)
            .into_iter()
            .map(str::to_owned)
            .collect()
    }

    const MIXED_HEAD: [(&str, bool); 4] = [
        ("2.0.0-beta1", false),
        ("1.5.0", false),
        ("1.4.0-rc1", false),
        ("1.0.0", false),
    ];

    #[tokio::test]
    async fn test_refactor_stable_requirement_drops_non_pick_prereleases() {
        let titles = refactor_titles_for("1.0.0", MIXED_HEAD.to_vec(), None, &MOCK_FORMATTER).await;
        assert!(titles.contains(&"1.5.0 (latest)".to_owned()), "{titles:?}");
        assert!(
            !titles
                .iter()
                .any(|t| t.contains("beta1") || t.contains("rc1")),
            "{titles:?}"
        );
    }

    #[tokio::test]
    async fn test_refactor_pick_prerelease_is_exempt_and_keeps_prereleases() {
        let titles = refactor_titles_for(
            "1.0.0",
            vec![("2.0.0-beta2", false), ("2.0.0-beta1", false)],
            None,
            &MOCK_FORMATTER,
        )
        .await;
        assert!(
            titles.contains(&"2.0.0-beta2 (latest)".to_owned()),
            "{titles:?}"
        );
        assert!(titles.contains(&"2.0.0-beta1".to_owned()), "{titles:?}");
    }

    #[tokio::test]
    async fn test_refactor_lockfile_prerelease_in_use_keeps_prereleases() {
        let titles = refactor_titles_for(
            "1.0.0",
            MIXED_HEAD.to_vec(),
            Some("1.4.0-rc1"),
            &MOCK_FORMATTER,
        )
        .await;
        assert!(titles.contains(&"2.0.0-beta1".to_owned()), "{titles:?}");
    }

    #[tokio::test]
    async fn test_refactor_requirement_naming_published_prerelease_keeps_prereleases() {
        let titles =
            refactor_titles_for("1.4.0-rc1", MIXED_HEAD.to_vec(), None, &MOCK_FORMATTER).await;
        assert!(titles.contains(&"2.0.0-beta1".to_owned()), "{titles:?}");
    }

    #[tokio::test]
    async fn test_refactor_strict_semver_prerelease_floor_keeps_prereleases() {
        let titles = refactor_titles_for(
            ">=0.9.0-alpha.1",
            MIXED_HEAD.to_vec(),
            None,
            &StrictSemverFormatter,
        )
        .await;
        assert!(titles.contains(&"2.0.0-beta1".to_owned()), "{titles:?}");
    }

    /// N1: `<2.0.0-0` exists to exclude pre-releases, so it must not opt in.
    #[tokio::test]
    async fn test_refactor_strict_semver_upper_bound_does_not_opt_in() {
        let titles = refactor_titles_for(
            ">=1.0.0, <3.0.0-0",
            MIXED_HEAD.to_vec(),
            None,
            &StrictSemverFormatter,
        )
        .await;
        assert!(!titles.iter().any(|t| t.contains("beta1")), "{titles:?}");
        assert!(titles.contains(&"1.5.0 (latest)".to_owned()), "{titles:?}");
    }

    #[test]
    fn test_prerelease_policy_oversized_requirement_is_stable_only() {
        let prereleases: HashSet<&str> = HashSet::from(["1.0.0-rc1"]);
        let within_cap = VersionReq::new(">=1.0.0-rc1");
        let oversized = VersionReq::new(format!(
            ">=1.0.0-rc1 {}",
            "1".repeat(crate::lsp_helpers::MAX_REQUIREMENT_LEN)
        ));
        let policy = |req: &VersionReq| {
            PrereleasePolicy::for_dependency(&prereleases, None, None, req, &MOCK_FORMATTER)
        };
        assert_eq!(policy(&within_cap), PrereleasePolicy::IncludePrereleases);
        assert_eq!(policy(&oversized), PrereleasePolicy::StableOnly);
    }

    #[test]
    fn test_requirement_opts_into_prereleases_defaults_to_false() {
        use crate::lsp_helpers::RequirementResolution;
        for requirement in ["^2.0@beta", "1.0.0-rc1", ">=2.0.0-beta", "[1.0-beta,)"] {
            let requirement = VersionReq::new(requirement);
            let bounded = BoundedVersionReq::new(&requirement).unwrap();
            assert!(!MOCK_FORMATTER.requirement_opts_into_prereleases(bounded));
        }
    }

    struct FlagOptInFormatter;

    impl crate::lsp_helpers::PackageNaming for FlagOptInFormatter {}

    impl crate::lsp_helpers::PackageRendering for FlagOptInFormatter {
        fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
            version.to_string()
        }

        fn package_url(&self, name: &crate::PackageName) -> String {
            name.as_str().to_string()
        }
    }

    impl crate::lsp_helpers::RequirementResolution for FlagOptInFormatter {
        fn requirement_opts_into_prereleases(&self, requirement: BoundedVersionReq<'_>) -> bool {
            requirement.as_str().contains("@beta")
        }
    }

    impl crate::lsp_helpers::DiagnosticMessages for FlagOptInFormatter {}
    impl crate::lsp_helpers::DiagnosticPolicy for FlagOptInFormatter {}
    impl crate::lsp_helpers::SourcePolicy for FlagOptInFormatter {}
    impl crate::lsp_helpers::OsvNaming for FlagOptInFormatter {}

    struct MajorOnlyFormatter;

    impl crate::lsp_helpers::PackageNaming for MajorOnlyFormatter {}

    impl crate::lsp_helpers::PackageRendering for MajorOnlyFormatter {
        fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
            version.to_string()
        }

        fn format_version_replacing(&self, version: &ConcreteVersion, _current: &str) -> String {
            version
                .as_str()
                .split('.')
                .next()
                .unwrap_or_default()
                .to_owned()
        }

        fn package_url(&self, name: &crate::PackageName) -> String {
            name.as_str().to_string()
        }
    }

    impl crate::lsp_helpers::RequirementResolution for MajorOnlyFormatter {}
    impl crate::lsp_helpers::DiagnosticMessages for MajorOnlyFormatter {}
    impl crate::lsp_helpers::DiagnosticPolicy for MajorOnlyFormatter {}
    impl crate::lsp_helpers::SourcePolicy for MajorOnlyFormatter {}
    impl crate::lsp_helpers::OsvNaming for MajorOnlyFormatter {}

    impl crate::lsp_helpers::DependencyFormatter for MajorOnlyFormatter {
        type Dep = MockDep;
    }

    #[tokio::test]
    async fn test_refactor_partial_bucket_keeps_newest_version_title() {
        let titles = refactor_titles_for(
            "5",
            vec![("6.2.1", false), ("6.1.0", false), ("5.4.0", false)],
            None,
            &MajorOnlyFormatter,
        )
        .await;
        assert_eq!(titles, vec!["6.2.1 (latest)".to_owned()], "{titles:?}");
    }

    #[test]
    fn test_prerelease_policy_ecosystem_hook_opts_in_but_never_when_oversized() {
        let prereleases: HashSet<&str> = HashSet::new();
        let policy = |req: &VersionReq, formatter: &dyn EcosystemFormatter| {
            PrereleasePolicy::for_dependency(&prereleases, None, None, req, formatter)
        };
        let flagged = VersionReq::new("^2.0@beta");
        assert_eq!(
            policy(&flagged, &FlagOptInFormatter),
            PrereleasePolicy::IncludePrereleases
        );
        assert_eq!(
            policy(&flagged, &MOCK_FORMATTER),
            PrereleasePolicy::StableOnly
        );
        let plain = VersionReq::new("^2.0");
        assert_eq!(
            policy(&plain, &FlagOptInFormatter),
            PrereleasePolicy::StableOnly
        );
        let oversized = VersionReq::new(format!(
            "^2.0@beta {}",
            "1".repeat(crate::lsp_helpers::MAX_REQUIREMENT_LEN)
        ));
        assert_eq!(
            policy(&oversized, &FlagOptInFormatter),
            PrereleasePolicy::StableOnly
        );
    }

    #[test]
    fn test_opt_in_comparator_versions_skips_upper_bounds() {
        let cases: [(&str, &[&str]); 9] = [
            ("<2.0.0-0", &[]),
            ("<=2.0.0-rc.1", &[]),
            ("!=1.0.0-rc1", &[]),
            (">=1.0.0 <2.0.0-0", &["1.0.0"]),
            (">=1.0.0, <2.0.0-0", &["1.0.0"]),
            ("^1.0.0-rc.1", &["1.0.0-rc.1"]),
            ("1.0.0 - 2.0.0-rc.1", &["1.0.0"]),
            ("~> 1.0.0.beta1", &["1.0.0.beta1"]),
            ("^1 || >= 2.0.0-beta", &["1", "2.0.0-beta"]),
        ];
        for (requirement, expected) in cases {
            assert_eq!(
                opt_in_comparator_versions(requirement),
                expected,
                "{requirement:?}"
            );
        }
    }

    #[tokio::test]
    async fn test_generate_code_actions_bumps_pick_outside_raw_order_window() {
        // Regression for #956: 5 consecutive pre-release entries sort ahead of the picked
        // stable version in raw fetch order, pushing it to post-filter index 5 — one past
        // the MAX_COMPLETION_VERSIONS(5) raw-order display cap. The bumped entry must still
        // appear among the generated REFACTOR actions, labeled `(latest)`, and be the one
        // `isPreferred` action.
        let (dep, version_range, content) = vulnerable_dep("0.9.0");
        let parse_result = MockParseResult {
            deps: vec![dep],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let cached = HashMap::new();
        let resolved = HashMap::new();
        let versions = VersionData::new(&cached, &resolved);
        let registry = FixedVersionRegistry {
            versions: vec![
                ("2.0.0-rc5", false),
                ("2.0.0-rc4", false),
                ("2.0.0-rc3", false),
                ("2.0.0-rc2", false),
                ("2.0.0-rc1", false),
                ("1.0.0", false),
            ],
        };

        let actions = generate_code_actions(
            &parse_result,
            version_range.start,
            parse_result.uri(),
            versions,
            &content,
            &registry,
            &MOCK_FORMATTER,
        )
        .await;

        let refactor_titles = refactor_titles(&actions);
        assert!(
            refactor_titles.contains(&"1.0.0 (latest)"),
            "the bumped stable pick must still appear, labeled (latest): {refactor_titles:?}"
        );
        assert!(
            !refactor_titles.contains(&"2.0.0-rc1"),
            "the 5th raw-order pre-release is displaced by the bumped pick: {refactor_titles:?}"
        );

        let preferred: Vec<&str> = actions
            .iter()
            .filter(|a| a.is_preferred == Some(true))
            .map(|a| a.title.as_str())
            .collect();
        assert_eq!(
            preferred,
            vec!["1.0.0 (latest)"],
            "the bumped entry must be isPreferred: {actions:?}"
        );
    }

    #[tokio::test]
    async fn test_generate_code_actions_all_prerelease_still_prefers_a_refactor_action() {
        // Critic C1: when every fetched version is a pre-release, the quick-fix list must
        // still agree with hover's own fallback (`Registry::select_latest_matching` falls
        // through the shared existence ladder to the newest overall) rather than leaving no
        // action preferred — the regression a raw `is_stable()`/`is_prerelease()` re-scan
        // introduced for the ~10 of 14 ecosystems sharing this ladder.
        let (dep, version_range, content) = vulnerable_dep("1.0.0");
        let parse_result = MockParseResult {
            deps: vec![dep],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let cached = HashMap::new();
        let resolved = HashMap::new();
        let versions = VersionData::new(&cached, &resolved);
        let registry = FixedVersionRegistry {
            versions: vec![("2.0.0-beta2", false), ("2.0.0-beta1", false)],
        };

        let actions = generate_code_actions(
            &parse_result,
            version_range.start,
            parse_result.uri(),
            versions,
            &content,
            &registry,
            &MOCK_FORMATTER,
        )
        .await;

        let refactor_titles = refactor_titles(&actions);
        assert!(
            refactor_titles.contains(&"2.0.0-beta2 (latest)"),
            "the newest overall must still carry the marker: {refactor_titles:?}"
        );

        let preferred: Vec<&str> = actions
            .iter()
            .filter(|a| a.is_preferred == Some(true))
            .map(|a| a.title.as_str())
            .collect();
        assert_eq!(preferred, vec!["2.0.0-beta2 (latest)"]);
    }

    #[tokio::test]
    async fn test_generate_code_actions_prefers_non_deprecated_over_newer_deprecated() {
        // Critic S1: the identical #952 defect class with "deprecated" substituted for
        // "pre-release" (npm's #338 NFR-002 shape) — `is_stable()` alone would still tag the
        // newer `AdvisoryDeprecated` entry as latest/preferred; delegating to the registry's
        // own `select_latest_matching` (the shared 3-rung ladder, gating on `is_flagged()`
        // rather than only `blocks_resolution()`) must prefer the older, non-flagged release
        // instead, agreeing with hover.
        let (dep, version_range, content) = vulnerable_dep("1.0.0");
        let parse_result = MockParseResult {
            deps: vec![dep],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let cached = HashMap::new();
        let resolved = HashMap::new();
        let versions = VersionData::new(&cached, &resolved);
        let registry = MockRegistryPreferringUnflagged {
            versions: vec![
                MockVersionWithStatus {
                    version: "2.0.0".into(),
                    status: crate::RemovalStatus::AdvisoryDeprecated,
                },
                MockVersionWithStatus {
                    version: "1.9.0".into(),
                    status: crate::RemovalStatus::Available,
                },
            ],
        };

        let actions = generate_code_actions(
            &parse_result,
            version_range.start,
            parse_result.uri(),
            versions,
            &content,
            &registry,
            &MOCK_FORMATTER,
        )
        .await;

        let refactor_titles = refactor_titles(&actions);
        assert!(
            refactor_titles.contains(&"2.0.0"),
            "the deprecated entry is still offered, unlabeled: {refactor_titles:?}"
        );
        assert!(
            refactor_titles.contains(&"1.9.0 (latest)"),
            "the non-deprecated entry must carry the marker instead: {refactor_titles:?}"
        );

        let preferred: Vec<&str> = actions
            .iter()
            .filter(|a| a.is_preferred == Some(true))
            .map(|a| a.title.as_str())
            .collect();
        assert_eq!(preferred, vec!["1.9.0 (latest)"]);
    }

    #[tokio::test]
    async fn test_generate_code_actions_fix_uses_ecosystem_format_version_replacing_override() {
        // Critic S3: `format_version_replacing` is overridden only by `deps-pypi`; no test
        // proved the vulnerability-fix action's `TextEdit` actually goes through such an
        // override rather than the default delegation — the same bug class #216 caught.
        use crate::osv::{
            Advisory, Capped, DependencyVulnerabilities, OsvVersion, UpgradeStatus, VulnSeverity,
        };
        use std::collections::HashMap;

        let (dep, version_range, content) = vulnerable_dep("==1.0.0");
        let uri = crate::test_util::test_uri("/test/requirements.txt");
        let parse_result = MockParseResult {
            deps: vec![dep],
            uri: uri.clone(),
        };

        let mut vulnerabilities = crate::osv::VulnerabilityMap::new();
        vulnerabilities.insert(
            crate::test_util::vuln_key("pkg"),
            ScanOutcome::Vulnerable(DependencyVulnerabilities {
                sibling_matches: None,
                advisories: Capped::new(
                    vec![std::sync::Arc::new(
                        Advisory::new(
                            "A1".to_string(),
                            "2023-01-01T00:00:00Z".to_string(),
                            VulnSeverity::High,
                        )
                        .expect("valid osv id")
                        .with_fixed_versions(vec![OsvVersion::new("1.0.2")]),
                    )],
                    1,
                ),
                fix_target_status: UpgradeStatus::CandidateClean {
                    version: ConcreteVersion::new("1.0.2"),
                },
            }),
        );

        let cached = HashMap::new();
        let resolved = HashMap::new();
        let versions = VersionData::new(&cached, &resolved).with_vulnerabilities(&vulnerabilities);

        let actions = generate_code_actions(
            &parse_result,
            version_range.start,
            parse_result.uri(),
            versions,
            &content,
            &MockRegistry,
            &PinPreservingFormatter,
        )
        .await;

        let quickfix = actions
            .iter()
            .find(|a| a.kind == Some(CodeActionKind::QUICKFIX))
            .expect("a vulnerability-fix quickfix should be offered");
        let new_text = quickfix
            .edit
            .as_ref()
            .and_then(|e| e.changes.as_ref())
            .and_then(|c| c.get(&crate::lsp_helpers::to_ls_uri(&uri)))
            .and_then(|edits| edits.first())
            .map(|e| e.new_text.as_str())
            .expect("quickfix should carry a TextEdit for the document uri");

        assert_eq!(
            new_text, "==1.0.2",
            "the fix action's TextEdit must go through format_version_replacing's \
             pin-preserving override, not the default format_version_for_text_edit delegation"
        );
    }

    /// Tests for the `literal_span_matches` guard on `generate_code_actions`
    /// (§6.3): a dependency whose `version_range` no longer slices to its
    /// declared requirement must yield no code action, mirroring the guard
    /// `collect_update_all_edits` already applies.
    mod code_actions_guard_tests {
        use super::*;
        use std::collections::HashMap;
        use tower_lsp_server::ls_types::{Position, Range};

        struct CaDep {
            name: PackageName,
            version_req: Option<VersionReq>,
            version_range: Option<Range>,
        }

        crate::impl_unprobed_dependency!(CaDep);
        impl Dependency for CaDep {
            fn name(&self) -> &PackageName {
                &self.name
            }
            fn name_range(&self) -> crate::position::Range {
                Range::default().into()
            }
            fn version_requirement(&self) -> Option<&VersionReq> {
                self.version_req.as_ref()
            }
            fn version_range(&self) -> Option<crate::position::Range> {
                self.version_range.map(Into::into)
            }
            fn source(&self) -> crate::parser::DependencySource {
                crate::parser::DependencySource::Registry
            }
        }

        struct CaParseResult {
            deps: Vec<CaDep>,
            uri: url::Url,
        }

        impl ParseResult for CaParseResult {
            fn dependencies(&self) -> Vec<&dyn Dependency> {
                self.deps.iter().map(|d| d as &dyn Dependency).collect()
            }
            fn workspace_root(&self) -> Option<&std::path::Path> {
                None
            }
            fn uri(&self) -> &url::Url {
                &self.uri
            }
        }

        impl crate::TypedParseResult for CaParseResult {
            type Dep = CaDep;
            fn own_dependencies(&self) -> &[CaDep] {
                &self.deps
            }
        }

        /// Mirrors `deps-swift`'s `SwiftDependency`: `version_req` is a synthesized
        /// comparator string, `version_range` spans only the bare literal it was
        /// synthesized from, and `version_literal` (unlike [`CaDep`], which relies on
        /// the trait's default `None`) carries that literal so the guard compares
        /// against it instead of `version_req` (#367).
        struct CaLiteralDep {
            name: PackageName,
            version_req: Option<VersionReq>,
            version_range: Option<Range>,
            version_literal: Option<String>,
        }

        crate::impl_unprobed_dependency!(CaLiteralDep);
        impl Dependency for CaLiteralDep {
            fn name(&self) -> &PackageName {
                &self.name
            }
            fn name_range(&self) -> crate::position::Range {
                Range::default().into()
            }
            fn version_requirement(&self) -> Option<&VersionReq> {
                self.version_req.as_ref()
            }
            fn version_range(&self) -> Option<crate::position::Range> {
                self.version_range.map(Into::into)
            }
            fn source(&self) -> crate::parser::DependencySource {
                crate::parser::DependencySource::Registry
            }
            fn version_literal(&self) -> Option<&str> {
                self.version_literal.as_deref()
            }
        }

        struct CaLiteralParseResult {
            deps: Vec<CaLiteralDep>,
            uri: url::Url,
        }

        impl ParseResult for CaLiteralParseResult {
            fn dependencies(&self) -> Vec<&dyn Dependency> {
                self.deps.iter().map(|d| d as &dyn Dependency).collect()
            }
            fn workspace_root(&self) -> Option<&std::path::Path> {
                None
            }
            fn uri(&self) -> &url::Url {
                &self.uri
            }
        }

        impl crate::TypedParseResult for CaLiteralParseResult {
            type Dep = CaLiteralDep;
            fn own_dependencies(&self) -> &[CaLiteralDep] {
                &self.deps
            }
        }

        struct CaVersion {
            version: ConcreteVersion,
            yanked: bool,
        }

        crate::impl_version!(CaVersion {
            version: version,
            status: |v: &CaVersion| crate::RemovalStatus::from_yanked(v.yanked),
        });

        struct CaRegistry;

        impl crate::Registry for CaRegistry {
            fn get_versions<'a>(
                &'a self,
                _name: &'a PackageName,
            ) -> crate::ecosystem::BoxFuture<'a, crate::error::Result<Vec<Box<dyn crate::Version>>>>
            {
                Box::pin(async move {
                    Ok(vec![Box::new(CaVersion {
                        version: "2.0.0".into(),
                        yanked: false,
                    }) as Box<dyn crate::Version>])
                })
            }

            fn get_latest_matching<'a>(
                &'a self,
                _name: &'a PackageName,
                _req: &'a VersionReq,
                _selection_context: &'a crate::SelectionContext,
            ) -> crate::ecosystem::BoxFuture<
                'a,
                crate::error::Result<Option<Box<dyn crate::Version>>>,
            > {
                Box::pin(async move { Ok(None) })
            }

            fn search_raw<'a>(
                &'a self,
                _query: &'a str,
                _limit: usize,
            ) -> crate::ecosystem::BoxFuture<'a, crate::error::Result<Vec<Box<dyn crate::Metadata>>>>
            {
                Box::pin(async move { Ok(Vec::new()) })
            }
        }

        fn range(sl: u32, sc: u32, el: u32, ec: u32) -> Range {
            Range::new(Position::new(sl, sc), Position::new(el, ec))
        }

        #[tokio::test]
        async fn test_guard_rejects_span_that_does_not_match_requirement() {
            // content has "1.0.0" at 0..5, but the dependency claims its
            // version_range covers 6..11 (out of bounds / wrong slice) —
            // simulate via a version_range that slices to different text.
            let content = "1.0.0 extra";
            let dep = CaDep {
                name: pkg("serde"),
                version_req: Some(VersionReq::new("1.0.0")),
                version_range: Some(range(0, 6, 0, 11)), // slices to "extra"
            };
            let pr = CaParseResult {
                deps: vec![dep],
                uri: crate::test_util::test_uri("/test/Cargo.toml"),
            };
            // Must fall inside `version_range` (6..11) for
            // `is_position_on_dependency`'s default impl to select this
            // dependency at all — the point of this test is the guard past
            // that selection, not the selection itself.
            let position = Position::new(0, 7);
            let cached = HashMap::new();
            let resolved = HashMap::new();
            let versions = VersionData::new(&cached, &resolved);

            let actions = generate_code_actions(
                &pr,
                position,
                pr.uri(),
                versions,
                content,
                &CaRegistry,
                &MOCK_FORMATTER.for_dependency(),
            )
            .await;

            assert!(actions.is_empty());
        }

        #[tokio::test]
        async fn test_guard_rejects_span_even_with_a_pending_vulnerability_fix() {
            // Critic S2: the guard must gate the vulnerability-fix quickfix too, not just the
            // plain "update version" action — moving `build_vulnerability_fix_action` above
            // the guard would reintroduce manifest corruption on a rejected span. Every other
            // test here uses an empty `VersionData`, which would pass regardless; this one
            // carries a real OSV hit so a reordering regression fails here.
            use crate::osv::{
                Advisory, Capped, DependencyVulnerabilities, OsvVersion, UpgradeStatus,
                VulnSeverity,
            };

            let content = "1.0.0 extra";
            let dep = CaDep {
                name: pkg("serde"),
                version_req: Some(VersionReq::new("1.0.0")),
                version_range: Some(range(0, 6, 0, 11)), // slices to "extra"
            };
            let pr = CaParseResult {
                deps: vec![dep],
                uri: crate::test_util::test_uri("/test/Cargo.toml"),
            };
            let position = Position::new(0, 7);

            let mut vulnerabilities = crate::osv::VulnerabilityMap::new();
            vulnerabilities.insert(
                crate::test_util::vuln_key("serde"),
                ScanOutcome::Vulnerable(DependencyVulnerabilities {
                    sibling_matches: None,
                    advisories: Capped::new(
                        vec![std::sync::Arc::new(
                            Advisory::new(
                                "A1".to_string(),
                                "2023-01-01T00:00:00Z".to_string(),
                                VulnSeverity::High,
                            )
                            .expect("valid osv id")
                            .with_fixed_versions(vec![OsvVersion::new("2.0.0")]),
                        )],
                        1,
                    ),
                    fix_target_status: UpgradeStatus::NotChecked,
                }),
            );
            let cached = HashMap::new();
            let resolved = HashMap::new();
            let versions =
                VersionData::new(&cached, &resolved).with_vulnerabilities(&vulnerabilities);

            let actions = generate_code_actions(
                &pr,
                position,
                pr.uri(),
                versions,
                content,
                &CaRegistry,
                &MOCK_FORMATTER.for_dependency(),
            )
            .await;

            assert!(quickfix_titles(&actions).is_empty());
            assert!(actions.is_empty());
        }

        #[tokio::test]
        async fn test_guard_accepts_matching_span() {
            let content = "1.0.0";
            let dep = CaDep {
                name: pkg("serde"),
                version_req: Some(VersionReq::new("1.0.0")),
                version_range: Some(range(0, 0, 0, 5)),
            };
            let pr = CaParseResult {
                deps: vec![dep],
                uri: crate::test_util::test_uri("/test/Cargo.toml"),
            };
            let position = Position::new(0, 0);
            let cached = HashMap::new();
            let resolved = HashMap::new();
            let versions = VersionData::new(&cached, &resolved);

            let actions = generate_code_actions(
                &pr,
                position,
                pr.uri(),
                versions,
                content,
                &CaRegistry,
                &MOCK_FORMATTER.for_dependency(),
            )
            .await;

            assert!(!actions.is_empty());
        }

        #[tokio::test]
        async fn test_guard_rejects_empty_requirement() {
            let content = "1.0.0";
            let dep = CaDep {
                name: pkg("serde"),
                version_req: Some(VersionReq::new("")),
                version_range: Some(range(0, 0, 0, 5)),
            };
            let pr = CaParseResult {
                deps: vec![dep],
                uri: crate::test_util::test_uri("/test/Cargo.toml"),
            };
            let position = Position::new(0, 0);
            let cached = HashMap::new();
            let resolved = HashMap::new();
            let versions = VersionData::new(&cached, &resolved);

            let actions = generate_code_actions(
                &pr,
                position,
                pr.uri(),
                versions,
                content,
                &CaRegistry,
                &MOCK_FORMATTER.for_dependency(),
            )
            .await;

            assert!(actions.is_empty());
        }

        #[tokio::test]
        async fn test_guard_rejects_synthesized_requirement_with_no_literal_override() {
            // Reproduces #367: a synthesized comparator requirement (mirroring
            // `deps-swift`'s `.upToNextMajor(from: "4.77.0")` -> `">=4.77.0, <5.0.0"`)
            // whose `version_range` spans only the bare literal `4.77.0`. Without a
            // `version_literal` override the guard compares the slice against the full
            // comparator string and can never match, so no action is ever produced —
            // the exact bug this issue reports.
            let content = "4.77.0";
            let dep = CaDep {
                name: pkg("vapor"),
                version_req: Some(VersionReq::new(">=4.77.0, <5.0.0")),
                version_range: Some(range(0, 0, 0, 6)),
            };
            let pr = CaParseResult {
                deps: vec![dep],
                uri: crate::test_util::test_uri("/test/Package.swift"),
            };
            let position = Position::new(0, 0);
            let cached = HashMap::new();
            let resolved = HashMap::new();
            let versions = VersionData::new(&cached, &resolved);

            let actions = generate_code_actions(
                &pr,
                position,
                pr.uri(),
                versions,
                content,
                &CaRegistry,
                &MOCK_FORMATTER.for_dependency(),
            )
            .await;

            assert!(actions.is_empty());
        }

        #[tokio::test]
        async fn test_guard_accepts_synthesized_requirement_via_version_literal_override() {
            // Fix for #367: same synthesized-requirement / bare-literal shape as
            // `test_guard_rejects_synthesized_requirement_with_no_literal_override`, but
            // `version_literal` now carries the bare literal the requirement was
            // synthesized from — the guard must compare against that instead of
            // `version_req` and accept the span.
            let content = "4.77.0";
            let dep = CaLiteralDep {
                name: pkg("vapor"),
                version_req: Some(VersionReq::new(">=4.77.0, <5.0.0")),
                version_range: Some(range(0, 0, 0, 6)),
                version_literal: Some("4.77.0".to_string()),
            };
            let pr = CaLiteralParseResult {
                deps: vec![dep],
                uri: crate::test_util::test_uri("/test/Package.swift"),
            };
            let position = Position::new(0, 0);
            let cached = HashMap::new();
            let resolved = HashMap::new();
            let versions = VersionData::new(&cached, &resolved);

            let actions = generate_code_actions(
                &pr,
                position,
                pr.uri(),
                versions,
                content,
                &CaRegistry,
                &MOCK_FORMATTER.for_dependency(),
            )
            .await;

            assert!(!actions.is_empty());
        }
    }

    /// Coverage for [`build_unsatisfiable_fix_action`] and its wiring into
    /// `generate_code_actions` (plan §1.2-§1.4): each guard, the yank filter, the
    /// vuln/unsat collision drop, and the `is_preferred` post-pass across producers.
    mod unsatisfiable_fix_action_tests {
        use super::*;
        use std::collections::HashMap;

        /// Same exact-match `compile_bounded_requirement` as [`ExactMatchFormatter`], but
        /// `format_version_replacing` always returns a fixed text that stays
        /// unsatisfiable against any `available` list not literally containing it —
        /// simulating a pypi/gradle-style override that preserves operator style
        /// into a still-broken range (plan §1.2.5 / critic M4).
        struct NonFixingFormatter;

        impl PackageNaming for NonFixingFormatter {}

        impl PackageRendering for NonFixingFormatter {
            fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
                version.to_string()
            }

            fn package_url(&self, name: &PackageName) -> String {
                format!("https://example.com/{}", name.as_str())
            }

            fn format_version_replacing(
                &self,
                _version: &ConcreteVersion,
                _current: &str,
            ) -> String {
                "still-bad".to_string()
            }
        }

        impl RequirementResolution for NonFixingFormatter {
            fn compile_bounded_requirement(
                &self,
                requirement: BoundedVersionReq<'_>,
            ) -> Option<Box<dyn RequirementMatcher>> {
                Some(Box::new(ExactMatcher(requirement.as_str().to_string())))
            }
        }

        impl DiagnosticMessages for NonFixingFormatter {}

        impl DiagnosticPolicy for NonFixingFormatter {}

        impl SourcePolicy for NonFixingFormatter {}

        impl OsvNaming for NonFixingFormatter {}

        impl DependencyFormatter for NonFixingFormatter {
            type Dep = MockDep;
        }

        /// Same exact-match `compile_bounded_requirement` as [`ExactMatchFormatter`], but
        /// `format_version_replacing` always returns the same fixed text regardless of
        /// its input — mirroring PyPI's `truncate_release_to_match`, which can map
        /// distinct registry versions to byte-identical rewritten text (M7 / plan
        /// §1.4). Used to construct a vuln-fix target and an unsat-fix target that are
        /// two different, independently-yankable versions whose formatted edits
        /// nonetheless collide.
        struct CollidingTextFormatter;

        impl PackageNaming for CollidingTextFormatter {}

        impl PackageRendering for CollidingTextFormatter {
            fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
                version.to_string()
            }

            fn package_url(&self, name: &PackageName) -> String {
                format!("https://example.com/{}", name.as_str())
            }

            fn format_version_replacing(
                &self,
                _version: &ConcreteVersion,
                _current: &str,
            ) -> String {
                "9.9.9".to_string()
            }
        }

        impl RequirementResolution for CollidingTextFormatter {
            fn compile_bounded_requirement(
                &self,
                requirement: BoundedVersionReq<'_>,
            ) -> Option<Box<dyn RequirementMatcher>> {
                Some(Box::new(ExactMatcher(requirement.as_str().to_string())))
            }
        }

        impl DiagnosticMessages for CollidingTextFormatter {}

        impl DiagnosticPolicy for CollidingTextFormatter {}

        impl SourcePolicy for CollidingTextFormatter {}

        impl OsvNaming for CollidingTextFormatter {}

        impl DependencyFormatter for CollidingTextFormatter {
            type Dep = MockDep;
        }

        /// Same exact-match `compile_bounded_requirement` as [`ExactMatchFormatter`], but with a
        /// non-identity `normalize_package_name`, for the M1 lookup-fallback test.
        struct NormalizingExactFormatter;

        impl PackageNaming for NormalizingExactFormatter {
            fn normalized_spelling(&self, name: &PackageName) -> String {
                format!("normalized-{}", name.as_str())
            }
        }

        impl PackageRendering for NormalizingExactFormatter {
            fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
                version.to_string()
            }

            fn package_url(&self, name: &PackageName) -> String {
                format!("https://example.com/{}", name.as_str())
            }
        }

        impl RequirementResolution for NormalizingExactFormatter {
            fn compile_bounded_requirement(
                &self,
                requirement: BoundedVersionReq<'_>,
            ) -> Option<Box<dyn RequirementMatcher>> {
                Some(Box::new(ExactMatcher(requirement.as_str().to_string())))
            }
        }

        impl DiagnosticMessages for NormalizingExactFormatter {}

        impl DiagnosticPolicy for NormalizingExactFormatter {}

        impl SourcePolicy for NormalizingExactFormatter {}

        impl OsvNaming for NormalizingExactFormatter {}

        impl DependencyFormatter for NormalizingExactFormatter {
            type Dep = MockDep;
        }

        fn cached_versions_keyed(
            key: &str,
            latest: &str,
            available: &[&str],
        ) -> HashMap<NormalizedName, PackageVersions> {
            let mut m = HashMap::new();
            m.insert(
                NormalizedName::for_test(key),
                PackageVersions {
                    latest: latest.into(),
                    available: Arc::from(
                        available
                            .iter()
                            .map(|s| ConcreteVersion::new(*s))
                            .collect::<Vec<_>>(),
                    ),
                    yanked: Arc::from(Vec::new()),
                    published_at: None,
                    gossip_excluded_version: None,
                    cooldown_fallback: None,
                },
            );
            m
        }

        fn cached_versions(
            latest: &str,
            available: &[&str],
        ) -> HashMap<NormalizedName, PackageVersions> {
            cached_versions_keyed("pkg", latest, available)
        }

        #[tokio::test]
        async fn test_unsat_fix_emitted_for_unsatisfiable_requirement() {
            let (dep, version_range, content) = vulnerable_dep("1.0.0");
            let parse_result = MockParseResult {
                deps: vec![dep],
                uri: crate::test_util::test_uri("/test/Cargo.toml"),
            };

            let cached = cached_versions("9.9.9", &["9.9.9"]);
            let resolved = HashMap::new();
            let versions = VersionData::new(&cached, &resolved);

            let actions = generate_code_actions(
                &parse_result,
                version_range.start,
                parse_result.uri(),
                versions,
                &content,
                &MockRegistry,
                &ExactMatchFormatter,
            )
            .await;

            assert_eq!(
                quickfix_titles(&actions),
                vec!["Fix unsatisfiable requirement: update to 9.9.9"]
            );
            assert_eq!(actions[0].is_preferred, Some(true));
        }

        #[tokio::test]
        async fn test_unsat_fix_absent_when_requirement_is_satisfied() {
            let (dep, version_range, content) = vulnerable_dep("9.9.9");
            let parse_result = MockParseResult {
                deps: vec![dep],
                uri: crate::test_util::test_uri("/test/Cargo.toml"),
            };

            let cached = cached_versions("9.9.9", &["9.9.9"]);
            let resolved = HashMap::new();
            let versions = VersionData::new(&cached, &resolved);

            let actions = generate_code_actions(
                &parse_result,
                version_range.start,
                parse_result.uri(),
                versions,
                &content,
                &MockRegistry,
                &ExactMatchFormatter,
            )
            .await;

            assert!(quickfix_titles(&actions).is_empty());
        }

        #[tokio::test]
        async fn test_unsat_fix_absent_for_unsafe_or_empty_latest() {
            // Regression for #302 (5th guarded call site, added alongside #304):
            // `build_unsatisfiable_fix_action`'s cached `latest` is exactly as untrusted
            // as `collect_update_all_edits`'s — a manifest-structural character or an
            // empty string must never reach `format_version_replacing` here either.
            for unsafe_latest in ["9.9.9\", \"evil\": \"true", "", "   "] {
                let (dep, version_range, content) = vulnerable_dep("1.0.0");
                let parse_result = MockParseResult {
                    deps: vec![dep],
                    uri: crate::test_util::test_uri("/test/Cargo.toml"),
                };

                let cached = cached_versions(unsafe_latest, &[unsafe_latest]);
                let resolved = HashMap::new();
                let versions = VersionData::new(&cached, &resolved);

                let actions = generate_code_actions(
                    &parse_result,
                    version_range.start,
                    parse_result.uri(),
                    versions,
                    &content,
                    &MockRegistry,
                    &ExactMatchFormatter,
                )
                .await;

                assert!(
                    quickfix_titles(&actions).is_empty(),
                    "expected no unsatisfiable-fix quickfix for latest {unsafe_latest:?}"
                );
            }
        }

        #[tokio::test]
        async fn test_unsat_fix_absent_for_non_resolvable_source() {
            // Mirrors the diagnostic's own `is_version_resolvable` call-site guard
            // (#248): a path/git/SDK/workspace dependency's cache entry may be
            // coincidental, so no fix action should be offered for it either.
            let content = "1.0.0";
            let dep = NonRegistryDep(
                MockDep {
                    name: pkg("pkg"),
                    version_req: VersionReq::new("1.0.0"),
                    version_range: Range::new(Position::new(0, 0), Position::new(0, 5)),
                    name_range: Range::default(),
                },
                crate::parser::DependencySource::Path {
                    path: "../local".into(),
                },
            );
            let pr = SingleDepParseResult {
                dep,
                uri: crate::test_util::test_uri("/test/Cargo.toml"),
            };

            let cached = cached_versions("9.9.9", &["9.9.9"]);
            let resolved = HashMap::new();
            let versions = VersionData::new(&cached, &resolved);

            let actions = generate_code_actions(
                &pr,
                Position::new(0, 0).into(),
                pr.uri(),
                versions,
                content,
                &MockRegistry,
                &NonRegistryExactFormatter,
            )
            .await;

            assert!(quickfix_titles(&actions).is_empty());
        }

        #[tokio::test]
        async fn test_unsat_fix_no_op_guard_skips_when_rewrite_equals_declared_text() {
            // `latest` already equals the declared requirement text (whitespace
            // aside) — nothing for the action to fix.
            let (dep, version_range, content) = vulnerable_dep("9.9.9");
            let parse_result = MockParseResult {
                deps: vec![dep],
                uri: crate::test_util::test_uri("/test/Cargo.toml"),
            };
            // Requirement "9.9.9" itself is unsatisfiable only if it isn't in
            // `available`; make it unsatisfiable via a *different* available set
            // but formatted rewrite identical to the declared text.
            let cached = cached_versions("9.9.9", &["1.0.0"]);
            let resolved = HashMap::new();
            let versions = VersionData::new(&cached, &resolved);

            let actions = generate_code_actions(
                &parse_result,
                version_range.start,
                parse_result.uri(),
                versions,
                &content,
                &MockRegistry,
                &ExactMatchFormatter,
            )
            .await;

            // "9.9.9" -> "9.9.9" is a no-op rewrite, so the action must be skipped
            // even though the requirement is genuinely unsatisfiable.
            assert!(quickfix_titles(&actions).is_empty());
        }

        #[tokio::test]
        async fn test_unsat_fix_verification_guard_rejects_rewrite_that_stays_unsatisfiable() {
            // Critic M4: `format_version_replacing` can preserve operator style into
            // a rewrite that is itself still unsatisfiable (pypi/gradle-style). The
            // action must not be offered in that case.
            let (dep, version_range, content) = vulnerable_dep("1.0.0");
            let parse_result = MockParseResult {
                deps: vec![dep],
                uri: crate::test_util::test_uri("/test/Cargo.toml"),
            };

            let cached = cached_versions("9.9.9", &["9.9.9"]);
            let resolved = HashMap::new();
            let versions = VersionData::new(&cached, &resolved);

            let actions = generate_code_actions(
                &parse_result,
                version_range.start,
                parse_result.uri(),
                versions,
                &content,
                &MockRegistry,
                &NonFixingFormatter,
            )
            .await;

            assert!(quickfix_titles(&actions).is_empty());
        }

        #[tokio::test]
        async fn test_unsat_fix_resolves_cache_entry_keyed_by_normalized_name() {
            // An ecosystem whose `normalize_package_name` is not the identity must resolve
            // the cache entry keyed by the normalized spelling.
            let (dep, version_range, content) = vulnerable_dep("1.0.0");
            let parse_result = MockParseResult {
                deps: vec![dep],
                uri: crate::test_util::test_uri("/test/Cargo.toml"),
            };

            let cached = cached_versions_keyed("normalized-pkg", "9.9.9", &["9.9.9"]);
            let resolved = HashMap::new();
            let versions = VersionData::new(&cached, &resolved);

            let actions = generate_code_actions(
                &parse_result,
                version_range.start,
                parse_result.uri(),
                versions,
                &content,
                &MockRegistry,
                &NormalizingExactFormatter,
            )
            .await;

            assert_eq!(
                quickfix_titles(&actions),
                vec!["Fix unsatisfiable requirement: update to 9.9.9"]
            );
        }

        #[tokio::test]
        async fn test_unsat_fix_dropped_when_target_is_yanked() {
            let (dep, version_range, content) = vulnerable_dep("1.0.0");
            let parse_result = MockParseResult {
                deps: vec![dep],
                uri: crate::test_util::test_uri("/test/Cargo.toml"),
            };

            let cached = cached_versions("9.9.9", &["9.9.9"]);
            let resolved = HashMap::new();
            let versions = VersionData::new(&cached, &resolved);
            let registry = FixedVersionRegistry {
                versions: vec![("9.9.9", true)],
            };

            let actions = generate_code_actions(
                &parse_result,
                version_range.start,
                parse_result.uri(),
                versions,
                &content,
                &registry,
                &ExactMatchFormatter,
            )
            .await;

            assert!(quickfix_titles(&actions).is_empty());
        }

        #[tokio::test]
        async fn test_unsat_fix_survives_registry_outage_and_is_preferred() {
            // S1: the single-exit restructure must not drop `isPreferred` on the
            // outage path when only the unsat fix (no vuln fix) is present.
            let (dep, version_range, content) = vulnerable_dep("1.0.0");
            let parse_result = MockParseResult {
                deps: vec![dep],
                uri: crate::test_util::test_uri("/test/Cargo.toml"),
            };

            let cached = cached_versions("9.9.9", &["9.9.9"]);
            let resolved = HashMap::new();
            let versions = VersionData::new(&cached, &resolved);

            let actions = generate_code_actions(
                &parse_result,
                version_range.start,
                parse_result.uri(),
                versions,
                &content,
                &ErrorRegistry,
                &ExactMatchFormatter,
            )
            .await;

            assert_eq!(
                quickfix_titles(&actions),
                vec!["Fix unsatisfiable requirement: update to 9.9.9"]
            );
            assert_eq!(actions[0].is_preferred, Some(true));
        }

        #[tokio::test]
        async fn test_vuln_and_unsat_fix_coexist_with_vuln_preferred() {
            use crate::osv::{
                Advisory, Capped, DependencyVulnerabilities, OsvVersion, UpgradeStatus,
                VulnSeverity,
            };

            let (dep, version_range, content) = vulnerable_dep("1.0.0");
            let parse_result = MockParseResult {
                deps: vec![dep],
                uri: crate::test_util::test_uri("/test/Cargo.toml"),
            };

            let mut vulnerabilities = crate::osv::VulnerabilityMap::new();
            vulnerabilities.insert(
                crate::test_util::vuln_key("pkg"),
                ScanOutcome::Vulnerable(DependencyVulnerabilities {
                    sibling_matches: None,
                    advisories: Capped::new(
                        vec![std::sync::Arc::new(
                            Advisory::new(
                                "A1".to_string(),
                                "2023-01-01T00:00:00Z".to_string(),
                                VulnSeverity::High,
                            )
                            .expect("valid osv id")
                            .with_fixed_versions(vec![OsvVersion::new("5.5.5")]),
                        )],
                        1,
                    ),
                    fix_target_status: UpgradeStatus::CandidateClean {
                        version: ConcreteVersion::new("5.5.5"),
                    },
                }),
            );
            // "9.9.9" (unsat target) differs from "5.5.5" (vuln target), so both
            // survive the text-collision drop.
            let cached = cached_versions("9.9.9", &["9.9.9", "5.5.5"]);
            let resolved = HashMap::new();
            let versions =
                VersionData::new(&cached, &resolved).with_vulnerabilities(&vulnerabilities);

            let actions = generate_code_actions(
                &parse_result,
                version_range.start,
                parse_result.uri(),
                versions,
                &content,
                &MockRegistry,
                &ExactMatchFormatter,
            )
            .await;

            let titles = quickfix_titles(&actions);
            assert_eq!(titles.len(), 2, "expected both fixes: {titles:?}");
            assert!(titles.iter().any(|t| t.starts_with("Update to 5.5.5")));
            assert!(
                titles
                    .iter()
                    .any(|t| t.starts_with("Fix unsatisfiable requirement"))
            );

            let vuln_action = actions
                .iter()
                .find(|a| a.title.starts_with("Update to 5.5.5"))
                .unwrap();
            let unsat_action = actions
                .iter()
                .find(|a| a.title.starts_with("Fix unsatisfiable"))
                .unwrap();
            assert_eq!(vuln_action.is_preferred, Some(true));
            assert_eq!(unsat_action.is_preferred, None);
            assert_eq!(
                actions
                    .iter()
                    .filter(|a| a.is_preferred == Some(true))
                    .count(),
                1
            );
        }

        #[tokio::test]
        async fn test_unsat_fix_dropped_when_it_collides_with_vuln_fix_text() {
            // Plan §1.4: when both fixes would write byte-identical text, the vuln
            // fix (richer title) wins and the unsat fix is dropped.
            use crate::osv::{
                Advisory, Capped, DependencyVulnerabilities, OsvVersion, UpgradeStatus,
                VulnSeverity,
            };

            let (dep, version_range, content) = vulnerable_dep("1.0.0");
            let parse_result = MockParseResult {
                deps: vec![dep],
                uri: crate::test_util::test_uri("/test/Cargo.toml"),
            };

            let mut vulnerabilities = crate::osv::VulnerabilityMap::new();
            vulnerabilities.insert(
                crate::test_util::vuln_key("pkg"),
                ScanOutcome::Vulnerable(DependencyVulnerabilities {
                    sibling_matches: None,
                    advisories: Capped::new(
                        vec![std::sync::Arc::new(
                            Advisory::new(
                                "A1".to_string(),
                                "2023-01-01T00:00:00Z".to_string(),
                                VulnSeverity::High,
                            )
                            .expect("valid osv id")
                            // Same target as the unsat fix's cached `latest` below.
                            .with_fixed_versions(vec![OsvVersion::new("9.9.9")]),
                        )],
                        1,
                    ),
                    fix_target_status: UpgradeStatus::CandidateClean {
                        version: ConcreteVersion::new("9.9.9"),
                    },
                }),
            );
            let cached = cached_versions("9.9.9", &["9.9.9"]);
            let resolved = HashMap::new();
            let versions =
                VersionData::new(&cached, &resolved).with_vulnerabilities(&vulnerabilities);

            let actions = generate_code_actions(
                &parse_result,
                version_range.start,
                parse_result.uri(),
                versions,
                &content,
                &MockRegistry,
                &ExactMatchFormatter,
            )
            .await;

            let titles = quickfix_titles(&actions);
            assert_eq!(titles.len(), 1, "unsat fix must be dropped: {titles:?}");
            assert!(titles[0].starts_with("Update to 9.9.9"));
        }

        #[tokio::test]
        async fn test_yank_filter_runs_before_collision_check_so_neither_fix_is_lost() {
            // Critic M7: the vuln fix targets a yanked version and the unsat fix a different,
            // live one, but both format to identical text (mirroring PyPI's
            // `truncate_release_to_match`). Yank-filtering must run before the collision
            // check, or collision-first would drop the unsat action for "colliding" with a
            // vuln fix the yank filter was about to drop anyway, leaving neither.
            use crate::osv::{
                Advisory, Capped, DependencyVulnerabilities, OsvVersion, UpgradeStatus,
                VulnSeverity,
            };

            let (dep, version_range, content) = vulnerable_dep("1.0.0");
            let parse_result = MockParseResult {
                deps: vec![dep],
                uri: crate::test_util::test_uri("/test/Cargo.toml"),
            };

            let mut vulnerabilities = crate::osv::VulnerabilityMap::new();
            vulnerabilities.insert(
                crate::test_util::vuln_key("pkg"),
                ScanOutcome::Vulnerable(DependencyVulnerabilities {
                    sibling_matches: None,
                    advisories: Capped::new(
                        vec![std::sync::Arc::new(
                            Advisory::new(
                                "A1".to_string(),
                                "2023-01-01T00:00:00Z".to_string(),
                                VulnSeverity::High,
                            )
                            .expect("valid osv id")
                            // Different raw version than the unsat fix's cached
                            // `latest` ("9.9.9") below, but `CollidingTextFormatter`
                            // rewrites both to the same "9.9.9" text.
                            .with_fixed_versions(vec![OsvVersion::new("9.9.5")]),
                        )],
                        1,
                    ),
                    fix_target_status: UpgradeStatus::CandidateClean {
                        version: ConcreteVersion::new("9.9.5"),
                    },
                }),
            );
            // Unsat fix's own gate/verification data (distinct from the registry
            // below): unsatisfiable against "9.9.9", and the rewritten "9.9.9"
            // re-verifies as satisfiable since it's literally in `available`.
            let cached = cached_versions("9.9.9", &["9.9.9"]);
            let resolved = HashMap::new();
            let versions =
                VersionData::new(&cached, &resolved).with_vulnerabilities(&vulnerabilities);
            // Registry-reported yank status: the vuln fix's target is yanked, the
            // unsat fix's target is live.
            let registry = FixedVersionRegistry {
                versions: vec![("9.9.5", true), ("9.9.9", false)],
            };

            let actions = generate_code_actions(
                &parse_result,
                version_range.start,
                parse_result.uri(),
                versions,
                &content,
                &registry,
                &CollidingTextFormatter,
            )
            .await;

            let titles = quickfix_titles(&actions);
            assert_eq!(
                titles,
                vec!["Fix unsatisfiable requirement: update to 9.9.9"],
                "vuln fix must be dropped for being yanked, unsat fix must survive: {titles:?}"
            );
        }

        #[tokio::test]
        async fn test_unsat_fix_dedups_refactor_item_writing_the_same_text() {
            let (dep, version_range, content) = vulnerable_dep("1.0.0");
            let parse_result = MockParseResult {
                deps: vec![dep],
                uri: crate::test_util::test_uri("/test/Cargo.toml"),
            };

            let cached = cached_versions("9.9.9", &["9.9.9"]);
            let resolved = HashMap::new();
            let versions = VersionData::new(&cached, &resolved);
            // The registry's own "9.9.9" entry would otherwise become a REFACTOR
            // "update to 9.9.9" display item, byte-identical to the unsat fix's edit.
            let registry = FixedVersionRegistry {
                versions: vec![("9.9.9", false)],
            };

            let actions = generate_code_actions(
                &parse_result,
                version_range.start,
                parse_result.uri(),
                versions,
                &content,
                &registry,
                &ExactMatchFormatter,
            )
            .await;

            assert_eq!(quickfix_titles(&actions).len(), 1);
            assert!(
                refactor_titles(&actions).is_empty(),
                "the duplicate REFACTOR item must be suppressed by the dedup set: {actions:?}"
            );
        }

        /// Same exact-match `compile_bounded_requirement` as [`ExactMatchFormatter`] (so an
        /// unsatisfiable-fix action would otherwise be offered, and the registry's versions
        /// would otherwise produce REFACTOR "Update to X" items), but
        /// `requirement_is_placeholder` unconditionally returns `true` — #1370 tester gap:
        /// proves the central gate actually fires on the two call sites
        /// (`build_unsatisfiable_fix_action`, the REFACTOR loop) that had no test coverage.
        struct PlaceholderGatedFormatter;

        impl PackageNaming for PlaceholderGatedFormatter {}

        impl PackageRendering for PlaceholderGatedFormatter {
            fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
                version.to_string()
            }

            fn package_url(&self, name: &PackageName) -> String {
                format!("https://example.com/{}", name.as_str())
            }
        }

        impl RequirementResolution for PlaceholderGatedFormatter {
            fn compile_bounded_requirement(
                &self,
                requirement: BoundedVersionReq<'_>,
            ) -> Option<Box<dyn RequirementMatcher>> {
                Some(Box::new(ExactMatcher(requirement.as_str().to_string())))
            }

            /// Pinned to `false`, diverging from [`Self::bounded_requirement_is_placeholder`] below
            /// (`true`) rather than relying on the trait's default delegation (#1380) —
            /// mutation-testing control: if `build_unsatisfiable_fix_action`'s central gate
            /// were ever swapped to consult `requirement_is_unresolved` instead of
            /// `requirement_is_placeholder`, this divergence makes
            /// `test_unsat_fix_absent_for_placeholder_requirement` fail instead of passing
            /// vacuously (both predicates would otherwise agree via the shared default).
            fn bounded_requirement_is_unresolved(
                &self,
                _requirement: BoundedVersionReq<'_>,
            ) -> bool {
                false
            }

            fn bounded_requirement_is_placeholder(
                &self,
                _requirement: BoundedVersionReq<'_>,
            ) -> bool {
                true
            }
        }

        impl DiagnosticMessages for PlaceholderGatedFormatter {}

        impl DiagnosticPolicy for PlaceholderGatedFormatter {}

        impl SourcePolicy for PlaceholderGatedFormatter {}

        impl OsvNaming for PlaceholderGatedFormatter {}

        impl DependencyFormatter for PlaceholderGatedFormatter {
            type Dep = MockDep;
        }

        /// #1370: same setup as `test_unsat_fix_emitted_for_unsatisfiable_requirement` (which
        /// asserts the action IS offered without the gate), swapping in
        /// `PlaceholderGatedFormatter` — proves `build_unsatisfiable_fix_action`'s central
        /// `requirement_is_placeholder` gate actually suppresses the action, not merely that
        /// the predicate exists.
        #[tokio::test]
        async fn test_unsat_fix_absent_for_placeholder_requirement() {
            let (dep, version_range, content) = vulnerable_dep("1.0.0");
            let parse_result = MockParseResult {
                deps: vec![dep],
                uri: crate::test_util::test_uri("/test/Cargo.toml"),
            };

            let cached = cached_versions("9.9.9", &["9.9.9"]);
            let resolved = HashMap::new();
            let versions = VersionData::new(&cached, &resolved);

            let actions = generate_code_actions(
                &parse_result,
                version_range.start,
                parse_result.uri(),
                versions,
                &content,
                &MockRegistry,
                &PlaceholderGatedFormatter,
            )
            .await;

            assert!(
                quickfix_titles(&actions).is_empty(),
                "a placeholder-shaped requirement must never produce an unsatisfiable-fix \
                 quickfix, even when compile_requirement would otherwise make it \
                 unsatisfiable: {actions:?}"
            );
        }

        /// #1370: mirrors the REFACTOR-loop tests above (e.g.
        /// `test_generate_code_actions_refactor_loop_no_op_guard_ignores_whitespace`), but with
        /// no OSV/unsat-fix action in play at all (empty `cached`) so only the REFACTOR loop's
        /// own gate is exercised — proves it actually suppresses "Update to X" items for a
        /// placeholder-shaped requirement, not just that a status check happens to.
        #[tokio::test]
        async fn test_refactor_loop_absent_for_placeholder_requirement() {
            let (dep, version_range, content) = vulnerable_dep("1.2.0");
            let parse_result = MockParseResult {
                deps: vec![dep],
                uri: crate::test_util::test_uri("/test/Cargo.toml"),
            };

            let cached = HashMap::new();
            let resolved = HashMap::new();
            let versions = VersionData::new(&cached, &resolved);
            let registry = FixedVersionRegistry {
                versions: vec![("1.2.0", false), ("1.1.0", false)],
            };

            let actions = generate_code_actions(
                &parse_result,
                version_range.start,
                parse_result.uri(),
                versions,
                &content,
                &registry,
                &PlaceholderGatedFormatter,
            )
            .await;

            assert!(
                refactor_titles(&actions).is_empty(),
                "a placeholder-shaped requirement must never produce a REFACTOR \"Update to X\" \
                 action, even when the registry lists a genuinely different version: {actions:?}"
            );
        }
    }
}
