use std::collections::HashSet;
use tower_lsp_server::ls_types::{CodeAction, CodeActionKind, Position, Range, Uri, WorkspaceEdit};

use crate::osv::ScanOutcome;
use crate::{Dependency, ParseResult, Registry, VersionReq};

use super::{
    DEPRECATED_DIAGNOSTIC_CODE, EcosystemFormatter, LineOffsetTable, UNSATISFIABLE_DIAGNOSTIC_CODE,
    VersionData, is_safe_version_string, literal_span_matches, requirement_is_unsatisfiable,
    single_file_edit, slice_for_range, strip_whitespace, warn_rejected_value,
};

/// The vulnerability-fix quickfix built by [`build_vulnerability_fix_action`],
/// bundled with the native-namespace version it targets so callers can dedup
/// display items and check the registry's yank flag against it without
/// re-parsing the action's title.
struct VulnerabilityFixAction {
    /// `fix.version`, converted to this ecosystem's namespace via
    /// [`EcosystemFormatter::osv_version_to_native`].
    version_native: String,
    /// The formatted edit text this action's own `TextEdit` writes — the exact
    /// value `action.edit` carries, kept alongside it so callers (the REFACTOR-loop
    /// dedup in [`generate_code_actions`]) can compare against it without
    /// recomputing `format_version_replacing` and risking the copy silently
    /// drifting from the actual edit if that computation ever changes.
    new_text: String,
    action: CodeAction,
}

/// Builds the "fix vulnerability" quickfix for `dep`, if OSV data
/// recommends one.
///
/// Registry-independent by construction (FR-007, mirroring the rule already
/// enforced in [`generate_diagnostics_from_cache`]): computed entirely from
/// `versions.vulnerabilities` and `version_req` (the caller's already-fetched
/// `dep.version_requirement()`), never from a registry fetch. Callers must
/// still reconcile the result against a successful registry fetch when one
/// is available — see the yank check in [`generate_code_actions`].
fn build_vulnerability_fix_action(
    parse_result: &dyn ParseResult,
    dep: &dyn Dependency,
    uri: &Uri,
    version_range: Range,
    versions: VersionData<'_>,
    version_req: &str,
    formatter: &dyn EcosystemFormatter,
) -> Option<VulnerabilityFixAction> {
    let normalized_name = formatter.normalize_package_name(dep.name());
    // #394 S2: prefer the version-qualified key so a fix action for one
    // occurrence of a duplicated name is never built from another
    // occurrence's OSV result. See `crate::osv::vulnerability_keys`.
    let vuln_key = versions.ecosystem.and_then(|ecosystem| {
        crate::osv::vulnerability_keys(parse_result, versions.resolved, formatter, ecosystem)
            .remove(&dep.name_range())
    });
    let outcome = versions.vulnerabilities.and_then(|m| {
        vuln_key
            .as_deref()
            .and_then(|key| m.get(key))
            .or_else(|| m.get(&normalized_name))
            .or_else(|| m.get(dep.name().as_str()))
    })?;
    let ScanOutcome::Vulnerable(dv) = outcome else {
        return None;
    };
    let fix = dv.recommended_fix()?;
    let version_native = formatter.osv_version_to_native(&fix.version);
    if !is_safe_version_string(&version_native) {
        warn_rejected_value(
            "is_safe_version_string",
            "vulnerability fix code action",
            &version_native,
        );
        return None;
    }
    // Computed before the N1 guard below against the *same* formatting the
    // plain "update version" action uses (`format_version_replacing`), not
    // the bare version: several ecosystems wrap or expand it (`deps-dart`'s
    // `^`-prefix, a range), and `deps-pypi` rewrites it in place to preserve
    // the manifest's existing pin style (`==1.0.1` -> `==1.0.2`) — the guard
    // must compare the text that would actually be written.
    let new_text = formatter.format_version_replacing(&version_native, version_req);

    // N1: skip a no-op edit — the manifest already declares exactly the text
    // this action would write, so applying it would rewrite the text to
    // itself. Whitespace-insensitive, mirroring `literal_span_matches`:
    // `version_req` can be a normalized requirement string with spacing the
    // declared text and the freshly-formatted text don't agree on (e.g.
    // pep508's `>=1.7, <2.0` vs. a formatter's `>=1.7,<2.0`), which would
    // otherwise let a whitespace-only edit slip past this guard. Compares
    // against `dep.version_literal()` rather than `version_req` when the
    // ecosystem provides one, mirroring `generate_code_actions`'s literal-span
    // guard — for `deps-swift`, `version_req` is a synthesized comparator
    // (`"=2.61.0"`) that never equals the bare-literal formatted text
    // (`"2.61.0"`) even when the edit genuinely is a no-op.
    let literal_target = dep.version_literal().unwrap_or(version_req);
    if strip_whitespace(literal_target) == strip_whitespace(&new_text) {
        return None;
    }

    // S3: the scan target may have been the lockfile-resolved version, not
    // the declared requirement — rewriting the manifest alone would then not
    // clear the diagnostic until the lockfile is regenerated. Say so in the
    // title rather than silently overclaiming.
    let lockfile_hit = versions
        .resolved
        .get(normalized_name.as_str())
        .or_else(|| versions.resolved.get(dep.name()))
        .is_some();

    // Names only the first (worst-severity, per `recommended_fix`'s sort)
    // advisory id and summarizes the rest — `recommended_fix` can return an
    // unbounded number of ids (up to `ADVISORY_DISPLAY_CAP`), and a title
    // listing every one of them would overflow an editor's code-action menu.
    let (first_id, rest_ids) = fix.advisory_ids.split_first()?;
    let fixes = if rest_ids.is_empty() {
        first_id.clone()
    } else {
        format!("{first_id} +{} more", rest_ids.len())
    };
    let title = if lockfile_hit {
        format!("Update to {version_native} (fixes {fixes}; update lockfile to apply)")
    } else {
        format!("Update to {version_native} (fixes {fixes})")
    };

    let edits = single_file_edit(uri, version_range, new_text.clone());

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
            // Stashes the resolved advisory ids, plus this action's own edit range, so the
            // `deps-lsp` handler can bind this action to the matching client-supplied
            // diagnostics (`CodeActionContext::diagnostics`) without deps-core needing to
            // know about LSP request context — cleared by the handler once consumed. Shape
            // shared with `build_unsatisfiable_fix_action`'s stashed payload: `bind_diagnostics`
            // matches on `diagnostic_codes` regardless of which producer built the action.
            data: Some(serde_json::json!({
                "diagnostic_codes": fix.advisory_ids,
                "diagnostic_range": version_range,
            })),
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
/// fetch, so a registry outage never hides it (the same FR-007 rationale). Gated by
/// [`requirement_is_unsatisfiable`] evaluated against the identical inputs
/// [`generate_diagnostics_from_cache`] uses, so this action can never appear without —
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
fn build_unsatisfiable_fix_action(
    dep: &dyn Dependency,
    uri: &Uri,
    version_range: Range,
    versions: VersionData<'_>,
    version_req: &VersionReq,
    formatter: &dyn EcosystemFormatter,
) -> Option<UnsatisfiableFixAction> {
    if !dep.source().is_version_resolvable() {
        return None;
    }

    let normalized_name = formatter.normalize_package_name(dep.name());
    let package_versions = versions
        .cached
        .get(normalized_name.as_str())
        .or_else(|| versions.cached.get(dep.name()))?;

    if !requirement_is_unsatisfiable(formatter, version_req, &package_versions.available) {
        return None;
    }

    let latest = package_versions.latest.clone();
    if !is_safe_version_string(&latest) {
        warn_rejected_value(
            "is_safe_version_string",
            "unsatisfiable-requirement fix code action",
            &latest,
        );
        return None;
    }
    let new_text = formatter.format_version_replacing(&latest, version_req.as_str());

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

    let edits = single_file_edit(uri, version_range, new_text.clone());

    Some(UnsatisfiableFixAction {
        version_native: latest.clone(),
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

/// Builds the "Replace with X" package-rename quickfix for `dep` (issue #205), if this
/// ecosystem opts in via [`EcosystemFormatter::supports_package_rename`] and a
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
    uri: &Uri,
    version_range: Range,
    versions: VersionData<'_>,
    content: &str,
    line_offsets: &LineOffsetTable,
    formatter: &dyn EcosystemFormatter,
) -> Option<CodeAction> {
    if !formatter.supports_package_rename() {
        return None;
    }

    let normalized_name = formatter.normalize_package_name(dep.name());
    let replacement = versions
        .deprecations
        .and_then(|d| d.get(&normalized_name))
        .and_then(|dep_info| dep_info.replacement.as_deref())
        .filter(|r| !r.is_empty())?;

    if formatter.validate_package_name(replacement).is_err() {
        return None;
    }

    let name_range = dep.name_range();
    let name_slice = slice_for_range(content, line_offsets, name_range);
    // I7: reuses `literal_span_matches` rather than a name-specific equality check purely
    // for the sentinel-rejecting behavior its whitespace-insensitive comparison already
    // gives (see D7(a)'s doc above). Its `[{slice}] == requirement` NuGet-bracket branch
    // is inert here — a package name never contains `[`/`]` (rejected by every
    // ecosystem's `validate_package_name`) — so it never changes this call's outcome.
    if !literal_span_matches(name_slice, dep.name().as_str()) {
        return None;
    }

    let edits = single_file_edit(uri, name_range, replacement.to_string());

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
///    carries an OSV scan result flagging this dependency and
///    [`crate::osv::DependencyVulnerabilities::recommended_fix`] has a
///    claimable target (see the private `build_vulnerability_fix_action` helper
///    just above). This action
///    is computed entirely from `versions` and the dependency's declared
///    requirement, deliberately *before* the `registry.get_versions` call
///    below — a registry outage must never hide a known-vulnerable
///    dependency's fix (FR-007), so this action is still returned even when
///    the registry fetch that produces the plain list below fails. When the
///    fetch does succeed, a fix target the registry reports as yanked is
///    dropped rather than offered.
/// 2. At most one `QUICKFIX` "fix unsatisfiable requirement" action, computed the same
///    registry-independent way (see the private `build_unsatisfiable_fix_action` helper
///    just above) for the same FR-007 reason. If its rewritten text collides with the
///    vulnerability fix's (both yank-filtered first), it is dropped in favor of the
///    vulnerability fix, whose title is the more informative of the two.
/// 3. Up to five plain `REFACTOR` "update to `<version>`" actions, one per
///    non-yanked version [`crate::completion::prepare_version_display_items`]
///    selects from the registry response. Each action's edit text
///    comes from [`EcosystemFormatter::format_version_replacing`], which
///    preserves the manifest's existing pin/operator style where an
///    ecosystem overrides it (e.g. PyPI's `==1.0.1` stays `==1.0.2` rather
///    than expanding to a `>=,<` range). Every entry's formatted edit text is
///    checked against a running set seeded with the declared requirement and
///    the two fix actions' own formatted text (whitespace-insensitive); an entry
///    is skipped, and never added to the set, when its text is already
///    present. This is the common case, not a rare edge case:
///    [`crate::completion::prepare_version_display_items`] lists the top 5
///    non-yanked registry versions newest-first, so whenever the declared
///    version is already within 5 releases of latest, it is itself one of
///    the display items being offered as an "update". The same set also
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
pub async fn generate_code_actions<R: Registry + ?Sized>(
    parse_result: &dyn ParseResult,
    position: Position,
    uri: &Uri,
    versions: VersionData<'_>,
    content: &str,
    registry: &R,
    formatter: &dyn EcosystemFormatter,
) -> Vec<CodeAction> {
    use crate::completion::prepare_version_display_items;

    let deps = parse_result.dependencies();
    let mut actions = Vec::with_capacity(deps.len().min(5) + 1);

    let Some(dep) = deps
        .into_iter()
        .find(|d| formatter.is_position_on_dependency(*d, position))
    else {
        return actions;
    };

    let Some(version_range) = dep.version_range() else {
        return actions;
    };

    let Some(version_req) = dep.version_requirement() else {
        return actions;
    };
    if version_req.as_str().is_empty() {
        // Defense-in-depth, mirroring `collect_update_all_edits`: an empty
        // requirement would trivially satisfy the guard below.
        return actions;
    }

    let line_offsets = LineOffsetTable::new(content);
    let slice = slice_for_range(content, &line_offsets, version_range);
    let literal_target = dep
        .version_literal()
        .unwrap_or_else(|| version_req.as_str());
    if !literal_span_matches(slice, literal_target) {
        // `version_range` no longer slices to the declared literal text (e.g. a Maven
        // `${property}` or a Gradle DSL variable/alias) — writing a TextEdit there would
        // corrupt the manifest instead of fixing it. Mirrors the guard
        // `collect_update_all_edits` already applies on the bulk-edit path. Compares
        // against `dep.version_literal()` rather than `version_req` when the ecosystem
        // provides one (see that method's doc) — an ecosystem that synthesizes its
        // requirement from a bare literal (e.g. `deps-swift`) would otherwise always fail
        // this guard even though `version_range` correctly spans the literal.
        return actions;
    }

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
    // `versions.deprecations` is cache-derived, not a fresh registry call.
    let replacement_action = build_replacement_action(
        dep,
        uri,
        version_range,
        versions,
        content,
        &line_offsets,
        formatter,
    );

    let registry_versions = registry.get_versions(dep.name()).await.ok();

    // A fix target that the registry reports as yanked is dropped entirely rather than
    // offered — the surviving diagnostics carry the finding either way, and there is no
    // comparator here to bound a search for an alternative target. On a registry outage
    // (`registry_versions` is `None`) there is nothing to check a yank flag against, so
    // both actions pass through unfiltered — the pre-existing vuln-fix behavior, now
    // shared by the unsat fix too.
    let is_yanked_target = |version_native: &str| {
        registry_versions.as_ref().is_some_and(|versions_list| {
            versions_list
                .iter()
                .find(|v| v.version_string() == version_native)
                .is_some_and(|v| v.removal_status().blocks_resolution())
        })
    };
    let fix = fix.filter(|f| !is_yanked_target(&f.version_native));
    let unsat_fix = unsat_fix.filter(|f| !is_yanked_target(&f.version_native));

    // Yank-filtering both actions before this collision check (not after) matters: PyPI's
    // `truncate_release_to_match` can map a yanked version and a live one to identical
    // rewritten text, and checking collision first would drop the unsat action for a text
    // match against a vuln fix that the yank filter above was about to drop anyway,
    // leaving neither action behind.
    let unsat_fix = unsat_fix.filter(|u| {
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

    // De-duplicates every REFACTOR action's formatted edit text against the declared
    // literal text, both fix actions' edits (if present), and every REFACTOR action already
    // emitted below, so no two actions in the response — nor a REFACTOR action and a fix
    // action above — ever carry a byte-identical `WorkspaceEdit`. Seeding with the
    // declared literal text subsumes the former N1 guard (an item whose formatted text
    // equals the declared text is a no-op); checking formatted text rather than raw
    // version also subsumes the former `item.version == fix_version_native` check, since
    // `format_version_replacing` is deterministic in its inputs. Whitespace-insensitive,
    // matching every other no-op guard in this crate (see `strip_whitespace`). Seeded with
    // `literal_target` (not `version_req`) for the same reason the guard above compares
    // against it: for an ecosystem synthesizing its requirement from a bare literal (e.g.
    // `deps-swift`), `version_req` never equals the formatted edit text even when the edit
    // genuinely is a no-op (`.exact("2.61.0")` declares `version_req` `"=2.61.0"`, but the
    // manifest text — and any freshly-formatted "update to 2.61.0" text — is `"2.61.0"`).
    let mut emitted_texts: HashSet<String> = HashSet::new();
    emitted_texts.insert(strip_whitespace(literal_target));
    if let Some(fix_text) = fix_new_text {
        emitted_texts.insert(fix_text);
    }
    if let Some(unsat_text) = unsat_new_text {
        emitted_texts.insert(unsat_text);
    }

    let mut latest_refactor_idx = None;
    if let Some(registry_versions) = &registry_versions {
        let display_items = prepare_version_display_items(registry_versions, dep.name());
        for item in display_items {
            if !is_safe_version_string(&item.version) {
                warn_rejected_value(
                    "is_safe_version_string",
                    "update-to-version refactor code action",
                    &item.version,
                );
                continue;
            }
            let new_text = formatter.format_version_replacing(&item.version, version_req.as_str());

            if !emitted_texts.insert(strip_whitespace(&new_text)) {
                continue;
            }

            let edits = single_file_edit(uri, version_range, new_text);

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
                // Resolved once below, for every producer at once.
                is_preferred: None,
                ..Default::default()
            });
        }
    }

    // Single post-pass resolving `isPreferred`: exactly one action, in priority order
    // vuln fix -> unsat fix -> latest REFACTOR item. Runs unconditionally on every path
    // through this function that can reach here, including the registry-outage path
    // (`registry_versions.is_none()`), so an outage never drops `isPreferred` from an
    // already-built fix action.
    if let Some(i) = vuln_idx.or(unsat_idx).or(latest_refactor_idx) {
        actions[i].is_preferred = Some(true);
    }

    actions
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lsp_helpers::test_support::*;
    use crate::lsp_helpers::*;
    use crate::{Dependency, PackageName, VersionReq};
    use std::any::Any;
    use std::collections::HashMap;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_generate_code_actions_combines_advisories_sharing_the_highest_fix() {
        use crate::osv::{Advisory, DependencyVulnerabilities, UpgradeStatus, VulnSeverity};
        use std::collections::HashMap;

        let (dep, version_range, content) = vulnerable_dep("1.0.0");
        let parse_result = MockParseResult {
            deps: vec![dep],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let mut vulnerabilities = crate::osv::VulnerabilityMap::new();
        vulnerabilities.insert(
            "pkg".to_string(),
            ScanOutcome::Vulnerable(DependencyVulnerabilities {
                advisories: vec![
                    std::sync::Arc::new(Advisory {
                        id: "A1".to_string(),
                        modified: "2023-01-01T00:00:00Z".to_string(),
                        summary: None,
                        aliases: vec![],
                        severity: VulnSeverity::High,
                        cvss_vector: None,
                        fixed_versions: vec!["1.1.0".to_string()],
                        url: String::new(),
                    }),
                    std::sync::Arc::new(Advisory {
                        id: "A2".to_string(),
                        modified: "2023-01-01T00:00:00Z".to_string(),
                        summary: None,
                        aliases: vec![],
                        severity: VulnSeverity::Critical,
                        cvss_vector: None,
                        fixed_versions: vec!["1.2.0".to_string()],
                        url: String::new(),
                    }),
                ],
                total_known: 2,
                upgrade_status: UpgradeStatus::NotChecked,
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
            &MockFormatter,
        )
        .await;

        let titles = quickfix_titles(&actions);
        assert_eq!(titles, vec!["Update to 1.2.0 (fixes A2 +1 more)"]);
        assert_eq!(actions[0].kind, Some(CodeActionKind::QUICKFIX));
        assert_eq!(actions[0].is_preferred, Some(true));
        // The full id list still travels in `data` for the diagnostics
        // binding, even though the title only names the first one.
        assert_eq!(
            actions[0].data,
            Some(serde_json::json!({
                "diagnostic_codes": ["A2", "A1"],
                "diagnostic_range": version_range,
            }))
        );
    }

    #[tokio::test]
    async fn test_generate_code_actions_fix_target_is_not_inflated_by_a_subtracted_advisory() {
        // Critic S1 counterexample: A1 is fixed at a high version (3.0.0) but
        // phase B reports it still applies at the checked candidate, so it is
        // excluded from the claim. A2 is fixed at a much lower version
        // (1.2.0) and is claimed. The recommended target must be 1.2.0 — the
        // version that clears what is actually claimed — not 3.0.0, which
        // would push the user across an unnecessary major-version boundary
        // for a fix A1 that version does not even resolve.
        use crate::osv::{Advisory, DependencyVulnerabilities, UpgradeStatus, VulnSeverity};
        use std::collections::HashMap;

        let (dep, version_range, content) = vulnerable_dep("1.0.0");
        let parse_result = MockParseResult {
            deps: vec![dep],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let mut vulnerabilities = crate::osv::VulnerabilityMap::new();
        vulnerabilities.insert(
            "pkg".to_string(),
            ScanOutcome::Vulnerable(DependencyVulnerabilities {
                advisories: vec![
                    std::sync::Arc::new(Advisory {
                        id: "A1".to_string(),
                        modified: "2023-01-01T00:00:00Z".to_string(),
                        summary: None,
                        aliases: vec![],
                        severity: VulnSeverity::High,
                        cvss_vector: None,
                        fixed_versions: vec!["3.0.0".to_string()],
                        url: String::new(),
                    }),
                    std::sync::Arc::new(Advisory {
                        id: "A2".to_string(),
                        modified: "2023-01-01T00:00:00Z".to_string(),
                        summary: None,
                        aliases: vec![],
                        severity: VulnSeverity::Medium,
                        cvss_vector: None,
                        fixed_versions: vec!["1.2.0".to_string()],
                        url: String::new(),
                    }),
                ],
                total_known: 2,
                upgrade_status: UpgradeStatus::CandidateVulnerable {
                    version: "3.0.0".to_string(),
                    advisory_ids: vec!["A1".to_string()],
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
            &MockFormatter,
        )
        .await;

        let titles = quickfix_titles(&actions);
        assert_eq!(titles, vec!["Update to 1.2.0 (fixes A2)"]);
    }

    #[tokio::test]
    async fn test_generate_code_actions_drops_yanked_fix_target() {
        use crate::osv::{Advisory, DependencyVulnerabilities, UpgradeStatus, VulnSeverity};
        use std::collections::HashMap;

        let (dep, version_range, content) = vulnerable_dep("1.0.0");
        let parse_result = MockParseResult {
            deps: vec![dep],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let mut vulnerabilities = crate::osv::VulnerabilityMap::new();
        vulnerabilities.insert(
            "pkg".to_string(),
            ScanOutcome::Vulnerable(DependencyVulnerabilities {
                advisories: vec![std::sync::Arc::new(Advisory {
                    id: "A1".to_string(),
                    modified: "2023-01-01T00:00:00Z".to_string(),
                    summary: None,
                    aliases: vec![],
                    severity: VulnSeverity::High,
                    cvss_vector: None,
                    fixed_versions: vec!["2.0.0".to_string()],
                    url: String::new(),
                })],
                total_known: 1,
                upgrade_status: UpgradeStatus::NotChecked,
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
            &MockFormatter,
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
        use crate::osv::{Advisory, DependencyVulnerabilities, UpgradeStatus, VulnSeverity};
        use std::collections::HashMap;

        // Manifest already declares exactly the fixed version.
        let (dep, version_range, content) = vulnerable_dep("1.2.0");
        let parse_result = MockParseResult {
            deps: vec![dep],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let mut vulnerabilities = crate::osv::VulnerabilityMap::new();
        vulnerabilities.insert(
            "pkg".to_string(),
            ScanOutcome::Vulnerable(DependencyVulnerabilities {
                advisories: vec![std::sync::Arc::new(Advisory {
                    id: "A1".to_string(),
                    modified: "2023-01-01T00:00:00Z".to_string(),
                    summary: None,
                    aliases: vec![],
                    severity: VulnSeverity::High,
                    cvss_vector: None,
                    fixed_versions: vec!["1.2.0".to_string()],
                    url: String::new(),
                })],
                total_known: 1,
                upgrade_status: UpgradeStatus::NotChecked,
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
            &IdentityFormatter,
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
        use crate::osv::{Advisory, DependencyVulnerabilities, UpgradeStatus, VulnSeverity};
        use std::collections::HashMap;

        let (dep, version_range, content) = vulnerable_dep("^1.2.0");
        let parse_result = MockParseResult {
            deps: vec![dep],
            uri: crate::test_util::test_uri("/test/pubspec.yaml"),
        };

        let mut vulnerabilities = crate::osv::VulnerabilityMap::new();
        vulnerabilities.insert(
            "pkg".to_string(),
            ScanOutcome::Vulnerable(DependencyVulnerabilities {
                advisories: vec![std::sync::Arc::new(Advisory {
                    id: "A1".to_string(),
                    modified: "2023-01-01T00:00:00Z".to_string(),
                    summary: None,
                    aliases: vec![],
                    severity: VulnSeverity::High,
                    cvss_vector: None,
                    fixed_versions: vec!["1.2.0".to_string()],
                    url: String::new(),
                })],
                total_known: 1,
                upgrade_status: UpgradeStatus::NotChecked,
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
        // REFACTOR loop's own no-op guard from `build_vulnerability_fix_action`'s
        // separate N1 guard (the two prior "no_op" tests above only exercise the latter,
        // since `MockRegistry` returns no versions and the REFACTOR loop body never
        // runs). The registry lists the already-declared version among the top-5
        // display items — the common case per `prepare_version_display_items`, not an
        // edge case — plus one genuinely newer version.
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
            &IdentityFormatter,
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
            &IdentityFormatter,
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
        use crate::osv::{Advisory, DependencyVulnerabilities, UpgradeStatus, VulnSeverity};
        use std::collections::HashMap;

        let (dep, version_range, content) = vulnerable_dep("1.0.0");
        let parse_result = MockParseResult {
            deps: vec![dep],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let mut vulnerabilities = crate::osv::VulnerabilityMap::new();
        vulnerabilities.insert(
            "pkg".to_string(),
            ScanOutcome::Vulnerable(DependencyVulnerabilities {
                advisories: vec![std::sync::Arc::new(Advisory {
                    id: "A1".to_string(),
                    modified: "2023-01-01T00:00:00Z".to_string(),
                    summary: None,
                    aliases: vec![],
                    severity: VulnSeverity::High,
                    cvss_vector: None,
                    fixed_versions: vec!["1.2.0\", \"evil\": \"true".to_string()],
                    url: String::new(),
                })],
                total_known: 1,
                upgrade_status: UpgradeStatus::NotChecked,
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
            &IdentityFormatter,
        )
        .await;

        assert!(
            quickfix_titles(&actions).is_empty(),
            "an unsafe fix version must never produce a vulnerability-fix quickfix"
        );
    }

    #[tokio::test]
    async fn test_generate_code_actions_vulnerability_fix_not_offered_on_patched_duplicate_occurrence()
     {
        // #394 S2 (critic addendum, security-relevant): the vulnerability
        // quickfix *mutates the manifest*, so offering it on the wrong
        // occurrence of a duplicated name is worse than a cosmetic bug.
        // `log4j-core` appears twice with different pins — one vulnerable,
        // one already patched. The quickfix must appear only at the
        // vulnerable occurrence's position, never at the patched one's,
        // regardless of which occurrence's OSV result happened to be
        // inserted into the shared map last.
        use crate::osv::{Advisory, DependencyVulnerabilities, UpgradeStatus, VulnSeverity};
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
            ),
            name_range: Range::new(Position::new(0, name_start), Position::new(0, name_end)),
        };
        let patched_dep = MockDep {
            name: pkg("log4j-core"),
            version_req: VersionReq::new("=2.17.1"),
            version_range: Range::new(
                Position::new(1, version_start),
                Position::new(1, version_start + "=2.17.1".len() as u32),
            ),
            name_range: Range::new(Position::new(1, name_start), Position::new(1, name_end)),
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
            &IdentityFormatter,
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
                advisories: vec![std::sync::Arc::new(Advisory {
                    id: "GHSA-log4j".to_string(),
                    modified: "2023-01-01T00:00:00Z".to_string(),
                    summary: None,
                    aliases: vec![],
                    severity: VulnSeverity::Critical,
                    cvss_vector: None,
                    fixed_versions: vec!["2.17.1".to_string()],
                    url: String::new(),
                })],
                total_known: 1,
                upgrade_status: UpgradeStatus::NotChecked,
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
            &IdentityFormatter,
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
            &IdentityFormatter,
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
        use crate::osv::{Advisory, DependencyVulnerabilities, UpgradeStatus, VulnSeverity};
        use std::collections::HashMap;

        let (dep, version_range, content) = vulnerable_dep("==1.0.0");
        let parse_result = MockParseResult {
            deps: vec![dep],
            uri: crate::test_util::test_uri("/test/requirements.txt"),
        };

        let mut vulnerabilities = crate::osv::VulnerabilityMap::new();
        vulnerabilities.insert(
            "pkg".to_string(),
            ScanOutcome::Vulnerable(DependencyVulnerabilities {
                advisories: vec![std::sync::Arc::new(Advisory {
                    id: "A1".to_string(),
                    modified: "2023-01-01T00:00:00Z".to_string(),
                    summary: None,
                    aliases: vec![],
                    severity: VulnSeverity::High,
                    cvss_vector: None,
                    fixed_versions: vec!["1.2.5".to_string()],
                    url: String::new(),
                })],
                total_known: 1,
                upgrade_status: UpgradeStatus::NotChecked,
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
            let edit_text = &action.edit.as_ref().unwrap().changes.as_ref().unwrap()
                [parse_result.uri()][0]
                .new_text;
            for other in actions.iter() {
                if std::ptr::eq(action, other) {
                    continue;
                }
                let other_text = &other.edit.as_ref().unwrap().changes.as_ref().unwrap()
                    [parse_result.uri()][0]
                    .new_text;
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
        use crate::osv::{Advisory, DependencyVulnerabilities, UpgradeStatus, VulnSeverity};
        use std::collections::HashMap;

        let (dep, version_range, content) = vulnerable_dep("^1.0");
        let parse_result = MockParseResult {
            deps: vec![dep],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let mut vulnerabilities = crate::osv::VulnerabilityMap::new();
        vulnerabilities.insert(
            "pkg".to_string(),
            ScanOutcome::Vulnerable(DependencyVulnerabilities {
                advisories: vec![std::sync::Arc::new(Advisory {
                    id: "A1".to_string(),
                    modified: "2023-01-01T00:00:00Z".to_string(),
                    summary: None,
                    aliases: vec![],
                    severity: VulnSeverity::High,
                    cvss_vector: None,
                    fixed_versions: vec!["1.0.2".to_string()],
                    url: String::new(),
                })],
                total_known: 1,
                upgrade_status: UpgradeStatus::NotChecked,
            }),
        );

        let cached = HashMap::new();
        let mut resolved = HashMap::new();
        resolved.insert(pkg("pkg"), "1.0.1".to_string());
        let versions = VersionData::new(&cached, &resolved).with_vulnerabilities(&vulnerabilities);

        let actions = generate_code_actions(
            &parse_result,
            version_range.start,
            parse_result.uri(),
            versions,
            &content,
            &MockRegistry,
            &MockFormatter,
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
        use crate::osv::{Advisory, DependencyVulnerabilities, UpgradeStatus, VulnSeverity};
        use std::collections::HashMap;

        let (dep, version_range, content) = vulnerable_dep("1.0.0");
        let parse_result = MockParseResult {
            deps: vec![dep],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let mut vulnerabilities = crate::osv::VulnerabilityMap::new();
        vulnerabilities.insert(
            "pkg".to_string(),
            ScanOutcome::Vulnerable(DependencyVulnerabilities {
                advisories: vec![std::sync::Arc::new(Advisory {
                    id: "A1".to_string(),
                    modified: "2023-01-01T00:00:00Z".to_string(),
                    summary: None,
                    aliases: vec![],
                    severity: VulnSeverity::High,
                    cvss_vector: None,
                    fixed_versions: vec!["1.2.0".to_string()],
                    url: String::new(),
                })],
                total_known: 1,
                upgrade_status: UpgradeStatus::NotChecked,
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
            &MockFormatter,
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

    #[tokio::test]
    async fn test_generate_code_actions_coexistence_dedups_fix_version_and_demotes_preferred() {
        // Exercises the branch where the registry fetch succeeds *and*
        // returns the fix's own target version alongside other non-yanked
        // versions: the display item for that exact version must not be
        // duplicated, and no plain item may claim `is_preferred` once a fix
        // action exists.
        use crate::osv::{Advisory, DependencyVulnerabilities, UpgradeStatus, VulnSeverity};
        use std::collections::HashMap;

        let (dep, version_range, content) = vulnerable_dep("1.0.0");
        let parse_result = MockParseResult {
            deps: vec![dep],
            uri: crate::test_util::test_uri("/test/Cargo.toml"),
        };

        let mut vulnerabilities = crate::osv::VulnerabilityMap::new();
        vulnerabilities.insert(
            "pkg".to_string(),
            ScanOutcome::Vulnerable(DependencyVulnerabilities {
                advisories: vec![std::sync::Arc::new(Advisory {
                    id: "A1".to_string(),
                    modified: "2023-01-01T00:00:00Z".to_string(),
                    summary: None,
                    aliases: vec![],
                    severity: VulnSeverity::High,
                    cvss_vector: None,
                    fixed_versions: vec!["1.2.0".to_string()],
                    url: String::new(),
                })],
                total_known: 1,
                upgrade_status: UpgradeStatus::NotChecked,
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
            &MockFormatter,
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
        // Critic C1 / review "Important": the most common production path — no
        // vulnerability, no unsatisfiable requirement, just a satisfiable
        // dependency with newer versions available — must still mark the
        // `item.is_latest` REFACTOR action as the editor's preferred quickfix.
        // This moved from a construction-site expression to the shared
        // `is_preferred` post-pass indexed by `latest_refactor_idx`; a wrong
        // index or a broken `.or()` chain would silently strip `isPreferred`
        // from every ordinary "update to latest" action across all 11
        // ecosystems with a fully green suite otherwise.
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
            &MockFormatter,
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

    #[tokio::test]
    async fn test_generate_code_actions_fix_uses_ecosystem_format_version_replacing_override() {
        // Critic S3: `format_version_replacing` is overridden in exactly one
        // place workspace-wide (`deps-pypi`); no test anywhere proved the
        // vulnerability-fix action's `TextEdit` actually goes through such
        // an override rather than the default delegation to
        // `format_version_for_text_edit` — the same bug class the original
        // #216 critique caught (a guard/edit comparing the wrong string,
        // silently bypassed per-ecosystem).
        use crate::osv::{Advisory, DependencyVulnerabilities, UpgradeStatus, VulnSeverity};
        use std::collections::HashMap;

        let (dep, version_range, content) = vulnerable_dep("==1.0.0");
        let uri = crate::test_util::test_uri("/test/requirements.txt");
        let parse_result = MockParseResult {
            deps: vec![dep],
            uri: uri.clone(),
        };

        let mut vulnerabilities = crate::osv::VulnerabilityMap::new();
        vulnerabilities.insert(
            "pkg".to_string(),
            ScanOutcome::Vulnerable(DependencyVulnerabilities {
                advisories: vec![std::sync::Arc::new(Advisory {
                    id: "A1".to_string(),
                    modified: "2023-01-01T00:00:00Z".to_string(),
                    summary: None,
                    aliases: vec![],
                    severity: VulnSeverity::High,
                    cvss_vector: None,
                    fixed_versions: vec!["1.0.2".to_string()],
                    url: String::new(),
                })],
                total_known: 1,
                upgrade_status: UpgradeStatus::NotChecked,
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
            .and_then(|c| c.get(&uri))
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

        impl Dependency for CaDep {
            fn name(&self) -> &PackageName {
                &self.name
            }
            fn name_range(&self) -> Range {
                Range::default()
            }
            fn version_requirement(&self) -> Option<&VersionReq> {
                self.version_req.as_ref()
            }
            fn version_range(&self) -> Option<Range> {
                self.version_range
            }
            fn source(&self) -> crate::parser::DependencySource {
                crate::parser::DependencySource::Registry
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        struct CaParseResult {
            deps: Vec<CaDep>,
            uri: Uri,
        }

        impl ParseResult for CaParseResult {
            fn dependencies(&self) -> Vec<&dyn Dependency> {
                self.deps.iter().map(|d| d as &dyn Dependency).collect()
            }
            fn workspace_root(&self) -> Option<&std::path::Path> {
                None
            }
            fn uri(&self) -> &Uri {
                &self.uri
            }
            fn as_any(&self) -> &dyn Any {
                self
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

        impl Dependency for CaLiteralDep {
            fn name(&self) -> &PackageName {
                &self.name
            }
            fn name_range(&self) -> Range {
                Range::default()
            }
            fn version_requirement(&self) -> Option<&VersionReq> {
                self.version_req.as_ref()
            }
            fn version_range(&self) -> Option<Range> {
                self.version_range
            }
            fn source(&self) -> crate::parser::DependencySource {
                crate::parser::DependencySource::Registry
            }
            fn version_literal(&self) -> Option<&str> {
                self.version_literal.as_deref()
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        struct CaLiteralParseResult {
            deps: Vec<CaLiteralDep>,
            uri: Uri,
        }

        impl ParseResult for CaLiteralParseResult {
            fn dependencies(&self) -> Vec<&dyn Dependency> {
                self.deps.iter().map(|d| d as &dyn Dependency).collect()
            }
            fn workspace_root(&self) -> Option<&std::path::Path> {
                None
            }
            fn uri(&self) -> &Uri {
                &self.uri
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        struct CaVersion {
            version: String,
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
                        version: "2.0.0".to_string(),
                        yanked: false,
                    }) as Box<dyn crate::Version>])
                })
            }

            fn get_latest_matching<'a>(
                &'a self,
                _name: &'a PackageName,
                _req: &'a VersionReq,
            ) -> crate::ecosystem::BoxFuture<
                'a,
                crate::error::Result<Option<Box<dyn crate::Version>>>,
            > {
                Box::pin(async move { Ok(None) })
            }

            fn search<'a>(
                &'a self,
                _query: &'a str,
                _limit: usize,
            ) -> crate::ecosystem::BoxFuture<'a, crate::error::Result<Vec<Box<dyn crate::Metadata>>>>
            {
                Box::pin(async move { Ok(Vec::new()) })
            }

            fn as_any(&self) -> &dyn Any {
                self
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
                &MockFormatter,
            )
            .await;

            assert!(actions.is_empty());
        }

        #[tokio::test]
        async fn test_guard_rejects_span_even_with_a_pending_vulnerability_fix() {
            // Critic S2: the guard must gate the vulnerability-fix quickfix
            // too, not just the plain "update version" action — a future
            // refactor moving `build_vulnerability_fix_action` above the
            // guard would reintroduce manifest corruption on a rejected
            // span (e.g. a Maven `${property}` reference) at P0 severity.
            // Every other test in this module uses an empty `VersionData`,
            // which would pass even if the guard only gated the plain
            // action; this one carries a real OSV hit so a regression that
            // reorders the two checks fails here.
            use crate::osv::{Advisory, DependencyVulnerabilities, UpgradeStatus, VulnSeverity};

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
                "serde".to_string(),
                ScanOutcome::Vulnerable(DependencyVulnerabilities {
                    advisories: vec![std::sync::Arc::new(Advisory {
                        id: "A1".to_string(),
                        modified: "2023-01-01T00:00:00Z".to_string(),
                        summary: None,
                        aliases: vec![],
                        severity: VulnSeverity::High,
                        cvss_vector: None,
                        fixed_versions: vec!["2.0.0".to_string()],
                        url: String::new(),
                    })],
                    total_known: 1,
                    upgrade_status: UpgradeStatus::NotChecked,
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
                &MockFormatter,
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
                &MockFormatter,
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
                &MockFormatter,
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
                &MockFormatter,
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
                &MockFormatter,
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

        /// Same exact-match `compile_requirement` as [`ExactMatchFormatter`], but
        /// `format_version_replacing` always returns a fixed text that stays
        /// unsatisfiable against any `available` list not literally containing it —
        /// simulating a pypi/gradle-style override that preserves operator style
        /// into a still-broken range (plan §1.2.5 / critic M4).
        struct NonFixingFormatter;

        impl EcosystemFormatter for NonFixingFormatter {
            fn format_version_for_text_edit(&self, version: &str) -> String {
                version.to_string()
            }
            fn package_url(&self, name: &PackageName) -> String {
                format!("https://example.com/{name}")
            }
            fn format_version_replacing(&self, _version: &str, _current: &str) -> String {
                "still-bad".to_string()
            }
            fn compile_requirement(
                &self,
                requirement: &VersionReq,
            ) -> Option<Box<dyn RequirementMatcher>> {
                Some(Box::new(ExactMatcher(requirement.as_str().to_string())))
            }
        }

        /// Same exact-match `compile_requirement` as [`ExactMatchFormatter`], but
        /// `format_version_replacing` always returns the same fixed text regardless of
        /// its input — mirroring PyPI's `truncate_release_to_match`, which can map
        /// distinct registry versions to byte-identical rewritten text (M7 / plan
        /// §1.4). Used to construct a vuln-fix target and an unsat-fix target that are
        /// two different, independently-yankable versions whose formatted edits
        /// nonetheless collide.
        struct CollidingTextFormatter;

        impl EcosystemFormatter for CollidingTextFormatter {
            fn format_version_for_text_edit(&self, version: &str) -> String {
                version.to_string()
            }
            fn package_url(&self, name: &PackageName) -> String {
                format!("https://example.com/{name}")
            }
            fn format_version_replacing(&self, _version: &str, _current: &str) -> String {
                "9.9.9".to_string()
            }
            fn compile_requirement(
                &self,
                requirement: &VersionReq,
            ) -> Option<Box<dyn RequirementMatcher>> {
                Some(Box::new(ExactMatcher(requirement.as_str().to_string())))
            }
        }

        /// Same exact-match `compile_requirement` as [`ExactMatchFormatter`], but with a
        /// non-identity `normalize_package_name`, for the M1 lookup-fallback test.
        struct NormalizingExactFormatter;

        impl EcosystemFormatter for NormalizingExactFormatter {
            fn format_version_for_text_edit(&self, version: &str) -> String {
                version.to_string()
            }
            fn package_url(&self, name: &PackageName) -> String {
                format!("https://example.com/{name}")
            }
            fn normalize_package_name(&self, name: &PackageName) -> String {
                format!("normalized-{name}")
            }
            fn compile_requirement(
                &self,
                requirement: &VersionReq,
            ) -> Option<Box<dyn RequirementMatcher>> {
                Some(Box::new(ExactMatcher(requirement.as_str().to_string())))
            }
        }

        struct UnsatDep {
            name: PackageName,
            version_req: VersionReq,
            version_range: Range,
            source: crate::parser::DependencySource,
        }

        impl Dependency for UnsatDep {
            fn name(&self) -> &PackageName {
                &self.name
            }
            fn name_range(&self) -> Range {
                Range::default()
            }
            fn version_requirement(&self) -> Option<&VersionReq> {
                Some(&self.version_req)
            }
            fn version_range(&self) -> Option<Range> {
                Some(self.version_range)
            }
            fn source(&self) -> crate::parser::DependencySource {
                self.source.clone()
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        /// `MockParseResult` only stores `MockDep`s; wraps a single `UnsatDep` instead.
        struct UnsatParseResult {
            dep: UnsatDep,
            uri: Uri,
        }

        impl ParseResult for UnsatParseResult {
            fn dependencies(&self) -> Vec<&dyn Dependency> {
                vec![&self.dep]
            }
            fn workspace_root(&self) -> Option<&std::path::Path> {
                None
            }
            fn uri(&self) -> &Uri {
                &self.uri
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        fn cached_versions_keyed(
            key: &str,
            latest: &str,
            available: &[&str],
        ) -> HashMap<PackageName, PackageVersions> {
            let mut m = HashMap::new();
            m.insert(
                pkg(key),
                PackageVersions {
                    latest: latest.to_string(),
                    available: Arc::from(
                        available.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
                    ),
                    yanked: Arc::from(Vec::new()),
                    published_at: None,
                },
            );
            m
        }

        fn cached_versions(
            latest: &str,
            available: &[&str],
        ) -> HashMap<PackageName, PackageVersions> {
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
            let dep = UnsatDep {
                name: pkg("pkg"),
                version_req: VersionReq::new("1.0.0"),
                version_range: Range::new(Position::new(0, 0), Position::new(0, 5)),
                source: crate::parser::DependencySource::Path {
                    path: "../local".into(),
                },
            };
            let pr = UnsatParseResult {
                dep,
                uri: crate::test_util::test_uri("/test/Cargo.toml"),
            };

            let cached = cached_versions("9.9.9", &["9.9.9"]);
            let resolved = HashMap::new();
            let versions = VersionData::new(&cached, &resolved);

            let actions = generate_code_actions(
                &pr,
                Position::new(0, 0),
                pr.uri(),
                versions,
                content,
                &MockRegistry,
                &ExactMatchFormatter,
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
        async fn test_unsat_fix_resolves_cache_entry_via_raw_name_fallback() {
            // Critic M1: mirrors the diagnostic's `.get(normalized).or_else(|| .get(raw))`
            // lookup — an ecosystem whose `normalize_package_name` is not the identity
            // must still resolve a cache entry keyed by the raw declared name.
            let (dep, version_range, content) = vulnerable_dep("1.0.0");
            let parse_result = MockParseResult {
                deps: vec![dep],
                uri: crate::test_util::test_uri("/test/Cargo.toml"),
            };

            // Keyed by the raw name "pkg", not "normalized-pkg".
            let cached = cached_versions_keyed("pkg", "9.9.9", &["9.9.9"]);
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
            use crate::osv::{Advisory, DependencyVulnerabilities, UpgradeStatus, VulnSeverity};

            let (dep, version_range, content) = vulnerable_dep("1.0.0");
            let parse_result = MockParseResult {
                deps: vec![dep],
                uri: crate::test_util::test_uri("/test/Cargo.toml"),
            };

            let mut vulnerabilities = crate::osv::VulnerabilityMap::new();
            vulnerabilities.insert(
                "pkg".to_string(),
                ScanOutcome::Vulnerable(DependencyVulnerabilities {
                    advisories: vec![std::sync::Arc::new(Advisory {
                        id: "A1".to_string(),
                        modified: "2023-01-01T00:00:00Z".to_string(),
                        summary: None,
                        aliases: vec![],
                        severity: VulnSeverity::High,
                        cvss_vector: None,
                        fixed_versions: vec!["5.5.5".to_string()],
                        url: String::new(),
                    })],
                    total_known: 1,
                    upgrade_status: UpgradeStatus::NotChecked,
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
            use crate::osv::{Advisory, DependencyVulnerabilities, UpgradeStatus, VulnSeverity};

            let (dep, version_range, content) = vulnerable_dep("1.0.0");
            let parse_result = MockParseResult {
                deps: vec![dep],
                uri: crate::test_util::test_uri("/test/Cargo.toml"),
            };

            let mut vulnerabilities = crate::osv::VulnerabilityMap::new();
            vulnerabilities.insert(
                "pkg".to_string(),
                ScanOutcome::Vulnerable(DependencyVulnerabilities {
                    advisories: vec![std::sync::Arc::new(Advisory {
                        id: "A1".to_string(),
                        modified: "2023-01-01T00:00:00Z".to_string(),
                        summary: None,
                        aliases: vec![],
                        severity: VulnSeverity::High,
                        cvss_vector: None,
                        // Same target as the unsat fix's cached `latest` below.
                        fixed_versions: vec!["9.9.9".to_string()],
                        url: String::new(),
                    })],
                    total_known: 1,
                    upgrade_status: UpgradeStatus::NotChecked,
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
            // Critic M7: the vuln fix targets a *yanked* version and the unsat fix
            // targets a *different, live* version, but both format to identical
            // text (mirroring PyPI's `truncate_release_to_match`). Yank-filtering
            // both actions before the collision check must run first: it drops the
            // yanked vuln fix and leaves the live unsat fix as the sole survivor.
            // The wrong order (collision-first) would drop the unsat action for
            // "colliding" with a vuln fix that the yank filter was about to drop
            // anyway, leaving the user with neither action.
            use crate::osv::{Advisory, DependencyVulnerabilities, UpgradeStatus, VulnSeverity};

            let (dep, version_range, content) = vulnerable_dep("1.0.0");
            let parse_result = MockParseResult {
                deps: vec![dep],
                uri: crate::test_util::test_uri("/test/Cargo.toml"),
            };

            let mut vulnerabilities = crate::osv::VulnerabilityMap::new();
            vulnerabilities.insert(
                "pkg".to_string(),
                ScanOutcome::Vulnerable(DependencyVulnerabilities {
                    advisories: vec![std::sync::Arc::new(Advisory {
                        id: "A1".to_string(),
                        modified: "2023-01-01T00:00:00Z".to_string(),
                        summary: None,
                        aliases: vec![],
                        severity: VulnSeverity::High,
                        cvss_vector: None,
                        // Different raw version than the unsat fix's cached
                        // `latest` ("9.9.9") below, but `CollidingTextFormatter`
                        // rewrites both to the same "9.9.9" text.
                        fixed_versions: vec!["9.9.5".to_string()],
                        url: String::new(),
                    })],
                    total_known: 1,
                    upgrade_status: UpgradeStatus::NotChecked,
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
    }
}
