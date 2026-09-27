//! LSP-only completion/code-action/hover support for GitLab CI (issues #634/#640/#643/#1137/
//! #1138, spec §8.2): SHA-pin quickfixes and completion-operator constants.
//!
//! This entire module is compiled only under the `lsp-responses` feature (gated once on the
//! `mod lsp;` declaration in `ecosystem.rs`) — `deps-cli` never needs to link against
//! `tower_lsp_server`'s completion types, so nothing here should leak into the non-gated part
//! of the crate. The names other code needs are re-imported explicitly right after that
//! declaration (not a glob — `clippy::wildcard_imports` denies it), so the crate's test
//! module (which globs `use super::*;`) keeps referencing them unqualified, unchanged from
//! before the move.

use std::time::Duration;
use tower_lsp_server::ls_types::{CodeAction, CodeActionKind, Position, TextEdit, WorkspaceEdit};

use deps_core::PackageName;
use deps_core::lsp_helpers::truncate_for_diagnostic;

use super::{
    GitlabCiDependency, GitlabCiFormatter, GitlabCiRegistry, MAX_DIAGNOSTIC_VALUE_CHARS,
    MUTABLE_REF_PIN_DIAGNOSTIC_CODE, PackageNaming, PackageRendering, ParseResultTrait,
    ShaPinQuickfixKind, Url, sha_pin_quickfix_kind,
};

/// Leading version-constraint operators stripped from a completion prefix before matching
/// it against registry versions. Empty: a component/include ref is a bare tag/branch/SHA,
/// with no comparison/caret/tilde operator syntax (#1137).
pub(super) const VERSION_OPERATOR_CHARS: &[char] = &[];

/// Implements `deps-core`'s shared "pin to commit SHA" resolution (issue #1138) for the
/// `ShaPinQuickfixKind::StaticTagIndex` path only: a `component:` include's
/// `Latest`/`Partial` pin (`ShaPinQuickfixKind::DynamicComponentPin`) needs a live fetch
/// and a [`GitlabCiRegistry`] handle this trait has no room for, so it stays local to
/// `build_dynamic_component_pin_action` — the one genuinely GitLab-specific quickfix arm
/// this ecosystem keeps outside the shared abstraction.
impl deps_core::lsp_helpers::ShaPinning for GitlabCiFormatter {
    fn resolve_static_sha_pin(
        &self,
        dep: &dyn deps_core::Dependency,
    ) -> Option<deps_core::lsp_helpers::ResolvedShaPin> {
        let gl_dep = dep.as_any().downcast_ref::<GitlabCiDependency>()?;
        if !matches!(
            sha_pin_quickfix_kind(dep, gl_dep, self),
            Some(ShaPinQuickfixKind::StaticTagIndex)
        ) {
            return None;
        }
        let version_range = gl_dep.version_range?;
        let tag = gl_dep
            .version_req
            .as_ref()
            .map(deps_core::VersionReq::as_str)?;
        let new_text = self.sha_pin_replacement_for(gl_dep.kind.endpoint(), &gl_dep.name, tag)?;
        Some(deps_core::lsp_helpers::ResolvedShaPin {
            display_name: gl_dep.name.as_str().to_string(),
            version_range,
            replacement: new_text,
        })
    }
}

/// Bound on [`GitlabCiRegistry::resolve_component_pin`]'s FR-007 hover-time resolution
/// (H1, #466 review) — mirrors `deps_core::lsp_helpers::hover`'s `HOVER_FALLBACK_TIMEOUT`
/// precedent for a live-fetch fallback invoked from hover generation: a failure or timeout
/// here degrades gracefully to no `**Resolved**` line, never aborting the rest of the hover.
pub(super) const COMPONENT_PIN_RESOLUTION_TIMEOUT: Duration = Duration::from_secs(5);

/// Builds the "Pin `{name}` to commit SHA" quickfix (issue #634) for the `PinStyle::Tag`
/// dependency at `position`, if `GitlabCiFormatter::sha_pin_replacement_for` resolves its
/// current tag/release name against the shared `TagIndex`.
///
/// Returns `None` (no destructive/no-op edit) when the dependency at `position` is not
/// `PinStyle::Tag`, has no `version_range`, or the `TagIndex` lookup misses (cache miss —
/// e.g. the document was opened before the registry fetch completed).
///
/// Deliberately **not** widened to `is_registry_confirmed_tag`'s `PinStyle::Branch` case
/// the way `mutable_ref_pin_diagnostics` is, mirroring
/// `deps_github_actions::ecosystem::build_sha_pin_action`'s identical pre-#551 guard: a
/// `PinStyle::Branch` include can share its ref/pin text with an unrelated tag of the same
/// name, and GitLab's own ref resolution for that collision is undocumented — an
/// *automated edit* that silently pins to the tag's commit could pin to a different commit
/// than the ref actually resolves to at run time. A diagnostic's advisory text carries no
/// such risk, but this destructive edit keeps the stricter guard.
///
/// Delegates entirely to [`deps_core::lsp_helpers::build_sha_pin_action`] (issue #1138) via
/// [`GitlabCiFormatter`]'s [`deps_core::lsp_helpers::ShaPinning`] impl, which carries this
/// guard (restricted to `ShaPinQuickfixKind::StaticTagIndex`).
pub(super) fn build_sha_pin_action(
    parse_result: &dyn ParseResultTrait,
    position: Position,
    uri: &Url,
    formatter: &GitlabCiFormatter,
) -> Option<CodeAction> {
    deps_core::lsp_helpers::build_sha_pin_action(
        parse_result,
        position,
        uri,
        formatter,
        MUTABLE_REF_PIN_DIAGNOSTIC_CODE,
    )
}

/// Builds the "Pin `{name}` to commit SHA" quickfix (validation follow-up C2/S2) for a
/// `component:` include pinned via `PinStyle::Latest`/`PinStyle::Partial` at `position`.
///
/// Unlike [`build_sha_pin_action`] (a synchronous `TagIndex` lookup only, since a
/// `PinStyle::Tag` pin's own text already names the version), neither `Latest` nor
/// `Partial` names a concrete version by itself — resolving one needs the FR-007 priority
/// ladder run against the project's published releases, exactly the live fetch
/// `generate_hover`'s `**Resolved**` splice already drives for the same pin forms. Bounded
/// by [`COMPONENT_PIN_RESOLUTION_TIMEOUT`], mirroring that call site's identical
/// degrade-to-nothing-on-timeout discipline: a failure or timeout here withholds the
/// quickfix rather than blocking the rest of `generate_code_actions`.
///
/// Returns `None` when the dependency at `position` is not a `component:` include pinned
/// via `Latest`/`Partial`, has no registered route, or the live resolution misses/fails/
/// times out. The eligibility guard (kind/pin/route) is `sha_pin_quickfix_kind` (issue
/// #643) — the single source of truth this and `mutable_ref_pin_diagnostics`'s message
/// both consult, so they cannot independently drift about whether a quickfix exists.
pub(super) async fn build_dynamic_component_pin_action(
    parse_result: &dyn ParseResultTrait,
    position: Position,
    uri: &Url,
    formatter: &GitlabCiFormatter,
    registry: &GitlabCiRegistry,
) -> Option<CodeAction> {
    // M2 (#640): the same `formatter.is_position_on_dependency` lookup
    // `build_sha_pin_action` uses, rather than a bare `version_range` check — a
    // consistency unification, not a behavior change for this pin shape.
    let dep = parse_result
        .dependencies()
        .into_iter()
        .find(|d| formatter.is_position_on_dependency(*d, position.into()))?;
    let gl_dep = dep.as_any().downcast_ref::<GitlabCiDependency>()?;
    if !matches!(
        sha_pin_quickfix_kind(dep, gl_dep, formatter),
        Some(ShaPinQuickfixKind::DynamicComponentPin)
    ) {
        return None;
    }
    let pin = gl_dep.pin.as_ref()?;
    let version_range = gl_dep.version_range?;
    let raw = gl_dep
        .version_req
        .as_ref()
        .map(deps_core::VersionReq::as_str)?;
    let deps_core::parser::DependencySource::AlternateRegistry { index, .. } = dep.source() else {
        return None;
    };
    let route = registry.routes().get(&index).map(|r| r.clone())?;

    let outcome = tokio::time::timeout(
        COMPONENT_PIN_RESOLUTION_TIMEOUT,
        registry.resolve_component_pin(dep.name(), &route, pin, raw),
    )
    .await;
    let resolved = match outcome {
        Ok(Ok(Some(resolved))) => resolved,
        Ok(Ok(None)) => return None,
        Ok(Err(error)) => {
            tracing::warn!(package = %dep.name().for_tracing(), %error, "C2 component pin quickfix resolution failed");
            return None;
        }
        Err(_) => {
            tracing::warn!(package = %dep.name().for_tracing(), "C2 component pin quickfix resolution timed out");
            return None;
        }
    };

    let changes = deps_core::single_file_edit(uri, version_range, resolved.sha?.to_string());

    Some(CodeAction {
        title: format!(
            "Pin {} to commit SHA",
            deps_core::lsp_helpers::redact_name_for_diagnostic(&gl_dep.name)
        ),
        kind: Some(CodeActionKind::QUICKFIX),
        edit: Some(WorkspaceEdit {
            changes: Some(changes),
            ..Default::default()
        }),
        data: Some(serde_json::json!({
            "diagnostic_codes": [MUTABLE_REF_PIN_DIAGNOSTIC_CODE],
            "diagnostic_range": tower_lsp_server::ls_types::Range::from(version_range),
        })),
        ..Default::default()
    })
}

/// Builds one [`TextEdit`] per mutable-ref dependency in `parse_result` resolvable to a
/// commit SHA from already-in-hand data (issue #640) — the bulk counterpart of
/// [`build_sha_pin_action`] and [`build_dynamic_component_pin_action`]'s per-position
/// quickfixes, dispatched through the same `sha_pin_quickfix_kind` classification so all
/// three can never disagree about which dependencies are eligible.
///
/// Deliberately performs **no network fetch**: a code lens is push-based and must never
/// itself trigger one. A `DynamicComponentPin` dependency is instead resolved by
/// reconstituting its release list from `versions.cached` (the caller's already-fetched
/// version data) paired with `formatter`'s `TagIndex` for each release's SHA, then handed
/// to the unmodified [`crate::component::resolve_component_pin`] ladder — see
/// [`reconstitute_component_releases`] for why an unresolved-SHA entry is kept as a
/// placeholder rather than dropped.
pub(super) fn collect_pin_all_to_sha_edits(
    parse_result: &dyn ParseResultTrait,
    formatter: &GitlabCiFormatter,
    versions: deps_core::VersionData<'_>,
) -> Vec<TextEdit> {
    let edits: Vec<TextEdit> = parse_result
        .dependencies()
        .into_iter()
        .filter_map(|dep| bulk_sha_pin_text_edit_for(dep, formatter, versions))
        .collect();
    deps_core::lsp_helpers::dedup_overlapping_edits(edits, "collect_pin_all_to_sha_edits")
}

/// Builds the bulk edit for one dependency, dispatching on `sha_pin_quickfix_kind`
/// exactly like [`build_sha_pin_action`]/[`build_dynamic_component_pin_action`] do for a
/// single position. `None` when the dependency is not diagnosable via either path, has no
/// `version_range`, or (`DynamicComponentPin` only) the ladder can't resolve it from the
/// caller's already-fetched `versions`.
pub(super) fn bulk_sha_pin_text_edit_for(
    dep: &dyn deps_core::Dependency,
    formatter: &GitlabCiFormatter,
    versions: deps_core::VersionData<'_>,
) -> Option<TextEdit> {
    let gl_dep = dep.as_any().downcast_ref::<GitlabCiDependency>()?;
    let version_range = gl_dep.version_range?;

    match sha_pin_quickfix_kind(dep, gl_dep, formatter)? {
        ShaPinQuickfixKind::StaticTagIndex => {
            deps_core::lsp_helpers::sha_pin_text_edit(formatter, dep)
        }
        ShaPinQuickfixKind::DynamicComponentPin => {
            let pin = gl_dep.pin.as_ref()?;
            let raw = gl_dep
                .version_req
                .as_ref()
                .map(deps_core::VersionReq::as_str)?;
            let releases =
                reconstitute_component_releases(dep.name(), gl_dep, formatter, versions)?;
            let resolved = crate::component::resolve_component_pin(pin, raw, &releases)?;
            // The reconstituted list may carry `sha: None` placeholders (see
            // `reconstitute_component_releases`); only a winner with a known SHA is safe
            // to splice into a `TextEdit` — `CommitSha` already guarantees full-SHA shape,
            // so no separate `is_full_sha` recheck is needed here.
            let sha = resolved.sha?;
            Some(TextEdit {
                range: version_range.into(),
                new_text: sha.to_string(),
            })
        }
    }
}

/// Reconstitutes the release list [`crate::component::resolve_component_pin`]'s ladder
/// needs for `name`, from `versions.cached` (already-fetched, never re-fetched here) and
/// `formatter`'s `TagIndex` (for each release's SHA) — the cache-only alternative to
/// `crate::registry::GitlabCiRegistry::resolve_component_pin`'s live fetch, since a bulk
/// code lens must never itself trigger one.
///
/// **Never drops an entry whose SHA is unknown in the `TagIndex`** — keeps it with
/// `sha: None` instead. This is not a per-release SHA gap guard (the registry's own
/// `releases_to_versions` already drops any release with no valid SHA before it ever
/// reaches `versions.cached`); it guards a *lifetime* mismatch between two caches populated
/// at different times: `TagIndex` is capacity-bounded and evictable, while `versions.cached`
/// is not, so a `tag_to_sha` miss for a release still present in `versions.cached` is a live
/// possibility, not a hypothetical one. Dropping such an entry would silently shift what
/// `Latest`/`Partial` resolves to onto a *different* release — and since
/// `resolve_component_pin`'s `max_by` returns the **last** maximum on a tie (two releases
/// normalizing to the same semver), preserving `versions.cached`'s exact order (itself the
/// registry's own fetch/sort order) matters as much as preserving every entry. The
/// `sha: None` placeholder is unreachable by the ladder's only SHA-matching arm
/// (`PinStyle::Sha`, which `sha_pin_quickfix_kind` never routes to this path) — the
/// caller still verifies the *winning* release actually has a SHA (`resolved.sha?`) before
/// splicing it into a `TextEdit`.
pub(super) fn reconstitute_component_releases(
    name: &PackageName,
    gl_dep: &GitlabCiDependency,
    formatter: &GitlabCiFormatter,
    versions: deps_core::VersionData<'_>,
) -> Option<Vec<crate::types::GitlabCiVersion>> {
    let normalized_name = formatter.normalize_package_name(name);
    let available = versions
        .cached
        .get(normalized_name.as_str())
        .or_else(|| versions.cached.get(name))
        .map(|v| &v.available)?;
    let endpoint = gl_dep.kind.endpoint();
    let tag_index = formatter.tag_index.get(&(endpoint, gl_dep.name.clone()));

    Some(
        available
            .iter()
            .map(|version| {
                let sha = tag_index
                    .as_ref()
                    .and_then(|index| index.tag_to_sha.get(version.as_str()).cloned());
                let prerelease =
                    semver::Version::parse(deps_core::github::normalize_tag(version.as_str()))
                        .is_ok_and(|parsed| !parsed.pre.is_empty());
                crate::types::GitlabCiVersion {
                    version: version.clone(),
                    sha,
                    prerelease,
                    published_at: None,
                }
            })
            .collect(),
    )
}

/// Inserts a `**Project**: [name](url)` line immediately after the hover heading, for a
/// `component:` include whose heading link is suppressed (spec §8.2).
///
/// The link *label* half is capped at `MAX_DIAGNOSTIC_VALUE_CHARS` — `url` is built
/// from `gl_dep.project_path`, a manifest-controlled string `is_valid_gitlab_coordinate`
/// bounds only by charset, not length or segment count (#1310 critic S3 — `deps-core`'s
/// `git_ref.rs::splice_resolved_line` fixed the same class for `resolved_tag`). Only the
/// *label* is capped, matching `HoverMarkdown::push_link`'s label-capped/
/// destination-unbounded contract. The label is truncated only, not escaped — safe
/// because `is_valid_gitlab_coordinate`'s charset gate (`is_valid_path_segment`,
/// `[A-Za-z0-9._-]`-only per segment) already runs before this function's only caller
/// builds `url`, so no Markdown-special character can reach it in the first place.
// `pos`/`insert_at` come from `find("\n\n")`, an ASCII token, so both are always char
// boundaries.
#[allow(clippy::string_slice)]
pub(super) fn splice_project_line(markdown: &str, url: &str) -> String {
    let label = truncate_for_diagnostic(url, MAX_DIAGNOSTIC_VALUE_CHARS);
    let line = format!("**Project**: [{label}]({url})\n\n");
    if let Some(pos) = markdown.find("\n\n") {
        let insert_at = pos + 2;
        let mut out = String::with_capacity(markdown.len() + line.len());
        out.push_str(&markdown[..insert_at]);
        out.push_str(&line);
        out.push_str(&markdown[insert_at..]);
        out
    } else {
        format!("{markdown}\n\n{line}")
    }
}
