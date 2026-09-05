//! GitHub Actions ecosystem implementation for deps-lsp.

use dashmap::DashMap;
use std::any::Any;
use std::sync::Arc;
use tower_lsp_server::ls_types::{
    CodeAction, CodeActionKind, Diagnostic, Hover, HoverContents, NumberOrString, Position,
    TextEdit, Uri, WorkspaceEdit,
};

use deps_core::{
    Ecosystem, PackageName, ParseResult as ParseResultTrait, Registry, Result,
    completion::Completions,
    lsp_helpers::{EcosystemFormatter, PackageRendering, markdown_code_span},
};

use crate::MUTABLE_REF_PIN_DIAGNOSTIC_CODE;

use crate::formatter::GithubActionsFormatter;
use crate::registry::{GithubActionsRegistry, TagIndex};
use crate::types::{GithubActionsDependency, PinStyle};

/// Whether `gha_dep`'s ref is diagnosable as a tag — either because
/// [`crate::parser::classify_uses_value`] already classified it as [`PinStyle::Tag`] from
/// its text shape, or because `tag_index`'s live `/tags` fetch confirms the ref is a
/// literal member of the repository's tag list even though it doesn't *look*
/// tag-shaped (issue #551, e.g. `taiki-e/install-action@cargo-deny`).
///
/// [`crate::parser::is_tag_shaped`] is a pure, registry-blind heuristic — it cannot tell
/// a literal tool-name tag from a genuinely moving branch, since both fail the same
/// "starts with `v`/a digit" test. Once the registry has actually answered (`tag_index`
/// carries this repository's entry), the real answer is available and takes priority
/// over the static guess; before that (`tag_index` cache miss), a [`PinStyle::Branch`]
/// step stays classified as the "honest unknown" — exactly the pre-#551 behavior — until
/// a fetch resolves it one way or the other.
fn is_registry_confirmed_tag(
    gha_dep: &GithubActionsDependency,
    tag_index: &DashMap<PackageName, Arc<TagIndex>>,
) -> bool {
    match &gha_dep.pin {
        Some(PinStyle::Tag) => true,
        Some(PinStyle::Branch) => gha_dep
            .version_req
            .as_ref()
            .map(deps_core::VersionReq::as_str)
            .is_some_and(|ref_text| {
                tag_index
                    .get(&gha_dep.name)
                    .is_some_and(|index| index.tag_to_sha.contains_key(ref_text))
            }),
        Some(PinStyle::Sha { .. }) | None => false,
    }
}

/// GitHub Actions ecosystem implementation.
///
/// Provides LSP functionality for `.github/workflows/*.yml`/`*.yaml` files, including:
/// - Dependency parsing with position tracking (see `parser` module docs for the pin
///   contract)
/// - Version information from the GitHub tags API
/// - Inlay hints, hover, completions, diagnostics, and code actions/lenses via the
///   shared `deps_core::lsp_helpers` machinery
pub struct GithubActionsEcosystem {
    registry: Arc<GithubActionsRegistry>,
    formatter: GithubActionsFormatter,
}

impl GithubActionsEcosystem {
    /// Creates a new GitHub Actions ecosystem with the given HTTP cache.
    #[must_use]
    pub fn new(cache: Arc<deps_core::HttpCache>) -> Self {
        let registry = Arc::new(GithubActionsRegistry::new(cache));
        let formatter = GithubActionsFormatter::new(registry.tag_index());
        Self {
            registry,
            formatter,
        }
    }
}

impl deps_core::ecosystem::private::Sealed for GithubActionsEcosystem {}

impl Ecosystem for GithubActionsEcosystem {
    fn id(&self) -> &'static str {
        "github-actions"
    }

    fn display_name(&self) -> &'static str {
        "GitHub Actions"
    }

    fn manifest_filenames(&self) -> &[&'static str] {
        &[]
    }

    /// GHA declares no fixed filename or extension — it is routed solely by directory
    /// path (D1): a `.github/workflows/*.yml`/`*.yaml` file, regardless of how many
    /// ancestor directories precede `.github`.
    fn manifest_directory_patterns(&self) -> &[(&'static str, &'static str)] {
        &[
            (".github/workflows", ".yml"),
            (".github/workflows", ".yaml"),
        ]
    }

    fn lockfile_filenames(&self) -> &[&'static str] {
        &[]
    }

    fn parse_manifest<'a>(
        &'a self,
        content: &'a str,
        uri: &'a Uri,
    ) -> deps_core::ecosystem::BoxFuture<'a, Result<Box<dyn ParseResultTrait>>> {
        Box::pin(async move {
            let result = crate::parser::parse_workflow_yaml(content, uri)?;
            Ok(Box::new(result) as Box<dyn ParseResultTrait>)
        })
    }

    fn registry(&self) -> Arc<dyn Registry> {
        self.registry.clone() as Arc<dyn Registry>
    }

    fn formatter(&self) -> &dyn EcosystemFormatter {
        &self.formatter
    }

    fn generate_completions<'a>(
        &'a self,
        parse_result: &'a dyn ParseResultTrait,
        position: Position,
        content: &'a str,
        freshness: deps_core::FreshnessSettings,
    ) -> deps_core::ecosystem::BoxFuture<'a, Completions> {
        Box::pin(async move {
            use deps_core::completion::{CompletionContext, detect_completion_context};

            match detect_completion_context(parse_result, position, content) {
                CompletionContext::Version {
                    package_name,
                    prefix,
                } => deps_core::completion::complete_versions_generic(
                    self.registry.as_ref(),
                    &package_name,
                    &prefix,
                    &[],
                    freshness,
                )
                .await
                .into(),
                CompletionContext::PackageName { .. }
                | CompletionContext::Feature { .. }
                | CompletionContext::None => Completions::default(),
            }
        })
    }

    /// Appends the mutable-ref-pin diagnostic (issue #473) to the shared default's
    /// output, one per `PinStyle::Tag` step — an additive, independent signal from the
    /// outdated-version diagnostic the shared default already computes (spec 031
    /// NFR-004: this override never changes that behavior, only appends to it).
    ///
    /// Gated on `severities.mutable_ref_pin_enabled` (spec 031 FR-009, corrected during
    /// implementation review): `severities.mutable_ref_pin` alone cannot silence this
    /// diagnostic, since `DiagnosticSeverity` has no suppression value.
    fn generate_diagnostics<'a>(
        &'a self,
        parse_result: &'a dyn ParseResultTrait,
        versions: deps_core::VersionData<'a>,
        uri: &'a Uri,
        freshness: deps_core::FreshnessSettings,
        severities: deps_core::lsp_helpers::DiagnosticSeverities,
    ) -> deps_core::ecosystem::BoxFuture<'a, Vec<Diagnostic>> {
        Box::pin(async move {
            let mut diagnostics = deps_core::lsp_helpers::generate_diagnostics_from_cache(
                parse_result,
                versions,
                self.formatter(),
                uri,
                freshness,
                severities,
                deps_core::PublishTime::now(),
            );
            if severities.mutable_ref_pin_enabled {
                diagnostics.extend(mutable_ref_pin_diagnostics(
                    parse_result,
                    severities.mutable_ref_pin,
                    &self.formatter.tag_index,
                ));
            }
            diagnostics
        })
    }

    /// Appends the "Pin to commit SHA" quickfix (issue #473) to the shared default's
    /// output when the position's dependency is a `PinStyle::Tag` step with a resolvable
    /// `TagIndex` entry.
    fn generate_code_actions<'a>(
        &'a self,
        parse_result: &'a dyn ParseResultTrait,
        position: Position,
        uri: &'a Uri,
        versions: deps_core::VersionData<'a>,
        content: &'a str,
    ) -> deps_core::ecosystem::BoxFuture<'a, Vec<CodeAction>> {
        Box::pin(async move {
            let registry = self.registry();
            let mut actions = deps_core::lsp_helpers::generate_code_actions(
                parse_result,
                position,
                uri,
                versions,
                content,
                registry.as_ref(),
                self.formatter(),
            )
            .await;
            actions.extend(build_sha_pin_action(
                parse_result,
                position,
                uri,
                &self.formatter,
            ));
            actions
        })
    }

    /// One documented NFR-004 divergence (S3): appends a `**Resolved**` line naming the
    /// tag a SHA pin's commit actually corresponds to, per
    /// [`crate::registry::GithubActionsRegistry`]'s [`crate::registry::TagIndex`].
    ///
    /// Necessary, not merely additive: `versions.resolved` (the shared helper's
    /// `**Current**` source) is keyed by package name and is unconditionally empty for
    /// GHA (no lockfile provider), so it cannot express per-occurrence resolution when
    /// the same action is pinned at two different SHAs in one workflow. The splice also
    /// makes a stale or hand-edited `# vX.Y.Z` comment visible for free (M4): the tag
    /// shown here comes from `TagIndex.sha_to_tag`, not from trusting the comment text.
    ///
    /// Scoped to [`PinStyle::Sha`] only — the SHA is the one pin form GitHub itself does
    /// not render as a readable version, so it is the only form where naming the tag it
    /// resolves to adds information; a `PinStyle::Tag` pin already shows the tag text
    /// directly. Guarded on `dep.version_range().is_some()` (N3): a non-resolvable
    /// dependency (a reusable-workflow call, `./local`, `docker://…`) still matches the
    /// shared helper's own hover-target predicate and must not have a `**Resolved**` line
    /// spliced onto it.
    fn generate_hover<'a>(
        &'a self,
        parse_result: &'a dyn ParseResultTrait,
        position: Position,
        versions: deps_core::VersionData<'a>,
        freshness: deps_core::FreshnessSettings,
    ) -> deps_core::ecosystem::BoxFuture<'a, Option<Hover>> {
        Box::pin(async move {
            let registry = self.registry.clone();
            let base_hover = deps_core::lsp_generate_hover(
                parse_result,
                position,
                versions,
                registry.as_ref(),
                self.formatter(),
                freshness,
                deps_core::PublishTime::now(),
            )
            .await;
            let mut hover = base_hover?;

            let dep = parse_result.dependencies().into_iter().find(|d| {
                deps_core::position_in_range(position, d.name_range())
                    || d.version_range()
                        .is_some_and(|r| deps_core::position_in_range(position, r))
            });
            let Some(dep) = dep else {
                return Some(hover);
            };
            if dep.version_range().is_none() {
                return Some(hover);
            }
            let Some(gha_dep) = dep.as_any().downcast_ref::<GithubActionsDependency>() else {
                return Some(hover);
            };

            // #501 gap (tester finding), widened by critic finding C1 (#550): the shared
            // `has_offline_actionable_data`/footer gate in `deps_core::generate_hover` only
            // sees `VersionData` and cannot see `formatter.tag_index` — GHA's "Pin to commit
            // SHA" quickfix (`build_sha_pin_action`, wired into `generate_code_actions`
            // above) is driven entirely by that separately-populated index, independent of
            // `versions`. So a `PinStyle::Tag` step with a warm `TagIndex` entry has a real
            // `Cmd+.` action even when the shared gate suppressed the footer for lack of any
            // `VersionData` signal — originally observed offline (#501), but #550's
            // empty-live-fetch footer gate reintroduced the identical gap *online* too: a
            // bare-major tag (`@v4`) whose repo tags entirely fail the full-semver filter
            // (`tags_to_versions`) makes `available_versions == Some([])`, which the shared
            // gate now (correctly, for the general case) treats as "nothing to update" — but
            // `populate_tag_index` still indexes bare-major tags (`v4 -> sha`) independent of
            // that filter, so the quickfix is still genuinely available. Restores the footer
            // post-hoc in both modes using the shared `CMD_DOT_FOOTER` constant (not a
            // hand-copied literal) so the two can never drift apart; the
            // `!content.value.contains(CMD_DOT_FOOTER)` guard below makes this idempotent
            // when the shared gate already rendered it, so dropping the online/offline split
            // cannot double-append.
            // `is_plain_scalar` mirrors `build_sha_pin_action`'s own guard (FR-010, spec
            // 031): for a quoted `uses:` scalar, `version_range` sits inside the quotes, so
            // the quickfix withholds itself rather than corrupt the value — the footer must
            // not advertise an action that was never actually offered.
            //
            // Deliberately keyed on the raw `PinStyle::Tag` check, not
            // `is_registry_confirmed_tag` (#551 plan): this footer only ever advertises
            // `build_sha_pin_action`, which itself stays on the stricter, pre-#551 guard
            // (see that function's doc comment) — the footer must never promise an action
            // that withholds itself.
            if gha_dep.pin == Some(PinStyle::Tag)
                && gha_dep.is_plain_scalar
                && let Some(tag) = gha_dep
                    .version_req
                    .as_ref()
                    .map(deps_core::VersionReq::as_str)
                && self
                    .formatter
                    .sha_pin_replacement_for(&gha_dep.name, tag)
                    .is_some()
                && let HoverContents::Markup(content) = &mut hover.contents
                && !content
                    .value
                    .contains(deps_core::lsp_helpers::CMD_DOT_FOOTER)
            {
                content
                    .value
                    .push_str(deps_core::lsp_helpers::CMD_DOT_FOOTER);
            }

            let Some(PinStyle::Sha { comment_tag }) = &gha_dep.pin else {
                return Some(hover);
            };

            let sha = match comment_tag {
                // Whitespace-token split, not `split_once(" # ")`: the parser's
                // comment-tag rule (B3) only requires the `#` to be *preceded* by
                // whitespace, so `<sha>  # v4.2.0` (two spaces) or `<sha>\t# v4.2.0`
                // are both valid literals that a single-space exact match would miss
                // (critic M2).
                Some(_) => gha_dep
                    .version_literal
                    .as_deref()
                    .and_then(|lit| lit.split_whitespace().next()),
                None => gha_dep
                    .version_req
                    .as_ref()
                    .map(deps_core::VersionReq::as_str),
            };
            let Some(sha) = sha else {
                return Some(hover);
            };

            let Some(resolved_tag) = self
                .formatter
                .tag_index
                .get(dep.name())
                .and_then(|index| index.sha_to_tag.get(sha).cloned())
            else {
                return Some(hover);
            };

            if let HoverContents::Markup(content) = &mut hover.contents {
                content.value = splice_resolved_line(&content.value, &resolved_tag, sha);
            }

            Some(hover)
        })
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    /// One [`TextEdit`] per `PinStyle::Tag` step in `parse_result` resolvable to a commit
    /// SHA via this ecosystem's own `TagIndex`-backed formatter (issue #633) — `versions`
    /// is unused: a GHA SHA pin's replacement comes entirely from the shared `TagIndex`,
    /// with no dependency on the caller's fetched version data.
    fn collect_pin_all_to_sha_edits(
        &self,
        parse_result: &dyn ParseResultTrait,
        _versions: deps_core::VersionData<'_>,
    ) -> Vec<TextEdit> {
        collect_pin_all_to_sha_edits(parse_result, &self.formatter)
    }

    fn pin_all_to_sha_noun(&self) -> deps_core::lsp_helpers::PinNoun {
        deps_core::lsp_helpers::PinNoun {
            singular: "action",
            plural: "actions",
        }
    }
}

/// Inserts a `**Resolved**: `tag` (`sha…`)` line immediately after the shared hover's
/// `**Current**`/`**Requirement**` line (whichever is present), falling back to append
/// only if neither anchor is found.
fn splice_resolved_line(markdown: &str, resolved_tag: &str, sha: &str) -> String {
    // `sha` is expected to be a validated, pure-ASCII full hex SHA by the time it
    // reaches here (`TagIndex` entries are filtered in `populate_tag_index`, security
    // S-3), so a byte slice is normally safe — `get(..7)` is a char-boundary-safe
    // belt-and-braces guard rather than a raw index (security S-4), falling back to
    // the whole string on anything unexpected instead of panicking.
    let short_sha = sha.get(..7).unwrap_or(sha);
    let line = format!(
        "**Resolved**: {} ({})\n\n",
        markdown_code_span(resolved_tag),
        markdown_code_span(&format!("{short_sha}…"))
    );

    for anchor in ["**Current**: ", "**Requirement**: "] {
        if let Some(pos) = markdown.find(anchor)
            && let Some(rel_end) = markdown[pos..].find("\n\n")
        {
            let insert_at = pos + rel_end + 2;
            let mut out = String::with_capacity(markdown.len() + line.len());
            out.push_str(&markdown[..insert_at]);
            out.push_str(&line);
            out.push_str(&markdown[insert_at..]);
            return out;
        }
    }
    format!("{markdown}{line}")
}

/// Builds one mutable-ref-pin [`Diagnostic`] (issue #473) per diagnosable-as-tag step in
/// `parse_result` — every `PinStyle::Tag` step, plus a `PinStyle::Branch` step
/// `tag_index` confirms is actually a real tag (issue #551, e.g.
/// `taiki-e/install-action@cargo-deny`: see [`is_registry_confirmed_tag`]).
/// `PinStyle::Sha` and a `PinStyle::Branch` `tag_index` cannot (yet) confirm produce no
/// diagnostic (FR-003).
/// Maximum character count of `mutable_ref_pin_diagnostics`' interpolated `name`/`tag`
/// values before truncation (security audit finding). Mirrors
/// `deps_core::lsp_helpers::diagnostics`' `MAX_BLOCKED_REGISTRY_MESSAGE_VALUE_CHARS`
/// precedent: nothing upstream caps a workflow file's `owner/repo` or ref text length, so
/// this is the last chokepoint before either renders inline in the editor, re-sent on
/// every `publishDiagnostics`.
const MAX_MUTABLE_REF_PIN_MESSAGE_VALUE_CHARS: usize = 128;

fn mutable_ref_pin_diagnostics(
    parse_result: &dyn ParseResultTrait,
    severity: tower_lsp_server::ls_types::DiagnosticSeverity,
    tag_index: &DashMap<PackageName, Arc<TagIndex>>,
) -> Vec<Diagnostic> {
    parse_result
        .dependencies()
        .into_iter()
        .filter_map(|dep| {
            let gha_dep = dep.as_any().downcast_ref::<GithubActionsDependency>()?;
            if !is_registry_confirmed_tag(gha_dep, tag_index) {
                return None;
            }
            let range = gha_dep.version_range?;
            let tag = gha_dep
                .version_req
                .as_ref()
                .map(deps_core::VersionReq::as_str)?;
            let name = deps_core::lsp_helpers::truncate_for_diagnostic(
                gha_dep.name.as_str(),
                MAX_MUTABLE_REF_PIN_MESSAGE_VALUE_CHARS,
            );
            let tag = deps_core::lsp_helpers::truncate_for_diagnostic(
                tag,
                MAX_MUTABLE_REF_PIN_MESSAGE_VALUE_CHARS,
            );
            // Critic finding C2 (#551): `build_sha_pin_action` deliberately stays
            // restricted to a statically-classified `PinStyle::Tag` (FR-005/plan §11 —
            // see that function's doc comment on the branch/tag name-collision risk), so
            // a registry-confirmed-but-`PinStyle::Branch` ref has no automated fix behind
            // `Cmd+.` here. The message must say so rather than imply one is a keystroke
            // away, matching every other resolvable-but-unactionable case in this
            // codebase (e.g. `deps_core`'s own "Registry lookup failed" wording never
            // promises a quickfix it can't offer).
            let message = if gha_dep.pin == Some(PinStyle::Tag) {
                format!(
                    "{name} is pinned to the mutable tag ref `{tag}`; pin to a full commit \
                     SHA to guard against tag mutation"
                )
            } else {
                format!(
                    "{name} is pinned to the mutable tag ref `{tag}`; pin to a full commit \
                     SHA to guard against tag mutation (manual edit — no automated fix \
                     available for this ref)"
                )
            };
            Some(Diagnostic {
                range,
                severity: Some(severity),
                message,
                code: Some(NumberOrString::String(
                    MUTABLE_REF_PIN_DIAGNOSTIC_CODE.into(),
                )),
                source: Some("deps-lsp".into()),
                ..Default::default()
            })
        })
        .collect()
}

/// Builds the "Pin `{name}` to commit SHA" quickfix (issue #473, US-002) for the
/// `PinStyle::Tag` dependency at `position`, if [`GithubActionsFormatter::sha_pin_replacement_for`]
/// resolves its current tag against the shared `TagIndex`.
///
/// Returns `None` (no destructive/no-op edit, FR-005) when the dependency at `position`
/// is not `PinStyle::Tag`, has no `version_range`, or the `TagIndex` lookup misses (cache
/// miss — e.g. the document was opened before the registry fetch completed).
///
/// Deliberately **not** widened to [`is_registry_confirmed_tag`]'s `PinStyle::Branch`
/// case the way [`mutable_ref_pin_diagnostics`] is (#551 plan): FR-005/plan §11 (see
/// `test_build_sha_pin_action_no_quickfix_for_branch_pin`) already forbids this
/// quickfix for a `PinStyle::Branch` step even when a same-named `TagIndex` entry
/// exists, since git permits a branch and a tag to share one name and GitHub's own
/// `uses:` ref resolution for that collision is undocumented — an *automated edit*
/// that silently pins to the tag's commit could pin to a different commit than the
/// ref actually resolves to at run time. A diagnostic's advisory text carries no such
/// risk (pinning to *some* SHA is safer than a moving ref either way), but this
/// destructive edit keeps the stricter, pre-#551 guard.
fn build_sha_pin_action(
    parse_result: &dyn ParseResultTrait,
    position: Position,
    uri: &Uri,
    formatter: &GithubActionsFormatter,
) -> Option<CodeAction> {
    // Same lookup convention every other deps-lsp code action goes through (critic S2) —
    // not a hand-rolled position check. The default (`version_range` only, GHA does not
    // override it) is exactly right here: the diagnostic and the edit both anchor on
    // `version_range`, never `name_range`.
    let dep = parse_result
        .dependencies()
        .into_iter()
        .find(|d| formatter.is_position_on_dependency(*d, position))?;

    let gha_dep = dep.as_any().downcast_ref::<GithubActionsDependency>()?;
    let text_edit = sha_pin_text_edit_for(dep, formatter)?;
    let diagnostic_range = text_edit.range;

    let mut changes = std::collections::HashMap::new();
    changes.insert(uri.clone(), vec![text_edit]);

    Some(CodeAction {
        title: format!("Pin {} to commit SHA", gha_dep.name),
        kind: Some(CodeActionKind::QUICKFIX),
        edit: Some(WorkspaceEdit {
            changes: Some(changes),
            ..Default::default()
        }),
        data: Some(serde_json::json!({
            "diagnostic_codes": [MUTABLE_REF_PIN_DIAGNOSTIC_CODE],
            "diagnostic_range": diagnostic_range,
        })),
        ..Default::default()
    })
}

/// Builds the `{sha} # {tag}` [`TextEdit`] for a single `PinStyle::Tag` step, shared by
/// [`build_sha_pin_action`] (wraps it into a per-position quickfix) and
/// [`collect_pin_all_to_sha_edits`] (the bulk "Pin all to SHA" code lens, issue #633).
///
/// `None` for anything but a plain-scalar `PinStyle::Tag` step with a resolvable
/// `TagIndex` entry — the same withholding guards `build_sha_pin_action`'s doc comment
/// describes (FR-010's quoted-scalar guard, and a `TagIndex` cache miss).
fn sha_pin_text_edit_for(
    dep: &dyn deps_core::Dependency,
    formatter: &GithubActionsFormatter,
) -> Option<TextEdit> {
    let gha_dep = dep.as_any().downcast_ref::<GithubActionsDependency>()?;
    if gha_dep.pin != Some(PinStyle::Tag) {
        return None;
    }
    // FR-010: for a quoted `uses:` scalar, `version_range` sits inside the quotes —
    // writing `{sha} # {tag}` there corrupts the value instead of adding a YAML comment
    // (security audit finding, spec 031 FR-010). Withhold rather than risk that edit.
    if !gha_dep.is_plain_scalar {
        return None;
    }
    // Security audit finding (issue #633): for a `uses:` step written in YAML flow
    // style (`{uses: actions/checkout@v4, with: {node: 20}}`), appending `# <tag>`
    // right after the ref comments out the rest of the flow collection, producing
    // invalid (unterminated) YAML instead of merely leaving the step unpinned.
    // Withhold rather than risk corrupting the workflow.
    if !gha_dep.is_last_on_line {
        return None;
    }
    let version_range = gha_dep.version_range?;
    let tag = gha_dep
        .version_req
        .as_ref()
        .map(deps_core::VersionReq::as_str)?;
    let new_text = formatter.sha_pin_replacement_for(&gha_dep.name, tag)?;
    Some(TextEdit {
        range: version_range,
        new_text,
    })
}

/// Builds one [`TextEdit`] per `PinStyle::Tag` step in `parse_result` resolvable to a
/// commit SHA via `formatter`'s `TagIndex` — the bulk counterpart to
/// [`build_sha_pin_action`]'s single-step quickfix (issue #633). A step with no
/// resolvable `TagIndex` entry (cache miss) is silently skipped, exactly like that
/// quickfix's own withholding behavior — never blocking on, or triggering, a fetch.
fn collect_pin_all_to_sha_edits(
    parse_result: &dyn ParseResultTrait,
    formatter: &GithubActionsFormatter,
) -> Vec<TextEdit> {
    let edits: Vec<TextEdit> = parse_result
        .dependencies()
        .into_iter()
        .filter_map(|dep| sha_pin_text_edit_for(dep, formatter))
        .collect();
    deps_core::lsp_helpers::dedup_overlapping_edits(edits, "collect_pin_all_to_sha_edits")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use tower_lsp_server::ls_types::DiagnosticSeverity;

    // --- issue #473: mutable-ref-pin diagnostic + "Pin to commit SHA" code action ---

    fn mutable_ref_pin_code() -> NumberOrString {
        NumberOrString::String(MUTABLE_REF_PIN_DIAGNOSTIC_CODE.into())
    }

    async fn diagnostics_for(content: &str) -> Vec<Diagnostic> {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = GithubActionsEcosystem::new(cache);
        let uri = deps_core::test_util::test_uri("/repo/.github/workflows/ci.yml");
        let parse_result = eco.parse_manifest(content, &uri).await.unwrap();
        let cached = HashMap::new();
        let resolved = HashMap::new();

        eco.generate_diagnostics(
            parse_result.as_ref(),
            deps_core::VersionData::new(&cached, &resolved),
            &uri,
            deps_core::FreshnessSettings::default(),
            deps_core::lsp_helpers::DiagnosticSeverities::default(),
        )
        .await
    }

    /// SC-003/SC-004: one fixture workflow mixing every `PinStyle` variant — exactly the
    /// `Tag` steps get the mutable-ref-pin diagnostic, and `Sha` steps (with or without a
    /// comment) get none, in the same document.
    #[tokio::test]
    async fn test_generate_diagnostics_fixture_covers_every_pin_style() {
        let content = format!(
            "steps:\n\
             \x20 - uses: actions/checkout@v4\n\
             \x20 - uses: actions/setup-node@{sha} # v4.0.0\n\
             \x20 - uses: actions/setup-node@{sha}\n\
             \x20 - uses: some-org/some-action@main\n",
            sha = "a".repeat(40)
        );
        let diagnostics = diagnostics_for(&content).await;
        let mutable_count = diagnostics
            .iter()
            .filter(|d| d.code == Some(mutable_ref_pin_code()))
            .count();
        assert_eq!(
            mutable_count, 1,
            "exactly the one Tag-pinned step must get the diagnostic: {diagnostics:?}"
        );
    }

    #[tokio::test]
    async fn test_generate_diagnostics_emits_mutable_ref_pin_for_tag_pin() {
        let diagnostics = diagnostics_for("steps:\n  - uses: actions/checkout@v4\n").await;
        let found = diagnostics
            .iter()
            .find(|d| d.code == Some(mutable_ref_pin_code()))
            .expect("expected a mutable-ref-pin diagnostic for a tag pin");
        assert_eq!(found.severity, Some(DiagnosticSeverity::HINT));
        assert!(found.message.contains("actions/checkout"));
    }

    /// Security audit finding (low): a huge ref text (attacker-controlled workflow file,
    /// no upstream length cap) must not render unbounded into the diagnostic message,
    /// re-sent on every `publishDiagnostics`.
    #[tokio::test]
    async fn test_generate_diagnostics_mutable_ref_pin_message_caps_long_tag() {
        let long_tag = format!("v{}", "1".repeat(10_000));
        let content = format!("steps:\n  - uses: actions/checkout@{long_tag}\n");
        let diagnostics = diagnostics_for(&content).await;

        let found = diagnostics
            .iter()
            .find(|d| d.code == Some(mutable_ref_pin_code()))
            .expect("expected a mutable-ref-pin diagnostic");
        assert!(
            found.message.len() < long_tag.len(),
            "a 10,000-char tag must not render in full inside the diagnostic message"
        );
        assert!(found.message.contains('…'));
    }

    #[tokio::test]
    async fn test_generate_diagnostics_no_mutable_ref_pin_for_sha_pin() {
        let diagnostics = diagnostics_for(&format!(
            "steps:\n  - uses: actions/checkout@{}\n",
            "a".repeat(40)
        ))
        .await;
        assert!(
            !diagnostics
                .iter()
                .any(|d| d.code == Some(mutable_ref_pin_code()))
        );
    }

    #[tokio::test]
    async fn test_generate_diagnostics_no_mutable_ref_pin_for_sha_with_comment_pin() {
        let diagnostics = diagnostics_for(&format!(
            "steps:\n  - uses: actions/checkout@{} # v4\n",
            "a".repeat(40)
        ))
        .await;
        assert!(
            !diagnostics
                .iter()
                .any(|d| d.code == Some(mutable_ref_pin_code()))
        );
    }

    #[tokio::test]
    async fn test_generate_diagnostics_no_mutable_ref_pin_for_branch_pin() {
        let diagnostics = diagnostics_for("steps:\n  - uses: some-org/some-action@main\n").await;
        assert!(
            !diagnostics
                .iter()
                .any(|d| d.code == Some(mutable_ref_pin_code()))
        );
    }

    /// Regression for #551: `taiki-e/install-action@cargo-deny` is a literal-named ref
    /// that parses as `PinStyle::Branch` (`is_tag_shaped` requires a leading `v`/digit)
    /// even though it's a real, resolvable git tag — the registry's own tags fetch is
    /// the only thing that can tell. Before any fetch has ever populated `TagIndex` for
    /// this repository (cold cache — the same state a fresh document open starts in),
    /// the mutable-ref-pin diagnostic must stay withheld: the "honest unknown" state is
    /// unchanged from before #551, since nothing has confirmed the ref one way or
    /// another yet.
    #[tokio::test]
    async fn test_generate_diagnostics_no_mutable_ref_pin_for_literal_tag_with_cold_tag_index() {
        let diagnostics =
            diagnostics_for("steps:\n  - uses: taiki-e/install-action@cargo-deny\n").await;
        assert!(
            !diagnostics
                .iter()
                .any(|d| d.code == Some(mutable_ref_pin_code())),
            "a literal-named ref with no TagIndex entry yet must stay the honest \
             unknown, not assumed a tag; got: {diagnostics:?}"
        );
    }

    /// Regression for #551: once a fetch has actually populated `TagIndex` for
    /// `taiki-e/install-action` — tag data mixing a literal tool-selector tag
    /// (`cargo-deny`, alongside its siblings `nextest`/`cross`/`wasm-pack` in the real
    /// repository) with a real `vN` release tag (`v2`) — `cargo-deny` must now be
    /// diagnosable: it's confirmed a real tag, not a moving branch, so the
    /// mutable-ref-pin hint applies (arguably more relevant here, since these ARE
    /// mutable reassignable tags). `v2` (statically `PinStyle::Tag` already, unaffected
    /// by #551) keeps getting its own diagnostic exactly as before.
    #[tokio::test]
    async fn test_generate_diagnostics_mutable_ref_pin_for_registry_confirmed_literal_tag() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = GithubActionsEcosystem::new(cache);
        let uri = deps_core::test_util::test_uri("/repo/.github/workflows/ci.yml");
        let content = "steps:\n\
             \x20 - uses: taiki-e/install-action@cargo-deny\n\
             \x20 - uses: taiki-e/install-action@v2\n";
        let parse_result = eco.parse_manifest(content, &uri).await.unwrap();

        let mut index = crate::registry::TagIndex::default();
        index
            .tag_to_sha
            .insert("cargo-deny".to_string(), "a".repeat(40));
        index
            .tag_to_sha
            .insert("nextest".to_string(), "b".repeat(40));
        index.tag_to_sha.insert("v2".to_string(), "c".repeat(40));
        eco.formatter.tag_index.insert(
            deps_core::PackageName::new("taiki-e/install-action"),
            Arc::new(index),
        );

        let cached = HashMap::new();
        let resolved = HashMap::new();
        let diagnostics = eco
            .generate_diagnostics(
                parse_result.as_ref(),
                deps_core::VersionData::new(&cached, &resolved),
                &uri,
                deps_core::FreshnessSettings::default(),
                deps_core::lsp_helpers::DiagnosticSeverities::default(),
            )
            .await;

        let mutable_ref_pin_messages: Vec<&str> = diagnostics
            .iter()
            .filter(|d| d.code == Some(mutable_ref_pin_code()))
            .map(|d| d.message.as_str())
            .collect();
        assert_eq!(
            mutable_ref_pin_messages.len(),
            2,
            "both the registry-confirmed literal tag and the statically-classified \
             tag must get the diagnostic; got: {diagnostics:?}"
        );
        let cargo_deny_message = *mutable_ref_pin_messages
            .iter()
            .find(|m| m.contains("cargo-deny"))
            .expect("expected a diagnostic naming the confirmed literal tag");
        let v2_message = *mutable_ref_pin_messages
            .iter()
            .find(|m| m.contains("`v2`"))
            .expect("expected a diagnostic naming the statically-classified tag");

        // Critic finding C2 (#551): `build_sha_pin_action` has no automated fix for the
        // registry-confirmed-but-`PinStyle::Branch` case (FR-005/plan §11), so its
        // message must say so — unlike the statically-classified `v2` tag, which does
        // have the "Pin to commit SHA" quickfix behind `Cmd+.`.
        assert!(
            cargo_deny_message.contains("no automated fix available"),
            "a registry-confirmed literal tag has no SHA-pin quickfix, so the message \
             must not imply one; got: {cargo_deny_message}"
        );
        assert!(
            !v2_message.contains("no automated fix available"),
            "a statically-classified tag DOES have the SHA-pin quickfix, so the message \
             must not claim otherwise; got: {v2_message}"
        );
    }

    /// US-003/FR-006: a step both stale and mutable gets both diagnostics, independently,
    /// with distinct codes — neither suppresses the other.
    #[tokio::test]
    async fn test_generate_diagnostics_mutable_and_outdated_coexist_with_distinct_codes() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = GithubActionsEcosystem::new(cache);
        let uri = deps_core::test_util::test_uri("/repo/.github/workflows/ci.yml");
        let content = "steps:\n  - uses: actions/checkout@v3\n";
        let parse_result = eco.parse_manifest(content, &uri).await.unwrap();

        let mut cached = HashMap::new();
        cached.insert(
            deps_core::PackageName::new("actions/checkout"),
            deps_core::PackageVersions {
                latest: "v4".into(),
                available: Arc::from(vec!["v4".into(), "v3".into()]),
                yanked: Arc::from(Vec::new()),
                published_at: None,
            },
        );
        let resolved = HashMap::new();

        let diagnostics = eco
            .generate_diagnostics(
                parse_result.as_ref(),
                deps_core::VersionData::new(&cached, &resolved),
                &uri,
                deps_core::FreshnessSettings::default(),
                deps_core::lsp_helpers::DiagnosticSeverities::default(),
            )
            .await;

        assert_eq!(
            diagnostics.len(),
            2,
            "expected both diagnostics: {diagnostics:?}"
        );
        assert!(
            diagnostics
                .iter()
                .any(|d| d.code == Some(mutable_ref_pin_code()))
        );
        assert!(
            diagnostics
                .iter()
                .any(|d| d.code != Some(mutable_ref_pin_code())
                    && d.message.contains("Newer version available"))
        );
    }

    #[tokio::test]
    async fn test_generate_diagnostics_mutable_ref_pin_uses_configured_severity() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = GithubActionsEcosystem::new(cache);
        let uri = deps_core::test_util::test_uri("/repo/.github/workflows/ci.yml");
        let content = "steps:\n  - uses: actions/checkout@v4\n";
        let parse_result = eco.parse_manifest(content, &uri).await.unwrap();
        let cached = HashMap::new();
        let resolved = HashMap::new();
        let severities = deps_core::lsp_helpers::DiagnosticSeverities {
            mutable_ref_pin: DiagnosticSeverity::ERROR,
            ..deps_core::lsp_helpers::DiagnosticSeverities::default()
        };

        let diagnostics = eco
            .generate_diagnostics(
                parse_result.as_ref(),
                deps_core::VersionData::new(&cached, &resolved),
                &uri,
                deps_core::FreshnessSettings::default(),
                severities,
            )
            .await;

        let found = diagnostics
            .iter()
            .find(|d| d.code == Some(mutable_ref_pin_code()))
            .expect("expected a mutable-ref-pin diagnostic");
        assert_eq!(found.severity, Some(DiagnosticSeverity::ERROR));
    }

    /// FR-009 (corrected): `mutable_ref_pin_enabled: false` must suppress the diagnostic
    /// entirely, since `mutable_ref_pin` severity alone has no way to.
    #[tokio::test]
    async fn test_generate_diagnostics_mutable_ref_pin_disabled_emits_nothing() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = GithubActionsEcosystem::new(cache);
        let uri = deps_core::test_util::test_uri("/repo/.github/workflows/ci.yml");
        let content = "steps:\n  - uses: actions/checkout@v4\n";
        let parse_result = eco.parse_manifest(content, &uri).await.unwrap();
        let cached = HashMap::new();
        let resolved = HashMap::new();
        let severities = deps_core::lsp_helpers::DiagnosticSeverities {
            mutable_ref_pin_enabled: false,
            ..deps_core::lsp_helpers::DiagnosticSeverities::default()
        };

        let diagnostics = eco
            .generate_diagnostics(
                parse_result.as_ref(),
                deps_core::VersionData::new(&cached, &resolved),
                &uri,
                deps_core::FreshnessSettings::default(),
                severities,
            )
            .await;

        assert!(
            !diagnostics
                .iter()
                .any(|d| d.code == Some(mutable_ref_pin_code())),
            "mutable_ref_pin_enabled: false must suppress the diagnostic entirely: {diagnostics:?}"
        );
    }

    /// Exercises `build_sha_pin_action` directly rather than through
    /// `GithubActionsEcosystem::generate_code_actions`: the shared default that override
    /// delegates to first drives a *live* registry fetch (to list "Update to X" actions),
    /// which would overwrite a hand-seeded `TagIndex` fixture with real GitHub data before
    /// this function ever runs.
    #[test]
    fn test_build_sha_pin_action_offers_quickfix_on_tag_index_hit() {
        let uri = deps_core::test_util::test_uri("/repo/.github/workflows/ci.yml");
        let content = "steps:\n  - uses: actions/checkout@v4\n";
        let parse_result = crate::parser::parse_workflow_yaml(content, &uri).unwrap();

        let formatter = GithubActionsFormatter {
            tag_index: Arc::new(dashmap::DashMap::new()),
        };
        let mut index = crate::registry::TagIndex::default();
        index.tag_to_sha.insert("v4".to_string(), "a".repeat(40));
        formatter.tag_index.insert(
            deps_core::PackageName::new("actions/checkout"),
            Arc::new(index),
        );

        let position = deps_core::ParseResult::dependencies(&parse_result)[0]
            .version_range()
            .unwrap()
            .start;

        let action = build_sha_pin_action(&parse_result, position, &uri, &formatter)
            .expect("expected a Pin-to-commit-SHA quickfix");
        assert!(action.title.contains("Pin") && action.title.contains("commit SHA"));
        let edit = action.edit.as_ref().unwrap();
        let text_edits = edit.changes.as_ref().unwrap().get(&uri).unwrap();
        assert_eq!(text_edits.len(), 1);
        assert_eq!(text_edits[0].new_text, format!("{} # v4", "a".repeat(40)));
    }

    /// Critic S2: the lookup now goes through the shared `is_position_on_dependency`
    /// convention (`version_range` only, GHA does not override it) rather than a
    /// hand-rolled check that also matched `name_range` — a cursor on the action *name*
    /// must not offer this quickfix, matching every other deps-lsp code action's UX.
    #[test]
    fn test_build_sha_pin_action_cursor_on_name_range_offers_nothing() {
        let uri = deps_core::test_util::test_uri("/repo/.github/workflows/ci.yml");
        let content = "steps:\n  - uses: actions/checkout@v4\n";
        let parse_result = crate::parser::parse_workflow_yaml(content, &uri).unwrap();

        let formatter = GithubActionsFormatter {
            tag_index: Arc::new(dashmap::DashMap::new()),
        };
        let mut index = crate::registry::TagIndex::default();
        index.tag_to_sha.insert("v4".to_string(), "a".repeat(40));
        formatter.tag_index.insert(
            deps_core::PackageName::new("actions/checkout"),
            Arc::new(index),
        );

        let position = deps_core::ParseResult::dependencies(&parse_result)[0]
            .name_range()
            .start;

        assert!(build_sha_pin_action(&parse_result, position, &uri, &formatter).is_none());
    }

    /// FR-005: a `TagIndex` cache miss must never offer a destructive/no-op edit.
    #[test]
    fn test_build_sha_pin_action_no_quickfix_on_tag_index_miss() {
        let uri = deps_core::test_util::test_uri("/repo/.github/workflows/ci.yml");
        let content = "steps:\n  - uses: actions/checkout@v4\n";
        let parse_result = crate::parser::parse_workflow_yaml(content, &uri).unwrap();

        let formatter = GithubActionsFormatter {
            tag_index: Arc::new(dashmap::DashMap::new()),
        };

        let position = deps_core::ParseResult::dependencies(&parse_result)[0]
            .version_range()
            .unwrap()
            .start;

        assert!(build_sha_pin_action(&parse_result, position, &uri, &formatter).is_none());
    }

    /// FR-005/plan §11: a `PinStyle::Branch` step must never get the SHA-pin quickfix,
    /// even if a `TagIndex` entry happens to exist for its literal ref text.
    #[test]
    fn test_build_sha_pin_action_no_quickfix_for_branch_pin() {
        let uri = deps_core::test_util::test_uri("/repo/.github/workflows/ci.yml");
        let content = "steps:\n  - uses: some-org/some-action@main\n";
        let parse_result = crate::parser::parse_workflow_yaml(content, &uri).unwrap();

        let formatter = GithubActionsFormatter {
            tag_index: Arc::new(dashmap::DashMap::new()),
        };
        let mut index = crate::registry::TagIndex::default();
        index.tag_to_sha.insert("main".to_string(), "a".repeat(40));
        formatter.tag_index.insert(
            deps_core::PackageName::new("some-org/some-action"),
            Arc::new(index),
        );

        let position = deps_core::ParseResult::dependencies(&parse_result)[0]
            .version_range()
            .unwrap()
            .start;

        assert!(build_sha_pin_action(&parse_result, position, &uri, &formatter).is_none());
    }

    /// FR-010 (security audit finding): a quoted `uses:` scalar must never get the
    /// SHA-pin quickfix, even on a `TagIndex` hit — writing `{sha} # {tag}` inside the
    /// quotes would corrupt the value and make it re-parse as `PinStyle::Branch`.
    #[test]
    fn test_build_sha_pin_action_no_quickfix_for_quoted_scalar() {
        let uri = deps_core::test_util::test_uri("/repo/.github/workflows/ci.yml");
        let content = "steps:\n  - uses: \"actions/checkout@v4\"\n";
        let parse_result = crate::parser::parse_workflow_yaml(content, &uri).unwrap();
        assert!(!parse_result.dependencies[0].is_plain_scalar);

        let formatter = GithubActionsFormatter {
            tag_index: Arc::new(dashmap::DashMap::new()),
        };
        let mut index = crate::registry::TagIndex::default();
        index.tag_to_sha.insert("v4".to_string(), "a".repeat(40));
        formatter.tag_index.insert(
            deps_core::PackageName::new("actions/checkout"),
            Arc::new(index),
        );

        let position = deps_core::ParseResult::dependencies(&parse_result)[0]
            .version_range()
            .unwrap()
            .start;

        assert!(
            build_sha_pin_action(&parse_result, position, &uri, &formatter).is_none(),
            "a quoted uses: scalar must withhold the quickfix even on a TagIndex hit"
        );
    }

    /// Security audit finding (issue #633): a `uses:` step written in YAML flow-mapping
    /// style has real content (`, with: {...}}`) after the ref on the same line — the
    /// quickfix must withhold itself even on a `TagIndex` hit, since appending `# v4`
    /// would comment out the rest of the flow mapping and produce invalid, unterminated
    /// YAML (reproduced live by the security audit against a real `yaml_rust2` re-parse).
    #[test]
    fn test_build_sha_pin_action_no_quickfix_for_flow_mapping_step() {
        let uri = deps_core::test_util::test_uri("/repo/.github/workflows/ci.yml");
        let content = "steps:\n  - {uses: actions/checkout@v4, with: {node: 20}}\n";
        let parse_result = crate::parser::parse_workflow_yaml(content, &uri).unwrap();
        assert!(!parse_result.dependencies[0].is_last_on_line);

        let formatter = GithubActionsFormatter {
            tag_index: Arc::new(dashmap::DashMap::new()),
        };
        let mut index = crate::registry::TagIndex::default();
        index.tag_to_sha.insert("v4".to_string(), "a".repeat(40));
        formatter.tag_index.insert(
            deps_core::PackageName::new("actions/checkout"),
            Arc::new(index),
        );

        let position = deps_core::ParseResult::dependencies(&parse_result)[0]
            .version_range()
            .unwrap()
            .start;

        assert!(
            build_sha_pin_action(&parse_result, position, &uri, &formatter).is_none(),
            "a flow-mapping uses: step must withhold the quickfix even on a TagIndex hit"
        );
    }

    #[test]
    fn test_ecosystem_id_and_display_name() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = GithubActionsEcosystem::new(cache);
        assert_eq!(eco.id(), "github-actions");
        assert_eq!(eco.display_name(), "GitHub Actions");
    }

    #[test]
    fn test_manifest_routing_is_directory_pattern_only() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = GithubActionsEcosystem::new(cache);
        assert!(eco.manifest_filenames().is_empty());
        assert!(eco.manifest_patterns().is_empty());
        assert!(eco.manifest_extensions().is_empty());
        assert_eq!(
            eco.manifest_directory_patterns(),
            &[
                (".github/workflows", ".yml"),
                (".github/workflows", ".yaml")
            ]
        );
    }

    #[test]
    fn test_as_any() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = GithubActionsEcosystem::new(cache);
        assert!(eco.as_any().is::<GithubActionsEcosystem>());
    }

    #[tokio::test]
    async fn test_parse_manifest_valid() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = GithubActionsEcosystem::new(cache);
        let uri = deps_core::test_util::test_uri("/repo/.github/workflows/ci.yml");
        let content = "steps:\n  - uses: actions/checkout@v4\n";
        let result = eco.parse_manifest(content, &uri).await.unwrap();
        assert_eq!(result.dependencies().len(), 1);
    }

    #[test]
    fn test_splice_resolved_line_after_requirement() {
        let markdown = "# actions/checkout\n\n**Requirement**: `v4.2.0`\n\n**Latest**: `v4.3.0`\n";
        let spliced = splice_resolved_line(markdown, "v4.2.0", &"a".repeat(40));
        let req_pos = spliced.find("**Requirement**").unwrap();
        let resolved_pos = spliced.find("**Resolved**").unwrap();
        let latest_pos = spliced.find("**Latest**").unwrap();
        assert!(req_pos < resolved_pos);
        assert!(resolved_pos < latest_pos);
        assert!(spliced.contains("aaaaaaa…"));
    }

    #[test]
    fn test_splice_resolved_line_after_current_when_present() {
        let markdown = "# actions/checkout\n\n**Current**: `v4.2.0`\n\n**Requirement**: `v4`\n";
        let spliced = splice_resolved_line(markdown, "v4.2.0", &"b".repeat(40));
        let current_pos = spliced.find("**Current**").unwrap();
        let resolved_pos = spliced.find("**Resolved**").unwrap();
        let requirement_pos = spliced.find("**Requirement**").unwrap();
        assert!(current_pos < resolved_pos);
        assert!(resolved_pos < requirement_pos);
    }

    #[test]
    fn test_splice_resolved_line_falls_back_to_append_when_no_anchor() {
        let markdown = "# actions/checkout\n\nno anchors here\n";
        let spliced = splice_resolved_line(markdown, "v4.2.0", &"c".repeat(40));
        assert!(spliced.starts_with(markdown));
        assert!(spliced.contains("**Resolved**"));
    }

    /// #501 (tester finding): the shared `deps_core::generate_hover` gate only sees
    /// `VersionData` and cannot know a `PinStyle::Tag` step still has a real "Pin to commit
    /// SHA" quickfix available via the ecosystem-private `TagIndex`. Seeding the index
    /// directly simulates a fetch that succeeded before the session went offline;
    /// `cache.set_offline(true)` then makes the live fetch this call attempts fail without
    /// touching the network (mirroring `HttpCache`'s real offline-cold behavior), so
    /// `VersionData` carries no signal of its own and only the post-hoc restore can produce
    /// the footer.
    #[tokio::test]
    async fn test_generate_hover_restores_footer_offline_for_tag_pin_with_warm_tag_index() {
        let cache = Arc::new(deps_core::HttpCache::new());
        cache.set_offline(true);
        let eco = GithubActionsEcosystem::new(cache);
        let uri = deps_core::test_util::test_uri("/repo/.github/workflows/ci.yml");
        let content = "steps:\n  - uses: actions/checkout@v4\n";
        let parse_result = eco.parse_manifest(content, &uri).await.unwrap();

        let mut index = crate::registry::TagIndex::default();
        index.tag_to_sha.insert("v4".to_string(), "a".repeat(40));
        eco.formatter.tag_index.insert(
            deps_core::PackageName::new("actions/checkout"),
            Arc::new(index),
        );

        let position = parse_result.dependencies()[0].name_range().start;
        let cached = HashMap::new();
        let resolved = HashMap::new();

        let hover = eco
            .generate_hover(
                parse_result.as_ref(),
                position,
                deps_core::VersionData::new(&cached, &resolved).with_offline(true),
                deps_core::FreshnessSettings::default(),
            )
            .await
            .expect("hover should be generated for the dependency on this line");

        let HoverContents::Markup(content) = hover.contents else {
            panic!("expected markup hover contents");
        };
        assert!(
            content.value.contains("Press `Cmd+.` to update version"),
            "a Tag-pinned step with a warm TagIndex entry still offers the SHA-pin quickfix \
             while offline, so the footer must be restored even with no VersionData signal; \
             got: {}",
            content.value
        );
    }

    /// A `PinStyle::Tag` step with no `TagIndex` entry (true cold start, nothing ever
    /// resolved) must not have the footer restored — there is no quickfix to advertise.
    #[tokio::test]
    async fn test_generate_hover_footer_stays_omitted_offline_for_tag_pin_without_tag_index() {
        let cache = Arc::new(deps_core::HttpCache::new());
        cache.set_offline(true);
        let eco = GithubActionsEcosystem::new(cache);
        let uri = deps_core::test_util::test_uri("/repo/.github/workflows/ci.yml");
        let content = "steps:\n  - uses: actions/checkout@v4\n";
        let parse_result = eco.parse_manifest(content, &uri).await.unwrap();

        let position = parse_result.dependencies()[0].name_range().start;
        let cached = HashMap::new();
        let resolved = HashMap::new();

        let hover = eco
            .generate_hover(
                parse_result.as_ref(),
                position,
                deps_core::VersionData::new(&cached, &resolved).with_offline(true),
                deps_core::FreshnessSettings::default(),
            )
            .await
            .expect("hover should be generated for the dependency on this line");

        let HoverContents::Markup(content) = hover.contents else {
            panic!("expected markup hover contents");
        };
        assert!(
            !content.value.contains("Press `Cmd+.` to update version"),
            "no TagIndex entry exists, so there is no quickfix to restore the footer for; \
             got: {}",
            content.value
        );
    }

    /// Regression for critic finding C1 (#550): a bare-major tag pin (`@v4`, "the most
    /// common real-world GitHub Actions pinning convention" per `populate_tag_index`'s own
    /// docs) whose repository's tags are *all* bare-major fails `tags_to_versions`' full
    /// `major.minor.patch` semver filter entirely, so the live hover fetch genuinely
    /// succeeds with `available_versions == Some([])` — the #550 hover fix correctly
    /// suppresses the shared footer for that case in general, but `populate_tag_index`
    /// indexes bare-major tags independently of that filter, so the SHA-pin quickfix is
    /// still genuinely available here. Unlike the offline-only sibling test above, this
    /// drives a real (mocked) network fetch through the actual `GithubActionsRegistry` to
    /// prove the restore now fires **online** too, not just offline.
    #[tokio::test]
    async fn test_generate_hover_restores_footer_online_for_bare_major_tag_with_empty_live_list() {
        let sha = "a".repeat(40);
        let mut server = mockito::Server::new_async().await;
        let _mock = server
            .mock("GET", "/repos/actions/checkout/tags")
            .match_query(mockito::Matcher::Any)
            .with_status(200)
            .with_body(format!(
                r#"[{{"name": "v4", "commit": {{"sha": "{sha}"}}}}]"#
            ))
            .create_async()
            .await;

        let registry = crate::registry::GithubActionsRegistry::for_test(
            Arc::new(deps_core::HttpCache::new()),
            server.url(),
            false,
        );
        let formatter = GithubActionsFormatter::new(registry.tag_index());
        let eco = GithubActionsEcosystem {
            registry: Arc::new(registry),
            formatter,
        };

        let uri = deps_core::test_util::test_uri("/repo/.github/workflows/ci.yml");
        let content = "steps:\n  - uses: actions/checkout@v4\n";
        let parse_result = eco.parse_manifest(content, &uri).await.unwrap();
        let position = parse_result.dependencies()[0].name_range().start;
        let cached = HashMap::new();
        let resolved = HashMap::new();

        let hover = eco
            .generate_hover(
                parse_result.as_ref(),
                position,
                deps_core::VersionData::new(&cached, &resolved),
                deps_core::FreshnessSettings::default(),
            )
            .await
            .expect("hover should be generated for the dependency on this line");

        let HoverContents::Markup(content) = hover.contents else {
            panic!("expected markup hover contents");
        };
        assert!(
            !content.value.contains("**Recent versions**"),
            "an all-bare-major tag list has zero full-semver entries, so the section \
             must stay omitted; got: {}",
            content.value
        );
        assert!(
            content.value.contains("Press `Cmd+.` to update version"),
            "a Tag-pinned step whose live fetch genuinely succeeded empty still has a \
             real SHA-pin quickfix via TagIndex, so the footer must be restored online \
             too, not just offline; got: {}",
            content.value
        );
    }

    /// FR-010 (security audit finding, mirrored from
    /// `test_build_sha_pin_action_no_quickfix_for_quoted_scalar`): a quoted `uses:` scalar
    /// never gets the SHA-pin quickfix even on a `TagIndex` hit, since `version_range` sits
    /// inside the quotes and editing it there would corrupt the value. The footer
    /// restoration must withhold itself the same way `build_sha_pin_action` does, not just
    /// check `pin`/`TagIndex` resolvability.
    #[tokio::test]
    async fn test_generate_hover_footer_not_restored_offline_for_quoted_tag_pin() {
        let cache = Arc::new(deps_core::HttpCache::new());
        cache.set_offline(true);
        let eco = GithubActionsEcosystem::new(cache);
        let uri = deps_core::test_util::test_uri("/repo/.github/workflows/ci.yml");
        let content = "steps:\n  - uses: \"actions/checkout@v4\"\n";
        let parse_result = eco.parse_manifest(content, &uri).await.unwrap();

        let mut index = crate::registry::TagIndex::default();
        index.tag_to_sha.insert("v4".to_string(), "a".repeat(40));
        eco.formatter.tag_index.insert(
            deps_core::PackageName::new("actions/checkout"),
            Arc::new(index),
        );

        let position = parse_result.dependencies()[0].name_range().start;
        let cached = HashMap::new();
        let resolved = HashMap::new();

        let hover = eco
            .generate_hover(
                parse_result.as_ref(),
                position,
                deps_core::VersionData::new(&cached, &resolved).with_offline(true),
                deps_core::FreshnessSettings::default(),
            )
            .await
            .expect("hover should be generated for the dependency on this line");

        let HoverContents::Markup(content) = hover.contents else {
            panic!("expected markup hover contents");
        };
        assert!(
            !content.value.contains("Press `Cmd+.` to update version"),
            "a quoted uses: scalar offers no SHA-pin quickfix even on a TagIndex hit, so the \
             footer must not be restored; got: {}",
            content.value
        );
    }

    // --- issue #633/#640: bulk "Pin all to SHA" collector + lens ---

    fn seed_tag(eco: &GithubActionsEcosystem, name: &str, tag: &str, sha: &str) {
        let mut index = crate::registry::TagIndex::default();
        index.tag_to_sha.insert(tag.to_string(), sha.to_string());
        eco.formatter
            .tag_index
            .insert(deps_core::PackageName::new(name), Arc::new(index));
    }

    fn empty_versions() -> (
        HashMap<deps_core::PackageName, deps_core::PackageVersions>,
        HashMap<deps_core::PackageName, deps_core::ConcreteVersion>,
    ) {
        (HashMap::new(), HashMap::new())
    }

    /// (C′) test split, issue #640: the lens title/command-id assertion stays owned by
    /// this crate — GHA's `pin_all_to_sha_noun()` wording must render byte-identically —
    /// but now drives `deps_core::lsp_helpers::build_pin_all_to_sha_lens` directly from
    /// `collect_pin_all_to_sha_edits`'s count, the same call `deps-lsp`'s
    /// `handlers::code_lens` makes, rather than going through the (now-deleted)
    /// `generate_code_lenses` override.
    #[tokio::test]
    async fn test_build_pin_all_to_sha_lens_title_and_command_id() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = GithubActionsEcosystem::new(cache);
        seed_tag(&eco, "actions/checkout", "v4", &"a".repeat(40));
        seed_tag(&eco, "actions/setup-node", "v3", &"b".repeat(40));

        let uri = deps_core::test_util::test_uri("/repo/.github/workflows/ci.yml");
        let content = "steps:\n\
             \x20 - uses: actions/checkout@v4\n\
             \x20 - uses: actions/setup-node@v3\n";
        let parse_result = eco.parse_manifest(content, &uri).await.unwrap();
        let (cached, resolved) = empty_versions();
        let versions = deps_core::VersionData::new(&cached, &resolved);

        let count = eco
            .collect_pin_all_to_sha_edits(parse_result.as_ref(), versions)
            .len();
        let lens = deps_core::lsp_helpers::build_pin_all_to_sha_lens(
            count,
            eco.pin_all_to_sha_noun(),
            &uri,
        )
        .expect("expected a Pin-all-to-SHA lens");
        let command = lens.command.unwrap();
        assert_eq!(command.title, "Pin 2 actions to commit SHA");
        assert_eq!(
            command.command,
            deps_core::lsp_helpers::PIN_ALL_TO_SHA_COMMAND_ID
        );
    }

    #[tokio::test]
    async fn test_collect_pin_all_to_sha_edits_singular_count_for_one_step() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = GithubActionsEcosystem::new(cache);
        seed_tag(&eco, "actions/checkout", "v4", &"a".repeat(40));

        let uri = deps_core::test_util::test_uri("/repo/.github/workflows/ci.yml");
        let content = "steps:\n  - uses: actions/checkout@v4\n";
        let parse_result = eco.parse_manifest(content, &uri).await.unwrap();
        let (cached, resolved) = empty_versions();
        let versions = deps_core::VersionData::new(&cached, &resolved);

        let edits = eco.collect_pin_all_to_sha_edits(parse_result.as_ref(), versions);
        assert_eq!(edits.len(), 1);
    }

    #[tokio::test]
    async fn test_collect_pin_all_to_sha_edits_empty_when_no_tag_pins() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = GithubActionsEcosystem::new(cache);

        let uri = deps_core::test_util::test_uri("/repo/.github/workflows/ci.yml");
        let content = format!("steps:\n  - uses: actions/checkout@{}\n", "a".repeat(40));
        let parse_result = eco.parse_manifest(&content, &uri).await.unwrap();
        let (cached, resolved) = empty_versions();
        let versions = deps_core::VersionData::new(&cached, &resolved);

        let edits = eco.collect_pin_all_to_sha_edits(parse_result.as_ref(), versions);
        assert!(
            edits.is_empty(),
            "an already-SHA-pinned workflow must produce no edits: {edits:?}"
        );
    }

    #[tokio::test]
    async fn test_collect_pin_all_to_sha_edits_empty_when_tag_index_miss() {
        // No `seed_tag` call: the TagIndex has no entry, so the one Tag-pinned step is a
        // cache miss and must be skipped gracefully — not blocking, not erroring.
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = GithubActionsEcosystem::new(cache);

        let uri = deps_core::test_util::test_uri("/repo/.github/workflows/ci.yml");
        let content = "steps:\n  - uses: actions/checkout@v4\n";
        let parse_result = eco.parse_manifest(content, &uri).await.unwrap();
        let (cached, resolved) = empty_versions();
        let versions = deps_core::VersionData::new(&cached, &resolved);

        let edits = eco.collect_pin_all_to_sha_edits(parse_result.as_ref(), versions);
        assert!(
            edits.is_empty(),
            "a TagIndex cache miss must be skipped gracefully, not promise a no-op edit: \
             {edits:?}"
        );
    }

    #[tokio::test]
    async fn test_collect_pin_all_to_sha_edits_skips_unresolvable_step_but_counts_others() {
        // A mix of one resolvable Tag pin and one cache-miss Tag pin: the collector must
        // count only the resolvable one, silently skipping the other rather than refusing
        // the whole batch or counting a step it cannot actually edit.
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = GithubActionsEcosystem::new(cache);
        seed_tag(&eco, "actions/checkout", "v4", &"a".repeat(40));

        let uri = deps_core::test_util::test_uri("/repo/.github/workflows/ci.yml");
        let content = "steps:\n\
             \x20 - uses: actions/checkout@v4\n\
             \x20 - uses: some-org/unresolved-action@v1\n";
        let parse_result = eco.parse_manifest(content, &uri).await.unwrap();
        let (cached, resolved) = empty_versions();
        let versions = deps_core::VersionData::new(&cached, &resolved);

        let edits = eco.collect_pin_all_to_sha_edits(parse_result.as_ref(), versions);
        assert_eq!(
            edits.len(),
            1,
            "only the resolvable step must be counted: {edits:?}"
        );
    }

    #[tokio::test]
    async fn test_collect_pin_all_to_sha_edits_produces_correct_workspace_edit_for_multiple_steps()
    {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = GithubActionsEcosystem::new(cache);
        let sha1 = "a".repeat(40);
        let sha2 = "b".repeat(40);
        seed_tag(&eco, "actions/checkout", "v4", &sha1);
        seed_tag(&eco, "actions/setup-node", "v3", &sha2);

        let uri = deps_core::test_util::test_uri("/repo/.github/workflows/ci.yml");
        let content = "steps:\n\
             \x20 - uses: actions/checkout@v4\n\
             \x20 - uses: actions/setup-node@v3\n";
        let parse_result = eco.parse_manifest(content, &uri).await.unwrap();
        let deps = deps_core::ParseResult::dependencies(parse_result.as_ref());
        let checkout_range = deps
            .iter()
            .find(|d| d.name().as_str() == "actions/checkout")
            .and_then(|d| d.version_range())
            .expect("actions/checkout must have a version_range");
        let setup_node_range = deps
            .iter()
            .find(|d| d.name().as_str() == "actions/setup-node")
            .and_then(|d| d.version_range())
            .expect("actions/setup-node must have a version_range");
        let (cached, resolved) = empty_versions();
        let versions = deps_core::VersionData::new(&cached, &resolved);

        let edits = eco.collect_pin_all_to_sha_edits(parse_result.as_ref(), versions);
        assert_eq!(edits.len(), 2);
        // M1 (critic): the entire risk of this feature is writing 40+ chars at the wrong
        // span, so the range each edit targets must be pinned, not just its text —
        // proving the aggregator's dep-to-range mapping doesn't swap or shift.
        let checkout_edit = edits
            .iter()
            .find(|e| e.new_text == format!("{sha1} # v4"))
            .expect("expected an edit for actions/checkout");
        assert_eq!(checkout_edit.range, checkout_range);
        let setup_node_edit = edits
            .iter()
            .find(|e| e.new_text == format!("{sha2} # v3"))
            .expect("expected an edit for actions/setup-node");
        assert_eq!(setup_node_edit.range, setup_node_range);
    }

    #[tokio::test]
    async fn test_collect_pin_all_to_sha_edits_empty_for_branch_and_quoted_scalar() {
        // A `PinStyle::Branch` step and a quoted-scalar `PinStyle::Tag` step must both be
        // withheld, matching `build_sha_pin_action`'s own guards (FR-005/plan §11,
        // FR-010) — the bulk aggregator must never be laxer than the per-step quickfix.
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = GithubActionsEcosystem::new(cache);
        seed_tag(&eco, "some-org/some-action", "main", &"a".repeat(40));
        seed_tag(&eco, "actions/checkout", "v4", &"b".repeat(40));

        let uri = deps_core::test_util::test_uri("/repo/.github/workflows/ci.yml");
        let content = "steps:\n\
             \x20 - uses: some-org/some-action@main\n\
             \x20 - uses: \"actions/checkout@v4\"\n";
        let parse_result = eco.parse_manifest(content, &uri).await.unwrap();
        let (cached, resolved) = empty_versions();
        let versions = deps_core::VersionData::new(&cached, &resolved);

        let edits = eco.collect_pin_all_to_sha_edits(parse_result.as_ref(), versions);
        assert!(
            edits.is_empty(),
            "a branch pin and a quoted-scalar tag pin must both be withheld: {edits:?}"
        );
    }

    /// Security audit finding (issue #633): the bulk aggregator must skip a flow-mapping
    /// `uses:` step the same way the per-step quickfix does — a click on "Pin N actions
    /// to commit SHA" must never turn a real click into workflow-wide YAML corruption.
    #[tokio::test]
    async fn test_collect_pin_all_to_sha_edits_empty_for_flow_mapping_step() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = GithubActionsEcosystem::new(cache);
        seed_tag(&eco, "actions/checkout", "v4", &"a".repeat(40));

        let uri = deps_core::test_util::test_uri("/repo/.github/workflows/ci.yml");
        let content = "steps:\n  - {uses: actions/checkout@v4, with: {node: 20}}\n";
        let parse_result = eco.parse_manifest(content, &uri).await.unwrap();
        let (cached, resolved) = empty_versions();
        let versions = deps_core::VersionData::new(&cached, &resolved);

        let edits = eco.collect_pin_all_to_sha_edits(parse_result.as_ref(), versions);
        assert!(
            edits.is_empty(),
            "a flow-mapping tag pin must be withheld, not corrupted: {edits:?}"
        );
    }
}
