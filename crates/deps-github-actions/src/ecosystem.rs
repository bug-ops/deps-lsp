//! GitHub Actions ecosystem implementation for deps-lsp.

use std::any::Any;
use std::sync::Arc;
use tower_lsp_server::ls_types::{
    CodeAction, CodeActionKind, Diagnostic, Hover, HoverContents, NumberOrString, Position,
    TextEdit, Uri, WorkspaceEdit,
};

use deps_core::{
    Ecosystem, ParseResult as ParseResultTrait, Registry, Result,
    completion::Completions,
    lsp_helpers::{EcosystemFormatter, markdown_code_span},
};

use crate::MUTABLE_REF_PIN_DIAGNOSTIC_CODE;

use crate::formatter::GithubActionsFormatter;
use crate::registry::GithubActionsRegistry;
use crate::types::{GithubActionsDependency, PinStyle};

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

            // #501 gap (tester finding): the shared `has_offline_actionable_data` gate in
            // `deps_core::generate_hover` only sees `VersionData` and cannot see
            // `formatter.tag_index` — GHA's "Pin to commit SHA" quickfix
            // (`build_sha_pin_action`, wired into `generate_code_actions` above) is driven
            // entirely by that separately-populated index, independent of `versions`. So a
            // `PinStyle::Tag` step with a warm `TagIndex` entry has a real `Cmd+.` action
            // while offline, even when the shared gate suppressed the footer for lack of any
            // `VersionData` signal. Restores it post-hoc using the shared `CMD_DOT_FOOTER`
            // constant (not a hand-copied literal) so the two can never drift apart.
            // `is_plain_scalar` mirrors `build_sha_pin_action`'s own guard (FR-010, spec
            // 031): for a quoted `uses:` scalar, `version_range` sits inside the quotes, so
            // the quickfix withholds itself rather than corrupt the value — the footer must
            // not advertise an action that was never actually offered.
            if versions.offline
                && gha_dep.pin == Some(PinStyle::Tag)
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

/// Builds one mutable-ref-pin [`Diagnostic`] (issue #473) per `PinStyle::Tag` step in
/// `parse_result` — `PinStyle::Sha`, `PinStyle::Branch`, and `None` steps produce no
/// diagnostic (FR-003; `PinStyle::Branch` is out of scope for this iteration, see spec
/// 031 §"Out of Scope").
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
) -> Vec<Diagnostic> {
    parse_result
        .dependencies()
        .into_iter()
        .filter_map(|dep| {
            let gha_dep = dep.as_any().downcast_ref::<GithubActionsDependency>()?;
            if gha_dep.pin != Some(PinStyle::Tag) {
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
            Some(Diagnostic {
                range,
                severity: Some(severity),
                message: format!(
                    "{name} is pinned to the mutable tag ref `{tag}`; pin to a full commit \
                     SHA to guard against tag mutation"
                ),
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
    if gha_dep.pin != Some(PinStyle::Tag) {
        return None;
    }
    // FR-010: for a quoted `uses:` scalar, `version_range` sits inside the quotes —
    // writing `{sha} # {tag}` there corrupts the value instead of adding a YAML comment
    // (security audit finding, spec 031 FR-010). Withhold rather than risk that edit.
    if !gha_dep.is_plain_scalar {
        return None;
    }
    let version_range = gha_dep.version_range?;
    let tag = gha_dep
        .version_req
        .as_ref()
        .map(deps_core::VersionReq::as_str)?;
    let new_text = formatter.sha_pin_replacement_for(&gha_dep.name, tag)?;

    let mut changes = std::collections::HashMap::new();
    changes.insert(
        uri.clone(),
        vec![TextEdit {
            range: version_range,
            new_text,
        }],
    );

    Some(CodeAction {
        title: format!("Pin {} to commit SHA", gha_dep.name),
        kind: Some(CodeActionKind::QUICKFIX),
        edit: Some(WorkspaceEdit {
            changes: Some(changes),
            ..Default::default()
        }),
        data: Some(serde_json::json!({
            "diagnostic_codes": [MUTABLE_REF_PIN_DIAGNOSTIC_CODE],
            "diagnostic_range": version_range,
        })),
        ..Default::default()
    })
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
}
