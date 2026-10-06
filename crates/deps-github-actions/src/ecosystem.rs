//! GitHub Actions ecosystem implementation for deps-lsp.

use dashmap::DashMap;
#[cfg(feature = "lsp-responses")]
use deps_core::completion::Completions;
#[cfg(feature = "lsp-responses")]
use deps_core::hover::Hover;
#[cfg(feature = "lsp-responses")]
use deps_core::lsp_helpers::ShaPinning;
use deps_core::{
    Dependency, Ecosystem, PackageName, ParseResult as ParseResultTrait, Registry, Result,
    diagnostic::{Diagnostic, DiagnosticKind, GitTagsPlatform, Severity},
    lsp_helpers::{EcosystemFormatter, unknown_ref_diagnostics},
};
use std::any::Any;
use std::sync::Arc;
#[cfg(feature = "lsp-responses")]
use tower_lsp_server::ls_types::{CodeAction, Position, TextEdit};
use url::Url;

use crate::formatter::GithubActionsFormatter;
use crate::registry::GithubActionsRegistry;
use crate::types::{GithubActionsDependency, PinStyle};
use deps_core::lsp_helpers::{CommentCheck, TagIndex, UnknownRefTarget};

#[cfg(feature = "lsp-responses")]
mod lsp;
#[cfg(feature = "lsp-responses")]
use lsp::{
    VERSION_OPERATOR_CHARS, build_sha_comment_fix_action, build_sha_pin_action,
    build_unknown_ref_fix_action, collect_pin_all_to_sha_edits, position_past_sha_pin_own_ref,
};

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
/// Provides LSP functionality for `.github/workflows/*.yml`/`*.yaml` workflow files and
/// `action.yml`/`action.yaml` composite action manifests (issue #706), including:
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
    fn ecosystem_id(&self) -> deps_core::EcosystemId {
        deps_core::EcosystemId::GithubActions
    }

    fn display_name(&self) -> &'static str {
        "GitHub Actions"
    }

    /// `action.yml`/`action.yaml` (issue #706): a composite (or Docker/JS) action's
    /// manifest, conventionally at a repository root or under `.github/actions/<name>/`.
    /// [`crate::parser::parse_workflow_yaml`]'s `uses:` detection is key-driven, not
    /// path-driven, so `runs.steps[].uses:` in such a file already parses identically to
    /// a workflow step — this is a routing-only extension. Matched by exact basename (via
    /// `deps_core::EcosystemRegistry::for_filename`), so it applies regardless of
    /// which directory the file lives in, not just a repository root.
    fn manifest_filenames(&self) -> &[&'static str] {
        &["action.yml", "action.yaml"]
    }

    /// GHA workflows are routed solely by directory path (D1): a
    /// `.github/workflows/*.yml`/`*.yaml` file, regardless of how many ancestor
    /// directories precede `.github`. No `.github/actions` entry is added here (issue
    /// #706 review finding): `deps_core::ecosystem_registry::directory_pattern_matches`
    /// only matches a file whose *immediate* containing directory's path ends with the
    /// pattern, so `(".github/actions", ".yml")` would match a flat file sitting directly
    /// in `.github/actions/` (a layout GitHub never treats as an action manifest) but
    /// would **not** match the real, canonical `.github/actions/<name>/action.yml` — that
    /// nested layout is already fully covered by the exact-basename
    /// [`Self::manifest_filenames`] match, which applies regardless of directory depth.
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
        uri: &'a Url,
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

    /// Emits a repository's name whenever its tag index is first populated or its tag-to-commit
    /// mapping changes; see [`GithubActionsRegistry::subscribe_tag_refreshes`] for the contract.
    fn tag_index_refreshes(&self) -> Option<deps_core::TagIndexRefreshes> {
        Some(self.registry.subscribe_tag_refreshes())
    }

    // No `complete_package_name` override: GHA has no package-name search endpoint, so
    // the inherited `Completions::default()` is correct (M3, #793).

    /// Withholds a `Version` completion when the cursor sits past a comment-annotated
    /// SHA pin's own ref text — in the whitespace padding before its trailing
    /// `# vX.Y.Z` comment, on the `#` itself, or inside the comment (issue #1182). That
    /// pin's `version_range` intentionally extends through the comment —
    /// `crate::formatter::GithubActionsFormatter::format_version_replacing_for`'s edit
    /// range and [`Self::generate_hover`]'s `**Resolved**` splice both depend on it
    /// spanning the full `<sha> # <tag>` text — so `detect_completion_context` still
    /// reports a `Version` context there. `position_past_sha_pin_own_ref` checks the
    /// cursor position directly against the SHA's own end column rather than scanning
    /// the extracted prefix: `extract_prefix` trims trailing whitespace, so a cursor
    /// sitting in the padding gap or exactly on `#` yields a bare-SHA prefix with no
    /// whitespace left for a prefix-content check to catch.
    ///
    /// The guard lives here rather than in a `generate_completions` override (issue
    /// #1195): the shared dispatch in `deps-core::Ecosystem::generate_completions`
    /// already routes a resolved `Version` context to this hook and stamps
    /// `CompletionOrigin::Version` on whatever it returns — including
    /// `Completions::default()` from this early return — so #1184 Gap 2's "never fall
    /// through to `deps-lsp`'s raw-text package-name search" guarantee holds without
    /// GHA needing its own dispatch override at all.
    // Position-based, gated: see complete_versions_at_position's own doc (#593, #1136).
    #[cfg(feature = "lsp-responses")]
    fn complete_version<'a>(
        &'a self,
        request: deps_core::completion::CompletionRequest<'a>,
        _package_name: deps_core::PackageName,
        prefix: String,
    ) -> deps_core::ecosystem::BoxFuture<'a, Completions> {
        Box::pin(async move {
            if position_past_sha_pin_own_ref(request.parse_result, request.position) {
                return Completions::default();
            }
            deps_core::completion::complete_versions_at_position(
                self.registry.as_ref(),
                &self.formatter,
                request.parse_result,
                request.position,
                &prefix,
                VERSION_OPERATOR_CHARS,
                request.freshness,
            )
            .await
            .into()
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
    ///
    /// Also appends the SHA-comment-mismatch diagnostic (issue #1722), which is not gated on
    /// `mutable_ref_pin_enabled`: it only fires for a provable mismatch, and the unknown-ref
    /// diagnostic (#1766) for a tag pin that is a full release no published tag matches.
    fn generate_diagnostics<'a>(
        &'a self,
        parse_result: &'a dyn ParseResultTrait,
        versions: deps_core::VersionData<'a>,
        uri: &'a Url,
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
            diagnostics.extend(sha_comment_mismatch_diagnostics(
                parse_result,
                severities.sha_comment_mismatch,
                &self.formatter,
            ));
            diagnostics.extend(unknown_ref_diagnostics(
                parse_result,
                severities.unknown_ref,
                |dep| tag_pin_target(&self.formatter, dep),
            ));
            diagnostics
        })
    }

    /// Appends the "Pin to commit SHA" quickfix (issue #473) to the shared default's
    /// output when the position's dependency is a `PinStyle::Tag` step with a resolvable
    /// `TagIndex` entry.
    #[cfg(feature = "lsp-responses")]
    fn generate_code_actions<'a>(
        &'a self,
        parse_result: &'a dyn ParseResultTrait,
        position: Position,
        uri: &'a Url,
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
            actions.extend(build_sha_comment_fix_action(
                parse_result,
                position,
                uri,
                &self.formatter,
            ));
            actions.extend(build_unknown_ref_fix_action(
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
    /// [`crate::registry::GithubActionsRegistry`]'s [`TagIndex`].
    ///
    /// Necessary, not merely additive: `versions.resolved` (the shared helper's
    /// `**Current**` source) is keyed by package name and is unconditionally empty for
    /// GHA (no lockfile provider), so it cannot express per-occurrence resolution when
    /// the same action is pinned at two different SHAs in one workflow. The splice also
    /// makes a stale or hand-edited `# vX.Y.Z` comment visible for free (M4): the tag
    /// shown here comes from `TagIndex.sha_to_tag`, not from trusting the comment text.
    ///
    /// Scoped to [`PinStyle::Sha`] and floating [`PinStyle::Tag`] pins (`@v4`, #1684) —
    /// the two forms where the pinned commit names a more specific release than the
    /// written text; an exact tag already shows its own version, and a floating tag whose
    /// commit only carries that same tag is not spliced (the line would be a tautology).
    /// Guarded on `dep.version_range().is_some()` (N3): a non-resolvable dependency (a
    /// reusable-workflow call, `./local`, `docker://…`) still matches the shared helper's
    /// own hover-target predicate and must not have a `**Resolved**` line spliced onto it.
    #[cfg(feature = "lsp-responses")]
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
                deps_core::position_in_range(position.into(), d.name_range())
                    || d.version_range()
                        .is_some_and(|r| deps_core::position_in_range(position.into(), r))
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

            // #501/#550: the shared footer gate only sees `VersionData`, not `tag_index` —
            // so a `PinStyle::Tag` step with a warm `TagIndex` entry can have a real "Pin to
            // commit SHA" quickfix even when the shared gate suppressed the footer for lack
            // of `VersionData`. Restored post-hoc via `CMD_DOT_FOOTER`, idempotently, using
            // the same centralized eligibility check the quickfix/code-lens build on (#1177).
            if self.formatter.resolve_static_sha_pin(dep).is_some()
                && !hover
                    .markdown()
                    .contains(deps_core::lsp_helpers::CMD_DOT_FOOTER)
            {
                hover.push_markdown(deps_core::lsp_helpers::CMD_DOT_FOOTER);
            }

            let Some(sha) = self.formatter.pinned_commit(gha_dep) else {
                return Some(hover);
            };

            use deps_core::lsp_helpers::{PinResolution, RequirementResolution};
            let resolved_tag = match self.formatter.resolved_pin_version(dep) {
                PinResolution::Resolved { pin, .. } => Some(pin.version().as_str().to_string()),
                PinResolution::Unresolved
                | PinResolution::NotYetIndexed
                | PinResolution::Unlisted
                | PinResolution::Untagged
                | PinResolution::Unpublished
                | PinResolution::CommentContradicted => None,
            };

            let written_tag = gha_dep
                .version_req
                .as_ref()
                .map(deps_core::VersionReq::as_str);
            if let Some(resolved_tag) = resolved_tag.filter(|resolved| {
                !(gha_dep.pin == Some(PinStyle::Tag) && written_tag == Some(resolved.as_str()))
            }) {
                hover.rewrite_markdown(|md| {
                    deps_core::lsp_helpers::splice_resolved_line(md, &resolved_tag, &sha)
                });
            }

            if let Some(CommentCheck::Mismatch(mismatch)) =
                self.formatter.sha_comment_check(gha_dep)
                && let Some(comment) = gha_dep.sha_comment()
            {
                let line = deps_core::lsp_helpers::sha_comment_mismatch_hover_line(
                    &sha,
                    &comment.pin_comment().tag,
                    &mismatch,
                );
                hover.rewrite_markdown(|md| deps_core::lsp_helpers::splice_hover_line(md, &line));
            }

            Some(hover)
        })
    }

    fn fallback_completion_prefix<'a>(
        &self,
        content: &'a str,
        position: deps_core::position::Position,
    ) -> Option<&'a str> {
        let line = deps_core::fallback_completion::line_at(content, position)?;
        if !is_in_dependencies_section(content, position.line as usize) {
            return None;
        }
        Some(extract_prefix(line, position.character))
    }

    fn completion_insert_text(&self, metadata: &dyn deps_core::Metadata) -> Option<String> {
        let name = metadata.name();
        let latest = metadata.latest_version().as_str();
        // Unreachable today since `search()` always returns `Ok(vec![])`; kept total in case
        // package-name search is added. Plain `contains('/')`, matching pre-#722 behavior.
        if !name.as_str().contains('/') {
            deps_core::lsp_helpers::warn_rejected_value(
                "owner/repo shape",
                "github actions package name completion item",
                name.as_str(),
            );
            return None;
        }
        if latest.is_empty() {
            Some(name.as_str().to_string())
        } else {
            Some(format!("{}@{latest}", name.as_str()))
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    /// One [`TextEdit`] per `PinStyle::Tag` step in `parse_result` resolvable to a commit
    /// SHA via this ecosystem's own `TagIndex`-backed formatter (issue #633) — `versions`
    /// is unused: a GHA SHA pin's replacement comes entirely from the shared `TagIndex`,
    /// with no dependency on the caller's fetched version data.
    #[cfg(feature = "lsp-responses")]
    fn collect_pin_all_to_sha_edits(
        &self,
        parse_result: &dyn ParseResultTrait,
        _versions: deps_core::VersionData<'_>,
    ) -> Vec<TextEdit> {
        collect_pin_all_to_sha_edits(parse_result, &self.formatter)
    }

    #[cfg(feature = "lsp-responses")]
    fn pin_all_to_sha_noun(&self) -> deps_core::lsp_helpers::PinNoun {
        deps_core::lsp_helpers::PinNoun {
            singular: "action",
            plural: "actions",
        }
    }
}

/// Whether line `line_number` of `content` is a workflow `uses:` step key (`uses:
/// owner/repo@ref` or, as a sequence item, `- uses: owner/repo@ref`), for
/// `deps-lsp`'s raw-text fallback completion (parse-failure path).
///
/// A `uses:` step key can appear at any nesting depth in a workflow file
/// (`jobs.*.steps[].uses`, `jobs.<id>.uses`), so unlike TOML/JSON/other-YAML
/// ecosystems there is no enclosing section header to track — the target line itself
/// is the only signal needed.
fn is_in_dependencies_section(content: &str, line_number: usize) -> bool {
    content
        .lines()
        .nth(line_number)
        .map(str::trim_start)
        .is_some_and(|trimmed| trimmed.starts_with("uses:") || trimmed.starts_with("- uses:"))
}

/// Extracts the fallback-completion prefix on `line` up to `character` — a bare
/// `owner/repo@ref` (or partial) specifier, with no manifest-syntax wrapper to strip.
fn extract_prefix(line: &str, character: u32) -> &str {
    deps_core::fallback_completion::raw_prefix(line, character)
}

/// Whether `gha_dep` is structurally eligible for GitHub Actions' static "pin to commit
/// SHA" resolution — `PinStyle::Tag` plus the two shape guards
/// [`deps_core::lsp_helpers::ShaPinning::resolve_static_sha_pin`] enforces before it ever
/// consults the `TagIndex` cache: `is_plain_scalar` (FR-010, a quoted scalar's
/// `version_range` sits inside the quotes) and `is_last_on_line` (#633, a flow-style
/// step has real YAML after the ref).
///
/// Deliberately **not** feature-gated behind `lsp-responses` (unlike `ShaPinning`/
/// `resolve_static_sha_pin` themselves, which need the `TagIndex`-backed formatter) and
/// deliberately **not** dependent on a live `TagIndex` cache hit — this is the single
/// source of truth [`mutable_ref_pin_diagnostics`]'s message-branch selection uses
/// (issue #1188), and both properties matter there: the message must render identically
/// in a `deps-cli` build with `lsp-responses` disabled (critic S1 — `deps-cli` never
/// enables that feature, per `Cargo.toml`, but `generate_diagnostics` still runs there),
/// and it must not flip between "automated fix available" and "manual edit" as the cache
/// warms or goes cold across a session (critic S2 — mirrors `deps-gitlab-ci`'s
/// `sha_pin_quickfix_kind`/`ecosystem.rs`, whose own doc comment rules the identical
/// question the same way: a diagnostic's advisory text needs no live cache hit the way
/// an actual destructive edit does).
///
/// [`GithubActionsEcosystem::generate_hover`]'s footer guard reaches the same predicate
/// through `resolve_static_sha_pin`.
pub(crate) fn is_sha_pinnable_tag(gha_dep: &GithubActionsDependency) -> bool {
    gha_dep.pin == Some(PinStyle::Tag) && gha_dep.is_plain_scalar && gha_dep.is_last_on_line
}

/// Builds one mutable-ref-pin [`Diagnostic`] (issue #473) per diagnosable-as-tag step in
/// `parse_result` — every `PinStyle::Tag` step, plus a `PinStyle::Branch` step
/// `tag_index` confirms is actually a real tag (issue #551, e.g.
/// `taiki-e/install-action@cargo-deny`: see [`is_registry_confirmed_tag`]).
/// `PinStyle::Sha` and a `PinStyle::Branch` `tag_index` cannot (yet) confirm produce no
/// diagnostic (FR-003).
fn mutable_ref_pin_diagnostics(
    parse_result: &dyn ParseResultTrait,
    severity: Severity,
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
            let name = deps_core::lsp_helpers::redact_name_for_diagnostic(&gha_dep.name);
            let tag = deps_core::lsp_helpers::sanitize_and_truncate_for_diagnostic(
                tag,
                deps_core::lsp_helpers::MAX_DIAGNOSTIC_VALUE_CHARS,
            );
            // Critic C2 (#551): a registry-confirmed `PinStyle::Branch` has no automated fix
            // (`build_sha_pin_action` stays restricted to `PinStyle::Tag`, FR-005) — the
            // message must say so, not imply one exists. Gated on `is_sha_pinnable_tag`
            // (#1188), not raw `PinStyle::Tag` alone, so a quoted-scalar/flow-style tag pin
            // (quickfix withheld) doesn't claim one.
            let message = if is_sha_pinnable_tag(gha_dep) {
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
            Some(
                Diagnostic::new(
                    DiagnosticKind::MutableRefPin(GitTagsPlatform::GithubActions),
                    range,
                    message,
                )
                .with_severity(severity),
            )
        })
        .collect()
}

/// Builds one SHA-comment-mismatch [`Diagnostic`] (issue #1722) per SHA-pinned step whose
/// trailing `# tag` comment provably names a different commit than the pinned SHA.
///
/// Emits nothing for a confirmed comment, a commentless pin, or an unverifiable one (cold
/// cache, or a SHA absent from a truncated tag list).
fn sha_comment_mismatch_diagnostics(
    parse_result: &dyn ParseResultTrait,
    severity: Severity,
    formatter: &GithubActionsFormatter,
) -> Vec<Diagnostic> {
    parse_result
        .dependencies()
        .into_iter()
        .filter_map(|dep| {
            let gha_dep = dep.as_any().downcast_ref::<GithubActionsDependency>()?;
            let CommentCheck::Mismatch(mismatch) = formatter.sha_comment_check(gha_dep)? else {
                return None;
            };
            let comment = gha_dep.sha_comment()?;
            Some(deps_core::lsp_helpers::sha_comment_mismatch_diagnostic(
                gha_dep.version_range?,
                &gha_dep.name,
                &formatter.pinned_commit(gha_dep)?,
                &comment.pin_comment().tag,
                &mismatch,
                severity,
            ))
        })
        .collect()
}

/// The tag pin `gha_dep` and the index that can speak for it, shared by the unknown-ref
/// diagnostic and its quick fix (#1781). `None` for a non-tag pin, a pin without a ref or range,
/// and a repository whose tags have not been fetched.
pub(crate) fn unknown_ref_target<'a>(
    formatter: &GithubActionsFormatter,
    gha_dep: &'a GithubActionsDependency,
) -> Option<UnknownRefTarget<'a>> {
    if gha_dep.pin != Some(PinStyle::Tag) {
        return None;
    }
    let written = gha_dep.version_req.as_ref()?.as_str();
    let index = formatter
        .tag_index
        .get(&gha_dep.name)
        .map(|index| Arc::clone(&index))?;
    Some(UnknownRefTarget::new(
        index,
        written,
        gha_dep.version_range?,
    ))
}

/// [`unknown_ref_target`] for a type-erased dependency of this ecosystem.
fn tag_pin_target<'a>(
    formatter: &GithubActionsFormatter,
    dep: &'a dyn Dependency,
) -> Option<UnknownRefTarget<'a>> {
    unknown_ref_target(
        formatter,
        dep.as_any().downcast_ref::<GithubActionsDependency>()?,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "lsp-responses")]
    use crate::SHA_COMMENT_MISMATCH_DIAGNOSTIC_CODE;
    use std::collections::HashMap;

    #[tokio::test]
    async fn test_ecosystem_tag_index_refreshes_carries_registry_fetches() {
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
        let registry = GithubActionsRegistry::for_test(
            Arc::new(deps_core::HttpCache::new()),
            server.url(),
            false,
        );
        let formatter = GithubActionsFormatter::new(registry.tag_index());
        let eco = GithubActionsEcosystem {
            registry: Arc::new(registry),
            formatter,
        };
        let mut refreshes = eco.tag_index_refreshes().expect("GHA has a tag index");

        eco.registry.get_versions("actions/checkout").await.unwrap();

        assert_eq!(
            refreshes.try_recv().ok(),
            Some(PackageName::new("actions/checkout"))
        );
    }

    /// Spec 076 FR-025/SC-018 (T005): GitHub Actions has no compiled requirement model at
    /// all — `fallback_edit_excludes_newer`'s check a0 (`OriginalUncompilable`) rejects it
    /// before this spec's rule is ever reached, unchanged, existing behavior from spec 075,
    /// not a new fail-closed case this spec introduces.
    #[tokio::test]
    async fn test_fallback_edit_excludes_newer_pins_a0_uncompilable() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = GithubActionsEcosystem::new(cache);
        let content = "steps:\n  - uses: actions/checkout@v4\n".to_string();
        let uri = deps_core::test_util::test_uri("/repo/.github/workflows/ci.yml");
        let parsed = ecosystem
            .parse_manifest(&content, &uri)
            .await
            .expect("manifest must parse");
        let dep = parsed
            .dependencies()
            .into_iter()
            .find(|d| d.name().as_str() == "actions/checkout")
            .expect("dependency present");
        let candidate = deps_core::edit::ManifestEdit {
            range: dep.version_range().expect("version range"),
            new_text: "v5".to_string(),
        };
        let reparse = deps_core::edit::EcosystemReparse {
            ecosystem: &ecosystem,
            uri: &uri,
        };
        let fallback = deps_core::ConcreteVersion::new("v5");
        let available = [deps_core::ConcreteVersion::new("v6"), fallback.clone()];

        let verdict = deps_core::lsp_helpers::fallback_edit_excludes_newer(
            ecosystem.formatter(),
            &reparse,
            &content,
            dep,
            &candidate,
            &fallback,
            &available,
        );
        assert_eq!(
            verdict,
            deps_core::lsp_helpers::FallbackEditVerdict::Rejected(
                deps_core::lsp_helpers::FallbackEditRejection::OriginalUncompilable
            )
        );
    }

    // --- issue #473: mutable-ref-pin diagnostic + "Pin to commit SHA" code action ---

    fn mutable_ref_pin_code() -> String {
        deps_core::diagnostic::GITHUB_ACTIONS_MUTABLE_REF_PIN_DIAGNOSTIC_CODE.into()
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
            .filter(|d| d.code() == Some(mutable_ref_pin_code().as_str()))
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
            .find(|d| d.code() == Some(mutable_ref_pin_code().as_str()))
            .expect("expected a mutable-ref-pin diagnostic for a tag pin");
        assert_eq!(found.severity, Some(Severity::Hint));
        assert!(found.message().contains("actions/checkout"));
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
            .find(|d| d.code() == Some(mutable_ref_pin_code().as_str()))
            .expect("expected a mutable-ref-pin diagnostic");
        assert!(
            found.message().len() < long_tag.len(),
            "a 10,000-char tag must not render in full inside the diagnostic message"
        );
        assert!(found.message().contains('…'));
    }

    /// Security audit finding (#1252): a bidi-override character in the `owner/repo` name
    /// and a raw newline in the tag ref must not survive into the rendered diagnostic
    /// message — either could forge a fake report row or spoof the displayed name
    /// (Trojan Source, CVE-2021-42574). Constructs the dependency directly rather than
    /// through YAML parsing: `is_valid_github_identity` already rejects a non-ASCII name
    /// at the parser boundary, so this exercises the sink's own sanitization in depth
    /// rather than relying on that unrelated upstream gate.
    #[tokio::test]
    async fn test_generate_diagnostics_mutable_ref_pin_sanitizes_bidi_and_newline() {
        use crate::types::GithubActionsParseResult;
        use deps_core::parser::DependencySource;
        use deps_core::position::{Position, Range};

        let range = Range::new(Position::new(0, 0), Position::new(0, 10));
        let parse_result = GithubActionsParseResult {
            dependencies: vec![GithubActionsDependency {
                name: "ac\u{202E}tions/checkout".into(),
                name_range: range,
                version_req: Some("v4\n0".into()),
                version_range: Some(range),
                pin: Some(PinStyle::Tag),
                source: DependencySource::Registry,
                is_plain_scalar: true,
                is_last_on_line: true,
            }],
            uri: deps_core::test_util::test_uri("/repo/.github/workflows/ci.yml"),
            dependency_truncation: None,
        };

        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = GithubActionsEcosystem::new(cache);
        let cached = HashMap::new();
        let resolved = HashMap::new();
        let diagnostics = eco
            .generate_diagnostics(
                &parse_result,
                deps_core::VersionData::new(&cached, &resolved),
                &parse_result.uri,
                deps_core::FreshnessSettings::default(),
                deps_core::lsp_helpers::DiagnosticSeverities::default(),
            )
            .await;

        let found = diagnostics
            .iter()
            .find(|d| d.code() == Some(mutable_ref_pin_code().as_str()))
            .expect("expected a mutable-ref-pin diagnostic");
        // Asserts the full sanitized message, not just absence of the bad characters —
        // a regression that sanitized the message down to nothing (or dropped unrelated
        // content) must fail loudly rather than vacuously pass a "does not contain" check.
        assert_eq!(
            found.message(),
            "ac tions/checkout is pinned to the mutable tag ref `v4 0`; pin to a full commit \
             SHA to guard against tag mutation"
        );
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
                .any(|d| d.code() == Some(mutable_ref_pin_code().as_str()))
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
                .any(|d| d.code() == Some(mutable_ref_pin_code().as_str()))
        );
    }

    #[tokio::test]
    async fn test_generate_diagnostics_no_mutable_ref_pin_for_branch_pin() {
        let diagnostics = diagnostics_for("steps:\n  - uses: some-org/some-action@main\n").await;
        assert!(
            !diagnostics
                .iter()
                .any(|d| d.code() == Some(mutable_ref_pin_code().as_str()))
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
                .any(|d| d.code() == Some(mutable_ref_pin_code().as_str())),
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

        let mut index = TagIndex::default();
        index.tag_to_sha.insert(
            "cargo-deny".to_string(),
            deps_core::lsp_helpers::CommitSha::parse(&"a".repeat(40)).unwrap(),
        );
        index.tag_to_sha.insert(
            "nextest".to_string(),
            deps_core::lsp_helpers::CommitSha::parse(&"b".repeat(40)).unwrap(),
        );
        index.tag_to_sha.insert(
            "v2".to_string(),
            deps_core::lsp_helpers::CommitSha::parse(&"c".repeat(40)).unwrap(),
        );
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
            .filter(|d| d.code() == Some(mutable_ref_pin_code().as_str()))
            .map(|d| d.message())
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

        // C2 (#551): `build_sha_pin_action` has no automated fix for the
        // registry-confirmed-but-`PinStyle::Branch` case, unlike `v2`'s statically-classified
        // tag, which does have the quickfix behind `Cmd+.`.
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

    /// #1188 regression: a quoted-scalar tag pin is still diagnosable (`PinStyle::Tag`)
    /// but not SHA-pin-quickfixable (`is_plain_scalar` is `false`, FR-010) — the message
    /// must say so, not claim an automated fix that `resolve_static_sha_pin`/
    /// `build_sha_pin_action` actually withhold. Mirrors
    /// `test_build_sha_pin_action_no_quickfix_for_quoted_scalar`'s fixture.
    #[tokio::test]
    async fn test_generate_diagnostics_mutable_ref_pin_no_automated_fix_for_quoted_scalar() {
        let diagnostics = diagnostics_for("steps:\n  - uses: \"actions/checkout@v4\"\n").await;
        let found = diagnostics
            .iter()
            .find(|d| d.code() == Some(mutable_ref_pin_code().as_str()))
            .expect("expected a mutable-ref-pin diagnostic for a quoted tag pin");
        assert!(
            found.message().contains("no automated fix available"),
            "a quoted scalar withholds the SHA-pin quickfix (FR-010), so the message \
             must say so; got: {}",
            found.message()
        );
    }

    /// #1188 regression: a flow-style tag pin (`!is_last_on_line`, #633) is still
    /// diagnosable but not quickfixable — the message must say so. Mirrors
    /// `test_build_sha_pin_action_no_quickfix_for_flow_mapping_step`'s fixture.
    #[tokio::test]
    async fn test_generate_diagnostics_mutable_ref_pin_no_automated_fix_for_flow_mapping_step() {
        let diagnostics =
            diagnostics_for("steps:\n  - {uses: actions/checkout@v4, with: {node: 20}}\n").await;
        let found = diagnostics
            .iter()
            .find(|d| d.code() == Some(mutable_ref_pin_code().as_str()))
            .expect("expected a mutable-ref-pin diagnostic for a flow-style tag pin");
        assert!(
            found.message().contains("no automated fix available"),
            "a flow-style step withholds the SHA-pin quickfix (#633), so the message \
             must say so; got: {}",
            found.message()
        );
    }

    /// #1188 critic S2: the message must not depend on a live `TagIndex` cache hit — a
    /// plain, un-quoted tag pin gets the "automated fix available" phrasing (no suffix)
    /// both cold (no fetch has happened yet) and warm (`TagIndex` populated for the same
    /// content), never flipping between document-open and the post-fetch republish.
    #[tokio::test]
    async fn test_generate_diagnostics_mutable_ref_pin_message_does_not_depend_on_cache_state() {
        let content = "steps:\n  - uses: actions/checkout@v4\n";

        let cold = diagnostics_for(content).await;
        let cold_message = cold
            .iter()
            .find(|d| d.code() == Some(mutable_ref_pin_code().as_str()))
            .expect("expected a diagnostic on cold cache")
            .message();
        assert!(
            !cold_message.contains("no automated fix available"),
            "a cold TagIndex must not force the manual-edit wording; got: {cold_message}"
        );

        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = GithubActionsEcosystem::new(cache);
        let uri = deps_core::test_util::test_uri("/repo/.github/workflows/ci.yml");
        let parse_result = eco.parse_manifest(content, &uri).await.unwrap();
        let mut index = TagIndex::default();
        index.tag_to_sha.insert(
            "v4".to_string(),
            deps_core::lsp_helpers::CommitSha::parse(&"a".repeat(40)).unwrap(),
        );
        eco.formatter.tag_index.insert(
            deps_core::PackageName::new("actions/checkout"),
            Arc::new(index),
        );
        let cached = HashMap::new();
        let resolved = HashMap::new();
        let warm = eco
            .generate_diagnostics(
                parse_result.as_ref(),
                deps_core::VersionData::new(&cached, &resolved),
                &uri,
                deps_core::FreshnessSettings::default(),
                deps_core::lsp_helpers::DiagnosticSeverities::default(),
            )
            .await;
        let warm_message = warm
            .iter()
            .find(|d| d.code() == Some(mutable_ref_pin_code().as_str()))
            .expect("expected a diagnostic on warm cache")
            .message();
        assert_eq!(
            cold_message, warm_message,
            "the diagnostic message must not flip as the TagIndex cache warms (critic S2)"
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
            deps_core::PackageVersions::new("v4".into(), Arc::from(vec!["v4".into(), "v3".into()])),
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
                .any(|d| d.code() == Some(mutable_ref_pin_code().as_str()))
        );
        assert!(
            diagnostics
                .iter()
                .any(|d| d.code() != Some(mutable_ref_pin_code().as_str())
                    && d.message().contains("Newer version available"))
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
        let severities = deps_core::lsp_helpers::DiagnosticSeverities::new()
            .with_mutable_ref_pin(Severity::Error);

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
            .find(|d| d.code() == Some(mutable_ref_pin_code().as_str()))
            .expect("expected a mutable-ref-pin diagnostic");
        assert_eq!(found.severity, Some(Severity::Error));
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
        let severities =
            deps_core::lsp_helpers::DiagnosticSeverities::new().with_mutable_ref_pin_enabled(false);

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
                .any(|d| d.code() == Some(mutable_ref_pin_code().as_str())),
            "mutable_ref_pin_enabled: false must suppress the diagnostic entirely: {diagnostics:?}"
        );
    }

    // #758: exact-value `Ecosystem` conformance, replacing two hand-written tests.
    // `lockfile_filenames()` omitted — GHA has no lock file concept (`no_lockfile_support`
    // below, #782 gap 2). No completion/json-depth conformance: GHA never performs
    // package-name search, and `parse_tags_page`'s depth cap is covered by deps-core's tests.
    deps_core::ecosystem_conformance! {
        mod github_actions_ecosystem_conformance;
        build: GithubActionsEcosystem::new(Arc::new(deps_core::HttpCache::new()));
        ty: GithubActionsEcosystem;
        id: "github-actions";
        display_name: "GitHub Actions";
        manifest_filenames: &["action.yml", "action.yaml"];
        no_lockfile_support: true;
        non_registry_fixture: ".github/workflows/ci.yml" => "steps:\n  - uses: ./local-action\n";
    }

    // #1354/#1370/#1391 security audit: GitHub Actions preserves an unresolved `${{ }}`
    // expression ref as `Some(version_requirement)` (unlike NuGet/PyPI/npm, which degrade to
    // `None`) — reachable through the full `deps_core::edit::plan_vulnerability_fix` pipeline,
    // so `GithubActionsFormatter::requirement_is_placeholder`'s central gate (consulted via
    // `deps_core::edit::requirement_is_placeholder_for`, the sole guard reached since #1391)
    // must actually hold. The second fixture entry is a Tag-shaped ref with an embedded
    // expression (`is_tag_shaped` only inspects the leading characters, so `v4-${{ env.X }}`
    // classifies `PinStyle::Tag`, not `Branch` — the same embedded-placeholder shape #1370
    // fixed for `deps-gitlab-ci`), which `requirement_is_unresolved`'s shape-only check alone
    // would miss.
    deps_core::unresolved_requirement_conformance! {
        mod github_actions_unresolved_requirement_conformance;
        build: GithubActionsEcosystem::new(Arc::new(deps_core::HttpCache::new()));
        reachable: true;
        fixture: ".github/workflows/unresolved.yml" =>
            "on: push\njobs:\n  build:\n    steps:\n      - uses: \"actions/checkout@${{ env.CHECKOUT_REF }}\"\n      - uses: \"actions/setup-node@v4-${{ env.NODE_REF }}\"\n      - uses: \"actions/cache@$(CACHE_REF)\"\n      - uses: \"actions/upload-artifact@$(UPLOAD-REF)\"\n";
    }

    #[test]
    fn test_manifest_routing_filenames_and_directory_patterns() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = GithubActionsEcosystem::new(cache);
        assert!(eco.manifest_patterns().is_empty());
        assert!(eco.manifest_extensions().is_empty());
        assert_eq!(
            eco.manifest_directory_patterns(),
            &[
                (".github/workflows", ".yml"),
                (".github/workflows", ".yaml"),
            ]
        );
    }

    /// S3 (review finding): `test_manifest_routing_filenames_and_directory_patterns`
    /// only asserts the raw lists, not actual `EcosystemRegistry` resolution — this test
    /// exercises real routing so a `directory_pattern_matches`-style bug (S1, the
    /// non-recursive `.github/actions` pattern that never matched the canonical nested
    /// layout) would be caught here rather than only by manual live testing.
    #[test]
    fn test_action_yml_routes_via_registry_at_root_and_nested_under_github_actions() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let registry = deps_core::EcosystemRegistry::new();
        registry.register(Arc::new(GithubActionsEcosystem::new(cache)));

        for path in [
            "/repo/action.yml",
            "/repo/action.yaml",
            "/repo/.github/actions/my-action/action.yml",
            "/repo/.github/actions/my-action/action.yaml",
            "/repo/deeply/nested/.github/actions/my-action/action.yml",
        ] {
            let uri = deps_core::test_util::test_uri(path);
            let eco = registry
                .for_uri(&uri)
                .unwrap_or_else(|| panic!("expected {path} to route to an ecosystem"));
            assert_eq!(eco.id(), "github-actions", "{path}");
        }
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

    fn empty_versions() -> (
        HashMap<deps_core::PackageName, deps_core::PackageVersions>,
        HashMap<deps_core::PackageName, deps_core::ConcreteVersion>,
    ) {
        (HashMap::new(), HashMap::new())
    }

    // --- #706 review (S3): end-to-end coverage for an action.yml-routed document ---
    // The routing tests above only cover routing; these exercise generate_diagnostics/
    // generate_hover against a document parsed from an action.yml URI.

    #[tokio::test]
    async fn test_generate_diagnostics_for_composite_action_yml_flags_tag_pin() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = GithubActionsEcosystem::new(cache);
        let uri = deps_core::test_util::test_uri("/repo/.github/actions/my-action/action.yml");
        let content = "name: My Action\n\
             runs:\n\
             \x20 using: composite\n\
             \x20 steps:\n\
             \x20   - uses: actions/checkout@v4\n";
        let parse_result = eco.parse_manifest(content, &uri).await.unwrap();
        let (cached, resolved) = empty_versions();

        let diagnostics = eco
            .generate_diagnostics(
                parse_result.as_ref(),
                deps_core::VersionData::new(&cached, &resolved),
                &uri,
                deps_core::FreshnessSettings::default(),
                deps_core::lsp_helpers::DiagnosticSeverities::default(),
            )
            .await;

        assert!(
            diagnostics
                .iter()
                .any(|d| d.code() == Some(mutable_ref_pin_code().as_str())),
            "a tag-pinned uses: step inside a composite action.yml must still get the \
             mutable-ref-pin diagnostic: {diagnostics:?}"
        );
    }

    /// Security audit finding (LOW): end-to-end confirmation that a stray, unrelated
    /// `action.yml` (no top-level `runs:` key) degrades gracefully through the full
    /// `generate_diagnostics` path — zero diagnostics, not a panic or a spurious fetch.
    #[tokio::test]
    async fn test_generate_diagnostics_for_non_action_yml_yields_nothing() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = GithubActionsEcosystem::new(cache);
        let uri = deps_core::test_util::test_uri("/repo/tools/action.yml");
        let content = "name: Not Actually a GitHub Action\nuses: internal/base-template@stable\n";
        let parse_result = eco.parse_manifest(content, &uri).await.unwrap();
        assert!(parse_result.dependencies().is_empty());
        let (cached, resolved) = empty_versions();

        let diagnostics = eco
            .generate_diagnostics(
                parse_result.as_ref(),
                deps_core::VersionData::new(&cached, &resolved),
                &uri,
                deps_core::FreshnessSettings::default(),
                deps_core::lsp_helpers::DiagnosticSeverities::default(),
            )
            .await;

        assert!(diagnostics.is_empty(), "{diagnostics:?}");
    }

    #[test]
    fn test_is_in_dependencies_section_uses_line() {
        let content = "jobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n";
        assert!(is_in_dependencies_section(content, 3));
        assert!(!is_in_dependencies_section(content, 0));
    }

    #[test]
    fn test_is_in_dependencies_section_composite_action_uses() {
        let content = "runs:\n  using: composite\n  steps:\n    - uses: actions/setup-node@v4\n";
        assert!(is_in_dependencies_section(content, 3));
    }

    struct MockMetadata {
        name: deps_core::PackageName,
        latest_version: deps_core::ConcreteVersion,
    }
    impl deps_core::Metadata for MockMetadata {
        fn name(&self) -> &deps_core::PackageName {
            &self.name
        }
        fn description(&self) -> Option<&str> {
            None
        }
        fn repository(&self) -> Option<&str> {
            None
        }
        fn documentation(&self) -> Option<&str> {
            None
        }
        fn latest_version(&self) -> &deps_core::ConcreteVersion {
            &self.latest_version
        }
        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    #[test]
    fn test_completion_insert_text() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = GithubActionsEcosystem::new(cache);
        let meta = MockMetadata {
            name: deps_core::PackageName::new("actions/checkout"),
            latest_version: "v4.1.1".into(),
        };
        assert_eq!(
            eco.completion_insert_text(&meta),
            Some("actions/checkout@v4.1.1".to_string())
        );
    }

    #[test]
    fn test_completion_insert_text_rejects_non_owner_repo_shape() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = GithubActionsEcosystem::new(cache);
        let meta = MockMetadata {
            name: deps_core::PackageName::new("checkout"),
            latest_version: "v4.1.1".into(),
        };
        assert!(eco.completion_insert_text(&meta).is_none());
    }

    #[cfg(feature = "lsp-responses")]
    mod lsp_tests {
        use super::*;

        use deps_core::lsp_helpers::splice_resolved_line;

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
            let mut index = TagIndex::default();
            index.tag_to_sha.insert(
                "v4".to_string(),
                deps_core::lsp_helpers::CommitSha::parse(&"a".repeat(40)).unwrap(),
            );
            formatter.tag_index.insert(
                deps_core::PackageName::new("actions/checkout"),
                Arc::new(index),
            );

            let position = deps_core::ParseResult::dependencies(&parse_result)[0]
                .version_range()
                .unwrap()
                .start
                .into();

            let action = build_sha_pin_action(&parse_result, position, &uri, &formatter)
                .expect("expected a Pin-to-commit-SHA quickfix");
            assert!(action.title.contains("Pin") && action.title.contains("commit SHA"));
            let edit = action.edit.as_ref().unwrap();
            let text_edits = edit
                .changes
                .as_ref()
                .unwrap()
                .get(&deps_core::to_ls_uri(&uri))
                .unwrap();
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
            let mut index = TagIndex::default();
            index.tag_to_sha.insert(
                "v4".to_string(),
                deps_core::lsp_helpers::CommitSha::parse(&"a".repeat(40)).unwrap(),
            );
            formatter.tag_index.insert(
                deps_core::PackageName::new("actions/checkout"),
                Arc::new(index),
            );

            let position = deps_core::ParseResult::dependencies(&parse_result)[0]
                .name_range()
                .start
                .into();

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
                .start
                .into();

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
            let mut index = TagIndex::default();
            index.tag_to_sha.insert(
                "main".to_string(),
                deps_core::lsp_helpers::CommitSha::parse(&"a".repeat(40)).unwrap(),
            );
            formatter.tag_index.insert(
                deps_core::PackageName::new("some-org/some-action"),
                Arc::new(index),
            );

            let position = deps_core::ParseResult::dependencies(&parse_result)[0]
                .version_range()
                .unwrap()
                .start
                .into();

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
            let mut index = TagIndex::default();
            index.tag_to_sha.insert(
                "v4".to_string(),
                deps_core::lsp_helpers::CommitSha::parse(&"a".repeat(40)).unwrap(),
            );
            formatter.tag_index.insert(
                deps_core::PackageName::new("actions/checkout"),
                Arc::new(index),
            );

            let position = deps_core::ParseResult::dependencies(&parse_result)[0]
                .version_range()
                .unwrap()
                .start
                .into();

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
            let mut index = TagIndex::default();
            index.tag_to_sha.insert(
                "v4".to_string(),
                deps_core::lsp_helpers::CommitSha::parse(&"a".repeat(40)).unwrap(),
            );
            formatter.tag_index.insert(
                deps_core::PackageName::new("actions/checkout"),
                Arc::new(index),
            );

            let position = deps_core::ParseResult::dependencies(&parse_result)[0]
                .version_range()
                .unwrap()
                .start
                .into();

            assert!(
                build_sha_pin_action(&parse_result, position, &uri, &formatter).is_none(),
                "a flow-mapping uses: step must withhold the quickfix even on a TagIndex hit"
            );
        }

        // #1137: regression guard, not independent parser verification (see
        // `operator_chars_conformance!`'s doc) — `required` mirrors `VERSION_OPERATOR_CHARS`'s
        // own doc comment (a `uses:` ref has no operator syntax), so an edit to one without the
        // other fails loudly instead of silently degrading completion.
        deps_core::operator_chars_conformance! {
            mod github_actions_operator_chars_conformance;
            ecosystem: "github-actions";
            operator_chars: VERSION_OPERATOR_CHARS;
            required: &[];
        }

        fn sha_of(c: char) -> deps_core::lsp_helpers::CommitSha {
            deps_core::lsp_helpers::CommitSha::parse(&c.to_string().repeat(40)).unwrap()
        }

        #[test]
        fn test_splice_resolved_line_after_requirement() {
            let markdown =
                "# actions/checkout\n\n**Requirement**: `v4.2.0`\n\n**Latest**: `v4.3.0`\n";
            let spliced = splice_resolved_line(markdown, "v4.2.0", &sha_of('a'));
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
            let spliced = splice_resolved_line(markdown, "v4.2.0", &sha_of('b'));
            let current_pos = spliced.find("**Current**").unwrap();
            let resolved_pos = spliced.find("**Resolved**").unwrap();
            let requirement_pos = spliced.find("**Requirement**").unwrap();
            assert!(current_pos < resolved_pos);
            assert!(resolved_pos < requirement_pos);
        }

        #[test]
        fn test_splice_resolved_line_falls_back_to_append_when_no_anchor() {
            let markdown = "# actions/checkout\n\nno anchors here\n";
            let spliced = splice_resolved_line(markdown, "v4.2.0", &sha_of('c'));
            assert!(spliced.starts_with(markdown));
            assert!(spliced.contains("**Resolved**"));
        }

        /// #501 (tester finding): the shared `deps_core::generate_hover` gate only sees
        /// `VersionData` and cannot know a `PinStyle::Tag` step still has a real "Pin to commit
        /// SHA" quickfix available via the ecosystem-private `TagIndex`. Seeding the index
        /// directly simulates a fetch that succeeded before the session went offline;
        /// `cache.set_offline(NetworkMode::Offline)` then makes the live fetch this call attempts fail without
        /// touching the network (mirroring `HttpCache`'s real offline-cold behavior), so
        /// `VersionData` carries no signal of its own and only the post-hoc restore can produce
        /// the footer.
        #[tokio::test]
        async fn test_generate_hover_restores_footer_offline_for_tag_pin_with_warm_tag_index() {
            let cache = Arc::new(deps_core::HttpCache::new());
            cache.set_offline(deps_core::NetworkMode::Offline);
            let eco = GithubActionsEcosystem::new(cache);
            let uri = deps_core::test_util::test_uri("/repo/.github/workflows/ci.yml");
            let content = "steps:\n  - uses: actions/checkout@v4\n";
            let parse_result = eco.parse_manifest(content, &uri).await.unwrap();

            let mut index = TagIndex::default();
            index.tag_to_sha.insert(
                "v4".to_string(),
                deps_core::lsp_helpers::CommitSha::parse(&"a".repeat(40)).unwrap(),
            );
            eco.formatter.tag_index.insert(
                deps_core::PackageName::new("actions/checkout"),
                Arc::new(index),
            );

            let position = parse_result.dependencies()[0].name_range().start.into();
            let cached = HashMap::new();
            let resolved = HashMap::new();

            let hover = eco
                .generate_hover(
                    parse_result.as_ref(),
                    position,
                    deps_core::VersionData::new(&cached, &resolved)
                        .with_network(deps_core::NetworkMode::Offline),
                    deps_core::FreshnessSettings::default(),
                )
                .await
                .expect("hover should be generated for the dependency on this line");

            let content = hover.markdown();
            assert!(
                content.contains("Press `Cmd+.` to update version"),
                "a Tag-pinned step with a warm TagIndex entry still offers the SHA-pin quickfix \
             while offline, so the footer must be restored even with no VersionData signal; \
             got: {}",
                content
            );
        }

        /// A SHA pin's `Resolved` line names the tag `TagIndex` ranks most specific for the
        /// commit, even when the commit carries several (including unrelated) tags.
        #[tokio::test]
        async fn test_generate_hover_sha_pin_resolved_uses_most_specific_tag() {
            let sha = "a".repeat(40);
            let cache = Arc::new(deps_core::HttpCache::new());
            cache.set_offline(deps_core::NetworkMode::Offline);
            let eco = GithubActionsEcosystem::new(cache);
            let uri = deps_core::test_util::test_uri("/repo/.github/workflows/ci.yml");
            let content = format!("steps:\n  - uses: actions/checkout@{sha} # v4\n");
            let parse_result = eco.parse_manifest(&content, &uri).await.unwrap();
            let commit = deps_core::lsp_helpers::CommitSha::parse(&sha).unwrap();
            let index =
                TagIndex::from_tags(["v4", "v4.2.2", "v5.0.0"].into_iter().map(|t| (t, &commit)));
            eco.formatter.tag_index.insert(
                deps_core::PackageName::new("actions/checkout"),
                Arc::new(index),
            );
            let expected = index_most_specific(&sha);

            let position = parse_result.dependencies()[0].name_range().start.into();
            let cached = HashMap::new();
            let resolved = HashMap::new();
            let md = eco
                .generate_hover(
                    parse_result.as_ref(),
                    position,
                    deps_core::VersionData::new(&cached, &resolved)
                        .with_network(deps_core::NetworkMode::Offline),
                    deps_core::FreshnessSettings::default(),
                )
                .await
                .expect("hover")
                .markdown()
                .to_string();
            assert!(
                md.contains(&format!("**Resolved**: `{expected}`")),
                "got: {md}"
            );
        }

        fn index_most_specific(sha: &str) -> String {
            let commit = deps_core::lsp_helpers::CommitSha::parse(sha).unwrap();
            TagIndex::from_tags(["v4", "v4.2.2", "v5.0.0"].into_iter().map(|t| (t, &commit)))
                .tag_for_sha(&commit)
                .unwrap()
                .to_string()
        }

        async fn floating_tag_hover(uses_ref: &str, tags: &[(&str, char)]) -> String {
            let cache = Arc::new(deps_core::HttpCache::new());
            cache.set_offline(deps_core::NetworkMode::Offline);
            let eco = GithubActionsEcosystem::new(cache);
            let uri = deps_core::test_util::test_uri("/repo/.github/workflows/ci.yml");
            let content = format!("steps:\n  - uses: actions/checkout@{uses_ref}\n");
            let parse_result = eco.parse_manifest(&content, &uri).await.unwrap();

            let commits: Vec<(&str, deps_core::lsp_helpers::CommitSha)> = tags
                .iter()
                .map(|(tag, c)| {
                    (
                        *tag,
                        deps_core::lsp_helpers::CommitSha::parse(&c.to_string().repeat(40))
                            .unwrap(),
                    )
                })
                .collect();
            let index = TagIndex::from_tags(commits.iter().map(|(t, c)| (*t, c)));
            eco.formatter.tag_index.insert(
                deps_core::PackageName::new("actions/checkout"),
                Arc::new(index),
            );

            let position = parse_result.dependencies()[0].name_range().start.into();
            let cached = HashMap::new();
            let resolved = HashMap::new();
            eco.generate_hover(
                parse_result.as_ref(),
                position,
                deps_core::VersionData::new(&cached, &resolved)
                    .with_network(deps_core::NetworkMode::Offline),
                deps_core::FreshnessSettings::default(),
            )
            .await
            .expect("hover")
            .markdown()
            .to_string()
        }

        /// #1684: a floating `@v4` with a warm index names the release its commit carries.
        #[tokio::test]
        async fn test_generate_hover_floating_tag_shows_resolved_release() {
            let md = floating_tag_hover("v4", &[("v4", 'a'), ("v4.2.2", 'a')]).await;
            assert!(
                md.contains("**Resolved**: `v4.2.2` (`aaaaaaa…`)"),
                "got: {md}"
            );
        }

        /// #1684 (critic N4): a commit carrying only the written tag would yield a
        /// tautological `Resolved v4` line.
        #[tokio::test]
        async fn test_generate_hover_floating_tag_without_specific_release_omits_resolved() {
            let md = floating_tag_hover("v4", &[("v4", 'a')]).await;
            assert!(!md.contains("**Resolved**"), "got: {md}");
        }

        /// #1684: an exact tag keeps showing only its own text.
        #[tokio::test]
        async fn test_generate_hover_exact_tag_omits_resolved() {
            let md = floating_tag_hover("v4.2.2", &[("v4", 'a'), ("v4.2.2", 'a')]).await;
            assert!(!md.contains("**Resolved**"), "got: {md}");
        }

        /// A `PinStyle::Tag` step with no `TagIndex` entry (true cold start, nothing ever
        /// resolved) must not have the footer restored — there is no quickfix to advertise.
        #[tokio::test]
        async fn test_generate_hover_footer_stays_omitted_offline_for_tag_pin_without_tag_index() {
            let cache = Arc::new(deps_core::HttpCache::new());
            cache.set_offline(deps_core::NetworkMode::Offline);
            let eco = GithubActionsEcosystem::new(cache);
            let uri = deps_core::test_util::test_uri("/repo/.github/workflows/ci.yml");
            let content = "steps:\n  - uses: actions/checkout@v4\n";
            let parse_result = eco.parse_manifest(content, &uri).await.unwrap();

            let position = parse_result.dependencies()[0].name_range().start.into();
            let cached = HashMap::new();
            let resolved = HashMap::new();

            let hover = eco
                .generate_hover(
                    parse_result.as_ref(),
                    position,
                    deps_core::VersionData::new(&cached, &resolved)
                        .with_network(deps_core::NetworkMode::Offline),
                    deps_core::FreshnessSettings::default(),
                )
                .await
                .expect("hover should be generated for the dependency on this line");

            let content = hover.markdown();
            assert!(
                !content.contains("Press `Cmd+.` to update version"),
                "no TagIndex entry exists, so there is no quickfix to restore the footer for; \
             got: {}",
                content
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
        async fn test_generate_hover_restores_footer_online_for_bare_major_tag_with_empty_live_list()
         {
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
            let position = parse_result.dependencies()[0].name_range().start.into();
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

            let content = hover.markdown();
            assert!(
                !content.contains("**Recent versions**"),
                "an all-bare-major tag list has zero full-semver entries, so the section \
             must stay omitted; got: {}",
                content
            );
            assert!(
                content.contains("Press `Cmd+.` to update version"),
                "a Tag-pinned step whose live fetch genuinely succeeded empty still has a \
             real SHA-pin quickfix via TagIndex, so the footer must be restored online \
             too, not just offline; got: {}",
                content
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
            cache.set_offline(deps_core::NetworkMode::Offline);
            let eco = GithubActionsEcosystem::new(cache);
            let uri = deps_core::test_util::test_uri("/repo/.github/workflows/ci.yml");
            let content = "steps:\n  - uses: \"actions/checkout@v4\"\n";
            let parse_result = eco.parse_manifest(content, &uri).await.unwrap();

            let mut index = TagIndex::default();
            index.tag_to_sha.insert(
                "v4".to_string(),
                deps_core::lsp_helpers::CommitSha::parse(&"a".repeat(40)).unwrap(),
            );
            eco.formatter.tag_index.insert(
                deps_core::PackageName::new("actions/checkout"),
                Arc::new(index),
            );

            let position = parse_result.dependencies()[0].name_range().start.into();
            let cached = HashMap::new();
            let resolved = HashMap::new();

            let hover = eco
                .generate_hover(
                    parse_result.as_ref(),
                    position,
                    deps_core::VersionData::new(&cached, &resolved)
                        .with_network(deps_core::NetworkMode::Offline),
                    deps_core::FreshnessSettings::default(),
                )
                .await
                .expect("hover should be generated for the dependency on this line");

            let content = hover.markdown();
            assert!(
                !content.contains("Press `Cmd+.` to update version"),
                "a quoted uses: scalar offers no SHA-pin quickfix even on a TagIndex hit, so the \
             footer must not be restored; got: {}",
                content
            );
        }

        /// Regression for #1178: a flow-style `uses:` step (issue #633's
        /// `is_last_on_line == false` scenario — `, with: {...}}` follows the ref on the same
        /// line) must not have the footer restored, even on a `TagIndex` hit. Before #1178 the
        /// hand-rolled eligibility check omitted this `is_last_on_line` condition entirely, so
        /// the footer was wrongly restored for a step whose quickfix `build_sha_pin_action`
        /// itself withholds (see `test_build_sha_pin_action_no_quickfix_for_flow_mapping_step`).
        #[tokio::test]
        async fn test_generate_hover_footer_not_restored_offline_for_flow_mapping_tag_pin() {
            let cache = Arc::new(deps_core::HttpCache::new());
            cache.set_offline(deps_core::NetworkMode::Offline);
            let eco = GithubActionsEcosystem::new(cache);
            let uri = deps_core::test_util::test_uri("/repo/.github/workflows/ci.yml");
            let content = "steps:\n  - {uses: actions/checkout@v4, with: {node: 20}}\n";
            let parse_result = eco.parse_manifest(content, &uri).await.unwrap();
            let gha_dep = parse_result.dependencies()[0]
                .as_any()
                .downcast_ref::<GithubActionsDependency>()
                .unwrap();
            assert!(!gha_dep.is_last_on_line);

            let mut index = TagIndex::default();
            index.tag_to_sha.insert(
                "v4".to_string(),
                deps_core::lsp_helpers::CommitSha::parse(&"a".repeat(40)).unwrap(),
            );
            eco.formatter.tag_index.insert(
                deps_core::PackageName::new("actions/checkout"),
                Arc::new(index),
            );

            let position = parse_result.dependencies()[0].name_range().start.into();
            let cached = HashMap::new();
            let resolved = HashMap::new();

            let hover = eco
                .generate_hover(
                    parse_result.as_ref(),
                    position,
                    deps_core::VersionData::new(&cached, &resolved)
                        .with_network(deps_core::NetworkMode::Offline),
                    deps_core::FreshnessSettings::default(),
                )
                .await
                .expect("hover should be generated for the dependency on this line");

            let content = hover.markdown();
            assert!(
                !content.contains(deps_core::lsp_helpers::CMD_DOT_FOOTER),
                "a flow-style uses: step is not the last token on its line, so appending a SHA \
             pin comment would produce invalid YAML; the footer must not be restored even \
             on a TagIndex hit; got: {}",
                content
            );
        }

        /// #1709/#1718: an advisory introduced in `v4.9.0` is reported against an exact `@v4.8.0`
        /// pin whose commit also carries `v4.9.0`, and hover/diagnostics name that release tag.
        #[tokio::test]
        async fn test_sibling_release_tag_match_is_named_in_hover_and_diagnostics() {
            use deps_core::ConcreteVersion;
            use deps_core::lsp_helpers::CommitSha;
            use deps_core::osv::{OsvClient, OsvPackageName, OsvQueryName, ScanTarget};

            let cache = Arc::new(deps_core::HttpCache::new());
            let eco = GithubActionsEcosystem::new(Arc::clone(&cache));
            let name = "actions/checkout";
            let sha = CommitSha::parse(&"a".repeat(40)).unwrap();
            eco.formatter.tag_index.insert(
                deps_core::PackageName::new(name),
                Arc::new(TagIndex::from_tags([("v4.8.0", &sha), ("v4.9.0", &sha)])),
            );

            let mut server = mockito::Server::new_async().await;
            let _batch = server
                .mock("POST", "/v1/querybatch")
                .with_status(200)
                .with_body(r#"{"results":[{"vulns":[{"id":"GHSA-aaaa-bbbb-cccc","modified":"2025-01-01T00:00:00Z"}]}]}"#)
                .create_async()
                .await;
            let _record = server
                .mock("GET", "/v1/vulns/GHSA-aaaa-bbbb-cccc")
                .with_status(200)
                .with_body(
                    r#"{"id":"GHSA-aaaa-bbbb-cccc","modified":"2025-01-01T00:00:00Z","summary":"Introduced late",
                    "affected":[{"package":{"name":"actions/checkout","ecosystem":"GitHub Actions"},
                    "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"4.9.0"},{"fixed":"4.9.1"}]}]}]}"#,
                )
                .create_async()
                .await;
            let osv = OsvClient::for_test(cache, server.url());
            let target = ScanTarget::from_native(
                deps_core::test_util::vuln_key(name),
                OsvQueryName::Confirmed(OsvPackageName::new(name).unwrap()),
                ConcreteVersion::new("v4.8.0"),
                &eco.formatter,
            )
            .with_siblings(
                &deps_core::lsp_helpers::InUseVersions::for_test(
                    ConcreteVersion::new("v4.8.0"),
                    vec![ConcreteVersion::new("v4.9.0")],
                ),
                &eco.formatter,
            );
            let vulns = osv
                .scan(
                    deps_core::EcosystemId::GithubActions,
                    &[target],
                    std::time::Duration::from_secs(30),
                )
                .await;

            let uri = deps_core::test_util::test_uri("/repo/.github/workflows/ci.yml");
            let parse_result = eco
                .parse_manifest("steps:\n  - uses: actions/checkout@v4.8.0\n", &uri)
                .await
                .unwrap();
            let (cached, resolved) = empty_versions();
            let versions =
                || deps_core::VersionData::new(&cached, &resolved).with_vulnerabilities(&vulns);

            let diagnostics = eco
                .generate_diagnostics(
                    parse_result.as_ref(),
                    versions(),
                    &uri,
                    deps_core::FreshnessSettings::default(),
                    deps_core::lsp_helpers::DiagnosticSeverities::default(),
                )
                .await;
            assert!(
                diagnostics
                    .iter()
                    .any(|d| d.message().contains("(matched release tag v4.9.0)")),
                "{diagnostics:?}"
            );

            let hover = eco
                .generate_hover(
                    parse_result.as_ref(),
                    Position::new(1, 30),
                    versions().with_network(deps_core::NetworkMode::Offline),
                    deps_core::FreshnessSettings::default(),
                )
                .await
                .expect("hover");
            assert!(
                hover.markdown().contains(r"matched release tag v4\.9\.0"),
                "{}",
                hover.markdown()
            );
        }

        // --- issue #633/#640: bulk "Pin all to SHA" collector + lens ---

        fn seed_tag(eco: &GithubActionsEcosystem, name: &str, tag: &str, sha: &str) {
            let mut index = TagIndex::default();
            index.tag_to_sha.insert(
                tag.to_string(),
                deps_core::lsp_helpers::CommitSha::parse(sha).unwrap(),
            );
            eco.formatter
                .tag_index
                .insert(deps_core::PackageName::new(name), Arc::new(index));
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

        /// #907 review follow-up (code review): the "Update N outdated dependencies" code
        /// lens (`collect_update_all_edits`, shared `deps-core` logic) must agree with
        /// inlay hints/diagnostics on a SHA pin's status. Here the SHA's registry-confirmed
        /// tag (`TagIndex.sha_to_tag`) is `v4.0.0`, genuinely behind `latest` `v4.3.1`, even
        /// though the human-written comment (`# v4`) matches at major-only precision — the
        /// lens must count and edit it as outdated, not silently exclude it.
        #[tokio::test]
        async fn test_collect_update_all_edits_counts_sha_pin_outdated_via_tag_index_ground_truth()
        {
            let cache = Arc::new(deps_core::HttpCache::new());
            let eco = GithubActionsEcosystem::new(cache);
            let sha = "a".repeat(40);
            let mut index = TagIndex::default();
            index.insert_sha_pin(
                deps_core::lsp_helpers::CommitSha::parse(&sha).unwrap(),
                deps_core::lsp_helpers::ResolvedPin::most_specific(
                    deps_core::ConcreteVersion::new("v4.0.0"),
                ),
            );
            // Needed so `format_version_replacing_for` produces a real replacement for `latest`,
            // or a `tag_to_sha` miss falls back to the unchanged literal and drops the edit.
            index.tag_to_sha.insert(
                "v4.3.1".to_string(),
                deps_core::lsp_helpers::CommitSha::parse(&"b".repeat(40)).unwrap(),
            );
            eco.formatter.tag_index.insert(
                deps_core::PackageName::new("actions/checkout"),
                Arc::new(index),
            );

            let uri = deps_core::test_util::test_uri("/repo/.github/workflows/ci.yml");
            let content = format!("steps:\n  - uses: actions/checkout@{sha} # v4\n");
            let parse_result = eco.parse_manifest(&content, &uri).await.unwrap();

            let mut cached = HashMap::new();
            cached.insert(
                deps_core::PackageName::new("actions/checkout"),
                deps_core::PackageVersions::latest_only("v4.3.1"),
            );
            let resolved = HashMap::new();
            let versions = deps_core::VersionData::new(&cached, &resolved);

            let edits = deps_core::lsp_helpers::collect_update_all_edits(
                parse_result.as_ref(),
                &content,
                versions,
                &eco.formatter,
            );

            assert_eq!(
                edits.len(),
                1,
                "the SHA's real tag v4.0.0 is behind latest v4.3.1 and must be counted as \
             outdated, even though its comment says v4 (which matches v4.3.1 at \
             major-only precision)"
            );
        }

        /// #1720: full-SHA pins absent from the populated release index must be reported
        /// consistently by diagnostics, inlay hints, the update-all lens and hover, while a
        /// control pin on latest's commit gets none of them. Code actions are not driven here:
        /// the shared default fetches the live registry, overwriting the seeded `TagIndex`.
        #[cfg(feature = "lsp-responses")]
        #[tokio::test]
        async fn test_sha_pin_missing_from_index_surfaces_agree() {
            use tower_lsp_server::ls_types::InlayHintLabel;

            let cache = Arc::new(deps_core::HttpCache::new());
            let eco = GithubActionsEcosystem::new(cache);
            let name = "EmbarkStudios/cargo-deny-action";
            let latest_sha = "3".repeat(40);
            let (missing_a, missing_b) = ("5".repeat(40), "6".repeat(40));
            let index = TagIndex::from_tags([(
                "v2.87.22",
                &deps_core::lsp_helpers::CommitSha::parse(&latest_sha).unwrap(),
            )]);
            eco.formatter
                .tag_index
                .insert(deps_core::PackageName::new(name), Arc::new(index));

            let uri = deps_core::test_util::test_uri("/repo/.github/workflows/ci.yml");
            let content = format!(
                "steps:\n\
                 \x20 - uses: {name}@{missing_a}\n\
                 \x20 - uses: {name}@{missing_a} # cargo-deny\n\
                 \x20 - uses: {name}@{missing_b}\n\
                 \x20 - uses: {name}@{missing_b} # cargo-deny\n\
                 \x20 - uses: {name}@{latest_sha} # cargo-deny\n"
            );
            let parse_result = eco.parse_manifest(&content, &uri).await.unwrap();
            let mut cached = HashMap::new();
            cached.insert(
                deps_core::PackageName::new(name),
                deps_core::PackageVersions::latest_only("v2.87.22"),
            );
            let resolved = HashMap::new();
            let versions = || deps_core::VersionData::new(&cached, &resolved);
            let outdated_lines = [1_u32, 2, 3, 4];
            let control_line = 5_u32;

            let diagnostics = eco
                .generate_diagnostics(
                    parse_result.as_ref(),
                    versions(),
                    &uri,
                    deps_core::FreshnessSettings::default(),
                    deps_core::lsp_helpers::DiagnosticSeverities::default(),
                )
                .await;
            let mut diagnostic_lines: Vec<u32> = diagnostics
                .iter()
                .filter(|d| d.message().contains("Newer version available"))
                .map(|d| d.range.start.line)
                .collect();
            diagnostic_lines.sort_unstable();
            assert_eq!(diagnostic_lines, outdated_lines, "{diagnostics:?}");

            let edits = deps_core::lsp_helpers::collect_update_all_edits(
                parse_result.as_ref(),
                &content,
                versions(),
                &eco.formatter,
            );
            let mut edit_lines: Vec<u32> = edits.iter().map(|e| e.range.start.line).collect();
            edit_lines.sort_unstable();
            assert_eq!(edit_lines, outdated_lines, "{edits:?}");
            assert!(edits.iter().all(|e| e.new_text.starts_with(&latest_sha)));

            let hints = eco
                .generate_inlay_hints(
                    parse_result.as_ref(),
                    versions(),
                    deps_core::LoadingState::Loaded,
                    &deps_core::EcosystemConfig::default(),
                )
                .await;
            let names_latest = |line: u32| {
                hints.iter().any(|h| {
                    h.position.line == line
                        && matches!(&h.label, InlayHintLabel::String(t) if t.contains("v2.87.22"))
                })
            };
            for line in outdated_lines {
                assert!(names_latest(line), "line {line}: {hints:?}");
            }
            assert!(!names_latest(control_line), "control: {hints:?}");

            for line in outdated_lines {
                let hover = eco
                    .generate_hover(
                        parse_result.as_ref(),
                        Position::new(line, 40),
                        versions().with_network(deps_core::NetworkMode::Offline),
                        deps_core::FreshnessSettings::default(),
                    )
                    .await
                    .expect("hover");
                assert!(
                    hover
                        .markdown()
                        .contains(deps_core::lsp_helpers::CMD_DOT_FOOTER),
                    "line {line}: {}",
                    hover.markdown()
                );
            }
        }

        /// #1724: for every YAML scalar style, "Newer version available" diagnostics and the
        /// planned update-all edits must agree, and applying the edit must re-parse as up to
        /// date with the quoting/flow structure intact.
        #[tokio::test]
        async fn test_sha_pin_update_edit_agrees_with_diagnostic_for_every_scalar_style() {
            let cache = Arc::new(deps_core::HttpCache::new());
            let eco = GithubActionsEcosystem::new(cache);
            let (old, new) = ("a".repeat(40), "b".repeat(40));
            let name = "actions/checkout";
            let index = TagIndex::from_tags([
                (
                    "v4.0.0",
                    &deps_core::lsp_helpers::CommitSha::parse(&old).unwrap(),
                ),
                (
                    "v4.3.1",
                    &deps_core::lsp_helpers::CommitSha::parse(&new).unwrap(),
                ),
            ]);
            eco.formatter
                .tag_index
                .insert(deps_core::PackageName::new(name), Arc::new(index));

            let mut cached = HashMap::new();
            cached.insert(
                deps_core::PackageName::new(name),
                deps_core::PackageVersions::latest_only("v4.3.1"),
            );
            let resolved = HashMap::new();
            let uri = deps_core::test_util::test_uri("/repo/.github/workflows/ci.yml");

            let cases = [
                (
                    format!("  - uses: {name}@{old}"),
                    format!("  - uses: {name}@{new} # v4.3.1"),
                ),
                (
                    format!("  - uses: {name}@{old} # v4.0.0"),
                    format!("  - uses: {name}@{new} # v4.3.1"),
                ),
                (
                    format!("  - uses: '{name}@{old}'"),
                    format!("  - uses: '{name}@{new}'"),
                ),
                (
                    format!("  - uses: \"{name}@{old}\""),
                    format!("  - uses: \"{name}@{new}\""),
                ),
                (
                    format!("  - {{uses: {name}@{old}, with: {{x: 1}}}}"),
                    format!("  - {{uses: {name}@{new}, with: {{x: 1}}}}"),
                ),
                (
                    format!("  - {{uses: {name}@{old}}}"),
                    format!("  - {{uses: {name}@{new}}}"),
                ),
                (
                    format!("  - uses: '{name}@{old}' # v4.0.0"),
                    format!("  - uses: '{name}@{new}' # v4.3.1"),
                ),
                (
                    format!("  - uses: \"{name}@{old}\" # v4.0.0"),
                    format!("  - uses: \"{name}@{new}\" # v4.3.1"),
                ),
                (
                    format!("  - {{uses: {name}@{old}}} # v4.0.0"),
                    format!("  - {{uses: {name}@{new}}} # v4.3.1"),
                ),
                (
                    format!("  - {{uses: \"{name}@{old}\"}} # v4.0.0"),
                    format!("  - {{uses: \"{name}@{new}\"}} # v4.3.1"),
                ),
                (
                    format!("  - {{uses: '{name}@{old}'}} # v4.0.0"),
                    format!("  - {{uses: '{name}@{new}'}} # v4.3.1"),
                ),
                (
                    format!("  - {{ uses: {name}@{old} }} # v4.0.0"),
                    format!("  - {{ uses: {name}@{new} }} # v4.3.1"),
                ),
                (
                    format!("  - {{uses: {name}@{old}\t}} # v4.0.0"),
                    format!("  - {{uses: {name}@{new}\t}} # v4.3.1"),
                ),
                (
                    format!("  - {{ uses: \"{name}@{old}\" }} # v4.0.0"),
                    format!("  - {{ uses: \"{name}@{new}\" }} # v4.3.1"),
                ),
                (
                    format!("  - {{ uses: {name}@{old} }}"),
                    format!("  - {{ uses: {name}@{new} }}"),
                ),
                (
                    format!("  - {{uses: {name}@{old}, with: {{x: 1}}}} # v4.0.0"),
                    format!("  - {{uses: {name}@{new}, with: {{x: 1}}}} # v4.0.0"),
                ),
            ];

            let newer_count = |diagnostics: &[Diagnostic]| {
                diagnostics
                    .iter()
                    .filter(|d| d.message().contains("Newer version available"))
                    .count()
            };
            for (line, expected_line) in cases {
                let content = format!("steps:\n{line}\n");
                let parse_result = eco.parse_manifest(&content, &uri).await.unwrap();
                let versions = deps_core::VersionData::new(&cached, &resolved);
                let diagnostics = eco
                    .generate_diagnostics(
                        parse_result.as_ref(),
                        versions,
                        &uri,
                        deps_core::FreshnessSettings::default(),
                        deps_core::lsp_helpers::DiagnosticSeverities::default(),
                    )
                    .await;
                let planned = deps_core::edit::collect_update_edits(
                    parse_result.as_ref(),
                    &content,
                    versions,
                    &eco.formatter,
                );
                assert_eq!(newer_count(&diagnostics), 1, "{line}: {diagnostics:?}");
                assert_eq!(
                    planned.len(),
                    1,
                    "{line}: diagnostic without a planned edit"
                );

                let edits: Vec<_> = planned.into_iter().map(|p| p.edit).collect();
                let applied = deps_core::edit::apply_edits(&content, &edits);
                assert_eq!(applied, format!("steps:\n{expected_line}\n"), "{line}");

                let reparsed = eco.parse_manifest(&applied, &uri).await.unwrap();
                let after = eco
                    .generate_diagnostics(
                        reparsed.as_ref(),
                        versions,
                        &uri,
                        deps_core::FreshnessSettings::default(),
                        deps_core::lsp_helpers::DiagnosticSeverities::default(),
                    )
                    .await;
                assert_eq!(newer_count(&after), 0, "{line}: not idempotent: {after:?}");
                // A comment after a flow mapping with sibling keys is deliberately not
                // attributed to the ref, so the stale `# v4.0.0` left behind is not flagged.
                assert!(
                    after
                        .iter()
                        .all(|d| d.code() != Some(SHA_COMMENT_MISMATCH_DIAGNOSTIC_CODE)),
                    "{line}: {after:?}"
                );
            }
        }

        fn mismatch_fixture() -> (GithubActionsEcosystem, String, [String; 3]) {
            let cache = Arc::new(deps_core::HttpCache::new());
            let eco = GithubActionsEcosystem::new(cache);
            let (a, b, missing) = ("a".repeat(40), "b".repeat(40), "c".repeat(40));
            let index = TagIndex::from_tags([
                (
                    "v2.87.20",
                    &deps_core::lsp_helpers::CommitSha::parse(&a).unwrap(),
                ),
                (
                    "v2.87.22",
                    &deps_core::lsp_helpers::CommitSha::parse(&b).unwrap(),
                ),
            ]);
            eco.formatter
                .tag_index
                .insert(deps_core::PackageName::new("owner/action"), Arc::new(index));
            (eco, "owner/action".to_string(), [a, b, missing])
        }

        /// Applies the single text edit of `action` to a one-edit-per-line ASCII `content`.
        #[cfg(feature = "lsp-responses")]
        fn apply_single_edit(content: &str, uri: &Url, action: &CodeAction) -> String {
            let edits = action
                .edit
                .as_ref()
                .and_then(|edit| edit.changes.as_ref())
                .and_then(|changes| changes.get(&deps_core::to_ls_uri(uri)))
                .expect("one file edit");
            assert_eq!(edits.len(), 1);
            let edit = &edits[0];
            assert_eq!(edit.range.start.line, edit.range.end.line);
            let mut lines: Vec<String> = content.lines().map(str::to_string).collect();
            let line = &mut lines[edit.range.start.line as usize];
            line.replace_range(
                edit.range.start.character as usize..edit.range.end.character as usize,
                &edit.new_text,
            );
            lines.join("\n") + "\n"
        }

        #[cfg(feature = "lsp-responses")]
        fn comment_fix_at(
            eco: &GithubActionsEcosystem,
            content: &str,
            dep_index: usize,
        ) -> Option<(CodeAction, String)> {
            let uri = deps_core::test_util::test_uri("/repo/.github/workflows/ci.yml");
            let parse_result = crate::parser::parse_workflow_yaml(content, &uri).unwrap();
            let range = deps_core::ParseResult::dependencies(&parse_result)[dep_index]
                .version_range()
                .unwrap();
            let action = build_sha_comment_fix_action(
                &parse_result,
                Position::new(range.start.line, range.start.character),
                &uri,
                &eco.formatter,
            )?;
            let fixed = apply_single_edit(content, &uri, &action);
            Some((action, fixed))
        }

        /// #1734: a mismatching comment gets a quickfix that rewrites only the tag token,
        /// keeping the written SHA casing and the closing delimiters, for the latest SHA and
        /// an older one alike; the corrected pin no longer mismatches.
        #[cfg(feature = "lsp-responses")]
        #[test]
        fn test_sha_comment_fix_rewrites_only_the_tag_token() {
            let (eco, name, [a, b, _missing]) = mismatch_fixture();
            let upper = a.to_ascii_uppercase();
            let content = format!(
                "steps:\n\
                 \x20 - uses: {name}@{upper} # v2.87.22\n\
                 \x20 - uses: {name}@{b} # v2.87.20\n\
                 \x20 - uses: \"{name}@{a}\" # v2.86\n\
                 \x20 - {{uses: {name}@{a}}} # v1\n"
            );
            let cases = [
                (0, format!("{upper} # v2.87.20"), "v2.87.20"),
                (1, format!("{b} # v2.87.22"), "v2.87.22"),
                (2, format!("{a}\" # v2.87.20"), "v2.87.20"),
                (3, format!("{a}}} # v2.87.20"), "v2.87.20"),
            ];
            for (dep_index, expected_literal, tag) in cases {
                let (action, fixed) = comment_fix_at(&eco, &content, dep_index)
                    .unwrap_or_else(|| panic!("dep {dep_index} must offer the comment fix"));
                assert_eq!(
                    action.title,
                    format!("Correct version comment to `{tag}`"),
                    "dep {dep_index}"
                );
                assert_eq!(
                    action.kind,
                    Some(tower_lsp_server::ls_types::CodeActionKind::QUICKFIX)
                );
                let fixed_line = fixed.lines().nth(dep_index + 1).unwrap();
                assert!(fixed_line.contains(&expected_literal), "{fixed_line}");
                assert!(
                    comment_fix_at(&eco, &fixed, dep_index).is_none(),
                    "{fixed_line}"
                );
            }
        }

        fn eco_with_single_tag(tag: &str) -> (GithubActionsEcosystem, String, String) {
            let eco = GithubActionsEcosystem::new(Arc::new(deps_core::HttpCache::new()));
            let sha = "a".repeat(40);
            let commit = deps_core::lsp_helpers::CommitSha::parse(&sha).unwrap();
            eco.formatter.tag_index.insert(
                deps_core::PackageName::new("owner/action"),
                Arc::new(TagIndex::from_tags([(tag, &commit)])),
            );
            let content = format!("steps:\n  - uses: owner/action@{sha} # v0.9.0\n");
            (eco, sha, content)
        }

        /// #1734 (impl-critic S2): registry tag text is never spliced into the manifest unless
        /// it is a plain, sanitized, bounded version tag.
        #[cfg(feature = "lsp-responses")]
        #[test]
        fn test_sha_comment_fix_withheld_for_unsafe_or_non_release_tags() {
            let overlong = format!("v1.0.0-{}", "a".repeat(300));
            for tag in [
                "v1.0.0\u{200B}",
                "v1.0.\u{202E}0",
                "v1.0.0\u{0007}",
                "cargo-deny",
                "v1.0.0.1",
                overlong.as_str(),
            ] {
                let (eco, _sha, content) = eco_with_single_tag(tag);
                assert!(
                    comment_fix_at(&eco, &content, 0).is_none(),
                    "{tag:?} must not be offered"
                );
            }
            let (eco, _sha, content) = eco_with_single_tag("v1.0.0");
            assert!(comment_fix_at(&eco, &content, 0).is_some());
        }

        /// #1734: a fix is withheld for a token with trailing punctuation (`v4-beta,`), whose
        /// corrected form would not re-parse as a comment tag; a clean token re-parses
        /// confirmed after the edit.
        #[cfg(feature = "lsp-responses")]
        #[test]
        fn test_sha_comment_fix_is_idempotent_or_withheld() {
            let (eco, sha, _) = eco_with_single_tag("v4.0.0");
            let punctuated = format!("steps:\n  - uses: owner/action@{sha} # v4-beta, pinned\n");
            assert!(comment_fix_at(&eco, &punctuated, 0).is_none());

            let clean = format!("steps:\n  - uses: owner/action@{sha} # v4-beta pinned\n");
            let (_, fixed) = comment_fix_at(&eco, &clean, 0).expect("fix offered");
            let uri = deps_core::test_util::test_uri("/repo/.github/workflows/ci.yml");
            let reparsed = crate::parser::parse_workflow_yaml(&fixed, &uri).unwrap();
            assert_eq!(
                reparsed.dependencies[0].sha_comment().unwrap().tag(),
                "v4.0.0"
            );
            assert!(comment_fix_at(&eco, &fixed, 0).is_none());
        }

        /// #1734: nothing to correct, or nothing to correct *to*, offers no fix.
        #[cfg(feature = "lsp-responses")]
        #[test]
        fn test_sha_comment_fix_absent_unless_another_tag_is_proven() {
            let (eco, name, [a, b, missing]) = mismatch_fixture();
            let content = format!(
                "steps:\n\
                 \x20 - uses: {name}@{b} # v2.87.22\n\
                 \x20 - uses: {name}@{a} # v2.87\n\
                 \x20 - uses: {name}@{a}\n\
                 \x20 - uses: {name}@{missing} # v2.87.22\n"
            );
            for dep_index in 0..4 {
                assert!(
                    comment_fix_at(&eco, &content, dep_index).is_none(),
                    "dep {dep_index}"
                );
            }
            let cold = GithubActionsEcosystem::new(Arc::new(deps_core::HttpCache::new()));
            assert!(comment_fix_at(&cold, &content, 1).is_none());
        }

        async fn diagnostics_with_code(
            eco: &GithubActionsEcosystem,
            content: &str,
            severities: deps_core::lsp_helpers::DiagnosticSeverities,
            code: &str,
        ) -> Vec<Diagnostic> {
            let uri = deps_core::test_util::test_uri("/repo/.github/workflows/ci.yml");
            let parse_result = eco.parse_manifest(content, &uri).await.unwrap();
            let mut cached = HashMap::new();
            cached.insert(
                deps_core::PackageName::new("owner/action"),
                deps_core::PackageVersions::latest_only("v2.87.22"),
            );
            let resolved = HashMap::new();
            eco.generate_diagnostics(
                parse_result.as_ref(),
                deps_core::VersionData::new(&cached, &resolved),
                &uri,
                deps_core::FreshnessSettings::default(),
                severities,
            )
            .await
            .into_iter()
            .filter(|d| d.code() == Some(code))
            .collect()
        }

        async fn unknown_ref_diagnostics_for(
            eco: &GithubActionsEcosystem,
            content: &str,
            severities: deps_core::lsp_helpers::DiagnosticSeverities,
        ) -> Vec<Diagnostic> {
            diagnostics_with_code(
                eco,
                content,
                severities,
                deps_core::lsp_helpers::UNKNOWN_REF_DIAGNOSTIC_CODE,
            )
            .await
        }

        /// #1766: only a full release the complete tag list lacks is reported, at the configured
        /// severity; partial shapes (possible branch pins, `@v40` included) never are.
        #[tokio::test]
        async fn test_unknown_ref_diagnostic_only_for_unpublished_full_release() {
            let (eco, name, [a, ..]) = mismatch_fixture();
            let content = format!(
                "steps:\n\
                 \x20 - uses: {name}@2.87.22\n\
                 \x20 - uses: {name}@v2.87.99\n\
                 \x20 - uses: {name}@v2.87.22\n\
                 \x20 - uses: {name}@v1\n\
                 \x20 - uses: {name}@v40\n\
                 \x20 - uses: {name}@v3.4.0-working\n\
                 \x20 - uses: {name}@v3-node20\n\
                 \x20 - uses: {name}@{a}\n"
            );

            let found = unknown_ref_diagnostics_for(
                &eco,
                &content,
                deps_core::lsp_helpers::DiagnosticSeverities::default(),
            )
            .await;
            let lines: Vec<u32> = found.iter().map(|d| d.range.start.line).collect();
            assert_eq!(lines, [1, 2], "{found:?}");
            assert!(found.iter().all(|d| d.severity == Some(Severity::Warning)));
            assert_eq!(
                found[0].message(),
                "`2.87.22` is not a published tag of owner/action"
            );
            assert_eq!(found[0].range.start.character, 23);
            assert_eq!(found[0].range.end.character, 30);

            let hint = unknown_ref_diagnostics_for(
                &eco,
                &content,
                deps_core::lsp_helpers::DiagnosticSeverities::default()
                    .with_unknown_ref(Severity::Hint),
            )
            .await;
            assert!(hint.iter().all(|d| d.severity == Some(Severity::Hint)));
        }

        /// #1781: the quick fix rewrites exactly the unpublished ref to the published spelling,
        /// exactly where the diagnostic fires, and the rewritten pin no longer reports.
        #[cfg(feature = "lsp-responses")]
        #[test]
        fn test_unknown_ref_fix_rewrites_the_ref_where_the_diagnostic_fires() {
            let (eco, name, [a, ..]) = mismatch_fixture();
            let content = format!(
                "steps:\n\
                 \x20 - uses: {name}@2.87.22\n\
                 \x20 - uses: {name}@v2.87.99\n\
                 \x20 - uses: {name}@v40\n\
                 \x20 - uses: {name}@{a}\n"
            );
            let uri = deps_core::test_util::test_uri("/repo/.github/workflows/ci.yml");
            let parse_result = crate::parser::parse_workflow_yaml(&content, &uri).unwrap();
            let fix_at = |dep_index: usize, text: &str| {
                let range = deps_core::ParseResult::dependencies(&parse_result)[dep_index]
                    .version_range()
                    .unwrap();
                let position = Position::new(range.start.line, range.start.character);
                build_unknown_ref_fix_action(&parse_result, position, &uri, &eco.formatter)
                    .map(|action| (action.title.clone(), apply_single_edit(text, &uri, &action)))
            };

            let (title, fixed) = fix_at(0, &content).expect("2.87.22 has a published spelling");
            assert_eq!(title, "Change ref to published tag `v2.87.22`");
            assert!(fixed.contains(&format!("{name}@v2.87.22\n")), "{fixed}");
            assert!(fix_at(1, &content).is_none(), "no tag matches v2.87.99");
            assert!(
                fix_at(2, &content).is_none(),
                "a partial shape may be a branch"
            );
            assert!(fix_at(3, &content).is_none(), "a SHA pin is not a tag pin");
        }

        /// #1766: a cold, empty or truncated tag list proves nothing, so nothing is reported.
        #[tokio::test]
        async fn test_unknown_ref_diagnostic_silent_without_a_complete_tag_list() {
            let content = "steps:\n  - uses: owner/action@2.87.22\n";
            let severities = deps_core::lsp_helpers::DiagnosticSeverities::default();

            let cold = GithubActionsEcosystem::new(Arc::new(deps_core::HttpCache::new()));
            assert!(
                unknown_ref_diagnostics_for(&cold, content, severities)
                    .await
                    .is_empty()
            );

            let (eco, ..) = mismatch_fixture();
            let sha = deps_core::lsp_helpers::CommitSha::parse(&"a".repeat(40)).unwrap();
            eco.formatter.tag_index.insert(
                deps_core::PackageName::new("owner/action"),
                Arc::new(
                    TagIndex::from_tags([("v2.87.20", &sha)])
                        .with_coverage(deps_core::pagination::ListCoverage::Truncated),
                ),
            );
            assert!(
                unknown_ref_diagnostics_for(&eco, content, severities)
                    .await
                    .is_empty()
            );
        }

        async fn sha_comment_diagnostics(
            eco: &GithubActionsEcosystem,
            content: &str,
            severities: deps_core::lsp_helpers::DiagnosticSeverities,
        ) -> Vec<Diagnostic> {
            diagnostics_with_code(
                eco,
                content,
                severities,
                SHA_COMMENT_MISMATCH_DIAGNOSTIC_CODE,
            )
            .await
        }

        /// #1722: exactly the provable mismatches are reported, at the configured severity,
        /// independent of `mutable_ref_pin_enabled`.
        #[tokio::test]
        async fn test_sha_comment_mismatch_diagnostic_only_for_provable_mismatch() {
            let (eco, name, [a, b, missing]) = mismatch_fixture();
            let content = format!(
                "steps:\n\
                 \x20 - uses: {name}@{a} # v2.87.22\n\
                 \x20 - uses: {name}@{missing} # v2.87.22\n\
                 \x20 - uses: {name}@{b} # v2.87.22\n\
                 \x20 - uses: {name}@{a} # v2.87\n\
                 \x20 - uses: {name}@{a}\n\
                 \x20 - uses: '{name}@{missing}'\n"
            );

            let default = sha_comment_diagnostics(
                &eco,
                &content,
                deps_core::lsp_helpers::DiagnosticSeverities::default()
                    .with_mutable_ref_pin_enabled(false),
            )
            .await;
            let lines: Vec<u32> = default.iter().map(|d| d.range.start.line).collect();
            assert_eq!(lines, [1, 2], "{default:?}");
            let expected_end = 23 + 40 + " # v2.87.22".len() as u32;
            for d in &default {
                assert_eq!(d.range.start.character, 23, "{d:?}");
                assert_eq!(d.range.end.character, expected_end, "{d:?}");
            }
            assert!(
                default
                    .iter()
                    .all(|d| d.severity == Some(Severity::Warning))
            );
            assert!(
                default[0].message().contains("it is `v2.87.20`"),
                "{default:?}"
            );
            assert!(
                default[1]
                    .message()
                    .contains("not the commit of any release tag"),
                "{default:?}"
            );

            let loud = sha_comment_diagnostics(
                &eco,
                &content,
                deps_core::lsp_helpers::DiagnosticSeverities::default()
                    .with_sha_comment_mismatch(Severity::Error),
            )
            .await;
            assert_eq!(loud.len(), 2);
            assert!(loud.iter().all(|d| d.severity == Some(Severity::Error)));
        }

        /// #1732: quoted and flow-mapping SHA pins with a trailing comment are checked for a
        /// mismatch too, with the range spanning the closing delimiters and the comment;
        /// a flow mapping with sibling keys is not.
        #[tokio::test]
        async fn test_sha_comment_mismatch_diagnostic_for_quoted_and_flow_forms() {
            let (eco, name, [a, _b, _missing]) = mismatch_fixture();
            let content = format!(
                "steps:\n\
                 \x20 - uses: \"{name}@{a}\" # v2.87.22\n\
                 \x20 - uses: '{name}@{a}' # v2.87.22\n\
                 \x20 - {{uses: {name}@{a}}} # v2.87.22\n\
                 \x20 - {{uses: \"{name}@{a}\"}} # v2.87.22\n\
                 \x20 - {{uses: {name}@{a}, name: x}} # v2.87.22\n\
                 \x20 - {{name: \"日本\", uses: \"{name}@{a}\"}} # v2.87.22\n\
                 \x20 - {{ uses: {name}@{a} }} # v2.87.22\n\
                 \x20 - {{uses: {name}@{a}\t}} # v2.87.22\n"
            );
            let found = sha_comment_diagnostics(
                &eco,
                &content,
                deps_core::lsp_helpers::DiagnosticSeverities::default(),
            )
            .await;
            let lines: Vec<u32> = found.iter().map(|d| d.range.start.line).collect();
            assert_eq!(lines, [1, 2, 3, 4, 6, 7, 8], "{found:?}");
            let widths: Vec<u32> = found
                .iter()
                .map(|d| d.range.end.character - d.range.start.character)
                .collect();
            let tail = " # v2.87.22".len() as u32;
            assert_eq!(
                widths,
                [
                    41 + tail,
                    41 + tail,
                    41 + tail,
                    42 + tail,
                    42 + tail,
                    42 + tail,
                    42 + tail
                ],
                "{found:?}"
            );
        }

        /// #1732: a commentless flow-mapping pin must not gain a ` # tag` that would
        /// swallow its closing `}` (#633); the rewrite stays a bare-SHA swap.
        #[tokio::test]
        async fn test_commentless_flow_sha_pin_update_keeps_closing_brace() {
            let cache = Arc::new(deps_core::HttpCache::new());
            let eco = GithubActionsEcosystem::new(cache);
            let (old, new) = ("a".repeat(40), "b".repeat(40));
            let name = "actions/checkout";
            eco.formatter.tag_index.insert(
                deps_core::PackageName::new(name),
                Arc::new(TagIndex::from_tags([
                    (
                        "v4.0.0",
                        &deps_core::lsp_helpers::CommitSha::parse(&old).unwrap(),
                    ),
                    (
                        "v4.3.1",
                        &deps_core::lsp_helpers::CommitSha::parse(&new).unwrap(),
                    ),
                ])),
            );
            let mut cached = HashMap::new();
            cached.insert(
                deps_core::PackageName::new(name),
                deps_core::PackageVersions::latest_only("v4.3.1"),
            );
            let resolved = HashMap::new();
            let uri = deps_core::test_util::test_uri("/repo/.github/workflows/ci.yml");
            let content = format!("steps:\n  - {{uses: {name}@{old}}}\n");
            let parse_result = eco.parse_manifest(&content, &uri).await.unwrap();
            let planned = deps_core::edit::collect_update_edits(
                parse_result.as_ref(),
                &content,
                deps_core::VersionData::new(&cached, &resolved),
                &eco.formatter,
            );
            let edits: Vec<_> = planned.into_iter().map(|p| p.edit).collect();
            assert_eq!(
                deps_core::edit::apply_edits(&content, &edits),
                format!("steps:\n  - {{uses: {name}@{new}}}\n")
            );
        }

        /// #1722: a cold cache must produce no mismatch diagnostic.
        #[tokio::test]
        async fn test_sha_comment_mismatch_diagnostic_silent_on_cold_cache() {
            let cache = Arc::new(deps_core::HttpCache::new());
            let eco = GithubActionsEcosystem::new(cache);
            let content = format!(
                "steps:\n  - uses: owner/action@{} # v2.87.22\n",
                "c".repeat(40)
            );
            let found = sha_comment_diagnostics(
                &eco,
                &content,
                deps_core::lsp_helpers::DiagnosticSeverities::default(),
            )
            .await;
            assert!(found.is_empty(), "{found:?}");
        }

        /// #1722: hover carries a warning line for both mismatch kinds.
        #[cfg(feature = "lsp-responses")]
        #[tokio::test]
        async fn test_sha_comment_mismatch_hover_warning() {
            let (eco, name, [a, _b, missing]) = mismatch_fixture();
            let content = format!(
                "steps:\n  - uses: {name}@{a} # v2.87.22\n  - uses: {name}@{missing} # v2.87.22\n"
            );
            let uri = deps_core::test_util::test_uri("/repo/.github/workflows/ci.yml");
            let parse_result = eco.parse_manifest(&content, &uri).await.unwrap();
            let mut cached = HashMap::new();
            cached.insert(
                deps_core::PackageName::new(&name),
                deps_core::PackageVersions::latest_only("v2.87.22"),
            );
            let resolved = HashMap::new();

            let hover_at = |line: u32| {
                let versions = deps_core::VersionData::new(&cached, &resolved)
                    .with_network(deps_core::NetworkMode::Offline);
                let parse_result = &parse_result;
                let eco = &eco;
                async move {
                    eco.generate_hover(
                        parse_result.as_ref(),
                        Position::new(line, 40),
                        versions,
                        deps_core::FreshnessSettings::default(),
                    )
                    .await
                    .expect("hover")
                    .markdown()
                    .to_string()
                }
            };

            let other = hover_at(1).await;
            assert!(
                other.contains(
                    "**Warning**: comment says `v2.87.22`, but SHA `aaaaaaa…` is `v2.87.20`"
                ),
                "{other}"
            );
            let resolved_at = other.find("**Resolved**").expect("resolved line");
            let warning_at = other.find("**Warning**").expect("warning line");
            assert!(resolved_at < warning_at, "{other}");
            let absent = hover_at(2).await;
            assert!(
                absent.contains("not the commit of any release tag"),
                "{absent}"
            );
            assert!(!absent.contains("**Resolved**"), "{absent}");
        }

        /// #1722: no warning for a confirmed comment, a commentless pin, or a cold cache.
        #[cfg(feature = "lsp-responses")]
        #[tokio::test]
        async fn test_sha_comment_hover_has_no_warning_when_not_mismatched() {
            let (eco, name, [a, b, _missing]) = mismatch_fixture();
            let content =
                format!("steps:\n  - uses: {name}@{b} # v2.87.22\n  - uses: {name}@{a}\n");
            let cold = GithubActionsEcosystem::new(Arc::new(deps_core::HttpCache::new()));
            let uri = deps_core::test_util::test_uri("/repo/.github/workflows/ci.yml");
            let mut cached = HashMap::new();
            cached.insert(
                deps_core::PackageName::new(&name),
                deps_core::PackageVersions::latest_only("v2.87.22"),
            );
            let resolved = HashMap::new();

            for (ecosystem, line, text) in [
                (&eco, 1_u32, content.clone()),
                (&eco, 2, content.clone()),
                (
                    &cold,
                    1,
                    format!("steps:\n  - uses: {name}@{a} # v2.87.22\n"),
                ),
            ] {
                let parse_result = ecosystem.parse_manifest(&text, &uri).await.unwrap();
                let hover = ecosystem
                    .generate_hover(
                        parse_result.as_ref(),
                        Position::new(line, 40),
                        deps_core::VersionData::new(&cached, &resolved)
                            .with_network(deps_core::NetworkMode::Offline),
                        deps_core::FreshnessSettings::default(),
                    )
                    .await
                    .expect("hover");
                assert!(
                    !hover.markdown().contains("**Warning**"),
                    "{}",
                    hover.markdown()
                );
            }
        }

        /// #1720: non-repo and reusable-workflow `uses:` are outside the SHA-pin status path.
        #[tokio::test]
        async fn test_sha_pin_status_does_not_touch_non_repo_uses() {
            let cache = Arc::new(deps_core::HttpCache::new());
            let eco = GithubActionsEcosystem::new(cache);
            let index = TagIndex::from_tags([(
                "v1.0.0",
                &deps_core::lsp_helpers::CommitSha::parse(&"3".repeat(40)).unwrap(),
            )]);
            eco.formatter.tag_index.insert(
                deps_core::PackageName::new("octo-org/repo"),
                Arc::new(index),
            );
            let uri = deps_core::test_util::test_uri("/repo/.github/workflows/ci.yml");
            let content = format!(
                "jobs:\n  call:\n    uses: octo-org/repo/.github/workflows/x.yml@{}\n  build:\n    steps:\n      - uses: docker://alpine:3.18\n      - uses: ./local\n",
                "5".repeat(40)
            );
            let parse_result = eco.parse_manifest(&content, &uri).await.unwrap();
            let mut cached = HashMap::new();
            cached.insert(
                deps_core::PackageName::new("octo-org/repo"),
                deps_core::PackageVersions::latest_only("v1.0.0"),
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
            assert!(
                diagnostics
                    .iter()
                    .all(|d| !d.message().contains("Newer version available")),
                "{diagnostics:?}"
            );
            let edits = deps_core::lsp_helpers::collect_update_all_edits(
                parse_result.as_ref(),
                &content,
                deps_core::VersionData::new(&cached, &resolved),
                &eco.formatter,
            );
            assert!(edits.is_empty(), "{edits:?}");
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
            // No `seed_tag` call: the one Tag-pinned step is a cache miss, skipped gracefully.
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
            // M1 (critic): the risk here is writing 40+ chars at the wrong span, so each edit's
            // range must be pinned, not just its text — proving the mapping doesn't swap or shift.
            let checkout_edit = edits
                .iter()
                .find(|e| e.new_text == format!("{sha1} # v4"))
                .expect("expected an edit for actions/checkout");
            assert_eq!(checkout_edit.range, checkout_range.into());
            let setup_node_edit = edits
                .iter()
                .find(|e| e.new_text == format!("{sha2} # v3"))
                .expect("expected an edit for actions/setup-node");
            assert_eq!(setup_node_edit.range, setup_node_range.into());
        }

        #[tokio::test]
        async fn test_collect_pin_all_to_sha_edits_empty_for_branch_and_quoted_scalar() {
            // Both must be withheld, matching `build_sha_pin_action`'s own guards (FR-005,
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

        #[tokio::test]
        async fn test_generate_hover_for_composite_action_yml_dependency() {
            // Offline: the shared hover helper otherwise drives a live registry fetch, which is
            // irrelevant here and would outlive the test as a leaked background task.
            let cache = Arc::new(deps_core::HttpCache::new());
            cache.set_offline(deps_core::NetworkMode::Offline);
            let eco = GithubActionsEcosystem::new(cache);
            let uri = deps_core::test_util::test_uri("/repo/action.yml");
            let content = "name: My Action\n\
             runs:\n\
             \x20 using: composite\n\
             \x20 steps:\n\
             \x20   - uses: actions/checkout@v4\n";
            let parse_result = eco.parse_manifest(content, &uri).await.unwrap();
            let name_position = deps_core::ParseResult::dependencies(parse_result.as_ref())[0]
                .name_range()
                .start
                .into();
            let (cached, resolved) = empty_versions();

            let hover = eco
                .generate_hover(
                    parse_result.as_ref(),
                    name_position,
                    deps_core::VersionData::new(&cached, &resolved),
                    deps_core::FreshnessSettings::default(),
                )
                .await;

            assert!(
                hover.is_some(),
                "hovering a uses: step inside a root-level action.yml must produce a hover"
            );
        }

        /// Composition regression guard (#390/#282 bug class): proves `line_at` +
        /// the `uses:` step-key detection compose correctly through the real trait
        /// method on realistic multi-line workflow content.
        #[test]
        fn test_fallback_completion_prefix_multi_line_composition() {
            let cache = Arc::new(deps_core::HttpCache::new());
            let eco = GithubActionsEcosystem::new(cache);
            let content = "jobs:\n  build:\n    steps:\n      - uses: actions/check";
            let line = content.lines().nth(3).unwrap();
            let position = Position::new(3, line.chars().count() as u32);
            // Raw trim only, no manifest-syntax stripping — matches this ecosystem's
            // "no override" prefix shape (see `extract_prefix`'s doc).
            assert_eq!(
                eco.fallback_completion_prefix(content, position.into()),
                Some("- uses: actions/check")
            );
        }

        // --- #793 characterization: `generate_completions` dispatch, pinned before the
        // wildcard-match refactor. GitHub Actions serves only `Version` (no package-name
        // search); `PackageName`/`Feature`/`None` must all return an untouched `Completions::default()`.

        #[tokio::test]
        async fn test_generate_completions_package_name_context_returns_empty_non_incomplete() {
            let cache = Arc::new(deps_core::HttpCache::new());
            let eco = GithubActionsEcosystem::new(cache);
            let uri = deps_core::test_util::test_uri("/repo/.github/workflows/ci.yml");
            let content = "steps:\n  - uses: actions/checkout@v4\n";
            let parse_result = eco.parse_manifest(content, &uri).await.unwrap();
            let position = parse_result.dependencies()[0].name_range().start.into();

            let result = eco
                .generate_completions(
                    parse_result.as_ref(),
                    position,
                    content,
                    deps_core::FreshnessSettings::default(),
                )
                .await;
            assert_eq!(
                result,
                Completions::default()
                    .with_origin(deps_core::completion::CompletionOrigin::PackageName)
            );
        }

        /// Drives a real (mocked) network fetch through `GithubActionsRegistry`, mirroring
        /// `test_generate_hover_restores_footer_online_for_bare_major_tag_with_empty_live_list`'s
        /// `for_test` setup, so this proves `generate_completions`'s `Version` arm actually
        /// threads the resolved position/`prefix` through to
        /// `complete_versions_at_position` rather than just checking an empty degenerate case.
        #[tokio::test]
        async fn test_generate_completions_version_context_dispatches_to_registry() {
            let mut server = mockito::Server::new_async().await;
            let _mock = server
                .mock("GET", "/repos/actions/checkout/tags")
                .match_query(mockito::Matcher::Any)
                .with_status(200)
                .with_body(format!(
                    r#"[{{"name": "v4.1.1", "commit": {{"sha": "{}"}}}}]"#,
                    "a".repeat(40)
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
            let position = parse_result.dependencies()[0]
                .version_range()
                .unwrap()
                .start
                .into();
            let freshness = deps_core::FreshnessSettings::default();

            let context = deps_core::completion::detect_completion_context(
                parse_result.as_ref(),
                position,
                content,
            );
            let deps_core::completion::CompletionContext::Version { prefix, .. } = context else {
                panic!("expected Version context, got {context:?}");
            };
            let direct = deps_core::completion::complete_versions_at_position(
                eco.registry.as_ref(),
                &eco.formatter,
                parse_result.as_ref(),
                position,
                &prefix,
                VERSION_OPERATOR_CHARS,
                freshness,
            )
            .await;
            let via_dispatch = eco
                .generate_completions(parse_result.as_ref(), position, content, freshness)
                .await;
            assert_eq!(via_dispatch.items, direct);
            assert_eq!(
                via_dispatch.origin,
                deps_core::completion::CompletionOrigin::Version
            );
            assert!(!direct.is_empty());
        }

        /// Regression test for issue #1182. A comment-annotated SHA pin's `version_range`
        /// intentionally spans through the trailing `# vX.Y.Z` comment — see
        /// `crate::parser::tests::test_sha_with_comment_tag` — because
        /// `GithubActionsFormatter::format_version_replacing_for`'s edit range and
        /// `generate_hover`'s `**Resolved**` splice both depend on it covering the full
        /// `<sha> # <tag>` text. That means `detect_completion_context` still reports a
        /// `Version` context for a cursor anywhere in that span; `generate_completions`
        /// must withhold a completion once the cursor is past the SHA's own end column —
        /// including the whitespace padding before `#` and `#` itself, not just once the
        /// cursor is past `#` (the gap an earlier, prefix-based guard missed, since
        /// `extract_prefix` trims a padding-only or bare-`#` slice back to a bare SHA with
        /// no whitespace left to detect) — while a cursor on or immediately after the SHA
        /// itself still gets one.
        ///
        /// Two spaces separate the SHA from `#` so the padding-gap and immediately-before-`#`
        /// positions below land on distinct columns.
        #[tokio::test]
        async fn test_generate_completions_withholds_only_past_sha_pins_own_ref_end() {
            let sha = "a".repeat(40);
            let mut server = mockito::Server::new_async().await;
            let _mock = server
                .mock("GET", "/repos/actions/checkout/tags")
                .match_query(mockito::Matcher::Any)
                .with_status(200)
                .with_body(format!(
                    r#"[{{"name": "v4.2.0", "commit": {{"sha": "{sha}"}}}}]"#
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
            let content = format!("steps:\n  - uses: actions/checkout@{sha}  # v4.2.0\n");
            let parse_result = eco.parse_manifest(&content, &uri).await.unwrap();
            let version_range = parse_result.dependencies()[0].version_range().unwrap();
            let sha_end = version_range.start.character + u32::try_from(sha.len()).unwrap();
            let line = version_range.start.line;
            let freshness = deps_core::FreshnessSettings::default();

            // Right after the SHA's own last character: still typing the ref, must complete.
            let allowed = eco
                .generate_completions(
                    parse_result.as_ref(),
                    deps_core::position::Position::new(line, sha_end).into(),
                    &content,
                    freshness,
                )
                .await;
            assert!(!allowed.items.is_empty());

            // Past the SHA's own end: in the padding gap, immediately before `#`, and
            // inside the comment past `#` — all three must withhold.
            for character in [sha_end + 1, sha_end + 2, sha_end + 3] {
                let withheld = eco
                    .generate_completions(
                        parse_result.as_ref(),
                        deps_core::position::Position::new(line, character).into(),
                        &content,
                        freshness,
                    )
                    .await;
                assert_eq!(
                    withheld,
                    Completions::default()
                        .with_origin(deps_core::completion::CompletionOrigin::Version),
                    "expected no completion (and no fallback) at character {character} \
                 (sha_end = {sha_end})"
                );
            }
        }

        /// #1732: for a quoted/flow pin the SHA's own end is the closing delimiter's start,
        /// so the column right after the SHA is not past it and the delimiter's column is.
        #[tokio::test]
        async fn test_position_past_sha_pin_own_ref_for_quoted_and_flow_pins() {
            let sha = "a".repeat(40);
            let eco = GithubActionsEcosystem::new(Arc::new(deps_core::HttpCache::new()));
            let uri = deps_core::test_util::test_uri("/repo/.github/workflows/ci.yml");
            for line in [
                format!("  - uses: \"actions/checkout@{sha}\" # v4"),
                format!("  - {{uses: actions/checkout@{sha}}} # v4"),
                format!("  - {{uses: 'actions/checkout@{sha}'}} # v4"),
            ] {
                let content = format!("steps:\n{line}\n");
                let parse_result = eco.parse_manifest(&content, &uri).await.unwrap();
                let start = parse_result.dependencies()[0]
                    .version_range()
                    .unwrap()
                    .start
                    .character;
                let past = |character: u32| {
                    position_past_sha_pin_own_ref(
                        parse_result.as_ref(),
                        Position::new(1, character),
                    )
                };
                assert!(!past(start + 40), "{line}");
                assert!(past(start + 41), "{line}");
            }
        }

        /// A commentless SHA pin's `version_range` already ends exactly at the SHA's own end
        /// (never widened) — `position_past_sha_pin_own_ref`'s guard must never fire for it,
        /// so completion at the ref's end column is unaffected by issue #1182's fix.
        #[tokio::test]
        async fn test_generate_completions_unaffected_for_commentless_sha_pin() {
            let sha = "a".repeat(40);
            let mut server = mockito::Server::new_async().await;
            let _mock = server
                .mock("GET", "/repos/actions/checkout/tags")
                .match_query(mockito::Matcher::Any)
                .with_status(200)
                .with_body(format!(
                    r#"[{{"name": "v4.2.0", "commit": {{"sha": "{sha}"}}}}]"#
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
            let content = format!("steps:\n  - uses: actions/checkout@{sha}\n");
            let parse_result = eco.parse_manifest(&content, &uri).await.unwrap();
            let version_range = parse_result.dependencies()[0].version_range().unwrap();
            let freshness = deps_core::FreshnessSettings::default();

            let result = eco
                .generate_completions(
                    parse_result.as_ref(),
                    version_range.end.into(),
                    &content,
                    freshness,
                )
                .await;
            assert!(!result.items.is_empty());
        }
    }
}
