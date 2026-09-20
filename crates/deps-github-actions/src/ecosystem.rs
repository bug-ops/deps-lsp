//! GitHub Actions ecosystem implementation for deps-lsp.

use dashmap::DashMap;
use std::any::Any;
use std::sync::Arc;
#[cfg(feature = "lsp-responses")]
use tower_lsp_server::ls_types::{CodeAction, Hover, HoverContents, Position, TextEdit};
use url::Url;

#[cfg(feature = "lsp-responses")]
use deps_core::completion::Completions;
#[cfg(feature = "lsp-responses")]
use deps_core::lsp_helpers::ShaPinning;
use deps_core::{
    Ecosystem, PackageName, ParseResult as ParseResultTrait, Registry, Result,
    diagnostic::{Diagnostic, Severity},
    lsp_helpers::EcosystemFormatter,
};

use crate::MUTABLE_REF_PIN_DIAGNOSTIC_CODE;

use crate::formatter::GithubActionsFormatter;
use crate::registry::{GithubActionsRegistry, TagIndex};
use crate::types::{GithubActionsDependency, PinStyle};

/// Leading version-constraint operators stripped from a completion prefix before matching
/// it against registry versions. Empty: a `uses:` ref is a bare tag/branch/SHA, with no
/// comparison/caret/tilde operator syntax (#1137).
#[cfg(feature = "lsp-responses")]
const VERSION_OPERATOR_CHARS: &[char] = &[];

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

/// Whether `position` sits strictly past a comment-annotated SHA pin's own ref text —
/// see [`GithubActionsEcosystem::generate_completions`]'s doc for why this check exists
/// (issue #1182) and why it cannot be a check on the extracted completion prefix.
///
/// Finds the dependency whose (deliberately widened) `version_range` contains
/// `position` and, only when it is a [`PinStyle::Sha`] with a `comment_tag` (the one
/// form where `version_range` extends past the ref's own text), compares `position`
/// against the SHA's own end column — [`crate::types::sha_pin_raw_sha`]'s length, added
/// to the range's start — rather than the range's own (widened) end. A position exactly
/// at that column (cursor immediately after the last SHA character, still typing it) is
/// deliberately *not* past it, so a commentless SHA pin's ordinary end-of-ref position is
/// unaffected; a [`PinStyle::Sha`] with no `comment_tag` has no widened tail at all
/// (`sha_pin_raw_sha` still resolves it, but its `version_range` already ends exactly at
/// the SHA's own end, so this predicate can never fire for it).
#[cfg(feature = "lsp-responses")]
fn position_past_sha_pin_own_ref(parse_result: &dyn ParseResultTrait, position: Position) -> bool {
    let position: deps_core::position::Position = position.into();
    parse_result.dependencies().into_iter().any(|dep| {
        let Some(range) = dep.version_range() else {
            return false;
        };
        if !deps_core::position_in_range(position, range) {
            return false;
        }
        let Some(gha_dep) = dep.as_any().downcast_ref::<GithubActionsDependency>() else {
            return false;
        };
        if !matches!(
            gha_dep.pin,
            Some(PinStyle::Sha {
                comment_tag: Some(_)
            })
        ) {
            return false;
        }
        let Some(sha) = crate::types::sha_pin_raw_sha(gha_dep) else {
            return false;
        };
        let Ok(sha_len) = u32::try_from(sha.len()) else {
            return false;
        };
        position.character > range.start.character.saturating_add(sha_len)
    })
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
                && let HoverContents::Markup(content) = &mut hover.contents
                && !content
                    .value
                    .contains(deps_core::lsp_helpers::CMD_DOT_FOOTER)
            {
                content
                    .value
                    .push_str(deps_core::lsp_helpers::CMD_DOT_FOOTER);
            }

            let Some(sha) = crate::types::sha_pin_raw_sha(gha_dep) else {
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
                content.value = deps_core::lsp_helpers::splice_resolved_line(
                    &content.value,
                    &resolved_tag,
                    sha,
                );
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
/// Not the same predicate [`GithubActionsEcosystem::generate_hover`]'s footer guard
/// checks: that guard still hand-rolls its own, narrower check (missing
/// `is_last_on_line`) pending PR #1187, so no parity claim is made with it here.
pub(crate) fn is_sha_pinnable_tag(gha_dep: &GithubActionsDependency) -> bool {
    gha_dep.pin == Some(PinStyle::Tag) && gha_dep.is_plain_scalar && gha_dep.is_last_on_line
}

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
            let name = deps_core::lsp_helpers::truncate_for_diagnostic(
                gha_dep.name.as_str(),
                MAX_MUTABLE_REF_PIN_MESSAGE_VALUE_CHARS,
            );
            let tag = deps_core::lsp_helpers::truncate_for_diagnostic(
                tag,
                MAX_MUTABLE_REF_PIN_MESSAGE_VALUE_CHARS,
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
                Diagnostic::new(range, message)
                    .with_severity(severity)
                    .with_code(MUTABLE_REF_PIN_DIAGNOSTIC_CODE),
            )
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
///
/// Delegates entirely to [`deps_core::lsp_helpers::build_sha_pin_action`] (issue #1138) via
/// [`GithubActionsFormatter`]'s [`deps_core::lsp_helpers::ShaPinning`] impl, which carries
/// this guard.
#[cfg(feature = "lsp-responses")]
fn build_sha_pin_action(
    parse_result: &dyn ParseResultTrait,
    position: Position,
    uri: &Url,
    formatter: &GithubActionsFormatter,
) -> Option<CodeAction> {
    deps_core::lsp_helpers::build_sha_pin_action(
        parse_result,
        position,
        uri,
        formatter,
        MUTABLE_REF_PIN_DIAGNOSTIC_CODE,
    )
}

/// Builds one [`TextEdit`] per `PinStyle::Tag` step in `parse_result` resolvable to a
/// commit SHA via `formatter`'s `TagIndex` — the bulk counterpart to
/// [`build_sha_pin_action`]'s single-step quickfix (issue #633). A step with no
/// resolvable `TagIndex` entry (cache miss) is silently skipped, exactly like that
/// quickfix's own withholding behavior — never blocking on, or triggering, a fetch.
#[cfg(feature = "lsp-responses")]
fn collect_pin_all_to_sha_edits(
    parse_result: &dyn ParseResultTrait,
    formatter: &GithubActionsFormatter,
) -> Vec<TextEdit> {
    let edits: Vec<TextEdit> = parse_result
        .dependencies()
        .into_iter()
        .filter_map(|dep| deps_core::lsp_helpers::sha_pin_text_edit(formatter, dep))
        .collect();
    deps_core::lsp_helpers::dedup_overlapping_edits(edits, "collect_pin_all_to_sha_edits")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "lsp-responses")]
    use deps_core::lsp_helpers::splice_resolved_line;
    use std::collections::HashMap;

    // --- issue #473: mutable-ref-pin diagnostic + "Pin to commit SHA" code action ---

    fn mutable_ref_pin_code() -> String {
        MUTABLE_REF_PIN_DIAGNOSTIC_CODE.into()
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
        assert_eq!(found.severity, Some(Severity::Hint));
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
            .find(|d| d.code == Some(mutable_ref_pin_code()))
            .expect("expected a mutable-ref-pin diagnostic for a quoted tag pin");
        assert!(
            found.message.contains("no automated fix available"),
            "a quoted scalar withholds the SHA-pin quickfix (FR-010), so the message \
             must say so; got: {}",
            found.message
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
            .find(|d| d.code == Some(mutable_ref_pin_code()))
            .expect("expected a mutable-ref-pin diagnostic for a flow-style tag pin");
        assert!(
            found.message.contains("no automated fix available"),
            "a flow-style step withholds the SHA-pin quickfix (#633), so the message \
             must say so; got: {}",
            found.message
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
            .find(|d| d.code == Some(mutable_ref_pin_code()))
            .expect("expected a diagnostic on cold cache")
            .message
            .clone();
        assert!(
            !cold_message.contains("no automated fix available"),
            "a cold TagIndex must not force the manual-edit wording; got: {cold_message}"
        );

        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = GithubActionsEcosystem::new(cache);
        let uri = deps_core::test_util::test_uri("/repo/.github/workflows/ci.yml");
        let parse_result = eco.parse_manifest(content, &uri).await.unwrap();
        let mut index = crate::registry::TagIndex::default();
        index.tag_to_sha.insert("v4".to_string(), "a".repeat(40));
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
            .find(|d| d.code == Some(mutable_ref_pin_code()))
            .expect("expected a diagnostic on warm cache")
            .message
            .clone();
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
            .find(|d| d.code == Some(mutable_ref_pin_code()))
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
                .any(|d| d.code == Some(mutable_ref_pin_code())),
            "mutable_ref_pin_enabled: false must suppress the diagnostic entirely: {diagnostics:?}"
        );
    }

    /// Exercises `build_sha_pin_action` directly rather than through
    /// `GithubActionsEcosystem::generate_code_actions`: the shared default that override
    /// delegates to first drives a *live* registry fetch (to list "Update to X" actions),
    /// which would overwrite a hand-seeded `TagIndex` fixture with real GitHub data before
    /// this function ever runs.
    #[cfg(feature = "lsp-responses")]
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
    #[cfg(feature = "lsp-responses")]
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
            .start
            .into();

        assert!(build_sha_pin_action(&parse_result, position, &uri, &formatter).is_none());
    }

    /// FR-005: a `TagIndex` cache miss must never offer a destructive/no-op edit.
    #[cfg(feature = "lsp-responses")]
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
    #[cfg(feature = "lsp-responses")]
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
            .start
            .into();

        assert!(build_sha_pin_action(&parse_result, position, &uri, &formatter).is_none());
    }

    /// FR-010 (security audit finding): a quoted `uses:` scalar must never get the
    /// SHA-pin quickfix, even on a `TagIndex` hit — writing `{sha} # {tag}` inside the
    /// quotes would corrupt the value and make it re-parse as `PinStyle::Branch`.
    #[cfg(feature = "lsp-responses")]
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
    #[cfg(feature = "lsp-responses")]
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
            .start
            .into();

        assert!(
            build_sha_pin_action(&parse_result, position, &uri, &formatter).is_none(),
            "a flow-mapping uses: step must withhold the quickfix even on a TagIndex hit"
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

    // #1137: regression guard, not independent parser verification (see
    // `operator_chars_conformance!`'s doc) — `required` mirrors `VERSION_OPERATOR_CHARS`'s
    // own doc comment (a `uses:` ref has no operator syntax), so an edit to one without the
    // other fails loudly instead of silently degrading completion.
    #[cfg(feature = "lsp-responses")]
    deps_core::operator_chars_conformance! {
        mod github_actions_operator_chars_conformance;
        ecosystem: "github-actions";
        operator_chars: VERSION_OPERATOR_CHARS;
        required: &[];
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

    #[cfg(feature = "lsp-responses")]
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

    #[cfg(feature = "lsp-responses")]
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

    #[cfg(feature = "lsp-responses")]
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
    #[cfg(feature = "lsp-responses")]
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

        let position = parse_result.dependencies()[0].name_range().start.into();
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
    #[cfg(feature = "lsp-responses")]
    #[tokio::test]
    async fn test_generate_hover_footer_stays_omitted_offline_for_tag_pin_without_tag_index() {
        let cache = Arc::new(deps_core::HttpCache::new());
        cache.set_offline(true);
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
    #[cfg(feature = "lsp-responses")]
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
    #[cfg(feature = "lsp-responses")]
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

        let position = parse_result.dependencies()[0].name_range().start.into();
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

    /// Regression for #1178: a flow-style `uses:` step (issue #633's
    /// `is_last_on_line == false` scenario — `, with: {...}}` follows the ref on the same
    /// line) must not have the footer restored, even on a `TagIndex` hit. Before #1178 the
    /// hand-rolled eligibility check omitted this `is_last_on_line` condition entirely, so
    /// the footer was wrongly restored for a step whose quickfix `build_sha_pin_action`
    /// itself withholds (see `test_build_sha_pin_action_no_quickfix_for_flow_mapping_step`).
    #[cfg(feature = "lsp-responses")]
    #[tokio::test]
    async fn test_generate_hover_footer_not_restored_offline_for_flow_mapping_tag_pin() {
        let cache = Arc::new(deps_core::HttpCache::new());
        cache.set_offline(true);
        let eco = GithubActionsEcosystem::new(cache);
        let uri = deps_core::test_util::test_uri("/repo/.github/workflows/ci.yml");
        let content = "steps:\n  - {uses: actions/checkout@v4, with: {node: 20}}\n";
        let parse_result = eco.parse_manifest(content, &uri).await.unwrap();
        let gha_dep = parse_result.dependencies()[0]
            .as_any()
            .downcast_ref::<GithubActionsDependency>()
            .unwrap();
        assert!(!gha_dep.is_last_on_line);

        let mut index = crate::registry::TagIndex::default();
        index.tag_to_sha.insert("v4".to_string(), "a".repeat(40));
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
                deps_core::VersionData::new(&cached, &resolved).with_offline(true),
                deps_core::FreshnessSettings::default(),
            )
            .await
            .expect("hover should be generated for the dependency on this line");

        let HoverContents::Markup(content) = hover.contents else {
            panic!("expected markup hover contents");
        };
        assert!(
            !content
                .value
                .contains(deps_core::lsp_helpers::CMD_DOT_FOOTER),
            "a flow-style uses: step is not the last token on its line, so appending a SHA \
             pin comment would produce invalid YAML; the footer must not be restored even \
             on a TagIndex hit; got: {}",
            content.value
        );
    }

    // --- issue #633/#640: bulk "Pin all to SHA" collector + lens ---

    #[cfg(feature = "lsp-responses")]
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
    #[cfg(feature = "lsp-responses")]
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

    #[cfg(feature = "lsp-responses")]
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
    #[cfg(feature = "lsp-responses")]
    #[tokio::test]
    async fn test_collect_update_all_edits_counts_sha_pin_outdated_via_tag_index_ground_truth() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = GithubActionsEcosystem::new(cache);
        let sha = "a".repeat(40);
        let mut index = crate::registry::TagIndex::default();
        index.sha_to_tag.insert(sha.clone(), "v4.0.0".to_string());
        // Needed so `format_version_replacing_for` produces a real replacement for `latest`,
        // or a `tag_to_sha` miss falls back to the unchanged literal and drops the edit.
        index
            .tag_to_sha
            .insert("v4.3.1".to_string(), "b".repeat(40));
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

    #[cfg(feature = "lsp-responses")]
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

    #[cfg(feature = "lsp-responses")]
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

    #[cfg(feature = "lsp-responses")]
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

    #[cfg(feature = "lsp-responses")]
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

    #[cfg(feature = "lsp-responses")]
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
    #[cfg(feature = "lsp-responses")]
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
                .any(|d| d.code == Some(mutable_ref_pin_code())),
            "a tag-pinned uses: step inside a composite action.yml must still get the \
             mutable-ref-pin diagnostic: {diagnostics:?}"
        );
    }

    #[cfg(feature = "lsp-responses")]
    #[tokio::test]
    async fn test_generate_hover_for_composite_action_yml_dependency() {
        // Offline: the shared hover helper otherwise drives a live registry fetch, which is
        // irrelevant here and would outlive the test as a leaked background task.
        let cache = Arc::new(deps_core::HttpCache::new());
        cache.set_offline(true);
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

    /// Composition regression guard (#390/#282 bug class): proves `line_at` +
    /// the `uses:` step-key detection compose correctly through the real trait
    /// method on realistic multi-line workflow content.
    #[cfg(feature = "lsp-responses")]
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

    // --- #793 characterization: `generate_completions` dispatch, pinned before the
    // wildcard-match refactor. GitHub Actions serves only `Version` (no package-name
    // search); `PackageName`/`Feature`/`None` must all return an untouched `Completions::default()`.

    #[cfg(feature = "lsp-responses")]
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
    #[cfg(feature = "lsp-responses")]
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
    #[cfg(feature = "lsp-responses")]
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

    /// A commentless SHA pin's `version_range` already ends exactly at the SHA's own end
    /// (never widened) — `position_past_sha_pin_own_ref`'s guard must never fire for it,
    /// so completion at the ref's end column is unaffected by issue #1182's fix.
    #[cfg(feature = "lsp-responses")]
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
