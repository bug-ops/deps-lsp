//! GitHub Actions ecosystem implementation for deps-lsp.

use std::any::Any;
use std::sync::Arc;
use tower_lsp_server::ls_types::{Hover, HoverContents, Position, Uri};

use deps_core::{
    Ecosystem, ParseResult as ParseResultTrait, Registry, Result,
    completion::Completions,
    lsp_helpers::{EcosystemFormatter, markdown_code_span},
};

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
        let formatter = GithubActionsFormatter {
            tag_index: registry.tag_index(),
        };
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
    /// not render as a readable version, and it is the only form
    /// [`crate::registry::TagIndex`] can resolve unambiguously by construction (it is
    /// populated only from fully-`major.minor.patch`-parseable tags, so a moving major
    /// tag like `v4` never has its own entry to resolve through). Guarded on
    /// `dep.version_range().is_some()` (N3): a non-resolvable dependency (a reusable-
    /// workflow call, `./local`, `docker://…`) still matches the shared helper's own
    /// hover-target predicate and must not have a `**Resolved**` line spliced onto it.
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
    // reaches here (`TagIndex` entries are filtered in `tags_to_versions`, security
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
