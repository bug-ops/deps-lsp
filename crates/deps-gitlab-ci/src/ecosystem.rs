//! GitLab CI ecosystem implementation for deps-lsp.

use std::any::Any;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tower_lsp_server::ls_types::{
    Diagnostic, DiagnosticSeverity, Hover, HoverContents, NumberOrString, Position, Uri,
};

use deps_core::net_policy::RegistryAccessPolicy;
use deps_core::{
    Ecosystem, HttpCache, ParseResult as ParseResultTrait, Registry, Result,
    completion::Completions,
    lsp_helpers::{EcosystemFormatter, markdown_code_span, truncate_for_diagnostic},
};

use crate::UNRESOLVED_HOST_DIAGNOSTIC_CODE;
use crate::client::GitlabApiClient;
use crate::formatter::GitlabCiFormatter;
use crate::host::{GitlabInstanceHost, is_valid_gitlab_coordinate};
use crate::registry::GitlabCiRegistry;
use crate::types::{GitlabCiDependency, HostRef, IncludeKind, PinStyle};

/// Maximum character count of an interpolated raw host expression before truncation —
/// mirrors `deps_github_actions`'s `MAX_MUTABLE_REF_PIN_MESSAGE_VALUE_CHARS` precedent.
const MAX_UNRESOLVED_HOST_MESSAGE_VALUE_CHARS: usize = 128;

/// Bound on [`GitlabCiRegistry::resolve_component_pin`]'s FR-007 hover-time resolution
/// (H1, #466 review) — mirrors `deps_core::lsp_helpers::hover`'s `HOVER_FALLBACK_TIMEOUT`
/// precedent for a live-fetch fallback invoked from hover generation: a failure or timeout
/// here degrades gracefully to no `**Resolved**` line, never aborting the rest of the hover.
const COMPONENT_PIN_RESOLUTION_TIMEOUT: Duration = Duration::from_secs(5);

/// GitLab CI ecosystem implementation.
///
/// Provides LSP functionality for `.gitlab-ci.yml`/`.gitlab/ci/*.yml`/`*.yaml` files — see
/// `crate` docs for the pin contract.
pub struct GitlabCiEcosystem {
    registry: Arc<GitlabCiRegistry>,
    formatter: GitlabCiFormatter,
    policy: Arc<RegistryAccessPolicy>,
    instance_host: Arc<GitlabInstanceHost>,
}

impl GitlabCiEcosystem {
    /// Creates a new GitLab CI ecosystem with a default (unset, process-default-policy)
    /// context — used by simple construction paths that don't need a live
    /// `registries.gitlab_instance_host`/`registries.workspace_registries` wiring (tests,
    /// doctests).
    #[must_use]
    pub fn new(cache: Arc<HttpCache>) -> Self {
        let policy = Arc::new(RegistryAccessPolicy::default());
        Self::with_context(cache, policy, Arc::new(RwLock::new(None)))
    }

    /// Creates a GitLab CI ecosystem sharing live `policy`/`gitlab_instance_host` handles —
    /// the production wiring path (`deps-lsp`'s `register_ecosystems`), mirroring
    /// `NuGetEcosystem`/`PypiEcosystem`'s identical `with_context` precedent.
    ///
    /// `gitlab_instance_host_raw` is the feature-agnostic `Arc<RwLock<Option<String>>>` cell
    /// `deps-lsp`'s `EcosystemRuntime` owns (spec §4.5's revision-3 note); this constructor
    /// is the one place it becomes a crate-local [`GitlabInstanceHost`].
    #[must_use]
    pub fn with_context(
        cache: Arc<HttpCache>,
        policy: Arc<RegistryAccessPolicy>,
        gitlab_instance_host_raw: Arc<RwLock<Option<String>>>,
    ) -> Self {
        let instance_host = Arc::new(GitlabInstanceHost::new(
            gitlab_instance_host_raw,
            Arc::clone(&policy),
        ));
        let client = Arc::new(GitlabApiClient::new(cache, Arc::clone(&instance_host)));
        let registry = Arc::new(GitlabCiRegistry::new(client));
        let formatter = GitlabCiFormatter::new(registry.routes(), registry.tag_index());
        Self {
            registry,
            formatter,
            policy,
            instance_host,
        }
    }
}

impl deps_core::ecosystem::private::Sealed for GitlabCiEcosystem {}

impl Ecosystem for GitlabCiEcosystem {
    fn id(&self) -> &'static str {
        "gitlab-ci"
    }

    fn display_name(&self) -> &'static str {
        "GitLab CI/CD"
    }

    /// GitLab does not accept `.gitlab-ci.yaml` — only `.gitlab-ci.yml` is recognized
    /// (spec FR-001).
    fn manifest_filenames(&self) -> &[&'static str] {
        &[".gitlab-ci.yml"]
    }

    /// The standard split-pipeline convention GitLab itself documents. This is the whole of
    /// v1's detection: a child pipeline at a conventionless path is not detected (spec
    /// FR-001).
    fn manifest_directory_patterns(&self) -> &[(&'static str, &'static str)] {
        &[(".gitlab/ci", ".yml"), (".gitlab/ci", ".yaml")]
    }

    fn lockfile_filenames(&self) -> &[&'static str] {
        &[]
    }

    /// Parses the manifest, then registers its routes into the shared registry and
    /// downgrades any dependency whose route the process-wide cap refused to
    /// `CustomRegistry` + [`HostRef::CapacityRefused`] (spec §3.2/§4.6) before returning —
    /// the same downgrade shape (#466 review M-a) [`crate::parser`]'s per-document host cap
    /// already produces, so the two capacity-refusal paths agree.
    fn parse_manifest<'a>(
        &'a self,
        content: &'a str,
        uri: &'a Uri,
    ) -> deps_core::ecosystem::BoxFuture<'a, Result<Box<dyn ParseResultTrait>>> {
        Box::pin(async move {
            let mut result = crate::parser::parse_gitlab_ci_yaml(
                content,
                uri,
                &self.policy,
                &self.instance_host,
            )?;
            let refused = self.registry.register_routes(&result.routes);
            if !refused.is_empty() {
                for dep in &mut result.dependencies {
                    if let deps_core::parser::DependencySource::AlternateRegistry { index, .. } =
                        &dep.source
                        && refused.contains(index)
                    {
                        let origin = match &dep.host {
                            HostRef::Literal(host) => host.origin().to_string(),
                            HostRef::Unresolved(raw) | HostRef::CapacityRefused(raw) => raw.clone(),
                        };
                        dep.source = deps_core::parser::DependencySource::CustomRegistry {
                            url: origin.clone(),
                        };
                        dep.host = HostRef::CapacityRefused(origin);
                    }
                }
            }
            Ok(Box::new(result) as Box<dyn ParseResultTrait>)
        })
    }

    fn registry(&self) -> Arc<dyn Registry> {
        self.registry.clone() as Arc<dyn Registry>
    }

    fn formatter(&self) -> &dyn EcosystemFormatter {
        &self.formatter
    }

    /// Version completions only, resolved through the source-aware
    /// [`deps_core::completion::complete_versions_generic_from`] (spec §7a.1) — the
    /// source-unaware default would return nothing, since this crate's `Registry` never
    /// resolves an unsourced fetch. The dependency's `source` is resolved **by position**,
    /// not by name: a `project:` and a `component:` include of the same project can share
    /// one `PackageName` (spec §3.1's documented residual collision), and a by-name lookup
    /// would risk picking the wrong one's source.
    fn generate_completions<'a>(
        &'a self,
        parse_result: &'a dyn ParseResultTrait,
        position: Position,
        content: &'a str,
        freshness: deps_core::FreshnessSettings,
    ) -> deps_core::ecosystem::BoxFuture<'a, Completions> {
        Box::pin(async move {
            use deps_core::completion::{
                CompletionContext, complete_versions_generic_from, detect_completion_context,
            };

            let CompletionContext::Version { prefix, .. } =
                detect_completion_context(parse_result, position, content)
            else {
                return Completions::default();
            };
            let Some(dep) = parse_result.dependencies().into_iter().find(|d| {
                d.version_range()
                    .is_some_and(|r| deps_core::position_in_range(position, r))
            }) else {
                return Completions::default();
            };

            complete_versions_generic_from(
                self.registry.as_ref(),
                dep.name(),
                &dep.source(),
                &prefix,
                &[],
                freshness,
            )
            .await
            .into()
        })
    }

    /// Appends the FR-012 informational unresolved-host diagnostic to the shared default's
    /// output, for every dependency whose host could not be statically determined.
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
            diagnostics.extend(unresolved_host_diagnostics(parse_result));
            diagnostics
        })
    }

    /// Splices a `**Resolved**` line for a SHA pin (via the shared tag index) and, for a
    /// `component:` include only, a `**Project**` link line — the one NFR-004 hover
    /// divergence this ecosystem has (spec §8.1/§8.2).
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
            let Some(gl_dep) = dep.as_any().downcast_ref::<GitlabCiDependency>() else {
                return Some(hover);
            };

            if gl_dep.kind == IncludeKind::Component
                && let HostRef::Literal(host) = &gl_dep.host
                && is_valid_gitlab_coordinate(&gl_dep.project_path)
                && let HoverContents::Markup(content) = &mut hover.contents
            {
                let url = format!("https://{}/{}", host.host(), gl_dep.project_path);
                content.value = splice_project_line(&content.value, &url);
            }

            if gl_dep.pin == Some(PinStyle::Sha)
                && let Some(sha) = gl_dep
                    .version_req
                    .as_ref()
                    .map(deps_core::VersionReq::as_str)
                && let Some(resolved_tag) = self.formatter.resolved_tag_for_sha(dep.name(), sha)
                && let HoverContents::Markup(content) = &mut hover.contents
            {
                content.value = splice_resolved_line(&content.value, &resolved_tag, sha);
            }

            // FR-007 (H1, #466 review): a `component:` `Latest`/`Partial` pin names no
            // concrete version by itself — unlike `Sha` (resolved above via the tag index,
            // no extra fetch needed) or `Tag`/`Branch` (whose text either is or isn't the
            // version). Resolving it needs the priority ladder run against the project's
            // published releases.
            if gl_dep.kind == IncludeKind::Component
                && let Some(pin @ (PinStyle::Latest | PinStyle::Partial)) = &gl_dep.pin
                && let deps_core::parser::DependencySource::AlternateRegistry { index, .. } =
                    dep.source()
                && let Some(route) = registry.routes().get(&index).map(|r| r.clone())
                && let Some(raw) = gl_dep
                    .version_req
                    .as_ref()
                    .map(deps_core::VersionReq::as_str)
            {
                let outcome = tokio::time::timeout(
                    COMPONENT_PIN_RESOLUTION_TIMEOUT,
                    registry.resolve_component_pin(dep.name(), &route, pin, raw),
                )
                .await;
                match outcome {
                    Ok(Ok(Some(resolved))) => {
                        if let HoverContents::Markup(content) = &mut hover.contents {
                            content.value = splice_resolved_line(
                                &content.value,
                                resolved.version.as_str(),
                                &resolved.sha,
                            );
                        }
                    }
                    Ok(Ok(None)) => {}
                    Ok(Err(error)) => {
                        tracing::warn!(package = %dep.name(), %error, "FR-007 component pin resolution failed");
                    }
                    Err(_) => {
                        tracing::warn!(package = %dep.name(), "FR-007 component pin resolution timed out");
                    }
                }
            }

            Some(hover)
        })
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

fn unresolved_host_diagnostics(parse_result: &dyn ParseResultTrait) -> Vec<Diagnostic> {
    parse_result
        .dependencies()
        .into_iter()
        .filter_map(|dep| {
            let gl_dep = dep.as_any().downcast_ref::<GitlabCiDependency>()?;
            // M-a (#466 review): a capacity refusal gets its own message — the host itself
            // was perfectly determinable, so telling the user to set
            // `registries.gitlab_instance_host` (a fix for `Unresolved`, not this) would be
            // actively wrong.
            let message = match &gl_dep.host {
                HostRef::Unresolved(raw) => {
                    let raw = truncate_for_diagnostic(raw, MAX_UNRESOLVED_HOST_MESSAGE_VALUE_CHARS);
                    format!(
                        "Cannot determine the GitLab instance host for '{raw}'. Set the \
                         `registries.gitlab_instance_host` setting to enable version resolution."
                    )
                }
                HostRef::CapacityRefused(origin) => {
                    let origin =
                        truncate_for_diagnostic(origin, MAX_UNRESOLVED_HOST_MESSAGE_VALUE_CHARS);
                    format!(
                        "'{origin}' was not registered for version resolution because a \
                         GitLab CI host/route capacity limit was reached. Reduce the number of \
                         distinct GitLab hosts or includes referenced in this workspace \
                         (unrelated to the `registries.gitlab_instance_host` setting)."
                    )
                }
                HostRef::Literal(_) => return None,
            };
            Some(Diagnostic {
                range: gl_dep.name_range,
                severity: Some(DiagnosticSeverity::INFORMATION),
                message,
                code: Some(NumberOrString::String(
                    UNRESOLVED_HOST_DIAGNOSTIC_CODE.into(),
                )),
                source: Some("deps-lsp".into()),
                ..Default::default()
            })
        })
        .collect()
}

/// Inserts a `**Project**: [name](url)` line immediately after the hover heading, for a
/// `component:` include whose heading link is suppressed (spec §8.2).
fn splice_project_line(markdown: &str, url: &str) -> String {
    let line = format!("**Project**: [{url}]({url})\n\n");
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

/// Inserts a `**Resolved**: `tag` (`sha…`)` line immediately after the shared hover's
/// `**Current**`/`**Requirement**` line, mirroring
/// `deps_github_actions::ecosystem::splice_resolved_line` exactly.
fn splice_resolved_line(markdown: &str, resolved_tag: &str, sha: &str) -> String {
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
        let cache = Arc::new(HttpCache::new());
        let eco = GitlabCiEcosystem::new(cache);
        assert_eq!(eco.id(), "gitlab-ci");
        assert_eq!(eco.display_name(), "GitLab CI/CD");
    }

    #[test]
    fn test_manifest_routing() {
        let cache = Arc::new(HttpCache::new());
        let eco = GitlabCiEcosystem::new(cache);
        assert_eq!(eco.manifest_filenames(), &[".gitlab-ci.yml"]);
        assert_eq!(
            eco.manifest_directory_patterns(),
            &[(".gitlab/ci", ".yml"), (".gitlab/ci", ".yaml")]
        );
        assert!(eco.manifest_patterns().is_empty());
        assert!(eco.manifest_extensions().is_empty());
    }

    #[test]
    fn test_as_any() {
        let cache = Arc::new(HttpCache::new());
        let eco = GitlabCiEcosystem::new(cache);
        assert!(eco.as_any().is::<GitlabCiEcosystem>());
    }

    #[tokio::test]
    async fn test_parse_manifest_valid() {
        let cache = Arc::new(HttpCache::new());
        let eco = GitlabCiEcosystem::new(cache);
        let uri = deps_core::test_util::test_uri("/repo/.gitlab-ci.yml");
        let content = "include:\n  - project: org/proj\n    ref: v1.0.0\n";
        let result = eco.parse_manifest(content, &uri).await.unwrap();
        assert_eq!(result.dependencies().len(), 1);
    }

    #[test]
    fn test_splice_project_line() {
        let markdown = "# gitlab.com/org/proj/comp\n\n**Requirement**: `1.0.0`\n";
        let spliced = splice_project_line(markdown, "https://gitlab.com/org/proj");
        assert!(spliced.contains("**Project**"));
        assert!(spliced.find("**Project**").unwrap() < spliced.find("**Requirement**").unwrap());
    }

    #[test]
    fn test_splice_resolved_line_after_requirement() {
        let markdown = "# org/proj\n\n**Requirement**: `v1.0.0`\n\n**Latest**: `v1.1.0`\n";
        let spliced = splice_resolved_line(markdown, "v1.0.0", &"a".repeat(40));
        let req_pos = spliced.find("**Requirement**").unwrap();
        let resolved_pos = spliced.find("**Resolved**").unwrap();
        let latest_pos = spliced.find("**Latest**").unwrap();
        assert!(req_pos < resolved_pos);
        assert!(resolved_pos < latest_pos);
    }

    /// M-a (#466 review): the two failure modes must produce visibly different messages —
    /// a genuinely unresolved host still points the user at `registries.gitlab_instance_host`,
    /// but a capacity refusal must not, since that setting cannot fix a capacity limit.
    #[test]
    fn test_unresolved_host_diagnostics_distinguishes_capacity_refusal_from_unresolved() {
        let uri = deps_core::test_util::test_uri("/repo/.gitlab-ci.yml");
        let range = tower_lsp_server::ls_types::Range::default();
        let make_dep = |host: HostRef| crate::types::GitlabCiDependency {
            name: "org/proj/comp".into(),
            name_range: range,
            version_req: Some("1.0.0".into()),
            version_range: Some(range),
            version_literal: None,
            source: deps_core::parser::DependencySource::CustomRegistry { url: "x".into() },
            is_plain_scalar: true,
            kind: IncludeKind::Component,
            host,
            pin: Some(PinStyle::Tag),
            project_path: "org/proj".to_string(),
        };
        let parse_result = crate::types::GitlabCiParseResult {
            dependencies: vec![
                make_dep(HostRef::Unresolved("$CI_SERVER_FQDN".to_string())),
                make_dep(HostRef::CapacityRefused(
                    "https://gitlab.other.example".to_string(),
                )),
            ],
            routes: vec![],
            uri,
        };

        let diagnostics = unresolved_host_diagnostics(&parse_result);

        assert_eq!(diagnostics.len(), 2);
        assert!(
            diagnostics[0]
                .message
                .contains("Set the `registries.gitlab_instance_host`")
        );
        // The capacity-refusal message must never instruct the user to *set* the setting —
        // it may still name it (to explain it's *not* the fix), but must not tell them to
        // configure it as a remedy.
        assert!(
            !diagnostics[1]
                .message
                .contains("Set the `registries.gitlab_instance_host`")
        );
        assert!(diagnostics[1].message.contains("capacity"));
    }

    /// Regression for the FR-012 diagnostic: an unresolved-host dependency must get the
    /// informational diagnostic, and no other diagnostic must compete (its source is
    /// `CustomRegistry`, which the shared unknown-package rule's `can_resolve_source` gate
    /// already excludes).
    #[tokio::test]
    async fn test_generate_diagnostics_unresolved_host() {
        let cache = Arc::new(HttpCache::new());
        let eco = GitlabCiEcosystem::new(cache);
        let uri = deps_core::test_util::test_uri("/repo/.gitlab-ci.yml");
        let content = "include:\n  - project: org/proj\n    ref: v1.0.0\n";
        let parse_result = eco.parse_manifest(content, &uri).await.unwrap();
        let cached = std::collections::HashMap::new();
        let resolved = std::collections::HashMap::new();

        let diagnostics = eco
            .generate_diagnostics(
                parse_result.as_ref(),
                deps_core::VersionData::new(&cached, &resolved),
                &uri,
                deps_core::FreshnessSettings::default(),
                deps_core::lsp_helpers::DiagnosticSeverities::default(),
            )
            .await;

        let found = diagnostics
            .iter()
            .find(|d| {
                d.code
                    == Some(NumberOrString::String(
                        UNRESOLVED_HOST_DIAGNOSTIC_CODE.into(),
                    ))
            })
            .expect("expected the unresolved-host diagnostic");
        assert_eq!(found.severity, Some(DiagnosticSeverity::INFORMATION));
        assert!(found.message.contains("gitlab_instance_host"));
    }
}
