//! GitLab CI ecosystem implementation for deps-lsp.

use dashmap::DashMap;
use std::any::Any;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tower_lsp_server::ls_types::{
    CodeAction, CodeActionKind, Diagnostic, DiagnosticSeverity, Hover, HoverContents,
    NumberOrString, Position, TextEdit, Uri, WorkspaceEdit,
};

use deps_core::net_policy::RegistryAccessPolicy;
use deps_core::{
    Ecosystem, HttpCache, PackageName, ParseResult as ParseResultTrait, Registry, Result,
    completion::Completions,
    lsp_helpers::{
        EcosystemFormatter, PackageRendering, markdown_code_span, truncate_for_diagnostic,
    },
};

use crate::MUTABLE_REF_PIN_DIAGNOSTIC_CODE;
use crate::UNRESOLVED_HOST_DIAGNOSTIC_CODE;
use crate::client::GitlabApiClient;
use crate::formatter::GitlabCiFormatter;
use crate::host::{GitlabInstanceHost, is_valid_gitlab_coordinate};
use crate::registry::{GitlabCiRegistry, TagIndex};
use crate::types::{EndpointKind, GitlabCiDependency, HostRef, IncludeKind, PinStyle};

/// Maximum character count of an interpolated raw host expression before truncation —
/// mirrors `deps_github_actions`'s `MAX_MUTABLE_REF_PIN_MESSAGE_VALUE_CHARS` precedent.
const MAX_UNRESOLVED_HOST_MESSAGE_VALUE_CHARS: usize = 128;

/// Maximum character count of `mutable_ref_pin_diagnostics`' interpolated `name`/`tag`
/// values before truncation — mirrors
/// `deps_github_actions::ecosystem::MAX_MUTABLE_REF_PIN_MESSAGE_VALUE_CHARS` exactly (same
/// rationale: neither a `project:`/`component:` value nor a `ref:`/version pin has any
/// upstream length cap before it renders inline in a diagnostic).
const MAX_MUTABLE_REF_PIN_MESSAGE_VALUE_CHARS: usize = 128;

/// Whether `gl_dep`'s pin is diagnosable as a mutable tag ref — either because it was
/// already classified [`PinStyle::Tag`] from its text shape, or because `tag_index`'s live
/// fetch confirms the ref/pin text is a literal member of the project's published
/// tags/releases even though it doesn't *look* tag-shaped (mirrors
/// `deps_github_actions::ecosystem::is_registry_confirmed_tag`, issue #551's lesson: a
/// [`PinStyle::Branch`] classification is a registry-blind, honest-unknown guess, not
/// proof the ref is actually a moving branch).
///
/// Keyed on `(gl_dep.kind.endpoint(), gl_dep.name)` — validation finding S2: a
/// `PackageName` alone can collide between an unrelated `project:` and `component:`
/// include (spec §3.1's documented residual collision is same-project only; a
/// same-*text*-different-*project* collision is not covered by it), so the endpoint must
/// be part of the key to keep the two `TagIndex` entries from ever being read as one.
fn is_registry_confirmed_tag(
    gl_dep: &GitlabCiDependency,
    tag_index: &DashMap<(EndpointKind, PackageName), Arc<TagIndex>>,
) -> bool {
    match &gl_dep.pin {
        Some(PinStyle::Tag) => true,
        Some(PinStyle::Branch) => gl_dep
            .version_req
            .as_ref()
            .map(deps_core::VersionReq::as_str)
            .is_some_and(|ref_text| {
                tag_index
                    .get(&(gl_dep.kind.endpoint(), gl_dep.name.clone()))
                    .is_some_and(|index| index.tag_to_sha.contains_key(ref_text))
            }),
        Some(PinStyle::Sha | PinStyle::Latest | PinStyle::Partial) | None => false,
    }
}

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

    /// Appends the FR-012 informational unresolved-host diagnostic and the mutable-ref-pin
    /// diagnostic (issue #634) to the shared default's output — both additive, independent
    /// signals from the outdated-version diagnostic the shared default already computes.
    ///
    /// The mutable-ref-pin diagnostic is gated on `severities.mutable_ref_pin_enabled`,
    /// mirroring `deps_github_actions`'s identical gate: `severities.mutable_ref_pin` alone
    /// cannot silence it, since `DiagnosticSeverity` has no suppression value.
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

    /// Appends the "Pin to commit SHA" quickfix (issue #634) to the shared default's
    /// output when the position's dependency is a `PinStyle::Tag` include with a
    /// resolvable `TagIndex` entry, mirroring
    /// `deps_github_actions::ecosystem::GithubActionsEcosystem::generate_code_actions`.
    ///
    /// Also offers the same quickfix for a `component:` include pinned via
    /// `PinStyle::Latest`/`PinStyle::Partial` (validation follow-up C2/S2): unlike `Tag`,
    /// neither names a concrete version by itself, so `build_dynamic_component_pin_action`
    /// resolves it against the project's published releases through the same FR-007
    /// priority ladder `generate_hover`'s `**Resolved**` splice already drives.
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
            if let Some(action) = build_dynamic_component_pin_action(
                parse_result,
                position,
                uri,
                self.registry.as_ref(),
            )
            .await
            {
                actions.push(action);
            }
            actions
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
                && let Some(resolved_tag) =
                    self.formatter
                        .resolved_tag_for_sha(gl_dep.kind.endpoint(), dep.name(), sha)
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

/// Builds one mutable-ref-pin [`Diagnostic`] (issue #634) per diagnosable dependency in
/// `parse_result`:
/// - every `PinStyle::Tag` include (quickfix available);
/// - a `PinStyle::Branch` include `tag_index` confirms is actually a real published
///   tag/release (issue #551's lesson, see [`is_registry_confirmed_tag`]);
/// - every `PinStyle::Latest`/`PinStyle::Partial` `component:` include — both always
///   resolve to whichever release currently matches, so they are mutable by construction,
///   not merely by absence of registry confirmation (validation finding C3/#634 follow-up);
/// - a ref-less `project:` include (`pin: None`) — GitLab defaults an omitted `ref:` to the
///   project's default branch, which is exactly as mutable as an explicit branch ref, so
///   this is not the "nothing to say yet" case its `None` might suggest (same finding).
///
/// None of the last three get the "Pin to commit SHA" quickfix — [`build_sha_pin_action`]
/// stays restricted to `PinStyle::Tag` — so their message says so explicitly. Only
/// `PinStyle::Sha` and an *unconfirmed* `PinStyle::Branch` produce no diagnostic at all.
fn mutable_ref_pin_diagnostics(
    parse_result: &dyn ParseResultTrait,
    severity: DiagnosticSeverity,
    tag_index: &DashMap<(EndpointKind, PackageName), Arc<TagIndex>>,
) -> Vec<Diagnostic> {
    parse_result
        .dependencies()
        .into_iter()
        .filter_map(|dep| {
            let gl_dep = dep.as_any().downcast_ref::<GitlabCiDependency>()?;
            let name = truncate_for_diagnostic(
                gl_dep.name.as_str(),
                MAX_MUTABLE_REF_PIN_MESSAGE_VALUE_CHARS,
            );
            let noun = match gl_dep.kind {
                IncludeKind::Project => "project",
                IncludeKind::Component => "component",
            };

            let Some(pin) = &gl_dep.pin else {
                // Ref-less `project:` include: no `ref:` key at all, so there is no
                // version span to anchor on or edit — anchor on the `project:` value
                // itself, mirroring the FR-012 unresolved-host diagnostic's convention.
                return Some(Diagnostic {
                    range: gl_dep.name_range,
                    severity: Some(severity),
                    message: format!(
                        "{name} project has no `ref:`; GitLab CI defaults to the project's \
                         default branch, which is mutable — add an explicit `ref:` pinned to \
                         a tag or commit SHA (manual edit — no automated fix available)"
                    ),
                    code: Some(NumberOrString::String(
                        MUTABLE_REF_PIN_DIAGNOSTIC_CODE.into(),
                    )),
                    source: Some("deps-lsp".into()),
                    ..Default::default()
                });
            };

            let diagnosable = match pin {
                PinStyle::Tag | PinStyle::Latest | PinStyle::Partial => true,
                PinStyle::Branch => is_registry_confirmed_tag(gl_dep, tag_index),
                PinStyle::Sha => false,
            };
            if !diagnosable {
                return None;
            }

            let range = gl_dep.version_range?;
            let tag = gl_dep
                .version_req
                .as_ref()
                .map(deps_core::VersionReq::as_str)?;
            let tag = truncate_for_diagnostic(tag, MAX_MUTABLE_REF_PIN_MESSAGE_VALUE_CHARS);

            // Mirrors `deps_github_actions::ecosystem::mutable_ref_pin_diagnostics`'s C2
            // (#551) discipline: `build_sha_pin_action` deliberately stays restricted to a
            // statically-classified `PinStyle::Tag` (see that function's doc comment on
            // the branch/tag name-collision risk), so every other diagnosable form has no
            // automated fix behind `Cmd+.` here — the message must say so rather than
            // imply one is a keystroke away.
            let message = if matches!(pin, PinStyle::Tag) {
                format!(
                    "{name} {noun} is pinned to the mutable ref `{tag}`; pin to a full commit \
                     SHA to guard against ref mutation"
                )
            } else if matches!(pin, PinStyle::Latest | PinStyle::Partial) {
                format!(
                    "{name} {noun} is pinned to `{tag}`, which always resolves to whichever \
                     release currently matches rather than a fixed version; pin to an exact \
                     release and commit SHA to guard against ref mutation (manual edit — no \
                     automated fix available for this ref)"
                )
            } else {
                format!(
                    "{name} {noun} is pinned to the mutable ref `{tag}`; pin to a full commit \
                     SHA to guard against ref mutation (manual edit — no automated fix \
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

/// Builds the "Pin `{name}` to commit SHA" quickfix (issue #634) for the `PinStyle::Tag`
/// dependency at `position`, if [`GitlabCiFormatter::sha_pin_replacement_for`] resolves its
/// current tag/release name against the shared `TagIndex`.
///
/// Returns `None` (no destructive/no-op edit) when the dependency at `position` is not
/// `PinStyle::Tag`, has no `version_range`, or the `TagIndex` lookup misses (cache miss —
/// e.g. the document was opened before the registry fetch completed).
///
/// Deliberately **not** widened to [`is_registry_confirmed_tag`]'s `PinStyle::Branch` case
/// the way [`mutable_ref_pin_diagnostics`] is, mirroring
/// `deps_github_actions::ecosystem::build_sha_pin_action`'s identical pre-#551 guard: a
/// `PinStyle::Branch` include can share its ref/pin text with an unrelated tag of the same
/// name, and GitLab's own ref resolution for that collision is undocumented — an
/// *automated edit* that silently pins to the tag's commit could pin to a different commit
/// than the ref actually resolves to at run time. A diagnostic's advisory text carries no
/// such risk, but this destructive edit keeps the stricter guard.
fn build_sha_pin_action(
    parse_result: &dyn ParseResultTrait,
    position: Position,
    uri: &Uri,
    formatter: &GitlabCiFormatter,
) -> Option<CodeAction> {
    // Same lookup convention every other deps-lsp code action goes through (critic S2) —
    // not a hand-rolled position check.
    let dep = parse_result
        .dependencies()
        .into_iter()
        .find(|d| formatter.is_position_on_dependency(*d, position))?;

    let gl_dep = dep.as_any().downcast_ref::<GitlabCiDependency>()?;
    if gl_dep.pin != Some(PinStyle::Tag) {
        return None;
    }
    let version_range = gl_dep.version_range?;
    let tag = gl_dep
        .version_req
        .as_ref()
        .map(deps_core::VersionReq::as_str)?;
    let new_text = formatter.sha_pin_replacement_for(gl_dep.kind.endpoint(), &gl_dep.name, tag)?;

    let mut changes = std::collections::HashMap::new();
    changes.insert(
        uri.clone(),
        vec![TextEdit {
            range: version_range,
            new_text,
        }],
    );

    Some(CodeAction {
        title: format!("Pin {} to commit SHA", gl_dep.name),
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
/// times out.
async fn build_dynamic_component_pin_action(
    parse_result: &dyn ParseResultTrait,
    position: Position,
    uri: &Uri,
    registry: &GitlabCiRegistry,
) -> Option<CodeAction> {
    let dep = parse_result.dependencies().into_iter().find(|d| {
        d.version_range()
            .is_some_and(|r| deps_core::position_in_range(position, r))
    })?;
    let gl_dep = dep.as_any().downcast_ref::<GitlabCiDependency>()?;
    if gl_dep.kind != IncludeKind::Component {
        return None;
    }
    let pin @ (PinStyle::Latest | PinStyle::Partial) = gl_dep.pin.as_ref()? else {
        return None;
    };
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
            tracing::warn!(package = %dep.name(), %error, "C2 component pin quickfix resolution failed");
            return None;
        }
        Err(_) => {
            tracing::warn!(package = %dep.name(), "C2 component pin quickfix resolution timed out");
            return None;
        }
    };

    let mut changes = std::collections::HashMap::new();
    changes.insert(
        uri.clone(),
        vec![TextEdit {
            range: version_range,
            new_text: resolved.sha,
        }],
    );

    Some(CodeAction {
        title: format!("Pin {} to commit SHA", gl_dep.name),
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

    // --- issue #634: mutable-ref-pin diagnostic + "Pin to commit SHA" code action ---

    fn mutable_ref_pin_code() -> NumberOrString {
        NumberOrString::String(MUTABLE_REF_PIN_DIAGNOSTIC_CODE.into())
    }

    async fn diagnostics_for(content: &str, uri: &Uri) -> Vec<Diagnostic> {
        let cache = Arc::new(HttpCache::new());
        let eco = GitlabCiEcosystem::new(cache);
        let parse_result = eco.parse_manifest(content, uri).await.unwrap();
        let cached = std::collections::HashMap::new();
        let resolved = std::collections::HashMap::new();
        eco.generate_diagnostics(
            parse_result.as_ref(),
            deps_core::VersionData::new(&cached, &resolved),
            uri,
            deps_core::FreshnessSettings::default(),
            deps_core::lsp_helpers::DiagnosticSeverities::default(),
        )
        .await
    }

    #[tokio::test]
    async fn test_mutable_ref_pin_diagnostic_fires_for_tag_pin() {
        let uri = deps_core::test_util::test_uri("/repo/.gitlab-ci.yml");
        let content = "include:\n  - project: org/proj\n    ref: v1.0.0\n";

        let diagnostics = diagnostics_for(content, &uri).await;

        let found = diagnostics
            .iter()
            .find(|d| d.code == Some(mutable_ref_pin_code()))
            .expect("expected the mutable-ref-pin diagnostic for a PinStyle::Tag include");
        assert_eq!(found.severity, Some(DiagnosticSeverity::HINT));
        assert!(found.message.contains("v1.0.0"));
        assert!(!found.message.contains("manual edit"));
    }

    #[tokio::test]
    async fn test_mutable_ref_pin_diagnostic_does_not_fire_for_sha_pin() {
        let uri = deps_core::test_util::test_uri("/repo/.gitlab-ci.yml");
        let sha = "a".repeat(40);
        let content = format!("include:\n  - project: org/proj\n    ref: {sha}\n");

        let diagnostics = diagnostics_for(&content, &uri).await;

        assert!(
            !diagnostics
                .iter()
                .any(|d| d.code == Some(mutable_ref_pin_code())),
            "a PinStyle::Sha include must never get the mutable-ref-pin diagnostic"
        );
    }

    #[tokio::test]
    async fn test_mutable_ref_pin_diagnostic_does_not_fire_for_unconfirmed_branch_pin() {
        let uri = deps_core::test_util::test_uri("/repo/.gitlab-ci.yml");
        let content = "include:\n  - project: org/proj\n    ref: main\n";

        let diagnostics = diagnostics_for(content, &uri).await;

        assert!(
            !diagnostics
                .iter()
                .any(|d| d.code == Some(mutable_ref_pin_code())),
            "a PinStyle::Branch include with no TagIndex confirmation is an honest \
             unknown, not diagnosable as a mutable tag ref"
        );
    }

    /// Issue #551's lesson, mirrored from `deps_github_actions`: a `PinStyle::Branch`
    /// include the `TagIndex` confirms is actually a published tag must still get the
    /// diagnostic — with wording that says no automated fix is available (since
    /// `build_sha_pin_action` deliberately stays restricted to `PinStyle::Tag`).
    ///
    /// Validation Fix 1: seeds `tag_index` through the crate's own
    /// [`crate::registry::populate_tag_index_entries`] — the exact function
    /// `GitlabCiRegistry::fetch_route` calls with the raw, unfiltered tags response — rather
    /// than hand-building a `TagIndex` a real fetch could never produce. `cargo-deny` fails
    /// `tags_to_versions`' full-semver filter, so this specifically proves the
    /// registry-confirmed-Branch path is reachable via production data, not just the
    /// diagnostic function's isolated logic (see also
    /// `registry::tests::test_fetch_route_tags_indexes_non_semver_tag_for_registry_confirmation`
    /// for the same guarantee at the live-fetch layer).
    #[test]
    fn test_mutable_ref_pin_diagnostics_fires_for_registry_confirmed_branch() {
        let uri = deps_core::test_util::test_uri("/repo/.gitlab-ci.yml");
        let content = "include:\n  - project: org/proj\n    ref: cargo-deny\n";
        let policy = deps_core::net_policy::RegistryAccessPolicy::default();
        let instance_host = crate::host::GitlabInstanceHost::new(
            Arc::new(RwLock::new(None)),
            Arc::new(deps_core::net_policy::RegistryAccessPolicy::default()),
        );
        let parse_result =
            crate::parser::parse_gitlab_ci_yaml(content, &uri, &policy, &instance_host).unwrap();
        assert_eq!(parse_result.dependencies[0].pin, Some(PinStyle::Branch));

        let tag_index: DashMap<(EndpointKind, PackageName), Arc<TagIndex>> = DashMap::new();
        let sha = "a".repeat(40);
        crate::registry::populate_tag_index_entries(
            &tag_index,
            (
                EndpointKind::Tags,
                parse_result.dependencies[0].name.clone(),
            ),
            std::iter::once(("cargo-deny", sha.as_str())),
        );

        let diagnostics =
            mutable_ref_pin_diagnostics(&parse_result, DiagnosticSeverity::HINT, &tag_index);

        let found = diagnostics
            .iter()
            .find(|d| d.code == Some(mutable_ref_pin_code()))
            .expect("expected the mutable-ref-pin diagnostic for a registry-confirmed tag");
        assert!(
            found.message.contains("no automated fix available"),
            "a registry-confirmed-but-Branch ref has no quickfix, so the message must say \
             so; got: {}",
            found.message
        );
    }

    fn test_formatter() -> GitlabCiFormatter {
        GitlabCiFormatter::new(Arc::new(DashMap::new()), Arc::new(DashMap::new()))
    }

    /// Exercises `build_sha_pin_action` directly rather than through
    /// `GitlabCiEcosystem::generate_code_actions`: the shared default that override
    /// delegates to first drives a *live* registry fetch (to list "Update to X" actions),
    /// which would overwrite a hand-seeded `TagIndex` fixture with real GitLab data before
    /// this function ever runs — mirrors `deps_github_actions`'s identical test rationale.
    #[test]
    fn test_build_sha_pin_action_offers_quickfix_on_tag_index_hit() {
        let uri = deps_core::test_util::test_uri("/repo/.gitlab-ci.yml");
        let content = "include:\n  - project: org/proj\n    ref: v1.0.0\n";
        let policy = deps_core::net_policy::RegistryAccessPolicy::default();
        let instance_host = crate::host::GitlabInstanceHost::new(
            Arc::new(RwLock::new(None)),
            Arc::new(deps_core::net_policy::RegistryAccessPolicy::default()),
        );
        let parse_result =
            crate::parser::parse_gitlab_ci_yaml(content, &uri, &policy, &instance_host).unwrap();

        let formatter = test_formatter();
        let mut index = TagIndex::default();
        let sha = "a".repeat(40);
        index.tag_to_sha.insert("v1.0.0".to_string(), sha.clone());
        formatter.tag_index.insert(
            (
                EndpointKind::Tags,
                parse_result.dependencies[0].name.clone(),
            ),
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
        assert_eq!(text_edits[0].new_text, sha);
    }

    #[test]
    fn test_build_sha_pin_action_no_quickfix_on_tag_index_miss() {
        let uri = deps_core::test_util::test_uri("/repo/.gitlab-ci.yml");
        let content = "include:\n  - project: org/proj\n    ref: v1.0.0\n";
        let policy = deps_core::net_policy::RegistryAccessPolicy::default();
        let instance_host = crate::host::GitlabInstanceHost::new(
            Arc::new(RwLock::new(None)),
            Arc::new(deps_core::net_policy::RegistryAccessPolicy::default()),
        );
        let parse_result =
            crate::parser::parse_gitlab_ci_yaml(content, &uri, &policy, &instance_host).unwrap();

        let formatter = test_formatter();

        let position = deps_core::ParseResult::dependencies(&parse_result)[0]
            .version_range()
            .unwrap()
            .start;

        assert!(build_sha_pin_action(&parse_result, position, &uri, &formatter).is_none());
    }

    /// Mirrors `deps_github_actions`'s identical guard: a `PinStyle::Branch` include must
    /// never get the SHA-pin quickfix, even if a `TagIndex` entry happens to exist for its
    /// literal ref text (a branch and a tag can share one name).
    #[test]
    fn test_build_sha_pin_action_no_quickfix_for_branch_pin() {
        let uri = deps_core::test_util::test_uri("/repo/.gitlab-ci.yml");
        let content = "include:\n  - project: org/proj\n    ref: main\n";
        let policy = deps_core::net_policy::RegistryAccessPolicy::default();
        let instance_host = crate::host::GitlabInstanceHost::new(
            Arc::new(RwLock::new(None)),
            Arc::new(deps_core::net_policy::RegistryAccessPolicy::default()),
        );
        let parse_result =
            crate::parser::parse_gitlab_ci_yaml(content, &uri, &policy, &instance_host).unwrap();

        let formatter = test_formatter();
        let mut index = TagIndex::default();
        index.tag_to_sha.insert("main".to_string(), "a".repeat(40));
        formatter.tag_index.insert(
            (
                EndpointKind::Tags,
                parse_result.dependencies[0].name.clone(),
            ),
            Arc::new(index),
        );

        let position = deps_core::ParseResult::dependencies(&parse_result)[0]
            .version_range()
            .unwrap()
            .start;

        assert!(build_sha_pin_action(&parse_result, position, &uri, &formatter).is_none());
    }

    // --- validation finding C3: always-mutable pin forms with no explicit ref/tag text ---

    /// A `component:` include pinned to `~latest` always resolves to whichever release is
    /// currently newest — it is mutable by construction, not merely "unconfirmed", so it
    /// must get the diagnostic even though `PinStyle::Latest` is never registry-confirmed
    /// the way a `Branch` pin can be.
    #[tokio::test]
    async fn test_mutable_ref_pin_diagnostic_fires_for_latest_component_pin() {
        let uri = deps_core::test_util::test_uri("/repo/.gitlab-ci.yml");
        let content = "include:\n  - component: gitlab.com/org/proj/comp@~latest\n";

        let diagnostics = diagnostics_for(content, &uri).await;

        let found = diagnostics
            .iter()
            .find(|d| d.code == Some(mutable_ref_pin_code()))
            .expect("expected the mutable-ref-pin diagnostic for a PinStyle::Latest component");
        assert!(found.message.contains("~latest"));
        assert!(found.message.contains("no automated fix available"));
    }

    /// A `component:` include pinned to a partial version (`1.2`) always resolves to
    /// whichever release currently matches that range — equally mutable as `~latest`.
    #[tokio::test]
    async fn test_mutable_ref_pin_diagnostic_fires_for_partial_component_pin() {
        let uri = deps_core::test_util::test_uri("/repo/.gitlab-ci.yml");
        let content = "include:\n  - component: gitlab.com/org/proj/comp@1.2\n";

        let diagnostics = diagnostics_for(content, &uri).await;

        let found = diagnostics
            .iter()
            .find(|d| d.code == Some(mutable_ref_pin_code()))
            .expect("expected the mutable-ref-pin diagnostic for a PinStyle::Partial component");
        assert!(found.message.contains("1.2"));
        assert!(found.message.contains("no automated fix available"));
    }

    /// A `project:` include with no `ref:` key at all defaults to the project's default
    /// branch — exactly as mutable as an explicit branch ref, so `pin: None` must not be
    /// treated as "nothing to diagnose". No `version_range` exists to anchor on, so this
    /// anchors on `name_range` instead (mirroring the FR-012 unresolved-host diagnostic).
    #[tokio::test]
    async fn test_mutable_ref_pin_diagnostic_fires_for_ref_less_project_include() {
        let uri = deps_core::test_util::test_uri("/repo/.gitlab-ci.yml");
        let content = "include:\n  - project: org/proj\n";

        let diagnostics = diagnostics_for(content, &uri).await;

        let found = diagnostics
            .iter()
            .find(|d| d.code == Some(mutable_ref_pin_code()))
            .expect("expected the mutable-ref-pin diagnostic for a ref-less project include");
        assert!(found.message.contains("no `ref:`"));
        assert!(found.message.contains("no automated fix available"));
    }

    #[tokio::test]
    async fn test_mutable_ref_pin_diagnostic_fires_for_component_tag_pin() {
        let uri = deps_core::test_util::test_uri("/repo/.gitlab-ci.yml");
        let content = "include:\n  - component: gitlab.com/org/proj/comp@1.0.0\n";

        let diagnostics = diagnostics_for(content, &uri).await;

        let found = diagnostics
            .iter()
            .find(|d| d.code == Some(mutable_ref_pin_code()))
            .expect("expected the mutable-ref-pin diagnostic for a PinStyle::Tag component");
        assert!(found.message.contains("1.0.0"));
        assert!(found.message.contains("component"));
    }

    #[tokio::test]
    async fn test_mutable_ref_pin_diagnostic_suppressed_when_disabled() {
        let uri = deps_core::test_util::test_uri("/repo/.gitlab-ci.yml");
        let content = "include:\n  - project: org/proj\n    ref: v1.0.0\n";
        let cache = Arc::new(HttpCache::new());
        let eco = GitlabCiEcosystem::new(cache);
        let parse_result = eco.parse_manifest(content, &uri).await.unwrap();
        let cached = std::collections::HashMap::new();
        let resolved = std::collections::HashMap::new();

        let diagnostics = eco
            .generate_diagnostics(
                parse_result.as_ref(),
                deps_core::VersionData::new(&cached, &resolved),
                &uri,
                deps_core::FreshnessSettings::default(),
                deps_core::lsp_helpers::DiagnosticSeverities {
                    mutable_ref_pin_enabled: false,
                    ..Default::default()
                },
            )
            .await;

        assert!(
            !diagnostics
                .iter()
                .any(|d| d.code == Some(mutable_ref_pin_code())),
            "mutable_ref_pin_enabled: false must suppress the diagnostic entirely"
        );
    }

    #[tokio::test]
    async fn test_mutable_ref_pin_diagnostics_multiple_includes_no_cross_contamination() {
        let uri = deps_core::test_util::test_uri("/repo/.gitlab-ci.yml");
        let content = "include:\n  - project: org/proj1\n    ref: v1.0.0\n  - project: org/proj2\n    ref: v2.0.0\n";

        let diagnostics = diagnostics_for(content, &uri).await;
        let mut found: Vec<_> = diagnostics
            .iter()
            .filter(|d| d.code == Some(mutable_ref_pin_code()))
            .collect();
        assert_eq!(found.len(), 2, "both Tag-pinned includes must be flagged");
        found.sort_by_key(|d| d.range.start.line);
        assert!(found[0].message.contains("v1.0.0"));
        assert!(!found[0].message.contains("v2.0.0"));
        assert!(found[1].message.contains("v2.0.0"));
        assert!(!found[1].message.contains("v1.0.0"));
    }

    #[test]
    fn test_build_sha_pin_action_multiple_includes_applies_matching_sha() {
        let uri = deps_core::test_util::test_uri("/repo/.gitlab-ci.yml");
        let content = "include:\n  - project: org/proj1\n    ref: v1.0.0\n  - project: org/proj2\n    ref: v2.0.0\n";
        let policy = deps_core::net_policy::RegistryAccessPolicy::default();
        let instance_host = crate::host::GitlabInstanceHost::new(
            Arc::new(RwLock::new(None)),
            Arc::new(deps_core::net_policy::RegistryAccessPolicy::default()),
        );
        let parse_result =
            crate::parser::parse_gitlab_ci_yaml(content, &uri, &policy, &instance_host).unwrap();
        assert_eq!(parse_result.dependencies.len(), 2);

        let formatter = test_formatter();
        let sha1 = "1".repeat(40);
        let sha2 = "2".repeat(40);
        let mut index1 = TagIndex::default();
        index1.tag_to_sha.insert("v1.0.0".to_string(), sha1.clone());
        formatter.tag_index.insert(
            (
                EndpointKind::Tags,
                parse_result.dependencies[0].name.clone(),
            ),
            Arc::new(index1),
        );
        let mut index2 = TagIndex::default();
        index2.tag_to_sha.insert("v2.0.0".to_string(), sha2.clone());
        formatter.tag_index.insert(
            (
                EndpointKind::Tags,
                parse_result.dependencies[1].name.clone(),
            ),
            Arc::new(index2),
        );

        let position0 = deps_core::ParseResult::dependencies(&parse_result)[0]
            .version_range()
            .unwrap()
            .start;
        let position1 = deps_core::ParseResult::dependencies(&parse_result)[1]
            .version_range()
            .unwrap()
            .start;

        let action0 = build_sha_pin_action(&parse_result, position0, &uri, &formatter)
            .expect("expected a quickfix for the first include");
        let action1 = build_sha_pin_action(&parse_result, position1, &uri, &formatter)
            .expect("expected a quickfix for the second include");

        let edit0 = action0.edit.as_ref().unwrap();
        let edit1 = action1.edit.as_ref().unwrap();
        assert_eq!(edit0.changes.as_ref().unwrap()[&uri][0].new_text, sha1);
        assert_eq!(edit1.changes.as_ref().unwrap()[&uri][0].new_text, sha2);
    }

    /// Validation Fix 2 regression, exercised at the actual quickfix-production boundary
    /// (not just the raw `TagIndex`, see `registry::tests::test_tag_index_keyed_by_endpoint_no_cross_kind_collision`):
    /// a `project:` include for repo `org/proj/comp` and a `component:` include naming
    /// component `comp` inside project `org/proj` share the identical host-qualified
    /// `PackageName` text. Before keying `TagIndex` by `(EndpointKind, PackageName)`, the
    /// second seeded entry would silently overwrite the first, and `build_sha_pin_action`
    /// would apply the wrong repository's SHA to whichever include was queried second.
    #[test]
    fn test_build_sha_pin_action_no_cross_kind_collision() {
        let uri = deps_core::test_util::test_uri("/repo/.gitlab-ci.yml");
        let content = "include:\n  - project: org/proj/comp\n    ref: v1.0.0\n  - component: gitlab.com/org/proj/comp@1.0.0\n";
        let (policy, instance_host) = {
            let policy = deps_core::net_policy::RegistryAccessPolicy::default();
            let instance_host = crate::host::GitlabInstanceHost::new(
                Arc::new(RwLock::new(Some("gitlab.com".to_string()))),
                Arc::new(deps_core::net_policy::RegistryAccessPolicy::default()),
            );
            (policy, instance_host)
        };
        let parse_result =
            crate::parser::parse_gitlab_ci_yaml(content, &uri, &policy, &instance_host).unwrap();
        assert_eq!(parse_result.dependencies.len(), 2);
        // Both includes resolve to the identical host-qualified name despite being
        // unrelated resources — the exact collision this fix guards against.
        assert_eq!(
            parse_result.dependencies[0].name,
            parse_result.dependencies[1].name
        );

        let formatter = test_formatter();
        let project_sha = "1".repeat(40);
        let component_sha = "2".repeat(40);
        let mut project_index = TagIndex::default();
        project_index
            .tag_to_sha
            .insert("v1.0.0".to_string(), project_sha.clone());
        formatter.tag_index.insert(
            (
                EndpointKind::Tags,
                parse_result.dependencies[0].name.clone(),
            ),
            Arc::new(project_index),
        );
        let mut component_index = TagIndex::default();
        component_index
            .tag_to_sha
            .insert("1.0.0".to_string(), component_sha.clone());
        formatter.tag_index.insert(
            (
                EndpointKind::Releases,
                parse_result.dependencies[1].name.clone(),
            ),
            Arc::new(component_index),
        );

        let position0 = deps_core::ParseResult::dependencies(&parse_result)[0]
            .version_range()
            .unwrap()
            .start;
        let position1 = deps_core::ParseResult::dependencies(&parse_result)[1]
            .version_range()
            .unwrap()
            .start;

        let action0 = build_sha_pin_action(&parse_result, position0, &uri, &formatter)
            .expect("expected a quickfix for the project: include");
        let action1 = build_sha_pin_action(&parse_result, position1, &uri, &formatter)
            .expect("expected a quickfix for the component: include");

        assert_eq!(
            action0.edit.as_ref().unwrap().changes.as_ref().unwrap()[&uri][0].new_text,
            project_sha,
            "the project: include must resolve its own Tags-route SHA, not the component's"
        );
        assert_eq!(
            action1.edit.as_ref().unwrap().changes.as_ref().unwrap()[&uri][0].new_text,
            component_sha,
            "the component: include must resolve its own Releases-route SHA, not the project's"
        );
    }

    // --- validation follow-up C2/S2: quickfix for Latest/Partial component pins ---

    fn component_pin_test_setup(
        server: &mockito::ServerGuard,
        pin: PinStyle,
        version_req: &str,
    ) -> (
        GitlabCiRegistry,
        crate::types::GitlabCiParseResult,
        Uri,
        Position,
    ) {
        let policy = Arc::new(deps_core::net_policy::RegistryAccessPolicy::default());
        let instance_host = Arc::new(crate::host::GitlabInstanceHost::new(
            Arc::new(RwLock::new(None)),
            Arc::clone(&policy),
        ));
        let client = Arc::new(GitlabApiClient::new(
            Arc::new(HttpCache::new()),
            instance_host,
        ));
        let registry = GitlabCiRegistry::new(client);

        let host_bare = server.url();
        let name = PackageName::new(format!("{host_bare}/org/proj/comp"));
        let index = "gitlab:component-pin-test".to_string();
        registry.register_routes(&[(
            index.clone(),
            crate::types::GitlabRoute {
                origin: host_bare.clone(),
                endpoint: EndpointKind::Releases,
            },
        )]);

        let range = tower_lsp_server::ls_types::Range::new(
            tower_lsp_server::ls_types::Position::new(0, 0),
            tower_lsp_server::ls_types::Position::new(0, version_req.len() as u32),
        );
        let dep = GitlabCiDependency {
            name,
            name_range: range,
            version_req: Some(version_req.into()),
            version_range: Some(range),
            version_literal: None,
            source: deps_core::parser::DependencySource::AlternateRegistry {
                index,
                mirrors_crates_io: false,
            },
            is_plain_scalar: true,
            kind: IncludeKind::Component,
            host: HostRef::Literal(crate::host::GitlabHost::for_test(&host_bare)),
            pin: Some(pin),
            project_path: "org/proj".to_string(),
        };
        let uri = deps_core::test_util::test_uri("/repo/.gitlab-ci.yml");
        let parse_result = crate::types::GitlabCiParseResult {
            dependencies: vec![dep],
            routes: vec![],
            uri: uri.clone(),
        };
        (registry, parse_result, uri, range.start)
    }

    #[tokio::test]
    async fn test_build_dynamic_component_pin_action_offers_quickfix_for_latest_pin() {
        let mut server = mockito::Server::new_async().await;
        let sha = "a".repeat(40);
        let _releases_mock = server
            .mock("GET", "/api/v4/projects/org%2Fproj/releases")
            .match_query(mockito::Matcher::Any)
            .with_status(200)
            .with_body(format!(
                r#"[{{"tag_name":"2.0.0","commit":{{"id":"{sha}"}}}}]"#
            ))
            .create_async()
            .await;

        let (registry, parse_result, uri, position) =
            component_pin_test_setup(&server, PinStyle::Latest, "~latest");

        let action = build_dynamic_component_pin_action(&parse_result, position, &uri, &registry)
            .await
            .expect("expected a quickfix resolving ~latest to a concrete SHA");
        assert_eq!(
            action.edit.as_ref().unwrap().changes.as_ref().unwrap()[&uri][0].new_text,
            sha
        );
    }

    #[tokio::test]
    async fn test_build_dynamic_component_pin_action_offers_quickfix_for_partial_pin() {
        let mut server = mockito::Server::new_async().await;
        let sha = "b".repeat(40);
        let _releases_mock = server
            .mock("GET", "/api/v4/projects/org%2Fproj/releases")
            .match_query(mockito::Matcher::Any)
            .with_status(200)
            .with_body(format!(
                r#"[{{"tag_name":"1.2.5","commit":{{"id":"{sha}"}}}}]"#
            ))
            .create_async()
            .await;

        let (registry, parse_result, uri, position) =
            component_pin_test_setup(&server, PinStyle::Partial, "1.2");

        let action = build_dynamic_component_pin_action(&parse_result, position, &uri, &registry)
            .await
            .expect("expected a quickfix resolving the partial pin to a concrete SHA");
        assert_eq!(
            action.edit.as_ref().unwrap().changes.as_ref().unwrap()[&uri][0].new_text,
            sha
        );
    }

    #[tokio::test]
    async fn test_build_dynamic_component_pin_action_no_quickfix_when_nothing_matches() {
        let mut server = mockito::Server::new_async().await;
        let _releases_mock = server
            .mock("GET", "/api/v4/projects/org%2Fproj/releases")
            .match_query(mockito::Matcher::Any)
            .with_status(200)
            .with_body("[]")
            .create_async()
            .await;

        let (registry, parse_result, uri, position) =
            component_pin_test_setup(&server, PinStyle::Partial, "1.2");

        assert!(
            build_dynamic_component_pin_action(&parse_result, position, &uri, &registry)
                .await
                .is_none()
        );
    }

    /// Neither a `project:` include nor a `component:` `PinStyle::Tag`/`PinStyle::Branch`
    /// pin is ever resolved by this function — it exists solely for `Latest`/`Partial`.
    #[tokio::test]
    async fn test_build_dynamic_component_pin_action_ignores_non_latest_partial_pins() {
        let server = mockito::Server::new_async().await;
        let (registry, parse_result, uri, position) =
            component_pin_test_setup(&server, PinStyle::Tag, "1.0.0");

        assert!(
            build_dynamic_component_pin_action(&parse_result, position, &uri, &registry)
                .await
                .is_none()
        );
    }
}
