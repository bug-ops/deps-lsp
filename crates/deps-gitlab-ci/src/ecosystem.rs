//! GitLab CI ecosystem implementation for deps-lsp.

#[cfg(test)]
#[cfg(feature = "lsp-responses")]
use deps_core::PackageName;
#[cfg(feature = "lsp-responses")]
use deps_core::completion::Completions;
#[cfg(feature = "lsp-responses")]
use deps_core::hover::Hover;
#[cfg(feature = "lsp-responses")]
use deps_core::lsp_helpers::sha_comment_mismatch_hover_line;
#[cfg(feature = "lsp-responses")]
use deps_core::lsp_helpers::{PackageNaming, PackageRendering};
use deps_core::net_policy::RegistryAccessPolicy;
use deps_core::{
    Dependency, Ecosystem, HttpCache, ParseResult as ParseResultTrait, Registry, Result,
    diagnostic::{Diagnostic, DiagnosticKind, GitTagsPlatform, Severity},
    lsp_helpers::{
        CommentCheck, EcosystemFormatter, MAX_DIAGNOSTIC_VALUE_CHARS, UnknownRefTarget,
        sanitize_and_truncate_for_diagnostic, sha_comment_mismatch_diagnostic,
        unknown_ref_diagnostics,
    },
};
use std::any::Any;
use std::sync::{Arc, RwLock};
#[cfg(feature = "lsp-responses")]
use tower_lsp_server::ls_types::{CodeAction, Position, TextEdit};
use url::Url;

use crate::client::GitlabApiClient;
use crate::formatter::GitlabCiFormatter;
use crate::host::GitlabInstanceHost;
#[cfg(feature = "lsp-responses")]
use crate::host::is_valid_gitlab_coordinate;
use crate::registry::GitlabCiRegistry;
use crate::types::{GitlabCiDependency, HostRef, IncludeKind, PinStyle};

#[cfg(feature = "lsp-responses")]
mod lsp;
#[cfg(feature = "lsp-responses")]
use lsp::{
    COMPONENT_PIN_RESOLUTION_TIMEOUT, VERSION_OPERATOR_CHARS, build_dynamic_component_pin_action,
    build_sha_comment_fix_action, build_sha_pin_action, build_unknown_ref_fix_action,
    collect_pin_all_to_sha_edits, splice_project_line,
};

/// Maximum character count of an interpolated raw host expression before truncation —
/// mirrors `deps_core::lsp_helpers::MAX_DIAGNOSTIC_VALUE_CHARS`'s numeric bound — a
/// separate `= 128` literal, not derived from it, out of #1278's scope (that issue's
/// nine-constant list did not include this one).
const MAX_UNRESOLVED_HOST_MESSAGE_VALUE_CHARS: usize = 128;

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
fn is_registry_confirmed_tag(gl_dep: &GitlabCiDependency, formatter: &GitlabCiFormatter) -> bool {
    match &gl_dep.pin {
        Some(PinStyle::Tag) => true,
        Some(PinStyle::Branch) => gl_dep
            .version_req
            .as_ref()
            .map(deps_core::VersionReq::as_str)
            .is_some_and(|ref_text| {
                formatter
                    .tag_index
                    .get(&(gl_dep.kind.endpoint(), gl_dep.name.clone()))
                    .is_some_and(|index| index.tag_to_sha.contains_key(ref_text))
            }),
        Some(PinStyle::Sha { .. } | PinStyle::Latest | PinStyle::Partial) | None => false,
    }
}

/// Which "Pin to commit SHA" quickfix a diagnosable pin resolves to, if any — the single
/// source of truth for both [`mutable_ref_pin_diagnostics`]'s message text (issue #643)
/// and `generate_code_actions`'s dispatch, so the two can never independently drift about
/// whether a quickfix is actually available.
enum ShaPinQuickfixKind {
    /// A `PinStyle::Tag` pin, resolved synchronously against the shared `TagIndex` — see
    /// [`build_sha_pin_action`].
    StaticTagIndex,
    /// A `component:` include pinned via `PinStyle::Latest`/`PinStyle::Partial`, resolved
    /// against the project's published releases — see
    /// [`build_dynamic_component_pin_action`]. Only when the dependency's route was
    /// actually registered (mirrors that function's own guard exactly, spec 048 FR-001):
    /// an `Unresolved`/`CapacityRefused` host has no route and therefore no quickfix.
    DynamicComponentPin,
}

/// Classifies `dep`/`gl_dep`'s pin against the two quickfix builders' own guards, so
/// message construction and quickfix dispatch read from one place instead of maintaining
/// two independent guards that can drift (issue #643).
fn sha_pin_quickfix_kind(
    dep: &dyn deps_core::Dependency,
    gl_dep: &GitlabCiDependency,
    formatter: &GitlabCiFormatter,
) -> Option<ShaPinQuickfixKind> {
    // FR-010: the single withholding gate for all three SHA-pin call sites (issue #643) —
    // an alias token (`ref: *pin`) is not an editable literal, so no quickfix may ever
    // target it. Checked before consulting `pin` at all.
    if gl_dep.is_alias_occurrence {
        return None;
    }
    match &gl_dep.pin {
        Some(PinStyle::Tag) => Some(ShaPinQuickfixKind::StaticTagIndex),
        Some(PinStyle::Latest | PinStyle::Partial) if gl_dep.kind == IncludeKind::Component => {
            let deps_core::parser::DependencySource::AlternateRegistry { index, .. } = dep.source()
            else {
                return None;
            };
            formatter
                .routes
                .contains_key(&index)
                .then_some(ShaPinQuickfixKind::DynamicComponentPin)
        }
        _ => None,
    }
}

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
    /// the production wiring path (`deps_engine::setup::register_ecosystems`), mirroring
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
        let client = Arc::new(GitlabApiClient::new(cache));
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
    fn ecosystem_id(&self) -> deps_core::EcosystemId {
        deps_core::EcosystemId::GitlabCi
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
        uri: &'a Url,
    ) -> deps_core::ecosystem::BoxFuture<'a, Result<Box<dyn ParseResultTrait>>> {
        Box::pin(async move {
            let mut result = crate::parser::parse_gitlab_ci_yaml(
                content,
                uri,
                &self.policy,
                &self.instance_host,
            )?;
            let refused = self.registry.register_alternate(&result.routes);
            if !refused.is_empty() {
                for dep in &mut result.dependencies {
                    if let deps_core::parser::DependencySource::AlternateRegistry { index, .. } =
                        &dep.source
                        && refused.contains(index)
                    {
                        // The `PolicyBlocked` alternative is unreachable in practice: it never
                        // produces a route (`build_source_and_route` returns `None` for it),
                        // so its source is never `AlternateRegistry` — included only for match
                        // exhaustiveness.
                        let origin = match &dep.host {
                            HostRef::Literal(host) => host.origin().to_string(),
                            HostRef::Unresolved(raw)
                            | HostRef::CapacityRefused(raw)
                            | HostRef::PolicyBlocked { raw, .. } => raw.clone(),
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

    /// Emits a project's name whenever a tags or releases fetch first populates its tag index
    /// or observably changes it; see [`GitlabCiRegistry::subscribe_tag_refreshes`].
    fn tag_index_refreshes(&self) -> Option<deps_core::TagIndexRefreshes> {
        Some(self.registry.subscribe_tag_refreshes())
    }

    fn formatter(&self) -> &dyn EcosystemFormatter {
        &self.formatter
    }

    // No override for `complete_package_name`: GitLab CI has no package-name search
    // endpoint (spec NFR-002 — an include only ever references an already-known
    // project/component path), so the inherited default (`Completions::default()`) is
    // correct — see M3 (#793).

    /// Version completions only, resolved through the source-aware
    /// [`deps_core::completion::complete_versions_generic_from`] (spec §7a.1) — the
    /// source-unaware default would return nothing, since this crate's `Registry` never
    /// resolves an unsourced fetch. The dependency's `source` is resolved **by position**,
    /// not by name: a `project:` and a `component:` include of the same project can share
    /// one `PackageName` (spec §3.1's documented residual collision), and a by-name lookup
    /// would risk picking the wrong one's source.
    #[cfg(feature = "lsp-responses")]
    fn complete_version<'a>(
        &'a self,
        request: deps_core::completion::CompletionRequest<'a>,
        _package_name: deps_core::PackageName,
        prefix: String,
    ) -> deps_core::ecosystem::BoxFuture<'a, Completions> {
        Box::pin(async move {
            let Some(dep) = request.parse_result.dependencies().into_iter().find(|d| {
                d.version_range()
                    .is_some_and(|r| deps_core::position_in_range(request.position.into(), r))
            }) else {
                return Completions::default();
            };
            // FR-011: withheld independently of `sha_pin_quickfix_kind` — completion is not
            // reached through that function. An alias token's `version_range` is not a
            // literal, so splicing a version string at the cursor would corrupt it.
            //
            // #912 critic S3: `deps_core::completion::detect_completion_context` already
            // rejects a non-literal `version_range` generically (`#922`,
            // `dependency_version_range_is_literal`), so for a genuine alias site this
            // `CompletionContext::Version` branch — and this whole `complete_version` call
            // — is never reached in the first place. This local check is kept as explicit
            // defense-in-depth (and as FR-011's literal specification), not as the
            // load-bearing gate.
            if dep
                .as_any()
                .downcast_ref::<GitlabCiDependency>()
                .is_some_and(|gl_dep| gl_dep.is_alias_occurrence)
            {
                return Completions::default();
            }

            if dep
                .as_any()
                .downcast_ref::<GitlabCiDependency>()
                .is_some_and(|gl_dep| position_in_sha_comment(gl_dep, request.position.into()))
            {
                return Completions::default();
            }

            deps_core::completion::complete_versions_generic_from(
                self.registry.as_ref(),
                &self.formatter,
                dep.name(),
                &dep.source(),
                &prefix,
                VERSION_OPERATOR_CHARS,
                request.freshness,
                &request.parse_result.selection_context(),
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
            diagnostics.extend(unresolved_host_diagnostics(parse_result));
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
            if severities.mutable_ref_pin_enabled {
                diagnostics.extend(mutable_ref_pin_diagnostics(
                    parse_result,
                    severities.mutable_ref_pin,
                    &self.formatter,
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
            if let Some(action) = build_dynamic_component_pin_action(
                parse_result,
                position,
                uri,
                &self.formatter,
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
            let Some(gl_dep) = dep.as_any().downcast_ref::<GitlabCiDependency>() else {
                return Some(hover);
            };

            if gl_dep.kind == IncludeKind::Component
                && let HostRef::Literal(host) = &gl_dep.host
                && is_valid_gitlab_coordinate(&gl_dep.project_path)
            {
                let url = format!("https://{}/{}", host.host(), gl_dep.project_path);
                hover.rewrite_markdown(|md| splice_project_line(md, &url));
            }

            if let Some(sha) = gl_dep.pinned_sha()
                && let Some(resolved_tag) =
                    self.formatter
                        .resolved_tag_for_sha(gl_dep.kind.endpoint(), dep.name(), sha)
            {
                hover.rewrite_markdown(|md| {
                    deps_core::lsp_helpers::splice_resolved_line(md, &resolved_tag, sha)
                });
            }

            if let Some(CommentCheck::Mismatch(mismatch)) = self.formatter.sha_comment_check(gl_dep)
                && let Some(comment) = gl_dep.sha_comment()
                && let Some(sha) = gl_dep.pinned_sha()
            {
                let line = sha_comment_mismatch_hover_line(sha, &comment.tag, &mismatch);
                hover.rewrite_markdown(|md| deps_core::lsp_helpers::splice_hover_line(md, &line));
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
                        if let Some(sha) = &resolved.sha {
                            hover.rewrite_markdown(|md| {
                                deps_core::lsp_helpers::splice_resolved_line(
                                    md,
                                    resolved.version.as_str(),
                                    sha,
                                )
                            });
                        }
                    }
                    Ok(Ok(None)) => {}
                    Ok(Err(error)) => {
                        tracing::warn!(package = %dep.name().for_tracing(), %error, "FR-007 component pin resolution failed");
                    }
                    Err(_) => {
                        tracing::warn!(package = %dep.name().for_tracing(), "FR-007 component pin resolution timed out");
                    }
                }
            }

            Some(hover)
        })
    }

    fn completion_insert_text(&self, metadata: &dyn deps_core::Metadata) -> Option<String> {
        let name = metadata.name();
        let latest = metadata.latest_version().as_str();
        // `search()` always returns `Ok(vec![])` (spec NFR-002 — no cheap GitLab
        // search endpoint under the rate-limit budget), so this is unreachable in
        // practice; it exists only to keep the trait implementation total. GitLab CI
        // has two structurally different include forms (`project:`+`ref:` vs.
        // `component:` `name@ref`), so there is no single insertable snippet shape —
        // this mirrors GitHub Actions' bare `name`/`name@version` fallback.
        if latest.is_empty() {
            Some(name.as_str().to_string())
        } else {
            Some(format!("{}@{latest}", name.as_str()))
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    /// One [`TextEdit`] per mutable-ref dependency in `parse_result` resolvable to a
    /// commit SHA without a network fetch (issue #640) — the bulk counterpart of
    /// `build_sha_pin_action`/`build_dynamic_component_pin_action`'s per-position
    /// quickfixes. `versions` supplies the already-fetched release list a `component:`
    /// `Latest`/`Partial` pin needs to resolve (see the crate-private
    /// `collect_pin_all_to_sha_edits` free function this delegates to): a lens is
    /// push-based and must never itself trigger a fetch.
    #[cfg(feature = "lsp-responses")]
    fn collect_pin_all_to_sha_edits(
        &self,
        parse_result: &dyn ParseResultTrait,
        versions: deps_core::VersionData<'_>,
    ) -> Vec<TextEdit> {
        collect_pin_all_to_sha_edits(parse_result, &self.formatter, versions)
    }

    // `pin_all_to_sha_noun` is deliberately left at the trait default (`{"ref", "refs"}`,
    // M6): it already matches this ecosystem's own vocabulary (every mutable-ref-pin
    // diagnostic message here already says "ref"), so overriding it would only restate
    // the default.
}

fn unresolved_host_diagnostics(parse_result: &dyn ParseResultTrait) -> Vec<Diagnostic> {
    // #1254: redact before sanitizing/truncating so a credential can't survive a cut.
    let redact_and_sanitize = |s: &str| {
        sanitize_and_truncate_for_diagnostic(
            &deps_core::net_policy::redact_declaration_key(s),
            MAX_UNRESOLVED_HOST_MESSAGE_VALUE_CHARS,
        )
    };
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
                    let raw = redact_and_sanitize(raw);
                    format!(
                        "Cannot determine the GitLab instance host for '{raw}'. Set the \
                         `registries.gitlab_instance_host` setting to enable version resolution."
                    )
                }
                HostRef::CapacityRefused(origin) => {
                    let origin = redact_and_sanitize(origin);
                    format!(
                        "'{origin}' was not registered for version resolution because a \
                         GitLab CI host/route capacity limit was reached. Reduce the number of \
                         distinct GitLab hosts or includes referenced in this workspace \
                         (unrelated to the `registries.gitlab_instance_host` setting)."
                    )
                }
                // Issue #967: a policy-blocked host is surfaced through
                // `ParseResult::blocked_registries` (via `generate_diagnostics_from_cache`'s
                // shared `blocked_registry_diagnostics` path) instead — the host itself is
                // fully determinable, so the `Unresolved` message above (which tells the user
                // to set `registries.gitlab_instance_host`) would misattribute the cause.
                HostRef::Literal(_) | HostRef::PolicyBlocked { .. } => return None,
            };
            Some(
                Diagnostic::new(
                    DiagnosticKind::UnresolvedGitlabHost,
                    gl_dep.name_range,
                    message,
                )
                .with_severity(Severity::Information),
            )
        })
        .collect()
}

/// Builds one mutable-ref-pin [`Diagnostic`] (issue #634) per diagnosable dependency in
/// `parse_result`:
/// - every `PinStyle::Tag` include (quickfix available);
/// - a `PinStyle::Branch` include `formatter`'s `TagIndex` confirms is actually a real
///   published tag/release (issue #551's lesson, see [`is_registry_confirmed_tag`]);
/// - every `PinStyle::Latest`/`PinStyle::Partial` `component:` include — both always
///   resolve to whichever release currently matches, so they are mutable by construction,
///   not merely by absence of registry confirmation (validation finding C3/#634 follow-up);
/// - a ref-less `project:` include (`pin: None`) — GitLab defaults an omitted `ref:` to the
///   project's default branch, which is exactly as mutable as an explicit branch ref, so
///   this is not the "nothing to say yet" case its `None` might suggest (same finding).
///
/// Whether a diagnosable form's message carries the "manual edit — no automated fix
/// available" suffix is decided by [`sha_pin_quickfix_kind`] — the single source of truth
/// for whether `generate_code_actions` actually offers a quickfix for this dependency, so
/// this message and that dispatch cannot independently drift apart again (issue #643).
/// `PinStyle::Sha` and an *unconfirmed* `PinStyle::Branch` produce no diagnostic at all.
fn mutable_ref_pin_diagnostics(
    parse_result: &dyn ParseResultTrait,
    severity: Severity,
    formatter: &GitlabCiFormatter,
) -> Vec<Diagnostic> {
    parse_result
        .dependencies()
        .into_iter()
        .filter_map(|dep| {
            let gl_dep = dep.as_any().downcast_ref::<GitlabCiDependency>()?;
            let name = deps_core::lsp_helpers::redact_name_for_diagnostic(&gl_dep.name);
            let noun = match gl_dep.kind {
                IncludeKind::Project => "project",
                IncludeKind::Component => "component",
            };

            let Some(pin) = &gl_dep.pin else {
                // Ref-less `project:` include: no `ref:` key at all, so there is no
                // version span to anchor on or edit — anchor on the `project:` value
                // itself, mirroring the FR-012 unresolved-host diagnostic's convention.
                return Some(
                    Diagnostic::new(
                        DiagnosticKind::MutableRefPin(GitTagsPlatform::GitlabCi),
                        gl_dep.name_range,
                        format!(
                            "{name} project has no `ref:`; GitLab CI defaults to the project's \
                             default branch, which is mutable — add an explicit `ref:` pinned \
                             to a tag or commit SHA (manual edit — no automated fix available)"
                        ),
                    )
                    .with_severity(severity),
                );
            };

            let diagnosable = match pin {
                PinStyle::Tag | PinStyle::Latest | PinStyle::Partial => true,
                PinStyle::Branch => is_registry_confirmed_tag(gl_dep, formatter),
                PinStyle::Sha { .. } => false,
            };
            if !diagnosable {
                return None;
            }

            let range = gl_dep.version_range?;
            let tag = gl_dep
                .version_req
                .as_ref()
                .map(deps_core::VersionReq::as_str)?;
            let tag = sanitize_and_truncate_for_diagnostic(tag, MAX_DIAGNOSTIC_VALUE_CHARS);

            // Issue #643/S1,S2: `sha_pin_quickfix_kind` is the single source of truth for
            // whether a quickfix is actually available for this dependency — the same
            // predicate `build_sha_pin_action`/`build_dynamic_component_pin_action` consult
            // for their own guards — so the suffix decision below can never independently
            // drift from what `generate_code_actions` actually offers. `PinStyle::Tag`
            // always classifies `Some(StaticTagIndex)` (even on a cold `TagIndex` miss —
            // the *diagnostic* doesn't need a live cache hit the way the quickfix build
            // does, so `Tag`'s message never carries the suffix regardless of cache state,
            // by design); a registry-confirmed `PinStyle::Branch` always classifies `None`
            // (`build_sha_pin_action` stays restricted to `Tag` only, C2/#551 branch/tag
            // name-collision risk), so its message always carries the suffix.
            let has_quickfix = sha_pin_quickfix_kind(dep, gl_dep, formatter).is_some();
            let manual_edit_suffix = if has_quickfix {
                ""
            } else {
                " (manual edit — no automated fix available for this ref)"
            };

            let message = if matches!(pin, PinStyle::Tag) {
                format!(
                    "{name} {noun} is pinned to the mutable ref `{tag}`; pin to a full commit \
                     SHA to guard against ref mutation{manual_edit_suffix}"
                )
            } else if matches!(pin, PinStyle::Latest | PinStyle::Partial) {
                format!(
                    "{name} {noun} is pinned to `{tag}`, which always resolves to whichever \
                     release currently matches rather than a fixed version; pin to an exact \
                     release and commit SHA to guard against ref mutation{manual_edit_suffix}"
                )
            } else {
                format!(
                    "{name} {noun} is pinned to the mutable ref `{tag}`; pin to a full commit \
                     SHA to guard against ref mutation{manual_edit_suffix}"
                )
            };
            Some(
                Diagnostic::new(
                    DiagnosticKind::MutableRefPin(GitTagsPlatform::GitlabCi),
                    range,
                    message,
                )
                .with_severity(severity),
            )
        })
        .collect()
}

/// Whether `position` lies in the trailing `# vX` comment of a SHA pin, whose version range
/// extends through the comment: a version item accepted there would replace part of the
/// comment (#1182).
#[cfg(feature = "lsp-responses")]
fn position_in_sha_comment(
    gl_dep: &GitlabCiDependency,
    position: deps_core::position::Position,
) -> bool {
    gl_dep.sha_comment().is_some()
        && gl_dep
            .version_range
            .is_some_and(|range| deps_core::lsp_helpers::position_past_sha(range, position))
}

/// One SHA-comment-mismatch diagnostic per SHA pin whose trailing `# tag` comment provably
/// names a different commit than the pinned SHA; silent for a confirmed, absent or
/// unverifiable (cold or truncated index) comment.
fn sha_comment_mismatch_diagnostics(
    parse_result: &dyn ParseResultTrait,
    severity: Severity,
    formatter: &GitlabCiFormatter,
) -> Vec<Diagnostic> {
    parse_result
        .dependencies()
        .into_iter()
        .filter_map(|dep| {
            let gl_dep = dep.as_any().downcast_ref::<GitlabCiDependency>()?;
            let CommentCheck::Mismatch(mismatch) = formatter.sha_comment_check(gl_dep)? else {
                return None;
            };
            let comment = gl_dep.sha_comment()?;
            let sha = gl_dep.pinned_sha()?;
            Some(sha_comment_mismatch_diagnostic(
                gl_dep.version_range?,
                &gl_dep.name,
                sha,
                &comment.tag,
                &mismatch,
                severity,
            ))
        })
        .collect()
}

/// The `project:` tag pin `gl_dep` and the Tags list that can speak for it, shared by the
/// unknown-ref diagnostic and its quick fix (#1781). `None` for a non-tag pin, a pin without a
/// ref or range, a `component:` include (a version without a release is not a missing tag), and
/// a project whose tags have not been fetched.
pub(crate) fn unknown_ref_target<'a>(
    formatter: &GitlabCiFormatter,
    gl_dep: &'a GitlabCiDependency,
) -> Option<UnknownRefTarget<'a>> {
    if gl_dep.pin != Some(PinStyle::Tag) {
        return None;
    }
    let written = gl_dep.version_req.as_ref()?.as_str();
    let index = formatter.tag_list_index(gl_dep)?;
    Some(UnknownRefTarget::new(index, written, gl_dep.version_range?))
}

/// [`unknown_ref_target`] for a type-erased dependency of this ecosystem.
fn tag_pin_target<'a>(
    formatter: &GitlabCiFormatter,
    dep: &'a dyn Dependency,
) -> Option<UnknownRefTarget<'a>> {
    unknown_ref_target(
        formatter,
        dep.as_any().downcast_ref::<GitlabCiDependency>()?,
    )
}

#[cfg(test)]
// Fixtures are single-line ASCII literals with hand-computed byte offsets.
#[allow(clippy::string_slice)]
mod tests {
    use super::*;
    use crate::types::EndpointKind;
    use crate::{MUTABLE_REF_PIN_DIAGNOSTIC_CODE, UNRESOLVED_HOST_DIAGNOSTIC_CODE};
    use dashmap::DashMap;

    #[test]
    fn test_ecosystem_exposes_tag_index_refreshes() {
        let ecosystem = GitlabCiEcosystem::new(Arc::new(HttpCache::new()));
        assert!(ecosystem.tag_index_refreshes().is_some());
    }

    /// Spec 076 FR-025/SC-018 (T005): GitLab CI has no compiled requirement model at all —
    /// `fallback_edit_excludes_newer`'s check a0 (`OriginalUncompilable`) rejects it before
    /// this spec's rule is ever reached, unchanged, existing behavior from spec 075, not a new
    /// fail-closed case this spec introduces.
    #[tokio::test]
    async fn test_fallback_edit_excludes_newer_pins_a0_uncompilable() {
        let cache = Arc::new(HttpCache::new());
        let ecosystem = GitlabCiEcosystem::new(cache);
        let content = "include:\n  - component: gitlab.com/org/proj/comp@1.0.0\n".to_string();
        let uri = deps_core::test_util::test_uri("/repo/.gitlab-ci.yml");
        let parsed = ecosystem
            .parse_manifest(&content, &uri)
            .await
            .expect("manifest must parse");
        let dep = parsed
            .dependencies()
            .into_iter()
            .next()
            .expect("at least one dependency");
        let candidate = deps_core::edit::ManifestEdit {
            range: dep.version_range().expect("version range"),
            new_text: "1.1.0".to_string(),
        };
        let reparse = deps_core::edit::EcosystemReparse {
            ecosystem: &ecosystem,
            uri: &uri,
        };
        let fallback = deps_core::ConcreteVersion::new("1.1.0");
        let available = [deps_core::ConcreteVersion::new("1.2.0"), fallback.clone()];

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

    // #758: exact-value `Ecosystem` conformance, replacing test_ecosystem_id_and_display_name
    // and test_as_any. `lockfile_filenames()` is omitted — GitLab CI pipelines have no lock
    // file concept (no `LockFileProvider` impl in this crate); `no_lockfile_support: true;`
    // below asserts that contract explicitly (#782 gap 2). No
    // `completion_guard_conformance!`/`json_depth_conformance!` for this crate:
    // `generate_completions` above only ever handles `CompletionContext::Version` (no
    // package-name search endpoint, spec NFR-002), and `client::parse_gitlab_page`
    // (backing both tags and releases parsing) is already depth-capped via
    // `deps_core::parser::parse_json_checked`, but fails open to `Ok(vec![])` rather than
    // `Err` on excess nesting (mirrors `deps_github_actions::parse_tags_page`'s identical,
    // deliberate malformed-page tolerance) — `json_depth_conformance!`'s
    // over-depth-rejected assertion does not hold for that call site, and the underlying
    // cap itself is already covered by deps-core's own `parser` test suite.
    deps_core::ecosystem_conformance! {
        mod gitlab_ci_ecosystem_conformance;
        build: GitlabCiEcosystem::new(Arc::new(HttpCache::new()));
        ty: GitlabCiEcosystem;
        id: "gitlab-ci";
        display_name: "GitLab CI/CD";
        manifest_filenames: &[".gitlab-ci.yml"];
        no_lockfile_support: true;
        non_registry_fixture: ".gitlab-ci.yml" => "include:\n  - project: org/proj\n    ref: v1.0.0\n";
    }

    // #1365/#1370/#1391: GitLab CI's `$VAR`/`${VAR}`/`%VAR%`/`{{ }}`/`{% %}`/`@VAR@`/`<%= %>`/
    // `$[[ inputs.x ]]`-in-ref placeholder is guarded by
    // `GitlabCiFormatter::requirement_is_placeholder` (the central gate `deps-core`'s
    // `plan_verified_fix`/`build_unsatisfiable_fix_action`/REFACTOR loop all consult via
    // `edit::requirement_is_placeholder_for` — see `formatter::contains_unresolved_gitlab_variable`)
    // — with its own hand-written regression test exercising the real formatter + a real
    // parsed dependency through `plan_vulnerability_fix`
    // (`formatter::tests::test_plan_vulnerability_fix_var_placeholder_skips_via_no_op_rewrite`).
    // This uses the `formatter_guarded` arm (not `reachable: true`/`reachable: false`, both
    // structurally unusable here independent of the guard existing):
    // - `reachable: true` requires at least one dependency to reach the per-dependency check
    //   loop, gated on `formatter.source_is_public_registry_content(&dep.source())`; GitLab CI
    //   dependencies are always `DependencySource::AlternateRegistry`/`CustomRegistry`, never
    //   plain `DependencySource::Registry`, so `source_is_public_registry_content` (default
    //   impl, not overridden here) is `false` for every one — verified empirically, not just
    //   read from the trait default. Overriding it just to satisfy this macro would be wrong:
    //   that predicate also gates OSV/deps.dev/hover-trust-signal classification elsewhere
    //   (`deps-engine`'s `classify::osv`/`classify::license`/`classify::resolved`), and GitLab
    //   CI dependencies genuinely have no public-registry OSV/deps.dev identity.
    // - `reachable: false` requires a control dependency named exactly
    //   `UNRESOLVED_REQUIREMENT_CONTROL_DEPENDENCY_NAME`; GitLab CI's `is_valid_gitlab_coordinate`
    //   rejects any name with fewer than two `/`-separated segments, so a dependency with that
    //   exact bare name can never be constructed under either the `project:` or `component:`
    //   grammar — verified empirically. The parser also does not degrade `$VAR` to `None`
    //   (mirrors `reachable: true` ecosystems, not `reachable: false` ones), so this arm would
    //   be doubly wrong even setting the naming issue aside.
    // `formatter_guarded` sidesteps both obstacles by asserting directly against the formatter,
    // with no parser or source-policy involved.
    // impl-critic M3 (#1379 follow-up): `placeholders` now also covers the four template forms
    // `contains_unresolved_gitlab_variable`'s full delegation to
    // `requirement_contains_template_placeholder` inherited for free — no fixture previously
    // pinned that (the doc comment describing this behavior was also stale, fixed alongside).
    // #1386: `$[[ inputs.x ]]` is GitLab CI/CD components' own input-interpolation syntax
    // (`contains_unresolved_gitlab_variable`'s doc), added alongside the `$VAR`/`${VAR}`/
    // `%VAR%` pipeline-variable forms and the `{{ }}`/`@VAR@`/`<%= %>` external-templating
    // forms this fixture already covers.
    deps_core::unresolved_requirement_conformance! {
        mod gitlab_ci_unresolved_requirement_conformance;
        formatter_guarded: GitlabCiFormatter::new(Arc::new(DashMap::new()), Arc::new(DashMap::new()));
        placeholders: [
            "$DEPLOY_VERSION", "${DEPLOY_VERSION}", "%DEPLOY_VERSION%", "v1.2-$BUILD",
            "{{ DEPLOY_VERSION }}", "@DEPLOY_VERSION@", "<%= DEPLOY_VERSION %>",
            "$[[ inputs.minor ]]", "1.$[[ inputs.minor ]]",
        ];
        // #1370 critic M2: negative control — a SHA, a branch, and an ordinary tag must never
        // be conflated with the variable-reference placeholder grammar above.
        non_placeholders: ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "main", "1.2", "v1.2.3"];
    }

    #[test]
    fn test_manifest_routing() {
        let cache = Arc::new(HttpCache::new());
        let eco = GitlabCiEcosystem::new(cache);
        assert_eq!(
            eco.manifest_directory_patterns(),
            &[(".gitlab/ci", ".yml"), (".gitlab/ci", ".yaml")]
        );
        assert!(eco.manifest_patterns().is_empty());
        assert!(eco.manifest_extensions().is_empty());
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

    /// M-a (#466 review): the two failure modes must produce visibly different messages —
    /// a genuinely unresolved host still points the user at `registries.gitlab_instance_host`,
    /// but a capacity refusal must not, since that setting cannot fix a capacity limit.
    #[test]
    fn test_unresolved_host_diagnostics_distinguishes_capacity_refusal_from_unresolved() {
        let uri = deps_core::test_util::test_uri("/repo/.gitlab-ci.yml");
        let range = deps_core::position::Range::default();
        let make_dep = |host: HostRef| crate::types::GitlabCiDependency {
            name: "org/proj/comp".into(),
            name_range: range,
            version_req: Some("1.0.0".into()),
            version_range: Some(range),
            version_literal: None,
            source: deps_core::parser::DependencySource::CustomRegistry { url: "x".into() },
            is_plain_scalar: true,
            is_alias_occurrence: false,
            kind: IncludeKind::Component,
            host,
            pin: Some(PinStyle::Tag),
            comment_slot: deps_core::lsp_helpers::CommentSlot::Unavailable,
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
            dependency_truncation: None,
            blocked_registries: Vec::new(),
        };

        let diagnostics = unresolved_host_diagnostics(&parse_result);

        assert_eq!(diagnostics.len(), 2);
        assert!(
            diagnostics[0]
                .message()
                .contains("Set the `registries.gitlab_instance_host`")
        );
        // The capacity-refusal message must never instruct the user to *set* the setting —
        // it may still name it (to explain it's *not* the fix), but must not tell them to
        // configure it as a remedy.
        assert!(
            !diagnostics[1]
                .message()
                .contains("Set the `registries.gitlab_instance_host`")
        );
        assert!(diagnostics[1].message().contains("capacity"));
    }

    /// Security audit finding (#1252): a bidi-override character in an `Unresolved` host
    /// expression and a raw newline in a `CapacityRefused` origin must not survive into the
    /// rendered diagnostic message (Trojan Source, CVE-2021-42574, or a forged report row).
    #[test]
    fn test_unresolved_host_diagnostics_sanitizes_bidi_and_newline() {
        let uri = deps_core::test_util::test_uri("/repo/.gitlab-ci.yml");
        let range = deps_core::position::Range::default();
        let make_dep = |host: HostRef| crate::types::GitlabCiDependency {
            name: "org/proj/comp".into(),
            name_range: range,
            version_req: Some("1.0.0".into()),
            version_range: Some(range),
            version_literal: None,
            source: deps_core::parser::DependencySource::CustomRegistry { url: "x".into() },
            is_plain_scalar: true,
            is_alias_occurrence: false,
            kind: IncludeKind::Component,
            host,
            pin: Some(PinStyle::Tag),
            comment_slot: deps_core::lsp_helpers::CommentSlot::Unavailable,
            project_path: "org/proj".to_string(),
        };
        let parse_result = crate::types::GitlabCiParseResult {
            dependencies: vec![
                make_dep(HostRef::Unresolved("ci\u{202E}host".to_string())),
                make_dep(HostRef::CapacityRefused(
                    "https://gitlab\n.example".to_string(),
                )),
            ],
            routes: vec![],
            uri,
            dependency_truncation: None,
            blocked_registries: Vec::new(),
        };

        let diagnostics = unresolved_host_diagnostics(&parse_result);

        assert_eq!(diagnostics.len(), 2);
        // Asserts the full sanitized message, not just absence of the bad characters —
        // a regression that sanitized the message down to nothing (or dropped unrelated
        // content) must fail loudly rather than vacuously pass a "does not contain" check.
        assert_eq!(
            diagnostics[0].message(),
            "Cannot determine the GitLab instance host for 'ci host'. Set the \
             `registries.gitlab_instance_host` setting to enable version resolution."
        );
        assert_eq!(
            diagnostics[1].message(),
            "'https://gitlab .example' was not registered for version resolution because a \
             GitLab CI host/route capacity limit was reached. Reduce the number of distinct \
             GitLab hosts or includes referenced in this workspace (unrelated to the \
             `registries.gitlab_instance_host` setting)."
        );
    }

    /// #1254: a credential-shaped `Unresolved`/`CapacityRefused` value (e.g. an `include:`
    /// URL embedding a token) must be redacted in the diagnostic MESSAGE, not just in
    /// `Debug` output (already covered by
    /// `types::tests::test_host_ref_unresolved_and_capacity_refused_redact_credentials`).
    #[test]
    fn test_unresolved_host_diagnostics_redacts_credentials_in_message() {
        let uri = deps_core::test_util::test_uri("/repo/.gitlab-ci.yml");
        let range = deps_core::position::Range::default();
        let make_dep = |host: HostRef| crate::types::GitlabCiDependency {
            name: "org/proj/comp".into(),
            name_range: range,
            version_req: Some("1.0.0".into()),
            version_range: Some(range),
            version_literal: None,
            source: deps_core::parser::DependencySource::CustomRegistry { url: "x".into() },
            is_plain_scalar: true,
            is_alias_occurrence: false,
            kind: IncludeKind::Component,
            host,
            pin: Some(PinStyle::Tag),
            comment_slot: deps_core::lsp_helpers::CommentSlot::Unavailable,
            project_path: "org/proj".to_string(),
        };
        let parse_result = crate::types::GitlabCiParseResult {
            dependencies: vec![
                make_dep(HostRef::Unresolved(
                    deps_core::conformance::CREDENTIAL_PROBE_KEY.to_string(),
                )),
                make_dep(HostRef::CapacityRefused(
                    deps_core::conformance::CREDENTIAL_PROBE_KEY.to_string(),
                )),
            ],
            routes: vec![],
            uri,
            dependency_truncation: None,
            blocked_registries: Vec::new(),
        };

        let diagnostics = unresolved_host_diagnostics(&parse_result);

        assert_eq!(diagnostics.len(), 2);
        for diagnostic in &diagnostics {
            assert!(
                !diagnostic
                    .message()
                    .contains(deps_core::conformance::CREDENTIAL_PROBE_SECRET),
                "plaintext credential survived into the diagnostic message: {}",
                diagnostic.message()
            );
            assert!(
                diagnostic.message().contains("***@git.internal.corp"),
                "expected the redacted `***@host` form in the diagnostic message: {}",
                diagnostic.message()
            );
        }
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
            .find(|d| d.code() == Some(UNRESOLVED_HOST_DIAGNOSTIC_CODE))
            .expect("expected the unresolved-host diagnostic");
        assert_eq!(found.severity, Some(Severity::Information));
        assert!(found.message().contains("gitlab_instance_host"));
    }

    /// Issue #967 end-to-end, inline-literal `component:` host path: a `component:` host
    /// blocked by `registries.workspace_registries` must produce the shared blocked-registry
    /// INFORMATION diagnostic (naming the blocked host class), and must **not** produce the
    /// unresolved-host diagnostic (which would misattribute the cause to
    /// `registries.gitlab_instance_host`).
    #[tokio::test]
    async fn test_generate_diagnostics_component_host_blocked_by_policy() {
        let cache = Arc::new(HttpCache::new());
        // `RegistryAccessPolicy::default()` is `PublicOnly` (blocks `10.0.0.1`, a private
        // address) — `GitlabCiEcosystem::new` wires it in directly.
        let eco = GitlabCiEcosystem::new(cache);
        let uri = deps_core::test_util::test_uri("/repo/.gitlab-ci.yml");
        let content = "include:\n  - component: 10.0.0.1/org/proj/comp@1.0.0\n";
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

        let blocked: Vec<_> = diagnostics
            .iter()
            .filter(|d| d.message().to_lowercase().contains("blocked"))
            .collect();
        assert_eq!(
            blocked.len(),
            1,
            "expected exactly one blocked-registry diagnostic, got: {diagnostics:?}"
        );
        assert_eq!(blocked[0].severity, Some(Severity::Information));
        assert!(
            diagnostics
                .iter()
                .all(|d| d.code() != Some(UNRESOLVED_HOST_DIAGNOSTIC_CODE)),
            "must not surface the unresolved-host diagnostic for a policy-blocked host: \
             {diagnostics:?}"
        );
        assert!(diagnostics.iter().all(|d| {
            !d.message()
                .contains("Cannot determine the GitLab instance host")
        }),);
    }

    /// Issue #967 end-to-end, `registries.gitlab_instance_host`-relative path: same as above,
    /// but for a `project:` include resolving through a blocked instance-host setting rather
    /// than an inline-literal `component:` host.
    #[tokio::test]
    async fn test_generate_diagnostics_instance_host_blocked_by_policy() {
        let cache = Arc::new(HttpCache::new());
        let policy = Arc::new(RegistryAccessPolicy::default());
        let gitlab_instance_host_raw = Arc::new(RwLock::new(Some("10.0.0.1".to_string())));
        let eco = GitlabCiEcosystem::with_context(cache, policy, gitlab_instance_host_raw);
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

        let blocked: Vec<_> = diagnostics
            .iter()
            .filter(|d| d.message().to_lowercase().contains("blocked"))
            .collect();
        assert_eq!(
            blocked.len(),
            1,
            "expected exactly one blocked-registry diagnostic, got: {diagnostics:?}"
        );
        // S1: the message must name the real configured value, not the `$CI_SERVER_FQDN`
        // placeholder, which appears nowhere in this manifest or its config.
        assert!(blocked[0].message().contains("10.0.0.1"));
        assert!(
            diagnostics
                .iter()
                .all(|d| d.code() != Some(UNRESOLVED_HOST_DIAGNOSTIC_CODE)),
            "must not surface the unresolved-host diagnostic for a policy-blocked host: \
             {diagnostics:?}"
        );
        assert!(diagnostics.iter().all(|d| {
            !d.message()
                .contains("Cannot determine the GitLab instance host")
        }),);
    }

    // --- issue #634: mutable-ref-pin diagnostic + "Pin to commit SHA" code action ---

    fn mutable_ref_pin_code() -> String {
        MUTABLE_REF_PIN_DIAGNOSTIC_CODE.into()
    }

    async fn diagnostics_for(content: &str, uri: &Url) -> Vec<Diagnostic> {
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
            .find(|d| d.code() == Some(mutable_ref_pin_code().as_str()))
            .expect("expected the mutable-ref-pin diagnostic for a PinStyle::Tag include");
        assert_eq!(found.severity, Some(Severity::Hint));
        assert!(found.message().contains("v1.0.0"));
        assert!(!found.message().contains("manual edit"));
    }

    /// #912 critic S1 regression: an aliased `project:` next to a **literal** `ref:` must
    /// not carry the "(manual edit — no automated fix available for this ref)" suffix —
    /// `sha_pin_quickfix_kind`'s `Tag` arm always classifies `Some(StaticTagIndex)`
    /// regardless of `TagIndex` cache state (see the cold-cache test above), and before
    /// the S1 fix the entry-wide `is_alias_occurrence` OR incorrectly withheld this even
    /// though the edit path only ever targets the literal `ref:`.
    #[tokio::test]
    async fn test_mutable_ref_pin_diagnostic_omits_suffix_when_only_project_is_aliased() {
        let uri = deps_core::test_util::test_uri("/repo/.gitlab-ci.yml");
        let content =
            ".proj: &proj group/project-a\ninclude:\n  - project: *proj\n    ref: v1.0.0\n";

        let diagnostics = diagnostics_for(content, &uri).await;

        let found = diagnostics
            .iter()
            .find(|d| d.code() == Some(mutable_ref_pin_code().as_str()))
            .expect("expected the mutable-ref-pin diagnostic for a PinStyle::Tag include");
        assert!(found.message().contains("v1.0.0"));
        assert!(
            !found.message().contains("manual edit"),
            "an aliased project: alone must not withhold the literal ref:'s quickfix: {}",
            found.message()
        );
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
                .any(|d| d.code() == Some(mutable_ref_pin_code().as_str())),
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
                .any(|d| d.code() == Some(mutable_ref_pin_code().as_str())),
            "a PinStyle::Branch include with no TagIndex confirmation is an honest \
             unknown, not diagnosable as a mutable tag ref"
        );
    }

    /// Security audit finding (#1252): a bidi-override character in the dependency name and
    /// a raw newline in the tag/ref text must not survive into the rendered mutable-ref-pin
    /// diagnostic message (Trojan Source, CVE-2021-42574, or a forged report row).
    #[test]
    fn test_mutable_ref_pin_diagnostics_sanitizes_bidi_and_newline() {
        let range = deps_core::position::Range::default();
        let dep = GitlabCiDependency {
            name: "org\u{202E}/proj".into(),
            name_range: range,
            version_req: Some("v1\n.0".into()),
            version_range: Some(range),
            version_literal: None,
            source: deps_core::parser::DependencySource::AlternateRegistry {
                index: "route".to_string(),
                mirrors_crates_io: false,
            },
            is_plain_scalar: true,
            is_alias_occurrence: false,
            kind: IncludeKind::Project,
            host: HostRef::Literal(crate::host::GitlabHost::for_test("gitlab.com")),
            pin: Some(PinStyle::Tag),
            comment_slot: deps_core::lsp_helpers::CommentSlot::Unavailable,
            project_path: "org/proj".to_string(),
        };
        let parse_result = crate::types::GitlabCiParseResult {
            dependencies: vec![dep],
            routes: vec![],
            uri: deps_core::test_util::test_uri("/repo/.gitlab-ci.yml"),
            dependency_truncation: None,
            blocked_registries: Vec::new(),
        };
        let formatter = GitlabCiFormatter::new(Arc::new(DashMap::new()), Arc::new(DashMap::new()));

        let diagnostics = mutable_ref_pin_diagnostics(&parse_result, Severity::Hint, &formatter);

        let found = diagnostics
            .iter()
            .find(|d| d.code() == Some(mutable_ref_pin_code().as_str()))
            .expect("expected a mutable-ref-pin diagnostic");
        // Asserts the full sanitized message, not just absence of the bad characters —
        // a regression that sanitized the message down to nothing (or dropped unrelated
        // content) must fail loudly rather than vacuously pass a "does not contain" check.
        assert_eq!(
            found.message(),
            "org /proj project is pinned to the mutable ref `v1 .0`; pin to a full commit \
             SHA to guard against ref mutation"
        );
    }

    // --- validation finding C3: always-mutable pin forms with no explicit ref/tag text ---

    /// A `component:` include pinned to `~latest` always resolves to whichever release is
    /// currently newest — it is mutable by construction, not merely "unconfirmed", so it
    /// must get the diagnostic even though `PinStyle::Latest` is never registry-confirmed
    /// the way a `Branch` pin can be.
    ///
    /// Spec 048/issue #643: `gitlab.com` here is a resolved host (a route gets registered
    /// for it during `parse_manifest`), so `sha_pin_quickfix_kind` finds a genuine
    /// `DynamicComponentPin` quickfix available — the message must NOT carry the "no
    /// automated fix available" suffix, since one is available. See
    /// `test_mutable_ref_pin_diagnostic_fires_for_latest_component_pin_unresolved_host_keeps_suffix`
    /// for the FR-001a counterpart where the suffix is correctly kept.
    #[tokio::test]
    async fn test_mutable_ref_pin_diagnostic_fires_for_latest_component_pin() {
        let uri = deps_core::test_util::test_uri("/repo/.gitlab-ci.yml");
        let content = "include:\n  - component: gitlab.com/org/proj/comp@~latest\n";

        let diagnostics = diagnostics_for(content, &uri).await;

        let found = diagnostics
            .iter()
            .find(|d| d.code() == Some(mutable_ref_pin_code().as_str()))
            .expect("expected the mutable-ref-pin diagnostic for a PinStyle::Latest component");
        assert!(found.message().contains("~latest"));
        assert!(
            !found.message().contains("no automated fix available"),
            "a resolved host has a genuine DynamicComponentPin quickfix available, so the \
             suffix must be omitted (spec 048 FR-001): {}",
            found.message()
        );
    }

    /// A `component:` include pinned to a partial version (`1.2`) always resolves to
    /// whichever release currently matches that range — equally mutable as `~latest`.
    ///
    /// Spec 048/issue #643: same resolved-host reasoning as the `~latest` test above.
    #[tokio::test]
    async fn test_mutable_ref_pin_diagnostic_fires_for_partial_component_pin() {
        let uri = deps_core::test_util::test_uri("/repo/.gitlab-ci.yml");
        let content = "include:\n  - component: gitlab.com/org/proj/comp@1.2\n";

        let diagnostics = diagnostics_for(content, &uri).await;

        let found = diagnostics
            .iter()
            .find(|d| d.code() == Some(mutable_ref_pin_code().as_str()))
            .expect("expected the mutable-ref-pin diagnostic for a PinStyle::Partial component");
        assert!(found.message().contains("1.2"));
        assert!(
            !found.message().contains("no automated fix available"),
            "a resolved host has a genuine DynamicComponentPin quickfix available, so the \
             suffix must be omitted (spec 048 FR-001): {}",
            found.message()
        );
    }

    /// Spec 048 FR-001a: the complementary case — a `component:` `Latest`/`Partial` pin on
    /// an *unresolved* host (`$CI_SERVER_FQDN` with no `registries.gitlab_instance_host`
    /// configured) has no registered route, so `generate_code_actions` genuinely offers no
    /// quickfix, and the suffix must be kept — this is the edge case the FR-001 amendment
    /// exists to avoid reintroducing the pre-#643 bug for.
    #[tokio::test]
    async fn test_mutable_ref_pin_diagnostic_fires_for_latest_component_pin_unresolved_host_keeps_suffix()
     {
        let uri = deps_core::test_util::test_uri("/repo/.gitlab-ci.yml");
        let content = "include:\n  - component: $CI_SERVER_FQDN/org/proj/comp@~latest\n";

        let diagnostics = diagnostics_for(content, &uri).await;

        let found = diagnostics
            .iter()
            .find(|d| d.code() == Some(mutable_ref_pin_code().as_str()))
            .expect("expected the mutable-ref-pin diagnostic for a PinStyle::Latest component");
        assert!(found.message().contains("~latest"));
        assert!(
            found.message().contains("no automated fix available"),
            "an unresolved host has no registered route, so no quickfix is genuinely \
             available — the suffix must be kept: {}",
            found.message()
        );
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
            .find(|d| d.code() == Some(mutable_ref_pin_code().as_str()))
            .expect("expected the mutable-ref-pin diagnostic for a ref-less project include");
        assert!(found.message().contains("no `ref:`"));
        assert!(found.message().contains("no automated fix available"));
    }

    #[tokio::test]
    async fn test_mutable_ref_pin_diagnostic_fires_for_component_tag_pin() {
        let uri = deps_core::test_util::test_uri("/repo/.gitlab-ci.yml");
        let content = "include:\n  - component: gitlab.com/org/proj/comp@1.0.0\n";

        let diagnostics = diagnostics_for(content, &uri).await;

        let found = diagnostics
            .iter()
            .find(|d| d.code() == Some(mutable_ref_pin_code().as_str()))
            .expect("expected the mutable-ref-pin diagnostic for a PinStyle::Tag component");
        assert!(found.message().contains("1.0.0"));
        assert!(found.message().contains("component"));
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
                deps_core::lsp_helpers::DiagnosticSeverities::new()
                    .with_mutable_ref_pin_enabled(false),
            )
            .await;

        assert!(
            !diagnostics
                .iter()
                .any(|d| d.code() == Some(mutable_ref_pin_code().as_str())),
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
            .filter(|d| d.code() == Some(mutable_ref_pin_code().as_str()))
            .collect();
        assert_eq!(found.len(), 2, "both Tag-pinned includes must be flagged");
        found.sort_by_key(|d| d.range.start.line);
        assert!(found[0].message().contains("v1.0.0"));
        assert!(!found[0].message().contains("v2.0.0"));
        assert!(found[1].message().contains("v2.0.0"));
        assert!(!found[1].message().contains("v1.0.0"));
    }

    // --- issue #643 anti-drift: sha_pin_quickfix_kind classification table (S1/S3) ---

    /// Table-driven regression for the single classification `mutable_ref_pin_diagnostics`'s
    /// message and `generate_code_actions`'s dispatch both consult (issue #643 S1) — locks
    /// down every `(IncludeKind, PinStyle, HostRef)` combination the critic identified as a
    /// drift risk, not just the two `(Component, Latest/Partial)` cases the original bug
    /// affected. `resolved_component_source`/`unresolved_component_source` stand in for a
    /// registered vs. unregistered route (an `AlternateRegistry` whose route never made it
    /// into `formatter.routes` — the same state a capacity-refused route leaves an index
    /// in); `custom_registry_source` is the literal `HostRef::Unresolved`/
    /// `CapacityRefused` shape (spec 048 FR-001a), which always downgrades to
    /// `DependencySource::CustomRegistry` rather than `AlternateRegistry`.
    #[test]
    fn test_sha_pin_quickfix_kind_classification_table() {
        let range = deps_core::position::Range::default();
        let routes: Arc<DashMap<String, crate::types::GitlabRoute>> = Arc::new(DashMap::new());
        routes.insert(
            "resolved-route".to_string(),
            crate::types::GitlabRoute {
                host: crate::host::GitlabHost::for_test("https://gitlab.com"),
                endpoint: EndpointKind::Releases,
            },
        );
        let formatter = GitlabCiFormatter::new(Arc::clone(&routes), Arc::new(DashMap::new()));

        let make_dep = |kind: IncludeKind,
                        pin: PinStyle,
                        source: deps_core::parser::DependencySource|
         -> GitlabCiDependency {
            GitlabCiDependency {
                name: "org/proj".into(),
                name_range: range,
                version_req: Some("x".into()),
                version_range: Some(range),
                version_literal: None,
                source,
                is_plain_scalar: true,
                is_alias_occurrence: false,
                kind,
                host: HostRef::Literal(crate::host::GitlabHost::for_test("gitlab.com")),
                pin: Some(pin),
                comment_slot: deps_core::lsp_helpers::CommentSlot::Unavailable,
                project_path: "org/proj".to_string(),
            }
        };

        let resolved_source = deps_core::parser::DependencySource::AlternateRegistry {
            index: "resolved-route".to_string(),
            mirrors_crates_io: false,
        };
        let unregistered_route_source = deps_core::parser::DependencySource::AlternateRegistry {
            index: "no-such-route".to_string(),
            mirrors_crates_io: false,
        };
        let custom_registry_source =
            deps_core::parser::DependencySource::CustomRegistry { url: "x".into() };

        // (label, dependency, expect StaticTagIndex, expect DynamicComponentPin)
        let cases = [
            (
                "project tag, resolved",
                make_dep(IncludeKind::Project, PinStyle::Tag, resolved_source.clone()),
                true,
                false,
            ),
            (
                "component tag, resolved",
                make_dep(
                    IncludeKind::Component,
                    PinStyle::Tag,
                    resolved_source.clone(),
                ),
                true,
                false,
            ),
            (
                "component latest, resolved route",
                make_dep(
                    IncludeKind::Component,
                    PinStyle::Latest,
                    resolved_source.clone(),
                ),
                false,
                true,
            ),
            (
                "component partial, resolved route",
                make_dep(
                    IncludeKind::Component,
                    PinStyle::Partial,
                    resolved_source.clone(),
                ),
                false,
                true,
            ),
            (
                "component latest, unregistered route",
                make_dep(
                    IncludeKind::Component,
                    PinStyle::Latest,
                    unregistered_route_source,
                ),
                false,
                false,
            ),
            (
                "component partial, unresolved host (CustomRegistry)",
                make_dep(
                    IncludeKind::Component,
                    PinStyle::Partial,
                    custom_registry_source,
                ),
                false,
                false,
            ),
            (
                "project branch",
                make_dep(
                    IncludeKind::Project,
                    PinStyle::Branch,
                    resolved_source.clone(),
                ),
                false,
                false,
            ),
            (
                "component sha",
                make_dep(
                    IncludeKind::Component,
                    PinStyle::sha_without_comment(
                        deps_core::lsp_helpers::CommitSha::parse(&"a".repeat(40)).unwrap(),
                    ),
                    resolved_source.clone(),
                ),
                false,
                false,
            ),
            (
                "project latest (project: pins are never Latest-shaped in production, but \
                 the classifier must still reject a non-Component kind)",
                make_dep(IncludeKind::Project, PinStyle::Latest, resolved_source),
                false,
                false,
            ),
        ];

        for (label, gl_dep, expect_static, expect_dynamic) in cases {
            let kind = sha_pin_quickfix_kind(&gl_dep, &gl_dep, &formatter);
            assert_eq!(
                matches!(kind, Some(ShaPinQuickfixKind::StaticTagIndex)),
                expect_static,
                "{label}: StaticTagIndex mismatch"
            );
            assert_eq!(
                matches!(kind, Some(ShaPinQuickfixKind::DynamicComponentPin)),
                expect_dynamic,
                "{label}: DynamicComponentPin mismatch"
            );
        }
    }

    #[test]
    fn test_completion_insert_text() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = GitlabCiEcosystem::new(cache);
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
        let meta = MockMetadata {
            name: deps_core::PackageName::new("my-component"),
            latest_version: "1.2.3".into(),
        };
        assert_eq!(
            eco.completion_insert_text(&meta),
            Some("my-component@1.2.3".to_string())
        );
    }

    // --- #912: alias-occurrence edit/completion withholding (spec FR-010/FR-011) ---

    /// An alias-site dependency for the withholding tests below — mirrors
    /// `dispatch_test_dep` (`project:`/`ref:` shape, `name_range != version_range`, per
    /// EC-016/SC-006: the `component:` shape (`name_range == version_range`) must NOT be
    /// used for an FR-011 test, since `CompletionContext::Version` is unreachable there
    /// regardless of FR-011 — see spec §9 P2/EC-017) but with `is_alias_occurrence: true`.
    fn alias_dispatch_test_dep(
        name_range: deps_core::position::Range,
        version_range: deps_core::position::Range,
        pin: Option<PinStyle>,
    ) -> crate::types::GitlabCiDependency {
        crate::types::GitlabCiDependency {
            name: "org/proj".into(),
            name_range,
            version_req: Some("v1.0.0".into()),
            version_range: Some(version_range),
            version_literal: None,
            source: deps_core::parser::DependencySource::CustomRegistry {
                url: "https://gitlab.example".into(),
            },
            is_plain_scalar: false,
            is_alias_occurrence: true,
            kind: IncludeKind::Project,
            host: HostRef::Unresolved("$CI_SERVER_FQDN".to_string()),
            pin,
            comment_slot: deps_core::lsp_helpers::CommentSlot::Unavailable,
            project_path: "org/proj".to_string(),
        }
    }

    /// FR-010: `sha_pin_quickfix_kind` returns `None` for an alias-occurrence dependency
    /// before consulting `pin` at all — even a `PinStyle::Tag` pin, which would otherwise
    /// always classify `Some(StaticTagIndex)`.
    #[test]
    fn test_sha_pin_quickfix_kind_withholds_for_alias_occurrence() {
        let formatter = GitlabCiFormatter::new(Arc::new(DashMap::new()), Arc::new(DashMap::new()));
        let range = deps_core::position::Range::default();
        let gl_dep = alias_dispatch_test_dep(range, range, Some(PinStyle::Tag));
        assert!(sha_pin_quickfix_kind(&gl_dep, &gl_dep, &formatter).is_none());
    }

    /// FR-010/#643: an alias-occurrence dependency's mutable-ref-pin diagnostic must carry
    /// the "manual edit" suffix — `sha_pin_quickfix_kind` (which this message's suffix
    /// decision reads) withholds regardless of `pin`, so the message stays honest about no
    /// quickfix being available.
    #[tokio::test]
    async fn test_mutable_ref_pin_diagnostic_carries_manual_edit_suffix_for_alias_occurrence() {
        let uri = deps_core::test_util::test_uri("/repo/.gitlab-ci.yml");
        let content = ".pin: &pin v1.2.3\ninclude:\n  - project: org/proj\n    ref: *pin\n";
        let diagnostics = diagnostics_for(content, &uri).await;
        let found = diagnostics
            .iter()
            .find(|d| d.code() == Some(mutable_ref_pin_code().as_str()))
            .expect("expected the mutable-ref-pin diagnostic for an alias-occurrence ref");
        assert!(
            found.message().contains("no automated fix available"),
            "alias-occurrence message must carry the manual-edit suffix: {}",
            found.message()
        );
    }

    #[cfg(feature = "lsp-responses")]
    mod lsp_tests {
        use super::*;

        use deps_core::lsp_helpers::splice_resolved_line;

        use deps_core::lsp_helpers::{CommitSha, TagIndex};

        // #1137: regression guard, not independent parser verification (see
        // `operator_chars_conformance!`'s doc) — `required` mirrors `VERSION_OPERATOR_CHARS`'s
        // own doc comment (a component/include ref has no operator syntax), so an edit to one
        // without the other fails loudly instead of silently degrading completion.
        deps_core::operator_chars_conformance! {
            mod gitlab_ci_operator_chars_conformance;
            ecosystem: "gitlab-ci";
            operator_chars: VERSION_OPERATOR_CHARS;
            required: &[];
        }

        #[test]
        fn test_splice_project_line() {
            let markdown = "# gitlab.com/org/proj/comp\n\n**Requirement**: `1.0.0`\n";
            let spliced = splice_project_line(markdown, "https://gitlab.com/org/proj");
            assert!(spliced.contains("**Project**"));
            assert!(
                spliced.find("**Project**").unwrap() < spliced.find("**Requirement**").unwrap()
            );
        }

        /// #1310 critic S3: `project_path` is manifest-controlled and `is_valid_gitlab_coordinate`
        /// bounds only its charset, not its length — the label half of the `**Project**` line
        /// must be capped, matching `deps-core::git_ref.rs`'s `splice_resolved_line` fix for the
        /// same class of gap.
        #[test]
        fn splice_project_line_caps_label_but_not_destination() {
            let long_url = format!("https://gitlab.example.com/{}", "a".repeat(5000));
            let spliced = splice_project_line("", &long_url);
            assert!(
                spliced.contains(&format!("]({long_url})")),
                "the destination must not be truncated; got: {spliced}"
            );
            assert!(
                spliced.contains('…'),
                "the label must be truncated; got: {spliced}"
            );
            let label_start = spliced.find('[').unwrap() + 1;
            let label_end = spliced.find(']').unwrap();
            assert!(
                spliced[label_start..label_end].chars().count() <= MAX_DIAGNOSTIC_VALUE_CHARS + 1,
                "label must be bounded by the cap plus the ellipsis marker; got: {spliced}"
            );
        }

        /// Boundary case (at cap / over cap), not just the 5000-char extreme.
        #[test]
        fn splice_project_line_label_boundary_at_and_over_cap() {
            let prefix = "https://gitlab.example.com/";
            let cap = MAX_DIAGNOSTIC_VALUE_CHARS;

            let at_cap_url = format!("{prefix}{}", "a".repeat(cap - prefix.len()));
            let spliced = splice_project_line("", &at_cap_url);
            assert!(
                spliced.contains(&format!("[{at_cap_url}]({at_cap_url})")),
                "a url whose label is exactly at the cap must render whole; got: {spliced}"
            );

            let over_cap_url = format!("{prefix}{}", "a".repeat(cap - prefix.len() + 1));
            let spliced = splice_project_line("", &over_cap_url);
            let truncated_label = format!("{}…", &over_cap_url[..cap]);
            assert!(
                spliced.contains(&format!("[{truncated_label}]({over_cap_url})")),
                "a url one char over the cap must truncate the label to exactly `cap` chars \
             plus the ellipsis, while leaving the destination whole; got: {spliced}"
            );
        }

        #[test]
        fn test_splice_resolved_line_after_requirement() {
            let markdown = "# org/proj\n\n**Requirement**: `v1.0.0`\n\n**Latest**: `v1.1.0`\n";
            let spliced = splice_resolved_line(
                markdown,
                "v1.0.0",
                &deps_core::lsp_helpers::CommitSha::parse(&"a".repeat(40)).unwrap(),
            );
            let req_pos = spliced.find("**Requirement**").unwrap();
            let resolved_pos = spliced.find("**Resolved**").unwrap();
            let latest_pos = spliced.find("**Latest**").unwrap();
            assert!(req_pos < resolved_pos);
            assert!(resolved_pos < latest_pos);
        }

        /// S3 cold-cache negative test (architect's plan, tester re-review): documents the one
        /// place where "message omits suffix" and "quickfix actually available" are
        /// deliberately NOT the same fact. A `PinStyle::Tag` message never carries the suffix
        /// — `sha_pin_quickfix_kind`'s `Tag` arm doesn't consult `TagIndex` at all, unlike the
        /// `Latest`/`Partial` arm — yet `build_sha_pin_action` still withholds the quickfix on
        /// a cold/unseeded cache (a genuine `TagIndex` miss, e.g. the document was opened
        /// before the registry fetch completed). This divergence is pre-existing and accepted
        /// (shared with `deps-github-actions`'s identical guard), not a regression #643
        /// introduced — this test exists so it stays a documented, deliberate fact rather than
        /// an implicit one.
        #[tokio::test]
        async fn test_tag_pin_message_omits_suffix_on_cold_cache_while_quickfix_unavailable() {
            let uri = deps_core::test_util::test_uri("/repo/.gitlab-ci.yml");
            let content = "include:\n  - project: org/proj\n    ref: v1.0.0\n";

            // `diagnostics_for` builds its own fresh `GitlabCiEcosystem`, so its `TagIndex` is
            // guaranteed cold here — no `seed_tag`/`populate_tag_index_entries` call anywhere
            // in this function.
            let diagnostics = diagnostics_for(content, &uri).await;
            let found = diagnostics
                .iter()
                .find(|d| d.code() == Some(mutable_ref_pin_code().as_str()))
                .expect("expected the mutable-ref-pin diagnostic for a PinStyle::Tag include");
            assert!(
                !found.message().contains("no automated fix available"),
                "a PinStyle::Tag message never carries the suffix, cold cache or not: {}",
                found.message()
            );

            // Independently-built parse result + formatter, likewise cold (no seeding).
            let policy = deps_core::net_policy::RegistryAccessPolicy::default();
            let instance_host = crate::host::GitlabInstanceHost::new(
                Arc::new(RwLock::new(None)),
                Arc::new(deps_core::net_policy::RegistryAccessPolicy::default()),
            );
            let parse_result =
                crate::parser::parse_gitlab_ci_yaml(content, &uri, &policy, &instance_host)
                    .unwrap();
            let formatter = test_formatter();
            let position = deps_core::ParseResult::dependencies(&parse_result)[0]
                .version_range()
                .unwrap()
                .start;
            assert!(
                build_sha_pin_action(&parse_result, position.into(), &uri, &formatter).is_none(),
                "a cold TagIndex must still withhold the quickfix even though the message \
             omits the suffix — the one accepted message/quickfix divergence"
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
                crate::parser::parse_gitlab_ci_yaml(content, &uri, &policy, &instance_host)
                    .unwrap();
            assert_eq!(parse_result.dependencies[0].pin, Some(PinStyle::Branch));

            let tag_index: Arc<DashMap<(EndpointKind, PackageName), Arc<TagIndex>>> =
                Arc::new(DashMap::new());
            let sha = "a".repeat(40);
            crate::registry::populate_tag_index_entries(
                &deps_core::TagIndexRefreshSender::new(),
                &tag_index,
                (
                    EndpointKind::Tags,
                    parse_result.dependencies[0].name.clone(),
                ),
                std::iter::once(("cargo-deny", sha.as_str())),
                deps_core::pagination::ListCoverage::Complete,
            );
            let formatter = GitlabCiFormatter::new(Arc::new(DashMap::new()), tag_index);

            let diagnostics =
                mutable_ref_pin_diagnostics(&parse_result, Severity::Hint, &formatter);

            let found = diagnostics
                .iter()
                .find(|d| d.code() == Some(mutable_ref_pin_code().as_str()))
                .expect("expected the mutable-ref-pin diagnostic for a registry-confirmed tag");
            assert!(
                found.message().contains("no automated fix available"),
                "a registry-confirmed-but-Branch ref has no quickfix, so the message must say \
             so; got: {}",
                found.message()
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
                crate::parser::parse_gitlab_ci_yaml(content, &uri, &policy, &instance_host)
                    .unwrap();

            let formatter = test_formatter();
            let mut index = TagIndex::default();
            let sha = "a".repeat(40);
            index
                .tag_to_sha
                .insert("v1.0.0".to_string(), CommitSha::parse(&sha).unwrap());
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

            let action = build_sha_pin_action(&parse_result, position.into(), &uri, &formatter)
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
            assert_eq!(text_edits[0].new_text, format!("{sha} # v1.0.0"));
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
                crate::parser::parse_gitlab_ci_yaml(content, &uri, &policy, &instance_host)
                    .unwrap();

            let formatter = test_formatter();

            let position = deps_core::ParseResult::dependencies(&parse_result)[0]
                .version_range()
                .unwrap()
                .start;

            assert!(
                build_sha_pin_action(&parse_result, position.into(), &uri, &formatter).is_none()
            );
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
                crate::parser::parse_gitlab_ci_yaml(content, &uri, &policy, &instance_host)
                    .unwrap();

            let formatter = test_formatter();
            let mut index = TagIndex::default();
            index.tag_to_sha.insert(
                "main".to_string(),
                CommitSha::parse(&"a".repeat(40)).unwrap(),
            );
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

            assert!(
                build_sha_pin_action(&parse_result, position.into(), &uri, &formatter).is_none()
            );
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
                crate::parser::parse_gitlab_ci_yaml(content, &uri, &policy, &instance_host)
                    .unwrap();
            assert_eq!(parse_result.dependencies.len(), 2);

            let formatter = test_formatter();
            let sha1 = "1".repeat(40);
            let sha2 = "2".repeat(40);
            let mut index1 = TagIndex::default();
            index1
                .tag_to_sha
                .insert("v1.0.0".to_string(), CommitSha::parse(&sha1).unwrap());
            formatter.tag_index.insert(
                (
                    EndpointKind::Tags,
                    parse_result.dependencies[0].name.clone(),
                ),
                Arc::new(index1),
            );
            let mut index2 = TagIndex::default();
            index2
                .tag_to_sha
                .insert("v2.0.0".to_string(), CommitSha::parse(&sha2).unwrap());
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

            let action0 = build_sha_pin_action(&parse_result, position0.into(), &uri, &formatter)
                .expect("expected a quickfix for the first include");
            let action1 = build_sha_pin_action(&parse_result, position1.into(), &uri, &formatter)
                .expect("expected a quickfix for the second include");

            let edit0 = action0.edit.as_ref().unwrap();
            let edit1 = action1.edit.as_ref().unwrap();
            let ls_uri = deps_core::to_ls_uri(&uri);
            assert_eq!(
                edit0.changes.as_ref().unwrap()[&ls_uri][0].new_text,
                format!("{sha1} # v1.0.0")
            );
            assert_eq!(
                edit1.changes.as_ref().unwrap()[&ls_uri][0].new_text,
                format!("{sha2} # v2.0.0")
            );
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
                crate::parser::parse_gitlab_ci_yaml(content, &uri, &policy, &instance_host)
                    .unwrap();
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
            project_index.tag_to_sha.insert(
                "v1.0.0".to_string(),
                CommitSha::parse(&project_sha).unwrap(),
            );
            formatter.tag_index.insert(
                (
                    EndpointKind::Tags,
                    parse_result.dependencies[0].name.clone(),
                ),
                Arc::new(project_index),
            );
            let mut component_index = TagIndex::default();
            component_index.tag_to_sha.insert(
                "1.0.0".to_string(),
                CommitSha::parse(&component_sha).unwrap(),
            );
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

            let action0 = build_sha_pin_action(&parse_result, position0.into(), &uri, &formatter)
                .expect("expected a quickfix for the project: include");
            let action1 = build_sha_pin_action(&parse_result, position1.into(), &uri, &formatter)
                .expect("expected a quickfix for the component: include");
            let ls_uri = deps_core::to_ls_uri(&uri);

            assert_eq!(
                action0.edit.as_ref().unwrap().changes.as_ref().unwrap()[&ls_uri][0].new_text,
                format!("{project_sha} # v1.0.0"),
                "the project: include must resolve its own Tags-route SHA, not the component's"
            );
            assert_eq!(
                action1.edit.as_ref().unwrap().changes.as_ref().unwrap()[&ls_uri][0].new_text,
                format!("{component_sha} # 1.0.0"),
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
            GitlabCiFormatter,
            crate::types::GitlabCiParseResult,
            Url,
            Position,
        ) {
            let client = Arc::new(GitlabApiClient::new(Arc::new(HttpCache::new())));
            let registry = GitlabCiRegistry::new(client);
            let formatter = GitlabCiFormatter::new(registry.routes(), registry.tag_index());

            let host_bare = server.url();
            let host = crate::host::GitlabHost::for_test(&host_bare);
            let name = PackageName::new(format!("{}/org/proj/comp", host.host()));
            let index = "gitlab:component-pin-test".to_string();
            registry.register_alternate(&[(
                index.clone(),
                crate::types::GitlabRoute {
                    host,
                    endpoint: EndpointKind::Releases,
                },
            )]);

            let range = tower_lsp_server::ls_types::Range::new(
                tower_lsp_server::ls_types::Position::new(0, 0),
                tower_lsp_server::ls_types::Position::new(0, version_req.len() as u32),
            );
            let dep = GitlabCiDependency {
                name,
                name_range: range.into(),
                version_req: Some(version_req.into()),
                version_range: Some(range.into()),
                version_literal: None,
                source: deps_core::parser::DependencySource::AlternateRegistry {
                    index,
                    mirrors_crates_io: false,
                },
                is_plain_scalar: true,
                is_alias_occurrence: false,
                kind: IncludeKind::Component,
                host: HostRef::Literal(crate::host::GitlabHost::for_test(&host_bare)),
                pin: Some(pin),
                comment_slot: deps_core::lsp_helpers::CommentSlot::Unavailable,
                project_path: "org/proj".to_string(),
            };
            let uri = deps_core::test_util::test_uri("/repo/.gitlab-ci.yml");
            let parse_result = crate::types::GitlabCiParseResult {
                dependencies: vec![dep],
                routes: vec![],
                uri: uri.clone(),
                dependency_truncation: None,
                blocked_registries: Vec::new(),
            };
            (registry, formatter, parse_result, uri, range.start)
        }

        /// Tester re-review: end-to-end tie between the two halves of the #643 invariant on
        /// the SAME fixture, in one assertion — the classification-table test only exercises
        /// `sha_pin_quickfix_kind` directly, and the message/action assertions otherwise live
        /// in disjoint tests, so nothing previously caught a future edit that special-cased one
        /// call site without touching the shared predicate. A resolved host must both omit the
        /// diagnostic's suffix AND actually offer the quickfix.
        #[tokio::test]
        async fn test_message_omits_suffix_iff_quickfix_actually_offered_for_resolved_latest_pin() {
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

            let (registry, formatter, parse_result, uri, position) =
                component_pin_test_setup(&server, PinStyle::Latest, "~latest");

            let diagnostics =
                mutable_ref_pin_diagnostics(&parse_result, Severity::Hint, &formatter);
            let found = diagnostics
                .iter()
                .find(|d| d.code() == Some(mutable_ref_pin_code().as_str()))
                .expect("expected the mutable-ref-pin diagnostic for a PinStyle::Latest component");
            assert!(
                !found.message().contains("no automated fix available"),
                "a resolved host has a genuine quickfix, so the message must omit the suffix: {}",
                found.message()
            );

            let action = build_dynamic_component_pin_action(
                &parse_result,
                position,
                &uri,
                &formatter,
                &registry,
            )
            .await
            .expect(
                "the message just claimed a quickfix is available for this exact dependency — \
             it must actually exist",
            );
            assert_eq!(
                action.edit.as_ref().unwrap().changes.as_ref().unwrap()
                    [&deps_core::to_ls_uri(&uri)][0]
                    .new_text,
                sha
            );
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

            let (registry, formatter, parse_result, uri, position) =
                component_pin_test_setup(&server, PinStyle::Latest, "~latest");

            let action = build_dynamic_component_pin_action(
                &parse_result,
                position,
                &uri,
                &formatter,
                &registry,
            )
            .await
            .expect("expected a quickfix resolving ~latest to a concrete SHA");
            assert_eq!(
                action.edit.as_ref().unwrap().changes.as_ref().unwrap()
                    [&deps_core::to_ls_uri(&uri)][0]
                    .new_text,
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

            let (registry, formatter, parse_result, uri, position) =
                component_pin_test_setup(&server, PinStyle::Partial, "1.2");

            let action = build_dynamic_component_pin_action(
                &parse_result,
                position,
                &uri,
                &formatter,
                &registry,
            )
            .await
            .expect("expected a quickfix resolving the partial pin to a concrete SHA");
            assert_eq!(
                action.edit.as_ref().unwrap().changes.as_ref().unwrap()
                    [&deps_core::to_ls_uri(&uri)][0]
                    .new_text,
                sha
            );
        }

        /// Security audit finding (#1252, critic follow-up C2): the one CodeAction title fixed
        /// in this PR (`build_dynamic_component_pin_action`'s "Pin {name} to commit SHA") had no
        /// regression test — a bidi override in the dependency name must not survive into the
        /// title, and an oversized name must not grow it unbounded.
        #[tokio::test]
        async fn test_build_dynamic_component_pin_action_title_sanitizes_and_caps_name() {
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

            let client = Arc::new(GitlabApiClient::new(Arc::new(HttpCache::new())));
            let registry = GitlabCiRegistry::new(client);
            let formatter = GitlabCiFormatter::new(registry.routes(), registry.tag_index());

            let host_bare = server.url();
            let long_suffix = "x".repeat(200);
            // The bidi override and the length go into the trailing component-name segment
            // only: `project_path_from_name`'s `Releases` branch derives the fetch path via
            // `rsplit_once('/')`, keeping everything before the last `/` as the project path
            // (must stay exactly "org/proj" to match the mock below) and treating the last
            // segment as the (here, deliberately hostile) component name.
            let host = crate::host::GitlabHost::for_test(&host_bare);
            let name = PackageName::new(format!(
                "{}/org/proj/co\u{202E}mp{long_suffix}",
                host.host()
            ));
            let index = "gitlab:component-pin-title-test".to_string();
            registry.register_alternate(&[(
                index.clone(),
                crate::types::GitlabRoute {
                    host,
                    endpoint: EndpointKind::Releases,
                },
            )]);

            let version_req = "~latest";
            let range = tower_lsp_server::ls_types::Range::new(
                tower_lsp_server::ls_types::Position::new(0, 0),
                tower_lsp_server::ls_types::Position::new(0, version_req.len() as u32),
            );
            let dep = GitlabCiDependency {
                name,
                name_range: range.into(),
                version_req: Some(version_req.into()),
                version_range: Some(range.into()),
                version_literal: None,
                source: deps_core::parser::DependencySource::AlternateRegistry {
                    index,
                    mirrors_crates_io: false,
                },
                is_plain_scalar: true,
                is_alias_occurrence: false,
                kind: IncludeKind::Component,
                host: HostRef::Literal(crate::host::GitlabHost::for_test(&host_bare)),
                pin: Some(PinStyle::Latest),
                comment_slot: deps_core::lsp_helpers::CommentSlot::Unavailable,
                project_path: "org/proj".to_string(),
            };
            let uri = deps_core::test_util::test_uri("/repo/.gitlab-ci.yml");
            let parse_result = crate::types::GitlabCiParseResult {
                dependencies: vec![dep],
                routes: vec![],
                uri: uri.clone(),
                dependency_truncation: None,
                blocked_registries: Vec::new(),
            };

            let action = build_dynamic_component_pin_action(
                &parse_result,
                range.start,
                &uri,
                &formatter,
                &registry,
            )
            .await
            .expect("expected a quickfix resolving ~latest to a concrete SHA");

            assert!(
                !action.title.contains('\u{202E}'),
                "bidi override must not survive into the title: {:?}",
                action.title
            );
            assert!(
                action.title.len() < long_suffix.len(),
                "an oversized name must not render in full inside the title: {:?}",
                action.title
            );
            assert!(action.title.contains('…'));
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

            let (registry, formatter, parse_result, uri, position) =
                component_pin_test_setup(&server, PinStyle::Partial, "1.2");

            assert!(
                build_dynamic_component_pin_action(
                    &parse_result,
                    position,
                    &uri,
                    &formatter,
                    &registry
                )
                .await
                .is_none()
            );
        }

        /// Neither a `project:` include nor a `component:` `PinStyle::Tag`/`PinStyle::Branch`
        /// pin is ever resolved by this function — it exists solely for `Latest`/`Partial`.
        #[tokio::test]
        async fn test_build_dynamic_component_pin_action_ignores_non_latest_partial_pins() {
            let server = mockito::Server::new_async().await;
            let (registry, formatter, parse_result, uri, position) =
                component_pin_test_setup(&server, PinStyle::Tag, "1.0.0");

            assert!(
                build_dynamic_component_pin_action(
                    &parse_result,
                    position,
                    &uri,
                    &formatter,
                    &registry
                )
                .await
                .is_none()
            );
        }

        // --- issue #640: bulk "Pin all to SHA" collector ---

        fn empty_versions() -> (
            std::collections::HashMap<PackageName, deps_core::PackageVersions>,
            std::collections::HashMap<PackageName, deps_core::ConcreteVersion>,
        ) {
            (
                std::collections::HashMap::new(),
                std::collections::HashMap::new(),
            )
        }

        #[tokio::test]
        async fn test_collect_pin_all_to_sha_edits_multiple_tag_includes_produce_sorted_edits() {
            let uri = deps_core::test_util::test_uri("/repo/.gitlab-ci.yml");
            let content = "include:\n  - project: org/proj1\n    ref: v1.0.0\n  - project: org/proj2\n    ref: v2.0.0\n";
            let eco = GitlabCiEcosystem::new(Arc::new(HttpCache::new()));
            let parse_result = eco.parse_manifest(content, &uri).await.unwrap();
            let deps = deps_core::ParseResult::dependencies(parse_result.as_ref());
            let sha1 = "1".repeat(40);
            let sha2 = "2".repeat(40);
            let mut index1 = TagIndex::default();
            index1
                .tag_to_sha
                .insert("v1.0.0".to_string(), CommitSha::parse(&sha1).unwrap());
            eco.formatter.tag_index.insert(
                (EndpointKind::Tags, deps[0].name().clone()),
                Arc::new(index1),
            );
            let mut index2 = TagIndex::default();
            index2
                .tag_to_sha
                .insert("v2.0.0".to_string(), CommitSha::parse(&sha2).unwrap());
            eco.formatter.tag_index.insert(
                (EndpointKind::Tags, deps[1].name().clone()),
                Arc::new(index2),
            );

            let (cached, resolved) = empty_versions();
            let versions = deps_core::VersionData::new(&cached, &resolved);
            let edits = eco.collect_pin_all_to_sha_edits(parse_result.as_ref(), versions);

            assert_eq!(edits.len(), 2);
            assert!(
                edits
                    .iter()
                    .any(|e| e.new_text == format!("{sha1} # v1.0.0"))
            );
            assert!(
                edits
                    .iter()
                    .any(|e| e.new_text == format!("{sha2} # v2.0.0"))
            );
        }

        #[tokio::test]
        async fn test_collect_pin_all_to_sha_edits_skips_sha_branch_and_refless_includes() {
            let uri = deps_core::test_util::test_uri("/repo/.gitlab-ci.yml");
            let sha_lit = "a".repeat(40);
            let content = format!(
                "include:\n\
             \x20 - project: org/sha\n    ref: {sha_lit}\n\
             \x20 - project: org/branch\n    ref: main\n\
             \x20 - project: org/norefs\n"
            );
            let eco = GitlabCiEcosystem::new(Arc::new(HttpCache::new()));
            let parse_result = eco.parse_manifest(&content, &uri).await.unwrap();

            let (cached, resolved) = empty_versions();
            let versions = deps_core::VersionData::new(&cached, &resolved);
            let edits = eco.collect_pin_all_to_sha_edits(parse_result.as_ref(), versions);

            assert!(
                edits.is_empty(),
                "a SHA pin, an unconfirmed branch pin, and a ref-less include must all be \
             withheld: {edits:?}"
            );
        }

        #[tokio::test]
        async fn test_collect_pin_all_to_sha_edits_tag_index_miss_is_skipped() {
            let uri = deps_core::test_util::test_uri("/repo/.gitlab-ci.yml");
            let content = "include:\n  - project: org/proj\n    ref: v1.0.0\n";
            let eco = GitlabCiEcosystem::new(Arc::new(HttpCache::new()));
            let parse_result = eco.parse_manifest(content, &uri).await.unwrap();
            // No `tag_index` seed: a genuine cache miss must be skipped gracefully.

            let (cached, resolved) = empty_versions();
            let versions = deps_core::VersionData::new(&cached, &resolved);
            let edits = eco.collect_pin_all_to_sha_edits(parse_result.as_ref(), versions);

            assert!(edits.is_empty());
        }

        #[tokio::test]
        async fn test_collect_pin_all_to_sha_edits_resolves_latest_component_pin_from_cached_versions()
         {
            let uri = deps_core::test_util::test_uri("/repo/.gitlab-ci.yml");
            let content = "include:\n  - component: gitlab.com/org/proj/comp@~latest\n";
            let eco = GitlabCiEcosystem::new(Arc::new(HttpCache::new()));
            let parse_result = eco.parse_manifest(content, &uri).await.unwrap();
            let name = deps_core::ParseResult::dependencies(parse_result.as_ref())[0]
                .name()
                .clone();

            let sha = "a".repeat(40);
            let mut index = TagIndex::default();
            index
                .tag_to_sha
                .insert("2.0.0".to_string(), CommitSha::parse(&sha).unwrap());
            eco.formatter
                .tag_index
                .insert((EndpointKind::Releases, name.clone()), Arc::new(index));

            let mut cached = std::collections::HashMap::new();
            cached.insert(name, deps_core::PackageVersions::latest_only("2.0.0"));
            let resolved = std::collections::HashMap::new();
            let versions = deps_core::VersionData::new(&cached, &resolved);

            let edits = eco.collect_pin_all_to_sha_edits(parse_result.as_ref(), versions);
            assert_eq!(edits.len(), 1);
            assert_eq!(edits[0].new_text, format!("{sha} # 2.0.0"));
        }

        #[tokio::test]
        async fn test_collect_pin_all_to_sha_edits_resolves_partial_component_pin_picks_highest_matching()
         {
            let uri = deps_core::test_util::test_uri("/repo/.gitlab-ci.yml");
            let content = "include:\n  - component: gitlab.com/org/proj/comp@1.2\n";
            let eco = GitlabCiEcosystem::new(Arc::new(HttpCache::new()));
            let parse_result = eco.parse_manifest(content, &uri).await.unwrap();
            let name = deps_core::ParseResult::dependencies(parse_result.as_ref())[0]
                .name()
                .clone();

            let sha_low = "1".repeat(40);
            let sha_high = "2".repeat(40);
            let mut index = TagIndex::default();
            index
                .tag_to_sha
                .insert("1.2.0".to_string(), CommitSha::parse(&sha_low).unwrap());
            index
                .tag_to_sha
                .insert("1.2.5".to_string(), CommitSha::parse(&sha_high).unwrap());
            eco.formatter
                .tag_index
                .insert((EndpointKind::Releases, name.clone()), Arc::new(index));

            let mut cached = std::collections::HashMap::new();
            let available: Vec<deps_core::ConcreteVersion> =
                vec!["1.2.0".into(), "1.2.5".into(), "1.3.0".into()];
            cached.insert(
                name,
                deps_core::PackageVersions::new("1.3.0".into(), std::sync::Arc::from(available)),
            );
            let resolved = std::collections::HashMap::new();
            let versions = deps_core::VersionData::new(&cached, &resolved);

            let edits = eco.collect_pin_all_to_sha_edits(parse_result.as_ref(), versions);
            assert_eq!(edits.len(), 1);
            assert_eq!(
                edits[0].new_text,
                format!("{sha_high} # 1.2.5"),
                "1.2 must pick the highest matching release (1.2.5), not 1.2.0 or the \
             out-of-range 1.3.0"
            );
        }

        /// S2 invariant-1 regression: the ladder's winning release (`2.0.0`, the highest) has
        /// no `TagIndex` entry — the reconstitution must keep it as an empty-SHA placeholder
        /// rather than dropping it, so `Latest` still resolves to `2.0.0` and then correctly
        /// withholds the edit (since its SHA is unknown), instead of silently shifting the
        /// result down to `1.0.0` just because that one happens to have a SHA on file.
        #[tokio::test]
        async fn test_collect_pin_all_to_sha_edits_unknown_sha_winner_is_skipped_not_shifted() {
            let uri = deps_core::test_util::test_uri("/repo/.gitlab-ci.yml");
            let content = "include:\n  - component: gitlab.com/org/proj/comp@~latest\n";
            let eco = GitlabCiEcosystem::new(Arc::new(HttpCache::new()));
            let parse_result = eco.parse_manifest(content, &uri).await.unwrap();
            let name = deps_core::ParseResult::dependencies(parse_result.as_ref())[0]
                .name()
                .clone();

            // Only "1.0.0" has a TagIndex entry; "2.0.0" (the true winner) does not.
            let mut index = TagIndex::default();
            index.tag_to_sha.insert(
                "1.0.0".to_string(),
                CommitSha::parse(&"a".repeat(40)).unwrap(),
            );
            eco.formatter
                .tag_index
                .insert((EndpointKind::Releases, name.clone()), Arc::new(index));

            let mut cached = std::collections::HashMap::new();
            let available: Vec<deps_core::ConcreteVersion> = vec!["1.0.0".into(), "2.0.0".into()];
            cached.insert(
                name,
                deps_core::PackageVersions::new("2.0.0".into(), std::sync::Arc::from(available)),
            );
            let resolved = std::collections::HashMap::new();
            let versions = deps_core::VersionData::new(&cached, &resolved);

            let edits = eco.collect_pin_all_to_sha_edits(parse_result.as_ref(), versions);
            assert!(
                edits.is_empty(),
                "the unresolvable winner must be skipped outright, never silently replaced by \
             a lower-ranked release that happens to have a known SHA: {edits:?}"
            );
        }

        /// M2 (impl-critic minor): regression for `resolve_component_pin`'s documented
        /// last-maximum tie-break (`component.rs:155`/`:167`) surviving through the bulk
        /// collector's reconstitution — two releases that normalize to the same semver
        /// (`1.2.0`/`v1.2.0`) must resolve by `available`'s own order, not be silently
        /// reordered/deduped by a future "tidy up" of `reconstitute_component_releases`.
        #[tokio::test]
        async fn test_collect_pin_all_to_sha_edits_latest_tie_break_picks_last_in_available_order()
        {
            let uri = deps_core::test_util::test_uri("/repo/.gitlab-ci.yml");
            let content = "include:\n  - component: gitlab.com/org/proj/comp@~latest\n";
            let eco = GitlabCiEcosystem::new(Arc::new(HttpCache::new()));
            let parse_result = eco.parse_manifest(content, &uri).await.unwrap();
            let name = deps_core::ParseResult::dependencies(parse_result.as_ref())[0]
                .name()
                .clone();

            let sha_first = "1".repeat(40);
            let sha_last = "2".repeat(40);
            let mut index = TagIndex::default();
            index
                .tag_to_sha
                .insert("1.2.0".to_string(), CommitSha::parse(&sha_first).unwrap());
            index
                .tag_to_sha
                .insert("v1.2.0".to_string(), CommitSha::parse(&sha_last).unwrap());
            eco.formatter
                .tag_index
                .insert((EndpointKind::Releases, name.clone()), Arc::new(index));

            let mut cached = std::collections::HashMap::new();
            // "1.2.0" and "v1.2.0" normalize to the identical semver — order decides the tie.
            let available: Vec<deps_core::ConcreteVersion> = vec!["1.2.0".into(), "v1.2.0".into()];
            cached.insert(
                name,
                deps_core::PackageVersions::new("v1.2.0".into(), std::sync::Arc::from(available)),
            );
            let resolved = std::collections::HashMap::new();
            let versions = deps_core::VersionData::new(&cached, &resolved);

            let edits = eco.collect_pin_all_to_sha_edits(parse_result.as_ref(), versions);
            assert_eq!(edits.len(), 1);
            assert_eq!(
                edits[0].new_text,
                format!("{sha_last} # v1.2.0"),
                "on a semver tie, the LAST entry in available's order must win, matching \
             resolve_component_pin's documented max_by behavior"
            );
        }

        /// M3: a quoted-scalar `ref:` must round-trip through the bulk collector exactly like
        /// an unquoted one — `version_range` locates only the raw value text (`git_ref`), so
        /// the surrounding quotes fall outside the edit and survive unmodified. Unlike
        /// `deps-github-actions`, this ecosystem has no `is_plain_scalar`/flow-mapping guard
        /// to withhold on, by design (see `build_sha_pin_action`'s doc comment).
        #[tokio::test]
        async fn test_collect_pin_all_to_sha_edits_quoted_scalar_tag_pin_round_trips() {
            let uri = deps_core::test_util::test_uri("/repo/.gitlab-ci.yml");
            let content = "include:\n  - project: org/proj\n    ref: \"v1.0.0\"\n";
            let eco = GitlabCiEcosystem::new(Arc::new(HttpCache::new()));
            let parse_result = eco.parse_manifest(content, &uri).await.unwrap();
            let name = deps_core::ParseResult::dependencies(parse_result.as_ref())[0]
                .name()
                .clone();
            let sha = "a".repeat(40);
            let mut index = TagIndex::default();
            index
                .tag_to_sha
                .insert("v1.0.0".to_string(), CommitSha::parse(&sha).unwrap());
            eco.formatter
                .tag_index
                .insert((EndpointKind::Tags, name), Arc::new(index));

            let (cached, resolved) = empty_versions();
            let versions = deps_core::VersionData::new(&cached, &resolved);
            let edits = eco.collect_pin_all_to_sha_edits(parse_result.as_ref(), versions);

            assert_eq!(edits.len(), 1);
            assert_eq!(edits[0].new_text, sha);

            let table = deps_core::LineOffsetTable::new(content);
            let start = table.position_to_byte_offset(content, edits[0].range.start.into());
            let end = table.position_to_byte_offset(content, edits[0].range.end.into());
            let new_content = format!(
                "{}{}{}",
                &content[..start],
                edits[0].new_text,
                &content[end..]
            );
            assert!(
                new_content.contains(&format!("\"{sha}\"")),
                "the surrounding quotes must survive the edit: {new_content}"
            );
            eco.parse_manifest(&new_content, &uri)
                .await
                .expect("resulting text must still parse");
        }

        /// `deps-gitlab-ci` never supports raw-text section detection at all (no cheap
        /// section boundary shared by `project:`/`component:` include forms) — no override.
        #[test]
        fn test_fallback_completion_prefix_default_none() {
            let cache = Arc::new(deps_core::HttpCache::new());
            let eco = GitlabCiEcosystem::new(cache);
            assert!(
                eco.fallback_completion_prefix("anything at all\n", Position::new(0, 0).into())
                    .is_none()
            );
        }

        // --- #793: `generate_completions` dispatch, pinned before the wildcard-match refactor
        // so it can't silently change behavior. GitLab CI serves only `Version` (no
        // package-name search, NFR-002); the other two contexts must return `Completions::default()`.

        /// A minimal, fully literal `GitlabCiDependency` for dispatch tests — bypasses the real
        /// YAML parser so `name_range`/`version_range`/`source` are exactly what the test wants,
        /// with no risk of a real parse resolving `source` to a live, network-reachable host.
        fn dispatch_test_dep(
            name_range: deps_core::position::Range,
            version_range: deps_core::position::Range,
            source: deps_core::parser::DependencySource,
        ) -> crate::types::GitlabCiDependency {
            crate::types::GitlabCiDependency {
                name: "org/proj".into(),
                name_range,
                version_req: Some("1.0.0".into()),
                version_range: Some(version_range),
                version_literal: None,
                source,
                is_plain_scalar: true,
                is_alias_occurrence: false,
                kind: IncludeKind::Project,
                host: HostRef::Unresolved("$CI_SERVER_FQDN".to_string()),
                pin: Some(PinStyle::Tag),
                comment_slot: deps_core::lsp_helpers::CommentSlot::Unavailable,
                project_path: "org/proj".to_string(),
            }
        }

        #[tokio::test]
        async fn test_generate_completions_package_name_context_returns_empty_non_incomplete() {
            let uri = deps_core::test_util::test_uri("/repo/.gitlab-ci.yml");
            let name_range =
                tower_lsp_server::ls_types::Range::new(Position::new(1, 4), Position::new(1, 12));
            let version_range =
                tower_lsp_server::ls_types::Range::new(Position::new(2, 9), Position::new(2, 15));
            let dep = dispatch_test_dep(
                name_range.into(),
                version_range.into(),
                deps_core::parser::DependencySource::CustomRegistry {
                    url: "https://gitlab.example".into(),
                },
            );
            let parse_result = crate::types::GitlabCiParseResult {
                dependencies: vec![dep],
                routes: vec![],
                uri,
                dependency_truncation: None,
                blocked_registries: Vec::new(),
            };
            let content = "include:\n  - project: org/proj\n    ref: v1.0.0\n";
            let cache = Arc::new(HttpCache::new());
            let eco = GitlabCiEcosystem::new(cache);

            let result = eco
                .generate_completions(
                    &parse_result,
                    name_range.start,
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

        #[tokio::test]
        async fn test_generate_completions_version_context_no_dependency_at_position_returns_empty()
        {
            let uri = deps_core::test_util::test_uri("/repo/.gitlab-ci.yml");
            let name_range =
                tower_lsp_server::ls_types::Range::new(Position::new(1, 4), Position::new(1, 12));
            let version_range =
                tower_lsp_server::ls_types::Range::new(Position::new(2, 9), Position::new(2, 15));
            let dep = dispatch_test_dep(
                name_range.into(),
                version_range.into(),
                deps_core::parser::DependencySource::CustomRegistry {
                    url: "https://gitlab.example".into(),
                },
            );
            let parse_result = crate::types::GitlabCiParseResult {
                dependencies: vec![dep],
                routes: vec![],
                uri,
                dependency_truncation: None,
                blocked_registries: Vec::new(),
            };
            let content = "include:\n  - project: org/proj\n    ref: v1.0.0\n";
            let cache = Arc::new(HttpCache::new());
            let eco = GitlabCiEcosystem::new(cache);

            // Line 0 falls outside every dependency's name/version range.
            let result = eco
                .generate_completions(
                    &parse_result,
                    Position::new(0, 0),
                    content,
                    deps_core::FreshnessSettings::default(),
                )
                .await;
            assert_eq!(result, Completions::default());
        }

        /// The dependency *is* found at `position`, but its source (`CustomRegistry`, an
        /// unresolved host) fails closed inside `GitlabCiRegistry::get_versions_from` before any
        /// network call — deterministic, and pins that `generate_completions` still threads the
        /// found dependency's own `name`/`source` into `complete_versions_generic_from` rather
        /// than, say, skipping the lookup or using a different dependency's source.
        ///
        /// tester finding #2 (post-#1136 review): the original version of this test only
        /// asserted `via_dispatch.items == direct` — both sides independently call the *same*
        /// gated function with the *same* args, so that equality would hold even if
        /// `can_resolve_source` were deleted entirely (both sides would just as happily agree on
        /// a non-empty result together). The explicit `is_empty()` assertion below is what
        /// actually pins the observable outcome for a `CustomRegistry` source.
        #[tokio::test]
        async fn test_generate_completions_version_context_dispatches_by_dependency_source() {
            let uri = deps_core::test_util::test_uri("/repo/.gitlab-ci.yml");
            let name_range =
                tower_lsp_server::ls_types::Range::new(Position::new(1, 4), Position::new(1, 12));
            let version_range =
                tower_lsp_server::ls_types::Range::new(Position::new(2, 9), Position::new(2, 15));
            let source = deps_core::parser::DependencySource::CustomRegistry {
                url: "https://gitlab.example".into(),
            };
            let dep = dispatch_test_dep(name_range.into(), version_range.into(), source.clone());
            let parse_result = crate::types::GitlabCiParseResult {
                dependencies: vec![dep],
                routes: vec![],
                uri,
                dependency_truncation: None,
                blocked_registries: Vec::new(),
            };
            let content = "include:\n  - project: org/proj\n    ref: v1.0.0\n";
            let cache = Arc::new(HttpCache::new());
            let eco = GitlabCiEcosystem::new(cache);
            let freshness = deps_core::FreshnessSettings::default();

            let via_dispatch = eco
                .generate_completions(&parse_result, Position::new(2, 13), content, freshness)
                .await;
            let direct = deps_core::completion::complete_versions_generic_from(
                eco.registry.as_ref(),
                &eco.formatter,
                &deps_core::PackageName::new("org/proj"),
                &source,
                "v1.0",
                VERSION_OPERATOR_CHARS,
                freshness,
                &deps_core::SelectionContext::none(),
            )
            .await;
            assert_eq!(via_dispatch.items, direct);
            assert!(
                via_dispatch.items.is_empty(),
                "a CustomRegistry source must yield zero completions, got: {:?}",
                via_dispatch.items
            );
            assert!(!via_dispatch.is_incomplete);
        }

        /// FR-010/US-002: the "Pin to commit SHA" code action must never be offered at an
        /// alias site, even when a real `TagIndex` entry would otherwise resolve one.
        #[tokio::test]
        async fn test_generate_code_actions_withholds_sha_pin_for_alias_occurrence() {
            let uri = deps_core::test_util::test_uri("/repo/.gitlab-ci.yml");
            let version_range =
                tower_lsp_server::ls_types::Range::new(Position::new(2, 9), Position::new(2, 13));
            let name_range =
                tower_lsp_server::ls_types::Range::new(Position::new(1, 4), Position::new(1, 12));
            let gl_dep = alias_dispatch_test_dep(
                name_range.into(),
                version_range.into(),
                Some(PinStyle::Tag),
            );
            let parse_result = crate::types::GitlabCiParseResult {
                dependencies: vec![gl_dep],
                routes: vec![],
                uri: uri.clone(),
                dependency_truncation: None,
                blocked_registries: Vec::new(),
            };
            let content = "include:\n  - project: org/proj\n    ref: *pin\n";
            let cache = Arc::new(HttpCache::new());
            let eco = GitlabCiEcosystem::new(cache);
            let cached = std::collections::HashMap::new();
            let resolved = std::collections::HashMap::new();

            let actions = eco
                .generate_code_actions(
                    &parse_result,
                    Position::new(2, 11),
                    &uri,
                    deps_core::VersionData::new(&cached, &resolved),
                    content,
                )
                .await;
            assert!(
                actions.is_empty(),
                "expected no quickfix at an alias site: {actions:?}"
            );
        }

        /// FR-011/EC-016/SC-006: version completion is withheld at an alias site using the
        /// `project:`/`ref:` shape (`name_range != version_range`) — the shape where
        /// `CompletionContext::Version` is actually reachable, so this is a meaningful test of
        /// the gate rather than a vacuous one (see [`alias_dispatch_test_dep`]'s doc comment).
        #[tokio::test]
        async fn test_generate_completions_withholds_version_completion_for_alias_occurrence() {
            let uri = deps_core::test_util::test_uri("/repo/.gitlab-ci.yml");
            let name_range =
                tower_lsp_server::ls_types::Range::new(Position::new(1, 4), Position::new(1, 12));
            let version_range =
                tower_lsp_server::ls_types::Range::new(Position::new(2, 9), Position::new(2, 13));
            let dep = alias_dispatch_test_dep(
                name_range.into(),
                version_range.into(),
                Some(PinStyle::Tag),
            );
            let parse_result = crate::types::GitlabCiParseResult {
                dependencies: vec![dep],
                routes: vec![],
                uri,
                dependency_truncation: None,
                blocked_registries: Vec::new(),
            };
            let content = "include:\n  - project: org/proj\n    ref: *pin\n";
            let cache = Arc::new(HttpCache::new());
            let eco = GitlabCiEcosystem::new(cache);

            // Cursor inside the alias token's `version_range`.
            let result = eco
                .generate_completions(
                    &parse_result,
                    Position::new(2, 11),
                    content,
                    deps_core::FreshnessSettings::default(),
                )
                .await;
            assert_eq!(result, Completions::default());
        }

        /// #912 critic S3: `#922`'s `dependency_version_range_is_literal` guard already blocks
        /// `detect_completion_context` from ever returning `Version` for a `*`-leading
        /// `version_range`, so the `generate_completions`-level test above no longer exercises
        /// this ecosystem's own FR-011 gate — it now passes even without it. This test calls
        /// `complete_version` directly, bypassing `detect_completion_context` entirely, to pin
        /// that the local gate itself still withholds (defense-in-depth, not dead code).
        #[tokio::test]
        async fn test_complete_version_directly_withholds_for_alias_occurrence() {
            let uri = deps_core::test_util::test_uri("/repo/.gitlab-ci.yml");
            let name_range =
                tower_lsp_server::ls_types::Range::new(Position::new(1, 4), Position::new(1, 12));
            let version_range =
                tower_lsp_server::ls_types::Range::new(Position::new(2, 9), Position::new(2, 13));
            let dep = alias_dispatch_test_dep(
                name_range.into(),
                version_range.into(),
                Some(PinStyle::Tag),
            );
            let parse_result = crate::types::GitlabCiParseResult {
                dependencies: vec![dep],
                routes: vec![],
                uri,
                dependency_truncation: None,
                blocked_registries: Vec::new(),
            };
            let cache = Arc::new(HttpCache::new());
            let eco = GitlabCiEcosystem::new(cache);
            let request = deps_core::completion::CompletionRequest::new(
                &parse_result,
                Position::new(2, 11),
                deps_core::FreshnessSettings::default(),
            );

            let result = eco
                .complete_version(request, PackageName::new("org/proj"), "v1.0".to_string())
                .await;
            assert_eq!(result, Completions::default());
        }

        /// FR-010/US-002: the bulk "pin all to SHA" lens must not produce an edit for an
        /// alias-occurrence dependency, even when its pin would otherwise resolve one.
        #[test]
        fn test_collect_pin_all_to_sha_edits_withholds_for_alias_occurrence() {
            let uri = deps_core::test_util::test_uri("/repo/.gitlab-ci.yml");
            let range = deps_core::position::Range::new(
                deps_core::position::Position::new(0, 0),
                deps_core::position::Position::new(0, 4),
            );
            let gl_dep = alias_dispatch_test_dep(range, range, Some(PinStyle::Tag));
            let parse_result = crate::types::GitlabCiParseResult {
                dependencies: vec![gl_dep],
                routes: vec![],
                uri,
                dependency_truncation: None,
                blocked_registries: Vec::new(),
            };
            let cache = Arc::new(HttpCache::new());
            let eco = GitlabCiEcosystem::new(cache);
            let cached = std::collections::HashMap::new();
            let resolved = std::collections::HashMap::new();

            let edits = eco.collect_pin_all_to_sha_edits(
                &parse_result,
                deps_core::VersionData::new(&cached, &resolved),
            );
            assert!(edits.is_empty());
        }

        /// #1729: update-all rewrites only a `Tag` pin; a branch (like `~latest`/partial
        /// component pins) is never rewritten into a (v-stripped) version.
        #[tokio::test]
        async fn test_update_all_rewrites_tag_pin_but_not_branch_latest_or_partial() {
            let eco = GitlabCiEcosystem::with_context(
                Arc::new(HttpCache::new()),
                Arc::new(deps_core::net_policy::RegistryAccessPolicy::default()),
                Arc::new(RwLock::new(Some("gitlab.com".to_string()))),
            );
            let content = "include:\n\
                 \x20 - project: org/tagged\n\
                 \x20   ref: v1.0.0\n\
                 \x20 - project: org/branched\n\
                 \x20   ref: main\n\
                 \x20 - component: gitlab.com/org/latest/comp@~latest\n\
                 \x20 - component: gitlab.com/org/partial/comp@1.0\n";
            let uri = deps_core::test_util::test_uri("/repo/.gitlab-ci.yml");
            let parse_result = eco.parse_manifest(content, &uri).await.unwrap();
            let deps = deps_core::ParseResult::dependencies(parse_result.as_ref());
            assert_eq!(deps.len(), 4);

            let mut cached = std::collections::HashMap::new();
            for dep in &deps {
                cached.insert(
                    dep.name().clone(),
                    deps_core::PackageVersions::latest_only("v1.1.0"),
                );
            }
            let resolved = std::collections::HashMap::new();
            let edits = deps_core::lsp_helpers::collect_update_all_edits(
                parse_result.as_ref(),
                content,
                deps_core::VersionData::new(&cached, &resolved),
                &eco.formatter,
            );
            let planned: Vec<(u32, &str)> = edits
                .iter()
                .map(|e| (e.range.start.line, e.new_text.as_str()))
                .collect();
            assert_eq!(planned, [(2, "v1.1.0")], "{edits:?}");
        }

        /// #1723: SHA pins absent from the populated index must be reported consistently by
        /// diagnostics, inlay hints, update-all and hover (`component:` and `project:`
        /// includes alike), and the rewrite is the latest tag's full SHA plus its `# tag` comment, never a bare tag. A
        /// control pin on latest's commit gets none of them.
        #[tokio::test]
        async fn test_sha_pin_surfaces_agree() {
            use tower_lsp_server::ls_types::InlayHintLabel;

            let eco = GitlabCiEcosystem::with_context(
                Arc::new(HttpCache::new()),
                Arc::new(deps_core::net_policy::RegistryAccessPolicy::default()),
                Arc::new(RwLock::new(Some("gitlab.com".to_string()))),
            );
            let latest_sha = "3".repeat(40);
            let missing = "5".repeat(40);
            let content = format!(
                "include:\n\
                 \x20 - component: gitlab.com/org/proj/comp@{missing}\n\
                 \x20 - project: org/proj\n\
                 \x20   ref: {missing}\n\
                 \x20 - component: gitlab.com/org/other/comp@{latest_sha}\n"
            );
            let uri = deps_core::test_util::test_uri("/repo/.gitlab-ci.yml");
            let parse_result = eco.parse_manifest(&content, &uri).await.unwrap();
            let deps = deps_core::ParseResult::dependencies(parse_result.as_ref());
            assert_eq!(deps.len(), 3);

            let mut cached = std::collections::HashMap::new();
            for (dep, endpoint) in deps.iter().zip([
                EndpointKind::Releases,
                EndpointKind::Tags,
                EndpointKind::Releases,
            ]) {
                let index =
                    TagIndex::from_tags([("v1.1.0", &CommitSha::parse(&latest_sha).unwrap())]);
                eco.formatter
                    .tag_index
                    .insert((endpoint, dep.name().clone()), Arc::new(index));
                cached.insert(
                    dep.name().clone(),
                    deps_core::PackageVersions::latest_only("v1.1.0"),
                );
            }
            let resolved = std::collections::HashMap::new();
            let versions = || deps_core::VersionData::new(&cached, &resolved);
            let outdated_lines = [1_u32, 3];
            let control_line = 4_u32;

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
            let rewritten = format!("{latest_sha} # v1.1.0");
            assert!(edits.iter().all(|e| e.new_text == rewritten), "{edits:?}");

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
                        && matches!(&h.label, InlayHintLabel::String(t) if t.contains("v1.1.0"))
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
                        Position::new(line, 30),
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

        const SHA_V117: &str = "44790937bcbf6120698250cc41c9b4fb811c2a03";
        const SHA_V120: &str = "78790114c4d7196c97b2b1a1263a0d725835640d";
        const SHA_OTHER: &str = "9999999999999999999999999999999999999999";

        /// A parsed manifest wired to a `TagIndex` per dependency and a `latest` version.
        struct CommentFixture {
            eco: GitlabCiEcosystem,
            uri: Url,
            content: String,
            parse_result: Box<dyn ParseResultTrait>,
            cached: std::collections::HashMap<PackageName, deps_core::PackageVersions>,
        }

        impl CommentFixture {
            async fn new(content: &str, tags: &[(&str, &str)], latest: &str) -> Self {
                let eco = GitlabCiEcosystem::with_context(
                    Arc::new(HttpCache::new()),
                    Arc::new(deps_core::net_policy::RegistryAccessPolicy::default()),
                    Arc::new(RwLock::new(Some("gitlab.com".to_string()))),
                );
                let uri = deps_core::test_util::test_uri("/repo/.gitlab-ci.yml");
                let parse_result = eco.parse_manifest(content, &uri).await.unwrap();
                let commits: Vec<(&str, CommitSha)> = tags
                    .iter()
                    .map(|(tag, sha)| (*tag, CommitSha::parse(sha).unwrap()))
                    .collect();
                let mut cached = std::collections::HashMap::new();
                for dep in deps_core::ParseResult::dependencies(parse_result.as_ref()) {
                    let kind = dep
                        .as_any()
                        .downcast_ref::<GitlabCiDependency>()
                        .unwrap()
                        .kind;
                    let index = TagIndex::from_tags(commits.iter().map(|(t, s)| (*t, s)));
                    eco.formatter
                        .tag_index
                        .insert((kind.endpoint(), dep.name().clone()), Arc::new(index));
                    cached.insert(
                        dep.name().clone(),
                        deps_core::PackageVersions::latest_only(latest),
                    );
                }
                Self {
                    eco,
                    uri,
                    content: content.to_string(),
                    parse_result,
                    cached,
                }
            }

            fn update_all(&self) -> Vec<TextEdit> {
                let resolved = std::collections::HashMap::new();
                deps_core::lsp_helpers::collect_update_all_edits(
                    self.parse_result.as_ref(),
                    &self.content,
                    deps_core::VersionData::new(&self.cached, &resolved),
                    &self.eco.formatter,
                )
            }

            async fn diagnostics(&self) -> Vec<Diagnostic> {
                self.diagnostics_with(deps_core::lsp_helpers::DiagnosticSeverities::default())
                    .await
            }

            async fn diagnostics_with(
                &self,
                severities: deps_core::lsp_helpers::DiagnosticSeverities,
            ) -> Vec<Diagnostic> {
                let resolved = std::collections::HashMap::new();
                self.eco
                    .generate_diagnostics(
                        self.parse_result.as_ref(),
                        deps_core::VersionData::new(&self.cached, &resolved),
                        &self.uri,
                        deps_core::FreshnessSettings::default(),
                        severities,
                    )
                    .await
            }
        }

        impl CommentFixture {
            fn pin_all(&self) -> Vec<TextEdit> {
                let resolved = std::collections::HashMap::new();
                collect_pin_all_to_sha_edits(
                    self.parse_result.as_ref(),
                    &self.eco.formatter,
                    deps_core::VersionData::new(&self.cached, &resolved),
                )
            }

            fn pin_action(&self, line: u32, column: u32) -> Option<CodeAction> {
                build_sha_pin_action(
                    self.parse_result.as_ref(),
                    Position::new(line, column),
                    &self.uri,
                    &self.eco.formatter,
                )
            }

            fn fix_action(&self, line: u32, column: u32) -> Option<CodeAction> {
                build_sha_comment_fix_action(
                    self.parse_result.as_ref(),
                    Position::new(line, column),
                    &self.uri,
                    &self.eco.formatter,
                )
            }

            fn unknown_ref_fix(&self, line: u32, column: u32) -> Option<CodeAction> {
                build_unknown_ref_fix_action(
                    self.parse_result.as_ref(),
                    Position::new(line, column),
                    &self.uri,
                    &self.eco.formatter,
                )
            }

            fn only_dep(&self) -> GitlabCiDependency {
                let deps = deps_core::ParseResult::dependencies(self.parse_result.as_ref());
                assert_eq!(deps.len(), 1);
                deps[0]
                    .as_any()
                    .downcast_ref::<GitlabCiDependency>()
                    .unwrap()
                    .clone()
            }
        }

        /// Applies one single-line ASCII edit to `content`.
        #[allow(clippy::string_slice)] // single-line ASCII fixtures
        fn apply_edit(content: &str, edit: &TextEdit) -> String {
            let mut out = String::new();
            for (number, line) in content.split_inclusive('\n').enumerate() {
                if number == edit.range.start.line as usize {
                    let (start, end) = (
                        edit.range.start.character as usize,
                        edit.range.end.character as usize,
                    );
                    out.push_str(&line[..start]);
                    out.push_str(&edit.new_text);
                    out.push_str(&line[end..]);
                } else {
                    out.push_str(line);
                }
            }
            out
        }

        fn project_pin(ref_text: &str) -> String {
            format!("include:\n  - project: gitlab-org/cli\n    ref: {ref_text}\n")
        }

        fn v117_v120_tags() -> [(&'static str, &'static str); 2] {
            [("v1.117.0", SHA_V117), ("v1.120.0", SHA_V120)]
        }

        /// #1743: updating a commented SHA `ref:` to `v1.120.0` rewrites the SHA and the trailing
        /// comment in one edit, and the result is stable (not outdated again). The code action
        /// builds its text through the same `replacement_text` path as update-all, but also
        /// fetches the registry live, so only update-all is unit-tested here.
        #[tokio::test]
        async fn test_sha_pin_update_rewrites_trailing_comment_1743() {
            let content = project_pin(&format!("{SHA_V117} # v1.117.0"));
            let fixture = CommentFixture::new(&content, &v117_v120_tags(), "v1.120.0").await;
            let expected = format!("{SHA_V120} # v1.120.0");

            let edits = fixture.update_all();
            assert_eq!(edits.len(), 1, "{edits:?}");
            assert_eq!(edits[0].new_text, expected);
            let updated = apply_edit(&content, &edits[0]);
            assert_eq!(updated, project_pin(&expected));

            let settled = CommentFixture::new(&updated, &v117_v120_tags(), "v1.120.0").await;
            assert!(settled.update_all().is_empty());
            assert!(
                settled
                    .diagnostics()
                    .await
                    .iter()
                    .all(|d| !d.message().contains("Newer version available"))
            );
        }

        #[tokio::test]
        async fn test_sha_pin_update_keeps_quoted_closing_delimiter() {
            let content = project_pin(&format!("\"{SHA_V117}\" # v1.117.0"));
            let fixture = CommentFixture::new(&content, &v117_v120_tags(), "v1.120.0").await;
            let edits = fixture.update_all();
            assert_eq!(edits.len(), 1, "{edits:?}");
            assert_eq!(
                apply_edit(&content, &edits[0]),
                project_pin(&format!("\"{SHA_V120}\" # v1.120.0"))
            );
        }

        #[tokio::test]
        async fn test_component_sha_pin_update_rewrites_trailing_comment() {
            let content =
                format!("include:\n  - component: gitlab.com/org/proj/comp@{SHA_V117} # 1.117.0\n");
            let fixture = CommentFixture::new(
                &content,
                &[("1.117.0", SHA_V117), ("1.120.0", SHA_V120)],
                "1.120.0",
            )
            .await;
            let edits = fixture.update_all();
            assert_eq!(edits.len(), 1, "{edits:?}");
            assert_eq!(
                apply_edit(&content, &edits[0]),
                format!("include:\n  - component: gitlab.com/org/proj/comp@{SHA_V120} # 1.120.0\n")
            );
        }

        /// A commentless plain pin gains the new tag's comment, as GitHub Actions pins do.
        #[tokio::test]
        async fn test_commentless_sha_pin_update_appends_comment() {
            let content = project_pin(SHA_V117);
            let fixture = CommentFixture::new(&content, &v117_v120_tags(), "v1.120.0").await;
            let edits = fixture.update_all();
            assert_eq!(edits.len(), 1, "{edits:?}");
            assert_eq!(
                apply_edit(&content, &edits[0]),
                project_pin(&format!("{SHA_V120} # v1.120.0"))
            );
        }

        /// A ref followed by flow content cannot take a comment: only the SHA is rewritten.
        #[tokio::test]
        async fn test_sha_pin_update_in_flow_mapping_never_appends_comment() {
            let content =
                format!("include:\n  - {{project: gitlab-org/cli, ref: {SHA_V117}, rules: []}}\n");
            let fixture = CommentFixture::new(&content, &v117_v120_tags(), "v1.120.0").await;
            let edits = fixture.update_all();
            assert_eq!(edits.len(), 1, "{edits:?}");
            assert_eq!(edits[0].new_text, SHA_V120);
        }

        /// A release name that is not version-shaped is never written as a comment, so the
        /// comments cannot pile up (`# stable # stable`) across repeated updates.
        #[tokio::test]
        async fn test_sha_pin_update_to_non_version_release_writes_no_comment() {
            let tags = [("v1.0.0", SHA_V117), ("stable", SHA_V120)];
            for ref_text in [format!("{SHA_V117} # v1.0.0"), SHA_V117.to_string()] {
                let content = project_pin(&ref_text);
                let fixture = CommentFixture::new(&content, &tags, "stable").await;
                let edits = fixture.update_all();
                assert_eq!(edits.len(), 1, "{ref_text}: {edits:?}");
                assert_eq!(edits[0].new_text, SHA_V120, "{ref_text}");
                let updated = apply_edit(&content, &edits[0]);
                assert_eq!(updated, project_pin(SHA_V120));

                let settled = CommentFixture::new(&updated, &tags, "stable").await;
                assert!(settled.update_all().is_empty(), "{ref_text}");
            }
        }

        /// Words after the tag stay inside a comment when the new release name is not a
        /// comment tag: `# v1.0.0 pinned for CVE` becomes `# pinned for CVE`, never
        /// `# stable # stable` or a bare `pinned for CVE` that would break the YAML.
        #[tokio::test]
        async fn test_sha_pin_update_to_non_version_release_keeps_trailing_words_in_comment() {
            let tags = [("v1.0.0", SHA_V117), ("stable", SHA_V120)];
            for (ref_text, expected) in [
                (
                    format!("{SHA_V117} # v1.0.0 pinned for CVE"),
                    format!("{SHA_V120} # pinned for CVE"),
                ),
                (
                    format!("\"{SHA_V117}\" # v1.0.0 pinned for CVE"),
                    format!("\"{SHA_V120}\" # pinned for CVE"),
                ),
            ] {
                let content = project_pin(&ref_text);
                let fixture = CommentFixture::new(&content, &tags, "stable").await;
                let edits = fixture.update_all();
                assert_eq!(edits.len(), 1, "{ref_text}: {edits:?}");
                let updated = apply_edit(&content, &edits[0]);
                assert_eq!(updated, project_pin(&expected), "{ref_text}");
                assert!(!updated.contains("# stable"), "{updated}");

                let settled = CommentFixture::new(&updated, &tags, "stable").await;
                assert!(settled.update_all().is_empty(), "{ref_text}");
            }
        }

        /// The latest tag is absent from the index: the rewrite falls back to the pin's own
        /// literal text, so the update never deletes the comment.
        #[tokio::test]
        async fn test_sha_pin_update_on_index_miss_keeps_comment() {
            let content = project_pin(&format!("{SHA_V117} # v1.117.0"));
            let fixture =
                CommentFixture::new(&content, &[("v1.117.0", SHA_V117)], "v1.120.0").await;
            assert!(fixture.update_all().is_empty());
        }

        /// A hand-written comment naming a different tag than the pinned commit's is flagged by
        /// both the `sha-comment-mismatch` diagnostic and a hover warning.
        #[tokio::test]
        async fn test_sha_comment_mismatch_diagnostic_and_hover() {
            let tags = [("v1.117.0", SHA_V117), ("v1.100.0", SHA_OTHER)];
            let content = project_pin(&format!("{SHA_V117} # v1.100.0"));
            let fixture = CommentFixture::new(&content, &tags, "v1.117.0").await;
            let mismatches: Vec<_> = fixture
                .diagnostics()
                .await
                .into_iter()
                .filter(|d| {
                    d.code() == Some(deps_core::lsp_helpers::SHA_COMMENT_MISMATCH_DIAGNOSTIC_CODE)
                })
                .collect();
            assert_eq!(mismatches.len(), 1, "{mismatches:?}");
            assert!(mismatches[0].message().contains("v1.117.0"));
            assert_eq!(mismatches[0].range.start.line, 2);

            let resolved = std::collections::HashMap::new();
            let hover = fixture
                .eco
                .generate_hover(
                    fixture.parse_result.as_ref(),
                    Position::new(2, 30),
                    deps_core::VersionData::new(&fixture.cached, &resolved)
                        .with_network(deps_core::NetworkMode::Offline),
                    deps_core::FreshnessSettings::default(),
                )
                .await
                .expect("hover");
            assert!(
                hover.markdown().contains("comment says"),
                "{}",
                hover.markdown()
            );
        }

        /// #1766: a `project:` tag pin that is a full release the complete Tags list lacks is
        /// reported; a partial shape (possibly a branch) and a listed tag are not.
        #[tokio::test]
        async fn test_unknown_ref_diagnostic_for_unpublished_full_release_only() {
            let codes = |ref_text: &str| {
                let content = project_pin(ref_text);
                async move {
                    let fixture =
                        CommentFixture::new(&content, &v117_v120_tags(), "v1.120.0").await;
                    fixture
                        .diagnostics()
                        .await
                        .into_iter()
                        .filter(|d| {
                            d.code() == Some(deps_core::lsp_helpers::UNKNOWN_REF_DIAGNOSTIC_CODE)
                        })
                        .collect::<Vec<_>>()
                }
            };

            let missing = codes("v1.119.0").await;
            assert_eq!(missing.len(), 1, "{missing:?}");
            assert_eq!(missing[0].severity, Some(Severity::Warning));
            assert!(
                missing[0]
                    .message()
                    .contains("`v1.119.0` is not a published tag")
            );
            assert_eq!(missing[0].range.start.line, 2);

            for silent in ["v1.120.0", "v1", "v40", "v1.119.0-working", "main"] {
                assert!(codes(silent).await.is_empty(), "{silent}");
            }
        }

        /// #1781: the quick fix rewrites a `project:` ref to the published spelling exactly where
        /// the unknown-ref diagnostic fires, and is withheld for an unmatched or partial ref.
        #[tokio::test]
        async fn test_unknown_ref_fix_rewrites_project_ref_to_published_tag() {
            let content = project_pin("1.120.0");
            let fixture = CommentFixture::new(&content, &v117_v120_tags(), "v1.120.0").await;
            let range = fixture.only_dep().version_range.unwrap();
            let action = fixture
                .unknown_ref_fix(range.start.line, range.start.character)
                .expect("1.120.0 has a published spelling");
            assert_eq!(action.title, "Change ref to published tag `v1.120.0`");
            let edit = &action
                .edit
                .unwrap()
                .changes
                .unwrap()
                .into_values()
                .next()
                .unwrap()[0];
            assert_eq!(apply_edit(&content, edit), project_pin("v1.120.0"));

            for silent in ["v1.119.0", "v1", "v1.120.0", "main"] {
                let content = project_pin(silent);
                let fixture = CommentFixture::new(&content, &v117_v120_tags(), "v1.120.0").await;
                let range = fixture.only_dep().version_range.unwrap();
                assert!(
                    fixture
                        .unknown_ref_fix(range.start.line, range.start.character)
                        .is_none(),
                    "{silent}"
                );
            }
        }

        /// #1766: a `component:` include is resolved through the Releases endpoint, which never
        /// proves a tag missing, so a version without a release is not reported.
        #[tokio::test]
        async fn test_unknown_ref_not_reported_for_component_include() {
            let content = "include:\n  - component: gitlab.com/org/proj/comp@1.119.0\n";
            let fixture = CommentFixture::new(content, &v117_v120_tags(), "v1.120.0").await;
            assert!(fixture.diagnostics().await.iter().all(|d| {
                d.code() != Some(deps_core::lsp_helpers::UNKNOWN_REF_DIAGNOSTIC_CODE)
            }));
        }

        /// #1766: `diagnostics.unknown_ref_severity` sets the diagnostic's severity.
        #[tokio::test]
        async fn test_unknown_ref_severity_override() {
            let content = project_pin("v1.119.0");
            let fixture = CommentFixture::new(&content, &v117_v120_tags(), "v1.120.0").await;
            let found: Vec<_> = fixture
                .diagnostics_with(
                    deps_core::lsp_helpers::DiagnosticSeverities::default()
                        .with_unknown_ref(Severity::Error),
                )
                .await
                .into_iter()
                .filter(|d| d.code() == Some(deps_core::lsp_helpers::UNKNOWN_REF_DIAGNOSTIC_CODE))
                .collect();
            assert_eq!(found.len(), 1, "{found:?}");
            assert_eq!(found[0].severity, Some(Severity::Error));
        }

        #[tokio::test]
        async fn test_matching_sha_comment_is_not_flagged() {
            let content = project_pin(&format!("{SHA_V117} # v1.117.0"));
            let fixture = CommentFixture::new(&content, &v117_v120_tags(), "v1.120.0").await;
            assert!(
                fixture.diagnostics().await.iter().all(|d| d.code()
                    != Some(deps_core::lsp_helpers::SHA_COMMENT_MISMATCH_DIAGNOSTIC_CODE))
            );
        }

        /// On a cold index the comment is trusted for the outdated verdict, and never flagged.
        #[tokio::test]
        async fn test_cold_index_trusts_sha_comment() {
            let outdated = project_pin(&format!("{SHA_V117} # v1.117.0"));
            let fixture = CommentFixture::new(&outdated, &[], "v1.120.0").await;
            let diagnostics = fixture.diagnostics().await;
            assert!(
                diagnostics
                    .iter()
                    .any(|d| d.message().contains("Newer version available")),
                "{diagnostics:?}"
            );
            assert!(
                diagnostics.iter().all(|d| d.code()
                    != Some(deps_core::lsp_helpers::SHA_COMMENT_MISMATCH_DIAGNOSTIC_CODE))
            );

            let current = project_pin(&format!("{SHA_V120} # v1.120.0"));
            let fixture = CommentFixture::new(&current, &[], "v1.120.0").await;
            assert!(
                fixture
                    .diagnostics()
                    .await
                    .iter()
                    .all(|d| !d.message().contains("Newer version available"))
            );
        }

        /// #1182: completion stays available while the cursor is in the SHA of a commented pin,
        /// and is withheld inside the trailing comment (project `ref:` and component `@sha`).
        #[tokio::test]
        async fn test_position_in_sha_comment_for_commented_pins() {
            let sha = "a".repeat(40);
            let eco = GitlabCiEcosystem::with_context(
                Arc::new(HttpCache::new()),
                Arc::new(deps_core::net_policy::RegistryAccessPolicy::default()),
                Arc::new(RwLock::new(Some("gitlab.com".to_string()))),
            );
            let uri = deps_core::test_util::test_uri("/repo/.gitlab-ci.yml");
            let manifests = [
                (
                    format!("include:\n  - project: org/proj\n    ref: {sha} # v1.0.0\n"),
                    2_u32,
                    9_u32,
                ),
                (
                    format!("include:\n  - component: gitlab.com/org/proj/comp@{sha} # 1.0.0\n"),
                    1,
                    40,
                ),
            ];
            for (content, line, sha_start) in manifests {
                let parsed = eco.parse_manifest(&content, &uri).await.unwrap();
                let dep = deps_core::ParseResult::dependencies(parsed.as_ref()).remove(0);
                let gl_dep = dep.as_any().downcast_ref::<GitlabCiDependency>().unwrap();
                let at = |column: u32| {
                    position_in_sha_comment(
                        gl_dep,
                        deps_core::position::Position::new(line, column),
                    )
                };
                assert!(!at(sha_start + 10), "{content}");
                assert!(!at(sha_start + 40), "{content}: cursor right after the SHA");
                assert!(at(sha_start + 43), "{content}");
                assert!(at(sha_start + 47), "{content}");
            }
        }

        #[tokio::test]
        async fn test_position_in_sha_comment_false_for_commentless_pin() {
            let sha = "a".repeat(40);
            let eco = GitlabCiEcosystem::with_context(
                Arc::new(HttpCache::new()),
                Arc::new(deps_core::net_policy::RegistryAccessPolicy::default()),
                Arc::new(RwLock::new(Some("gitlab.com".to_string()))),
            );
            let uri = deps_core::test_util::test_uri("/repo/.gitlab-ci.yml");
            let content = format!("include:\n  - project: org/proj\n    ref: {sha}\n");
            let parsed = eco.parse_manifest(&content, &uri).await.unwrap();
            let dep = deps_core::ParseResult::dependencies(parsed.as_ref()).remove(0);
            let gl_dep = dep.as_any().downcast_ref::<GitlabCiDependency>().unwrap();
            assert!(!position_in_sha_comment(
                gl_dep,
                deps_core::position::Position::new(2, 49)
            ));
        }

        /// #1182: the completion guard also covers a quoted pin, whose range ends after the
        /// closing quote and trailing comment.
        #[tokio::test]
        async fn test_position_in_sha_comment_for_quoted_pin() {
            let sha = "a".repeat(40);
            let eco = GitlabCiEcosystem::with_context(
                Arc::new(HttpCache::new()),
                Arc::new(deps_core::net_policy::RegistryAccessPolicy::default()),
                Arc::new(RwLock::new(Some("gitlab.com".to_string()))),
            );
            let uri = deps_core::test_util::test_uri("/repo/.gitlab-ci.yml");
            let content = format!("include:\n  - project: org/proj\n    ref: \"{sha}\" # v1.0.0\n");
            let parsed = eco.parse_manifest(&content, &uri).await.unwrap();
            let dep = deps_core::ParseResult::dependencies(parsed.as_ref()).remove(0);
            let gl_dep = dep.as_any().downcast_ref::<GitlabCiDependency>().unwrap();
            let at = |column: u32| {
                position_in_sha_comment(gl_dep, deps_core::position::Position::new(2, column))
            };
            assert!(!at(10 + 10));
            assert!(!at(10 + 40), "cursor right after the SHA");
            assert!(at(10 + 43));
            assert!(at(10 + 47));
        }

        fn one_tag(tag: &str) -> [(&str, &str); 1] {
            [(tag, SHA_V117)]
        }

        /// #1760: a plain literal tag ref gains the tag as a trailing comment, and the rewritten
        /// pin re-parses as a commented SHA pin whose comment the index confirms.
        #[tokio::test]
        async fn test_pin_plain_project_tag_appends_comment_and_round_trips() {
            let content = project_pin("v1.117.0");
            let fixture = CommentFixture::new(&content, &one_tag("v1.117.0"), "v1.117.0").await;
            let edits = fixture.pin_all();
            assert_eq!(edits.len(), 1, "{edits:?}");
            assert_eq!(edits[0].new_text, format!("{SHA_V117} # v1.117.0"));
            let action = fixture.pin_action(2, 12).expect("pin action");
            let changes = action.edit.unwrap().changes.unwrap();
            let action_edits = changes.values().next().unwrap();
            assert_eq!(action_edits[0].new_text, edits[0].new_text);

            let updated = apply_edit(&content, &edits[0]);
            let settled = CommentFixture::new(&updated, &one_tag("v1.117.0"), "v1.117.0").await;
            let dep = settled.only_dep();
            assert!(dep.sha_comment().is_some(), "{dep:?}");
            assert_eq!(
                settled.eco.formatter.sha_comment_check(&dep),
                Some(CommentCheck::Confirmed)
            );
        }

        /// #1760: a quoted ref cannot take a comment, so it gets the bare SHA and keeps its quotes.
        #[tokio::test]
        async fn test_pin_quoted_project_tag_writes_bare_sha() {
            let content = project_pin("\"v1.117.0\"");
            let fixture = CommentFixture::new(&content, &one_tag("v1.117.0"), "v1.117.0").await;
            let edits = fixture.pin_all();
            assert_eq!(edits.len(), 1, "{edits:?}");
            assert_eq!(edits[0].new_text, SHA_V117);
            assert_eq!(
                apply_edit(&content, &edits[0]),
                project_pin(&format!("\"{SHA_V117}\""))
            );
        }

        /// #1760: a flow-style ref gets the bare SHA and its neighbouring keys survive.
        #[tokio::test]
        async fn test_pin_flow_project_tag_writes_bare_sha_and_keeps_siblings() {
            let content = "include:\n  - {project: gitlab-org/cli, ref: v1.117.0, file: ci.yml}\n"
                .to_string();
            let fixture = CommentFixture::new(&content, &one_tag("v1.117.0"), "v1.117.0").await;
            let edits = fixture.pin_all();
            assert_eq!(edits.len(), 1, "{edits:?}");
            assert_eq!(
                apply_edit(&content, &edits[0]),
                format!(
                    "include:\n  - {{project: gitlab-org/cli, ref: {SHA_V117}, file: ci.yml}}\n"
                )
            );
        }

        /// #1760: a plain `component:` tag gets the release name as a comment.
        #[tokio::test]
        async fn test_pin_plain_component_tag_appends_comment() {
            let content = "include:\n  - component: gitlab.com/org/proj/comp@1.2.0\n".to_string();
            let fixture = CommentFixture::new(&content, &one_tag("1.2.0"), "1.2.0").await;
            let edits = fixture.pin_all();
            assert_eq!(edits.len(), 1, "{edits:?}");
            assert_eq!(
                apply_edit(&content, &edits[0]),
                format!("include:\n  - component: gitlab.com/org/proj/comp@{SHA_V117} # 1.2.0\n")
            );
        }

        /// #1760: an aliased ref is not an editable literal, so no pin action or edit exists.
        #[tokio::test]
        async fn test_pin_aliased_ref_offers_nothing() {
            let content =
                "x: &pin v1.117.0\ninclude:\n  - project: gitlab-org/cli\n    ref: *pin\n"
                    .to_string();
            let fixture = CommentFixture::new(&content, &one_tag("v1.117.0"), "v1.117.0").await;
            assert!(fixture.pin_all().is_empty());
            assert!(fixture.pin_action(3, 11).is_none());
        }

        /// #1760: `Latest`/`Partial` component pins go through the same rewrite as a tag pin.
        #[tokio::test]
        async fn test_pin_dynamic_component_pins_share_the_comment_rule() {
            for (version, quoted, expected) in [
                ("~latest", false, format!("{SHA_V117} # 1.2.0")),
                ("1.2", false, format!("{SHA_V117} # 1.2.0")),
                ("~latest", true, SHA_V117.to_string()),
            ] {
                let field = if quoted {
                    format!("\"gitlab.com/org/proj/comp@{version}\"")
                } else {
                    format!("gitlab.com/org/proj/comp@{version}")
                };
                let content = format!("include:\n  - component: {field}\n");
                let fixture = CommentFixture::new(&content, &one_tag("1.2.0"), "1.2.0").await;
                let edits = fixture.pin_all();
                assert_eq!(edits.len(), 1, "{version} {quoted}: {edits:?}");
                assert_eq!(edits[0].new_text, expected, "{version} {quoted}");
            }
        }

        const COMMENT_FIX_TAGS: [(&str, &str); 2] =
            [("v1.117.0", SHA_V117), ("v1.100.0", SHA_OTHER)];

        /// #1760: "Correct version comment" rewrites only the tag of a comment naming another tag.
        #[tokio::test]
        async fn test_correct_version_comment_action_on_other_tag() {
            let content = project_pin(&format!("{SHA_V117} # v1.100.0"));
            let fixture = CommentFixture::new(&content, &COMMENT_FIX_TAGS, "v1.117.0").await;
            let action = fixture.fix_action(2, 12).expect("fix action");
            assert_eq!(action.title, "Correct version comment to `v1.117.0`");
            let changes = action.edit.unwrap().changes.unwrap();
            let edit = &changes.values().next().unwrap()[0];
            assert_eq!(
                apply_edit(&content, edit),
                project_pin(&format!("{SHA_V117} # v1.117.0"))
            );
        }

        /// The fix action is offered for `ShaIsOtherTag` only: not for a confirmed comment, a
        /// missing comment, or a SHA the index does not know.
        #[tokio::test]
        async fn test_correct_version_comment_action_absent_for_other_states() {
            for ref_text in [
                format!("{SHA_V117} # v1.117.0"),
                SHA_V117.to_string(),
                format!("{SHA_V120} # v1.117.0"),
            ] {
                let content = project_pin(&ref_text);
                let fixture = CommentFixture::new(&content, &COMMENT_FIX_TAGS, "v1.117.0").await;
                assert!(fixture.fix_action(2, 12).is_none(), "{ref_text}");
            }
        }

        /// The comment's tag range is in UTF-16 columns even when non-ASCII text precedes it.
        #[tokio::test]
        async fn test_correct_version_comment_action_range_is_utf16() {
            let content = format!(
                "include:\n  - {{file: \"é.yml\", project: gitlab-org/cli, ref: {SHA_V117}}} # v1.100.0\n"
            );
            let fixture = CommentFixture::new(&content, &COMMENT_FIX_TAGS, "v1.117.0").await;
            let dep = fixture.only_dep();
            let comment = dep.sha_comment().expect("comment");
            let line: Vec<u16> = content.lines().nth(1).unwrap().encode_utf16().collect();
            let start = comment.tag_range.start.character as usize;
            let end = comment.tag_range.end.character as usize;
            assert_eq!(String::from_utf16(&line[start..end]).unwrap(), "v1.100.0");
        }
    }
}
