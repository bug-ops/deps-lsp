//! Ecosystem registration.
//!
//! [`EcosystemRuntime`] bundles the live-updatable settings every adapter threads into the
//! ecosystems that need them, and [`register_ecosystems`] wires every feature-enabled
//! `deps-<ecosystem>` crate into a [`deps_core::EcosystemRegistry`].
//!
//! Moved verbatim from `deps-lsp/src/lib.rs` (issue #1058) so `deps-cli`/`deps-mcp` share the
//! exact same registration instead of each maintaining an independent, non-uniform copy — see
//! `specs/062-cli-check-mode/architecture-decision.md` §5.2 for why per-adapter re-registration
//! was rejected.

use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use deps_core::policy_config::PolicyConfig;
use deps_core::{EcosystemRegistry, HttpCache};

/// Live-updatable settings [`register_ecosystems`] threads into every ecosystem that needs them.
///
/// Bundled into one struct (issue #561, M3) rather than growing that function's arity again
/// for each new cross-ecosystem live flag.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct EcosystemRuntime {
    /// Gates every workspace-declared registry index host (spec #443,
    /// `registries.workspace_registries`).
    pub policy: Arc<deps_core::net_policy::RegistryAccessPolicy>,
    /// `registries.nuget_user_profile_sources` (issue #561, FR-006) — whether a NuGet
    /// user-profile-tier `NuGet.Config` source with no repo-declared counterpart becomes a
    /// routing hop, not just a credential source. Default `false`.
    pub nuget_user_profile_sources: Arc<AtomicBool>,
    /// `registries.gitlab_instance_host` (issue #466, spec FR-005a/FR-011a) — the raw
    /// configured GitLab instance host string, or `None` when unset. A feature-agnostic
    /// `Arc<RwLock<Option<String>>>` (not a `deps-gitlab-ci` type) since this struct is
    /// un-`cfg`'d — see `deps_gitlab_ci::host::GitlabInstanceHost`'s docs for why host
    /// validation lives in that crate instead, applied on read.
    pub gitlab_instance_host: Arc<std::sync::RwLock<Option<String>>>,
}

impl EcosystemRuntime {
    /// Constructs the runtime from its three live-updatable settings handles.
    ///
    /// Needed because [`Self`] is `#[non_exhaustive]`: a struct literal only works inside
    /// this crate, so every other crate — including anything embedding [`register_ecosystems`],
    /// this module's advertised entry point — must use this constructor instead. Unlike some
    /// config-DTO builders elsewhere in this workspace (e.g. `deps_lsp::config::InlayHintsConfig::new`),
    /// all three fields are required here: none has a sensible default, so there is no
    /// accompanying `with_*` chain — a future field can still add one without breaking this
    /// signature.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::net_policy::RegistryAccessPolicy;
    /// use deps_engine::setup::EcosystemRuntime;
    /// use std::sync::atomic::AtomicBool;
    /// use std::sync::{Arc, RwLock};
    ///
    /// let runtime = EcosystemRuntime::new(
    ///     Arc::new(RegistryAccessPolicy::default()),
    ///     Arc::new(AtomicBool::new(false)),
    ///     Arc::new(RwLock::new(None)),
    /// );
    /// assert!(!runtime.nuget_user_profile_sources.load(std::sync::atomic::Ordering::Relaxed));
    /// ```
    #[must_use]
    pub fn new(
        policy: Arc<deps_core::net_policy::RegistryAccessPolicy>,
        nuget_user_profile_sources: Arc<AtomicBool>,
        gitlab_instance_host: Arc<std::sync::RwLock<Option<String>>>,
    ) -> Self {
        Self {
            policy,
            nuget_user_profile_sources,
            gitlab_instance_host,
        }
    }

    /// Builds the runtime's three live-updatable handles from a [`PolicyConfig`] snapshot.
    ///
    /// Construction only — this does not touch any adapter-side state (e.g. `deps-lsp`'s
    /// `ServerState::cache`/`cold_start_limiter`, or its
    /// `warn_if_gitlab_instance_host_invalid` notification call): those remain the caller's
    /// responsibility, since they carry their own ordering constraints relative to the
    /// adapter's own config-reload lifecycle (issue #1058; see
    /// `specs/062-cli-check-mode/architecture-decision.md` §8, PR 1b-ii).
    ///
    /// The three values themselves come from
    /// [`RegistriesConfig::resolve`](deps_core::policy_config::RegistriesConfig::resolve),
    /// shared with `deps-lsp`'s `initialize`/`did_change_configuration` config-reload sites so
    /// this derivation exists in exactly one place (issue #1058, T009).
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::policy_config::PolicyConfig;
    /// use deps_engine::setup::EcosystemRuntime;
    ///
    /// let runtime = EcosystemRuntime::from_policy(&PolicyConfig::default());
    /// assert!(!runtime.nuget_user_profile_sources.load(std::sync::atomic::Ordering::Relaxed));
    /// ```
    #[must_use]
    pub fn from_policy(policy: &PolicyConfig) -> Self {
        let resolved = policy.registries.resolve();
        Self::new(
            Arc::new(deps_core::net_policy::RegistryAccessPolicy::new(
                resolved.workspace_registries,
            )),
            Arc::new(AtomicBool::new(resolved.nuget_user_profile_sources)),
            Arc::new(std::sync::RwLock::new(resolved.gitlab_instance_host)),
        )
    }
}

/// Validates a `registries.gitlab_instance_host` value against the live registry-access
/// policy, without the caller needing to name `deps_gitlab_ci` directly.
///
/// Exists so `deps-lsp` (and any future adapter) can validate this value while depending only
/// on `deps-engine` — per `specs/062-cli-check-mode/architecture-decision.md` §3.3's placement
/// rule, code that must name a concrete ecosystem type belongs in `deps-engine`, not in an
/// adapter crate.
///
/// # Errors
///
/// Returns [`deps_core::net_policy::IndexUrlError`] under the same conditions as
/// [`deps_gitlab_ci::GitlabHost::parse`] — `raw` contains a URL-structural character, fails to
/// parse, is not `https`-eligible, carries userinfo, round-trips to a different host, or
/// resolves to a [`deps_core::net_policy::HostClass`] the current policy blocks.
///
/// # Examples
///
/// ```
/// use deps_core::net_policy::{RegistryAccessPolicy, WorkspaceRegistryAccess};
/// use deps_engine::setup::validate_gitlab_instance_host;
///
/// let policy = RegistryAccessPolicy::new(WorkspaceRegistryAccess::PublicOnly);
/// assert!(validate_gitlab_instance_host("gitlab.com", &policy).is_ok());
/// assert!(validate_gitlab_instance_host("gitlab.com/evil", &policy).is_err());
/// ```
#[cfg(feature = "gitlab-ci")]
pub fn validate_gitlab_instance_host(
    raw: &str,
    policy: &deps_core::net_policy::RegistryAccessPolicy,
) -> Result<(), deps_core::net_policy::IndexUrlError> {
    deps_gitlab_ci::GitlabHost::parse(raw, policy).map(|_| ())
}

/// Declares an ecosystem: re-exports types and registers at runtime.
///
/// `$types` re-export rule (#834 §6 last bullet — the list used to be asymmetric with no
/// stated rule: `*Formatter` re-exported for 8/14 ecosystems, `*LockParser` for 4/14,
/// `*Registry` for 13/14): **always list every `*Registry`/`*Formatter`/`*LockParser`
/// (or ecosystem-specific-named lock parser, e.g. `GoSumParser`) type the ecosystem crate
/// actually defines and re-exports from its own crate root.** Omit only when the crate
/// genuinely has none — e.g. `deps-gradle` has no `GradleRegistry` (reuses
/// `deps_maven::MavenCentralRegistry` directly), and several ecosystems omit a
/// `*LockParser` entry because the crate has no `lockfile` module at all (Maven, Gradle,
/// GitHub Actions, GitLab CI — no lock file format exists for these; Deno — `deno.lock`
/// exists as a format, but this crate has no parser for it yet, a real coverage gap rather
/// than "no format" like the other four).
macro_rules! ecosystem {
    ($feature:literal, $crate_name:ident, $ecosystem:ident, [$($types:ident),* $(,)?]) => {
        #[cfg(feature = $feature)]
        pub use $crate_name::{$ecosystem, $($types),*};
    };
}

/// Registers ecosystem if feature is enabled.
macro_rules! register {
    ($feature:literal, $ecosystem:ident, $registry:expr, $cache:expr) => {
        #[cfg(feature = $feature)]
        $registry.register(Arc::new($ecosystem::new(Arc::clone($cache))));
    };
}

// =============================================================================
// Ecosystems — to add new: 1) feature in Cargo.toml  2) add ecosystem!() + register!()
// =============================================================================

ecosystem!(
    "cargo",
    deps_cargo,
    CargoEcosystem,
    [
        CargoDependency,
        CargoDependencySection,
        CargoFormatter,
        CargoLockParser,
        CargoParseResult,
        CargoParser,
        CargoRegistry,
        CargoVersion,
        CrateInfo,
        CratesIoRegistry,
        parse_cargo_toml,
    ]
);

ecosystem!(
    "npm",
    deps_npm,
    NpmEcosystem,
    [
        NpmDependency,
        NpmDependencySection,
        NpmFormatter,
        NpmLockParser,
        NpmPackage,
        NpmParseResult,
        NpmRegistry,
        NpmVersion,
        parse_package_json,
    ]
);

ecosystem!(
    "pypi",
    deps_pypi,
    PypiEcosystem,
    [
        PypiDependency,
        PypiDependencySection,
        PypiFormatter,
        PypiLockParser,
        PypiParser,
        PypiRegistry,
        PypiVersion,
    ]
);

ecosystem!(
    "go",
    deps_go,
    GoEcosystem,
    [
        GoDependency,
        GoDirective,
        GoFormatter,
        GoParseResult,
        GoRegistry,
        GoSumParser,
        GoVersion,
        parse_go_mod,
    ]
);

ecosystem!(
    "bundler",
    deps_bundler,
    BundlerEcosystem,
    [
        BundlerDependency,
        BundlerFormatter,
        BundlerParseResult,
        BundlerVersion,
        DependencyGroup,
        GemInfo,
        GemfileLockParser,
        RubyGemsRegistry,
        parse_gemfile,
    ]
);

ecosystem!(
    "dart",
    deps_dart,
    DartEcosystem,
    [
        DartDependency,
        DartParseResult,
        DartVersion,
        DartFormatter,
        PackageInfo,
        PubDevRegistry,
        PubspecLockParser,
        parse_pubspec_yaml,
    ]
);

ecosystem!(
    "maven",
    deps_maven,
    MavenEcosystem,
    [
        MavenDependency,
        MavenParseResult,
        MavenVersion,
        MavenFormatter,
        ArtifactInfo,
        MavenCentralRegistry,
        parse_pom_xml,
    ]
);

ecosystem!(
    "gradle",
    deps_gradle,
    GradleEcosystem,
    [
        GradleDependency,
        GradleParseResult,
        GradleVersion,
        GradleFormatter,
        parse_gradle,
    ]
);

ecosystem!(
    "swift",
    deps_swift,
    SwiftEcosystem,
    [
        SwiftDependency,
        SwiftParseResult,
        SwiftVersion,
        SwiftPackage,
        SwiftFormatter,
        SwiftRegistry,
        SwiftLockParser,
        parse_package_swift,
    ]
);

ecosystem!(
    "composer",
    deps_composer,
    ComposerEcosystem,
    [
        ComposerDependency,
        ComposerFormatter,
        ComposerLockParser,
        ComposerSection,
        ComposerPackage,
        ComposerParseResult,
        PackagistRegistry,
        ComposerVersion,
        parse_composer_json,
    ]
);

// Note: `PackageInfo` is deliberately omitted from this re-export list — it collides with
// `deps_dart::PackageInfo`, already re-exported above. Reachable directly as
// `deps_nuget::PackageInfo` for anything that needs it.
ecosystem!(
    "nuget",
    deps_nuget,
    NuGetEcosystem,
    [
        NuGetDependency,
        NuGetParseResult,
        NuGetVersion,
        NuGetFormatter,
        NuGetRegistry,
        NuGetLockParser,
        parse_project_file,
    ]
);

ecosystem!(
    "deno",
    deps_deno,
    DenoEcosystem,
    [
        DenoDependency,
        DenoDependencySection,
        DenoFormatter,
        DenoMetadata,
        DenoParseResult,
        DenoRegistry,
        JsrPackage,
        JsrRegistry,
        JsrVersion,
        parse_deno_json,
    ]
);

ecosystem!(
    "github-actions",
    deps_github_actions,
    GithubActionsEcosystem,
    [
        GithubActionsDependency,
        GithubActionsFormatter,
        GithubActionsParseResult,
        GithubActionsRegistry,
        GithubActionsVersion,
        parse_workflow_yaml,
    ]
);

ecosystem!(
    "gitlab-ci",
    deps_gitlab_ci,
    GitlabCiEcosystem,
    [
        GitlabCiDependency,
        GitlabCiFormatter,
        GitlabCiParseResult,
        GitlabCiRegistry,
        GitlabCiVersion,
        parse_gitlab_ci_yaml,
    ]
);

/// Registers all enabled ecosystems.
///
/// `cargo` is special-cased (spec #443/#441, plan-1b §1.6): unlike `register!`'s generic
/// `Ecosystem::new(cache)` call, `CargoEcosystem` needs `policy` threaded through
/// `CargoEcosystem::with_context` so the calling adapter's live-updatable
/// `Arc<RegistryAccessPolicy>` (e.g. `deps-lsp`'s `document::state::ServerState::registry_policy`)
/// is the exact same handle every Cargo parse reads — the adapter updating it then takes
/// effect immediately, with no need to reconstruct the ecosystem.
///
/// `npm` and `deno` are special-cased (#312): when both features are enabled, they share
/// one `NpmRegistry` instance — built once here and handed to both `NpmEcosystem` and
/// `DenoEcosystem`'s `npm:`-scheme half via `with_registry`/`with_npm` — instead of each
/// constructing its own. `NpmRegistry` is cheaply `Clone` (its `HttpCache` and
/// freshness-path publish-time map are both `Arc`-wrapped internally), so this dedupes the
/// freshness path's full-packument fetch and its publish-time cache for a package
/// appearing in both `package.json` and a `deno.json` `npm:`-specifier dependency, on top
/// of the plain cached GETs the shared `cache` already dedupes.
/// Returns every ecosystem id this call threaded the live `RegistryAccessPolicy` handle
/// into (issue #592 security M1) — the single source of truth `deps_lsp::config::reparse_scope`'s
/// caller consults to scope a `registries.workspace_registries` reparse, so that set can
/// never drift from what this function actually wires up. Adding a 6th policy-consuming
/// ecosystem means editing this function anyway (to thread `policy` through its parse
/// context); pushing its id onto the returned list at that same call site keeps the two
/// facts — "receives the policy" and "is in the reparse scope" — physically inseparable,
/// rather than duplicated across two independently-editable places.
///
/// # Examples
///
/// ```
/// use deps_core::policy_config::PolicyConfig;
/// use deps_core::{EcosystemRegistry, HttpCache};
/// use deps_engine::setup::{EcosystemRuntime, register_ecosystems};
/// use std::sync::Arc;
///
/// let registry = EcosystemRegistry::new();
/// let cache = Arc::new(HttpCache::new());
/// let runtime = EcosystemRuntime::from_policy(&PolicyConfig::default());
/// let workspace_registry_ecosystems = register_ecosystems(&registry, cache, &runtime);
///
/// // Every id this call reports as policy-consuming is actually registered.
/// for id in &workspace_registry_ecosystems {
///     assert!(registry.get(id).is_some());
/// }
/// ```
pub fn register_ecosystems(
    registry: &EcosystemRegistry,
    cache: Arc<HttpCache>,
    runtime: &EcosystemRuntime,
) -> Vec<&'static str> {
    let policy = Arc::clone(&runtime.policy);
    // Keeps `policy` used even when none of its consumers (cargo, npm, pypi, go, nuget,
    // gitlab-ci) are compiled in.
    let _ = &policy;
    // Keeps `registry`/`cache` used even when every ecosystem feature is compiled out.
    let _ = (&registry, &cache);
    let mut workspace_registry_ecosystems = Vec::new();
    // Keeps `mut` used even when none of the five features that push into this vec below
    // (cargo, npm, pypi, go, nuget) are enabled.
    let _ = &mut workspace_registry_ecosystems;

    #[cfg(feature = "cargo")]
    {
        let context = deps_cargo::parser::CargoParseContext::new(
            Arc::clone(&policy),
            Arc::new(deps_cargo::config::ConfigFileCache::new()),
        );
        registry.register(Arc::new(CargoEcosystem::with_context(
            Arc::clone(&cache),
            context,
        )));
        workspace_registry_ecosystems.push("cargo");
    }

    #[cfg(all(feature = "npm", feature = "deno"))]
    {
        let npm_context = deps_npm::config::NpmParseContext::new(
            Arc::clone(&policy),
            Arc::new(deps_npm::config::NpmConfigCache::new()),
            Arc::new(deps_npm::catalog::PnpmWorkspaceCache::new()),
        );
        let npm_registry = Arc::new(NpmRegistry::new(Arc::clone(&cache)));
        registry.register(Arc::new(NpmEcosystem::with_context(
            Arc::clone(&npm_registry),
            npm_context,
        )));
        workspace_registry_ecosystems.push("npm");
        // `DenoEcosystem::with_npm` shares the registry above but is never handed `policy`
        // itself (its own `.npmrc`-style workspace registry concept doesn't exist yet), so
        // "deno" deliberately never joins this list.
        registry.register(Arc::new(DenoEcosystem::with_npm(
            Arc::clone(&cache),
            npm_registry.as_ref().clone(),
        )));
    }
    // npm is written out explicitly rather than via `register!` (spec 032, S3): that macro's
    // `NpmEcosystem::new(cache)` would give npm a default, disconnected `NpmParseContext` —
    // its `.npmrc` reachability policy would never see a live `initialize`/
    // `didChangeConfiguration` update.
    #[cfg(all(feature = "npm", not(feature = "deno")))]
    {
        let npm_context = deps_npm::config::NpmParseContext::new(
            Arc::clone(&policy),
            Arc::new(deps_npm::config::NpmConfigCache::new()),
            Arc::new(deps_npm::catalog::PnpmWorkspaceCache::new()),
        );
        registry.register(Arc::new(NpmEcosystem::with_context(
            Arc::new(NpmRegistry::new(Arc::clone(&cache))),
            npm_context,
        )));
        workspace_registry_ecosystems.push("npm");
    }
    #[cfg(all(feature = "deno", not(feature = "npm")))]
    register!("deno", DenoEcosystem, registry, &cache);

    // pypi is written out explicitly rather than via `register!` (spec 033, mirroring npm's
    // spec 032 S3 precedent): that macro's `PypiEcosystem::new(cache)` would give pypi a
    // default, disconnected `RegistryAccessPolicy` — its private-index reachability policy
    // would never see a live `initialize`/`didChangeConfiguration` update.
    #[cfg(feature = "pypi")]
    {
        registry.register(Arc::new(PypiEcosystem::with_policy(
            Arc::new(PypiRegistry::new(Arc::clone(&cache))),
            Arc::clone(&policy),
        )));
        workspace_registry_ecosystems.push("pypi");
    }

    // go is written out explicitly rather than via `register!` (spec 034, mirroring npm's
    // spec 032 S3 precedent): that macro's `GoEcosystem::new(cache)` would give Go a
    // default, disconnected `GoParseContext` — its `$GOENV` reachability policy would never
    // see a live `initialize`/`didChangeConfiguration` update.
    #[cfg(feature = "go")]
    {
        let go_context = deps_go::config::GoParseContext::new(
            Arc::clone(&policy),
            Arc::new(deps_go::config::GoEnvCache::new()),
            deps_go::config::goenv_path(),
        );
        registry.register(Arc::new(GoEcosystem::with_context(
            Arc::new(GoRegistry::new(Arc::clone(&cache))),
            go_context,
        )));
        workspace_registry_ecosystems.push("go");
    }
    register!("bundler", BundlerEcosystem, registry, &cache);
    register!("dart", DartEcosystem, registry, &cache);
    register!("maven", MavenEcosystem, registry, &cache);
    register!("gradle", GradleEcosystem, registry, &cache);
    register!("swift", SwiftEcosystem, registry, &cache);
    register!("composer", ComposerEcosystem, registry, &cache);

    // nuget is written out explicitly rather than via `register!` (issue #523, mirroring
    // npm's/pypi's identical precedent): that macro's `NuGetEcosystem::new(cache)` would give
    // nuget a default, disconnected `RegistryAccessPolicy` — its private-feed reachability
    // policy would never see a live `initialize`/`didChangeConfiguration` update.
    #[cfg(feature = "nuget")]
    {
        let nuget_context = deps_nuget::config::NuGetParseContext::new(
            Arc::clone(&policy),
            Arc::new(deps_nuget::config::NuGetConfigCache::new()),
            Arc::clone(&runtime.nuget_user_profile_sources),
        );
        registry.register(Arc::new(NuGetEcosystem::with_context(
            Arc::new(NuGetRegistry::new(Arc::clone(&cache))),
            nuget_context,
        )));
        workspace_registry_ecosystems.push("nuget");
    }

    register!("github-actions", GithubActionsEcosystem, registry, &cache);

    // gitlab-ci is written out explicitly rather than via `register!` (issue #466, mirroring
    // github-actions'/nuget's identical precedent): that macro's `GitlabCiEcosystem::new(cache)`
    // would give it a default, disconnected `registries.gitlab_instance_host` — its
    // self-hosted-instance resolution and the single token-host rule (spec FR-005a/FR-011a)
    // would never see a live `initialize`/`didChangeConfiguration` update.
    #[cfg(feature = "gitlab-ci")]
    registry.register(Arc::new(GitlabCiEcosystem::with_context(
        Arc::clone(&cache),
        Arc::clone(&policy),
        Arc::clone(&runtime.gitlab_instance_host),
    )));

    workspace_registry_ecosystems
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_runtime() -> EcosystemRuntime {
        EcosystemRuntime::new(
            Arc::new(deps_core::net_policy::RegistryAccessPolicy::default()),
            Arc::new(AtomicBool::new(false)),
            Arc::new(std::sync::RwLock::new(None)),
        )
    }

    /// The doctest on [`EcosystemRuntime::from_policy`] only exercises `PolicyConfig::default()`
    /// (empty `gitlab_instance_host` -> `None`, `nuget_user_profile_sources` -> `false`). This
    /// covers its other branches: a non-empty `gitlab_instance_host`, `nuget_user_profile_sources
    /// = true`, and a non-default `workspace_registries` setting.
    #[test]
    fn test_from_policy_non_default_branches() {
        use deps_core::net_policy::WorkspaceRegistryAccess;
        use deps_core::policy_config::{
            PolicyConfig, RegistriesConfig, WorkspaceRegistriesSetting,
        };

        let policy = PolicyConfig {
            registries: RegistriesConfig::new()
                .with_workspace_registries(WorkspaceRegistriesSetting::All)
                .with_nuget_user_profile_sources(true)
                .with_gitlab_instance_host("gitlab.corp"),
            ..PolicyConfig::default()
        };

        let runtime = EcosystemRuntime::from_policy(&policy);

        assert_eq!(runtime.policy.get(), WorkspaceRegistryAccess::All);
        assert!(
            runtime
                .nuget_user_profile_sources
                .load(std::sync::atomic::Ordering::Relaxed)
        );
        assert_eq!(
            runtime
                .gitlab_instance_host
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_deref(),
            Some("gitlab.corp")
        );
    }

    /// Direct `cargo nextest` coverage for [`validate_gitlab_instance_host`] — its doctest
    /// exercises the same two cases inline, but only as a doctest (tester finding, issue
    /// #1073). Also checks the rejected-host error never leaks the raw credential, mirroring
    /// `deps-lsp`'s `test_gitlab_instance_host_invalid_message_redacts_credential`, since
    /// [`deps_core::net_policy::IndexUrlError::InvalidUrl`] wraps an already-redacted
    /// [`deps_core::net_policy::RedactedUrl`].
    #[cfg(feature = "gitlab-ci")]
    #[test]
    fn test_validate_gitlab_instance_host_accepts_valid_rejects_invalid() {
        use deps_core::net_policy::{RegistryAccessPolicy, WorkspaceRegistryAccess};

        let policy = RegistryAccessPolicy::new(WorkspaceRegistryAccess::PublicOnly);

        assert!(validate_gitlab_instance_host("gitlab.com", &policy).is_ok());

        let raw = "user:hunter2@gitlab.corp";
        let error = validate_gitlab_instance_host(raw, &policy)
            .expect_err("credential-shaped host must be rejected");
        assert!(
            !error.to_string().contains("hunter2"),
            "rejected-host error must not leak the raw credential: {error}"
        );
    }

    /// Smoke test: `register_ecosystems` must not panic under any feature combination.
    /// Per-ecosystem "is it actually registered" coverage moved to
    /// [`test_ecosystem_id_all_registered`] (#758) — driven by
    /// [`deps_core::EcosystemId::ALL`] instead of this hand-written, drift-prone 14-line list.
    #[test]
    fn test_register_ecosystems() {
        let registry = Arc::new(EcosystemRegistry::new());
        let cache = Arc::new(HttpCache::new());
        register_ecosystems(&registry, Arc::clone(&cache), &test_runtime());
    }

    /// Issue #592 security M1: every id `register_ecosystems` returns must actually be a
    /// registered ecosystem (catches a typo'd `push` literal) and, for this feature set,
    /// must exactly match the five ecosystems known to thread `RegistryAccessPolicy` through
    /// their parse context — a regression here means either a policy-consuming ecosystem
    /// was added without pushing its id (fails closed for `deps_lsp::config::reparse_scope`), or
    /// an id was pushed for an ecosystem that no longer receives the policy (harmless
    /// over-scoping, but signals the two facts drifted anyway).
    #[test]
    #[allow(
        clippy::vec_init_then_push,
        reason = "each push is independently feature-gated, so a `vec![]` literal can't \
                  express the feature-conditional membership"
    )]
    fn test_register_ecosystems_workspace_registry_list_matches_registered_ecosystems() {
        let registry = Arc::new(EcosystemRegistry::new());
        let cache = Arc::new(HttpCache::new());
        let workspace_registry_ecosystems =
            register_ecosystems(&registry, Arc::clone(&cache), &test_runtime());

        for id in &workspace_registry_ecosystems {
            assert!(
                registry.get(id).is_some(),
                "{id:?} was returned as policy-consuming but is not a registered ecosystem"
            );
        }

        let mut expected: Vec<&str> = Vec::new();
        #[cfg(feature = "cargo")]
        expected.push("cargo");
        #[cfg(feature = "npm")]
        expected.push("npm");
        #[cfg(feature = "pypi")]
        expected.push("pypi");
        #[cfg(feature = "go")]
        expected.push("go");
        #[cfg(feature = "nuget")]
        expected.push("nuget");
        expected.sort_unstable();
        let mut actual = workspace_registry_ecosystems.clone();
        actual.sort_unstable();
        assert_eq!(
            actual, expected,
            "workspace-registry-policy ecosystem set changed — update this test's `expected` \
             list alongside whatever registration change caused it"
        );
    }

    /// Layer 1a (#758): completeness — every [`deps_core::EcosystemId::ALL`] variant must
    /// actually be registered by [`register_ecosystems`]. Driven by `ALL` itself, not
    /// `registry.ecosystem_ids()`, so an ecosystem declared in the enum but never wired in
    /// fails this test instead of silently vanishing from coverage.
    ///
    /// Gated on every ecosystem feature at once: `ALL` always lists 14 variants regardless of
    /// which features are enabled for this build, so this specific claim — "all 14 are
    /// present" — is only meaningful, and only makes sense to check, in an all-features build.
    /// The per-ecosystem invariants that don't depend on all 14 being present live in the
    /// ungated [`test_registered_ecosystems_universal_invariants`] instead (#758 impl-critic
    /// S2): unlike this completeness check, those must keep working under any feature subset,
    /// the way the two hand-written per-feature lists this pair replaces used to.
    #[cfg(all(
        feature = "cargo",
        feature = "npm",
        feature = "pypi",
        feature = "go",
        feature = "bundler",
        feature = "dart",
        feature = "maven",
        feature = "gradle",
        feature = "swift",
        feature = "composer",
        feature = "nuget",
        feature = "deno",
        feature = "github-actions",
        feature = "gitlab-ci"
    ))]
    #[test]
    fn test_ecosystem_id_all_registered() {
        let registry = Arc::new(EcosystemRegistry::new());
        let cache = Arc::new(HttpCache::new());
        register_ecosystems(&registry, Arc::clone(&cache), &test_runtime());

        for id in deps_core::EcosystemId::ALL {
            assert!(
                registry.get(id.id()).is_some(),
                "{id:?} is in EcosystemId::ALL but was not registered by register_ecosystems"
            );
        }
    }

    /// Layer 1b (#758): universal, offline invariants every ecosystem this build actually
    /// registers must satisfy. Deliberately **ungated** — unlike
    /// [`test_ecosystem_id_all_registered`]'s completeness claim, none of these invariants
    /// depend on all 14 ecosystems being present, so this iterates whatever
    /// `registry.ecosystem_ids()` this build's feature set produced (#758 impl-critic S2):
    /// under `--no-default-features --features npm`, it still covers `npm` alone; under the
    /// default (all 14) build, it covers all 14, same as before the split.
    ///
    /// Per ecosystem: id round-trip; `display_name()` non-empty and unique across the set; at
    /// least one routing surface non-empty; `lockfile_filenames().is_empty() ==
    /// lockfile_provider().is_none()`; `package_url` hostile-input safety (display sink only —
    /// see `deps_core::conformance`'s doc for the display-vs-fetch sink split; does **not**
    /// prove the URL is non-degenerate, that is `formatter_conformance!`'s job per ecosystem);
    /// `completion_insert_text` does not panic.
    #[test]
    fn test_registered_ecosystems_universal_invariants() {
        let registry = Arc::new(EcosystemRegistry::new());
        let cache = Arc::new(HttpCache::new());
        register_ecosystems(&registry, Arc::clone(&cache), &test_runtime());

        let mut display_names = std::collections::HashSet::new();

        for id in registry.ecosystem_ids() {
            let ecosystem = registry
                .get(id)
                .unwrap_or_else(|| panic!("{id:?} came from registry.ecosystem_ids() itself"));

            let parsed_id: deps_core::EcosystemId = id.parse().unwrap_or_else(|_| {
                panic!("{id:?} has no matching EcosystemId variant (see issue #118)")
            });
            assert_eq!(
                parsed_id.id(),
                id,
                "{id:?}: EcosystemId round-trip mismatch"
            );
            assert_eq!(ecosystem.id(), id, "{id:?}: Ecosystem::id() mismatch");

            let display_name = ecosystem.display_name();
            assert!(!display_name.is_empty(), "{id:?} has an empty display_name");
            assert!(
                display_names.insert(display_name),
                "{id:?}'s display_name {display_name:?} collides with another ecosystem's"
            );

            assert!(
                !ecosystem.manifest_filenames().is_empty()
                    || !ecosystem.manifest_patterns().is_empty()
                    || !ecosystem.manifest_extensions().is_empty()
                    || !ecosystem.manifest_directory_patterns().is_empty(),
                "{id:?} has no routing surface at all (manifest_filenames/patterns/extensions/directory_patterns)"
            );

            assert_eq!(
                ecosystem.lockfile_filenames().is_empty(),
                ecosystem.lockfile_provider().is_none(),
                "{id:?}: lockfile_filenames()/lockfile_provider() disagree on whether a lock file format exists"
            );

            // Hostile-input safety for the `package_url` *display* sink
            // (`lsp_helpers::hover`'s `# [{name}]({url})`, destination written raw — see
            // `HOSTILE_DISPLAY_LINK_PAYLOAD`'s doc for the full sink/hazard rationale, #758
            // security-review). Shared with `formatter_conformance!`'s own unconditional
            // per-crate check (#782 gap 1) — see `conformance::assert_package_url_hostile_input_safe`'s
            // doc for why both layers call the same implementation.
            deps_core::conformance::assert_package_url_hostile_input_safe(
                ecosystem.formatter(),
                &format!("{id:?}"),
            );

            let metadata = deps_core::test_util::MockMetadata::new("conformance-probe", "1.0.0");
            let _ = ecosystem.completion_insert_text(&metadata);
        }
    }

    /// CRITICAL regression (issue #706 review): GitHub Actions' `action.yml`/`action.yaml`
    /// bare-basename routing and GitLab CI's `.gitlab/ci/*.yml` directory-pattern routing
    /// can both match `.gitlab/ci/action.yml` — before `EcosystemRegistry::for_uri`'s
    /// fix (deps-core), the basename match was checked first and always won, silently
    /// routing a real GitLab CI file to `github-actions` (which would then, on top of
    /// that, degrade it to zero dependencies since it lacks a top-level `runs:` key —
    /// total, silent loss of hover/diagnostics/completions for the file). Exercises the
    /// real production registry both real ecosystem crates are wired into, not a mock.
    #[cfg(all(feature = "github-actions", feature = "gitlab-ci"))]
    #[test]
    fn test_gitlab_ci_directory_pattern_wins_over_github_actions_basename_match() {
        let registry = Arc::new(EcosystemRegistry::new());
        let cache = Arc::new(HttpCache::new());
        register_ecosystems(&registry, Arc::clone(&cache), &test_runtime());

        let uri = deps_core::test_util::test_uri("/repo/.gitlab/ci/action.yml");
        assert_eq!(
            registry.for_uri(&uri).map(|e| e.id()),
            Some(deps_core::EcosystemId::GitlabCi.id()),
            "a real .gitlab/ci/action.yml file must route to gitlab-ci, not github-actions"
        );

        // Non-conflicting action.yml locations must be unaffected.
        let root_action = deps_core::test_util::test_uri("/repo/action.yml");
        assert_eq!(
            registry.for_uri(&root_action).map(|e| e.id()),
            Some(deps_core::EcosystemId::GithubActions.id())
        );
        let nested_action =
            deps_core::test_util::test_uri("/repo/.github/actions/my-action/action.yml");
        assert_eq!(
            registry.for_uri(&nested_action).map(|e| e.id()),
            Some(deps_core::EcosystemId::GithubActions.id())
        );
    }

    /// Whether `formatter`'s own comparator (preferring
    /// [`deps_core::lsp_helpers::RequirementResolution::compile_requirement`], falling back to
    /// [`deps_core::lsp_helpers::RequirementResolution::version_satisfies_requirement`] when it
    /// declines to compile) treats a bare `requirement` as an exact pin: it must match
    /// `requirement` itself but reject both a higher patch (`"1.2.9"`) and a higher
    /// minor/major (`"9.9.9"`) — the same "matches only this one version" shape
    /// [`deps_core::lsp_helpers::concrete_pin_version`] asserts. Also correctly says `false`
    /// for a genuine partial-version range (e.g. `"1.2"`), since that legitimately matches
    /// more than one candidate.
    #[cfg(any(
        feature = "cargo",
        feature = "npm",
        feature = "go",
        feature = "bundler",
        feature = "dart",
        feature = "maven",
        feature = "composer",
        feature = "gradle",
        feature = "nuget",
        feature = "deno",
        feature = "github-actions",
        feature = "gitlab-ci",
        feature = "swift",
        feature = "pypi"
    ))]
    fn formatter_treats_bare_version_as_exact_pin(
        formatter: &dyn deps_core::lsp_helpers::EcosystemFormatter,
        bare: &str,
    ) -> bool {
        use deps_core::{ConcreteVersion, VersionReq};

        let requirement = VersionReq::new(bare);
        let matches = |candidate: &str| -> bool {
            let version = ConcreteVersion::from(candidate);
            if let Some(matcher) = formatter.compile_requirement(&requirement) {
                matcher.matches(&version) == Some(true)
            } else {
                formatter.version_satisfies_requirement(&version, bare)
            }
        };

        matches(bare) && !matches("9.9.9") && !matches("1.2.9")
    }

    /// How a given ecosystem's bare-version-is-a-pin verdict relates to its own formatter's
    /// comparator — see [`bare_version_agreement_expectation`].
    #[cfg(any(
        feature = "cargo",
        feature = "npm",
        feature = "go",
        feature = "bundler",
        feature = "dart",
        feature = "maven",
        feature = "composer",
        feature = "gradle",
        feature = "nuget",
        feature = "deno",
        feature = "github-actions",
        feature = "gitlab-ci",
        feature = "swift",
        feature = "pypi"
    ))]
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum BareVersionAgreementExpectation {
        /// `deps-core`'s `concrete_pin_version` and the ecosystem's own comparator must
        /// agree on whether a bare full version (`"1.2.3"`) is an exact pin. When `true`,
        /// also checked against a bare *partial* version (`"1.2"`, impl-critic M1) —
        /// gated per-ecosystem because a partial-version *requirement* is not a concept
        /// every `Concrete`-policy ecosystem actually has: Go's own comparator, for
        /// instance, treats a bare string as a version *prefix* to support pseudo-version
        /// and `+incompatible`-suffix matching (`go_version_matches`), which makes it
        /// (correctly, for its real purpose) accept `"1.2"` against a candidate `"1.2.9"`
        /// — a false "divergence" against `deps-core` if compared as though `"1.2"` were
        /// a genuine partial-version requirement, which go.mod's `require` directive
        /// never actually contains (it is always a complete version). Only the
        /// ecosystems with a real bare-partial-is-a-range grammar (`AlwaysRange`'s Cargo
        /// caret, `ConcreteIfFullVersion`'s X-range/moving-tag ecosystems) get `true`.
        Checked { test_partial: bool },
        /// The ecosystem's own comparator would disagree with `deps-core`'s verdict, but
        /// the parser can never actually emit a bare requirement in the first place, so the
        /// divergence never reaches `concrete_pin_version` in practice (Swift, PyPI).
        LatentOnly,
        /// `deps-core` deliberately reports a bare requirement as a pin even though the
        /// ecosystem's own comparator disagrees — a documented approximation, not an
        /// oversight (NuGet).
        DeliberateApproximation,
    }

    /// #669 regression guard: `deps-core`'s `bare_requirement_policy` hand-maintains a
    /// per-ecosystem model of "is a bare version requirement a pin or a range", but every
    /// ecosystem's own formatter already has the authoritative answer via
    /// `compile_requirement`/`version_satisfies_requirement`, and nothing kept the two in
    /// sync — this already caused two shipped bugs (#664 npm/Composer, #667 Deno). For every
    /// ecosystem this crate can register, classifies it via [`BareVersionAgreementExpectation`]
    /// and checks the matching invariant: `Checked` ecosystems must agree on both a bare full
    /// version (`"1.2.3"`) and a bare partial version (`"1.2"`, impl-critic M1); `LatentOnly`
    /// and `DeliberateApproximation` ecosystems must instead still exhibit the disagreement
    /// their exemption relies on (impl-critic M2) — so an alignment on either side (a parser
    /// change, a comparator change) fails this test instead of silently going stale.
    ///
    /// The `match` in [`bare_version_agreement_expectation`] is deliberately exhaustive
    /// (`.claude/CLAUDE.md`'s bug-class-#118 rule): a future 15th ecosystem must get an
    /// explicit arm — added to `Checked` or listed as a commented, reviewed exemption —
    /// rather than silently falling through a wildcard.
    #[cfg(any(
        feature = "cargo",
        feature = "npm",
        feature = "go",
        feature = "bundler",
        feature = "dart",
        feature = "maven",
        feature = "composer",
        feature = "gradle",
        feature = "nuget",
        feature = "deno",
        feature = "github-actions",
        feature = "gitlab-ci",
        feature = "swift",
        feature = "pypi"
    ))]
    fn bare_version_agreement_expectation(
        id: deps_core::EcosystemId,
    ) -> BareVersionAgreementExpectation {
        use BareVersionAgreementExpectation::{Checked, DeliberateApproximation, LatentOnly};

        match id {
            // Cargo (caret), and the `ConcreteIfFullVersion` ecosystems (npm/Composer/Deno's
            // X-ranges, GitHub Actions'/GitLab CI's moving-major tags): a bare *partial*
            // version is a real, distinct requirement shape from a bare full version under
            // these ecosystems' own grammar, so both are worth checking.
            deps_core::EcosystemId::Cargo
            | deps_core::EcosystemId::Npm
            | deps_core::EcosystemId::Composer
            | deps_core::EcosystemId::Deno
            | deps_core::EcosystemId::GithubActions
            | deps_core::EcosystemId::GitlabCi => Checked { test_partial: true },
            // Go/Bundler/Dart/Maven/Gradle: no partial-version requirement concept exists in
            // these ecosystems' own manifests (a bare version is always a complete one), so a
            // synthetic partial input like `"1.2"` isn't a meaningful requirement to compare —
            // only the full-version case is checked. (Go's own comparator in particular
            // treats a bare string as a version *prefix*, for pseudo-version/`+incompatible`
            // matching, not as a partial-version range — comparing it against `"1.2"` as if it
            // were a partial-range requirement produces a false divergence.)
            deps_core::EcosystemId::Go
            | deps_core::EcosystemId::Bundler
            | deps_core::EcosystemId::Dart
            | deps_core::EcosystemId::Maven
            | deps_core::EcosystemId::Gradle => Checked {
                test_partial: false,
            },
            // Swift: `SwiftFormatter::compile_requirement` parses a requirement via
            // `semver::VersionReq`, whose bare-string default is a caret range — the same
            // divergence NuGet has — but `deps-swift`'s parser always emits an explicit
            // range spelling (`">=X, <Y"`) or an exact `"=X"` pin, never a bare `"X.Y.Z"`
            // string (see `deps-swift/src/parser.rs`'s `upToNextMajor`/`.exact(...)`
            // handling), so this can't fire today. Re-review if the parser ever changes to
            // emit a bare form.
            deps_core::EcosystemId::Swift => LatentOnly,
            // PyPI: the parser retains the pep440 comparator on every requirement (e.g. an
            // exact pin parses to `"==1.2.3"`, never bare `"1.2.3"` — see `deps-core`'s
            // `concrete_pin_version_strips_pep440_double_equals_comparator`), so a bare
            // requirement never reaches this check either. Re-review if the parser ever
            // changes to emit a bare form.
            deps_core::EcosystemId::Pypi => LatentOnly,
            // NuGet (#669): a bare `Version="X"` is really an unbounded minimum floor under
            // `NuGetFormatter`'s own comparator, but `deps-core` deliberately still reports
            // it as a pin — restore resolves a direct `PackageReference` to its floor
            // version in practice, mirrored by `NuGetFormatter::is_requirement_up_to_date`
            // treating the same bare floor as a pin for outdated-checking. See
            // `deps-core`'s `bare_requirement_policy` doc for the full rationale, including
            // why the alternative (an always-range policy) was tried and reverted.
            deps_core::EcosystemId::NuGet => DeliberateApproximation,
        }
    }

    #[cfg(any(
        feature = "cargo",
        feature = "npm",
        feature = "go",
        feature = "bundler",
        feature = "dart",
        feature = "maven",
        feature = "composer",
        feature = "gradle",
        feature = "nuget",
        feature = "deno",
        feature = "github-actions",
        feature = "gitlab-ci",
        feature = "swift",
        feature = "pypi"
    ))]
    #[test]
    fn test_concrete_pin_version_agrees_with_formatter_for_bare_version() {
        use deps_core::{ConcreteVersion, VersionReq};

        let registry = Arc::new(EcosystemRegistry::new());
        let cache = Arc::new(HttpCache::new());
        register_ecosystems(&registry, Arc::clone(&cache), &test_runtime());

        const BARE_FULL_VERSION: &str = "1.2.3";
        const BARE_PARTIAL_VERSION: &str = "1.2";

        for str_id in registry.ecosystem_ids() {
            let id: deps_core::EcosystemId = str_id.parse().unwrap_or_else(|_| {
                panic!("registered ecosystem id {str_id:?} has no matching EcosystemId variant")
            });
            let ecosystem = registry
                .get(str_id)
                .unwrap_or_else(|| panic!("{str_id:?} just parsed from the registry's own ids"));
            let formatter = ecosystem.formatter();

            match bare_version_agreement_expectation(id) {
                BareVersionAgreementExpectation::Checked { test_partial } => {
                    let bare_inputs: &[&str] = if test_partial {
                        &[BARE_FULL_VERSION, BARE_PARTIAL_VERSION]
                    } else {
                        &[BARE_FULL_VERSION]
                    };
                    for &bare in bare_inputs {
                        let deps_core_says_pin =
                            deps_core::lsp_helpers::concrete_pin_version(bare, id).is_some();
                        let formatter_says_pin =
                            formatter_treats_bare_version_as_exact_pin(formatter, bare);

                        assert_eq!(
                            deps_core_says_pin, formatter_says_pin,
                            "{id:?} ({bare:?}): deps-core's concrete_pin_version and the \
                             ecosystem's own compile_requirement/version_satisfies_requirement \
                             disagree on whether this bare requirement is an exact pin"
                        );
                    }
                }
                BareVersionAgreementExpectation::LatentOnly => {
                    let deps_core_says_pin =
                        deps_core::lsp_helpers::concrete_pin_version(BARE_FULL_VERSION, id)
                            .is_some();
                    let formatter_says_pin =
                        formatter_treats_bare_version_as_exact_pin(formatter, BARE_FULL_VERSION);

                    assert_ne!(
                        deps_core_says_pin, formatter_says_pin,
                        "{id:?}: this ecosystem is exempted as a latent-only mismatch, but its \
                         comparator no longer disagrees with deps-core's verdict — either the \
                         parser started emitting a bare requirement (making this a live bug, \
                         not a latent one) or the comparator changed; re-review this exemption \
                         in bare_version_agreement_expectation"
                    );
                }
                BareVersionAgreementExpectation::DeliberateApproximation => {
                    assert!(
                        deps_core::lsp_helpers::concrete_pin_version(BARE_FULL_VERSION, id)
                            .is_some(),
                        "{id:?}: deps-core should still report a bare full version as a pin \
                         (the deliberate approximation this exemption documents)"
                    );
                    assert!(
                        !formatter_treats_bare_version_as_exact_pin(formatter, BARE_FULL_VERSION),
                        "{id:?}: the ecosystem's own comparator no longer disagrees with a \
                         strict pin verdict — re-review whether this exemption (and the \
                         Concrete-policy approximation it documents) is still needed"
                    );

                    let requirement = VersionReq::new(BARE_FULL_VERSION);
                    assert!(
                        formatter.is_requirement_up_to_date(
                            &requirement,
                            &ConcreteVersion::from(BARE_FULL_VERSION)
                        ),
                        "{id:?}: is_requirement_up_to_date should treat a bare floor as \
                         up to date when latest equals the floor — the pin-like precedent \
                         this exemption relies on"
                    );
                    assert!(
                        !formatter.is_requirement_up_to_date(
                            &requirement,
                            &ConcreteVersion::from("9.9.9")
                        ),
                        "{id:?}: is_requirement_up_to_date should treat a bare floor as \
                         outdated once latest moves past it — confirming it is handled as a \
                         pin, not an auto-following range"
                    );
                }
            }
        }
    }

    /// #348 regression: `select_latest_matching` must resolve an all-`AdvisoryDeprecated`
    /// version list under a wildcard requirement for every registered ecosystem — an
    /// advisory-only flag (npm `deprecated`, Composer `abandoned`, ...) must never make an
    /// existing package look unresolvable (#347). Iterates every id `register_ecosystems`
    /// wires up via `EcosystemRegistry::ecosystem_ids`, so a 12th ecosystem is covered
    /// automatically without a new test. The paired `Available` control guards against a
    /// `None` result that has nothing to do with the advisory flag (e.g. the fixture
    /// version strings not fitting this ecosystem's matcher).
    ///
    /// This assertion is only genuinely discriminating for an ecosystem whose
    /// `select_latest_matching` actually consults `removal_status()` when filtering under
    /// a wildcard requirement (currently Composer, npm, and Deno-via-npm) — for an
    /// ecosystem that doesn't filter on it at all, or that only maps a real per-version
    /// yank (not the advisory case), `subject.is_some()` is trivially true regardless of
    /// whether the ecosystem maps its advisory flag correctly.
    #[test]
    fn test_select_latest_matching_resolves_advisory_deprecated_for_every_ecosystem() {
        use deps_core::{RemovalStatus, Version, VersionReq};
        use std::any::Any;

        struct StatusVersion {
            version: deps_core::ConcreteVersion,
            status: RemovalStatus,
        }

        impl Version for StatusVersion {
            fn version_string(&self) -> &deps_core::ConcreteVersion {
                &self.version
            }

            fn removal_status(&self) -> RemovalStatus {
                self.status
            }

            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        fn fixture(status: RemovalStatus) -> Vec<Box<dyn Version>> {
            vec![
                Box::new(StatusVersion {
                    version: "2.0.0".into(),
                    status,
                }),
                Box::new(StatusVersion {
                    version: "1.2.3".into(),
                    status,
                }),
            ]
        }

        // #421 S2: a package whose only releases so far are all prerelease must still
        // resolve under a wildcard requirement, same as an all-`AdvisoryDeprecated` one
        // above — a prerelease-only flag is a ranking preference for "latest", not a hard
        // removal from existence. `is_prerelease()` is overridden directly rather than
        // relying on a hyphenated version string, so this fixture is unambiguous regardless
        // of which ecosystem-specific parser (if any) `select_latest_matching` re-parses
        // `version_string()` with.
        struct PrereleaseOnlyVersion {
            version: deps_core::ConcreteVersion,
        }

        impl Version for PrereleaseOnlyVersion {
            fn version_string(&self) -> &deps_core::ConcreteVersion {
                &self.version
            }

            fn is_prerelease(&self) -> bool {
                true
            }

            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        fn prerelease_only_fixture() -> Vec<Box<dyn Version>> {
            vec![
                Box::new(PrereleaseOnlyVersion {
                    version: "2.0.0-beta2".into(),
                }),
                Box::new(PrereleaseOnlyVersion {
                    version: "2.0.0-beta1".into(),
                }),
            ]
        }

        let registry = Arc::new(EcosystemRegistry::new());
        let cache = Arc::new(HttpCache::new());
        register_ecosystems(&registry, Arc::clone(&cache), &test_runtime());

        let req = VersionReq::new("*");
        for id in registry.ecosystem_ids() {
            let ecosystem = registry.get(id).expect("id came from ecosystem_ids()");
            let ecosystem_registry = ecosystem.registry();

            let control =
                ecosystem_registry.select_latest_matching(&fixture(RemovalStatus::Available), &req);
            assert!(
                control.is_some(),
                "{id}: control fixture (all Available) must resolve under a wildcard \
                 requirement — a `None` here means the fixture itself doesn't fit this \
                 ecosystem's matcher, not that the advisory flag broke anything"
            );

            let subject = ecosystem_registry
                .select_latest_matching(&fixture(RemovalStatus::AdvisoryDeprecated), &req);
            assert!(
                subject.is_some(),
                "{id}: an advisory-only flag must not hide an existing package under a \
                 wildcard requirement (#347)"
            );

            // Go is a deliberate exception to this invariant, not an #421-class bug
            // (documented at #364): `select_latest_matching` intentionally excludes
            // prerelease pseudo-versions unconditionally, with no wildcard fallback, so the
            // `/@v/list`-based pick never shadows the `/@latest` fallback the fetch loop
            // needs for a module whose only tags are prerelease. Asserting this invariant
            // for Go would mean "fixing" behavior that was already deliberately chosen.
            //
            // NuGet used to be excluded here too (`req = "*"` read as NuGet's own
            // floating-version "latest stable" syntax rather than this ladder's existence
            // check), but #423 added a fallback rung to `pick_latest_matching`/
            // `select_latest_matching` (`deps-nuget/src/registry.rs`) so a prerelease-only
            // package now resolves under a bare wildcard too, matching every other
            // ecosystem — no exception needed anymore.
            if matches!(id, "go") {
                continue;
            }

            let prerelease_subject =
                ecosystem_registry.select_latest_matching(&prerelease_only_fixture(), &req);
            assert!(
                prerelease_subject.is_some(),
                "{id}: a package whose only releases so far are prerelease must still \
                 resolve under a wildcard requirement (#421)"
            );
        }
    }
}
