// `document/fetch.rs` and the test-only mock `Registry` implementations in `test_utils.rs`/
// `handlers/completion.rs` box futures for every ecosystem's `get_latest_matching`-style call;
// rustc's default recursion limit has proven occasionally insufficient to prove the resulting
// `Send` bound for several ecosystem crates' own implementations, downgrading a
// previously-silent trait-solver retry into `recursion_depth_exceeding_limit`, which the fuzz
// CI job's `-D warnings` nightly build turns into a hard error (rust-lang/rust#159228). Same
// class of fix as deps-cargo (#745), deps-nuget (#696), deps-swift (#673), deps-composer.
#![recursion_limit = "256"]

//! The `deps-lsp` binary crate: wires the 14 ecosystem crates into a running
//! `tower-lsp-server` [`LanguageServer`](tower_lsp_server::LanguageServer)
//! implementation.
//!
//! [`register_ecosystems`] registers every feature-enabled ecosystem crate
//! against an [`EcosystemRegistry`], threading live-updatable settings
//! ([`EcosystemRuntime`]) into the ones that need them. [`server::Backend`]
//! is the `LanguageServer` implementation itself; `document` holds the
//! per-document state machine driving hover/completion/diagnostics.

/// Live configuration parsing and the config schema (`deny_unknown_fields`).
pub mod config;
pub mod document;
pub mod file_watcher;
pub mod handlers;
pub mod progress;
/// The `tower-lsp-server` [`LanguageServer`](tower_lsp_server::LanguageServer) implementation.
pub mod server;

#[cfg(test)]
mod test_utils;

use std::sync::Arc;
use std::sync::atomic::AtomicBool;

pub use deps_core::parser::DependencySource;
pub use deps_core::{DepsError, EcosystemRegistry, HttpCache, Result};
pub use server::Backend;

/// Live-updatable settings [`register_ecosystems`] threads into every ecosystem that needs them.
///
/// Bundled into one struct (issue #561, M3) rather than growing that function's arity again
/// for each new cross-ecosystem live flag.
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

/// Declares an ecosystem: re-exports types and registers at runtime.
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
        CargoParseResult,
        CargoParser,
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
        GoParseResult,
        GoRegistry,
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
/// `CargoEcosystem::with_context` so `ServerState`'s live-updatable
/// `Arc<RegistryAccessPolicy>` (see `document::state::ServerState::registry_policy`) is the
/// exact same handle every Cargo parse reads — `initialize`/`did_change_configuration`
/// updating it then takes effect immediately, with no need to reconstruct the ecosystem.
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
/// into (issue #592 security M1) — the single source of truth `config::reparse_scope`'s
/// caller consults to scope a `registries.workspace_registries` reparse, so that set can
/// never drift from what this function actually wires up. Adding a 6th policy-consuming
/// ecosystem means editing this function anyway (to thread `policy` through its parse
/// context); pushing its id onto the returned list at that same call site keeps the two
/// facts — "receives the policy" and "is in the reparse scope" — physically inseparable,
/// rather than duplicated across two independently-editable places.
pub fn register_ecosystems(
    registry: &EcosystemRegistry,
    cache: Arc<HttpCache>,
    runtime: &EcosystemRuntime,
) -> Vec<&'static str> {
    let policy = Arc::clone(&runtime.policy);
    // Keeps `policy` used even when the `cargo` feature (its only consumer) is compiled out.
    let _ = &policy;
    let mut workspace_registry_ecosystems = Vec::new();

    #[cfg(feature = "cargo")]
    {
        let context = deps_cargo::parser::CargoParseContext {
            policy: Arc::clone(&policy),
            config_cache: Arc::new(deps_cargo::config::ConfigFileCache::new()),
        };
        registry.register(Arc::new(CargoEcosystem::with_context(
            Arc::clone(&cache),
            context,
        )));
        workspace_registry_ecosystems.push("cargo");
    }

    #[cfg(all(feature = "npm", feature = "deno"))]
    {
        let npm_context = deps_npm::config::NpmParseContext {
            policy: Arc::clone(&policy),
            config_cache: Arc::new(deps_npm::config::NpmConfigCache::new()),
            workspace_cache: Arc::new(deps_npm::catalog::PnpmWorkspaceCache::new()),
        };
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
        let npm_context = deps_npm::config::NpmParseContext {
            policy: Arc::clone(&policy),
            config_cache: Arc::new(deps_npm::config::NpmConfigCache::new()),
            workspace_cache: Arc::new(deps_npm::catalog::PnpmWorkspaceCache::new()),
        };
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
        let go_context = deps_go::config::GoParseContext {
            policy: Arc::clone(&policy),
            config_cache: Arc::new(deps_go::config::GoEnvCache::new()),
            goenv_path: deps_go::config::goenv_path(),
        };
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
        EcosystemRuntime {
            policy: Arc::new(deps_core::net_policy::RegistryAccessPolicy::default()),
            nuget_user_profile_sources: Arc::new(AtomicBool::new(false)),
            gitlab_instance_host: Arc::new(std::sync::RwLock::new(None)),
        }
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
    /// was added without pushing its id (fails closed for `config::reparse_scope`), or an id
    /// was pushed for an ecosystem that no longer receives the policy (harmless over-scoping,
    /// but signals the two facts drifted anyway).
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

        let mut expected = Vec::new();
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

    /// Regression guard for issue #118: `EcosystemId`'s string literals (`deps-core`)
    /// are hand-duplicated from each ecosystem crate's own `Ecosystem::id()`, with
    /// nothing linking them at compile time. This proves every id actually registered
    /// by `register_ecosystems` round-trips through `EcosystemId::from_str`/`id()` — so a
    /// future rename fails this test instead of panicking at document-open time (see the
    /// `.expect()` in `document::resolved::resolve_ecosystem_id`).
    ///
    /// The reverse direction — every `EcosystemId` variant resolves back to a registered
    /// ecosystem — moved to [`test_ecosystem_id_all_registered`] (#758): driven by
    /// [`deps_core::EcosystemId::ALL`] instead of this hand-written, drift-prone 14-line list,
    /// so an ecosystem declared in the enum but never wired into `register_ecosystems` fails
    /// closed rather than silently passing an empty loop here.
    #[test]
    fn test_ecosystem_id_matches_registered_ecosystems() {
        let registry = Arc::new(EcosystemRegistry::new());
        let cache = Arc::new(HttpCache::new());
        register_ecosystems(&registry, Arc::clone(&cache), &test_runtime());

        for id in registry.ecosystem_ids() {
            let parsed: deps_core::EcosystemId = id.parse().unwrap_or_else(|_| {
                panic!("registered ecosystem id {id:?} has no matching EcosystemId variant")
            });
            assert_eq!(parsed.id(), id);
        }
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
            // security-review). Every character that can break out of a markdown
            // `[label](destination)` link is checked, not just newline/autolink/percent.
            let hostile_name =
                deps_core::PackageName::new(deps_core::conformance::HOSTILE_DISPLAY_LINK_PAYLOAD);
            let url = ecosystem.formatter().package_url(&hostile_name);
            assert!(
                url.is_empty() || url::Url::parse(&url).is_ok(),
                "{id:?}: package_url produced an unparsable non-empty URL: {url:?}"
            );
            if !url.is_empty() {
                for hazard in ['\n', '<', '>', '(', ')', '[', ']', '`'] {
                    assert!(
                        !url.contains(hazard),
                        "{id:?}: package_url leaked a literal {hazard:?} — a markdown \
                         `[label](destination)` link-destination breakout character: {url:?}"
                    );
                }
                assert!(
                    !url.chars().any(char::is_control),
                    "{id:?}: package_url leaked a raw control character: {url:?}"
                );
                assert!(
                    !url.contains('\u{202e}'),
                    "{id:?}: package_url leaked a raw U+202E right-to-left override \
                     (display-spoofing): {url:?}"
                );
                assert!(
                    url.contains("%25"),
                    "{id:?}: package_url did not encode the payload's literal '%' as %25: {url:?}"
                );
            }

            let metadata = deps_core::test_util::MockMetadata::new("conformance-probe", "1.0.0");
            let _ = ecosystem.completion_insert_text(&metadata);
        }
    }

    /// CRITICAL regression (issue #706 review): GitHub Actions' `action.yml`/`action.yaml`
    /// bare-basename routing and GitLab CI's `.gitlab/ci/*.yml` directory-pattern routing
    /// can both match `.gitlab/ci/action.yml` — before `EcosystemRegistry::get_for_uri`'s
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
            registry.get_for_uri(&uri).map(|e| e.id()),
            Some(deps_core::EcosystemId::GitlabCi.id()),
            "a real .gitlab/ci/action.yml file must route to gitlab-ci, not github-actions"
        );

        // Non-conflicting action.yml locations must be unaffected.
        let root_action = deps_core::test_util::test_uri("/repo/action.yml");
        assert_eq!(
            registry.get_for_uri(&root_action).map(|e| e.id()),
            Some(deps_core::EcosystemId::GithubActions.id())
        );
        let nested_action =
            deps_core::test_util::test_uri("/repo/.github/actions/my-action/action.yml");
        assert_eq!(
            registry.get_for_uri(&nested_action).map(|e| e.id()),
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
