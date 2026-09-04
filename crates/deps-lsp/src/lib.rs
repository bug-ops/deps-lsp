pub mod config;
pub mod document;
pub mod file_watcher;
pub mod handlers;
pub mod progress;
pub mod server;

#[cfg(test)]
mod test_utils;

use std::sync::Arc;

pub use deps_core::{DepsError, EcosystemRegistry, HttpCache, Result};
pub use server::Backend;

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
        CargoParser,
        CargoVersion,
        CrateInfo,
        CratesIoRegistry,
        DependencySection,
        DependencySource,
        ParseResult,
        ParsedDependency,
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
pub fn register_ecosystems(
    registry: &EcosystemRegistry,
    cache: Arc<HttpCache>,
    policy: Arc<deps_core::net_policy::RegistryAccessPolicy>,
) {
    // Keeps `policy` used even when the `cargo` feature (its only consumer) is compiled out.
    let _ = &policy;

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
    }

    #[cfg(all(feature = "npm", feature = "deno"))]
    {
        let npm_context = deps_npm::config::NpmParseContext {
            policy: Arc::clone(&policy),
            config_cache: Arc::new(deps_npm::config::NpmConfigCache::new()),
        };
        let npm_registry = Arc::new(NpmRegistry::new(Arc::clone(&cache)));
        registry.register(Arc::new(NpmEcosystem::with_context(
            Arc::clone(&npm_registry),
            npm_context,
        )));
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
        };
        registry.register(Arc::new(NpmEcosystem::with_context(
            Arc::new(NpmRegistry::new(Arc::clone(&cache))),
            npm_context,
        )));
    }
    #[cfg(all(feature = "deno", not(feature = "npm")))]
    register!("deno", DenoEcosystem, registry, &cache);

    // pypi is written out explicitly rather than via `register!` (spec 033, mirroring npm's
    // spec 032 S3 precedent): that macro's `PypiEcosystem::new(cache)` would give pypi a
    // default, disconnected `RegistryAccessPolicy` — its private-index reachability policy
    // would never see a live `initialize`/`didChangeConfiguration` update.
    #[cfg(feature = "pypi")]
    registry.register(Arc::new(PypiEcosystem::with_policy(
        Arc::new(PypiRegistry::new(Arc::clone(&cache))),
        Arc::clone(&policy),
    )));

    // go is written out explicitly rather than via `register!` (spec 034, mirroring npm's
    // spec 032 S3 precedent): that macro's `GoEcosystem::new(cache)` would give Go a
    // default, disconnected `GoParseContext` — its `$GOENV` reachability policy would never
    // see a live `initialize`/`didChangeConfiguration` update.
    #[cfg(feature = "go")]
    {
        let go_context = deps_go::config::GoParseContext {
            policy: Arc::clone(&policy),
            config_cache: Arc::new(deps_go::config::GoEnvCache::new()),
        };
        registry.register(Arc::new(GoEcosystem::with_context(
            Arc::new(GoRegistry::new(Arc::clone(&cache))),
            go_context,
        )));
    }
    register!("bundler", BundlerEcosystem, registry, &cache);
    register!("dart", DartEcosystem, registry, &cache);
    register!("maven", MavenEcosystem, registry, &cache);
    register!("gradle", GradleEcosystem, registry, &cache);
    register!("swift", SwiftEcosystem, registry, &cache);
    register!("composer", ComposerEcosystem, registry, &cache);
    register!("nuget", NuGetEcosystem, registry, &cache);
    register!("github-actions", GithubActionsEcosystem, registry, &cache);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_ecosystems() {
        let registry = Arc::new(EcosystemRegistry::new());
        let cache = Arc::new(HttpCache::new());
        register_ecosystems(
            &registry,
            Arc::clone(&cache),
            Arc::new(deps_core::net_policy::RegistryAccessPolicy::default()),
        );

        #[cfg(feature = "cargo")]
        assert!(registry.get("cargo").is_some());
        #[cfg(feature = "npm")]
        assert!(registry.get("npm").is_some());
        #[cfg(feature = "pypi")]
        assert!(registry.get("pypi").is_some());
        #[cfg(feature = "go")]
        assert!(registry.get("go").is_some());
        #[cfg(feature = "bundler")]
        assert!(registry.get("bundler").is_some());
        #[cfg(feature = "dart")]
        assert!(registry.get("dart").is_some());
        #[cfg(feature = "maven")]
        assert!(registry.get("maven").is_some());
        #[cfg(feature = "gradle")]
        assert!(registry.get("gradle").is_some());
        #[cfg(feature = "swift")]
        assert!(registry.get("swift").is_some());
        #[cfg(feature = "composer")]
        assert!(registry.get("composer").is_some());
        #[cfg(feature = "nuget")]
        assert!(registry.get("nuget").is_some());
        #[cfg(feature = "deno")]
        assert!(registry.get("deno").is_some());
        #[cfg(feature = "github-actions")]
        assert!(registry.get("github-actions").is_some());
    }

    /// Regression guard for issue #118: `EcosystemId`'s string literals (`deps-core`)
    /// are hand-duplicated from each ecosystem crate's own `Ecosystem::id()`, with
    /// nothing linking them at compile time. This proves every id actually registered
    /// by `register_ecosystems` round-trips through `EcosystemId::from_str`/`id()`,
    /// and that every `EcosystemId` variant resolves back to a registered ecosystem —
    /// so a future rename fails this test instead of panicking at document-open time
    /// (see the `.expect()` in `document::lifecycle::resolve_ecosystem_id`).
    #[test]
    fn test_ecosystem_id_matches_registered_ecosystems() {
        let registry = Arc::new(EcosystemRegistry::new());
        let cache = Arc::new(HttpCache::new());
        register_ecosystems(
            &registry,
            Arc::clone(&cache),
            Arc::new(deps_core::net_policy::RegistryAccessPolicy::default()),
        );

        for id in registry.ecosystem_ids() {
            let parsed: deps_core::EcosystemId = id.parse().unwrap_or_else(|_| {
                panic!("registered ecosystem id {id:?} has no matching EcosystemId variant")
            });
            assert_eq!(parsed.id(), id);
        }

        #[cfg(feature = "cargo")]
        assert!(registry.get(deps_core::EcosystemId::Cargo.id()).is_some());
        #[cfg(feature = "npm")]
        assert!(registry.get(deps_core::EcosystemId::Npm.id()).is_some());
        #[cfg(feature = "pypi")]
        assert!(registry.get(deps_core::EcosystemId::Pypi.id()).is_some());
        #[cfg(feature = "go")]
        assert!(registry.get(deps_core::EcosystemId::Go.id()).is_some());
        #[cfg(feature = "bundler")]
        assert!(registry.get(deps_core::EcosystemId::Bundler.id()).is_some());
        #[cfg(feature = "dart")]
        assert!(registry.get(deps_core::EcosystemId::Dart.id()).is_some());
        #[cfg(feature = "maven")]
        assert!(registry.get(deps_core::EcosystemId::Maven.id()).is_some());
        #[cfg(feature = "gradle")]
        assert!(registry.get(deps_core::EcosystemId::Gradle.id()).is_some());
        #[cfg(feature = "swift")]
        assert!(registry.get(deps_core::EcosystemId::Swift.id()).is_some());
        #[cfg(feature = "composer")]
        assert!(
            registry
                .get(deps_core::EcosystemId::Composer.id())
                .is_some()
        );
        #[cfg(feature = "nuget")]
        assert!(registry.get(deps_core::EcosystemId::NuGet.id()).is_some());
        #[cfg(feature = "deno")]
        assert!(registry.get(deps_core::EcosystemId::Deno.id()).is_some());
        #[cfg(feature = "github-actions")]
        assert!(
            registry
                .get(deps_core::EcosystemId::GithubActions.id())
                .is_some()
        );
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
        register_ecosystems(
            &registry,
            Arc::clone(&cache),
            Arc::new(deps_core::net_policy::RegistryAccessPolicy::default()),
        );

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
