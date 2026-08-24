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

/// Registers all enabled ecosystems.
///
/// `npm` and `deno` are special-cased (#312): when both features are enabled, they share
/// one `NpmRegistry` instance — built once here and handed to both `NpmEcosystem` and
/// `DenoEcosystem`'s `npm:`-scheme half via `with_registry`/`with_npm` — instead of each
/// constructing its own. `NpmRegistry` is cheaply `Clone` (its `HttpCache` and
/// freshness-path publish-time map are both `Arc`-wrapped internally), so this dedupes the
/// freshness path's full-packument fetch and its publish-time cache for a package
/// appearing in both `package.json` and a `deno.json` `npm:`-specifier dependency, on top
/// of the plain cached GETs the shared `cache` already dedupes.
pub fn register_ecosystems(registry: &EcosystemRegistry, cache: Arc<HttpCache>) {
    register!("cargo", CargoEcosystem, registry, &cache);

    #[cfg(all(feature = "npm", feature = "deno"))]
    {
        let npm_registry = Arc::new(NpmRegistry::new(Arc::clone(&cache)));
        registry.register(Arc::new(NpmEcosystem::with_registry(Arc::clone(
            &npm_registry,
        ))));
        registry.register(Arc::new(DenoEcosystem::with_npm(
            Arc::clone(&cache),
            npm_registry.as_ref().clone(),
        )));
    }
    #[cfg(all(feature = "npm", not(feature = "deno")))]
    register!("npm", NpmEcosystem, registry, &cache);
    #[cfg(all(feature = "deno", not(feature = "npm")))]
    register!("deno", DenoEcosystem, registry, &cache);

    register!("pypi", PypiEcosystem, registry, &cache);
    register!("go", GoEcosystem, registry, &cache);
    register!("bundler", BundlerEcosystem, registry, &cache);
    register!("dart", DartEcosystem, registry, &cache);
    register!("maven", MavenEcosystem, registry, &cache);
    register!("gradle", GradleEcosystem, registry, &cache);
    register!("swift", SwiftEcosystem, registry, &cache);
    register!("composer", ComposerEcosystem, registry, &cache);
    register!("nuget", NuGetEcosystem, registry, &cache);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_ecosystems() {
        let registry = Arc::new(EcosystemRegistry::new());
        let cache = Arc::new(HttpCache::new());
        register_ecosystems(&registry, Arc::clone(&cache));

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
        register_ecosystems(&registry, Arc::clone(&cache));

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
    }
}
