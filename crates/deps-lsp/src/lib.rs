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

/// Registers all enabled ecosystems.
pub fn register_ecosystems(registry: &EcosystemRegistry, cache: Arc<HttpCache>) {
    register!("cargo", CargoEcosystem, registry, &cache);
    register!("npm", NpmEcosystem, registry, &cache);
    register!("pypi", PypiEcosystem, registry, &cache);
    register!("go", GoEcosystem, registry, &cache);
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
    }
}
