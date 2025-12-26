pub mod config;
pub mod document;
pub mod file_watcher;
pub mod handlers;
pub mod server;

#[cfg(test)]
mod test_utils;

// Re-export from deps-core
pub use deps_core::{DepsError, Result};

// Re-export from deps-cargo
#[cfg(feature = "cargo")]
pub use deps_cargo::{
    CargoParser, CargoVersion, CrateInfo, CratesIoRegistry, DependencySection, DependencySource,
    ParseResult, ParsedDependency, parse_cargo_toml,
};

// Re-export from deps-npm
#[cfg(feature = "npm")]
pub use deps_npm::{
    NpmDependency, NpmDependencySection, NpmPackage, NpmParseResult, NpmRegistry, NpmVersion,
    parse_package_json,
};

// Re-export from deps-pypi
#[cfg(feature = "pypi")]
pub use deps_pypi::{
    PypiDependency, PypiDependencySection, PypiEcosystem, PypiParser, PypiRegistry, PypiVersion,
};

// Re-export from deps-go
#[cfg(feature = "go")]
pub use deps_go::{
    GoDependency, GoDirective, GoEcosystem, GoParseResult, GoRegistry, GoVersion, parse_go_mod,
};

// Re-export server
pub use server::Backend;
