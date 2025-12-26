pub mod config;
pub mod document;
pub mod file_watcher;
pub mod handlers;
pub mod server;

// Re-export from deps-core
pub use deps_core::{DepsError, Result};

// Re-export from deps-cargo
pub use deps_cargo::{
    CargoParser, CargoVersion, CrateInfo, CratesIoRegistry, DependencySection, DependencySource,
    ParseResult, ParsedDependency, parse_cargo_toml,
};

// Re-export from deps-npm
pub use deps_npm::{
    NpmDependency, NpmDependencySection, NpmPackage, NpmParseResult, NpmRegistry, NpmVersion,
    parse_package_json,
};

// Re-export server
pub use server::Backend;
