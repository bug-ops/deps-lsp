//! npm ecosystem support for deps-lsp.
//!
//! This module provides package.json parsing and npm registry integration
//! for JavaScript/TypeScript projects.

pub mod catalog;
pub mod config;
pub mod ecosystem;
pub mod formatter;
pub mod lockfile;
pub mod parser;
pub mod registry;
pub mod types;

pub use catalog::{CatalogOrigin, CatalogOutcome, PnpmWorkspaceCache};
pub use config::{NpmConfig, NpmConfigCache, NpmParseContext, NpmRegistryIndex};
pub use ecosystem::NpmEcosystem;
pub use formatter::NpmFormatter;
pub use lockfile::NpmLockParser;
pub use parser::{NpmParseResult, parse_package_json, parse_package_json_with_context};
pub use registry::{NpmRegistry, package_url};
pub use types::{NpmDependency, NpmDependencySection, NpmPackage, NpmVersion};

pub type NpmVersionReq = node_semver::Range;
