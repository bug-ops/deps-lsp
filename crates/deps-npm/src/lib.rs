// Boxed-future `Send`-bound proof in `get_latest_matching`'s async chain can exceed rustc's
// default recursion limit, hard-erroring under fuzz CI's `-D warnings` (rust-lang/rust#159228).
// Same fix as deps-cargo #745, deps-nuget #696, deps-swift #673, deps-composer; deps-deno's
// npm-specifier lookups delegate here and share the exposure.
#![recursion_limit = "256"]

//! npm ecosystem support for deps-lsp.
//!
//! This module provides package.json parsing and npm registry integration
//! for JavaScript/TypeScript projects.

pub mod catalog;
pub mod config;
pub mod ecosystem;
/// Version formatting and comparison for npm (node-semver ranges).
pub mod formatter;
pub mod lockfile;
pub mod parser;
pub mod registry;
/// Domain types for npm dependencies (parsed `package.json` entries, registry versions).
pub mod types;

pub use catalog::{CatalogOrigin, CatalogOutcome, PnpmWorkspaceCache};
pub use config::{NpmConfig, NpmConfigCache, NpmParseContext, NpmRegistryIndex};
pub use ecosystem::NpmEcosystem;
pub use formatter::{NpmFormatter, compile_node_semver_range};
pub use lockfile::NpmLockParser;
// Wrappers exposed only under non-default `fuzzing` feature (#727) so `fuzz/`'s pnpm targets
// can reach the otherwise-private parsers; mirrors deps-gradle's `fuzz_parse_pom_licenses`.
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub use catalog::fuzz_parse_pnpm_workspace;
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub use lockfile::fuzz_parse_package_lock_json_content;
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub use lockfile::fuzz_parse_pnpm_lock_yaml;
pub use parser::{NpmParseResult, parse_package_json, parse_package_json_with_context};
pub use registry::{NpmRegistry, package_url};
pub use types::{NpmDependency, NpmDependencySection, NpmPackage, NpmVersion};
