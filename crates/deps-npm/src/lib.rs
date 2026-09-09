// `NpmRegistry::get_latest_matching`'s boxed-future coercion nests through
// `get_latest_matching_from`'s own `async fn` call chain; rustc's default recursion limit is
// occasionally insufficient to prove the resulting `Send` bound and downgrades a
// previously-silent trait-solver retry into `recursion_depth_exceeding_limit`, which the fuzz
// CI job's `-D warnings` nightly build turns into a hard error (rust-lang/rust#159228). Same
// class of fix as deps-cargo (#745), deps-nuget (#696), deps-swift (#673), deps-composer.
// deps-deno's `DenoRegistry` delegates npm-specifier lookups to this registry and shares the
// same exposure.
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
pub use formatter::NpmFormatter;
pub use lockfile::NpmLockParser;
// `parse_pnpm_lock_yaml`/`parse_pnpm_workspace` themselves stay private (mirrors
// `deps-gradle`'s `fuzz_parse_pom_licenses` precedent): only these two wrappers are exposed,
// and only under the non-default `fuzzing` feature (issue #727, see this crate's Cargo.toml)
// — `fuzz/`'s `pnpm_lockfile`/`pnpm_catalog` targets reach them as
// `deps_npm::fuzz_parse_pnpm_lock_yaml`/`deps_npm::fuzz_parse_pnpm_workspace`; the crate's
// default public API is unaffected.
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub use catalog::fuzz_parse_pnpm_workspace;
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub use lockfile::fuzz_parse_pnpm_lock_yaml;
pub use parser::{NpmParseResult, parse_package_json, parse_package_json_with_context};
pub use registry::{NpmRegistry, package_url};
pub use types::{NpmDependency, NpmDependencySection, NpmPackage, NpmVersion};

/// npm's version-requirement range type (a node-semver range, e.g. `"^1.2.0"`).
pub type NpmVersionReq = node_semver::Range;
