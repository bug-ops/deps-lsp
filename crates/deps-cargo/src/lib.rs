// `CargoRegistry::get_latest_matching_from`'s boxed-future coercion nests through
// `CargoRegistry::get_latest_matching_for_source`/`CratesIoRegistry::get_latest_matching`'s
// `tokio::join!`/`MaybeDone` combinators; rustc's default recursion limit is occasionally
// insufficient to prove the resulting `Send` bound and downgrades a previously-silent
// trait-solver retry into `recursion_depth_exceeding_limit`, which the fuzz CI job's
// `-D warnings` nightly build turns into a hard error (rust-lang/rust#159228). Same fix as
// deps-nuget (#696) and deps-swift (#673).
#![recursion_limit = "256"]

//! Cargo.toml parsing and crates.io integration.
//!
//! This crate provides Cargo-specific functionality for the deps-lsp server,
//! including TOML parsing, dependency extraction, and crates.io registry
//! integration via the sparse index protocol.
//!
//! # Features
//!
//! - Parsing `Cargo.toml` dependencies with position tracking
//! - Fetching version data from crates.io sparse index
//! - Supporting registry, git, and path dependencies
//! - Workspace inheritance (`workspace = true`)
//!
//! # Examples
//!
//! ```
//! use deps_cargo::{CargoDependency, CratesIoRegistry};
//!
//! // Types are re-exported for convenience
//! let _deps: Vec<CargoDependency> = vec![];
//! ```

pub mod config;
pub mod ecosystem;
/// Version formatting and comparison for Cargo (SemVer caret ranges).
pub mod formatter;
pub mod lockfile;
pub mod parser;
pub mod registry;
pub mod sparse;
/// Domain types for Cargo dependencies (parsed `Cargo.toml` entries, crates.io versions).
pub mod types;

// Re-export commonly used types
pub use config::{CargoConfig, Provenance, RegistryIndex, ResolvedRegistryEntry};
pub use ecosystem::CargoEcosystem;
pub use formatter::CargoFormatter;
pub use lockfile::CargoLockParser;
pub use parser::{CargoParseResult, CargoParser, parse_cargo_toml};
pub use registry::{CargoRegistry, CratesIoRegistry, crate_url};
pub use sparse::SparseIndexClient;
pub use types::{
    CargoDependency, CargoDependencySection, CargoVersion, CrateInfo, DependencySource,
};
