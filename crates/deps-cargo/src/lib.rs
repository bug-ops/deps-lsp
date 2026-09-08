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
//! use deps_cargo::{ParsedDependency, CratesIoRegistry};
//!
//! // Types are re-exported for convenience
//! let _deps: Vec<ParsedDependency> = vec![];
//! ```

// #673: restriction lints, scoped to this crate only via a source attribute (overrides
// this crate's `[lints] workspace = true` Cargo.toml table regardless of that table's
// level) rather than a duplicated `[lints.clippy]` table — avoids ~90 lines of
// drift-prone duplication of the workspace allow-list. Deliberately never added to
// `[workspace.lints.clippy]` itself (must stay opt-in per crate, not workspace-wide).
// Sites confirmed safe are individually `#[allow]`ed with a one-line justification.
// #680: `clippy::string_slice` appended to the same restriction-lint attribute for the
// same reason — string slicing on a byte index that isn't a verified char boundary
// panics; sites confirmed boundary-safe by construction are individually `#[allow]`ed.
#![warn(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::string_slice
)]

pub mod config;
pub mod ecosystem;
pub mod formatter;
pub mod lockfile;
pub mod parser;
pub mod registry;
pub mod sparse;
pub mod types;

// Re-export commonly used types
pub use config::{CargoConfig, Provenance, RegistryIndex, ResolvedRegistryEntry};
pub use ecosystem::CargoEcosystem;
pub use formatter::CargoFormatter;
pub use lockfile::CargoLockParser;
pub use parser::{CargoParser, ParseResult, parse_cargo_toml};
pub use registry::{CargoRegistry, CratesIoRegistry, crate_url};
pub use sparse::SparseIndexClient;
pub use types::{CargoVersion, CrateInfo, DependencySection, DependencySource, ParsedDependency};
