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
//! - Implementing deps-core traits for generic LSP handlers
//!
//! # Examples
//!
//! ```
//! use deps_cargo::{ParsedDependency, CratesIoRegistry};
//!
//! // Types are re-exported for convenience
//! let _deps: Vec<ParsedDependency> = vec![];
//! ```

pub mod ecosystem;
pub mod error;
pub mod formatter;
pub mod handler;
pub mod lockfile;
pub mod parser;
pub mod registry;
pub mod types;

// Re-export commonly used types
pub use ecosystem::CargoEcosystem;
pub use error::{CargoError, Result};
pub use formatter::CargoFormatter;
pub use handler::CargoHandler;
pub use lockfile::CargoLockParser;
pub use parser::{CargoParser, ParseResult, parse_cargo_toml};
pub use registry::{CratesIoRegistry, crate_url};
pub use types::{CargoVersion, CrateInfo, DependencySection, DependencySource, ParsedDependency};
