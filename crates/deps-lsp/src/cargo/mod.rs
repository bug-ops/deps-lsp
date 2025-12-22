//! Cargo.toml parsing and crates.io integration.
//!
//! This module provides Cargo-specific functionality for the LSP server,
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
//! use deps_lsp::cargo::ParsedDependency;
//!
//! // Types are re-exported for convenience
//! let _deps: Vec<ParsedDependency> = vec![];
//! ```

pub mod parser;
pub mod registry;
pub mod types;

// Re-export commonly used types
pub use parser::{ParseResult, parse_cargo_toml};
pub use registry::CratesIoRegistry;
pub use types::ParsedDependency;
