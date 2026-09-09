//! Gemfile parsing and rubygems.org integration.
//!
//! This crate provides Bundler-specific functionality for the deps-lsp server,
//! including Gemfile DSL parsing, dependency extraction, and rubygems.org
//! registry integration.
//!
//! # Features
//!
//! - Parsing `Gemfile` dependencies with position tracking
//! - Fetching version data from rubygems.org API
//! - Supporting registry, git, path, and github dependencies
//! - Group handling (`:development`, `:test`, `:production`)
//! - Implementing deps-core traits for generic LSP handlers
//!
//! # Examples
//!
//! ```
//! use deps_bundler::{BundlerDependency, RubyGemsRegistry};
//!
//! // Types are re-exported for convenience
//! let _deps: Vec<BundlerDependency> = vec![];
//! ```

// #680: string slicing on a byte index that isn't a verified char boundary panics; sites
// confirmed boundary-safe by construction are individually `#[allow]`ed with a justification.
// #683: the three remaining #673 restriction lints, scoped to this crate only via a source
// attribute (which overrides this crate's `[lints] workspace = true` Cargo.toml table
// regardless of that table's level) rather than a duplicated `[lints.clippy]` table — avoids
// ~90 lines of drift-prone duplication of the workspace allow-list. Deliberately never added
// to `[workspace.lints.clippy]` itself (must stay opt-in per crate, not workspace-wide).
// Sites confirmed safe are individually `#[allow]`ed with a one-line justification.
#![warn(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::string_slice
)]

pub mod ecosystem;
pub mod formatter;
pub mod lockfile;
pub mod parser;
pub mod registry;
pub mod types;
pub mod version;

// Re-export commonly used types
pub use ecosystem::BundlerEcosystem;
pub use formatter::BundlerFormatter;
pub use lockfile::GemfileLockParser;
pub use parser::{BundlerParseResult, BundlerParser, parse_gemfile};
pub use registry::{RubyGemsRegistry, gem_url};
pub use types::{BundlerDependency, BundlerVersion, DependencyGroup, DependencySource, GemInfo};
