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

pub mod ecosystem;
pub mod error;
pub mod formatter;
pub mod lockfile;
pub mod parser;
pub mod registry;
pub mod types;
pub mod version;

// Re-export commonly used types
pub use ecosystem::BundlerEcosystem;
pub use error::{BundlerError, Result};
pub use formatter::BundlerFormatter;
pub use lockfile::GemfileLockParser;
pub use parser::{BundlerParseResult, BundlerParser, parse_gemfile};
pub use registry::{RubyGemsRegistry, gem_url};
pub use types::{BundlerDependency, BundlerVersion, DependencyGroup, DependencySource, GemInfo};
