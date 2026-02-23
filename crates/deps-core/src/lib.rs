//! Core abstractions for deps-lsp.
//!
//! This crate provides the foundational traits and utilities used across
//! all ecosystem-specific implementations (Cargo, npm, PyPI, etc.).
//!
//! # Architecture
//!
//! deps-core defines:
//! - **Traits**: `Registry`, `Version`, `Metadata`, `Ecosystem`, `ParseResult`
//! - **HTTP Cache**: Shared caching layer with ETag/Last-Modified validation
//! - **Error Types**: Unified error handling across all ecosystems

pub mod cache;
pub mod completion;
pub mod ecosystem;
pub mod ecosystem_registry;
pub mod error;
pub mod lockfile;
pub mod lsp_helpers;
pub mod macros;
pub mod parser;
pub mod registry;
pub mod version_matcher;

// Re-export commonly used types
pub use cache::{CachedResponse, HttpCache};
pub use ecosystem::{Dependency, Ecosystem, EcosystemConfig, ParseResult};
pub use ecosystem_registry::EcosystemRegistry;
pub use error::{DepsError, Result};
pub use lockfile::{LockFileProvider, ResolvedPackage, ResolvedPackages, ResolvedSource};
pub use lsp_helpers::{
    EcosystemFormatter, LineOffsetTable, generate_code_actions as lsp_generate_code_actions,
    generate_diagnostics as lsp_generate_diagnostics, generate_hover as lsp_generate_hover,
    generate_inlay_hints as lsp_generate_inlay_hints, is_same_major_minor, position_in_range,
};
pub use parser::{DependencyInfo, DependencySource, LoadingState, ManifestParser, ParseResultInfo};
pub use registry::{Metadata, Registry, Version, find_latest_stable};
pub use version_matcher::{
    Pep440Matcher, SemverMatcher, VersionRequirementMatcher, extract_pypi_min_version,
    normalize_and_parse_version,
};
