//! Core abstractions for deps-lsp.
//!
//! This crate provides the foundational traits and utilities used across
//! all ecosystem-specific implementations (Cargo, npm, PyPI, etc.).
//!
//! # Architecture
//!
//! deps-core defines:
//! - **Traits**: `PackageRegistry`, `ManifestParser`, `VersionInfo`, `PackageMetadata`
//! - **HTTP Cache**: Shared caching layer with ETag/Last-Modified validation
//! - **Error Types**: Unified error handling across all ecosystems
//!
//! # Examples
//!
//! Implementing a registry for a new ecosystem:
//!
//! ```no_run
//! use deps_core::{PackageRegistry, VersionInfo, PackageMetadata};
//! use async_trait::async_trait;
//!
//! #[derive(Clone)]
//! struct MyVersion {
//!     version: String,
//!     deprecated: bool,
//! }
//!
//! impl VersionInfo for MyVersion {
//!     fn version_string(&self) -> &str {
//!         &self.version
//!     }
//!
//!     fn is_yanked(&self) -> bool {
//!         self.deprecated
//!     }
//! }
//!
//! #[derive(Clone)]
//! struct MyMetadata {
//!     name: String,
//!     latest: String,
//! }
//!
//! impl PackageMetadata for MyMetadata {
//!     fn name(&self) -> &str {
//!         &self.name
//!     }
//!
//!     fn description(&self) -> Option<&str> {
//!         None
//!     }
//!
//!     fn repository(&self) -> Option<&str> {
//!         None
//!     }
//!
//!     fn documentation(&self) -> Option<&str> {
//!         None
//!     }
//!
//!     fn latest_version(&self) -> &str {
//!         &self.latest
//!     }
//! }
//!
//! struct MyRegistry;
//!
//! #[async_trait]
//! impl PackageRegistry for MyRegistry {
//!     type Version = MyVersion;
//!     type Metadata = MyMetadata;
//!     type VersionReq = String;
//!
//!     async fn get_versions(&self, _name: &str) -> deps_core::error::Result<Vec<Self::Version>> {
//!         Ok(vec![])
//!     }
//!
//!     async fn get_latest_matching(
//!         &self,
//!         _name: &str,
//!         _req: &Self::VersionReq,
//!     ) -> deps_core::error::Result<Option<Self::Version>> {
//!         Ok(None)
//!     }
//!
//!     async fn search(&self, _query: &str, _limit: usize) -> deps_core::error::Result<Vec<Self::Metadata>> {
//!         Ok(vec![])
//!     }
//! }
//! ```

pub mod cache;
pub mod error;
pub mod handler;
pub mod macros;
pub mod parser;
pub mod registry;
pub mod version_matcher;

// Re-export commonly used types
pub use cache::{CachedResponse, HttpCache};
pub use error::{DepsError, Result};
pub use handler::{
    EcosystemHandler, InlayHintsConfig, VersionStringGetter, YankedChecker, generate_hover,
    generate_inlay_hints,
};
pub use parser::{DependencyInfo, DependencySource, ManifestParser, ParseResultInfo};
pub use registry::{PackageMetadata, PackageRegistry, VersionInfo};
pub use version_matcher::{
    Pep440Matcher, SemverMatcher, VersionRequirementMatcher, extract_pypi_min_version,
    normalize_and_parse_version,
};
