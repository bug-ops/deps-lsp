use crate::error::Result;
use tower_lsp::lsp_types::{Range, Url};

/// Generic manifest parser interface.
///
/// Implementors parse ecosystem-specific manifest files (Cargo.toml, package.json, etc.)
/// and extract dependency information with precise LSP positions.
pub trait ManifestParser: Send + Sync {
    /// Parsed dependency type for this ecosystem.
    type Dependency: DependencyInfo + Clone + Send + Sync;

    /// Parse result containing dependencies and optional workspace information.
    type ParseResult: ParseResultInfo<Dependency = Self::Dependency> + Send;

    /// Parses a manifest file and extracts all dependencies with positions.
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Manifest syntax is invalid
    /// - File path cannot be determined from URL
    fn parse(&self, content: &str, doc_uri: &Url) -> Result<Self::ParseResult>;
}

/// Dependency information trait.
///
/// All parsed dependencies must implement this for generic handler access.
pub trait DependencyInfo {
    /// Dependency name (package/crate name).
    fn name(&self) -> &str;

    /// LSP range of the dependency name in the source file.
    fn name_range(&self) -> Range;

    /// Version requirement string (e.g., "^1.0", "~2.3.4").
    fn version_requirement(&self) -> Option<&str>;

    /// LSP range of the version string (for inlay hints positioning).
    fn version_range(&self) -> Option<Range>;

    /// Dependency source (registry, git, path).
    fn source(&self) -> DependencySource;

    /// Feature flags requested (Cargo-specific, empty for npm).
    fn features(&self) -> &[String] {
        &[]
    }
}

/// Parse result information trait.
pub trait ParseResultInfo {
    type Dependency: DependencyInfo;

    /// All dependencies found in the manifest.
    fn dependencies(&self) -> &[Self::Dependency];

    /// Workspace root path (for monorepo support).
    fn workspace_root(&self) -> Option<&std::path::Path>;
}

/// Dependency source (shared across ecosystems).
#[derive(Debug, Clone, PartialEq)]
pub enum DependencySource {
    /// Dependency from default registry (crates.io, npm, PyPI).
    Registry,
    /// Dependency from Git repository.
    Git { url: String, rev: Option<String> },
    /// Dependency from local filesystem path.
    Path { path: String },
}
