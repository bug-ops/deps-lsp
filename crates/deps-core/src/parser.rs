use crate::error::Result;
use tower_lsp::lsp_types::{Range, Url};

/// Generic manifest parser interface.
///
/// Implementors parse ecosystem-specific manifest files (Cargo.toml, package.json, etc.)
/// and extract dependency information with precise LSP positions.
///
/// # Note
///
/// This trait is being phased out in favor of the `Ecosystem` trait.
/// New implementations should use `Ecosystem::parse_manifest()` instead.
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
///
/// # Note
///
/// The new `Ecosystem` trait uses `crate::ecosystem::Dependency` instead.
/// This trait is kept for backward compatibility during migration.
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
///
/// # Note
///
/// The new `Ecosystem` trait uses `crate::ecosystem::ParseResult` instead.
/// This trait is kept for backward compatibility during migration.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dependency_source_registry() {
        let source = DependencySource::Registry;
        assert_eq!(source, DependencySource::Registry);
    }

    #[test]
    fn test_dependency_source_git() {
        let source = DependencySource::Git {
            url: "https://github.com/user/repo".into(),
            rev: Some("main".into()),
        };

        match source {
            DependencySource::Git { url, rev } => {
                assert_eq!(url, "https://github.com/user/repo");
                assert_eq!(rev, Some("main".into()));
            }
            _ => panic!("Expected Git source"),
        }
    }

    #[test]
    fn test_dependency_source_git_no_rev() {
        let source = DependencySource::Git {
            url: "https://github.com/user/repo".into(),
            rev: None,
        };

        match source {
            DependencySource::Git { url, rev } => {
                assert_eq!(url, "https://github.com/user/repo");
                assert!(rev.is_none());
            }
            _ => panic!("Expected Git source"),
        }
    }

    #[test]
    fn test_dependency_source_path() {
        let source = DependencySource::Path {
            path: "../local-crate".into(),
        };

        match source {
            DependencySource::Path { path } => {
                assert_eq!(path, "../local-crate");
            }
            _ => panic!("Expected Path source"),
        }
    }

    #[test]
    fn test_dependency_source_clone() {
        let source1 = DependencySource::Git {
            url: "https://example.com/repo".into(),
            rev: Some("v1.0".into()),
        };
        let source2 = source1.clone();

        assert_eq!(source1, source2);
    }

    #[test]
    fn test_dependency_source_equality() {
        let reg1 = DependencySource::Registry;
        let reg2 = DependencySource::Registry;
        assert_eq!(reg1, reg2);

        let git1 = DependencySource::Git {
            url: "https://example.com".into(),
            rev: None,
        };
        let git2 = DependencySource::Git {
            url: "https://example.com".into(),
            rev: None,
        };
        assert_eq!(git1, git2);

        let git3 = DependencySource::Git {
            url: "https://different.com".into(),
            rev: None,
        };
        assert_ne!(git1, git3);
    }

    #[test]
    fn test_dependency_source_debug() {
        let source = DependencySource::Registry;
        let debug = format!("{:?}", source);
        assert_eq!(debug, "Registry");

        let git = DependencySource::Git {
            url: "https://example.com".into(),
            rev: Some("main".into()),
        };
        let git_debug = format!("{:?}", git);
        assert!(git_debug.contains("https://example.com"));
        assert!(git_debug.contains("main"));
    }
}
