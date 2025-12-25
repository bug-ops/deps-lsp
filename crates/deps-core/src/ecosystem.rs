use async_trait::async_trait;
use std::any::Any;
use std::sync::Arc;
use tower_lsp_server::ls_types::{
    CodeAction, CompletionItem, Diagnostic, Hover, InlayHint, Position, Uri,
};

use crate::Registry;

/// Parse result trait containing dependencies and metadata.
///
/// Implementations hold ecosystem-specific dependency types
/// but expose them through trait object interfaces.
pub trait ParseResult: Send + Sync {
    /// All dependencies found in the manifest
    fn dependencies(&self) -> Vec<&dyn Dependency>;

    /// Workspace root path (for monorepo support)
    fn workspace_root(&self) -> Option<&std::path::Path>;

    /// Document URI
    fn uri(&self) -> &Uri;

    /// Downcast to concrete type for ecosystem-specific operations
    fn as_any(&self) -> &dyn Any;
}

/// Generic dependency trait.
///
/// All parsed dependencies must implement this for generic handler access.
pub trait Dependency: Send + Sync {
    /// Package name
    fn name(&self) -> &str;

    /// LSP range of the dependency name
    fn name_range(&self) -> tower_lsp_server::ls_types::Range;

    /// Version requirement string (e.g., "^1.0", ">=2.0")
    fn version_requirement(&self) -> Option<&str>;

    /// LSP range of the version string
    fn version_range(&self) -> Option<tower_lsp_server::ls_types::Range>;

    /// Dependency source (registry, git, path)
    fn source(&self) -> crate::parser::DependencySource;

    /// Feature flags (ecosystem-specific, empty if not supported)
    fn features(&self) -> &[String] {
        &[]
    }

    /// Downcast to concrete type
    fn as_any(&self) -> &dyn Any;
}

/// Configuration for LSP inlay hints feature.
#[derive(Debug, Clone)]
pub struct EcosystemConfig {
    /// Whether to show inlay hints for up-to-date dependencies
    pub show_up_to_date_hints: bool,
    /// Text to display for up-to-date dependencies
    pub up_to_date_text: String,
    /// Text to display for dependencies needing updates (use {} for version placeholder)
    pub needs_update_text: String,
}

impl Default for EcosystemConfig {
    fn default() -> Self {
        Self {
            show_up_to_date_hints: true,
            up_to_date_text: "✅".to_string(),
            needs_update_text: "❌ {}".to_string(),
        }
    }
}

/// Main trait that all ecosystem implementations must implement.
///
/// Each ecosystem (Cargo, npm, PyPI, etc.) provides its own implementation.
/// This trait defines the contract for parsing manifests, fetching registry data,
/// and generating LSP responses.
///
/// # Type Erasure
///
/// This trait uses `Box<dyn Trait>` instead of associated types to allow
/// runtime polymorphism and dynamic ecosystem registration.
///
/// # Examples
///
/// ```no_run
/// use deps_core::{Ecosystem, ParseResult, Registry, EcosystemConfig};
/// use async_trait::async_trait;
/// use std::sync::Arc;
/// use std::any::Any;
/// use tower_lsp_server::ls_types::{Uri, InlayHint, Hover, CodeAction, Diagnostic, CompletionItem, Position};
///
/// struct MyEcosystem {
///     registry: Arc<dyn Registry>,
/// }
///
/// #[async_trait]
/// impl Ecosystem for MyEcosystem {
///     fn id(&self) -> &'static str {
///         "my-ecosystem"
///     }
///
///     fn display_name(&self) -> &'static str {
///         "My Ecosystem"
///     }
///
///     fn manifest_filenames(&self) -> &[&'static str] {
///         &["my-manifest.toml"]
///     }
///
///     async fn parse_manifest(
///         &self,
///         content: &str,
///         uri: &Uri,
///     ) -> deps_core::error::Result<Box<dyn ParseResult>> {
///         // Implementation here
///         todo!()
///     }
///
///     fn registry(&self) -> Arc<dyn Registry> {
///         self.registry.clone()
///     }
///
///     async fn generate_inlay_hints(
///         &self,
///         parse_result: &dyn ParseResult,
///         cached_versions: &std::collections::HashMap<String, String>,
///         resolved_versions: &std::collections::HashMap<String, String>,
///         config: &EcosystemConfig,
///     ) -> Vec<InlayHint> {
///         let _ = resolved_versions; // Use resolved versions for lock file support
///         vec![]
///     }
///
///     async fn generate_hover(
///         &self,
///         parse_result: &dyn ParseResult,
///         position: Position,
///         cached_versions: &std::collections::HashMap<String, String>,
///         resolved_versions: &std::collections::HashMap<String, String>,
///     ) -> Option<Hover> {
///         let _ = resolved_versions; // Use resolved versions for lock file support
///         None
///     }
///
///     async fn generate_code_actions(
///         &self,
///         parse_result: &dyn ParseResult,
///         position: Position,
///         cached_versions: &std::collections::HashMap<String, String>,
///         uri: &Uri,
///     ) -> Vec<CodeAction> {
///         vec![]
///     }
///
///     async fn generate_diagnostics(
///         &self,
///         parse_result: &dyn ParseResult,
///         cached_versions: &std::collections::HashMap<String, String>,
///         uri: &Uri,
///     ) -> Vec<Diagnostic> {
///         vec![]
///     }
///
///     async fn generate_completions(
///         &self,
///         parse_result: &dyn ParseResult,
///         position: Position,
///         content: &str,
///     ) -> Vec<CompletionItem> {
///         vec![]
///     }
///
///     fn as_any(&self) -> &dyn Any {
///         self
///     }
/// }
/// ```
#[async_trait]
pub trait Ecosystem: Send + Sync {
    /// Unique identifier (e.g., "cargo", "npm", "pypi")
    ///
    /// This identifier is used for ecosystem registration and routing.
    fn id(&self) -> &'static str;

    /// Human-readable name (e.g., "Cargo (Rust)", "npm (JavaScript)")
    ///
    /// This name is displayed in diagnostic messages and logs.
    fn display_name(&self) -> &'static str;

    /// Manifest filenames this ecosystem handles (e.g., ["Cargo.toml"])
    ///
    /// The ecosystem registry uses these filenames to route file URIs
    /// to the appropriate ecosystem implementation.
    fn manifest_filenames(&self) -> &[&'static str];

    /// Lock file filenames this ecosystem uses (e.g., ["Cargo.lock"])
    ///
    /// Used for file watching - LSP will monitor changes to these files
    /// and refresh UI when they change. Returns empty slice if ecosystem
    /// doesn't use lock files.
    ///
    /// # Default Implementation
    ///
    /// Returns empty slice by default, indicating no lock files are used.
    fn lockfile_filenames(&self) -> &[&'static str] {
        &[]
    }

    /// Parse a manifest file and return parsed result
    ///
    /// # Arguments
    ///
    /// * `content` - Raw file content
    /// * `uri` - Document URI for position tracking
    ///
    /// # Errors
    ///
    /// Returns error if manifest cannot be parsed
    async fn parse_manifest(
        &self,
        content: &str,
        uri: &Uri,
    ) -> crate::error::Result<Box<dyn ParseResult>>;

    /// Get the registry client for this ecosystem
    ///
    /// The registry provides version lookup and package search capabilities.
    fn registry(&self) -> Arc<dyn Registry>;

    /// Get the lock file provider for this ecosystem.
    ///
    /// Returns `None` if the ecosystem doesn't support lock files.
    /// Lock files provide resolved dependency versions without network requests.
    fn lockfile_provider(&self) -> Option<Arc<dyn crate::lockfile::LockFileProvider>> {
        None
    }

    /// Generate inlay hints for the document
    ///
    /// Inlay hints show additional version information inline in the editor.
    ///
    /// # Arguments
    ///
    /// * `parse_result` - Parsed dependencies from manifest
    /// * `cached_versions` - Pre-fetched version information (name -> latest version from registry)
    /// * `resolved_versions` - Resolved versions from lock file (name -> locked version)
    /// * `config` - User configuration for hint display
    async fn generate_inlay_hints(
        &self,
        parse_result: &dyn ParseResult,
        cached_versions: &std::collections::HashMap<String, String>,
        resolved_versions: &std::collections::HashMap<String, String>,
        config: &EcosystemConfig,
    ) -> Vec<InlayHint>;

    /// Generate hover information for a position
    ///
    /// Shows package information when hovering over a dependency name or version.
    ///
    /// # Arguments
    ///
    /// * `parse_result` - Parsed dependencies from manifest
    /// * `position` - Cursor position in document
    /// * `cached_versions` - Pre-fetched latest version information from registry
    /// * `resolved_versions` - Resolved versions from lock file (takes precedence for "Current" display)
    async fn generate_hover(
        &self,
        parse_result: &dyn ParseResult,
        position: Position,
        cached_versions: &std::collections::HashMap<String, String>,
        resolved_versions: &std::collections::HashMap<String, String>,
    ) -> Option<Hover>;

    /// Generate code actions for a position
    ///
    /// Code actions provide quick fixes like "Update to latest version".
    ///
    /// # Arguments
    ///
    /// * `parse_result` - Parsed dependencies from manifest
    /// * `position` - Cursor position in document
    /// * `cached_versions` - Pre-fetched version information
    /// * `uri` - Document URI for workspace edits
    async fn generate_code_actions(
        &self,
        parse_result: &dyn ParseResult,
        position: Position,
        cached_versions: &std::collections::HashMap<String, String>,
        uri: &Uri,
    ) -> Vec<CodeAction>;

    /// Generate diagnostics for the document
    ///
    /// Diagnostics highlight issues like outdated dependencies or unknown packages.
    ///
    /// # Arguments
    ///
    /// * `parse_result` - Parsed dependencies from manifest
    /// * `cached_versions` - Pre-fetched version information
    /// * `uri` - Document URI for diagnostic reporting
    async fn generate_diagnostics(
        &self,
        parse_result: &dyn ParseResult,
        cached_versions: &std::collections::HashMap<String, String>,
        uri: &Uri,
    ) -> Vec<Diagnostic>;

    /// Generate completions for a position
    ///
    /// Provides autocomplete suggestions for package names and versions.
    ///
    /// # Arguments
    ///
    /// * `parse_result` - Parsed dependencies from manifest
    /// * `position` - Cursor position in document
    /// * `content` - Full document content for context analysis
    async fn generate_completions(
        &self,
        parse_result: &dyn ParseResult,
        position: Position,
        content: &str,
    ) -> Vec<CompletionItem>;

    /// Support for downcasting to concrete ecosystem type
    ///
    /// This allows ecosystem-specific operations when needed.
    fn as_any(&self) -> &dyn Any;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ecosystem_config_default() {
        let config = EcosystemConfig::default();
        assert!(config.show_up_to_date_hints);
        assert_eq!(config.up_to_date_text, "✅");
        assert_eq!(config.needs_update_text, "❌ {}");
    }

    #[test]
    fn test_ecosystem_config_custom() {
        let config = EcosystemConfig {
            show_up_to_date_hints: false,
            up_to_date_text: "OK".to_string(),
            needs_update_text: "Update to {}".to_string(),
        };
        assert!(!config.show_up_to_date_hints);
        assert_eq!(config.up_to_date_text, "OK");
        assert_eq!(config.needs_update_text, "Update to {}");
    }

    #[test]
    fn test_ecosystem_config_clone() {
        let config1 = EcosystemConfig::default();
        let config2 = config1.clone();
        assert_eq!(config1.up_to_date_text, config2.up_to_date_text);
        assert_eq!(config1.show_up_to_date_hints, config2.show_up_to_date_hints);
        assert_eq!(config1.needs_update_text, config2.needs_update_text);
    }

    #[test]
    fn test_dependency_default_features() {
        struct MockDep;
        impl Dependency for MockDep {
            fn name(&self) -> &str {
                "test"
            }
            fn name_range(&self) -> tower_lsp_server::ls_types::Range {
                tower_lsp_server::ls_types::Range::default()
            }
            fn version_requirement(&self) -> Option<&str> {
                None
            }
            fn version_range(&self) -> Option<tower_lsp_server::ls_types::Range> {
                None
            }
            fn source(&self) -> crate::parser::DependencySource {
                crate::parser::DependencySource::Registry
            }
            fn as_any(&self) -> &dyn std::any::Any {
                self
            }
        }

        let dep = MockDep;
        assert_eq!(dep.features(), &[] as &[String]);
    }
}
