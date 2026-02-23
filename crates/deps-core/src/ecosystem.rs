use std::any::Any;
use std::pin::Pin;
use std::sync::Arc;
use tower_lsp_server::ls_types::{
    CodeAction, CompletionItem, Diagnostic, Hover, InlayHint, Position, Uri,
};

use crate::{Registry, lsp_helpers::EcosystemFormatter};

pub mod private {
    pub trait Sealed {}
}

pub type BoxFuture<'a, T> = Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

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
    /// Text to display while loading registry data
    pub loading_text: String,
    /// Whether to show loading hints in inlay hints
    pub show_loading_hints: bool,
}

impl Default for EcosystemConfig {
    fn default() -> Self {
        Self {
            show_up_to_date_hints: true,
            up_to_date_text: "✅".to_string(),
            needs_update_text: "❌ {}".to_string(),
            loading_text: "⏳".to_string(),
            show_loading_hints: true,
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
/// use deps_core::lsp_helpers::EcosystemFormatter;
/// use std::sync::Arc;
/// use std::any::Any;
/// use tower_lsp_server::ls_types::{Uri, CompletionItem, Position};
///
/// struct MyFormatter;
/// impl EcosystemFormatter for MyFormatter {
///     fn format_version_for_text_edit(&self, version: &str) -> String { version.to_string() }
///     fn package_url(&self, name: &str) -> String { format!("https://example.com/{name}") }
/// }
///
/// struct MyEcosystem {
///     registry: Arc<dyn Registry>,
///     formatter: MyFormatter,
/// }
///
/// impl deps_core::ecosystem::private::Sealed for MyEcosystem {}
///
/// impl Ecosystem for MyEcosystem {
///     fn id(&self) -> &'static str { "my-ecosystem" }
///     fn display_name(&self) -> &'static str { "My Ecosystem" }
///     fn manifest_filenames(&self) -> &[&'static str] { &["my-manifest.toml"] }
///
///     fn parse_manifest<'a>(
///         &'a self,
///         _content: &'a str,
///         _uri: &'a Uri,
///     ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::error::Result<Box<dyn ParseResult>>> {
///         Box::pin(async move { todo!() })
///     }
///
///     fn registry(&self) -> Arc<dyn Registry> { self.registry.clone() }
///
///     fn formatter(&self) -> &dyn EcosystemFormatter { &self.formatter }
///
///     fn generate_completions<'a>(
///         &'a self,
///         _parse_result: &'a dyn ParseResult,
///         _position: Position,
///         _content: &'a str,
///     ) -> deps_core::ecosystem::BoxFuture<'a, Vec<CompletionItem>> {
///         Box::pin(async move { vec![] })
///     }
///
///     fn as_any(&self) -> &dyn Any { self }
/// }
/// ```
pub trait Ecosystem: Send + Sync + private::Sealed {
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
    fn parse_manifest<'a>(
        &'a self,
        content: &'a str,
        uri: &'a Uri,
    ) -> BoxFuture<'a, crate::error::Result<Box<dyn ParseResult>>>;

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

    /// Get the ecosystem-specific formatter for LSP response generation.
    ///
    /// The formatter handles version comparison, package URLs, and text formatting.
    /// Override this to customize LSP response generation.
    fn formatter(&self) -> &dyn EcosystemFormatter;

    /// Generate inlay hints for the document.
    ///
    /// Default implementation delegates to `lsp_helpers::generate_inlay_hints`
    /// using `self.formatter()`. Override only if custom behavior is needed.
    fn generate_inlay_hints<'a>(
        &'a self,
        parse_result: &'a dyn ParseResult,
        cached_versions: &'a std::collections::HashMap<String, String>,
        resolved_versions: &'a std::collections::HashMap<String, String>,
        loading_state: crate::LoadingState,
        config: &'a EcosystemConfig,
    ) -> BoxFuture<'a, Vec<InlayHint>> {
        Box::pin(async move {
            crate::lsp_helpers::generate_inlay_hints(
                parse_result,
                cached_versions,
                resolved_versions,
                loading_state,
                config,
                self.formatter(),
            )
        })
    }

    /// Generate hover information for a position.
    ///
    /// Default implementation delegates to `lsp_helpers::generate_hover`
    /// using `self.formatter()` and `self.registry()`.
    fn generate_hover<'a>(
        &'a self,
        parse_result: &'a dyn ParseResult,
        position: Position,
        cached_versions: &'a std::collections::HashMap<String, String>,
        resolved_versions: &'a std::collections::HashMap<String, String>,
    ) -> BoxFuture<'a, Option<Hover>> {
        Box::pin(async move {
            let registry = self.registry();
            crate::lsp_helpers::generate_hover(
                parse_result,
                position,
                cached_versions,
                resolved_versions,
                registry.as_ref(),
                self.formatter(),
            )
            .await
        })
    }

    /// Generate code actions for a position.
    ///
    /// Default implementation delegates to `lsp_helpers::generate_code_actions`
    /// using `self.formatter()` and `self.registry()`.
    fn generate_code_actions<'a>(
        &'a self,
        parse_result: &'a dyn ParseResult,
        position: Position,
        _cached_versions: &'a std::collections::HashMap<String, String>,
        uri: &'a Uri,
    ) -> BoxFuture<'a, Vec<CodeAction>> {
        Box::pin(async move {
            let registry = self.registry();
            crate::lsp_helpers::generate_code_actions(
                parse_result,
                position,
                uri,
                registry.as_ref(),
                self.formatter(),
            )
            .await
        })
    }

    /// Generate diagnostics for the document.
    ///
    /// Default implementation delegates to `lsp_helpers::generate_diagnostics_from_cache`
    /// using `self.formatter()`.
    fn generate_diagnostics<'a>(
        &'a self,
        parse_result: &'a dyn ParseResult,
        cached_versions: &'a std::collections::HashMap<String, String>,
        resolved_versions: &'a std::collections::HashMap<String, String>,
        _uri: &'a Uri,
    ) -> BoxFuture<'a, Vec<Diagnostic>> {
        Box::pin(async move {
            crate::lsp_helpers::generate_diagnostics_from_cache(
                parse_result,
                cached_versions,
                resolved_versions,
                self.formatter(),
            )
        })
    }

    /// Generate completions for a position.
    ///
    /// Provides autocomplete suggestions for package names and versions.
    fn generate_completions<'a>(
        &'a self,
        parse_result: &'a dyn ParseResult,
        position: Position,
        content: &'a str,
    ) -> BoxFuture<'a, Vec<CompletionItem>>;

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
            loading_text: "Loading...".to_string(),
            show_loading_hints: false,
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
            fn name(&self) -> &'static str {
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
