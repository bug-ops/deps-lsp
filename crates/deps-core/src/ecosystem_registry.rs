use dashmap::DashMap;
use std::sync::Arc;
use tower_lsp::lsp_types::Url;

use crate::Ecosystem;

/// Registry for all available ecosystems.
///
/// This registry manages ecosystem implementations and provides fast lookup
/// by ecosystem ID or manifest filename. It's designed for thread-safe
/// concurrent access using DashMap.
///
/// # Examples
///
/// ```no_run
/// use deps_core::EcosystemRegistry;
/// use std::sync::Arc;
///
/// let registry = EcosystemRegistry::new();
///
/// // Register ecosystems (would be actual implementations)
/// // registry.register(Arc::new(CargoEcosystem::new(cache.clone())));
/// // registry.register(Arc::new(NpmEcosystem::new(cache.clone())));
///
/// // Look up by filename
/// if let Some(ecosystem) = registry.get_for_filename("Cargo.toml") {
///     println!("Found ecosystem: {}", ecosystem.display_name());
/// }
///
/// // List all registered ecosystems
/// for id in registry.ecosystem_ids() {
///     println!("Registered: {}", id);
/// }
/// ```
pub struct EcosystemRegistry {
    /// Map from ecosystem ID to implementation
    ecosystems: DashMap<&'static str, Arc<dyn Ecosystem>>,
    /// Map from filename to ecosystem ID (for fast lookup)
    filename_map: DashMap<&'static str, &'static str>,
}

impl EcosystemRegistry {
    /// Create a new empty registry
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::EcosystemRegistry;
    ///
    /// let registry = EcosystemRegistry::new();
    /// assert_eq!(registry.ecosystem_ids().len(), 0);
    /// ```
    pub fn new() -> Self {
        Self {
            ecosystems: DashMap::new(),
            filename_map: DashMap::new(),
        }
    }

    /// Register an ecosystem implementation
    ///
    /// This method registers the ecosystem and creates filename mappings
    /// for all manifest filenames declared by the ecosystem.
    ///
    /// # Arguments
    ///
    /// * `ecosystem` - Arc-wrapped ecosystem implementation
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use deps_core::EcosystemRegistry;
    /// use std::sync::Arc;
    ///
    /// let registry = EcosystemRegistry::new();
    /// // registry.register(Arc::new(CargoEcosystem::new(cache)));
    /// ```
    pub fn register(&self, ecosystem: Arc<dyn Ecosystem>) {
        let id = ecosystem.id();

        // Register filename mappings
        for filename in ecosystem.manifest_filenames() {
            self.filename_map.insert(*filename, id);
        }

        // Register ecosystem
        self.ecosystems.insert(id, ecosystem);
    }

    /// Get ecosystem by ID
    ///
    /// # Arguments
    ///
    /// * `id` - Ecosystem identifier (e.g., "cargo", "npm", "pypi")
    ///
    /// # Returns
    ///
    /// * `Some(Arc<dyn Ecosystem>)` - Registered ecosystem
    /// * `None` - No ecosystem registered with this ID
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use deps_core::EcosystemRegistry;
    ///
    /// let registry = EcosystemRegistry::new();
    /// if let Some(ecosystem) = registry.get("cargo") {
    ///     println!("Found: {}", ecosystem.display_name());
    /// }
    /// ```
    pub fn get(&self, id: &str) -> Option<Arc<dyn Ecosystem>> {
        self.ecosystems.get(id).map(|e| Arc::clone(&e))
    }

    /// Get ecosystem for a filename
    ///
    /// # Arguments
    ///
    /// * `filename` - Manifest filename (e.g., "Cargo.toml", "package.json")
    ///
    /// # Returns
    ///
    /// * `Some(Arc<dyn Ecosystem>)` - Ecosystem handling this filename
    /// * `None` - No ecosystem handles this filename
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use deps_core::EcosystemRegistry;
    ///
    /// let registry = EcosystemRegistry::new();
    /// if let Some(ecosystem) = registry.get_for_filename("Cargo.toml") {
    ///     println!("Cargo.toml handled by: {}", ecosystem.display_name());
    /// }
    /// ```
    pub fn get_for_filename(&self, filename: &str) -> Option<Arc<dyn Ecosystem>> {
        let id = self.filename_map.get(filename)?;
        self.get(*id)
    }

    /// Get ecosystem from URI
    ///
    /// Extracts the filename from the URI path and looks up the ecosystem.
    ///
    /// # Arguments
    ///
    /// * `uri` - Document URI (file:///path/to/Cargo.toml)
    ///
    /// # Returns
    ///
    /// * `Some(Arc<dyn Ecosystem>)` - Ecosystem handling this file
    /// * `None` - No ecosystem handles this file type or URI parsing failed
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use deps_core::EcosystemRegistry;
    /// use tower_lsp::lsp_types::Url;
    ///
    /// let registry = EcosystemRegistry::new();
    /// let uri = Url::parse("file:///home/user/project/Cargo.toml").unwrap();
    ///
    /// if let Some(ecosystem) = registry.get_for_uri(&uri) {
    ///     println!("File handled by: {}", ecosystem.display_name());
    /// }
    /// ```
    pub fn get_for_uri(&self, uri: &Url) -> Option<Arc<dyn Ecosystem>> {
        let path = uri.path();
        let filename = path.rsplit('/').next()?;
        self.get_for_filename(filename)
    }

    /// Get all registered ecosystem IDs
    ///
    /// Returns a vector of all ecosystem IDs currently registered.
    /// This is useful for debugging and listing available ecosystems.
    ///
    /// # Returns
    ///
    /// Vector of ecosystem ID strings
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use deps_core::EcosystemRegistry;
    ///
    /// let registry = EcosystemRegistry::new();
    /// // registry.register(cargo_ecosystem);
    /// // registry.register(npm_ecosystem);
    ///
    /// for id in registry.ecosystem_ids() {
    ///     println!("Registered ecosystem: {}", id);
    /// }
    /// ```
    pub fn ecosystem_ids(&self) -> Vec<&'static str> {
        self.ecosystems.iter().map(|e| *e.key()).collect()
    }
}

impl Default for EcosystemRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::any::Any;
    use tower_lsp::lsp_types::{
        CodeAction, CompletionItem, Diagnostic, Hover, InlayHint, Position,
    };

    use crate::{EcosystemConfig, ParseResult, Registry};

    // Mock ecosystem for testing
    struct MockEcosystem {
        id: &'static str,
        display_name: &'static str,
        filenames: &'static [&'static str],
    }

    #[async_trait]
    impl Ecosystem for MockEcosystem {
        fn id(&self) -> &'static str {
            self.id
        }

        fn display_name(&self) -> &'static str {
            self.display_name
        }

        fn manifest_filenames(&self) -> &[&'static str] {
            self.filenames
        }

        async fn parse_manifest(
            &self,
            _content: &str,
            _uri: &Url,
        ) -> crate::error::Result<Box<dyn ParseResult>> {
            unimplemented!()
        }

        fn registry(&self) -> Arc<dyn Registry> {
            unimplemented!()
        }

        async fn generate_inlay_hints(
            &self,
            _parse_result: &dyn ParseResult,
            _cached_versions: &std::collections::HashMap<String, String>,
            _resolved_versions: &std::collections::HashMap<String, String>,
            _config: &EcosystemConfig,
        ) -> Vec<InlayHint> {
            vec![]
        }

        async fn generate_hover(
            &self,
            _parse_result: &dyn ParseResult,
            _position: Position,
            _cached_versions: &std::collections::HashMap<String, String>,
            _resolved_versions: &std::collections::HashMap<String, String>,
        ) -> Option<Hover> {
            None
        }

        async fn generate_code_actions(
            &self,
            _parse_result: &dyn ParseResult,
            _position: Position,
            _cached_versions: &std::collections::HashMap<String, String>,
            _uri: &Url,
        ) -> Vec<CodeAction> {
            vec![]
        }

        async fn generate_diagnostics(
            &self,
            _parse_result: &dyn ParseResult,
            _cached_versions: &std::collections::HashMap<String, String>,
            _uri: &Url,
        ) -> Vec<Diagnostic> {
            vec![]
        }

        async fn generate_completions(
            &self,
            _parse_result: &dyn ParseResult,
            _position: Position,
            _content: &str,
        ) -> Vec<CompletionItem> {
            vec![]
        }

        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    #[test]
    fn test_new_registry_is_empty() {
        let registry = EcosystemRegistry::new();
        assert_eq!(registry.ecosystem_ids().len(), 0);
    }

    #[test]
    fn test_register_ecosystem() {
        let registry = EcosystemRegistry::new();
        let ecosystem = Arc::new(MockEcosystem {
            id: "test",
            display_name: "Test Ecosystem",
            filenames: &["test.toml"],
        });

        registry.register(ecosystem);

        assert_eq!(registry.ecosystem_ids().len(), 1);
        assert!(registry.get("test").is_some());
    }

    #[test]
    fn test_get_by_id() {
        let registry = EcosystemRegistry::new();
        let ecosystem = Arc::new(MockEcosystem {
            id: "test",
            display_name: "Test Ecosystem",
            filenames: &["test.toml"],
        });

        registry.register(ecosystem);

        let retrieved = registry.get("test").unwrap();
        assert_eq!(retrieved.id(), "test");
        assert_eq!(retrieved.display_name(), "Test Ecosystem");
    }

    #[test]
    fn test_get_by_filename() {
        let registry = EcosystemRegistry::new();
        let ecosystem = Arc::new(MockEcosystem {
            id: "test",
            display_name: "Test Ecosystem",
            filenames: &["test.toml", "test.json"],
        });

        registry.register(ecosystem);

        let retrieved1 = registry.get_for_filename("test.toml").unwrap();
        assert_eq!(retrieved1.id(), "test");

        let retrieved2 = registry.get_for_filename("test.json").unwrap();
        assert_eq!(retrieved2.id(), "test");

        assert!(registry.get_for_filename("unknown.toml").is_none());
    }

    #[test]
    fn test_get_by_uri() {
        let registry = EcosystemRegistry::new();
        let ecosystem = Arc::new(MockEcosystem {
            id: "test",
            display_name: "Test Ecosystem",
            filenames: &["test.toml"],
        });

        registry.register(ecosystem);

        let uri = Url::parse("file:///home/user/project/test.toml").unwrap();
        let retrieved = registry.get_for_uri(&uri).unwrap();
        assert_eq!(retrieved.id(), "test");

        let unknown_uri = Url::parse("file:///home/user/project/unknown.toml").unwrap();
        assert!(registry.get_for_uri(&unknown_uri).is_none());
    }

    #[test]
    fn test_multiple_ecosystems() {
        let registry = EcosystemRegistry::new();

        let eco1 = Arc::new(MockEcosystem {
            id: "cargo",
            display_name: "Cargo",
            filenames: &["Cargo.toml"],
        });

        let eco2 = Arc::new(MockEcosystem {
            id: "npm",
            display_name: "npm",
            filenames: &["package.json"],
        });

        registry.register(eco1);
        registry.register(eco2);

        assert_eq!(registry.ecosystem_ids().len(), 2);

        assert_eq!(
            registry.get_for_filename("Cargo.toml").unwrap().id(),
            "cargo"
        );
        assert_eq!(
            registry.get_for_filename("package.json").unwrap().id(),
            "npm"
        );
    }
}
