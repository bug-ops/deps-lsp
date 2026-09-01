use dashmap::DashMap;
use std::sync::Arc;
use tower_lsp_server::ls_types::Uri;

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
    /// Map from lowercased file extension (e.g. ".csproj") to ecosystem ID.
    ///
    /// Consulted only when an exact `filename_map` lookup misses. Kept as a
    /// separate `DashMap` rather than folded into `filename_map` so extension
    /// routing cannot silently shadow an exact filename. Two ecosystems
    /// claiming the same extension is a configuration error caught by a
    /// `debug_assert!` in [`register`](EcosystemRegistry::register) — in a
    /// release build (or if the assertion is otherwise skipped) `DashMap::insert`
    /// silently last-write-wins, so the outcome is registration-order-dependent,
    /// not deterministic.
    extension_map: DashMap<&'static str, &'static str>,
    /// Map from a basename pattern (e.g. `"requirements*.txt"`) to
    /// `(prefix, suffix, ecosystem_id)`, split on the pattern's single `*` at
    /// [`register`](EcosystemRegistry::register) time. Consulted between the
    /// exact-filename and extension stages in
    /// [`get_for_filename`](EcosystemRegistry::get_for_filename), using
    /// most-specific-wins selection over all matches for determinism
    /// regardless of `DashMap` iteration order.
    patterns: DashMap<&'static str, (&'static str, &'static str, &'static str)>,
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
            extension_map: DashMap::new(),
            patterns: DashMap::new(),
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

        // Register extension mappings (fallback for unbounded basenames, e.g. *.csproj)
        for extension in ecosystem.manifest_extensions() {
            debug_assert!(
                self.extension_map
                    .get(extension)
                    .is_none_or(|owner| *owner == id),
                "extension {extension:?} already claimed by ecosystem {:?}, cannot also assign it to {id:?}",
                self.extension_map.get(extension).map(|o| *o),
            );
            self.extension_map.insert(*extension, id);
        }

        // Register pattern mappings (e.g. `requirements*.txt`)
        for &pattern in ecosystem.manifest_patterns() {
            let Some((prefix, suffix)) = pattern.split_once('*') else {
                debug_assert!(
                    false,
                    "manifest pattern {pattern:?} must contain exactly one '*'"
                );
                continue;
            };
            debug_assert!(
                !prefix.is_empty() || !suffix.is_empty(),
                "manifest pattern {pattern:?} must not be a bare '*', which would claim every file"
            );
            debug_assert!(
                !suffix.contains('*'),
                "manifest pattern {pattern:?} must contain exactly one '*'"
            );
            debug_assert!(
                self.patterns
                    .iter()
                    .all(|e| e.value().2 == id || *e.key() == pattern),
                "pattern {pattern:?} would introduce a second ecosystem ({id:?}) into the \
                 single-owner pattern set; the most-specific-wins selection in \
                 get_for_filename assumes all patterns belong to one ecosystem"
            );
            self.patterns.insert(pattern, (prefix, suffix, id));
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
    /// Lookup is two-stage: an exact, case-sensitive match against
    /// registered manifest filenames (e.g. `"Cargo.toml"`) is tried first;
    /// if that misses, the filename's extension is matched case-insensitively
    /// against registered [`Ecosystem::manifest_extensions`]. This asymmetry
    /// is deliberate — exact filenames are canonical and case-sensitive on
    /// Unix filesystems, while extensions on unbounded basenames (e.g.
    /// `*.csproj`) come from MSBuild/Windows projects that commonly vary
    /// case (`MyApp.CSPROJ`). So `MyApp.CSPROJ` routes via the extension
    /// fallback, but `packages.Config` does **not** match the exact-name
    /// entry for `packages.config`.
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
        if let Some(id) = self.filename_map.get(filename) {
            return self.get(*id);
        }

        if let Some(id) = self.match_pattern(filename) {
            return self.get(id);
        }

        // Avoid the rsplit_once/format! allocation below when no ecosystem has registered
        // an extension (extension routing is only used by nuget today) — this runs on
        // every exact-match miss, including every did_open/did_change via get_for_uri.
        if self.extension_map.is_empty() {
            return None;
        }

        let (_, extension) = filename.rsplit_once('.')?;
        let lowercased = format!(".{}", extension.to_lowercase());
        let id = self.extension_map.get(lowercased.as_str())?;
        self.get(*id)
    }

    /// Matches `filename` against registered [`Ecosystem::manifest_patterns`],
    /// case-sensitively, returning the ecosystem id of the most specific
    /// match (greatest `prefix.len() + suffix.len()`, ties broken by pattern
    /// string ascending) rather than the first `DashMap` hit — so the result
    /// is deterministic regardless of map iteration order.
    fn match_pattern(&self, filename: &str) -> Option<&'static str> {
        if self.patterns.is_empty() {
            return None;
        }

        let mut best: Option<(usize, &'static str, &'static str)> = None; // (specificity, pattern, id)
        for e in self.patterns.iter() {
            let (prefix, suffix, id) = *e.value();
            if filename.len() >= prefix.len() + suffix.len()
                && filename.starts_with(prefix)
                && filename.ends_with(suffix)
            {
                let score = prefix.len() + suffix.len();
                let pattern = *e.key();
                if best.is_none_or(|(s, p, _)| (score, pattern) > (s, p)) {
                    best = Some((score, pattern, id));
                }
            }
        }

        best.map(|(_, _, id)| id)
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
    /// use tower_lsp_server::ls_types::Uri;
    ///
    /// let registry = EcosystemRegistry::new();
    /// let uri = Uri::from_file_path("/home/user/project/Cargo.toml").unwrap();
    ///
    /// if let Some(ecosystem) = registry.get_for_uri(&uri) {
    ///     println!("File handled by: {}", ecosystem.display_name());
    /// }
    /// ```
    // TODO(critic): support requirements/*.txt layout (needs path, not basename)
    pub fn get_for_uri(&self, uri: &Uri) -> Option<Arc<dyn Ecosystem>> {
        let path = uri.path().as_str();
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

    /// Get ecosystem for a lock file name
    ///
    /// # Arguments
    ///
    /// * `filename` - Lock file name (e.g., "Cargo.lock", "package-lock.json")
    ///
    /// # Returns
    ///
    /// * `Some(Arc<dyn Ecosystem>)` - Ecosystem using this lock file
    /// * `None` - No ecosystem uses this lock file
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use deps_core::EcosystemRegistry;
    ///
    /// let registry = EcosystemRegistry::new();
    /// // registry.register(cargo_ecosystem);
    ///
    /// if let Some(ecosystem) = registry.get_for_lockfile("Cargo.lock") {
    ///     println!("Cargo.lock handled by: {}", ecosystem.display_name());
    /// }
    /// ```
    pub fn get_for_lockfile(&self, filename: &str) -> Option<Arc<dyn Ecosystem>> {
        for entry in self.ecosystems.iter() {
            let ecosystem = entry.value();
            if ecosystem.lockfile_filenames().contains(&filename) {
                return Some(Arc::clone(ecosystem));
            }
        }
        None
    }

    /// Get all lock file patterns for file watching
    ///
    /// Returns glob patterns (e.g., "**/Cargo.lock") for all registered ecosystems.
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
    /// let patterns = registry.all_lockfile_patterns();
    /// for pattern in patterns {
    ///     println!("Watching pattern: {}", pattern);
    /// }
    /// ```
    pub fn all_lockfile_patterns(&self) -> Vec<String> {
        let mut patterns = Vec::new();
        for entry in self.ecosystems.iter() {
            let ecosystem = entry.value();
            for filename in ecosystem.lockfile_filenames() {
                patterns.push(format!("**/{}", filename));
            }
        }
        patterns
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
    use std::any::Any;
    use tower_lsp_server::ls_types::Position;

    use crate::{
        PackageName, ParseResult, Registry, completion::Completions,
        lsp_helpers::EcosystemFormatter,
    };

    struct MockFormatter;
    impl EcosystemFormatter for MockFormatter {
        fn format_version_for_text_edit(&self, version: &str) -> String {
            version.to_string()
        }
        fn package_url(&self, name: &PackageName) -> String {
            format!("https://example.com/{name}")
        }
    }

    // Mock ecosystem for testing
    struct MockEcosystem {
        id: &'static str,
        display_name: &'static str,
        filenames: &'static [&'static str],
        lockfiles: &'static [&'static str],
    }

    impl crate::ecosystem::private::Sealed for MockEcosystem {}

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

        fn lockfile_filenames(&self) -> &[&'static str] {
            self.lockfiles
        }

        fn parse_manifest<'a>(
            &'a self,
            _content: &'a str,
            _uri: &'a Uri,
        ) -> crate::ecosystem::BoxFuture<'a, crate::error::Result<Box<dyn ParseResult>>> {
            Box::pin(async move { unimplemented!() })
        }

        fn registry(&self) -> Arc<dyn Registry> {
            unimplemented!()
        }

        fn formatter(&self) -> &dyn EcosystemFormatter {
            &MockFormatter
        }

        fn generate_completions<'a>(
            &'a self,
            _parse_result: &'a dyn ParseResult,
            _position: Position,
            _content: &'a str,
            _freshness: crate::FreshnessSettings,
        ) -> crate::ecosystem::BoxFuture<'a, Completions> {
            Box::pin(async move { Completions::default() })
        }

        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    // Mock ecosystem with unbounded-basename extension routing (mirrors NuGet's *.csproj)
    struct MockExtEcosystem {
        id: &'static str,
        filenames: &'static [&'static str],
        extensions: &'static [&'static str],
    }

    impl crate::ecosystem::private::Sealed for MockExtEcosystem {}

    impl Ecosystem for MockExtEcosystem {
        fn id(&self) -> &'static str {
            self.id
        }

        fn display_name(&self) -> &'static str {
            self.id
        }

        fn manifest_filenames(&self) -> &[&'static str] {
            self.filenames
        }

        fn manifest_extensions(&self) -> &[&'static str] {
            self.extensions
        }

        fn parse_manifest<'a>(
            &'a self,
            _content: &'a str,
            _uri: &'a Uri,
        ) -> crate::ecosystem::BoxFuture<'a, crate::error::Result<Box<dyn ParseResult>>> {
            Box::pin(async move { unimplemented!() })
        }

        fn registry(&self) -> Arc<dyn Registry> {
            unimplemented!()
        }

        fn formatter(&self) -> &dyn EcosystemFormatter {
            &MockFormatter
        }

        fn generate_completions<'a>(
            &'a self,
            _parse_result: &'a dyn ParseResult,
            _position: Position,
            _content: &'a str,
            _freshness: crate::FreshnessSettings,
        ) -> crate::ecosystem::BoxFuture<'a, Completions> {
            Box::pin(async move { Completions::default() })
        }

        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    // Mock ecosystem with basename patterns (mirrors PyPI's `requirements*.txt`)
    struct MockPatternEcosystem {
        id: &'static str,
        patterns: &'static [&'static str],
    }

    impl crate::ecosystem::private::Sealed for MockPatternEcosystem {}

    impl Ecosystem for MockPatternEcosystem {
        fn id(&self) -> &'static str {
            self.id
        }

        fn display_name(&self) -> &'static str {
            self.id
        }

        fn manifest_filenames(&self) -> &[&'static str] {
            &[]
        }

        fn manifest_patterns(&self) -> &[&'static str] {
            self.patterns
        }

        fn parse_manifest<'a>(
            &'a self,
            _content: &'a str,
            _uri: &'a Uri,
        ) -> crate::ecosystem::BoxFuture<'a, crate::error::Result<Box<dyn ParseResult>>> {
            Box::pin(async move { unimplemented!() })
        }

        fn registry(&self) -> Arc<dyn Registry> {
            unimplemented!()
        }

        fn formatter(&self) -> &dyn EcosystemFormatter {
            &MockFormatter
        }

        fn generate_completions<'a>(
            &'a self,
            _parse_result: &'a dyn ParseResult,
            _position: Position,
            _content: &'a str,
            _freshness: crate::FreshnessSettings,
        ) -> crate::ecosystem::BoxFuture<'a, Completions> {
            Box::pin(async move { Completions::default() })
        }

        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    fn pypi_pattern_registry() -> EcosystemRegistry {
        let registry = EcosystemRegistry::new();
        registry.register(Arc::new(MockPatternEcosystem {
            id: "pypi",
            patterns: &[
                "requirements*.txt",
                "*-requirements.txt",
                "*.requirements.txt",
                "constraints*.txt",
            ],
        }));
        registry
    }

    #[test]
    fn test_get_for_filename_pattern_matches_requirements_variants() {
        let registry = pypi_pattern_registry();
        for name in [
            "requirements.txt",
            "requirements-dev.txt",
            "requirements.dev.txt",
            "requirements_test.txt",
            "dev-requirements.txt",
            "test.requirements.txt",
            "constraints.txt",
            "constraints-prod.txt",
        ] {
            assert_eq!(
                registry.get_for_filename(name).map(|e| e.id()),
                Some("pypi"),
                "{name} should match a PyPI pattern"
            );
        }
    }

    #[test]
    fn test_get_for_filename_pattern_does_not_match_unrelated_files() {
        let registry = pypi_pattern_registry();
        for name in [
            "notes.txt",
            "LICENSE.txt",
            "myrequirements.txt",
            "requirements.txt.bak",
            "Requirements.txt",
            "requirements",
        ] {
            assert!(
                registry.get_for_filename(name).is_none(),
                "{name} should not match any PyPI pattern"
            );
        }
    }

    #[test]
    fn test_get_for_filename_exact_name_wins_over_pattern() {
        let registry = EcosystemRegistry::new();
        registry.register(Arc::new(MockEcosystem {
            id: "exact",
            display_name: "Exact",
            filenames: &["requirements.txt"],
            lockfiles: &[],
        }));
        registry.register(Arc::new(MockPatternEcosystem {
            id: "pattern",
            patterns: &["requirements*.txt"],
        }));

        assert_eq!(
            registry.get_for_filename("requirements.txt").unwrap().id(),
            "exact"
        );
    }

    #[test]
    fn test_get_for_filename_pattern_wins_over_extension() {
        let registry = EcosystemRegistry::new();
        registry.register(Arc::new(MockExtEcosystem {
            id: "ext",
            filenames: &[],
            extensions: &[".txt"],
        }));
        registry.register(Arc::new(MockPatternEcosystem {
            id: "pattern",
            patterns: &["requirements*.txt"],
        }));

        assert_eq!(
            registry.get_for_filename("requirements.txt").unwrap().id(),
            "pattern"
        );
    }

    #[test]
    fn test_get_for_filename_pattern_most_specific_wins_deterministically() {
        let registry = pypi_pattern_registry();
        // Matches both `requirements*.txt` (score 16) and `*.requirements.txt`
        // (score 17) — the longer, more specific pattern must win.
        assert_eq!(
            registry
                .get_for_filename("requirements.requirements.txt")
                .unwrap()
                .id(),
            "pypi"
        );
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
            lockfiles: &[],
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
            lockfiles: &[],
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
            lockfiles: &[],
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
            lockfiles: &[],
        });

        registry.register(ecosystem);

        let uri = crate::test_util::test_uri("/home/user/project/test.toml");
        let retrieved = registry.get_for_uri(&uri).unwrap();
        assert_eq!(retrieved.id(), "test");

        let unknown_uri = crate::test_util::test_uri("/home/user/project/unknown.toml");
        assert!(registry.get_for_uri(&unknown_uri).is_none());
    }

    #[test]
    fn test_multiple_ecosystems() {
        let registry = EcosystemRegistry::new();

        let eco1 = Arc::new(MockEcosystem {
            id: "cargo",
            display_name: "Cargo",
            filenames: &["Cargo.toml"],
            lockfiles: &["Cargo.lock"],
        });

        let eco2 = Arc::new(MockEcosystem {
            id: "npm",
            display_name: "npm",
            filenames: &["package.json"],
            lockfiles: &["package-lock.json"],
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

    #[test]
    fn test_get_for_lockfile() {
        let registry = EcosystemRegistry::new();
        let ecosystem = Arc::new(MockEcosystem {
            id: "cargo",
            display_name: "Cargo",
            filenames: &["Cargo.toml"],
            lockfiles: &["Cargo.lock"],
        });

        registry.register(ecosystem);

        let retrieved = registry.get_for_lockfile("Cargo.lock").unwrap();
        assert_eq!(retrieved.id(), "cargo");
        assert_eq!(retrieved.display_name(), "Cargo");

        // Unknown lockfile should return None
        assert!(registry.get_for_lockfile("unknown.lock").is_none());
    }

    #[test]
    fn test_get_for_lockfile_multiple_lockfiles() {
        let registry = EcosystemRegistry::new();
        let ecosystem = Arc::new(MockEcosystem {
            id: "pypi",
            display_name: "PyPI",
            filenames: &["pyproject.toml"],
            lockfiles: &["poetry.lock", "uv.lock"],
        });

        registry.register(ecosystem);

        let retrieved1 = registry.get_for_lockfile("poetry.lock").unwrap();
        assert_eq!(retrieved1.id(), "pypi");

        let retrieved2 = registry.get_for_lockfile("uv.lock").unwrap();
        assert_eq!(retrieved2.id(), "pypi");
    }

    #[test]
    fn test_all_lockfile_patterns_empty() {
        let registry = EcosystemRegistry::new();
        assert!(registry.all_lockfile_patterns().is_empty());
    }

    #[test]
    fn test_all_lockfile_patterns_single_ecosystem() {
        let registry = EcosystemRegistry::new();
        let ecosystem = Arc::new(MockEcosystem {
            id: "cargo",
            display_name: "Cargo",
            filenames: &["Cargo.toml"],
            lockfiles: &["Cargo.lock"],
        });

        registry.register(ecosystem);

        let patterns = registry.all_lockfile_patterns();
        assert_eq!(patterns.len(), 1);
        assert_eq!(patterns[0], "**/Cargo.lock");
    }

    #[test]
    fn test_all_lockfile_patterns_multiple_ecosystems() {
        let registry = EcosystemRegistry::new();

        let eco1 = Arc::new(MockEcosystem {
            id: "cargo",
            display_name: "Cargo",
            filenames: &["Cargo.toml"],
            lockfiles: &["Cargo.lock"],
        });

        let eco2 = Arc::new(MockEcosystem {
            id: "npm",
            display_name: "npm",
            filenames: &["package.json"],
            lockfiles: &["package-lock.json"],
        });

        let eco3 = Arc::new(MockEcosystem {
            id: "pypi",
            display_name: "PyPI",
            filenames: &["pyproject.toml"],
            lockfiles: &["poetry.lock", "uv.lock"],
        });

        registry.register(eco1);
        registry.register(eco2);
        registry.register(eco3);

        let patterns = registry.all_lockfile_patterns();
        assert_eq!(patterns.len(), 4);
        assert!(patterns.contains(&"**/Cargo.lock".to_string()));
        assert!(patterns.contains(&"**/package-lock.json".to_string()));
        assert!(patterns.contains(&"**/poetry.lock".to_string()));
        assert!(patterns.contains(&"**/uv.lock".to_string()));
    }

    #[test]
    fn test_all_lockfile_patterns_no_lockfiles() {
        let registry = EcosystemRegistry::new();
        let ecosystem = Arc::new(MockEcosystem {
            id: "test",
            display_name: "Test",
            filenames: &["test.toml"],
            lockfiles: &[],
        });

        registry.register(ecosystem);

        let patterns = registry.all_lockfile_patterns();
        assert!(patterns.is_empty());
    }

    #[test]
    fn test_get_for_filename_extension_fallback() {
        let registry = EcosystemRegistry::new();
        registry.register(Arc::new(MockExtEcosystem {
            id: "nuget",
            filenames: &["Directory.Packages.props"],
            extensions: &[".csproj", ".fsproj"],
        }));

        assert_eq!(
            registry.get_for_filename("MyApp.csproj").unwrap().id(),
            "nuget"
        );
        assert_eq!(
            registry
                .get_for_filename("Directory.Packages.props")
                .unwrap()
                .id(),
            "nuget"
        );
        assert!(registry.get_for_filename("unrelated.txt").is_none());
    }

    #[test]
    fn test_get_for_filename_extension_fallback_case_insensitive() {
        let registry = EcosystemRegistry::new();
        registry.register(Arc::new(MockExtEcosystem {
            id: "nuget",
            filenames: &["Directory.Packages.props"],
            extensions: &[".csproj"],
        }));

        assert_eq!(
            registry.get_for_filename("MyApp.CSPROJ").unwrap().id(),
            "nuget"
        );
    }

    #[test]
    fn test_get_for_filename_exact_match_case_sensitive_not_shadowed_by_extension() {
        let registry = EcosystemRegistry::new();
        registry.register(Arc::new(MockExtEcosystem {
            id: "nuget",
            filenames: &["packages.config"],
            extensions: &[],
        }));

        // Exact filenames stay case-sensitive: differently-cased basename does not match.
        assert!(registry.get_for_filename("packages.Config").is_none());
    }

    #[test]
    fn test_get_for_filename_no_extension_returns_none() {
        let registry = EcosystemRegistry::new();
        registry.register(Arc::new(MockExtEcosystem {
            id: "nuget",
            filenames: &[],
            extensions: &[".csproj"],
        }));

        assert!(registry.get_for_filename("README").is_none());
    }
}
