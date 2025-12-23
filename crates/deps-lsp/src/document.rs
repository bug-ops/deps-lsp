use dashmap::DashMap;
use deps_cargo::{CargoVersion, ParsedDependency};
use deps_core::HttpCache;
use deps_core::lockfile::LockFileCache;
use deps_npm::{NpmDependency, NpmVersion};
use deps_pypi::{PypiDependency, PypiVersion};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::task::JoinHandle;
use tower_lsp::lsp_types::Url;

/// Unified dependency enum for multi-ecosystem support.
///
/// Wraps ecosystem-specific dependency types to allow storing
/// dependencies from different ecosystems in the same document state.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum UnifiedDependency {
    Cargo(ParsedDependency),
    Npm(NpmDependency),
    Pypi(PypiDependency),
}

impl UnifiedDependency {
    /// Returns the dependency name.
    pub fn name(&self) -> &str {
        match self {
            UnifiedDependency::Cargo(dep) => &dep.name,
            UnifiedDependency::Npm(dep) => &dep.name,
            UnifiedDependency::Pypi(dep) => &dep.name,
        }
    }

    /// Returns the name range for LSP operations.
    pub fn name_range(&self) -> tower_lsp::lsp_types::Range {
        match self {
            UnifiedDependency::Cargo(dep) => dep.name_range,
            UnifiedDependency::Npm(dep) => dep.name_range,
            UnifiedDependency::Pypi(dep) => dep.name_range,
        }
    }

    /// Returns the version requirement string if present.
    pub fn version_req(&self) -> Option<&str> {
        match self {
            UnifiedDependency::Cargo(dep) => dep.version_req.as_deref(),
            UnifiedDependency::Npm(dep) => dep.version_req.as_deref(),
            UnifiedDependency::Pypi(dep) => dep.version_req.as_deref(),
        }
    }

    /// Returns the version range for LSP operations if present.
    pub fn version_range(&self) -> Option<tower_lsp::lsp_types::Range> {
        match self {
            UnifiedDependency::Cargo(dep) => dep.version_range,
            UnifiedDependency::Npm(dep) => dep.version_range,
            UnifiedDependency::Pypi(dep) => dep.version_range,
        }
    }

    /// Returns true if this is a registry dependency (not Git/Path).
    pub fn is_registry(&self) -> bool {
        match self {
            UnifiedDependency::Cargo(dep) => {
                matches!(dep.source, deps_cargo::DependencySource::Registry)
            }
            UnifiedDependency::Npm(_) => true,
            UnifiedDependency::Pypi(dep) => {
                matches!(dep.source, deps_pypi::PypiDependencySource::PyPI)
            }
        }
    }
}

/// Unified version information enum for multi-ecosystem support.
///
/// Wraps ecosystem-specific version types.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum UnifiedVersion {
    Cargo(CargoVersion),
    Npm(NpmVersion),
    Pypi(PypiVersion),
}

impl UnifiedVersion {
    /// Returns the version number as a string.
    pub fn version_string(&self) -> &str {
        match self {
            UnifiedVersion::Cargo(v) => &v.num,
            UnifiedVersion::Npm(v) => &v.version,
            UnifiedVersion::Pypi(v) => &v.version,
        }
    }

    /// Returns true if this version is yanked/deprecated.
    pub fn is_yanked(&self) -> bool {
        match self {
            UnifiedVersion::Cargo(v) => v.yanked,
            UnifiedVersion::Npm(v) => v.deprecated,
            UnifiedVersion::Pypi(v) => v.yanked,
        }
    }
}

// Implement helper traits from deps-core for generic handler support
impl deps_core::VersionStringGetter for UnifiedVersion {
    fn version_string(&self) -> &str {
        self.version_string()
    }
}

impl deps_core::YankedChecker for UnifiedVersion {
    fn is_yanked(&self) -> bool {
        self.is_yanked()
    }
}

/// Package ecosystem type.
///
/// Identifies which package manager and manifest file format
/// a document belongs to. Used for routing LSP operations to
/// the appropriate parser and registry.
///
/// # Examples
///
/// ```
/// use deps_lsp::document::Ecosystem;
///
/// let cargo = Ecosystem::from_filename("Cargo.toml");
/// assert_eq!(cargo, Some(Ecosystem::Cargo));
///
/// let npm = Ecosystem::from_filename("package.json");
/// assert_eq!(npm, Some(Ecosystem::Npm));
///
/// let pypi = Ecosystem::from_filename("pyproject.toml");
/// assert_eq!(pypi, Some(Ecosystem::Pypi));
///
/// let unknown = Ecosystem::from_filename("requirements.txt");
/// assert_eq!(unknown, None);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Ecosystem {
    /// Rust Cargo ecosystem (Cargo.toml)
    Cargo,
    /// JavaScript/TypeScript npm ecosystem (package.json)
    Npm,
    /// Python PyPI ecosystem (pyproject.toml)
    Pypi,
}

impl Ecosystem {
    /// Detects ecosystem from filename.
    ///
    /// Returns `Some(Ecosystem)` if the filename matches a known manifest file,
    /// or `None` if the file is not recognized.
    pub fn from_filename(filename: &str) -> Option<Self> {
        match filename {
            "Cargo.toml" => Some(Self::Cargo),
            "package.json" => Some(Self::Npm),
            "pyproject.toml" => Some(Self::Pypi),
            _ => None,
        }
    }

    /// Detects ecosystem from full URI path.
    ///
    /// Extracts the filename from the URI and checks if it matches a known manifest.
    pub fn from_uri(uri: &Url) -> Option<Self> {
        let path = uri.path();
        let filename = path.split('/').next_back()?;
        Self::from_filename(filename)
    }
}

/// State for a single open document.
///
/// Stores the document content, parsed dependency information, and cached
/// version data for a single file. The state is updated when the document
/// changes or when version information is fetched from the registry.
///
/// Supports multiple package ecosystems (Cargo, npm) with unified dependency
/// and version storage.
///
/// # Examples
///
/// ```no_run
/// use deps_lsp::document::{DocumentState, Ecosystem, UnifiedDependency};
/// use deps_lsp::ParsedDependency;
/// use deps_cargo::{DependencySection, DependencySource};
/// use tower_lsp::lsp_types::{Position, Range};
///
/// let dep = ParsedDependency {
///     name: "serde".into(),
///     name_range: Range::new(Position::new(0, 0), Position::new(0, 5)),
///     version_req: Some("1.0".into()),
///     version_range: Some(Range::new(Position::new(0, 8), Position::new(0, 12))),
///     features: vec![],
///     features_range: None,
///     source: DependencySource::Registry,
///     workspace_inherited: false,
///     section: DependencySection::Dependencies,
/// };
///
/// let state = DocumentState::new(
///     Ecosystem::Cargo,
///     "[dependencies]\nserde = \"1.0\"".into(),
///     vec![UnifiedDependency::Cargo(dep)],
/// );
///
/// assert!(state.versions.is_empty());
/// assert_eq!(state.dependencies.len(), 1);
/// ```
#[derive(Debug, Clone)]
pub struct DocumentState {
    /// Package ecosystem type
    pub ecosystem: Ecosystem,
    /// Original document content
    pub content: String,
    /// Parsed dependencies with positions
    pub dependencies: Vec<UnifiedDependency>,
    /// Cached latest version information from registry (for inlay hints)
    pub versions: HashMap<String, UnifiedVersion>,
    /// Resolved versions from lock file (for hover "Current" display)
    pub resolved_versions: HashMap<String, String>,
    /// Last successful parse time
    pub parsed_at: Instant,
}

impl DocumentState {
    /// Creates a new document state.
    ///
    /// Initializes with the given ecosystem, content, and parsed dependencies.
    /// Version information starts empty and is populated asynchronously.
    pub fn new(
        ecosystem: Ecosystem,
        content: String,
        dependencies: Vec<UnifiedDependency>,
    ) -> Self {
        Self {
            ecosystem,
            content,
            dependencies,
            versions: HashMap::new(),
            resolved_versions: HashMap::new(),
            parsed_at: Instant::now(),
        }
    }

    /// Updates the cached latest version information for dependencies.
    ///
    /// This is called after fetching version data from the registry.
    /// Used for inlay hints to show latest available version.
    pub fn update_versions(&mut self, versions: HashMap<String, UnifiedVersion>) {
        self.versions = versions;
    }

    /// Updates the resolved versions from lock file.
    ///
    /// This is called after parsing the lock file.
    /// Used for hover to show actual installed version.
    pub fn update_resolved_versions(&mut self, versions: HashMap<String, String>) {
        self.resolved_versions = versions;
    }
}

/// Global LSP server state.
///
/// Manages all open documents, HTTP cache, lock file cache, and background
/// tasks for the server. This state is shared across all LSP handlers via
/// `Arc` and uses concurrent data structures (`DashMap`, `RwLock`) for
/// thread-safe access.
///
/// # Examples
///
/// ```
/// use deps_lsp::document::ServerState;
/// use tower_lsp::lsp_types::Url;
///
/// let state = ServerState::new();
/// assert_eq!(state.document_count(), 0);
/// ```
pub struct ServerState {
    /// Open documents by URI
    pub documents: DashMap<Url, DocumentState>,
    /// HTTP cache for registry requests
    pub cache: Arc<HttpCache>,
    /// Lock file cache for parsed lock files
    pub lockfile_cache: Arc<LockFileCache>,
    /// Background task handles
    tasks: tokio::sync::RwLock<HashMap<Url, JoinHandle<()>>>,
}

impl ServerState {
    /// Creates a new server state with default configuration.
    pub fn new() -> Self {
        Self {
            documents: DashMap::new(),
            cache: Arc::new(HttpCache::new()),
            lockfile_cache: Arc::new(LockFileCache::new()),
            tasks: tokio::sync::RwLock::new(HashMap::new()),
        }
    }

    /// Retrieves document state by URI.
    ///
    /// Returns a read-only reference to the document state if it exists.
    /// The reference holds a lock on the internal map, so it should be
    /// dropped as soon as possible.
    pub fn get_document(
        &self,
        uri: &Url,
    ) -> Option<dashmap::mapref::one::Ref<'_, Url, DocumentState>> {
        self.documents.get(uri)
    }

    /// Updates or inserts document state.
    ///
    /// If a document already exists at the given URI, it is replaced.
    /// Otherwise, a new entry is created.
    pub fn update_document(&self, uri: Url, state: DocumentState) {
        self.documents.insert(uri, state);
    }

    /// Removes document state and returns the removed entry.
    ///
    /// Returns `None` if no document exists at the given URI.
    pub fn remove_document(&self, uri: &Url) -> Option<(Url, DocumentState)> {
        self.documents.remove(uri)
    }

    /// Spawns a background task for a document.
    ///
    /// If a task already exists for the given URI, it is aborted before
    /// the new task is registered. This ensures only one background task
    /// runs per document.
    ///
    /// Typical use case: fetching version data asynchronously after
    /// document open or change.
    pub async fn spawn_background_task(&self, uri: Url, task: JoinHandle<()>) {
        let mut tasks = self.tasks.write().await;

        // Cancel existing task if any
        if let Some(old_task) = tasks.remove(&uri) {
            old_task.abort();
        }

        tasks.insert(uri, task);
    }

    /// Cancels the background task for a document.
    ///
    /// If no task exists, this is a no-op.
    pub async fn cancel_background_task(&self, uri: &Url) {
        let mut tasks = self.tasks.write().await;
        if let Some(task) = tasks.remove(uri) {
            task.abort();
        }
    }

    /// Returns the number of open documents.
    pub fn document_count(&self) -> usize {
        self.documents.len()
    }
}

impl Default for ServerState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use deps_cargo::{DependencySection, DependencySource};
    use tower_lsp::lsp_types::{Position, Range};

    fn create_test_cargo_dependency() -> UnifiedDependency {
        UnifiedDependency::Cargo(ParsedDependency {
            name: "serde".into(),
            name_range: Range::new(Position::new(0, 0), Position::new(0, 5)),
            version_req: Some("1.0".into()),
            version_range: Some(Range::new(Position::new(0, 9), Position::new(0, 14))),
            features: vec![],
            features_range: None,
            source: DependencySource::Registry,
            workspace_inherited: false,
            section: DependencySection::Dependencies,
        })
    }

    #[test]
    fn test_ecosystem_from_filename() {
        assert_eq!(
            Ecosystem::from_filename("Cargo.toml"),
            Some(Ecosystem::Cargo)
        );
        assert_eq!(
            Ecosystem::from_filename("package.json"),
            Some(Ecosystem::Npm)
        );
        assert_eq!(
            Ecosystem::from_filename("pyproject.toml"),
            Some(Ecosystem::Pypi)
        );
        assert_eq!(Ecosystem::from_filename("unknown.txt"), None);
    }

    #[test]
    fn test_ecosystem_from_uri() {
        let cargo_uri = Url::parse("file:///path/to/Cargo.toml").unwrap();
        assert_eq!(Ecosystem::from_uri(&cargo_uri), Some(Ecosystem::Cargo));

        let npm_uri = Url::parse("file:///path/to/package.json").unwrap();
        assert_eq!(Ecosystem::from_uri(&npm_uri), Some(Ecosystem::Npm));

        let pypi_uri = Url::parse("file:///path/to/pyproject.toml").unwrap();
        assert_eq!(Ecosystem::from_uri(&pypi_uri), Some(Ecosystem::Pypi));

        let unknown_uri = Url::parse("file:///path/to/README.md").unwrap();
        assert_eq!(Ecosystem::from_uri(&unknown_uri), None);
    }

    #[test]
    fn test_document_state_creation() {
        let deps = vec![create_test_cargo_dependency()];
        let state = DocumentState::new(Ecosystem::Cargo, "test content".into(), deps);

        assert_eq!(state.ecosystem, Ecosystem::Cargo);
        assert_eq!(state.content, "test content");
        assert_eq!(state.dependencies.len(), 1);
        assert!(state.versions.is_empty());
    }

    #[test]
    fn test_document_state_update_versions() {
        let deps = vec![create_test_cargo_dependency()];
        let mut state = DocumentState::new(Ecosystem::Cargo, "test".into(), deps);

        let mut versions = HashMap::new();
        versions.insert(
            "serde".into(),
            UnifiedVersion::Cargo(CargoVersion {
                num: "1.0.0".into(),
                yanked: false,
                features: HashMap::new(),
            }),
        );

        state.update_versions(versions);
        assert_eq!(state.versions.len(), 1);
        assert!(state.versions.contains_key("serde"));
    }

    #[test]
    fn test_server_state_creation() {
        let state = ServerState::new();
        assert_eq!(state.document_count(), 0);
        assert!(state.cache.is_empty(), "Cache should start empty");
    }

    #[test]
    fn test_server_state_document_operations() {
        let state = ServerState::new();
        let uri = Url::parse("file:///test.toml").unwrap();
        let deps = vec![create_test_cargo_dependency()];
        let doc_state = DocumentState::new(Ecosystem::Cargo, "test".into(), deps);

        // Insert document
        state.update_document(uri.clone(), doc_state.clone());
        assert_eq!(state.document_count(), 1);

        // Get document
        let retrieved = state.get_document(&uri);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().content, "test");

        // Remove document
        let removed = state.remove_document(&uri);
        assert!(removed.is_some());
        assert_eq!(state.document_count(), 0);
    }

    #[tokio::test]
    async fn test_server_state_background_tasks() {
        let state = ServerState::new();
        let uri = Url::parse("file:///test.toml").unwrap();

        // Spawn task
        let task = tokio::spawn(async {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        });

        state.spawn_background_task(uri.clone(), task).await;

        // Cancel task
        state.cancel_background_task(&uri).await;
    }
}
