use dashmap::DashMap;
use deps_core::HttpCache;
use deps_core::lockfile::LockFileCache;
use deps_core::{EcosystemRegistry, ParseResult};
use std::collections::HashMap;

#[cfg(feature = "cargo")]
use deps_cargo::{CargoVersion, ParsedDependency};
#[cfg(feature = "go")]
use deps_go::{GoDependency, GoVersion};
#[cfg(feature = "npm")]
use deps_npm::{NpmDependency, NpmVersion};
#[cfg(feature = "pypi")]
use deps_pypi::{PypiDependency, PypiVersion};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::task::JoinHandle;
use tower_lsp_server::ls_types::Uri;

/// Unified dependency enum for multi-ecosystem support.
///
/// Wraps ecosystem-specific dependency types to allow storing
/// dependencies from different ecosystems in the same document state.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum UnifiedDependency {
    #[cfg(feature = "cargo")]
    Cargo(ParsedDependency),
    #[cfg(feature = "npm")]
    Npm(NpmDependency),
    #[cfg(feature = "pypi")]
    Pypi(PypiDependency),
    #[cfg(feature = "go")]
    Go(GoDependency),
}

impl UnifiedDependency {
    /// Returns the dependency name.
    #[allow(unreachable_patterns)]
    pub fn name(&self) -> &str {
        match self {
            #[cfg(feature = "cargo")]
            Self::Cargo(dep) => &dep.name,
            #[cfg(feature = "npm")]
            Self::Npm(dep) => &dep.name,
            #[cfg(feature = "pypi")]
            Self::Pypi(dep) => &dep.name,
            #[cfg(feature = "go")]
            Self::Go(dep) => &dep.module_path,
            _ => unreachable!("no ecosystem features enabled"),
        }
    }

    /// Returns the name range for LSP operations.
    #[allow(unreachable_patterns)]
    pub fn name_range(&self) -> tower_lsp_server::ls_types::Range {
        match self {
            #[cfg(feature = "cargo")]
            Self::Cargo(dep) => dep.name_range,
            #[cfg(feature = "npm")]
            Self::Npm(dep) => dep.name_range,
            #[cfg(feature = "pypi")]
            Self::Pypi(dep) => dep.name_range,
            #[cfg(feature = "go")]
            Self::Go(dep) => dep.module_path_range,
            _ => unreachable!("no ecosystem features enabled"),
        }
    }

    /// Returns the version requirement string if present.
    #[allow(unreachable_patterns)]
    pub fn version_req(&self) -> Option<&str> {
        match self {
            #[cfg(feature = "cargo")]
            Self::Cargo(dep) => dep.version_req.as_deref(),
            #[cfg(feature = "npm")]
            Self::Npm(dep) => dep.version_req.as_deref(),
            #[cfg(feature = "pypi")]
            Self::Pypi(dep) => dep.version_req.as_deref(),
            #[cfg(feature = "go")]
            Self::Go(dep) => dep.version.as_deref(),
            _ => unreachable!("no ecosystem features enabled"),
        }
    }

    /// Returns the version range for LSP operations if present.
    #[allow(unreachable_patterns)]
    pub fn version_range(&self) -> Option<tower_lsp_server::ls_types::Range> {
        match self {
            #[cfg(feature = "cargo")]
            Self::Cargo(dep) => dep.version_range,
            #[cfg(feature = "npm")]
            Self::Npm(dep) => dep.version_range,
            #[cfg(feature = "pypi")]
            Self::Pypi(dep) => dep.version_range,
            #[cfg(feature = "go")]
            Self::Go(dep) => dep.version_range,
            _ => unreachable!("no ecosystem features enabled"),
        }
    }

    /// Returns true if this is a registry dependency (not Git/Path).
    #[allow(unreachable_patterns)]
    pub fn is_registry(&self) -> bool {
        match self {
            #[cfg(feature = "cargo")]
            Self::Cargo(dep) => {
                matches!(dep.source, deps_cargo::DependencySource::Registry)
            }
            #[cfg(feature = "npm")]
            Self::Npm(_) => true,
            #[cfg(feature = "pypi")]
            Self::Pypi(dep) => {
                matches!(dep.source, deps_pypi::PypiDependencySource::PyPI)
            }
            #[cfg(feature = "go")]
            Self::Go(_) => true,
            _ => unreachable!("no ecosystem features enabled"),
        }
    }
}

/// Unified version information enum for multi-ecosystem support.
///
/// Wraps ecosystem-specific version types.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum UnifiedVersion {
    #[cfg(feature = "cargo")]
    Cargo(CargoVersion),
    #[cfg(feature = "npm")]
    Npm(NpmVersion),
    #[cfg(feature = "pypi")]
    Pypi(PypiVersion),
    #[cfg(feature = "go")]
    Go(GoVersion),
}

impl UnifiedVersion {
    /// Returns the version number as a string.
    #[allow(unreachable_patterns)]
    pub fn version_string(&self) -> &str {
        match self {
            #[cfg(feature = "cargo")]
            Self::Cargo(v) => &v.num,
            #[cfg(feature = "npm")]
            Self::Npm(v) => &v.version,
            #[cfg(feature = "pypi")]
            Self::Pypi(v) => &v.version,
            #[cfg(feature = "go")]
            Self::Go(v) => &v.version,
            _ => unreachable!("no ecosystem features enabled"),
        }
    }

    /// Returns true if this version is yanked/deprecated.
    #[allow(unreachable_patterns)]
    pub fn is_yanked(&self) -> bool {
        match self {
            #[cfg(feature = "cargo")]
            Self::Cargo(v) => v.yanked,
            #[cfg(feature = "npm")]
            Self::Npm(v) => v.deprecated,
            #[cfg(feature = "pypi")]
            Self::Pypi(v) => v.yanked,
            #[cfg(feature = "go")]
            Self::Go(v) => v.retracted,
            _ => unreachable!("no ecosystem features enabled"),
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

/// Loading state for registry data fetching.
///
/// Tracks the current state of background version fetching tasks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LoadingState {
    /// No data loaded, not currently loading
    #[default]
    Idle,
    /// Currently fetching registry data
    Loading,
    /// Data fetched and cached
    Loaded,
    /// Fetch failed (still show old cached data if available)
    Failed,
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
    /// Go modules ecosystem (go.mod)
    Go,
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
            "go.mod" => Some(Self::Go),
            _ => None,
        }
    }

    /// Detects ecosystem from full URI path.
    ///
    /// Extracts the filename from the URI and checks if it matches a known manifest.
    pub fn from_uri(uri: &Uri) -> Option<Self> {
        let path = uri.path();
        let filename = path.as_str().split('/').next_back()?;
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
/// use tower_lsp_server::ls_types::{Position, Range};
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
pub struct DocumentState {
    /// Package ecosystem type (deprecated, use ecosystem_id)
    pub ecosystem: Ecosystem,
    /// Ecosystem identifier ("cargo", "npm", "pypi")
    pub ecosystem_id: &'static str,
    /// Original document content
    pub content: String,
    /// Parsed dependencies with positions (legacy)
    pub dependencies: Vec<UnifiedDependency>,
    /// Parsed result as trait object (new architecture)
    /// Note: This is not cloned when DocumentState is cloned
    #[allow(dead_code)]
    parse_result: Option<Box<dyn ParseResult>>,
    /// Cached latest version information from registry
    pub versions: HashMap<String, UnifiedVersion>,
    /// Simplified cached versions (just strings) for new architecture
    pub cached_versions: HashMap<String, String>,
    /// Resolved versions from lock file
    pub resolved_versions: HashMap<String, String>,
    /// Last successful parse time
    pub parsed_at: Instant,
    /// Current loading state for registry data
    pub loading_state: LoadingState,
    /// When the current loading operation started (for timeout/metrics)
    pub loading_started_at: Option<Instant>,
}

impl Clone for DocumentState {
    fn clone(&self) -> Self {
        Self {
            ecosystem: self.ecosystem,
            ecosystem_id: self.ecosystem_id,
            content: self.content.clone(),
            dependencies: self.dependencies.clone(),
            parse_result: None, // Don't clone trait object
            versions: self.versions.clone(),
            cached_versions: self.cached_versions.clone(),
            resolved_versions: self.resolved_versions.clone(),
            parsed_at: self.parsed_at,
            loading_state: self.loading_state,
            // Note: Instant is Copy. Clones share the same loading start time.
            loading_started_at: self.loading_started_at,
        }
    }
}

/// Tracks recent cold start attempts per URI to prevent DOS.
///
/// Uses rate limiting with a configurable minimum interval between
/// cold start attempts for the same URI. This prevents malicious or
/// buggy clients from overwhelming the server with rapid file loading
/// requests.
///
/// # Examples
///
/// ```
/// use deps_lsp::document::ColdStartLimiter;
/// use tower_lsp_server::ls_types::Uri;
/// use std::time::Duration;
///
/// let limiter = ColdStartLimiter::new(Duration::from_millis(100));
/// let uri = Uri::from_file_path("/test.toml").unwrap();
///
/// assert!(limiter.allow_cold_start(&uri));
/// assert!(!limiter.allow_cold_start(&uri)); // Rate limited
/// ```
#[derive(Debug)]
pub struct ColdStartLimiter {
    /// Maps URI to last cold start attempt time.
    last_attempts: DashMap<Uri, Instant>,
    /// Minimum interval between cold start attempts for the same URI.
    min_interval: Duration,
}

impl ColdStartLimiter {
    /// Creates a new cold start limiter with the specified minimum interval.
    pub fn new(min_interval: Duration) -> Self {
        Self {
            last_attempts: DashMap::new(),
            min_interval,
        }
    }

    /// Returns true if cold start is allowed, false if rate limited.
    ///
    /// Updates the last attempt time if the cold start is allowed.
    pub fn allow_cold_start(&self, uri: &Uri) -> bool {
        let now = Instant::now();

        // Check last attempt time
        if let Some(mut entry) = self.last_attempts.get_mut(uri) {
            let elapsed = now.duration_since(*entry);
            if elapsed < self.min_interval {
                let retry_after = self.min_interval.checked_sub(elapsed).unwrap();
                tracing::warn!(
                    "Cold start rate limited for {:?} (retry after {:?})",
                    uri,
                    retry_after
                );
                return false;
            }
            *entry = now;
        } else {
            self.last_attempts.insert(uri.clone(), now);
        }

        true
    }

    /// Cleans up old entries periodically.
    ///
    /// Removes entries older than `max_age` to prevent unbounded memory growth.
    /// Should be called from a background task.
    pub fn cleanup_old_entries(&self, max_age: Duration) {
        let now = Instant::now();
        self.last_attempts
            .retain(|_, instant| now.duration_since(*instant) < max_age);
    }

    /// Returns the number of tracked URIs.
    #[cfg(test)]
    pub fn tracked_count(&self) -> usize {
        self.last_attempts.len()
    }
}

impl std::fmt::Debug for DocumentState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DocumentState")
            .field("ecosystem", &self.ecosystem)
            .field("ecosystem_id", &self.ecosystem_id)
            .field("content_len", &self.content.len())
            .field("dependencies_count", &self.dependencies.len())
            .field("has_parse_result", &self.parse_result.is_some())
            .field("versions_count", &self.versions.len())
            .field("cached_versions_count", &self.cached_versions.len())
            .field("resolved_versions_count", &self.resolved_versions.len())
            .field("parsed_at", &self.parsed_at)
            .field("loading_state", &self.loading_state)
            .field("loading_started_at", &self.loading_started_at)
            .finish()
    }
}

impl DocumentState {
    /// Creates a new document state (legacy constructor).
    ///
    /// Initializes with the given ecosystem, content, and parsed dependencies.
    /// Version information starts empty and is populated asynchronously.
    pub fn new(
        ecosystem: Ecosystem,
        content: String,
        dependencies: Vec<UnifiedDependency>,
    ) -> Self {
        let ecosystem_id = match ecosystem {
            Ecosystem::Cargo => "cargo",
            Ecosystem::Npm => "npm",
            Ecosystem::Pypi => "pypi",
            Ecosystem::Go => "go",
        };

        Self {
            ecosystem,
            ecosystem_id,
            content,
            dependencies,
            parse_result: None,
            versions: HashMap::new(),
            cached_versions: HashMap::new(),
            resolved_versions: HashMap::new(),
            parsed_at: Instant::now(),
            loading_state: LoadingState::Idle,
            loading_started_at: None,
        }
    }

    /// Creates a new document state using trait objects (new architecture).
    ///
    /// This is the preferred constructor for Phase 3+ implementations.
    pub fn new_from_parse_result(
        ecosystem_id: &'static str,
        content: String,
        parse_result: Box<dyn ParseResult>,
    ) -> Self {
        let ecosystem = match ecosystem_id {
            "cargo" => Ecosystem::Cargo,
            "npm" => Ecosystem::Npm,
            "pypi" => Ecosystem::Pypi,
            "go" => Ecosystem::Go,
            _ => Ecosystem::Cargo, // Default fallback
        };

        Self {
            ecosystem,
            ecosystem_id,
            content,
            dependencies: vec![],
            parse_result: Some(parse_result),
            versions: HashMap::new(),
            cached_versions: HashMap::new(),
            resolved_versions: HashMap::new(),
            parsed_at: Instant::now(),
            loading_state: LoadingState::Idle,
            loading_started_at: None,
        }
    }

    /// Creates a new document state without a parse result.
    ///
    /// Used when parsing fails but the document should still be stored
    /// to enable fallback completion and other LSP features.
    pub fn new_without_parse_result(ecosystem_id: &'static str, content: String) -> Self {
        let ecosystem = match ecosystem_id {
            "cargo" => Ecosystem::Cargo,
            "npm" => Ecosystem::Npm,
            "pypi" => Ecosystem::Pypi,
            "go" => Ecosystem::Go,
            _ => Ecosystem::Cargo, // Default fallback
        };

        Self {
            ecosystem,
            ecosystem_id,
            content,
            dependencies: vec![],
            parse_result: None,
            versions: HashMap::new(),
            cached_versions: HashMap::new(),
            resolved_versions: HashMap::new(),
            parsed_at: Instant::now(),
            loading_state: LoadingState::Idle,
            loading_started_at: None,
        }
    }

    /// Gets a reference to the parse result if available.
    pub fn parse_result(&self) -> Option<&dyn ParseResult> {
        self.parse_result.as_ref().map(std::convert::AsRef::as_ref)
    }

    /// Updates the cached latest version information for dependencies.
    pub fn update_versions(&mut self, versions: HashMap<String, UnifiedVersion>) {
        self.versions = versions;
    }

    /// Updates the simplified cached versions (new architecture).
    pub fn update_cached_versions(&mut self, versions: HashMap<String, String>) {
        self.cached_versions = versions;
    }

    /// Updates the resolved versions from lock file.
    pub fn update_resolved_versions(&mut self, versions: HashMap<String, String>) {
        self.resolved_versions = versions;
    }

    /// Mark document as loading registry data.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_lsp::document::DocumentState;
    ///
    /// let mut doc = DocumentState::new_without_parse_result("cargo", "".into());
    /// doc.set_loading();
    /// assert!(doc.loading_started_at.is_some());
    /// ```
    ///
    /// # Thread Safety
    ///
    /// This method requires exclusive access (`&mut self`). When used with
    /// `DashMap::get_mut()`, thread safety is guaranteed by the lock.
    /// Calling while already `Loading` resets the timer.
    pub fn set_loading(&mut self) {
        self.loading_state = LoadingState::Loading;
        self.loading_started_at = Some(Instant::now());
    }

    /// Mark document as loaded with fresh data.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_lsp::document::{DocumentState, LoadingState};
    ///
    /// let mut doc = DocumentState::new_without_parse_result("cargo", "".into());
    /// doc.set_loading();
    /// doc.set_loaded();
    /// assert_eq!(doc.loading_state, LoadingState::Loaded);
    /// assert!(doc.loading_started_at.is_none());
    /// ```
    pub fn set_loaded(&mut self) {
        self.loading_state = LoadingState::Loaded;
        self.loading_started_at = None;
    }

    /// Mark document as failed to load (keeps old cached data).
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_lsp::document::{DocumentState, LoadingState};
    ///
    /// let mut doc = DocumentState::new_without_parse_result("cargo", "".into());
    /// doc.set_loading();
    /// doc.set_failed();
    /// assert_eq!(doc.loading_state, LoadingState::Failed);
    /// assert!(doc.loading_started_at.is_none());
    /// ```
    pub fn set_failed(&mut self) {
        self.loading_state = LoadingState::Failed;
        self.loading_started_at = None;
    }

    /// Get current loading duration if loading.
    ///
    /// Returns `None` if not currently loading, or `Some(Duration)` representing
    /// how long the current loading operation has been running.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_lsp::document::DocumentState;
    ///
    /// let mut doc = DocumentState::new_without_parse_result("cargo", "".into());
    /// assert!(doc.loading_duration().is_none());
    ///
    /// doc.set_loading();
    /// assert!(doc.loading_duration().is_some());
    /// ```
    #[must_use]
    pub fn loading_duration(&self) -> Option<Duration> {
        self.loading_started_at
            .map(|start| Instant::now().duration_since(start))
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
/// use tower_lsp_server::ls_types::Uri;
///
/// let state = ServerState::new();
/// assert_eq!(state.document_count(), 0);
/// ```
pub struct ServerState {
    /// Open documents by URI
    pub documents: DashMap<Uri, DocumentState>,
    /// HTTP cache for registry requests
    pub cache: Arc<HttpCache>,
    /// Lock file cache for parsed lock files
    pub lockfile_cache: Arc<LockFileCache>,
    /// Ecosystem registry for trait-based architecture
    pub ecosystem_registry: Arc<EcosystemRegistry>,
    /// Cold start rate limiter
    pub cold_start_limiter: ColdStartLimiter,
    /// Background task handles
    tasks: tokio::sync::RwLock<HashMap<Uri, JoinHandle<()>>>,
}

impl ServerState {
    /// Creates a new server state with default configuration.
    pub fn new() -> Self {
        let cache = Arc::new(HttpCache::new());
        let lockfile_cache = Arc::new(LockFileCache::new());
        let ecosystem_registry = Arc::new(EcosystemRegistry::new());

        // Register ecosystems based on enabled features
        crate::register_ecosystems(&ecosystem_registry, Arc::clone(&cache));

        // Create cold start limiter with default 100ms interval (10 req/sec per URI)
        let cold_start_limiter = ColdStartLimiter::new(Duration::from_millis(100));

        Self {
            documents: DashMap::new(),
            cache,
            lockfile_cache,
            ecosystem_registry,
            cold_start_limiter,
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
        uri: &Uri,
    ) -> Option<dashmap::mapref::one::Ref<'_, Uri, DocumentState>> {
        self.documents.get(uri)
    }

    /// Retrieves a cloned copy of document state by URI.
    ///
    /// This method clones the document state immediately and releases
    /// the DashMap lock, allowing concurrent access to the map while
    /// the document is being processed. Use this in hot paths where
    /// async operations are performed with the document data.
    ///
    /// # Performance
    ///
    /// Cloning `DocumentState` is relatively cheap as it only clones
    /// `String` and `HashMap` metadata, not the underlying parse result
    /// trait object.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use deps_lsp::document::ServerState;
    /// # use tower_lsp_server::ls_types::Uri;
    /// # async fn example(state: &ServerState, uri: &Uri) {
    /// // Lock released immediately after clone
    /// let doc = state.get_document_clone(uri);
    ///
    /// if let Some(doc) = doc {
    ///     // Perform async operations without holding lock
    ///     let result = process_async(&doc).await;
    /// }
    /// # }
    /// # async fn process_async(doc: &deps_lsp::document::DocumentState) {}
    /// ```
    pub fn get_document_clone(&self, uri: &Uri) -> Option<DocumentState> {
        self.documents.get(uri).map(|doc| doc.clone())
    }

    /// Updates or inserts document state.
    ///
    /// If a document already exists at the given URI, it is replaced.
    /// Otherwise, a new entry is created.
    pub fn update_document(&self, uri: Uri, state: DocumentState) {
        self.documents.insert(uri, state);
    }

    /// Removes document state and returns the removed entry.
    ///
    /// Returns `None` if no document exists at the given URI.
    pub fn remove_document(&self, uri: &Uri) -> Option<(Uri, DocumentState)> {
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
    pub async fn spawn_background_task(&self, uri: Uri, task: JoinHandle<()>) {
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
    pub async fn cancel_background_task(&self, uri: &Uri) {
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

    // =========================================================================
    // Generic tests (no feature flag required)
    // =========================================================================

    // =========================================================================
    // LoadingState tests
    // =========================================================================

    mod loading_state_tests {
        use super::*;

        #[test]
        fn test_loading_state_default() {
            let state = LoadingState::default();
            assert_eq!(state, LoadingState::Idle);
        }

        #[test]
        fn test_loading_state_transitions() {
            use std::time::Duration;

            let content = "[dependencies]\nserde = \"1.0\"".to_string();
            let mut doc = DocumentState::new_without_parse_result("cargo", content);

            // Initial state
            assert_eq!(doc.loading_state, LoadingState::Idle);
            assert!(doc.loading_started_at.is_none());

            // Transition to Loading
            doc.set_loading();
            assert_eq!(doc.loading_state, LoadingState::Loading);
            assert!(doc.loading_started_at.is_some());

            // Small sleep to ensure duration is non-zero
            std::thread::sleep(Duration::from_millis(10));

            // Check loading duration
            let duration = doc.loading_duration();
            assert!(duration.is_some());
            assert!(duration.unwrap() >= Duration::from_millis(10));

            // Transition to Loaded
            doc.set_loaded();
            assert_eq!(doc.loading_state, LoadingState::Loaded);
            assert!(doc.loading_started_at.is_none());
            assert!(doc.loading_duration().is_none());
        }

        #[test]
        fn test_loading_state_failed_transition() {
            let content = "[dependencies]\nserde = \"1.0\"".to_string();
            let mut doc = DocumentState::new_without_parse_result("cargo", content);

            doc.set_loading();
            assert_eq!(doc.loading_state, LoadingState::Loading);

            doc.set_failed();
            assert_eq!(doc.loading_state, LoadingState::Failed);
            assert!(doc.loading_started_at.is_none());
        }

        #[test]
        fn test_loading_state_clone() {
            let content = "[dependencies]\nserde = \"1.0\"".to_string();
            let mut doc = DocumentState::new_without_parse_result("cargo", content);

            doc.set_loading();
            let cloned = doc.clone();

            assert_eq!(cloned.loading_state, LoadingState::Loading);
            assert!(cloned.loading_started_at.is_some());
        }

        #[test]
        fn test_loading_state_debug() {
            let content = "[dependencies]\nserde = \"1.0\"".to_string();
            let mut doc = DocumentState::new_without_parse_result("cargo", content);
            doc.set_loading();

            let debug_str = format!("{:?}", doc);
            assert!(debug_str.contains("loading_state"));
            assert!(debug_str.contains("Loading"));
        }

        #[test]
        fn test_loading_duration_none_when_idle() {
            let content = "[dependencies]\nserde = \"1.0\"".to_string();
            let doc = DocumentState::new_without_parse_result("cargo", content);

            assert_eq!(doc.loading_state, LoadingState::Idle);
            assert!(doc.loading_duration().is_none());
        }

        #[test]
        fn test_loading_state_equality() {
            assert_eq!(LoadingState::Idle, LoadingState::Idle);
            assert_eq!(LoadingState::Loading, LoadingState::Loading);
            assert_eq!(LoadingState::Loaded, LoadingState::Loaded);
            assert_eq!(LoadingState::Failed, LoadingState::Failed);

            assert_ne!(LoadingState::Idle, LoadingState::Loading);
            assert_ne!(LoadingState::Loading, LoadingState::Loaded);
        }

        #[test]
        fn test_loading_duration_tracks_time_correctly() {
            use std::time::Duration;

            let content = "[dependencies]\nserde = \"1.0\"".to_string();
            let mut doc = DocumentState::new_without_parse_result("cargo", content);

            doc.set_loading();

            // Check duration increases over time
            let duration1 = doc.loading_duration().unwrap();
            std::thread::sleep(Duration::from_millis(20));
            let duration2 = doc.loading_duration().unwrap();

            assert!(duration2 > duration1, "Duration should increase over time");
        }

        #[tokio::test]
        async fn test_concurrent_loading_state_mutations() {
            use std::sync::Arc;
            use tokio::sync::Barrier;

            let state = Arc::new(ServerState::new());
            let uri = Uri::from_file_path("/concurrent-loading-test.toml").unwrap();

            let doc = DocumentState::new_without_parse_result("cargo", String::new());
            state.update_document(uri.clone(), doc);

            let barrier = Arc::new(Barrier::new(10));
            let mut handles = vec![];

            for i in 0..10 {
                let state_clone = Arc::clone(&state);
                let uri_clone = uri.clone();
                let barrier_clone = Arc::clone(&barrier);

                handles.push(tokio::spawn(async move {
                    barrier_clone.wait().await;
                    if let Some(mut doc) = state_clone.documents.get_mut(&uri_clone) {
                        if i % 3 == 0 {
                            doc.set_loading();
                        } else if i % 3 == 1 {
                            doc.set_loaded();
                        } else {
                            doc.set_failed();
                        }
                    }
                }));
            }

            for handle in handles {
                handle.await.unwrap();
            }

            let doc = state.get_document(&uri).unwrap();
            assert!(matches!(
                doc.loading_state,
                LoadingState::Idle
                    | LoadingState::Loading
                    | LoadingState::Loaded
                    | LoadingState::Failed
            ));
        }

        #[test]
        fn test_set_loaded_idempotent() {
            let mut doc = DocumentState::new_without_parse_result("cargo", String::new());

            doc.set_loading();
            doc.set_loaded();

            // Call again - should be safe
            doc.set_loaded();

            assert_eq!(doc.loading_state, LoadingState::Loaded);
            assert!(doc.loading_started_at.is_none());
        }

        #[test]
        fn test_set_loading_resets_timer() {
            let mut doc = DocumentState::new_without_parse_result("cargo", String::new());

            doc.set_loading();
            let first_start = doc.loading_started_at.unwrap();

            std::thread::sleep(std::time::Duration::from_millis(10));

            // Call set_loading again - should reset timer
            doc.set_loading();
            let second_start = doc.loading_started_at.unwrap();

            assert!(second_start > first_start, "Timer should be reset");
            assert_eq!(doc.loading_state, LoadingState::Loading);
        }

        #[test]
        fn test_retry_after_failure() {
            let mut doc = DocumentState::new_without_parse_result("cargo", String::new());

            doc.set_loading();
            doc.set_failed();
            assert_eq!(doc.loading_state, LoadingState::Failed);
            assert!(doc.loading_started_at.is_none());

            // Retry
            doc.set_loading();
            assert_eq!(doc.loading_state, LoadingState::Loading);
            assert!(doc.loading_started_at.is_some());

            doc.set_loaded();
            assert_eq!(doc.loading_state, LoadingState::Loaded);
        }

        #[test]
        fn test_refresh_after_loaded() {
            let mut doc = DocumentState::new_without_parse_result("cargo", String::new());

            doc.set_loading();
            doc.set_loaded();
            assert_eq!(doc.loading_state, LoadingState::Loaded);

            // Refresh
            doc.set_loading();
            assert_eq!(doc.loading_state, LoadingState::Loading);
            assert!(doc.loading_started_at.is_some());

            doc.set_loaded();
            assert_eq!(doc.loading_state, LoadingState::Loaded);
        }
    }

    #[test]
    fn test_ecosystem_from_filename() {
        #[cfg(feature = "cargo")]
        assert_eq!(
            Ecosystem::from_filename("Cargo.toml"),
            Some(Ecosystem::Cargo)
        );
        #[cfg(feature = "npm")]
        assert_eq!(
            Ecosystem::from_filename("package.json"),
            Some(Ecosystem::Npm)
        );
        #[cfg(feature = "pypi")]
        assert_eq!(
            Ecosystem::from_filename("pyproject.toml"),
            Some(Ecosystem::Pypi)
        );
        #[cfg(feature = "go")]
        assert_eq!(Ecosystem::from_filename("go.mod"), Some(Ecosystem::Go));
        assert_eq!(Ecosystem::from_filename("unknown.txt"), None);
    }

    #[test]
    fn test_ecosystem_from_uri() {
        #[cfg(feature = "cargo")]
        {
            let cargo_uri = Uri::from_file_path("/path/to/Cargo.toml").unwrap();
            assert_eq!(Ecosystem::from_uri(&cargo_uri), Some(Ecosystem::Cargo));
        }
        #[cfg(feature = "npm")]
        {
            let npm_uri = Uri::from_file_path("/path/to/package.json").unwrap();
            assert_eq!(Ecosystem::from_uri(&npm_uri), Some(Ecosystem::Npm));
        }
        #[cfg(feature = "pypi")]
        {
            let pypi_uri = Uri::from_file_path("/path/to/pyproject.toml").unwrap();
            assert_eq!(Ecosystem::from_uri(&pypi_uri), Some(Ecosystem::Pypi));
        }
        #[cfg(feature = "go")]
        {
            let go_uri = Uri::from_file_path("/path/to/go.mod").unwrap();
            assert_eq!(Ecosystem::from_uri(&go_uri), Some(Ecosystem::Go));
        }
        let unknown_uri = Uri::from_file_path("/path/to/README.md").unwrap();
        assert_eq!(Ecosystem::from_uri(&unknown_uri), None);
    }

    #[test]
    fn test_ecosystem_from_filename_edge_cases() {
        assert_eq!(Ecosystem::from_filename(""), None);
        assert_eq!(Ecosystem::from_filename("cargo.toml"), None);
        assert_eq!(Ecosystem::from_filename("CARGO.TOML"), None);
        assert_eq!(Ecosystem::from_filename("requirements.txt"), None);
    }

    #[test]
    fn test_server_state_creation() {
        let state = ServerState::new();
        assert_eq!(state.document_count(), 0);
        assert!(state.cache.is_empty(), "Cache should start empty");
    }

    #[test]
    fn test_server_state_default() {
        let state = ServerState::default();
        assert_eq!(state.document_count(), 0);
    }

    #[tokio::test]
    async fn test_server_state_background_tasks() {
        let state = ServerState::new();
        let uri = Uri::from_file_path("/test.toml").unwrap();

        let task = tokio::spawn(async {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        });

        state.spawn_background_task(uri.clone(), task).await;
        state.cancel_background_task(&uri).await;
    }

    #[tokio::test]
    async fn test_spawn_background_task_cancels_previous() {
        let state = ServerState::new();
        let uri = Uri::from_file_path("/test.toml").unwrap();

        let task1 = tokio::spawn(async {
            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
        });
        state.spawn_background_task(uri.clone(), task1).await;

        let task2 = tokio::spawn(async {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        });
        state.spawn_background_task(uri.clone(), task2).await;
        state.cancel_background_task(&uri).await;
    }

    #[tokio::test]
    async fn test_cancel_background_task_nonexistent() {
        let state = ServerState::new();
        let uri = Uri::from_file_path("/test.toml").unwrap();
        state.cancel_background_task(&uri).await;
    }

    // =========================================================================
    // ColdStartLimiter tests
    // =========================================================================

    mod cold_start_limiter {
        use super::*;
        use std::time::Duration;

        #[test]
        fn test_allows_first_request() {
            let limiter = ColdStartLimiter::new(Duration::from_millis(100));
            let uri = Uri::from_file_path("/test.toml").unwrap();
            assert!(
                limiter.allow_cold_start(&uri),
                "First request should be allowed"
            );
        }

        #[test]
        fn test_blocks_rapid_requests() {
            let limiter = ColdStartLimiter::new(Duration::from_millis(100));
            let uri = Uri::from_file_path("/test.toml").unwrap();

            assert!(limiter.allow_cold_start(&uri), "First request allowed");
            assert!(
                !limiter.allow_cold_start(&uri),
                "Second immediate request should be blocked"
            );
        }

        #[tokio::test]
        async fn test_allows_after_interval() {
            let limiter = ColdStartLimiter::new(Duration::from_millis(50));
            let uri = Uri::from_file_path("/test.toml").unwrap();

            assert!(limiter.allow_cold_start(&uri), "First request allowed");
            tokio::time::sleep(Duration::from_millis(60)).await;
            assert!(
                limiter.allow_cold_start(&uri),
                "Request after interval should be allowed"
            );
        }

        #[test]
        fn test_different_uris_independent() {
            let limiter = ColdStartLimiter::new(Duration::from_millis(100));
            let uri1 = Uri::from_file_path("/test1.toml").unwrap();
            let uri2 = Uri::from_file_path("/test2.toml").unwrap();

            assert!(limiter.allow_cold_start(&uri1), "URI 1 first request");
            assert!(limiter.allow_cold_start(&uri2), "URI 2 first request");
            assert!(
                !limiter.allow_cold_start(&uri1),
                "URI 1 second request blocked"
            );
            assert!(
                !limiter.allow_cold_start(&uri2),
                "URI 2 second request blocked"
            );
        }

        #[test]
        fn test_cleanup() {
            let limiter = ColdStartLimiter::new(Duration::from_millis(100));
            let uri1 = Uri::from_file_path("/test1.toml").unwrap();
            let uri2 = Uri::from_file_path("/test2.toml").unwrap();

            limiter.allow_cold_start(&uri1);
            limiter.allow_cold_start(&uri2);
            assert_eq!(limiter.tracked_count(), 2, "Should track 2 URIs");

            limiter.cleanup_old_entries(Duration::from_millis(0));
            assert_eq!(
                limiter.tracked_count(),
                0,
                "All entries should be cleaned up"
            );
        }

        #[tokio::test]
        async fn test_concurrent_access() {
            use std::sync::Arc;

            let limiter = Arc::new(ColdStartLimiter::new(Duration::from_millis(100)));
            let uri = Uri::from_file_path("/concurrent-test.toml").unwrap();

            let mut handles = vec![];
            const CONCURRENT_TASKS: usize = 10;

            for _ in 0..CONCURRENT_TASKS {
                let limiter_clone = Arc::clone(&limiter);
                let uri_clone = uri.clone();
                let handle =
                    tokio::spawn(async move { limiter_clone.allow_cold_start(&uri_clone) });
                handles.push(handle);
            }

            let mut results = vec![];
            for handle in handles {
                results.push(handle.await.unwrap());
            }

            let allowed_count = results.iter().filter(|&&allowed| allowed).count();
            assert_eq!(allowed_count, 1, "Exactly one concurrent request allowed");

            let blocked_count = results.iter().filter(|&&allowed| !allowed).count();
            assert_eq!(
                blocked_count,
                CONCURRENT_TASKS - 1,
                "Rest should be blocked"
            );
        }
    }

    // =========================================================================
    // Cargo ecosystem tests
    // =========================================================================

    #[cfg(feature = "cargo")]
    mod cargo_tests {
        use super::*;
        use deps_cargo::{DependencySection, DependencySource};
        use tower_lsp_server::ls_types::{Position, Range};

        fn create_test_dependency() -> UnifiedDependency {
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
        fn test_document_state_creation() {
            let deps = vec![create_test_dependency()];
            let state = DocumentState::new(Ecosystem::Cargo, "test content".into(), deps);

            assert_eq!(state.ecosystem, Ecosystem::Cargo);
            assert_eq!(state.content, "test content");
            assert_eq!(state.dependencies.len(), 1);
            assert!(state.versions.is_empty());
        }

        #[test]
        fn test_document_state_update_versions() {
            let deps = vec![create_test_dependency()];
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
        fn test_server_state_document_operations() {
            let state = ServerState::new();
            let uri = Uri::from_file_path("/test.toml").unwrap();
            let deps = vec![create_test_dependency()];
            let doc_state = DocumentState::new(Ecosystem::Cargo, "test".into(), deps);

            state.update_document(uri.clone(), doc_state);
            assert_eq!(state.document_count(), 1);

            let retrieved = state.get_document(&uri);
            assert!(retrieved.is_some());
            assert_eq!(retrieved.unwrap().content, "test");

            let removed = state.remove_document(&uri);
            assert!(removed.is_some());
            assert_eq!(state.document_count(), 0);
        }

        #[test]
        fn test_unified_dependency_name() {
            let cargo_dep = create_test_dependency();
            assert_eq!(cargo_dep.name(), "serde");
            assert_eq!(cargo_dep.version_req(), Some("1.0"));
            assert!(cargo_dep.is_registry());
        }

        #[test]
        fn test_unified_dependency_git_source() {
            let git_dep = UnifiedDependency::Cargo(ParsedDependency {
                name: "custom".into(),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 6)),
                version_req: None,
                version_range: None,
                features: vec![],
                features_range: None,
                source: DependencySource::Git {
                    url: "https://github.com/user/repo".into(),
                    rev: None,
                },
                workspace_inherited: false,
                section: DependencySection::Dependencies,
            });
            assert!(!git_dep.is_registry());
        }

        #[test]
        fn test_unified_version() {
            let version = UnifiedVersion::Cargo(CargoVersion {
                num: "1.0.0".into(),
                yanked: false,
                features: HashMap::new(),
            });
            assert_eq!(version.version_string(), "1.0.0");
            assert!(!version.is_yanked());
        }

        #[test]
        fn test_document_state_new_from_parse_result() {
            let state = ServerState::new();
            let uri = Uri::from_file_path("/test/Cargo.toml").unwrap();
            let ecosystem = state.ecosystem_registry.get("cargo").unwrap();
            let content = "[dependencies]\nserde = \"1.0\"\n".to_string();

            let parse_result = tokio::runtime::Runtime::new()
                .unwrap()
                .block_on(ecosystem.parse_manifest(&content, &uri))
                .unwrap();

            let doc_state =
                DocumentState::new_from_parse_result("cargo", content.clone(), parse_result);

            assert_eq!(doc_state.ecosystem_id, "cargo");
            assert_eq!(doc_state.content, content);
            assert!(doc_state.parse_result.is_some());
        }

        #[test]
        fn test_document_state_new_without_parse_result() {
            let content = "[dependencies]\nserde = \"1.0\"\n".to_string();
            let doc_state = DocumentState::new_without_parse_result("cargo", content);

            assert_eq!(doc_state.ecosystem_id, "cargo");
            assert_eq!(doc_state.ecosystem, Ecosystem::Cargo);
            assert!(doc_state.parse_result.is_none());
            assert!(doc_state.dependencies.is_empty());
        }

        #[test]
        fn test_document_state_update_resolved_versions() {
            let deps = vec![create_test_dependency()];
            let mut state = DocumentState::new(Ecosystem::Cargo, "test".into(), deps);

            let mut resolved = HashMap::new();
            resolved.insert("serde".into(), "1.0.195".into());

            state.update_resolved_versions(resolved);
            assert_eq!(state.resolved_versions.len(), 1);
            assert_eq!(
                state.resolved_versions.get("serde"),
                Some(&"1.0.195".into())
            );
        }

        #[test]
        fn test_document_state_update_cached_versions() {
            let deps = vec![create_test_dependency()];
            let mut state = DocumentState::new(Ecosystem::Cargo, "test".into(), deps);

            let mut cached = HashMap::new();
            cached.insert("serde".into(), "1.0.210".into());

            state.update_cached_versions(cached);
            assert_eq!(state.cached_versions.len(), 1);
        }

        #[test]
        fn test_document_state_parse_result_accessor() {
            let deps = vec![create_test_dependency()];
            let state = DocumentState::new(Ecosystem::Cargo, "test".into(), deps);
            assert!(state.parse_result().is_none());
        }

        #[test]
        fn test_document_state_clone() {
            let deps = vec![create_test_dependency()];
            let state = DocumentState::new(Ecosystem::Cargo, "test content".into(), deps);
            let cloned = state.clone();

            assert_eq!(cloned.ecosystem, state.ecosystem);
            assert_eq!(cloned.content, state.content);
            assert_eq!(cloned.dependencies.len(), state.dependencies.len());
            assert!(cloned.parse_result.is_none());
        }

        #[test]
        fn test_document_state_debug() {
            let deps = vec![create_test_dependency()];
            let state = DocumentState::new(Ecosystem::Cargo, "test".into(), deps);
            let debug_str = format!("{state:?}");
            assert!(debug_str.contains("DocumentState"));
        }
    }

    // =========================================================================
    // npm ecosystem tests
    // =========================================================================

    #[cfg(feature = "npm")]
    mod npm_tests {
        use super::*;
        use deps_npm::{NpmDependency, NpmDependencySection};
        use tower_lsp_server::ls_types::{Position, Range};

        #[test]
        fn test_unified_dependency() {
            let npm_dep = UnifiedDependency::Npm(NpmDependency {
                name: "express".into(),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 7)),
                version_req: Some("^4.0.0".into()),
                version_range: Some(Range::new(Position::new(0, 11), Position::new(0, 18))),
                section: NpmDependencySection::Dependencies,
            });

            assert_eq!(npm_dep.name(), "express");
            assert_eq!(npm_dep.version_req(), Some("^4.0.0"));
            assert!(npm_dep.is_registry());
        }

        #[test]
        fn test_unified_version() {
            let version = UnifiedVersion::Npm(deps_npm::NpmVersion {
                version: "4.18.2".into(),
                deprecated: false,
            });
            assert_eq!(version.version_string(), "4.18.2");
            assert!(!version.is_yanked());
        }

        #[test]
        fn test_document_state_new_without_parse_result() {
            let content = r#"{"dependencies": {"express": "^4.18.0"}}"#.to_string();
            let doc_state = DocumentState::new_without_parse_result("npm", content);

            assert_eq!(doc_state.ecosystem_id, "npm");
            assert_eq!(doc_state.ecosystem, Ecosystem::Npm);
            assert!(doc_state.parse_result.is_none());
        }
    }

    // =========================================================================
    // PyPI ecosystem tests
    // =========================================================================

    #[cfg(feature = "pypi")]
    mod pypi_tests {
        use super::*;
        use deps_pypi::{PypiDependency, PypiDependencySection, PypiDependencySource};
        use tower_lsp_server::ls_types::{Position, Range};

        #[test]
        fn test_unified_dependency() {
            let pypi_dep = UnifiedDependency::Pypi(PypiDependency {
                name: "requests".into(),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 8)),
                version_req: Some(">=2.0.0".into()),
                version_range: Some(Range::new(Position::new(0, 10), Position::new(0, 18))),
                extras: vec![],
                extras_range: None,
                markers: None,
                markers_range: None,
                source: PypiDependencySource::PyPI,
                section: PypiDependencySection::Dependencies,
            });

            assert_eq!(pypi_dep.name(), "requests");
            assert_eq!(pypi_dep.version_req(), Some(">=2.0.0"));
            assert!(pypi_dep.is_registry());
        }

        #[test]
        fn test_unified_version() {
            let version = UnifiedVersion::Pypi(deps_pypi::PypiVersion {
                version: "2.31.0".into(),
                yanked: true,
            });
            assert_eq!(version.version_string(), "2.31.0");
            assert!(version.is_yanked());
        }

        #[test]
        fn test_document_state_new_without_parse_result() {
            let content = "[project]\ndependencies = [\"requests>=2.0.0\"]\n".to_string();
            let doc_state = DocumentState::new_without_parse_result("pypi", content);

            assert_eq!(doc_state.ecosystem_id, "pypi");
            assert_eq!(doc_state.ecosystem, Ecosystem::Pypi);
            assert!(doc_state.parse_result.is_none());
        }
    }

    // =========================================================================
    // Go ecosystem tests
    // =========================================================================

    #[cfg(feature = "go")]
    mod go_tests {
        use super::*;
        use deps_go::{GoDependency, GoDirective, GoVersion};
        use tower_lsp_server::ls_types::{Position, Range};

        fn create_test_dependency() -> UnifiedDependency {
            UnifiedDependency::Go(GoDependency {
                module_path: "github.com/gin-gonic/gin".into(),
                module_path_range: Range::new(Position::new(0, 0), Position::new(0, 25)),
                version: Some("v1.9.1".into()),
                version_range: Some(Range::new(Position::new(0, 26), Position::new(0, 32))),
                directive: GoDirective::Require,
                indirect: false,
            })
        }

        #[test]
        fn test_unified_dependency() {
            let go_dep = create_test_dependency();
            assert_eq!(go_dep.name(), "github.com/gin-gonic/gin");
            assert_eq!(go_dep.version_req(), Some("v1.9.1"));
            assert!(go_dep.is_registry());
        }

        #[test]
        fn test_unified_dependency_name_range() {
            let range = Range::new(Position::new(5, 10), Position::new(5, 35));
            let go_dep = UnifiedDependency::Go(GoDependency {
                module_path: "github.com/example/pkg".into(),
                module_path_range: range,
                version: Some("v1.0.0".into()),
                version_range: Some(Range::new(Position::new(5, 36), Position::new(5, 42))),
                directive: GoDirective::Require,
                indirect: false,
            });
            assert_eq!(go_dep.name_range(), range);
        }

        #[test]
        fn test_unified_dependency_version_range() {
            let version_range = Range::new(Position::new(5, 36), Position::new(5, 42));
            let go_dep = UnifiedDependency::Go(GoDependency {
                module_path: "github.com/example/pkg".into(),
                module_path_range: Range::new(Position::new(5, 10), Position::new(5, 35)),
                version: Some("v1.0.0".into()),
                version_range: Some(version_range),
                directive: GoDirective::Require,
                indirect: false,
            });
            assert_eq!(go_dep.version_range(), Some(version_range));
        }

        #[test]
        fn test_unified_dependency_no_version() {
            let go_dep = UnifiedDependency::Go(GoDependency {
                module_path: "github.com/example/pkg".into(),
                module_path_range: Range::new(Position::new(5, 10), Position::new(5, 35)),
                version: None,
                version_range: None,
                directive: GoDirective::Require,
                indirect: false,
            });
            assert_eq!(go_dep.version_req(), None);
            assert_eq!(go_dep.version_range(), None);
        }

        #[test]
        fn test_unified_version() {
            let version = UnifiedVersion::Go(GoVersion {
                version: "v1.9.1".into(),
                time: Some("2023-07-18T14:30:00Z".into()),
                is_pseudo: false,
                retracted: false,
            });
            assert_eq!(version.version_string(), "v1.9.1");
            assert!(!version.is_yanked());
        }

        #[test]
        fn test_unified_version_retracted() {
            let version = UnifiedVersion::Go(GoVersion {
                version: "v1.0.0".into(),
                time: None,
                is_pseudo: false,
                retracted: true,
            });
            assert_eq!(version.version_string(), "v1.0.0");
            assert!(version.is_yanked());
        }

        #[test]
        fn test_unified_version_pseudo() {
            let version = UnifiedVersion::Go(GoVersion {
                version: "v0.0.0-20191109021931-daa7c04131f5".into(),
                time: Some("2019-11-09T02:19:31Z".into()),
                is_pseudo: true,
                retracted: false,
            });
            assert_eq!(
                version.version_string(),
                "v0.0.0-20191109021931-daa7c04131f5"
            );
            assert!(!version.is_yanked());
        }

        #[test]
        fn test_document_state_new() {
            let deps = vec![create_test_dependency()];
            let state = DocumentState::new(Ecosystem::Go, "test content".into(), deps);

            assert_eq!(state.ecosystem, Ecosystem::Go);
            assert_eq!(state.ecosystem_id, "go");
            assert_eq!(state.dependencies.len(), 1);
        }

        #[test]
        fn test_document_state_new_without_parse_result() {
            let content =
                "module example.com/myapp\n\ngo 1.21\n\nrequire github.com/gin-gonic/gin v1.9.1\n"
                    .to_string();
            let doc_state = DocumentState::new_without_parse_result("go", content);

            assert_eq!(doc_state.ecosystem_id, "go");
            assert_eq!(doc_state.ecosystem, Ecosystem::Go);
            assert!(doc_state.parse_result.is_none());
        }

        #[test]
        fn test_document_state_new_from_parse_result() {
            let state = ServerState::new();
            let uri = Uri::from_file_path("/test/go.mod").unwrap();
            let ecosystem = state.ecosystem_registry.get("go").unwrap();
            let content =
                "module example.com/myapp\n\ngo 1.21\n\nrequire github.com/gin-gonic/gin v1.9.1\n"
                    .to_string();

            let parse_result = tokio::runtime::Runtime::new()
                .unwrap()
                .block_on(ecosystem.parse_manifest(&content, &uri))
                .unwrap();

            let doc_state =
                DocumentState::new_from_parse_result("go", content.clone(), parse_result);

            assert_eq!(doc_state.ecosystem_id, "go");
            assert!(doc_state.parse_result.is_some());
        }
    }
}
