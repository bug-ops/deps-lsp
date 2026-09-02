use dashmap::DashMap;
use deps_core::HttpCache;
use deps_core::lockfile::LockFileCache;
use deps_core::net_policy::RegistryAccessPolicy;
use deps_core::osv::{OsvClient, VulnerabilityMap};
use deps_core::{
    ConcreteVersion, DependencyOutcomes, EcosystemId, EcosystemRegistry, PackageName,
    PackageVersions, ParseResult,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::task::JoinHandle;
use tower_lsp_server::Client;
use tower_lsp_server::ls_types::Uri;

/// Upper bound on how long a server-to-client request is allowed to wait for a
/// reply before being abandoned (issue #493). Used both for the detached
/// `workspace/*/refresh` requests below (S2: without it, a client that declares
/// refresh support but stops replying would let these detached tasks — and
/// `tower_lsp_server`'s internal pending-request bookkeeping — accumulate without
/// limit as the user keeps editing) and, via re-export, for the `initialized()`
/// registration requests and `workspace/diagnostic/refresh` in `server.rs` (S1: same
/// hang risk, an unresponsive client would otherwise stall those handlers forever).
/// Also reused (not itself a "refresh") for `workspace/applyEdit` in `server.rs`'s
/// `execute_command` handlers (issue #496): same directly-awaited hang risk, since a
/// client that never answers `applyEdit` would otherwise permanently occupy one of
/// `tower_lsp_server`'s limited `buffer_unordered` concurrency slots.
pub(crate) const CLIENT_REFRESH_TIMEOUT: Duration = Duration::from_secs(5);

// Re-export LoadingState from deps-core for convenience
pub use deps_core::LoadingState;

/// State for a single open document.
///
/// Stores the document content, parsed dependency information, and cached
/// version data for a single file. The state is updated when the document
/// changes or when version information is fetched from the registry.
///
/// Supports multiple package ecosystems via the trait-based `ParseResult`.
///
/// # Examples
///
/// ```no_run
/// use deps_core::EcosystemId;
/// use deps_lsp::document::DocumentState;
///
/// let state = DocumentState::new_without_parse_result(
///     EcosystemId::Cargo,
///     "[dependencies]\nserde = \"1.0\"".into(),
/// );
///
/// assert!(state.cached_versions.is_empty());
/// ```
pub struct DocumentState {
    /// Package ecosystem identifier, exhaustively typed.
    pub ecosystem: EcosystemId,
    /// Original document content
    pub content: String,
    /// Parsed result as trait object, wrapped in `Arc` (rather than `Box`) so
    /// [`Self::parse_result_arc`] can hand a caller a cheap owned clone — letting it
    /// release the DashMap shard `Ref` before an `.await` on a registry-bound
    /// `generate_*` call without deep-cloning ecosystem-specific parse data (#319).
    parse_result: Option<Arc<dyn ParseResult>>,
    /// Latest known version and full version list per package, fetched together in a
    /// single registry round trip (see [`PackageVersions`]).
    pub cached_versions: HashMap<PackageName, PackageVersions>,
    /// Resolved versions from lock file
    pub resolved_versions: HashMap<PackageName, ConcreteVersion>,
    /// OSV.dev scan results, keyed by normalized package name. Empty until
    /// the first background scan completes; carried across document edits
    /// by `preserve_cache` so it is not wiped on every keystroke.
    pub vulnerabilities: VulnerabilityMap,
    /// Yanked, deprecation, and fetch-failure findings from the lifecycle's registry
    /// fetch, keyed by **normalized** package name. This is deliberately a different
    /// type from `FetchResult`'s raw-keyed triple: the split makes a forgotten
    /// normalization at a store/merge site a compile error rather than a silent bug for
    /// ecosystems where normalization changes the name (e.g. PyPI). See
    /// [`DependencyOutcome`](deps_core::DependencyOutcome) for what each of the three
    /// channels means. Empty until the first fetch completes; carried across document
    /// edits by `preserve_cache` so it doesn't flicker off on every keystroke.
    pub outcomes: DependencyOutcomes,
    /// Last successful parse time
    pub parsed_at: Instant,
    /// Current loading state for registry data
    pub loading_state: LoadingState,
    /// When the current loading operation started (for timeout/metrics)
    pub loading_started_at: Option<Instant>,
    /// LSP document version from the client's `didOpen`/`didChange`, `None` if this
    /// state was populated from disk (cold start) rather than an LSP notification.
    ///
    /// Threaded into `WorkspaceEdit.document_changes` so the client can reject a batch
    /// edit whose ranges were computed against a buffer state it has since moved past
    /// (see `handlers::code_lens`).
    pub version: Option<i32>,
}

impl Clone for DocumentState {
    fn clone(&self) -> Self {
        Self {
            ecosystem: self.ecosystem,
            content: self.content.clone(),
            // Cheap: `Arc::clone`, not a deep copy of the parse result.
            parse_result: self.parse_result.clone(),
            cached_versions: self.cached_versions.clone(),
            resolved_versions: self.resolved_versions.clone(),
            vulnerabilities: self.vulnerabilities.clone(),
            outcomes: self.outcomes.clone(),
            parsed_at: self.parsed_at,
            loading_state: self.loading_state,
            // Note: Instant is Copy. Clones share the same loading start time.
            loading_started_at: self.loading_started_at,
            version: self.version,
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
/// use std::time::Duration;
///
/// let limiter = ColdStartLimiter::new(Duration::from_secs(10));
/// let uri = deps_core::test_util::test_uri("/test.toml");
///
/// assert!(limiter.allow_cold_start(&uri));
/// assert!(!limiter.allow_cold_start(&uri)); // Rate limited
/// ```
#[derive(Debug)]
pub struct ColdStartLimiter {
    /// Maps URI to last cold start attempt time.
    last_attempts: DashMap<Uri, Instant>,
    /// Minimum interval between cold start attempts for the same URI, in
    /// milliseconds. Atomic so `set_min_interval` can live-update it from
    /// `did_change_configuration` (issue #499) without disturbing in-flight
    /// `allow_cold_start` callers.
    min_interval_ms: AtomicU64,
}

impl ColdStartLimiter {
    /// Creates a new cold start limiter with the specified minimum interval.
    pub fn new(min_interval: Duration) -> Self {
        Self {
            last_attempts: DashMap::new(),
            min_interval_ms: AtomicU64::new(min_interval.as_millis() as u64),
        }
    }

    /// Updates the minimum interval between cold start attempts.
    ///
    /// Takes effect on the next `allow_cold_start` call. Used to apply a
    /// live-reloaded `cold_start.rate_limit_ms` (issue #499).
    pub fn set_min_interval(&self, min_interval: Duration) {
        self.min_interval_ms
            .store(min_interval.as_millis() as u64, Ordering::Relaxed);
    }

    /// Returns true if cold start is allowed, false if rate limited.
    ///
    /// Updates the last attempt time if the cold start is allowed.
    pub fn allow_cold_start(&self, uri: &Uri) -> bool {
        let min_interval = Duration::from_millis(self.min_interval_ms.load(Ordering::Relaxed));
        let now = Instant::now();

        // Check last attempt time
        if let Some(mut entry) = self.last_attempts.get_mut(uri) {
            let elapsed = now.duration_since(*entry);
            if elapsed < min_interval {
                let retry_after = min_interval.checked_sub(elapsed).unwrap();
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
            .field("ecosystem_id", &self.ecosystem_id())
            .field("content_len", &self.content.len())
            .field("has_parse_result", &self.parse_result.is_some())
            .field("cached_versions_count", &self.cached_versions.len())
            .field("resolved_versions_count", &self.resolved_versions.len())
            .field("vulnerabilities_count", &self.vulnerabilities.len())
            .field("yanked_versions_count", &self.outcomes.yanked_count())
            .field("deprecations_count", &self.outcomes.deprecation_count())
            .field("fetch_failed_count", &self.outcomes.fetch_failure_count())
            .field("parsed_at", &self.parsed_at)
            .field("loading_state", &self.loading_state)
            .field("loading_started_at", &self.loading_started_at)
            .field("version", &self.version)
            .finish()
    }
}

impl DocumentState {
    /// Creates a new document state using trait objects (new architecture).
    ///
    /// This is the preferred constructor for Phase 3+ implementations.
    pub fn new_from_parse_result(
        ecosystem: EcosystemId,
        content: String,
        parse_result: Box<dyn ParseResult>,
    ) -> Self {
        Self {
            ecosystem,
            content,
            parse_result: Some(Arc::from(parse_result)),
            cached_versions: HashMap::new(),
            resolved_versions: HashMap::new(),
            vulnerabilities: VulnerabilityMap::new(),
            outcomes: DependencyOutcomes::new(),
            parsed_at: Instant::now(),
            loading_state: LoadingState::Idle,
            loading_started_at: None,
            version: None,
        }
    }

    /// Creates a new document state without a parse result.
    ///
    /// Used when parsing fails but the document should still be stored
    /// to enable fallback completion and other LSP features.
    pub fn new_without_parse_result(ecosystem: EcosystemId, content: String) -> Self {
        Self {
            ecosystem,
            content,
            parse_result: None,
            cached_versions: HashMap::new(),
            resolved_versions: HashMap::new(),
            vulnerabilities: VulnerabilityMap::new(),
            outcomes: DependencyOutcomes::new(),
            parsed_at: Instant::now(),
            loading_state: LoadingState::Idle,
            loading_started_at: None,
            version: None,
        }
    }

    /// Returns the ecosystem identifier as a `&'static str`, derived from
    /// [`DocumentState::ecosystem`]. Registry lookups (`EcosystemRegistry::get`)
    /// are keyed by string, so this mirrors `ecosystem.id()`.
    pub fn ecosystem_id(&self) -> &'static str {
        self.ecosystem.id()
    }

    /// Gets a reference to the parse result if available.
    pub fn parse_result(&self) -> Option<&dyn ParseResult> {
        self.parse_result.as_deref()
    }

    /// Returns a cheap `Arc` clone of the parse result, if available.
    ///
    /// Lets a caller (e.g. a `handlers::{hover,completion,code_actions}` handler) own
    /// the parse result and release the DashMap shard `Ref` before awaiting a
    /// registry-bound `Ecosystem::generate_*` call, without deep-cloning
    /// ecosystem-specific parse data on every request (#319).
    pub fn parse_result_arc(&self) -> Option<Arc<dyn ParseResult>> {
        self.parse_result.clone()
    }

    /// Updates the cached registry version data (new architecture).
    pub fn update_cached_versions(&mut self, versions: HashMap<PackageName, PackageVersions>) {
        self.cached_versions = versions;
    }

    /// Updates the resolved versions from lock file.
    pub fn update_resolved_versions(&mut self, versions: HashMap<PackageName, ConcreteVersion>) {
        self.resolved_versions = versions;
    }

    /// Updates the OSV.dev scan results.
    pub fn update_vulnerabilities(&mut self, vulnerabilities: VulnerabilityMap) {
        self.vulnerabilities = vulnerabilities;
    }

    /// Replaces the yanked/deprecation/fetch-failure outcome map wholesale (normalized-keyed,
    /// see [`Self::outcomes`]).
    pub fn replace_outcomes(&mut self, outcomes: DependencyOutcomes) {
        self.outcomes = outcomes;
    }

    /// Sets the LSP document version from the client's `didOpen`/`didChange`, or clears
    /// it (`None`) for a document populated from disk rather than an LSP notification.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::EcosystemId;
    /// use deps_lsp::document::DocumentState;
    ///
    /// let mut doc = DocumentState::new_without_parse_result(EcosystemId::Cargo, "".into());
    /// assert!(doc.version.is_none());
    /// doc.set_version(Some(3));
    /// assert_eq!(doc.version, Some(3));
    /// ```
    pub fn set_version(&mut self, version: Option<i32>) {
        self.version = version;
    }

    /// Whether this document has everything `deps-lsp.updateAllOutdated` (and the code
    /// lens that surfaces it) need to safely act: version data isn't currently
    /// `Loading`, and the document has a known LSP version.
    ///
    /// `version: None` means this state was populated from disk after a missed
    /// `didOpen` (server restart/crash) — the client's buffer may hold unsaved edits
    /// the disk copy does not reflect, so batch-editing it is unsafe even though the
    /// document is otherwise loaded.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::EcosystemId;
    /// use deps_lsp::document::DocumentState;
    ///
    /// let mut doc = DocumentState::new_without_parse_result(EcosystemId::Cargo, "".into());
    /// assert!(!doc.is_ready_for_batch_update(), "no version yet");
    ///
    /// doc.set_version(Some(1));
    /// assert!(doc.is_ready_for_batch_update());
    ///
    /// doc.set_loading();
    /// assert!(!doc.is_ready_for_batch_update(), "still loading");
    /// ```
    #[must_use]
    pub fn is_ready_for_batch_update(&self) -> bool {
        self.loading_state != LoadingState::Loading && self.version.is_some()
    }

    /// Mark document as loading registry data.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::EcosystemId;
    /// use deps_lsp::document::DocumentState;
    ///
    /// let mut doc = DocumentState::new_without_parse_result(EcosystemId::Cargo, "".into());
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
    /// use deps_core::EcosystemId;
    /// use deps_lsp::document::{DocumentState, LoadingState};
    ///
    /// let mut doc = DocumentState::new_without_parse_result(EcosystemId::Cargo, "".into());
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
    /// use deps_core::EcosystemId;
    /// use deps_lsp::document::{DocumentState, LoadingState};
    ///
    /// let mut doc = DocumentState::new_without_parse_result(EcosystemId::Cargo, "".into());
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
    /// use deps_core::EcosystemId;
    /// use deps_lsp::document::DocumentState;
    ///
    /// let mut doc = DocumentState::new_without_parse_result(EcosystemId::Cargo, "".into());
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
    /// OSV.dev vulnerability scan client, shared server-lifetime so every
    /// open document's scan benefits from the same query/record cache.
    pub osv: Arc<OsvClient>,
    /// Lock file cache for parsed lock files
    pub lockfile_cache: Arc<LockFileCache>,
    /// Ecosystem registry for trait-based architecture
    pub ecosystem_registry: Arc<EcosystemRegistry>,
    /// Live-updatable Cargo workspace-registry reachability policy (spec #443,
    /// `cargo.workspace_registries`) — the same handle `crate::register_ecosystems` hands to
    /// `CargoEcosystem::with_context`, so `Backend::initialize`/`did_change_configuration`
    /// updating this value here takes effect on every parse from then on, with no need to
    /// reconstruct the ecosystem.
    pub registry_policy: Arc<RegistryAccessPolicy>,
    /// Cold start rate limiter
    pub cold_start_limiter: ColdStartLimiter,
    /// Background task handles
    tasks: tokio::sync::RwLock<HashMap<Uri, JoinHandle<()>>>,
    /// Whether the client advertised `window.workDoneProgress` support during
    /// `initialize`. Set once, read from spawned lifecycle tasks that have no
    /// direct access to `ClientCapabilities` (see `RegistryProgress::start` call
    /// sites in `document::lifecycle`).
    progress_supported: AtomicBool,
    /// Whether the client advertised `workspace.inlayHint.refreshSupport` during
    /// `initialize`. Set once, read from spawned lifecycle tasks (issue #493: a
    /// client that never declared this and never replies would otherwise hang the
    /// unbounded `inlay_hint_refresh` await forever).
    inlay_hint_refresh_supported: AtomicBool,
    /// Whether the client advertised `workspace.codeLens.refreshSupport` during
    /// `initialize`. See `inlay_hint_refresh_supported` for rationale.
    code_lens_refresh_supported: AtomicBool,
}

impl ServerState {
    /// Creates a new server state with default configuration.
    pub fn new() -> Self {
        let registry_policy = Arc::new(RegistryAccessPolicy::default());
        // `HttpCache::with_policy` (not `HttpCache::new`) so this server's one long-lived cache
        // shares the same policy handle `register_ecosystems` hands to `CargoEcosystem` below —
        // issue #455's workspace-tier connect-time guard needs the live policy, not a
        // default-initialized copy.
        let cache = Arc::new(HttpCache::with_policy(Arc::clone(&registry_policy)));
        let osv = Arc::new(OsvClient::new(Arc::clone(&cache)));
        let lockfile_cache = Arc::new(LockFileCache::new());
        let ecosystem_registry = Arc::new(EcosystemRegistry::new());

        // Register ecosystems based on enabled features
        crate::register_ecosystems(
            &ecosystem_registry,
            Arc::clone(&cache),
            Arc::clone(&registry_policy),
        );

        // Default interval, live-updated by `set_min_interval` once `initialize`/
        // `did_change_configuration` parses a real `cold_start.rate_limit_ms` (issue
        // #499). Sourced from `ColdStartConfig::default()` rather than a bare literal
        // so this can never drift from `default_rate_limit_ms()`.
        let cold_start_limiter = ColdStartLimiter::new(Duration::from_millis(
            crate::config::ColdStartConfig::default().rate_limit_ms,
        ));

        Self {
            documents: DashMap::new(),
            cache,
            osv,
            lockfile_cache,
            ecosystem_registry,
            registry_policy,
            cold_start_limiter,
            tasks: tokio::sync::RwLock::new(HashMap::new()),
            progress_supported: AtomicBool::new(false),
            inlay_hint_refresh_supported: AtomicBool::new(false),
            code_lens_refresh_supported: AtomicBool::new(false),
        }
    }

    /// Returns whether the client supports LSP work done progress notifications.
    pub fn supports_progress(&self) -> bool {
        self.progress_supported.load(Ordering::Relaxed)
    }

    /// Records whether the client supports LSP work done progress notifications.
    ///
    /// Called once from `initialize` with the result of negotiating
    /// `window.workDoneProgress` from `ClientCapabilities`.
    pub fn set_progress_supported(&self, supported: bool) {
        self.progress_supported.store(supported, Ordering::Relaxed);
    }

    /// Returns whether the client supports `workspace/inlayHint/refresh`.
    pub fn inlay_hint_refresh_supported(&self) -> bool {
        self.inlay_hint_refresh_supported.load(Ordering::Relaxed)
    }

    /// Records whether the client supports `workspace/inlayHint/refresh`.
    ///
    /// Called once from `initialize` with the result of negotiating
    /// `workspace.inlayHint.refreshSupport` from `ClientCapabilities`.
    pub fn set_inlay_hint_refresh_supported(&self, supported: bool) {
        self.inlay_hint_refresh_supported
            .store(supported, Ordering::Relaxed);
    }

    /// Returns whether the client supports `workspace/codeLens/refresh`.
    pub fn code_lens_refresh_supported(&self) -> bool {
        self.code_lens_refresh_supported.load(Ordering::Relaxed)
    }

    /// Records whether the client supports `workspace/codeLens/refresh`.
    ///
    /// Called once from `initialize` with the result of negotiating
    /// `workspace.codeLens.refreshSupport` from `ClientCapabilities`.
    pub fn set_code_lens_refresh_supported(&self, supported: bool) {
        self.code_lens_refresh_supported
            .store(supported, Ordering::Relaxed);
    }

    /// Fires `workspace/inlayHint/refresh` and `workspace/codeLens/refresh` as
    /// detached, capability-gated, timeout-bounded background requests (issue #493).
    ///
    /// Neither refresh feeds anything downstream (hover/inlay-hint/code-lens
    /// handlers recompute on demand from already-committed document state), so a
    /// failure or timeout is only logged and never blocks the caller's critical
    /// path — the OSV vulnerability commit and diagnostics publish this is called
    /// alongside. The capability gate skips clients that never declared support (and
    /// so may never reply); the timeout additionally bounds a client that declares
    /// support but stops replying, so detached tasks can't accumulate without limit.
    pub fn spawn_refresh_requests(&self, client: &Client) {
        if self.inlay_hint_refresh_supported() {
            let client = client.clone();
            tokio::spawn(async move {
                match tokio::time::timeout(CLIENT_REFRESH_TIMEOUT, client.inlay_hint_refresh())
                    .await
                {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => tracing::debug!("inlay_hint_refresh failed: {:?}", e),
                    Err(_) => tracing::debug!(
                        "inlay_hint_refresh timed out after {CLIENT_REFRESH_TIMEOUT:?}"
                    ),
                }
            });
        }
        if self.code_lens_refresh_supported() {
            let client = client.clone();
            tokio::spawn(async move {
                match tokio::time::timeout(CLIENT_REFRESH_TIMEOUT, client.code_lens_refresh()).await
                {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => tracing::debug!("code_lens_refresh failed: {:?}", e),
                    Err(_) => tracing::debug!(
                        "code_lens_refresh timed out after {CLIENT_REFRESH_TIMEOUT:?}"
                    ),
                }
            });
        }
    }

    /// Retrieves document state by URI.
    ///
    /// Returns a read-only reference to the document state if it exists.
    /// The reference holds a lock on the internal map, so it should be
    /// dropped as soon as possible. Prefer [`Self::with_document`] when the
    /// caller needs to `.await` anything afterward — it makes dropping the
    /// guard before the `.await` structural rather than a convention to remember.
    pub fn get_document(
        &self,
        uri: &Uri,
    ) -> Option<dashmap::mapref::one::Ref<'_, Uri, DocumentState>> {
        self.documents.get(uri)
    }

    /// Extracts owned data from a document without exposing the DashMap shard `Ref`
    /// to the caller.
    ///
    /// `extract` runs synchronously while the shard lock is held and must return only
    /// owned or `Arc`-cloned data (e.g. via [`DocumentState::parse_result_arc`]); the
    /// `Ref` this method acquires is dropped before the call returns, so *that*
    /// particular guard can never leak across an `.await` through `T`. This does not by
    /// itself prevent `extract` from independently capturing and returning some other,
    /// unrelated `Ref` (e.g. from a second `get_document` call on `state`) — `extract`'s
    /// closure environment is not restricted to this method's own guard. The
    /// project-wide backstop against the DashMap Ref-across-await hazard (#333) in
    /// general is the `await-holding-invalid-types` lint configured in the workspace
    /// `clippy.toml` (#334), not this method's type signature alone.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use deps_lsp::document::ServerState;
    /// # use tower_lsp_server::ls_types::Uri;
    /// # async fn example(state: &ServerState, uri: &Uri) {
    /// let content_len = state.with_document(uri, |doc| doc.content.len());
    /// # }
    /// ```
    pub fn with_document<T>(
        &self,
        uri: &Uri,
        extract: impl FnOnce(&DocumentState) -> T,
    ) -> Option<T> {
        self.documents.get(uri).map(|doc| extract(&doc))
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
    /// Cloning `DocumentState` is relatively cheap: `String`/`HashMap` metadata is
    /// deep-cloned, but the parse result is an `Arc` clone (a refcount bump), not a
    /// deep copy of the underlying ecosystem-specific parse data.
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
            let mut doc = DocumentState::new_without_parse_result(EcosystemId::Cargo, content);

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
            let mut doc = DocumentState::new_without_parse_result(EcosystemId::Cargo, content);

            doc.set_loading();
            assert_eq!(doc.loading_state, LoadingState::Loading);

            doc.set_failed();
            assert_eq!(doc.loading_state, LoadingState::Failed);
            assert!(doc.loading_started_at.is_none());
        }

        #[test]
        fn test_loading_state_clone() {
            let content = "[dependencies]\nserde = \"1.0\"".to_string();
            let mut doc = DocumentState::new_without_parse_result(EcosystemId::Cargo, content);

            doc.set_loading();
            let cloned = doc.clone();

            assert_eq!(cloned.loading_state, LoadingState::Loading);
            assert!(cloned.loading_started_at.is_some());
        }

        #[test]
        fn test_loading_state_debug() {
            let content = "[dependencies]\nserde = \"1.0\"".to_string();
            let mut doc = DocumentState::new_without_parse_result(EcosystemId::Cargo, content);
            doc.set_loading();

            let debug_str = format!("{:?}", doc);
            assert!(debug_str.contains("loading_state"));
            assert!(debug_str.contains("Loading"));
        }

        #[test]
        fn test_loading_duration_none_when_idle() {
            let content = "[dependencies]\nserde = \"1.0\"".to_string();
            let doc = DocumentState::new_without_parse_result(EcosystemId::Cargo, content);

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
            let mut doc = DocumentState::new_without_parse_result(EcosystemId::Cargo, content);

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
            let uri = deps_core::test_util::test_uri("/concurrent-loading-test.toml");

            let doc = DocumentState::new_without_parse_result(EcosystemId::Cargo, String::new());
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
            let mut doc =
                DocumentState::new_without_parse_result(EcosystemId::Cargo, String::new());

            doc.set_loading();
            doc.set_loaded();

            // Call again - should be safe
            doc.set_loaded();

            assert_eq!(doc.loading_state, LoadingState::Loaded);
            assert!(doc.loading_started_at.is_none());
        }

        #[test]
        fn test_set_loading_resets_timer() {
            let mut doc =
                DocumentState::new_without_parse_result(EcosystemId::Cargo, String::new());

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
            let mut doc =
                DocumentState::new_without_parse_result(EcosystemId::Cargo, String::new());

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
            let mut doc =
                DocumentState::new_without_parse_result(EcosystemId::Cargo, String::new());

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

    // =========================================================================
    // `is_ready_for_batch_update` tests — the shared predicate `handlers::code_lens`
    // and `server::execute_update_all_outdated` both consult (M7/S1).
    // =========================================================================

    mod is_ready_for_batch_update_tests {
        use super::*;

        #[test]
        fn test_not_ready_without_a_version() {
            let mut doc =
                DocumentState::new_without_parse_result(EcosystemId::Cargo, String::new());
            doc.set_loaded();
            assert!(!doc.is_ready_for_batch_update());
        }

        #[test]
        fn test_not_ready_while_loading_even_with_a_version() {
            let mut doc =
                DocumentState::new_without_parse_result(EcosystemId::Cargo, String::new());
            doc.set_version(Some(1));
            doc.set_loading();
            assert!(!doc.is_ready_for_batch_update());
        }

        #[test]
        fn test_ready_when_loaded_with_a_version() {
            let mut doc =
                DocumentState::new_without_parse_result(EcosystemId::Cargo, String::new());
            doc.set_version(Some(1));
            doc.set_loaded();
            assert!(doc.is_ready_for_batch_update());
        }

        #[test]
        fn test_ready_when_failed_with_a_version() {
            // `Failed` is not `Loading` — a document whose registry fetch failed but
            // which still has a known LSP version is safe to batch-edit (the edit only
            // touches spans already present in `cached_versions`, which may simply be
            // sparse after a failure).
            let mut doc =
                DocumentState::new_without_parse_result(EcosystemId::Cargo, String::new());
            doc.set_version(Some(1));
            doc.set_failed();
            assert!(doc.is_ready_for_batch_update());
        }

        #[test]
        fn test_not_ready_without_version_or_loaded_state() {
            let doc = DocumentState::new_without_parse_result(EcosystemId::Cargo, String::new());
            assert!(!doc.is_ready_for_batch_update());
        }
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

    /// Issue #493: the fire-and-forget refresh call sites in `document::lifecycle`
    /// read these flags synchronously instead of awaiting `ClientCapabilities` — a
    /// wrong default (or a setter that doesn't round-trip) would either suppress a
    /// refresh a client wants or resurrect the original hang by letting an
    /// unsupported client's request be sent anyway.
    #[test]
    fn test_inlay_hint_refresh_supported_defaults_false_and_round_trips() {
        let state = ServerState::new();
        assert!(!state.inlay_hint_refresh_supported());

        state.set_inlay_hint_refresh_supported(true);
        assert!(state.inlay_hint_refresh_supported());

        state.set_inlay_hint_refresh_supported(false);
        assert!(!state.inlay_hint_refresh_supported());
    }

    #[test]
    fn test_code_lens_refresh_supported_defaults_false_and_round_trips() {
        let state = ServerState::new();
        assert!(!state.code_lens_refresh_supported());

        state.set_code_lens_refresh_supported(true);
        assert!(state.code_lens_refresh_supported());

        state.set_code_lens_refresh_supported(false);
        assert!(!state.code_lens_refresh_supported());
    }

    #[tokio::test]
    async fn test_server_state_background_tasks() {
        let state = ServerState::new();
        let uri = deps_core::test_util::test_uri("/test.toml");

        let task = tokio::spawn(async {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        });

        state.spawn_background_task(uri.clone(), task).await;
        state.cancel_background_task(&uri).await;
    }

    #[tokio::test]
    async fn test_spawn_background_task_cancels_previous() {
        let state = ServerState::new();
        let uri = deps_core::test_util::test_uri("/test.toml");

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
        let uri = deps_core::test_util::test_uri("/test.toml");
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
            let uri = deps_core::test_util::test_uri("/test.toml");
            assert!(
                limiter.allow_cold_start(&uri),
                "First request should be allowed"
            );
        }

        #[test]
        fn test_blocks_rapid_requests() {
            let limiter = ColdStartLimiter::new(Duration::from_millis(100));
            let uri = deps_core::test_util::test_uri("/test.toml");

            assert!(limiter.allow_cold_start(&uri), "First request allowed");
            assert!(
                !limiter.allow_cold_start(&uri),
                "Second immediate request should be blocked"
            );
        }

        #[tokio::test]
        async fn test_allows_after_interval() {
            let limiter = ColdStartLimiter::new(Duration::from_millis(50));
            let uri = deps_core::test_util::test_uri("/test.toml");

            assert!(limiter.allow_cold_start(&uri), "First request allowed");
            tokio::time::sleep(Duration::from_millis(60)).await;
            assert!(
                limiter.allow_cold_start(&uri),
                "Request after interval should be allowed"
            );
        }

        /// Issue #499: `set_min_interval` must actually change rate-limiting
        /// behavior, not just be stored inertly.
        #[tokio::test]
        async fn test_set_min_interval_changes_behavior() {
            let limiter = ColdStartLimiter::new(Duration::from_millis(100));
            let uri = deps_core::test_util::test_uri("/test.toml");

            assert!(limiter.allow_cold_start(&uri), "First request allowed");
            assert!(
                !limiter.allow_cold_start(&uri),
                "Second immediate request blocked under the original 100ms interval"
            );

            // `rate_limit_ms: 0` disables rate limiting entirely (`elapsed < ZERO` is
            // never true), so this is deterministic regardless of scheduling jitter —
            // no sleep needed, unlike a short nonzero interval would require.
            limiter.set_min_interval(Duration::ZERO);

            assert!(
                limiter.allow_cold_start(&uri),
                "Lowering the interval to 0 should allow every request immediately"
            );
            assert!(
                limiter.allow_cold_start(&uri),
                "A zero interval keeps allowing consecutive requests"
            );
        }

        #[test]
        fn test_different_uris_independent() {
            let limiter = ColdStartLimiter::new(Duration::from_millis(100));
            let uri1 = deps_core::test_util::test_uri("/test1.toml");
            let uri2 = deps_core::test_util::test_uri("/test2.toml");

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
            let uri1 = deps_core::test_util::test_uri("/test1.toml");
            let uri2 = deps_core::test_util::test_uri("/test2.toml");

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
            let uri = deps_core::test_util::test_uri("/concurrent-test.toml");

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
    // Issue #118 regression tests: ecosystem_id resolution
    // =========================================================================

    /// Regression test for issue #118: before the `EcosystemId` refactor, any
    /// `ecosystem_id` outside `{cargo, npm, pypi, go}` silently fell back to
    /// `Ecosystem::Cargo`. The constructors are now infallible (`DocumentState`
    /// takes `EcosystemId` directly, see the #144 follow-up), so the resolution
    /// risk now lives entirely in `str::parse::<EcosystemId>()` — exercised here
    /// for every registered ecosystem, alongside the constructor's derivation of
    /// `ecosystem_id` back from `EcosystemId::id()`.
    #[test]
    fn test_document_state_new_without_parse_result_resolves_all_ecosystems() {
        for (id, expected) in [
            ("cargo", EcosystemId::Cargo),
            ("npm", EcosystemId::Npm),
            ("pypi", EcosystemId::Pypi),
            ("go", EcosystemId::Go),
            ("bundler", EcosystemId::Bundler),
            ("dart", EcosystemId::Dart),
            ("maven", EcosystemId::Maven),
            ("composer", EcosystemId::Composer),
            ("gradle", EcosystemId::Gradle),
            ("swift", EcosystemId::Swift),
            ("nuget", EcosystemId::NuGet),
            ("deno", EcosystemId::Deno),
            ("github-actions", EcosystemId::GithubActions),
        ] {
            let parsed: EcosystemId = id
                .parse()
                .unwrap_or_else(|_| panic!("ecosystem_id {id:?} failed to parse"));
            assert_eq!(parsed, expected, "ecosystem_id {id:?} misresolved");

            let doc = DocumentState::new_without_parse_result(expected, String::new());
            assert_eq!(doc.ecosystem, expected);
            assert_eq!(doc.ecosystem_id(), id);
        }
    }

    /// Same regression as above, but through `new_from_parse_result` with a real
    /// `ParseResult` for one of the previously-misclassified ecosystems (maven).
    /// Parses `"maven"` explicitly first, mirroring the parse-then-construct
    /// sequence `document::lifecycle::resolve_ecosystem_id` performs in production.
    #[cfg(feature = "maven")]
    #[test]
    fn test_document_state_new_from_parse_result_maven_not_misclassified_as_cargo() {
        let state = ServerState::new();
        let uri = deps_core::test_util::test_uri("/test/pom.xml");
        let ecosystem = state.ecosystem_registry.get("maven").unwrap();
        let content = r"<project>
  <dependencies>
    <dependency>
      <groupId>org.apache.commons</groupId>
      <artifactId>commons-lang3</artifactId>
      <version>3.12.0</version>
    </dependency>
  </dependencies>
</project>
"
        .to_string();

        let parse_result = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(ecosystem.parse_manifest(&content, &uri))
            .unwrap();

        let ecosystem_id: EcosystemId = "maven"
            .parse()
            .expect("maven must resolve to an EcosystemId");
        let doc_state = DocumentState::new_from_parse_result(ecosystem_id, content, parse_result);

        assert_eq!(doc_state.ecosystem_id(), "maven");
        assert_eq!(doc_state.ecosystem, EcosystemId::Maven);
    }

    // =========================================================================
    // Cargo ecosystem tests
    // =========================================================================

    #[cfg(feature = "cargo")]
    mod cargo_tests {
        use super::*;

        #[test]
        fn test_document_state_creation() {
            let state =
                DocumentState::new_without_parse_result(EcosystemId::Cargo, "test content".into());

            assert_eq!(state.ecosystem, EcosystemId::Cargo);
            assert_eq!(state.content, "test content");
            assert!(state.cached_versions.is_empty());
        }

        #[test]
        fn test_server_state_document_operations() {
            let state = ServerState::new();
            let uri = deps_core::test_util::test_uri("/test.toml");
            let doc_state =
                DocumentState::new_without_parse_result(EcosystemId::Cargo, "test".into());

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
        fn test_document_state_new_from_parse_result() {
            let state = ServerState::new();
            let uri = deps_core::test_util::test_uri("/test/Cargo.toml");
            let ecosystem = state.ecosystem_registry.get("cargo").unwrap();
            let content = "[dependencies]\nserde = \"1.0\"\n".to_string();

            let parse_result = tokio::runtime::Runtime::new()
                .unwrap()
                .block_on(ecosystem.parse_manifest(&content, &uri))
                .unwrap();

            let doc_state = DocumentState::new_from_parse_result(
                EcosystemId::Cargo,
                content.clone(),
                parse_result,
            );

            assert_eq!(doc_state.ecosystem_id(), "cargo");
            assert_eq!(doc_state.content, content);
            assert!(doc_state.parse_result.is_some());
        }

        #[test]
        fn test_document_state_new_without_parse_result() {
            let content = "[dependencies]\nserde = \"1.0\"\n".to_string();
            let doc_state = DocumentState::new_without_parse_result(EcosystemId::Cargo, content);

            assert_eq!(doc_state.ecosystem_id(), "cargo");
            assert_eq!(doc_state.ecosystem, EcosystemId::Cargo);
            assert!(doc_state.parse_result.is_none());
        }

        #[test]
        fn test_document_state_update_resolved_versions() {
            let mut state =
                DocumentState::new_without_parse_result(EcosystemId::Cargo, "test".into());

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
            let mut state =
                DocumentState::new_without_parse_result(EcosystemId::Cargo, "test".into());

            let mut cached = HashMap::new();
            cached.insert("serde".into(), PackageVersions::latest_only("1.0.210"));

            state.update_cached_versions(cached);
            assert_eq!(state.cached_versions.len(), 1);
        }

        #[test]
        fn test_document_state_parse_result_accessor() {
            let state = DocumentState::new_without_parse_result(EcosystemId::Cargo, "test".into());
            assert!(state.parse_result().is_none());
        }

        #[test]
        fn test_document_state_clone() {
            let state =
                DocumentState::new_without_parse_result(EcosystemId::Cargo, "test content".into());
            let cloned = state.clone();

            assert_eq!(cloned.ecosystem, state.ecosystem);
            assert_eq!(cloned.content, state.content);
            assert!(cloned.parse_result.is_none());
        }

        /// `parse_result` is stored as `Arc<dyn ParseResult>` (#319), so — unlike the
        /// old `Box`-backed field, which `Clone` had to silently drop — a clone now
        /// carries a cheap `Arc` clone of the *same* parse result rather than losing it.
        #[test]
        fn test_document_state_clone_preserves_parse_result() {
            let uri = deps_core::test_util::test_uri("/test/Cargo.toml");
            let ecosystem = ServerState::new().ecosystem_registry.get("cargo").unwrap();
            let content = "[dependencies]\nserde = \"1.0\"\n".to_string();
            let parse_result = tokio::runtime::Runtime::new()
                .unwrap()
                .block_on(ecosystem.parse_manifest(&content, &uri))
                .unwrap();

            let state =
                DocumentState::new_from_parse_result(EcosystemId::Cargo, content, parse_result);
            let cloned = state.clone();

            assert!(
                cloned.parse_result_arc().is_some(),
                "clone must still carry the parse result"
            );
            assert!(std::sync::Arc::ptr_eq(
                &state.parse_result_arc().unwrap(),
                &cloned.parse_result_arc().unwrap()
            ));
        }

        #[test]
        fn test_document_state_debug() {
            let state = DocumentState::new_without_parse_result(EcosystemId::Cargo, "test".into());
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

        #[test]
        fn test_document_state_new_without_parse_result() {
            let content = r#"{"dependencies": {"express": "^4.18.0"}}"#.to_string();
            let doc_state = DocumentState::new_without_parse_result(EcosystemId::Npm, content);

            assert_eq!(doc_state.ecosystem_id(), "npm");
            assert_eq!(doc_state.ecosystem, EcosystemId::Npm);
            assert!(doc_state.parse_result.is_none());
        }
    }

    // =========================================================================
    // Deno ecosystem tests
    // =========================================================================

    #[cfg(feature = "deno")]
    mod deno_tests {
        use super::*;

        #[test]
        fn test_document_state_new_without_parse_result() {
            let content = r#"{"imports": {"@std/fs": "jsr:@std/fs@^1.0"}}"#.to_string();
            let doc_state = DocumentState::new_without_parse_result(EcosystemId::Deno, content);

            assert_eq!(doc_state.ecosystem_id(), "deno");
            assert_eq!(doc_state.ecosystem, EcosystemId::Deno);
            assert!(doc_state.parse_result.is_none());
        }
    }

    // =========================================================================
    // PyPI ecosystem tests
    // =========================================================================

    #[cfg(feature = "pypi")]
    mod pypi_tests {
        use super::*;

        #[test]
        fn test_document_state_new_without_parse_result() {
            let content = "[project]\ndependencies = [\"requests>=2.0.0\"]\n".to_string();
            let doc_state = DocumentState::new_without_parse_result(EcosystemId::Pypi, content);

            assert_eq!(doc_state.ecosystem_id(), "pypi");
            assert_eq!(doc_state.ecosystem, EcosystemId::Pypi);
            assert!(doc_state.parse_result.is_none());
        }
    }

    // =========================================================================
    // Go ecosystem tests
    // =========================================================================

    #[cfg(feature = "go")]
    mod go_tests {
        use super::*;

        #[test]
        fn test_document_state_new_without_parse_result() {
            let content =
                "module example.com/myapp\n\ngo 1.21\n\nrequire github.com/gin-gonic/gin v1.9.1\n"
                    .to_string();
            let doc_state = DocumentState::new_without_parse_result(EcosystemId::Go, content);

            assert_eq!(doc_state.ecosystem_id(), "go");
            assert_eq!(doc_state.ecosystem, EcosystemId::Go);
            assert!(doc_state.parse_result.is_none());
        }

        #[test]
        fn test_document_state_new_from_parse_result() {
            let state = ServerState::new();
            let uri = deps_core::test_util::test_uri("/test/go.mod");
            let ecosystem = state.ecosystem_registry.get("go").unwrap();
            let content =
                "module example.com/myapp\n\ngo 1.21\n\nrequire github.com/gin-gonic/gin v1.9.1\n"
                    .to_string();

            let parse_result = tokio::runtime::Runtime::new()
                .unwrap()
                .block_on(ecosystem.parse_manifest(&content, &uri))
                .unwrap();

            let doc_state = DocumentState::new_from_parse_result(
                EcosystemId::Go,
                content.clone(),
                parse_result,
            );

            assert_eq!(doc_state.ecosystem_id(), "go");
            assert!(doc_state.parse_result.is_some());
        }
    }
}
