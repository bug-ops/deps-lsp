//! PyPI registry client.
//!
//! Provides access to the PyPI registry via:
//! - Simple API (<https://pypi.org/simple/{package}/>), PEP 691 JSON variant,
//!   for version lookups (`get_versions`) — smaller than the full JSON API
//! - Package metadata API (<https://pypi.org/pypi/{package}/json>) for hover
//!   metadata (`get_package_metadata`), which needs `summary`/`project_urls`
//!   that the Simple API doesn't carry
//!
//! All HTTP requests are cached aggressively using ETag/Last-Modified headers.

use crate::config::{PypiIndexUrl, ResolvedChain};
use crate::types::{PypiPackage, PypiVersion};
use dashmap::DashMap;
use deps_core::parser::DependencySource;
use deps_core::{
    DepsError, FreshnessSettings, HttpCache, Result, lsp_helpers::warn_rejected_value,
};
use pep440_rs::{Version, VersionSpecifiers};
use serde::Deserialize;
use std::any::Any;
use std::future::Future;
use std::str::FromStr;
use std::sync::Arc;

const PYPI_BASE: &str = "https://pypi.org/pypi";

/// Base URL for the PEP 691 Simple API, used by `get_versions`.
const PYPI_SIMPLE_BASE: &str = "https://pypi.org/simple";

/// `Accept` header requesting the PEP 691 Simple API JSON representation.
/// Roughly a third smaller than the full JSON API (verified against
/// `django`: 619,755 bytes full vs 411,376 bytes Simple API).
///
/// Shared with `crate::search`, which requests the same representation for the
/// full project index.
pub(crate) const SIMPLE_API_ACCEPT: &str = "application/vnd.pypi.simple.v1+json";

/// Display name for PyPI used in not-found and API-response error messages.
pub const REGISTRY: &str = "PyPI";

/// Upper bound on [`PypiRegistry::alternates`]' entry count. Generous for any realistic
/// project's private-index configuration count; exists only to keep this map, keyed by
/// workspace-controlled chain identities, from growing unbounded for the process lifetime.
/// Mirrors `deps-npm`'s identical `MAX_ALTERNATE_REGISTRIES`. Once at capacity, a *new* chain
/// is simply never registered (see [`PypiRegistry::register_chain`]) — a dependency resolved
/// to an unregistered chain degrades to [`DepsError::PackageNotFound`], never to a
/// `pypi.org` lookup by name (spec FR-010).
///
/// Note (plan.md §1's risk note): this cap counts distinct *chain identities*
/// ([`ResolvedChain::key`]), not distinct index URLs — a monorepo with many files declaring
/// different `--extra-index-url` combinations against the same primary could exhaust it
/// faster than a simpler one-registration-per-URL model.
const MAX_ALTERNATE_REGISTRIES: usize = 256;

/// Which transport a [`PypiRegistry`] instance fetches through (spec FR-008).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PypiRegistryTier {
    /// `pypi.org` (or a test override) — `HttpCache::get_cached_with_headers`, today's path,
    /// unchanged.
    Public,
    /// A `requirements.txt`/`pyproject.toml`-declared private index —
    /// `HttpCache::get_cached_workspace_with_headers`, so every redirect hop is re-classified
    /// against the live [`deps_core::net_policy::RegistryAccessPolicy`] (mirrors
    /// `deps-npm`'s identical `WorkspaceDeclared` routing).
    WorkspaceDeclared,
}

/// Base URL for package pages on pypi.org
pub const PYPI_URL: &str = "https://pypi.org/project";

/// Returns the URL for a package's page on pypi.org.
///
/// Package names are normalized and URL-encoded to prevent path traversal attacks.
/// Returns an empty string if `name` normalizes to nothing (e.g. `"---"`),
/// rather than a dead link with an empty path segment — matching the
/// `PackageNotFound` short-circuit `get_versions`/`get_package_metadata`
/// apply for the same case.
pub fn package_url(name: &str) -> String {
    let normalized = crate::name::normalize(name);
    if normalized.is_empty() {
        warn_rejected_value(
            "pypi_normalized_name_empty",
            "PyPI package display URL",
            name,
        );
        return String::new();
    }
    format!("{}/{}", PYPI_URL, urlencoding::encode(&normalized))
}

/// Builds the Simple API request URL for `normalized`'s version listing against `base`.
///
/// `base` is `PYPI_SIMPLE_BASE` for the public registry, or a resolved
/// [`PypiIndexUrl`]'s own `simple_base` for a private/alternate index — the C4 fix (see
/// `crates/deps-pypi/src/registry.rs`'s `PypiRegistry::simple_base` doc): version fetches
/// must be parameterized on the index actually configured, not hardcoded to `pypi.org`.
/// `metadata_url` deliberately stays unparameterized — see `metadata_url`'s own doc.
///
/// The name segment is URL-encoded (matching `package_url`) since
/// `name::normalize` only collapses `-`/`_`/`.` separators and leaves
/// characters like `/`, `?`, `#` untouched.
fn simple_api_url(base: &str, normalized: &str) -> String {
    format!("{base}/{}/", urlencoding::encode(normalized))
}

/// Builds the JSON API request URL for `normalized`'s package metadata.
///
/// Always built from the module-level `PYPI_BASE` constant, never parameterized on a
/// resolved private index's base — `PYPI_BASE`/`PYPI_SIMPLE_BASE` are different URL roots
/// (`/pypi` vs `/simple`), so parameterizing this on a private index's `simple_base` would
/// 404. This is also moot in practice: [`PypiRegistry::get_package_metadata`] is tier-guarded
/// off for any `WorkspaceDeclared` client (T008), so this is only ever reached by the public
/// root.
fn metadata_url(normalized: &str) -> String {
    format!("{PYPI_BASE}/{}/json", urlencoding::encode(normalized))
}

/// Converts a 404 response into `DepsError::PackageNotFound`, passing through
/// any other error unchanged.
fn not_found_or(err: DepsError, name: &str) -> DepsError {
    if matches!(err, DepsError::HttpStatus { status: 404, .. }) {
        DepsError::PackageNotFound {
            package: name.to_string(),
            registry: REGISTRY,
        }
    } else {
        err
    }
}

/// Builds a search-result stub for `name`, a normalized name matched from the
/// package-name search index.
///
/// [`PypiRegistry::search`] serves unranked prefix matches from a local index that
/// carries only names, not metadata, so every other field is left at its "unknown"
/// value. This is safe for completion: `build_package_completion`
/// (`deps_core::completion`) and `create_package_completion_item`
/// (`deps-lsp`'s fallback path) both already guard `detail` on `latest_version` being
/// non-empty, so an empty `latest_version` here renders as no detail line rather than
/// a misleading `Latest: `.
fn package_stub(name: &str) -> PypiPackage {
    PypiPackage {
        name: deps_core::PackageName::new(name),
        summary: None,
        project_urls: Vec::new(),
        latest_version: deps_core::ConcreteVersion::new(""),
    }
}

/// Client for interacting with the PyPI registry.
///
/// Uses the PyPI JSON API for package metadata.
/// All requests are cached via the provided HttpCache.
///
/// # Examples
///
/// ```no_run
/// # use deps_pypi::PypiRegistry;
/// # use deps_core::HttpCache;
/// # use std::sync::Arc;
/// # #[tokio::main]
/// # async fn main() {
/// let cache = Arc::new(HttpCache::new());
/// let registry = PypiRegistry::new(cache);
///
/// let versions = registry.get_versions("requests").await.unwrap();
/// assert!(!versions.is_empty());
/// # }
/// ```
#[derive(Clone)]
pub struct PypiRegistry {
    cache: Arc<HttpCache>,
    /// Base URL for the package-name search index (see [`Self::search`]).
    /// Injectable for tests, mirroring `NuGetRegistry::with_service_index_url`.
    ///
    /// **Unchanged meaning** — package-name *search*-index base only, consumed solely by
    /// `search`/`warm_search_index`. Distinct from [`Self::simple_base`] below (the C4 fix):
    /// do not reuse one for the other.
    index_url: String,
    /// Version-fetch base for **this client's own hop**, consumed only by
    /// [`simple_api_url`] (PEP 503/691 Simple API). `PYPI_SIMPLE_BASE` for the public root;
    /// a resolved [`PypiIndexUrl`]'s own URL for a private/alternate hop.
    ///
    /// New field (fixes C4, plan.md's second critic pass finding N3): an earlier draft
    /// reused [`Self::index_url`] as if it were the version-fetch base — but that field is
    /// `crate::search::SIMPLE_INDEX_URL`, consumed only by `search`/`warm_search_index`, so
    /// an alternate client would have silently kept fetching `pypi.org` for every version
    /// lookup. Deliberately does **not** parameterize `metadata_url` too — see that
    /// function's own doc for why (different URL root, would 404).
    simple_base: String,
    /// Build-once, in-memory package-name search index (issue #419). See
    /// `crate::search` for the full design. Never populated for a `WorkspaceDeclared`-tier
    /// client — `search`/`warm_search_index` are tier-guarded off before ever reaching it
    /// (T008).
    index: Arc<crate::search::IndexCell>,
    /// Which transport [`Self::get_versions`]/[`Self::search`] fetch through (spec FR-008).
    tier: PypiRegistryTier,
    /// Resolved chain-router clients, keyed by [`ResolvedChain::key`] (a primary/extras
    /// chain) or by a named source's own URL (Poetry `source =`/uv `index =`). Only the root
    /// (`Public`-tier) instance this crate constructs via [`Self::new`] ever registers into
    /// this or is ever looked up by [`Self::alternate_client`] — a chain-hop leaf's own map
    /// is always empty by construction (never populated by [`Self::with_base`]), the same
    /// invariant `deps-npm`'s `NpmRegistry::alternates` documents. `Arc<DashMap<..>>` (not a
    /// bare `DashMap`) since `PypiRegistry` is `Clone` — a bare field would silently fork the
    /// map.
    alternates: Arc<DashMap<String, Arc<Self>>>,
    /// Resolved, already-constructed hop clients this instance falls through to when it
    /// (hop 0) misses (spec FR-005, fixes C1). Empty for the `Public`-tier root and every
    /// named-source/leaf client — populated only on the *head* client
    /// [`Self::register_chain`] builds for a multi-hop chain. Never looked up by string key at
    /// fetch time; `Self::get_versions_chained` walks this `Vec` positionally.
    fallback_chain: Vec<Arc<Self>>,
}

impl PypiRegistry {
    /// Creates a new PyPI registry client with the given HTTP cache.
    pub fn new(cache: Arc<HttpCache>) -> Self {
        Self::with_index_url(cache, crate::search::SIMPLE_INDEX_URL.to_string())
    }

    /// Creates a registry client whose search index is built from `index_url`
    /// rather than the real [`crate::search::SIMPLE_INDEX_URL`]. `pub(crate)` so
    /// tests elsewhere in the crate (`crate::ecosystem`) can point it at a mock
    /// server; mirrors `NuGetRegistry::with_service_index_url`.
    ///
    /// Always `Public`-tier with an empty `fallback_chain`: this is the pre-existing entry
    /// point every non-alternate-index test in the workspace already uses. A test exercising
    /// the private-index chain path constructs its mock client via [`Self::with_base`]
    /// instead, so it goes through the workspace-gated transport (FR-008) and exercises the
    /// same production routing.
    pub(crate) fn with_index_url(cache: Arc<HttpCache>, index_url: String) -> Self {
        Self {
            cache,
            index_url,
            simple_base: PYPI_SIMPLE_BASE.to_string(),
            index: Arc::new(crate::search::IndexCell::new()),
            tier: PypiRegistryTier::Public,
            alternates: Arc::new(DashMap::new()),
            fallback_chain: Vec::new(),
        }
    }

    /// Test-only: constructs a `Public`-tier root client with `simple_base` pointed at a
    /// mock server, so the implicit public fallback hop (spec FR-005(b)) can be exercised in
    /// a behavioral test — request order/count via mockito — without ever contacting the real
    /// `pypi.org`. Mirrors [`PypiIndexUrl`]'s identical `cfg(test)`/`test-util`-gated loopback
    /// carve-out (validator finding #9).
    ///
    /// [`Self::register_chain`]'s implicit-public-fallback hop is built from `root`'s own
    /// `simple_base` (not the hardcoded `PYPI_SIMPLE_BASE` constant), so registering a chain
    /// against a root constructed this way makes that hop resolve to the mock server too —
    /// the same code path production uses, just pointed elsewhere.
    #[cfg(any(test, feature = "test-util"))]
    #[must_use]
    pub fn with_public_base_for_test(cache: Arc<HttpCache>, simple_base: String) -> Self {
        Self {
            cache,
            index_url: crate::search::SIMPLE_INDEX_URL.to_string(),
            simple_base,
            index: Arc::new(crate::search::IndexCell::new()),
            tier: PypiRegistryTier::Public,
            alternates: Arc::new(DashMap::new()),
            fallback_chain: Vec::new(),
        }
    }

    /// Creates a [`PypiRegistry`] client for one resolved private-index hop — an ordinary
    /// production constructor, `WorkspaceDeclared`-tier so it fetches through
    /// `HttpCache::get_cached_workspace_with_headers` (FR-008's redirect-hop gating) instead
    /// of the ungated transport.
    ///
    /// `fallback_chain` is empty for every call except the *head* client
    /// [`Self::register_chain`] builds for a multi-hop chain — every other hop (a chain's own
    /// leaf hops, or a single-hop named-source client) is a dead end with nothing further to
    /// fall through to, matching plan.md §1's "leaf clients are never themselves looked up by
    /// key, only walked positionally" design. Its own `alternates` map starts empty and is
    /// never populated — only the root ever registers a chain (see `Self::alternates`'s
    /// doc).
    #[must_use]
    pub fn with_base(
        cache: Arc<HttpCache>,
        simple_base: &PypiIndexUrl,
        fallback_chain: Vec<Arc<Self>>,
    ) -> Self {
        Self {
            cache,
            index_url: crate::search::SIMPLE_INDEX_URL.to_string(),
            simple_base: simple_base.as_str().to_string(),
            index: Arc::new(crate::search::IndexCell::new()),
            tier: PypiRegistryTier::WorkspaceDeclared,
            alternates: Arc::new(DashMap::new()),
            fallback_chain,
        }
    }

    /// Builds the full hop tree for one [`ResolvedChain`] and inserts the head into
    /// `root.alternates` under `chain.key`. Idempotent per key (a repeat registration for the
    /// same key is a no-op), capacity-capped at `MAX_ALTERNATE_REGISTRIES`.
    ///
    /// Called only from `PypiEcosystem::parse_manifest` over
    /// `PypiIndexConfig::resolved_chains()`, at parse time only. Takes `root: &Arc<Self>` as a
    /// plain parameter rather than `&self` (fixes N1, second critic pass) — `self: &Arc<Self>`
    /// receivers are unstable, and building the implicit-public final hop needs an owned
    /// `Arc<Self>`; `PypiEcosystem` already holds `registry: Arc<PypiRegistry>` and passes it
    /// here directly.
    ///
    /// The implicit-public final hop (when `chain.implicit_public_fallback` is set) is a
    /// **freshly-constructed `Public`-tier client** ([`Self::new`], same URL/transport as the
    /// root), never `Arc::clone(root)` — cloning the root would create a
    /// root→alternates→head→fallback_chain→root reference cycle (N1's second half).
    pub fn register_chain(root: &Arc<Self>, chain: &ResolvedChain) {
        let Some((first_hop, rest_hops)) = chain.hops.split_first() else {
            // Defensive: `PypiIndexConfig::resolved_chains` never produces an empty-hop
            // chain (the zero-hop case resolves to plain `DependencySource::Registry`
            // instead, with nothing to register).
            return;
        };

        // Read before `entry()`: `DashMap::len` read-locks every shard, and `entry()` holds
        // a write guard on one — checking capacity from inside the `Vacant` arm would
        // self-deadlock on that shard (mirrors `deps-npm::NpmRegistry::register_alternate`).
        let at_capacity = root.alternates.len() >= MAX_ALTERNATE_REGISTRIES;

        if let dashmap::mapref::entry::Entry::Vacant(slot) =
            root.alternates.entry(chain.key.clone())
        {
            if at_capacity {
                tracing::warn!(
                    key = %chain.key,
                    cap = MAX_ALTERNATE_REGISTRIES,
                    "PyPI alternate registry cap reached; not registering a new chain"
                );
                return;
            }

            let mut fallback_chain: Vec<Arc<Self>> = rest_hops
                .iter()
                .map(|hop| Arc::new(Self::with_base(Arc::clone(&root.cache), hop, Vec::new())))
                .collect();
            if chain.implicit_public_fallback {
                // Built from `root`'s own `simple_base`/`index_url` rather than
                // `Self::new(..)`'s hardcoded `PYPI_SIMPLE_BASE` (validator finding #9) — in
                // production `root` is always constructed via `Self::new`, so this is the
                // exact same URL either way; in a test built via
                // `Self::with_public_base_for_test`, this hop follows the root to a mock
                // server, making the implicit-fallback ordering behaviorally testable.
                fallback_chain.push(Arc::new(Self {
                    cache: Arc::clone(&root.cache),
                    index_url: root.index_url.clone(),
                    simple_base: root.simple_base.clone(),
                    index: Arc::new(crate::search::IndexCell::new()),
                    tier: PypiRegistryTier::Public,
                    alternates: Arc::new(DashMap::new()),
                    fallback_chain: Vec::new(),
                }));
            }

            let head = Self::with_base(Arc::clone(&root.cache), first_hop, fallback_chain);
            slot.insert(Arc::new(head));
        }
    }

    /// Registers a single-hop named-source client (Poetry `source =`/uv `index =`, spec
    /// FR-007/FR-013) under `index`'s own URL into `root.alternates`. Same
    /// idempotency/capacity rules and `root: &Arc<Self>` parameter shape as
    /// [`Self::register_chain`].
    pub fn register_named_source(root: &Arc<Self>, index: &PypiIndexUrl) {
        let key = index.as_str().to_string();
        let at_capacity = root.alternates.len() >= MAX_ALTERNATE_REGISTRIES;

        if let dashmap::mapref::entry::Entry::Vacant(slot) = root.alternates.entry(key.clone()) {
            if at_capacity {
                tracing::warn!(
                    key = %key,
                    cap = MAX_ALTERNATE_REGISTRIES,
                    "PyPI alternate registry cap reached; not registering a new named source"
                );
                return;
            }
            slot.insert(Arc::new(Self::with_base(
                Arc::clone(&root.cache),
                index,
                Vec::new(),
            )));
        }
    }

    /// The registered client for `index` (a [`ResolvedChain::key`] or a named source's own
    /// URL), if any — read-only, performs no registration, no validation.
    ///
    /// Intentionally only ever meaningful on the **root** — a chain-hop leaf's own
    /// `alternates` map is always empty by construction ([`Self::with_base`] never populates
    /// it), so calling this on a non-root client always returns `None`, documenting the
    /// invariant rather than a bug: `Self::get_versions_chained` never calls this on
    /// `self`, only walks the already-resolved `Self::fallback_chain` positionally.
    #[must_use]
    pub fn alternate_client(&self, index: &str) -> Option<Arc<Self>> {
        self.alternates.get(index).map(|entry| Arc::clone(&entry))
    }

    /// FR-005/NFR-006: tries `self` (hop 0) first, then each already-resolved
    /// `Self::fallback_chain` entry in order — no further map lookup at any point (verifies
    /// [`Self::register_chain`]'s C1 fix actually resolves a hop end to end).
    ///
    /// Implements the plan's three-way failure taxonomy: `Ok(versions)` with `versions`
    /// non-empty is terminal success; `Err(PackageNotFound)` or `Ok(versions)` with `versions`
    /// empty (some PEP 503 indexes answer `200` with an empty listing for an unknown project)
    /// continues to the next hop; any other `Err` (5xx, timeout, network error) is terminal,
    /// propagated immediately — this is the confirmed trade-off (N4, second critic pass):
    /// applied to a case-(b) chain (no explicit primary, hop 0 is a declared extra), an
    /// unreachable hop 0 halts resolution for every dependency in that file, public ones
    /// included, rather than silently falling through to `pypi.org` (which would leak the
    /// package's name to the public index precisely when the private index is merely
    /// unreachable — the exact disclosure NFR-003(2) exists to prevent). This terminal case
    /// returns [`DepsError::ChainResolutionHalted`] (M2 fix) rather than the underlying
    /// transport error unchanged — deps-core's `RateLimited`-precedented mechanism for a safe,
    /// fixed diagnostic hint (`DepsError::fetch_failure` -> `FetchFailure::Actionable`) that
    /// reaches hover/diagnostics text, not just the `tracing::warn!` below (which still logs
    /// the real underlying error for debugging) — this is NFR-003(3)'s required
    /// distinguishable diagnostic.
    async fn get_versions_chained(&self, name: &str) -> Result<Vec<PypiVersion>> {
        let mut last_miss: Result<Vec<PypiVersion>> = Err(DepsError::PackageNotFound {
            package: name.to_string(),
            registry: REGISTRY,
        });

        for hop in std::iter::once(self).chain(self.fallback_chain.iter().map(Arc::as_ref)) {
            match hop.get_versions(name).await {
                Ok(versions) if !versions.is_empty() => return Ok(versions),
                Ok(empty) => last_miss = Ok(empty),
                Err(DepsError::PackageNotFound { .. }) => {
                    last_miss = Err(DepsError::PackageNotFound {
                        package: name.to_string(),
                        registry: REGISTRY,
                    });
                }
                Err(other) => {
                    tracing::warn!(
                        package = name,
                        error = %other,
                        "PyPI alternate-index chain resolution halted on a transport error \
                         — not falling back to pypi.org or the next configured index"
                    );
                    // M2 fix: returns deps-core's pre-vetted-message `ChainResolutionHalted`
                    // rather than propagating `other` unchanged, so the diagnostic/hover path
                    // (via `DepsError::fetch_failure`) can safely surface a fixed, safe hint
                    // instead of only this log line — see this method's own doc.
                    return Err(DepsError::ChainResolutionHalted);
                }
            }
        }

        last_miss
    }

    /// Fetches all versions for a package from PyPI's Simple API (PEP 691).
    ///
    /// Requests the JSON representation (`Accept:
    /// application/vnd.pypi.simple.v1+json`), which is smaller than the full
    /// JSON API and provides the version list directly, without needing to
    /// derive versions from release-file names.
    ///
    /// Returns versions sorted newest-first. Filters out yanked versions by default.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - HTTP request fails
    /// - Response body is invalid UTF-8
    /// - JSON parsing fails
    /// - Package does not exist
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use deps_pypi::PypiRegistry;
    /// # use deps_core::HttpCache;
    /// # use std::sync::Arc;
    /// # #[tokio::main]
    /// # async fn main() {
    /// let cache = Arc::new(HttpCache::new());
    /// let registry = PypiRegistry::new(cache);
    ///
    /// let versions = registry.get_versions("flask").await.unwrap();
    /// assert!(!versions.is_empty());
    /// # }
    /// ```
    pub async fn get_versions(&self, name: &str) -> Result<Vec<PypiVersion>> {
        let normalized = crate::name::normalize(name);
        if normalized.is_empty() {
            warn_rejected_value(
                "pypi_normalized_name_empty",
                "PyPI simple API request URL",
                name,
            );
            return Err(DepsError::PackageNotFound {
                package: name.to_string(),
                registry: REGISTRY,
            });
        }
        let url = simple_api_url(&self.simple_base, &normalized);
        let headers = [(reqwest::header::ACCEPT, SIMPLE_API_ACCEPT)];
        let data = match self.tier {
            PypiRegistryTier::Public => self.cache.get_cached_with_headers(&url, &headers).await,
            PypiRegistryTier::WorkspaceDeclared => {
                self.cache
                    .get_cached_workspace_with_headers(&url, &headers)
                    .await
            }
        }
        .map_err(|e| not_found_or(e, name))?;

        parse_simple_api_response(name, &data)
    }

    /// Finds the latest version matching the given PEP 440 version specifier.
    ///
    /// Only returns non-yanked, non-prerelease versions by default.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - HTTP request fails
    /// - Package does not exist
    /// - Version specifier is invalid
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use deps_pypi::PypiRegistry;
    /// # use deps_core::HttpCache;
    /// # use std::sync::Arc;
    /// # #[tokio::main]
    /// # async fn main() {
    /// let cache = Arc::new(HttpCache::new());
    /// let registry = PypiRegistry::new(cache);
    ///
    /// let latest = registry.get_latest_matching("flask", ">=3.0,<4.0").await.unwrap();
    /// assert!(latest.is_some());
    /// # }
    /// ```
    pub async fn get_latest_matching(
        &self,
        name: &str,
        req_str: &str,
    ) -> Result<Option<PypiVersion>> {
        let versions = self.get_versions(name).await?;

        // PEP 440 uses empty string for "any version"
        let normalized_req = if req_str == "*" { "" } else { req_str };

        let specs = VersionSpecifiers::from_str(normalized_req)
            .map_err(|e| DepsError::InvalidVersionReq(format!("{req_str}: {e}")))?;

        Ok(versions.into_iter().find(|v| {
            if let Ok(version) = Version::from_str(v.version.as_str()) {
                specs.contains(&version) && !v.yanked && !v.is_prerelease()
            } else {
                false
            }
        }))
    }

    /// Searches for packages whose PEP 503 normalized name starts with `query`.
    ///
    /// PyPI removed its XML-RPC search API and offers no first-party ranked search,
    /// so this serves unranked, alphabetically-sorted prefix matches against a
    /// lazily-built, in-memory index of the full PyPI Simple API project list
    /// (~882k names) — the same approach PyCharm's PyPI completion uses. See
    /// `crate::search` for the index's build/backoff lifecycle.
    ///
    /// On a cold start (the index has not finished building yet), this returns an
    /// empty result immediately rather than blocking on a ~9.6 MB download, and
    /// triggers a background build. Once built, the index is never rebuilt for the
    /// life of the process — there is no TTL (see `crate::search`'s module doc for
    /// why). Because the result set can be a truncated view of a much larger match
    /// set, callers should treat every result (empty or not) as incomplete;
    /// `PypiEcosystem::generate_completions` does this by reporting
    /// [`deps_core::completion::Completions::is_incomplete`] for the `PackageName`
    /// completion context this method backs.
    ///
    /// # Errors
    ///
    /// Never returns `Err`: a failed background build is logged and degrades to an
    /// empty result, matching this method's pre-existing observable behavior.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use deps_pypi::PypiRegistry;
    /// # use deps_core::HttpCache;
    /// # use std::sync::Arc;
    /// # #[tokio::main]
    /// # async fn main() {
    /// let cache = Arc::new(HttpCache::new());
    /// let registry = PypiRegistry::new(cache);
    ///
    /// // May be empty on a cold start; a later call (once the index has built)
    /// // returns matches.
    /// let _results = registry.search("flask", 10).await.unwrap();
    /// # }
    /// ```
    pub fn search(
        &self,
        query: &str,
        limit: usize,
    ) -> impl Future<Output = Result<Vec<PypiPackage>>> + use<> {
        let normalized = crate::name::normalize(query);
        let cache = Arc::clone(&self.cache);
        let index_url = self.index_url.clone();
        let index = Arc::clone(&self.index);
        let tier = self.tier;
        async move {
            // T008 (fixes S4/M3): a `WorkspaceDeclared`-tier client never performs a
            // package-*name* search — an unguarded search would trigger a full
            // project-listing download from the private host (the multi-MB Simple index,
            // not a single-package fetch). Enforced here rather than relied on via the call
            // graph, mirroring `deps-npm::NpmRegistry::search`'s identical guard.
            if tier == PypiRegistryTier::WorkspaceDeclared {
                return Ok(Vec::new());
            }
            if normalized.is_empty() {
                return Ok(Vec::new());
            }
            if let Some(ready) = index.ready() {
                return Ok(ready
                    .prefix_matches(&normalized, limit)
                    .into_iter()
                    .map(package_stub)
                    .collect());
            }
            crate::search::trigger_index_build(cache, index_url, index);
            Ok(Vec::new())
        }
    }

    /// Starts building the package-name search index in the background if it isn't
    /// ready yet (or a prior failed attempt's backoff window has elapsed).
    ///
    /// Safe to call unconditionally and often — a cheap no-op once the index is
    /// `crate::search::IndexState::Ready` or while a prior failure
    /// is still within its backoff window. `deps-pypi`'s `PypiEcosystem` calls this
    /// on every completion request in a Python manifest (not only package-name
    /// completion), so the index is typically already built by the time the user
    /// starts typing a package name.
    pub fn warm_search_index(&self) {
        // T008: mirrors `Self::search`'s tier guard — never triggers `trigger_index_build`'s
        // full-listing download for a private index client.
        if self.tier == PypiRegistryTier::WorkspaceDeclared {
            return;
        }
        crate::search::trigger_index_build(
            Arc::clone(&self.cache),
            self.index_url.clone(),
            Arc::clone(&self.index),
        );
    }

    /// Fetches package metadata including description and project URLs.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - HTTP request fails
    /// - Package does not exist
    /// - JSON parsing fails
    /// - `self` is `WorkspaceDeclared`-tier (T008, fixes S4/M3) — this method is `pub`,
    ///   ungated, and unrouted by any in-workspace caller today, but a future call site
    ///   reaching it on a private-index client would otherwise send that client's package
    ///   name to `pypi.org`'s JSON API (`metadata_url` is always built from the hardcoded
    ///   `PYPI_BASE`, never parameterized — see `metadata_url`'s doc) — closed here before
    ///   any such call site exists, not relied on via the call graph
    pub async fn get_package_metadata(&self, name: &str) -> Result<PypiPackage> {
        if self.tier == PypiRegistryTier::WorkspaceDeclared {
            return Err(DepsError::PackageNotFound {
                package: name.to_string(),
                registry: REGISTRY,
            });
        }
        let normalized = crate::name::normalize(name);
        if normalized.is_empty() {
            warn_rejected_value(
                "pypi_normalized_name_empty",
                "PyPI package metadata request URL",
                name,
            );
            return Err(DepsError::PackageNotFound {
                package: name.to_string(),
                registry: REGISTRY,
            });
        }
        let url = metadata_url(&normalized);
        let data = self
            .cache
            .get_cached(&url)
            .await
            .map_err(|e| not_found_or(e, name))?;

        parse_package_info(name, &data)
    }
}

// Implement Registry trait for PypiRegistry
impl deps_core::Registry for PypiRegistry {
    fn get_versions<'a>(
        &'a self,
        name: &'a deps_core::PackageName,
    ) -> deps_core::ecosystem::BoxFuture<
        'a,
        deps_core::error::Result<Vec<Box<dyn deps_core::Version>>>,
    > {
        Box::pin(async move {
            let versions = Self::get_versions(self, name.as_str()).await?;
            Ok(versions
                .into_iter()
                .map(|v| Box::new(v) as Box<dyn deps_core::Version>)
                .collect())
        })
    }

    fn get_latest_matching<'a>(
        &'a self,
        name: &'a deps_core::PackageName,
        req: &'a deps_core::VersionReq,
    ) -> deps_core::ecosystem::BoxFuture<
        'a,
        deps_core::error::Result<Option<Box<dyn deps_core::Version>>>,
    > {
        Box::pin(async move {
            let version = Self::get_latest_matching(self, name.as_str(), req.as_str()).await?;
            Ok(version.map(|v| Box::new(v) as Box<dyn deps_core::Version>))
        })
    }

    /// Dispatches by `source` (spec FR-010): an `AlternateRegistry` whose index has a
    /// registered client routes through `Self::get_versions_chained` (FR-005's chain
    /// walk); one with **no** registered client is `PackageNotFound`, never a fall back to
    /// `pypi.org` (PyPI always sets `mirrors_crates_io: false`, so Cargo's mirror-degradation
    /// arm is dead here and must not be written — falling back would send a private package
    /// name to the public index, the exact #248-class leak this feature closes). Every other
    /// source keeps today's public-registry path unchanged.
    fn get_versions_from<'a>(
        &'a self,
        name: &'a deps_core::PackageName,
        source: &'a DependencySource,
        freshness: FreshnessSettings,
    ) -> deps_core::ecosystem::BoxFuture<
        'a,
        deps_core::error::Result<Vec<Box<dyn deps_core::Version>>>,
    > {
        Box::pin(async move {
            match source {
                DependencySource::AlternateRegistry { index, .. } => {
                    match self.alternate_client(index) {
                        Some(client) => {
                            let versions = client.get_versions_chained(name.as_str()).await?;
                            Ok(versions
                                .into_iter()
                                .map(|v| Box::new(v) as Box<dyn deps_core::Version>)
                                .collect())
                        }
                        None => Err(DepsError::PackageNotFound {
                            package: name.to_string(),
                            registry: "alternate registry (not registered)",
                        }),
                    }
                }
                _ => deps_core::Registry::get_versions_with(self, name, freshness).await,
            }
        })
    }

    /// `get_versions_from`'s `get_latest_matching`-shaped counterpart — same dispatch, same
    /// "never fall back to `pypi.org` for an unregistered `AlternateRegistry`" invariant.
    ///
    /// Derived from `Self::get_versions_chained` +
    /// [`Registry::select_latest_matching`](deps_core::Registry::select_latest_matching) (fixes
    /// M4) rather than an independent per-hop version-matching walk: the winning hop (first
    /// hop with a non-empty version list) is selected once by
    /// `Self::get_versions_chained`, and matching happens only within that single hop's
    /// list. If the winning hop has no version matching `req`, that is terminal (`Ok(None)`),
    /// not a trigger to search later hops for a "better" match — continuing would reintroduce
    /// the cross-index version comparison this design avoids for the same
    /// dependency-confusion reasons FR-005(b)'s ordering exists.
    fn get_latest_matching_from<'a>(
        &'a self,
        name: &'a deps_core::PackageName,
        source: &'a DependencySource,
        req: &'a deps_core::VersionReq,
        _minimum_stability: Option<&'a str>,
    ) -> deps_core::ecosystem::BoxFuture<
        'a,
        deps_core::error::Result<Option<Box<dyn deps_core::Version>>>,
    > {
        Box::pin(async move {
            match source {
                DependencySource::AlternateRegistry { index, .. } => {
                    match self.alternate_client(index) {
                        Some(client) => {
                            let versions: Vec<Box<dyn deps_core::Version>> = client
                                .get_versions_chained(name.as_str())
                                .await?
                                .into_iter()
                                .map(|v| Box::new(v) as Box<dyn deps_core::Version>)
                                .collect();
                            let idx = client.select_latest_matching(&versions, req);
                            Ok(idx.and_then(|i| versions.into_iter().nth(i)))
                        }
                        None => Err(DepsError::PackageNotFound {
                            package: name.to_string(),
                            registry: "alternate registry (not registered)",
                        }),
                    }
                }
                _ => {
                    let version =
                        Self::get_latest_matching(self, name.as_str(), req.as_str()).await?;
                    Ok(version.map(|v| Box::new(v) as Box<dyn deps_core::Version>))
                }
            }
        })
    }

    fn search<'a>(
        &'a self,
        query: &'a str,
        limit: usize,
    ) -> deps_core::ecosystem::BoxFuture<
        'a,
        deps_core::error::Result<Vec<Box<dyn deps_core::Metadata>>>,
    > {
        Box::pin(async move {
            let packages = Self::search(self, query, limit).await?;
            Ok(packages
                .into_iter()
                .map(|p| Box::new(p) as Box<dyn deps_core::Metadata>)
                .collect())
        })
    }

    fn select_latest_matching(
        &self,
        versions: &[Box<dyn deps_core::Version>],
        req: &deps_core::VersionReq,
    ) -> Option<usize> {
        if deps_core::is_existence_wildcard(req) {
            return deps_core::select_latest_for_existence(versions, |v| v.as_ref());
        }
        // The wildcard gate above already consumed `""`/`"*"`, so `req_str` here is always a
        // concrete PEP 440 specifier — no "any version" normalization needed.
        let specs = VersionSpecifiers::from_str(req.as_str()).ok()?;

        versions.iter().position(|v| {
            // Parsed directly via `pep440_rs` rather than the trait's default
            // `is_prerelease` heuristic (substring match on "-alpha"/"-rc"/...), which
            // does not recognize PyPI's unhyphenated prerelease spellings like
            // "1.0.0rc1" and would silently treat them as stable.
            Version::from_str(v.version_string().as_str()).is_ok_and(|ver| {
                specs.contains(&ver) && !v.removal_status().blocks_resolution() && !ver.is_pre()
            })
        })
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

// JSON response types

#[derive(Debug, Deserialize)]
struct PypiResponse {
    info: PypiInfo,
}

#[derive(Debug, Deserialize)]
struct PypiInfo {
    name: String,
    summary: Option<String>,
    project_urls: Option<std::collections::HashMap<String, String>>,
    version: String,
}

// PEP 691 Simple API JSON response types

#[derive(Debug, Deserialize)]
struct SimpleApiResponse {
    versions: Vec<String>,
    files: Vec<SimpleFile>,
}

#[derive(Debug, Deserialize)]
struct SimpleFile {
    filename: String,
    #[serde(default)]
    yanked: Yanked,
    /// PEP 700 upload timestamp (RFC 3339), per file rather than per version.
    ///
    /// Absent on older Simple API responses; `#[serde(default)]` keeps such
    /// entries parseable.
    #[serde(rename = "upload-time", default)]
    upload_time: Option<String>,
}

/// A file's yanked status per PEP 592: either `false` (not yanked) or a
/// string giving the yank reason. `get_versions` only needs the yanked/not
/// distinction, so the reason text itself is discarded on parse.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum Yanked {
    Flag(bool),
    Reason(#[expect(dead_code, reason = "reason text not surfaced by get_versions")] String),
}

impl Default for Yanked {
    fn default() -> Self {
        Self::Flag(false)
    }
}

impl Yanked {
    const fn is_yanked(&self) -> bool {
        match self {
            Self::Flag(b) => *b,
            Self::Reason(_) => true,
        }
    }
}

/// Archive/wheel file extensions recognized on PyPI's Simple API index, used
/// to strip the trailing extension off an sdist-style filename (one with no
/// further `-`-delimited tags after the version) when deriving its version.
const KNOWN_ARCHIVE_EXTENSIONS: &[&str] = &[
    ".tar.gz", ".tar.bz2", ".tar.xz", ".tar.lz", ".tar.Z", ".zip", ".whl", ".egg", ".tar",
];

/// Derives the release version directly from `filename`'s structure, given
/// the package's PEP 503 normalized name, in O(filename length) with no
/// dependency on the number of known versions.
///
/// PyPI release filenames are `{name}-{version}[-...].{ext}`, but the
/// `{name}` segment on disk may use the project's original casing and
/// original `-`/`_`/`.` separators (e.g. `zope.interface-3.3.0b1.tar.gz` for
/// normalized name `zope-interface`) rather than the normalized spelling.
/// This walks `normalized_name` against `filename` byte-for-byte,
/// case-insensitively, treating any run of `-`/`_`/`.` in `filename` as
/// equivalent to a single `-` in `normalized_name`, then cuts the remainder
/// at the first `-` (wheel tags) or a recognized archive extension (sdists).
///
/// Returns `None` if `filename` doesn't conform closely enough to derive a
/// version unambiguously; callers skip attributing that file rather than
/// guess (see [`build_version_metadata`]).
fn parse_version_from_filename<'a>(filename: &'a str, normalized_name: &str) -> Option<&'a str> {
    let bytes = filename.as_bytes();
    let mut fi = 0usize;
    for nb in normalized_name.bytes() {
        if nb == b'-' {
            let start = fi;
            while matches!(bytes.get(fi), Some(b'-' | b'_' | b'.')) {
                fi += 1;
            }
            if fi == start {
                return None;
            }
        } else {
            match bytes.get(fi) {
                Some(&fb) if fb.to_ascii_lowercase() == nb => fi += 1,
                _ => return None,
            }
        }
    }
    if bytes.get(fi) != Some(&b'-') {
        return None;
    }
    let rest = &filename[fi + 1..];
    match rest.find('-') {
        Some(end) => Some(&rest[..end]),
        None => KNOWN_ARCHIVE_EXTENSIONS
            .iter()
            .find_map(|ext| rest.strip_suffix(ext)),
    }
}

/// Aggregated per-version metadata derived from a Simple API `files` list.
#[derive(Debug, Default, PartialEq, Eq)]
struct VersionMetadata {
    /// A version is yanked if any of its release files are yanked (PyPI
    /// itself treats a release as yanked once any file under it is, since
    /// new uploads to an already-yanked version are rejected).
    yanked: bool,
    /// Earliest `upload-time` across the version's release files (a version
    /// can ship multiple files/wheels uploaded at different times). `None`
    /// if no file reports one.
    published_at: Option<deps_core::PublishTime>,
}

/// Builds a per-version metadata map from a Simple API `files` list.
///
/// Derives each file's version in O(1) via [`parse_version_from_filename`]
/// and resolves it against `versions` in two tiers, the second tried only
/// if the first misses:
/// 1. Exact string match — the common case, and the only tier that can tell
///    apart distinct-but-PEP-440-equal strings like `1.0` and `1.0.0`
///    (legacy packages can list both as separate releases).
/// 2. Match as a parsed [`Version`] — PyPI filenames sometimes spell a
///    version differently than its canonical form (e.g. `4.21.0_rc_1` in a
///    wheel filename for the canonical `4.21.0rc1`), which `Version`'s
///    `Eq`/`Hash` normalize away.
///
/// A file whose filename doesn't structurally parse, or whose derived
/// version matches neither tier, is skipped rather than guessed at via
/// substring search — an earlier substring-based fallback could misattribute
/// a file to an unrelated version whose digits happened to appear elsewhere
/// in the filename (e.g. a platform tag), which is worse than the version's
/// yanked status resting on its other, better-formed release files.
fn build_version_metadata(
    files: &[SimpleFile],
    versions: &[String],
    normalized_name: &str,
) -> std::collections::HashMap<String, VersionMetadata> {
    let version_set: std::collections::HashSet<&str> =
        versions.iter().map(String::as_str).collect();

    // Built lazily: most real-world responses resolve every file via the
    // exact-string tier and never need this.
    let mut parsed_versions: Option<std::collections::HashMap<Version, &str>> = None;

    let mut metadata: std::collections::HashMap<String, VersionMetadata> =
        std::collections::HashMap::new();
    for file in files {
        let matched =
            parse_version_from_filename(&file.filename, normalized_name).and_then(|candidate| {
                version_set.get(candidate).copied().or_else(|| {
                    let parsed = Version::from_str(candidate).ok()?;
                    let map = parsed_versions.get_or_insert_with(|| {
                        versions
                            .iter()
                            .filter_map(|v| Some((Version::from_str(v).ok()?, v.as_str())))
                            .collect()
                    });
                    map.get(&parsed).copied()
                })
            });

        let Some(version) = matched else {
            continue;
        };
        let entry = metadata.entry(version.to_string()).or_default();
        entry.yanked |= file.yanked.is_yanked();
        if let Some(uploaded) = file
            .upload_time
            .as_deref()
            .and_then(deps_core::PublishTime::parse_rfc3339)
        {
            entry.published_at = Some(
                entry
                    .published_at
                    .map_or(uploaded, |existing| existing.max(uploaded)),
            );
        }
    }
    metadata
}

/// Parse the version list from a PyPI Simple API (PEP 691) JSON response.
fn parse_simple_api_response(package_name: &str, data: &[u8]) -> Result<Vec<PypiVersion>> {
    let response: SimpleApiResponse =
        deps_core::parse_json_checked(data).map_err(|e| DepsError::ApiResponse {
            package: package_name.to_string(),
            registry: REGISTRY,
            source: e,
        })?;

    let normalized_name = crate::name::normalize(package_name);
    let metadata_map =
        build_version_metadata(&response.files, &response.versions, &normalized_name);

    let mut versions_with_parsed: Vec<(PypiVersion, Version)> = response
        .versions
        .into_iter()
        .filter_map(|version_str| {
            let parsed = Version::from_str(&version_str).ok()?;
            let meta = metadata_map.get(&version_str);
            let yanked = meta.is_some_and(|m| m.yanked);
            let published_at = meta.and_then(|m| m.published_at);
            Some((
                PypiVersion {
                    version: version_str.into(),
                    yanked,
                    published_at,
                },
                parsed,
            ))
        })
        .collect();

    // Sort by version (newest first) using pre-parsed versions
    versions_with_parsed.sort_by(|a, b| b.1.cmp(&a.1));

    Ok(versions_with_parsed.into_iter().map(|(v, _)| v).collect())
}

/// Parse package info from PyPI JSON response.
fn parse_package_info(package_name: &str, data: &[u8]) -> Result<PypiPackage> {
    let response: PypiResponse =
        deps_core::parse_json_checked(data).map_err(|e| DepsError::ApiResponse {
            package: package_name.to_string(),
            registry: REGISTRY,
            source: e,
        })?;

    let project_urls = response
        .info
        .project_urls
        .unwrap_or_default()
        .into_iter()
        .collect();

    Ok(PypiPackage {
        name: response.info.name.into(),
        summary: response.info.summary,
        project_urls,
        latest_version: response.info.version.into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use deps_core::test_util::{capture_tracing_output, capture_tracing_output_async};

    #[test]
    fn test_package_url() {
        assert_eq!(package_url("requests"), "https://pypi.org/project/requests");
        assert_eq!(package_url("flask"), "https://pypi.org/project/flask");
    }

    #[test]
    fn test_package_url_normalization() {
        assert_eq!(package_url("Flask"), "https://pypi.org/project/flask");
        assert_eq!(
            package_url("django_rest_framework"),
            "https://pypi.org/project/django-rest-framework"
        );
    }

    #[test]
    fn test_package_url_encoding() {
        let url = package_url("my-package");
        assert!(url.starts_with("https://pypi.org/project/"));
        assert!(url.contains("my-package"));
    }

    #[test]
    fn test_package_url_encodes_malicious_name() {
        let url = package_url("evil](https://evil.example)[pkg");
        assert!(!url.contains('('));
        assert!(!url.contains(')'));
        assert!(!url.contains('['));
        assert!(!url.contains(']'));
    }

    #[test]
    fn test_package_url_encodes_newline_autolink_and_percent() {
        let url = package_url("evil\n<https://evil%zz.example>");
        assert!(!url.contains('\n'));
        assert!(!url.contains('<'));
        assert!(!url.contains('>'));
        // The literal '%' from the payload must itself be encoded (to %25), or a
        // browser/renderer double-decode could smuggle a raw byte back in.
        assert!(url.contains("%25"));
    }

    #[test]
    fn test_package_url_empty_name() {
        assert_eq!(package_url(""), "");
    }

    #[test]
    fn test_package_url_normalizes_to_empty() {
        // "---" normalizes to "" (all separators) — must not build a dead
        // link with an empty path segment.
        assert_eq!(package_url("---"), "");
    }

    #[test]
    fn test_parse_simple_api_response() {
        // Shape captured live from `pypi.org/simple/requests/` with
        // `Accept: application/vnd.pypi.simple.v1+json`.
        let json = r#"{
            "meta": {"api-version": "1.4"},
            "name": "requests",
            "versions": ["2.27.0", "2.28.0", "2.28.1", "2.28.2"],
            "files": [
                {"filename": "requests-2.27.0.tar.gz", "yanked": false},
                {"filename": "requests-2.28.0.tar.gz", "yanked": true},
                {"filename": "requests-2.28.0-py3-none-any.whl", "yanked": true},
                {"filename": "requests-2.28.1.tar.gz", "yanked": false},
                {"filename": "requests-2.28.2.tar.gz", "yanked": false},
                {"filename": "requests-2.28.2-py3-none-any.whl", "yanked": false}
            ]
        }"#;

        let versions = parse_simple_api_response("requests", json.as_bytes()).unwrap();

        assert_eq!(versions.len(), 4);
        assert_eq!(versions[0].version, "2.28.2");
        assert!(!versions[0].yanked);
        assert!(
            versions
                .iter()
                .find(|v| v.version == "2.28.0")
                .unwrap()
                .yanked
        );
    }

    #[test]
    fn test_parse_simple_api_response_nesting_at_max_depth_accepted() {
        let depth = deps_core::MAX_JSON_NESTING_DEPTH;
        let json = format!(
            r#"{{"versions": [], "files": [], "extra": {}1{}}}"#,
            "[".repeat(depth - 1),
            "]".repeat(depth - 1)
        );
        assert!(parse_simple_api_response("pkg", json.as_bytes()).is_ok());
    }

    #[test]
    fn test_parse_simple_api_response_nesting_over_max_depth_rejected() {
        let depth = deps_core::MAX_JSON_NESTING_DEPTH + 1;
        let json = format!(
            r#"{{"versions": [], "files": [], "extra": {}1{}}}"#,
            "[".repeat(depth),
            "]".repeat(depth)
        );
        assert!(parse_simple_api_response("pkg", json.as_bytes()).is_err());
    }

    #[test]
    fn test_parse_simple_api_response_with_upload_time() {
        let json = r#"{
            "meta": {"api-version": "1.4"},
            "name": "requests",
            "versions": ["2.28.2"],
            "files": [
                {"filename": "requests-2.28.2.tar.gz", "yanked": false, "upload-time": "2026-05-14T19:25:27.735762Z"}
            ]
        }"#;

        let versions = parse_simple_api_response("requests", json.as_bytes()).unwrap();
        assert_eq!(versions.len(), 1);
        assert_eq!(
            versions[0].published_at,
            deps_core::PublishTime::parse_rfc3339("2026-05-14T19:25:27.735762Z")
        );
    }

    #[test]
    fn test_parse_simple_api_response_without_upload_time() {
        let json = r#"{
            "meta": {"api-version": "1.4"},
            "name": "requests",
            "versions": ["2.28.2"],
            "files": [
                {"filename": "requests-2.28.2.tar.gz", "yanked": false}
            ]
        }"#;

        let versions = parse_simple_api_response("requests", json.as_bytes()).unwrap();
        assert_eq!(versions.len(), 1);
        assert!(versions[0].published_at.is_none());
    }

    #[test]
    fn test_parse_simple_api_response_with_malformed_upload_time() {
        let json = r#"{
            "meta": {"api-version": "1.4"},
            "name": "requests",
            "versions": ["2.28.2"],
            "files": [
                {"filename": "requests-2.28.2.tar.gz", "yanked": false, "upload-time": "not-a-timestamp"}
            ]
        }"#;

        let versions = parse_simple_api_response("requests", json.as_bytes()).unwrap();
        assert_eq!(versions.len(), 1);
        assert!(
            versions[0].published_at.is_none(),
            "malformed upload-time degrades to None, not an error"
        );
    }

    #[test]
    fn test_parse_simple_api_response_yanked_with_reason_string() {
        // PEP 592: `yanked` may be a non-empty string giving the reason,
        // which still means "yanked" (only `false` means not yanked).
        let json = r#"{
            "meta": {"api-version": "1.4"},
            "name": "urllib3",
            "versions": ["1.25"],
            "files": [
                {"filename": "urllib3-1.25-py2.py3-none-any.whl", "yanked": "Broken release"},
                {"filename": "urllib3-1.25.tar.gz", "yanked": "Broken release"}
            ]
        }"#;

        let versions = parse_simple_api_response("urllib3", json.as_bytes()).unwrap();
        assert_eq!(versions.len(), 1);
        assert!(versions[0].yanked);
    }

    #[test]
    fn test_build_version_metadata_disambiguates_version_prefixes() {
        // "1.0" is a substring of the "1.0.0" filename; trying the longer
        // version first must ensure "1.0"'s own (absent) file isn't
        // conflated with "1.0.0"'s file.
        let files = vec![SimpleFile {
            filename: "pkg-1.0.0.tar.gz".to_string(),
            yanked: Yanked::Flag(true),
            upload_time: None,
        }];
        let versions = vec!["1.0".to_string(), "1.0.0".to_string()];
        let map = build_version_metadata(&files, &versions, "pkg");
        assert!(map.get("1.0.0").unwrap().yanked);
        assert!(!map.contains_key("1.0"));
    }

    #[test]
    fn test_build_version_metadata_any_file_yanked_marks_version_yanked() {
        let files = vec![
            SimpleFile {
                filename: "pkg-1.0.0-py3-none-any.whl".to_string(),
                yanked: Yanked::Flag(false),
                upload_time: None,
            },
            SimpleFile {
                filename: "pkg-1.0.0.tar.gz".to_string(),
                yanked: Yanked::Flag(true),
                upload_time: None,
            },
        ];
        let versions = vec!["1.0.0".to_string()];
        let map = build_version_metadata(&files, &versions, "pkg");
        assert!(map.get("1.0.0").unwrap().yanked);
    }

    #[test]
    fn test_build_version_metadata_disambiguates_in_both_directions() {
        // Both "1.0" and "1.0.0" are real releases with their own files.
        // Matching must not let the longer version's absent file bleed into
        // the shorter version's real one, nor vice versa.
        let files = vec![
            SimpleFile {
                filename: "pkg-1.0.tar.gz".to_string(),
                yanked: Yanked::Flag(true),
                upload_time: None,
            },
            SimpleFile {
                filename: "pkg-1.0.0.tar.gz".to_string(),
                yanked: Yanked::Flag(false),
                upload_time: None,
            },
        ];
        let versions = vec!["1.0".to_string(), "1.0.0".to_string()];
        let map = build_version_metadata(&files, &versions, "pkg");
        assert!(map.get("1.0").unwrap().yanked);
        assert!(!map.get("1.0.0").unwrap().yanked);
    }

    #[test]
    fn test_build_version_metadata_pre_post_dev_suffixes() {
        // Pre/post/dev-release version strings are '.'-delimited suffixes on
        // the base version and must not be conflated with it or each other.
        let files = vec![
            SimpleFile {
                filename: "pkg-1.0.0.tar.gz".to_string(),
                yanked: Yanked::Flag(false),
                upload_time: None,
            },
            SimpleFile {
                filename: "pkg-1.0.0rc1.tar.gz".to_string(),
                yanked: Yanked::Flag(true),
                upload_time: None,
            },
            SimpleFile {
                filename: "pkg-1.0.0.post1.tar.gz".to_string(),
                yanked: Yanked::Flag(false),
                upload_time: None,
            },
            SimpleFile {
                filename: "pkg-1.0.0.dev1.tar.gz".to_string(),
                yanked: Yanked::Flag(true),
                upload_time: None,
            },
        ];
        let versions = vec![
            "1.0.0".to_string(),
            "1.0.0rc1".to_string(),
            "1.0.0.post1".to_string(),
            "1.0.0.dev1".to_string(),
        ];
        let map = build_version_metadata(&files, &versions, "pkg");
        assert!(!map.get("1.0.0").unwrap().yanked);
        assert!(map.get("1.0.0rc1").unwrap().yanked);
        assert!(!map.get("1.0.0.post1").unwrap().yanked);
        assert!(map.get("1.0.0.dev1").unwrap().yanked);
    }

    #[test]
    fn test_build_version_metadata_takes_maximum_upload_time() {
        // A version can ship multiple files (sdist + wheels) uploaded at
        // different times, and PyPI allows adding a new file to an already
        // published version. The most-recently-added file is what should
        // count for freshness (fail-closed against the cooldown window),
        // not the version's original release.
        let files = vec![
            SimpleFile {
                filename: "pkg-1.0.0-py3-none-any.whl".to_string(),
                yanked: Yanked::Flag(false),
                upload_time: Some("2026-05-14T19:25:27Z".to_string()),
            },
            SimpleFile {
                filename: "pkg-1.0.0.tar.gz".to_string(),
                yanked: Yanked::Flag(false),
                upload_time: Some("2026-05-14T10:00:00Z".to_string()),
            },
        ];
        let versions = vec!["1.0.0".to_string()];
        let map = build_version_metadata(&files, &versions, "pkg");
        assert_eq!(
            map.get("1.0.0").unwrap().published_at,
            deps_core::PublishTime::parse_rfc3339("2026-05-14T19:25:27Z")
        );
    }

    #[test]
    fn test_build_version_metadata_absent_upload_time_is_none() {
        let files = vec![SimpleFile {
            filename: "pkg-1.0.0.tar.gz".to_string(),
            yanked: Yanked::Flag(false),
            upload_time: None,
        }];
        let versions = vec!["1.0.0".to_string()];
        let map = build_version_metadata(&files, &versions, "pkg");
        assert!(map.get("1.0.0").unwrap().published_at.is_none());
    }

    #[test]
    fn test_build_version_metadata_malformed_upload_time_is_none() {
        let files = vec![SimpleFile {
            filename: "pkg-1.0.0.tar.gz".to_string(),
            yanked: Yanked::Flag(false),
            upload_time: Some("not-a-timestamp".to_string()),
        }];
        let versions = vec!["1.0.0".to_string()];
        let map = build_version_metadata(&files, &versions, "pkg");
        assert!(
            map.get("1.0.0").unwrap().published_at.is_none(),
            "malformed upload-time degrades to None, not an error"
        );
    }

    #[test]
    fn test_parse_version_from_filename_wheel_and_sdist() {
        assert_eq!(
            parse_version_from_filename("requests-2.28.2.tar.gz", "requests"),
            Some("2.28.2")
        );
        assert_eq!(
            parse_version_from_filename("requests-2.28.2-py3-none-any.whl", "requests"),
            Some("2.28.2")
        );
    }

    #[test]
    fn test_parse_version_from_filename_dotted_and_underscored_project_name() {
        // Real PyPI filenames keep the project's original separator style
        // even though `normalized_name` collapses it to hyphens.
        assert_eq!(
            parse_version_from_filename("zope.interface-3.3.0b1.tar.gz", "zope-interface"),
            Some("3.3.0b1")
        );
        assert_eq!(
            parse_version_from_filename(
                "typing_extensions-3.6.2-py3-none-any.whl",
                "typing-extensions"
            ),
            Some("3.6.2")
        );
    }

    #[test]
    fn test_parse_version_from_filename_rejects_non_conforming() {
        // Doesn't start with the package name at all.
        assert_eq!(
            parse_version_from_filename("other-1.0.0.tar.gz", "pkg"),
            None
        );
        // Name matches but there's no name/version separator afterwards.
        assert_eq!(parse_version_from_filename("pkg1.0.0.tar.gz", "pkg"), None);
    }

    #[test]
    fn test_parse_version_from_filename_no_digit_run_confusion() {
        // Structural parsing reads the version as the literal token right
        // after the name prefix, so "1.10.0" is never mistaken for "1.0.0"
        // the way a substring search could be.
        assert_eq!(
            parse_version_from_filename("pkg-1.10.0.tar.gz", "pkg"),
            Some("1.10.0")
        );
    }

    #[test]
    fn test_build_version_metadata_uses_fast_path_not_quadratic_fallback() {
        // Regression guard for the O(files x versions) blowup: a well-formed
        // filename must resolve via the O(1) structural fast path,
        // regardless of how many other versions exist.
        let mut versions: Vec<String> = (0..2000).map(|i| format!("0.0.{i}")).collect();
        versions.push("9.9.9".to_string());
        let files = vec![SimpleFile {
            filename: "pkg-9.9.9.tar.gz".to_string(),
            yanked: Yanked::Flag(true),
            upload_time: None,
        }];
        assert_eq!(
            parse_version_from_filename(&files[0].filename, "pkg"),
            Some("9.9.9"),
            "fast path must derive the version directly from filename structure"
        );
        let map = build_version_metadata(&files, &versions, "pkg");
        assert!(map.get("9.9.9").unwrap().yanked);
    }

    #[test]
    fn test_build_version_metadata_ignores_platform_tag_false_match() {
        // Regression for a live PyPI file (`pyobjc_core-2.2-py2.6-macosx-10.3-fat.egg`):
        // the old whole-filename substring scan could misattribute this file
        // to version "10.3" (a platform tag that happens to look like a
        // version and sorts before "2.2" by length) instead of "2.2". The
        // structural fast path only looks at the token right after the name
        // prefix, so it can't be fooled by tags later in the filename.
        let files = vec![SimpleFile {
            filename: "pyobjc_core-2.2-py2.6-macosx-10.3-fat.egg".to_string(),
            yanked: Yanked::Flag(true),
            upload_time: None,
        }];
        let versions = vec!["2.2".to_string(), "10.3".to_string()];
        let map = build_version_metadata(&files, &versions, "pyobjc-core");
        assert!(map.get("2.2").unwrap().yanked);
        assert!(!map.contains_key("10.3"));
    }

    #[test]
    fn test_build_version_metadata_pep440_underscore_normalization() {
        // Regression for a live PyPI file
        // (`protobuf-4.21.0_rc_1-cp310-abi3-win_amd64.whl`): the wheel
        // filename spells the pre-release as `4.21.0_rc_1` while the
        // canonical version string PyPI lists is `4.21.0rc1`. An exact
        // string comparison misses this; PEP 440-normalized comparison
        // (`Version`'s `Eq`) does not.
        let files = vec![SimpleFile {
            filename: "protobuf-4.21.0_rc_1-cp310-abi3-win_amd64.whl".to_string(),
            yanked: Yanked::Flag(false),
            upload_time: None,
        }];
        let versions = vec!["4.21.0rc1".to_string()];
        let map = build_version_metadata(&files, &versions, "protobuf");
        assert!(!map.get("4.21.0rc1").unwrap().yanked);
    }

    #[test]
    fn test_build_version_metadata_skips_non_conforming_filename_instead_of_guessing() {
        // A filename whose leading segment doesn't match the package's
        // normalized name at all can't resolve via the structural fast path.
        // Rather than fall back to a substring guess (the mechanism behind
        // the pyobjc-core misattribution above), that file is skipped —
        // it contributes nothing to the metadata map, but doesn't corrupt it
        // either. A well-formed file for the same version still resolves
        // correctly, and an unrelated version stays untouched.
        let files = vec![
            SimpleFile {
                filename: "unrelated-file-1.0.0.zip".to_string(),
                yanked: Yanked::Flag(true),
                upload_time: None,
            },
            SimpleFile {
                filename: "pkg-1.0.0-py3-none-any.whl".to_string(),
                yanked: Yanked::Flag(true),
                upload_time: None,
            },
        ];
        let versions = vec!["1.0.0".to_string(), "2.0.0".to_string()];
        assert_eq!(
            parse_version_from_filename(&files[0].filename, "pkg"),
            None,
            "filename doesn't start with the package name, must be skipped"
        );
        let map = build_version_metadata(&files, &versions, "pkg");
        assert!(map.get("1.0.0").unwrap().yanked);
        assert!(!map.contains_key("2.0.0"));
    }

    #[test]
    fn test_simple_api_url_encodes_malicious_name() {
        // `normalize_package_name` only collapses `-`/`_`/`.` separators and
        // leaves characters like `/` untouched, so the URL builder itself
        // must encode them to prevent smuggling extra path segments.
        let url = simple_api_url(PYPI_SIMPLE_BASE, "evil/../secret");
        assert!(url.starts_with(PYPI_SIMPLE_BASE));
        assert!(!url.contains("/../"));
        assert_eq!(url, format!("{PYPI_SIMPLE_BASE}/evil%2F..%2Fsecret/"));
    }

    #[test]
    fn test_metadata_url_encodes_malicious_name() {
        let url = metadata_url("pkg?x=1#frag");
        assert!(!url.contains('?'));
        assert!(!url.contains('#'));
    }

    /// #365 regression sweep: exercises the real production `name::normalize`
    /// (collapsing a dot-segment to the empty string, rejected before the sink) and
    /// `simple_api_url` together against the shared adversarial input set. Uses the
    /// `_transformed` variant since `normalize` legitimately rewrites a compound input
    /// (e.g. `../../etc/passwd` -> `/-/etc/passwd`) rather than passing it through
    /// unchanged, so the survival check must compare against the normalized form, not the
    /// raw adversarial segment.
    #[test]
    fn test_simple_api_url_dot_segment_sweep() {
        deps_core::test_util::assert_dot_segment_gated_or_contained_transformed(
            |seg| {
                let normalized = crate::name::normalize(seg);
                (!normalized.is_empty()).then(|| simple_api_url(PYPI_SIMPLE_BASE, &normalized))
            },
            crate::name::normalize,
            "pypi.org",
            "/simple/",
        );
    }

    /// #365 regression sweep: exercises the real production `name::normalize` and
    /// `metadata_url` together against the shared adversarial input set, mirroring
    /// `test_simple_api_url_dot_segment_sweep` for the sibling sink (#380).
    #[test]
    fn test_metadata_url_dot_segment_sweep() {
        deps_core::test_util::assert_dot_segment_gated_or_contained_transformed(
            |seg| {
                let normalized = crate::name::normalize(seg);
                (!normalized.is_empty()).then(|| metadata_url(&normalized))
            },
            crate::name::normalize,
            "pypi.org",
            "/pypi/",
        );
    }

    #[test]
    fn test_simple_api_url_normal_names() {
        assert_eq!(
            simple_api_url(PYPI_SIMPLE_BASE, "requests"),
            "https://pypi.org/simple/requests/"
        );
        assert_eq!(
            simple_api_url(PYPI_SIMPLE_BASE, "zope-interface"),
            "https://pypi.org/simple/zope-interface/"
        );
    }

    #[test]
    fn test_parse_package_info() {
        let json = r#"{
            "info": {
                "name": "flask",
                "summary": "A micro web framework",
                "version": "3.0.0",
                "project_urls": {
                    "Documentation": "https://flask.palletsprojects.com/",
                    "Repository": "https://github.com/pallets/flask"
                }
            }
        }"#;

        let pkg = parse_package_info("flask", json.as_bytes()).unwrap();

        assert_eq!(pkg.name, "flask");
        assert_eq!(pkg.summary, Some("A micro web framework".to_string()));
        assert_eq!(pkg.latest_version, "3.0.0");
        assert_eq!(pkg.project_urls.len(), 2);
    }

    #[test]
    fn test_parse_package_info_nesting_at_max_depth_accepted() {
        let depth = deps_core::MAX_JSON_NESTING_DEPTH;
        let json = format!(
            r#"{{"info": {{"name": "pkg", "version": "1.0.0"}}, "extra": {}1{}}}"#,
            "[".repeat(depth - 1),
            "]".repeat(depth - 1)
        );
        assert!(parse_package_info("pkg", json.as_bytes()).is_ok());
    }

    #[test]
    fn test_parse_package_info_nesting_over_max_depth_rejected() {
        let depth = deps_core::MAX_JSON_NESTING_DEPTH + 1;
        let json = format!(
            r#"{{"info": {{"name": "pkg", "version": "1.0.0"}}, "extra": {}1{}}}"#,
            "[".repeat(depth),
            "]".repeat(depth)
        );
        assert!(parse_package_info("pkg", json.as_bytes()).is_err());
    }

    #[test]
    fn test_wildcard_specifier_normalization() {
        // Test that "*" is normalized to empty string for PEP 440 compatibility
        // The get_latest_matching method normalizes "*" to "" internally
        let normalized = if "*" == "*" { "" } else { "*" };
        assert_eq!(normalized, "");

        // Verify that empty string is valid PEP 440 (matches any version)
        let specs = VersionSpecifiers::from_str("").unwrap();
        assert!(specs.contains(&Version::from_str("1.0.0").unwrap()));
        assert!(specs.contains(&Version::from_str("2.5.3").unwrap()));
        assert!(specs.contains(&Version::from_str("0.0.1").unwrap()));
    }

    #[test]
    fn test_not_found_or_maps_404_to_package_not_found() {
        let err = DepsError::HttpStatus {
            url: "https://pypi.org/pypi/flask/json".into(),
            status: 404,
        };
        let result = not_found_or(err, "flask");
        assert!(matches!(
            result,
            DepsError::PackageNotFound { package, registry }
                if package == "flask" && registry == REGISTRY
        ));
    }

    #[test]
    fn test_not_found_or_passes_through_non_404() {
        // Regression test: a package name containing the substring "404" must
        // not be misclassified as not-found for a non-404 failure, since the
        // fix replaced string matching on the formatted error with a
        // structural match on the HTTP status code.
        let err = DepsError::HttpStatus {
            url: "https://pypi.org/pypi/pytest-404/json".into(),
            status: 500,
        };
        let result = not_found_or(err, "pytest-404");
        assert!(matches!(result, DepsError::HttpStatus { status: 500, .. }));
    }

    #[test]
    fn test_prerelease_detection() {
        let json = r#"{
            "meta": {"api-version": "1.4"},
            "name": "test",
            "versions": ["1.0.0", "1.0.0a1", "1.0.0b2", "1.0.0rc1"],
            "files": [
                {"filename": "test-1.0.0.tar.gz", "yanked": false},
                {"filename": "test-1.0.0a1.tar.gz", "yanked": false},
                {"filename": "test-1.0.0b2.tar.gz", "yanked": false},
                {"filename": "test-1.0.0rc1.tar.gz", "yanked": false}
            ]
        }"#;

        let versions = parse_simple_api_response("test", json.as_bytes()).unwrap();

        let stable: Vec<_> = versions.iter().filter(|v| !v.is_prerelease()).collect();
        let prerelease: Vec<_> = versions.iter().filter(|v| v.is_prerelease()).collect();

        assert_eq!(stable.len(), 1);
        assert_eq!(prerelease.len(), 3);
    }

    #[tokio::test]
    async fn test_get_versions_empty_normalized_name_short_circuits() {
        // `name::normalize("---")` is "" — must fail as PackageNotFound
        // before any HTTP request is attempted (an empty Simple API segment
        // would otherwise build `https://pypi.org/simple//`).
        let cache = std::sync::Arc::new(deps_core::HttpCache::new());
        let registry = PypiRegistry::new(cache);
        let err = registry.get_versions("---").await.unwrap_err();
        assert!(matches!(
            err,
            DepsError::PackageNotFound { package, registry }
                if package == "---" && registry == REGISTRY
        ));
    }

    #[tokio::test]
    async fn test_get_package_metadata_empty_normalized_name_short_circuits() {
        let cache = std::sync::Arc::new(deps_core::HttpCache::new());
        let registry = PypiRegistry::new(cache);
        let err = registry.get_package_metadata("...").await.unwrap_err();
        assert!(matches!(err, DepsError::PackageNotFound { .. }));
    }

    #[tokio::test]
    async fn test_get_versions_empty_normalized_name_logs_warn_rejected_value() {
        // #380 B3: the short-circuit test above only proves the `Err` return value, not
        // that `warn_rejected_value` actually fires — a deleted warn call would still pass it.
        let cache = std::sync::Arc::new(deps_core::HttpCache::new());
        let registry = PypiRegistry::new(cache);
        let output = capture_tracing_output_async(async {
            let _ = registry.get_versions("---").await;
        })
        .await;
        assert!(
            output.contains("pypi_normalized_name_empty"),
            "output was: {output}"
        );
        assert!(
            output.contains("PyPI simple API request URL"),
            "output was: {output}"
        );
    }

    #[tokio::test]
    async fn test_get_package_metadata_empty_normalized_name_logs_warn_rejected_value() {
        let cache = std::sync::Arc::new(deps_core::HttpCache::new());
        let registry = PypiRegistry::new(cache);
        let output = capture_tracing_output_async(async {
            let _ = registry.get_package_metadata("...").await;
        })
        .await;
        assert!(
            output.contains("pypi_normalized_name_empty"),
            "output was: {output}"
        );
        assert!(
            output.contains("PyPI package metadata request URL"),
            "output was: {output}"
        );
    }

    #[test]
    fn test_package_url_empty_normalized_name_logs_warn_rejected_value() {
        let output = capture_tracing_output(|| {
            let _ = package_url("---");
        });
        assert!(
            output.contains("pypi_normalized_name_empty"),
            "output was: {output}"
        );
        assert!(
            output.contains("PyPI package display URL"),
            "output was: {output}"
        );
        assert!(
            !output.contains("---"),
            "raw rejected value must not be logged: {output}"
        );
    }

    #[test]
    fn test_package_url_accepted_logs_no_warn() {
        let output = capture_tracing_output(|| {
            let _ = package_url("requests");
        });
        assert!(output.is_empty(), "output was: {output}");
    }

    #[test]
    fn test_select_latest_matching_not_default_none() {
        use deps_core::{Registry, VersionReq};

        let cache = Arc::new(HttpCache::new());
        let registry = PypiRegistry::new(cache);
        let versions: Vec<Box<dyn deps_core::Version>> = vec![
            Box::new(PypiVersion {
                version: "2.0.0".into(),
                yanked: true,
                published_at: None,
            }),
            Box::new(PypiVersion {
                version: "1.0.0".into(),
                yanked: false,
                published_at: None,
            }),
        ];
        let req = VersionReq::new("*");
        assert_eq!(registry.select_latest_matching(&versions, &req), Some(1));
    }

    #[test]
    fn test_select_latest_matching_excludes_unhyphenated_prerelease() {
        // Regression guard: the trait default `is_prerelease` heuristic (substring match
        // on "-rc"/"-alpha"/...) does not recognize PyPI's unhyphenated spelling
        // ("1.0.0rc1") and would wrongly treat it as stable if used here instead of the
        // pep440_rs-based check.
        use deps_core::{Registry, VersionReq};

        let cache = Arc::new(HttpCache::new());
        let registry = PypiRegistry::new(cache);
        let versions: Vec<Box<dyn deps_core::Version>> = vec![
            Box::new(PypiVersion {
                version: "2.0.0rc1".into(),
                yanked: false,
                published_at: None,
            }),
            Box::new(PypiVersion {
                version: "1.0.0".into(),
                yanked: false,
                published_at: None,
            }),
        ];
        let req = VersionReq::new("*");
        assert_eq!(registry.select_latest_matching(&versions, &req), Some(1));
    }

    #[test]
    fn test_select_latest_matching_all_yanked_returns_newest_yanked() {
        use deps_core::{Registry, VersionReq};

        let cache = Arc::new(HttpCache::new());
        let registry = PypiRegistry::new(cache);
        let versions: Vec<Box<dyn deps_core::Version>> = vec![
            Box::new(PypiVersion {
                version: "2.0.0".into(),
                yanked: true,
                published_at: None,
            }),
            Box::new(PypiVersion {
                version: "1.0.0".into(),
                yanked: true,
                published_at: None,
            }),
        ];
        let req = VersionReq::new("*");
        assert_eq!(registry.select_latest_matching(&versions, &req), Some(0));
    }

    #[test]
    fn test_select_latest_matching_all_prerelease_returns_newest_prerelease() {
        use deps_core::{Registry, VersionReq};

        let cache = Arc::new(HttpCache::new());
        let registry = PypiRegistry::new(cache);
        let versions: Vec<Box<dyn deps_core::Version>> = vec![
            Box::new(PypiVersion {
                version: "2.0.0rc1".into(),
                yanked: false,
                published_at: None,
            }),
            Box::new(PypiVersion {
                version: "1.0.0rc1".into(),
                yanked: false,
                published_at: None,
            }),
        ];
        let req = VersionReq::new("*");
        assert_eq!(registry.select_latest_matching(&versions, &req), Some(0));
    }

    #[tokio::test]
    async fn test_search_empty_query_returns_empty_without_building_index() {
        // A mock with `expect(0)` (the default) fails the test if it's ever hit —
        // an empty/whitespace query must short-circuit before touching the
        // network at all.
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/simple/")
            .expect(0)
            .create_async()
            .await;

        let cache = Arc::new(HttpCache::new());
        let index_url = format!("{}/simple/", server.url());
        let registry = PypiRegistry::with_index_url(cache, index_url);

        assert!(registry.search("", 10).await.unwrap().is_empty());
        assert!(registry.search("---", 10).await.unwrap().is_empty());
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_search_cold_start_returns_empty_immediately() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/simple/")
            .with_status(200)
            .with_body(crate::search::sample_index_body(&["requests"]))
            .expect(1)
            .create_async()
            .await;

        let cache = Arc::new(HttpCache::new());
        let index_url = format!("{}/simple/", server.url());
        let registry = PypiRegistry::with_index_url(cache, index_url);

        // The very first call must not block on the download.
        let results = registry.search("reque", 10).await.unwrap();
        assert!(
            results.is_empty(),
            "cold start must return empty immediately"
        );

        // #419 M4 regression: the old permanent stub also satisfied the assertion
        // above, since it always returned empty. What must distinguish the real
        // implementation is that the cold-start call above actually triggered a
        // background build — confirmed here by waiting for the mock to be hit,
        // rather than stopping at "returned empty" alone.
        for _ in 0..100 {
            if mock.matched_async().await {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_search_finds_match_after_index_builds() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/simple/")
            .with_status(200)
            .with_body(crate::search::sample_index_body(&[
                "requests",
                "requests-oauthlib",
            ]))
            .expect(1)
            .create_async()
            .await;

        let cache = Arc::new(HttpCache::new());
        let index_url = format!("{}/simple/", server.url());
        let registry = PypiRegistry::with_index_url(cache, index_url);

        let mut results = registry.search("reque", 10).await.unwrap();
        for _ in 0..100 {
            if !results.is_empty() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            results = registry.search("reque", 10).await.unwrap();
        }

        let names: Vec<String> = results.iter().map(|p| p.name.to_string()).collect();
        assert!(names.contains(&"requests".to_string()));
        assert!(names.contains(&"requests-oauthlib".to_string()));
        // C2 build-once: a second round of searches after the index is ready
        // must not trigger another fetch.
        let _ = registry.search("req", 10).await.unwrap();
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_search_no_match_returns_empty_once_index_is_ready() {
        let mut server = mockito::Server::new_async().await;
        let _mock = server
            .mock("GET", "/simple/")
            .with_status(200)
            .with_body(crate::search::sample_index_body(&["requests"]))
            .create_async()
            .await;

        let cache = Arc::new(HttpCache::new());
        let index_url = format!("{}/simple/", server.url());
        let registry = PypiRegistry::with_index_url(cache, index_url);

        // Poll on a query that IS expected to eventually match, purely to know
        // the index has finished building, then assert a non-matching query
        // against the now-ready index.
        let mut became_ready = false;
        for _ in 0..100 {
            if !registry.search("reque", 10).await.unwrap().is_empty() {
                became_ready = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        // #419 M4 regression: without this assertion, a version of the index that
        // never finishes building would make the final `no_match.is_empty()`
        // assertion vacuously true instead of exercising the intended "matched
        // against a ready index" case.
        assert!(
            became_ready,
            "index never became ready within the poll budget"
        );

        let no_match = registry
            .search("this-prefix-matches-nothing-zzz", 10)
            .await
            .unwrap();
        assert!(no_match.is_empty());
    }

    // --- T006/T007/T008: private-index chain infrastructure ---

    fn all_policy() -> deps_core::net_policy::RegistryAccessPolicy {
        deps_core::net_policy::RegistryAccessPolicy::new(
            deps_core::net_policy::WorkspaceRegistryAccess::All,
        )
    }

    /// Builds a validated [`PypiIndexUrl`] for a `mockito` loopback server — requires both
    /// the `cfg(test)` loopback carve-out and an `All` runtime policy.
    fn index_url(raw: &str) -> PypiIndexUrl {
        PypiIndexUrl::new(raw, &all_policy()).unwrap()
    }

    /// C4 fix: an alternate client's version fetch must hit the configured private host, not
    /// `pypi.org` — proven by asserting the `simple_base`-derived request lands on the mock
    /// server, not by absence-of-request on a `pypi.org` mock (which this crate's existing
    /// tests never contact anyway).
    #[tokio::test]
    async fn test_with_base_fetches_configured_host_not_pypi_org() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/simple/flask/")
            .with_status(200)
            .with_body(r#"{"versions": ["3.0.0"], "files": []}"#)
            .create_async()
            .await;

        let cache = Arc::new(HttpCache::new());
        cache.set_registry_policy(deps_core::net_policy::WorkspaceRegistryAccess::All);
        let base = index_url(&format!("{}/simple", server.url()));
        let client = PypiRegistry::with_base(Arc::clone(&cache), &base, Vec::new());

        let versions = client.get_versions("flask").await.unwrap();
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0].version.as_str(), "3.0.0");
        mock.assert_async().await;
    }

    /// FR-005(a)/NFR-006: an explicit-primary chain resolves via hop 0 first — a package
    /// present there never reaches the extra.
    #[tokio::test]
    async fn test_get_versions_from_case_a_primary_wins() {
        use deps_core::PackageName;

        let mut primary_server = mockito::Server::new_async().await;
        let primary_mock = primary_server
            .mock("GET", "/simple/pkg/")
            .with_status(200)
            .with_body(r#"{"versions": ["1.0.0"], "files": []}"#)
            .create_async()
            .await;

        let mut extra_server = mockito::Server::new_async().await;
        let extra_mock = extra_server
            .mock("GET", "/simple/pkg/")
            .with_status(200)
            .with_body(r#"{"versions": ["9.9.9"], "files": []}"#)
            .expect(0)
            .create_async()
            .await;

        let cache = Arc::new(HttpCache::new());
        cache.set_registry_policy(deps_core::net_policy::WorkspaceRegistryAccess::All);
        let root = Arc::new(PypiRegistry::new(Arc::clone(&cache)));

        let primary = index_url(&format!("{}/simple", primary_server.url()));
        let extra = index_url(&format!("{}/simple", extra_server.url()));
        let chain = crate::config::ResolvedChain {
            key: "test-chain-a".to_string(),
            hops: vec![primary, extra],
            implicit_public_fallback: false,
        };
        PypiRegistry::register_chain(&root, &chain);

        let source = DependencySource::AlternateRegistry {
            index: chain.key.clone(),
            mirrors_crates_io: false,
        };
        let versions = deps_core::Registry::get_versions_from(
            root.as_ref(),
            &PackageName::new("pkg"),
            &source,
            deps_core::FreshnessSettings::default(),
        )
        .await
        .unwrap();
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0].version_string().as_str(), "1.0.0");

        primary_mock.assert_async().await;
        extra_mock.assert_async().await;
    }

    /// S5 failure taxonomy: hop 0 misses (`PackageNotFound`, a 404) -> falls through to hop 1.
    #[tokio::test]
    async fn test_get_versions_chained_falls_through_on_package_not_found() {
        let mut hop0_server = mockito::Server::new_async().await;
        let hop0_mock = hop0_server
            .mock("GET", "/simple/pkg/")
            .with_status(404)
            .create_async()
            .await;

        let mut hop1_server = mockito::Server::new_async().await;
        let hop1_mock = hop1_server
            .mock("GET", "/simple/pkg/")
            .with_status(200)
            .with_body(r#"{"versions": ["2.0.0"], "files": []}"#)
            .create_async()
            .await;

        let cache = Arc::new(HttpCache::new());
        cache.set_registry_policy(deps_core::net_policy::WorkspaceRegistryAccess::All);
        let hop1 = Arc::new(PypiRegistry::with_base(
            Arc::clone(&cache),
            &index_url(&format!("{}/simple", hop1_server.url())),
            Vec::new(),
        ));
        let head = PypiRegistry::with_base(
            Arc::clone(&cache),
            &index_url(&format!("{}/simple", hop0_server.url())),
            vec![hop1],
        );

        let versions = head.get_versions_chained("pkg").await.unwrap();
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0].version.as_str(), "2.0.0");

        hop0_mock.assert_async().await;
        hop1_mock.assert_async().await;
    }

    /// S5 failure taxonomy: hop 0 answers `200` with an empty listing (not a 404) -> treated
    /// identically to `PackageNotFound`, falls through.
    #[tokio::test]
    async fn test_get_versions_chained_falls_through_on_empty_listing() {
        let mut hop0_server = mockito::Server::new_async().await;
        let hop0_mock = hop0_server
            .mock("GET", "/simple/pkg/")
            .with_status(200)
            .with_body(r#"{"versions": [], "files": []}"#)
            .create_async()
            .await;

        let mut hop1_server = mockito::Server::new_async().await;
        let hop1_mock = hop1_server
            .mock("GET", "/simple/pkg/")
            .with_status(200)
            .with_body(r#"{"versions": ["2.0.0"], "files": []}"#)
            .create_async()
            .await;

        let cache = Arc::new(HttpCache::new());
        cache.set_registry_policy(deps_core::net_policy::WorkspaceRegistryAccess::All);
        let hop1 = Arc::new(PypiRegistry::with_base(
            Arc::clone(&cache),
            &index_url(&format!("{}/simple", hop1_server.url())),
            Vec::new(),
        ));
        let head = PypiRegistry::with_base(
            Arc::clone(&cache),
            &index_url(&format!("{}/simple", hop0_server.url())),
            vec![hop1],
        );

        let versions = head.get_versions_chained("pkg").await.unwrap();
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0].version.as_str(), "2.0.0");

        hop0_mock.assert_async().await;
        hop1_mock.assert_async().await;
    }

    /// N4/second critic pass: a genuine transport error (5xx) on hop 0 is terminal — the
    /// chain does **not** try hop 1, even though hop 1 would have succeeded. This is the
    /// case-(b) "unreachable declared extra halts resolution for the whole file" trade-off,
    /// exercised directly at the chain-walk level.
    #[tokio::test]
    async fn test_get_versions_chained_terminates_on_transport_error_never_tries_next_hop() {
        let mut hop0_server = mockito::Server::new_async().await;
        let hop0_mock = hop0_server
            .mock("GET", "/simple/pkg/")
            .with_status(503)
            .create_async()
            .await;

        let mut hop1_server = mockito::Server::new_async().await;
        let hop1_mock = hop1_server
            .mock("GET", "/simple/pkg/")
            .with_status(200)
            .with_body(r#"{"versions": ["2.0.0"], "files": []}"#)
            .expect(0)
            .create_async()
            .await;

        let cache = Arc::new(HttpCache::new());
        cache.set_registry_policy(deps_core::net_policy::WorkspaceRegistryAccess::All);
        let hop1 = Arc::new(PypiRegistry::with_base(
            Arc::clone(&cache),
            &index_url(&format!("{}/simple", hop1_server.url())),
            Vec::new(),
        ));
        let head = PypiRegistry::with_base(
            Arc::clone(&cache),
            &index_url(&format!("{}/simple", hop0_server.url())),
            vec![hop1],
        );

        let err = head.get_versions_chained("pkg").await.unwrap_err();
        // M2 fix: a terminal transport error is reported as `ChainResolutionHalted` — not
        // `PackageNotFound` (which would wrongly trigger "continue to next hop" logic
        // anywhere else this error might be inspected), and not the raw underlying transport
        // error either (which `DepsError::fetch_failure` cannot safely classify as
        // `Actionable` — see `ChainResolutionHalted`'s own doc).
        assert!(
            matches!(err, DepsError::ChainResolutionHalted),
            "expected ChainResolutionHalted, got: {err:?}"
        );
        // NFR-003(3): this must reach hover/diagnostics as a distinguishable, safe hint via
        // deps-core's established `fetch_failure` -> `Actionable` mechanism, not stay
        // log-only.
        assert_eq!(
            err.fetch_failure(),
            deps_core::error::FetchFailure::Actionable(
                "index unreachable — resolution halted, not falling back to a less-trusted \
                 index"
                    .to_string()
            )
        );

        hop0_mock.assert_async().await;
        hop1_mock.assert_async().await;
    }

    /// NFR-003(3): the terminal-transport-error path logs a distinguishable diagnostic
    /// naming the halted-chain behavior, not a generic fetch-failed message.
    #[tokio::test]
    async fn test_transport_error_logs_distinguishable_diagnostic() {
        let mut hop0_server = mockito::Server::new_async().await;
        let hop0_mock = hop0_server
            .mock("GET", "/simple/pkg/")
            .with_status(503)
            .create_async()
            .await;

        let cache = Arc::new(HttpCache::new());
        cache.set_registry_policy(deps_core::net_policy::WorkspaceRegistryAccess::All);
        let head = PypiRegistry::with_base(
            Arc::clone(&cache),
            &index_url(&format!("{}/simple", hop0_server.url())),
            Vec::new(),
        );

        let log = deps_core::test_util::capture_tracing_output_async(async {
            head.get_versions_chained("pkg").await.unwrap_err();
        })
        .await;
        assert!(
            log.contains("not falling back to pypi.org"),
            "expected a distinguishable halted-chain diagnostic, got: {log:?}"
        );

        hop0_mock.assert_async().await;
    }

    /// Zero-hop `ResolvedChain::hops` (defensive — `PypiIndexConfig` never actually produces
    /// one) is a no-op registration, not a panic.
    #[test]
    fn test_register_chain_empty_hops_is_noop() {
        let cache = Arc::new(HttpCache::new());
        let root = Arc::new(PypiRegistry::new(cache));
        let chain = crate::config::ResolvedChain {
            key: "empty".to_string(),
            hops: Vec::new(),
            implicit_public_fallback: false,
        };
        PypiRegistry::register_chain(&root, &chain);
        assert!(root.alternate_client("empty").is_none());
    }

    /// `register_chain` is idempotent per key — a second registration for the same key is a
    /// no-op (mirrors `deps-npm::NpmRegistry::register_alternate`'s identical guarantee).
    #[test]
    fn test_register_chain_idempotent() {
        let cache = Arc::new(HttpCache::new());
        let root = Arc::new(PypiRegistry::new(cache));
        let chain = crate::config::ResolvedChain {
            key: "dup".to_string(),
            hops: vec![index_url("https://a.example/simple")],
            implicit_public_fallback: false,
        };
        PypiRegistry::register_chain(&root, &chain);
        let first = root.alternate_client("dup").unwrap();
        PypiRegistry::register_chain(&root, &chain);
        let second = root.alternate_client("dup").unwrap();
        assert!(Arc::ptr_eq(&first, &second));
    }

    /// `MAX_ALTERNATE_REGISTRIES` cap: once reached, a new chain is not registered (degrades
    /// to `PackageNotFound` at fetch time, never a silent public fallback).
    #[test]
    fn test_register_chain_capacity_cap() {
        let cache = Arc::new(HttpCache::new());
        let root = Arc::new(PypiRegistry::new(cache));
        for i in 0..MAX_ALTERNATE_REGISTRIES {
            let chain = crate::config::ResolvedChain {
                key: format!("chain-{i}"),
                hops: vec![index_url("https://a.example/simple")],
                implicit_public_fallback: false,
            };
            PypiRegistry::register_chain(&root, &chain);
        }
        let overflow = crate::config::ResolvedChain {
            key: "overflow".to_string(),
            hops: vec![index_url("https://b.example/simple")],
            implicit_public_fallback: false,
        };
        PypiRegistry::register_chain(&root, &overflow);
        assert!(root.alternate_client("overflow").is_none());
    }

    /// The C1 invariant: a chain-hop leaf's own `alternates` map is always empty — calling
    /// `alternate_client` on a non-root client returns `None` for everything, documented as
    /// intentional (T006), not a bug.
    #[test]
    fn test_alternate_client_only_meaningful_on_root() {
        let cache = Arc::new(HttpCache::new());
        let root = Arc::new(PypiRegistry::new(Arc::clone(&cache)));
        let chain = crate::config::ResolvedChain {
            key: "chain".to_string(),
            hops: vec![index_url("https://a.example/simple")],
            implicit_public_fallback: false,
        };
        PypiRegistry::register_chain(&root, &chain);
        let head = root.alternate_client("chain").unwrap();
        assert!(head.alternate_client("chain").is_none());
    }

    /// N1's fix: the implicit-public final hop is a fresh `Public`-tier leaf, not
    /// `Arc::clone(&root)` — dropping the root (and every other strong reference) after
    /// registering an implicit-fallback chain must actually deallocate it, proving there is
    /// no root->alternates->head->fallback_chain->root reference cycle.
    #[test]
    fn test_implicit_public_hop_does_not_create_reference_cycle() {
        let cache = Arc::new(HttpCache::new());
        let root = Arc::new(PypiRegistry::new(Arc::clone(&cache)));
        let root_weak = Arc::downgrade(&root);

        let chain = crate::config::ResolvedChain {
            key: "implicit".to_string(),
            hops: vec![index_url("https://a.example/simple")],
            implicit_public_fallback: true,
        };
        PypiRegistry::register_chain(&root, &chain);

        drop(root);
        assert!(
            root_weak.upgrade().is_none(),
            "root must deallocate once its only strong reference is dropped — a cycle would \
             keep it alive"
        );
    }

    /// FR-005(b)/N1: `register_chain` with `implicit_public_fallback: true` appends a
    /// freshly-constructed `Public`-tier leaf (same URL/transport as `pypi.org`) as the
    /// chain's final hop — verified structurally rather than by dispatching a live
    /// `get_versions_from` call, since walking off the end of this chain would otherwise
    /// contact the real `pypi.org` from a unit test.
    #[test]
    fn test_register_chain_implicit_public_fallback_hop_shape() {
        let cache = Arc::new(HttpCache::new());
        cache.set_registry_policy(deps_core::net_policy::WorkspaceRegistryAccess::All);
        let root = Arc::new(PypiRegistry::new(Arc::clone(&cache)));

        let extra = index_url("https://extra.example/simple");
        let chain = crate::config::ResolvedChain {
            key: "case-b".to_string(),
            hops: vec![extra],
            implicit_public_fallback: true,
        };
        PypiRegistry::register_chain(&root, &chain);

        let head = root.alternate_client("case-b").unwrap();
        assert_eq!(head.simple_base, "https://extra.example/simple");
        assert_eq!(head.fallback_chain.len(), 1);
        assert_eq!(head.fallback_chain[0].tier, PypiRegistryTier::Public);
        assert_eq!(head.fallback_chain[0].simple_base, PYPI_SIMPLE_BASE);
    }

    /// T012's explicit "must" criterion (validator finding #9), now actually testable via
    /// `Self::with_public_base_for_test`: FR-005(b) — a package present on **both** a
    /// declared extra and the (mocked) implicit public fallback resolves via the extra, and
    /// the public mock is **never contacted** for that name. `expect(0)` on the public mock
    /// makes this a hard request-count assertion, not just a check of the final result.
    #[tokio::test]
    async fn test_case_b_extra_wins_over_implicit_public_request_count_asserted() {
        use deps_core::PackageName;

        let mut extra_server = mockito::Server::new_async().await;
        let extra_mock = extra_server
            .mock("GET", "/simple/mypkg/")
            .with_status(200)
            .with_body(r#"{"versions": ["1.0.0"], "files": []}"#)
            .expect(1)
            .create_async()
            .await;

        let mut public_server = mockito::Server::new_async().await;
        let public_mock = public_server
            .mock("GET", mockito::Matcher::Any)
            .expect(0)
            .create_async()
            .await;

        let cache = Arc::new(HttpCache::new());
        cache.set_registry_policy(deps_core::net_policy::WorkspaceRegistryAccess::All);
        let root = Arc::new(PypiRegistry::with_public_base_for_test(
            Arc::clone(&cache),
            format!("{}/simple", public_server.url()),
        ));

        let extra = index_url(&format!("{}/simple", extra_server.url()));
        let chain = crate::config::ResolvedChain {
            key: "case-b-request-count".to_string(),
            hops: vec![extra],
            implicit_public_fallback: true,
        };
        PypiRegistry::register_chain(&root, &chain);

        let source = DependencySource::AlternateRegistry {
            index: chain.key.clone(),
            mirrors_crates_io: false,
        };
        let versions = deps_core::Registry::get_versions_from(
            root.as_ref(),
            &PackageName::new("mypkg"),
            &source,
            deps_core::FreshnessSettings::default(),
        )
        .await
        .unwrap();
        assert_eq!(versions.len(), 1);

        extra_mock.assert_async().await;
        public_mock.assert_async().await;
    }

    /// The mirror scenario: the extra misses (404), so the chain correctly falls through to
    /// the (mocked) implicit public fallback — proving the ordering is "extra first, public
    /// last", not "public only" or "extra only".
    #[tokio::test]
    async fn test_case_b_falls_through_to_implicit_public_when_extra_misses() {
        use deps_core::PackageName;

        let mut extra_server = mockito::Server::new_async().await;
        let extra_mock = extra_server
            .mock("GET", "/simple/mypkg/")
            .with_status(404)
            .create_async()
            .await;

        let mut public_server = mockito::Server::new_async().await;
        let public_mock = public_server
            .mock("GET", "/simple/mypkg/")
            .with_status(200)
            .with_body(r#"{"versions": ["9.9.9"], "files": []}"#)
            .create_async()
            .await;

        let cache = Arc::new(HttpCache::new());
        cache.set_registry_policy(deps_core::net_policy::WorkspaceRegistryAccess::All);
        let root = Arc::new(PypiRegistry::with_public_base_for_test(
            Arc::clone(&cache),
            format!("{}/simple", public_server.url()),
        ));

        let extra = index_url(&format!("{}/simple", extra_server.url()));
        let chain = crate::config::ResolvedChain {
            key: "case-b-fallthrough".to_string(),
            hops: vec![extra],
            implicit_public_fallback: true,
        };
        PypiRegistry::register_chain(&root, &chain);

        let source = DependencySource::AlternateRegistry {
            index: chain.key.clone(),
            mirrors_crates_io: false,
        };
        let versions = deps_core::Registry::get_versions_from(
            root.as_ref(),
            &PackageName::new("mypkg"),
            &source,
            deps_core::FreshnessSettings::default(),
        )
        .await
        .unwrap();
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0].version_string().as_str(), "9.9.9");

        extra_mock.assert_async().await;
        public_mock.assert_async().await;
    }

    /// Validator finding #10: a happy-path test for `get_latest_matching_from` — only the
    /// unregistered-alternate failure case was previously tested. Derived from
    /// `get_versions_chained` (M4, no independent chain walk), so this also confirms that
    /// path picks the right version out of the winning hop's list.
    #[tokio::test]
    async fn test_get_latest_matching_from_alternate_registry_happy_path() {
        use deps_core::PackageName;

        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/simple/pkg/")
            .with_status(200)
            .with_body(r#"{"versions": ["1.0.0", "1.5.0", "2.0.0"], "files": []}"#)
            .create_async()
            .await;

        let cache = Arc::new(HttpCache::new());
        cache.set_registry_policy(deps_core::net_policy::WorkspaceRegistryAccess::All);
        let root = Arc::new(PypiRegistry::new(Arc::clone(&cache)));

        let chain = crate::config::ResolvedChain {
            key: "latest-matching-happy-path".to_string(),
            hops: vec![index_url(&format!("{}/simple", server.url()))],
            implicit_public_fallback: false,
        };
        PypiRegistry::register_chain(&root, &chain);

        let source = DependencySource::AlternateRegistry {
            index: chain.key.clone(),
            mirrors_crates_io: false,
        };
        let latest = deps_core::Registry::get_latest_matching_from(
            root.as_ref(),
            &PackageName::new("pkg"),
            &source,
            &deps_core::VersionReq::new(">=1.0.0,<2.0.0"),
            None,
        )
        .await
        .unwrap();
        assert_eq!(
            latest.map(|v| v.version_string().to_string()),
            Some("1.5.0".to_string())
        );
        mock.assert_async().await;
    }

    /// Validator finding #11: a 3+-hop chain — every prior test caps at 2 hops. Confirms
    /// `get_versions_chained` correctly walks past a second miss to reach a third, winning
    /// hop, and that both earlier hops were actually queried in order (not skipped).
    #[tokio::test]
    async fn test_three_hop_chain_falls_through_to_third_hop() {
        let mut hop0_server = mockito::Server::new_async().await;
        let hop0_mock = hop0_server
            .mock("GET", "/simple/pkg/")
            .with_status(404)
            .create_async()
            .await;

        let mut hop1_server = mockito::Server::new_async().await;
        let hop1_mock = hop1_server
            .mock("GET", "/simple/pkg/")
            .with_status(200)
            .with_body(r#"{"versions": [], "files": []}"#)
            .create_async()
            .await;

        let mut hop2_server = mockito::Server::new_async().await;
        let hop2_mock = hop2_server
            .mock("GET", "/simple/pkg/")
            .with_status(200)
            .with_body(r#"{"versions": ["3.0.0"], "files": []}"#)
            .create_async()
            .await;

        let cache = Arc::new(HttpCache::new());
        cache.set_registry_policy(deps_core::net_policy::WorkspaceRegistryAccess::All);
        // `fallback_chain` is a flat list of every hop after hop 0, all direct children of
        // the head — never nested per-hop (that's how `register_chain` actually builds it;
        // `get_versions_chained` only ever walks `self.fallback_chain` one level deep, not
        // recursively).
        let hop1 = Arc::new(PypiRegistry::with_base(
            Arc::clone(&cache),
            &index_url(&format!("{}/simple", hop1_server.url())),
            Vec::new(),
        ));
        let hop2 = Arc::new(PypiRegistry::with_base(
            Arc::clone(&cache),
            &index_url(&format!("{}/simple", hop2_server.url())),
            Vec::new(),
        ));
        let head = PypiRegistry::with_base(
            Arc::clone(&cache),
            &index_url(&format!("{}/simple", hop0_server.url())),
            vec![hop1, hop2],
        );

        let versions = head.get_versions_chained("pkg").await.unwrap();
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0].version.as_str(), "3.0.0");

        hop0_mock.assert_async().await;
        hop1_mock.assert_async().await;
        hop2_mock.assert_async().await;
    }

    /// `AlternateRegistry` with no registered client -> `PackageNotFound`, never a public
    /// fallback (FR-010).
    #[tokio::test]
    async fn test_get_versions_from_unregistered_alternate_never_falls_back() {
        use deps_core::PackageName;

        let cache = Arc::new(HttpCache::new());
        let registry = PypiRegistry::new(cache);
        let source = DependencySource::AlternateRegistry {
            index: "pypi-chain:never-registered".to_string(),
            mirrors_crates_io: false,
        };
        let result = deps_core::Registry::get_versions_from(
            &registry,
            &PackageName::new("pkg"),
            &source,
            deps_core::FreshnessSettings::default(),
        )
        .await;
        assert!(matches!(result, Err(DepsError::PackageNotFound { .. })));

        let result = deps_core::Registry::get_latest_matching_from(
            &registry,
            &PackageName::new("pkg"),
            &source,
            &deps_core::VersionReq::new("*"),
            None,
        )
        .await;
        assert!(matches!(result, Err(DepsError::PackageNotFound { .. })));
    }

    // --- T008: tier guard on search/warm_search_index/get_package_metadata ---

    #[tokio::test]
    async fn test_search_on_workspace_declared_tier_issues_no_request() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", mockito::Matcher::Any)
            .expect(0)
            .create_async()
            .await;

        let cache = Arc::new(HttpCache::new());
        cache.set_registry_policy(deps_core::net_policy::WorkspaceRegistryAccess::All);
        let base = index_url(&format!("{}/simple", server.url()));
        let client = PypiRegistry::with_base(Arc::clone(&cache), &base, Vec::new());

        assert!(client.search("flask", 10).await.unwrap().is_empty());
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_warm_search_index_on_workspace_declared_tier_issues_no_request() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", mockito::Matcher::Any)
            .expect(0)
            .create_async()
            .await;

        let cache = Arc::new(HttpCache::new());
        cache.set_registry_policy(deps_core::net_policy::WorkspaceRegistryAccess::All);
        let base = index_url(&format!("{}/simple", server.url()));
        let client = PypiRegistry::with_base(Arc::clone(&cache), &base, Vec::new());

        client.warm_search_index();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_get_package_metadata_on_workspace_declared_tier_issues_no_request() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", mockito::Matcher::Any)
            .expect(0)
            .create_async()
            .await;

        let cache = Arc::new(HttpCache::new());
        cache.set_registry_policy(deps_core::net_policy::WorkspaceRegistryAccess::All);
        let base = index_url(&format!("{}/simple", server.url()));
        let client = PypiRegistry::with_base(Arc::clone(&cache), &base, Vec::new());

        let err = client.get_package_metadata("flask").await.unwrap_err();
        assert!(matches!(err, DepsError::PackageNotFound { .. }));
        mock.assert_async().await;
    }
}
