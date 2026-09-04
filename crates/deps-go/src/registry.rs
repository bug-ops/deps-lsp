//! proxy.golang.org registry client.
//!
//! Provides access to Go module proxy via:
//! - `/{module}/@v/list` - list all versions
//! - `/{module}/@v/{version}.info` - version metadata
//! - `/{module}/@v/{version}.mod` - go.mod file
//! - `/{module}/@latest` - latest version info
//!
//! All HTTP requests are cached aggressively using ETag/Last-Modified headers.
//!
//! # Examples
//!
//! ```no_run
//! use deps_go::GoRegistry;
//! use deps_core::HttpCache;
//! use std::sync::Arc;
//!
//! #[tokio::main]
//! async fn main() {
//!     let cache = Arc::new(HttpCache::new());
//!     let registry = GoRegistry::new(cache);
//!
//!     let versions = registry.get_versions("github.com/gin-gonic/gin").await.unwrap();
//!     println!("Latest gin: {}", versions[0].version);
//! }
//! ```

use crate::config::{ChainSeparator, GoProxyChain, GoProxyHop, GoProxyUrl};
use crate::types::GoVersion;
use crate::version::{escape_module_path, escape_version, is_pseudo_version};
use dashmap::DashMap;
use deps_core::parser::DependencySource;
use deps_core::{DepsError, HttpCache, Result, is_dot_segment, lsp_helpers::warn_rejected_value};
use serde::Deserialize;
use std::any::Any;
use std::sync::Arc;

const PROXY_BASE: &str = "https://proxy.golang.org";

/// Display name for the Go module proxy used in not-found and API-response
/// error messages.
pub const REGISTRY: &str = "Go proxy";

/// Base URL for Go package documentation
pub const PKG_GO_DEV_URL: &str = "https://pkg.go.dev";

/// Upper bound on [`GoRegistry::alternates`]' entry count. Generous for any realistic
/// project's `$GOENV` configuration, exists only to keep this map — keyed by
/// process-config-controlled chain identities — from growing unbounded for the process
/// lifetime. Mirrors `deps-pypi`/`deps-npm`'s identical cap. Once at capacity, a *new* chain
/// is simply never registered (see [`GoRegistry::register_chain`]) — a dependency resolved to
/// an unregistered chain degrades to [`DepsError::PackageNotFound`], never to a
/// `proxy.golang.org` lookup by name (spec FR-009/FR-013).
const MAX_ALTERNATE_REGISTRIES: usize = 256;

/// Which transport/behavior a [`GoRegistry`] instance uses (spec 034 FR-004/FR-006/FR-011).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GoRegistryTier {
    /// `proxy.golang.org` (or a test override) — `HttpCache::get_cached`, today's path,
    /// unchanged, never subject to `registries.workspace_registries` (FR-011).
    Public,
    /// A `$GOENV`-declared `GOPROXY` hop — `HttpCache::get_cached_workspace`, so every
    /// redirect hop is re-classified against the live
    /// [`deps_core::net_policy::RegistryAccessPolicy`] (mirrors `deps-pypi`/`deps-npm`'s
    /// identical `WorkspaceDeclared` routing).
    WorkspaceDeclared,
    /// A [`GoProxyHop::Direct`]/[`GoProxyHop::Off`] sentinel (FR-004/FR-006) — every inherent
    /// fetch method short-circuits to [`DepsError::PackageNotFound`] before building any URL
    /// or issuing any request. Both sentinels are observably identical: phase 1 has no
    /// direct-VCS resolution mechanism, and `off` disallows downloads outright.
    Terminal,
}

/// Maximum allowed module path length to prevent DoS
const MAX_MODULE_PATH_LENGTH: usize = 500;

/// Maximum allowed version string length
const MAX_VERSION_LENGTH: usize = 128;

/// Validates a module path for length and basic format.
///
/// Rejections intentionally render through the shared `DepsError::InvalidVersionReq` variant
/// rather than a Go-specific one — see #399.
///
/// # Errors
///
/// Returns error if:
/// - Path is empty
/// - Path exceeds MAX_MODULE_PATH_LENGTH
/// - Any `/`-separated segment is exactly `.`/`..`
///
/// `pub(crate)` (not private) so [`crate::formatter::GoFormatter::validate_package_name`] can
/// reuse the same structural rule for its "Invalid package name" diagnostic lint (#402).
pub(crate) fn validate_module_path(module_path: &str) -> Result<()> {
    if module_path.is_empty() {
        return Err(DepsError::InvalidVersionReq("module path is empty".into()));
    }

    if module_path.len() > MAX_MODULE_PATH_LENGTH {
        return Err(DepsError::InvalidVersionReq(format!(
            "module path exceeds maximum length of {MAX_MODULE_PATH_LENGTH} characters"
        )));
    }

    // `escape_module_path` deliberately passes `.` and `/` through unescaped — the Go
    // module proxy protocol requires literal `/` for multi-segment paths, and Go module
    // paths legitimately contain dots within a segment (e.g. `golang.org/x/mod`). But a
    // segment that is *exactly* `.`/`..` is never a valid module path component, and once
    // spliced into `{PROXY_BASE}/{escaped}/@v/list` (etc.) it is silently collapsed by the
    // URL parser's dot-segment normalization — the same defect class as #341/#349/#357/#361.
    if module_path.split('/').any(is_dot_segment) {
        warn_rejected_value("is_dot_segment", "Go module proxy request URL", module_path);
        return Err(DepsError::InvalidVersionReq(format!(
            "module path '{module_path}' contains a `.`/`..` path segment"
        )));
    }

    Ok(())
}

/// Builds the Go module proxy request URL for a module's version list, against `base`
/// (`PROXY_BASE` for the public root; a resolved `$GOENV`-declared `GOPROXY` hop's own URL
/// otherwise — spec 034 FR-013). Callers must run [`validate_module_path`] first —
/// `escape_module_path` passes `.`/`/` through unescaped by design, so a `.`/`..` path
/// segment reaches this unfiltered.
fn versions_list_url_at(base: &str, module_path: &str) -> String {
    let escaped = escape_module_path(module_path);
    format!("{base}/{escaped}/@v/list")
}

/// Validates a version string for length and basic format.
///
/// # Errors
///
/// Returns error if:
/// - Version is empty
/// - Version exceeds MAX_VERSION_LENGTH
/// - Version contains path traversal sequences
fn validate_version_string(version: &str) -> Result<()> {
    if version.is_empty() {
        return Err(DepsError::InvalidVersionReq(
            "version string is empty".into(),
        ));
    }

    if version.len() > MAX_VERSION_LENGTH {
        return Err(DepsError::InvalidVersionReq(format!(
            "version string exceeds maximum length of {MAX_VERSION_LENGTH} characters"
        )));
    }

    // Check for path traversal attempts
    if version.contains("..") || version.contains('/') || version.contains('\\') {
        return Err(DepsError::InvalidVersionReq(
            "version string contains invalid characters".into(),
        ));
    }

    Ok(())
}

/// Returns the URL for a module's documentation page on pkg.go.dev.
///
/// Each `/`-separated path segment is percent-encoded individually via
/// `urlencoding::encode` (the same helper every other ecosystem uses), so `/` survives
/// as the legitimate path separator in Go module paths (e.g.
/// `github.com/gin-gonic/gin`) while every other character — including `%`, which a
/// hand-rolled denylist would otherwise miss — is escaped.
///
/// Display link only, never fetched by this process — unlike a registry-fetch URL
/// builder, so it is deliberately not gated against a `.`/`..` module-path segment (see
/// [`deps_core::is_dot_segment`]'s doc for the fetch-sink-vs-display-link scope split, #379).
pub fn package_url(module_path: &str) -> String {
    let encoded = module_path
        .split('/')
        .map(urlencoding::encode)
        .collect::<Vec<_>>()
        .join("/");
    format!("{PKG_GO_DEV_URL}/{encoded}")
}

/// Builds a `/@v/{version}.{suffix}` proxy URL (e.g. `.info`, `.mod`) for a module.
///
/// Both `module_path` and `version` are escaped via `escape_module_path` and
/// `escape_version` respectively before interpolation, so a version string
/// carrying `?`, `#`, or whitespace cannot retarget the request to a
/// different endpoint or inject a query string / fragment (#377).
fn version_url_at(base: &str, module_path: &str, version: &str, suffix: &str) -> String {
    let escaped_module = escape_module_path(module_path);
    let escaped_version = escape_version(version);
    format!("{base}/{escaped_module}/@v/{escaped_version}.{suffix}")
}

/// Converts a `404`/`410` response into `DepsError::PackageNotFound`, passing through any
/// other error unchanged.
///
/// `410 Gone` is included alongside `404` (spec 034 C1): the Go toolchain's own module-proxy
/// client (`cmd/go/internal/web/api.go`) treats both as "module/version not found", and
/// Athens/JFrog Artifactory/Sonatype Nexus/GitLab's Go proxy implementations — the exact
/// `GOPROXY` chain hops this feature targets — return `410` for an absent module. Missing this
/// left a real `410` response falling into `get_versions_chained`'s transport-failure arm,
/// halting chain resolution instead of falling through to the next hop (FR-005).
fn not_found_or(err: DepsError, module_path: &str) -> DepsError {
    if matches!(
        err,
        DepsError::HttpStatus {
            status: 404 | 410,
            ..
        }
    ) {
        DepsError::PackageNotFound {
            package: module_path.to_string(),
            registry: REGISTRY,
        }
    } else {
        err
    }
}

/// Client for interacting with proxy.golang.org.
///
/// Uses the Go module proxy protocol for version lookups and metadata.
/// All requests are cached via the provided HttpCache.
#[derive(Clone)]
pub struct GoRegistry {
    cache: Arc<HttpCache>,
    /// Version-fetch base for **this client's own hop** — `PROXY_BASE` for the public root; a
    /// resolved [`GoProxyUrl`]'s own URL for a `$GOENV`-declared `GOPROXY` hop; unused
    /// (never reached — every fetch short-circuits first) for a `Terminal`-tier client.
    proxy_base: String,
    /// Which transport/behavior this client uses (spec 034 FR-004/FR-006/FR-011).
    tier: GoRegistryTier,
    /// Resolved chain-router clients, keyed by [`GoProxyChain::key`] (a `GOPROXY` chain) or
    /// [`crate::config::GOPRIVATE_CHAIN_KEY`] (the `GOPRIVATE`-bypass chain). Only the root
    /// (`Public`-tier) instance this crate constructs via [`Self::new`] ever registers into
    /// this or is ever looked up by [`Self::alternate_client`] — a chain-hop leaf's own map is
    /// always empty by construction, mirroring `deps-pypi`'s identical `alternates` invariant.
    alternates: Arc<DashMap<String, Arc<Self>>>,
    /// Resolved, already-constructed hop clients this instance falls through to when it (hop
    /// 0) misses (spec FR-005), each paired with the [`ChainSeparator`] governing the
    /// transition *into* it (spec 034 S2 — `,` = fall through only on not-found, `|` = fall
    /// through on any error). Empty for the `Public`-tier root and every leaf hop — populated
    /// only on the *head* client [`Self::register_chain`] builds for a multi-hop chain.
    fallback_chain: Vec<(ChainSeparator, Arc<Self>)>,
}

impl GoRegistry {
    /// Creates a new Go registry client with the given HTTP cache.
    pub fn new(cache: Arc<HttpCache>) -> Self {
        Self {
            cache,
            proxy_base: PROXY_BASE.to_string(),
            tier: GoRegistryTier::Public,
            alternates: Arc::new(DashMap::new()),
            fallback_chain: Vec::new(),
        }
    }

    /// Creates a [`GoRegistry`] client for one resolved `$GOENV`-declared `GOPROXY` hop —
    /// `WorkspaceDeclared`-tier so it fetches through `HttpCache::get_cached_workspace`
    /// (FR-011's redirect-hop gating) instead of the ungated public transport.
    ///
    /// `fallback_chain` is empty for every call except the *head* client
    /// [`Self::register_chain`] builds for a multi-hop chain — every other hop is a leaf with
    /// nothing further to fall through to, matching `deps-pypi`'s identical design.
    #[must_use]
    fn with_base(
        cache: Arc<HttpCache>,
        url: &GoProxyUrl,
        fallback_chain: Vec<(ChainSeparator, Arc<Self>)>,
    ) -> Self {
        Self {
            cache,
            proxy_base: url.as_str().to_string(),
            tier: GoRegistryTier::WorkspaceDeclared,
            alternates: Arc::new(DashMap::new()),
            fallback_chain,
        }
    }

    /// Creates a `Terminal`-tier client (spec FR-004/FR-006) for a
    /// [`GoProxyHop::Direct`]/[`GoProxyHop::Off`] chain entry — every inherent fetch method
    /// short-circuits to [`DepsError::PackageNotFound`] before ever building a URL, so
    /// `proxy_base` is left empty (never read).
    #[must_use]
    fn terminal(cache: Arc<HttpCache>, fallback_chain: Vec<(ChainSeparator, Arc<Self>)>) -> Self {
        Self {
            cache,
            proxy_base: String::new(),
            tier: GoRegistryTier::Terminal,
            alternates: Arc::new(DashMap::new()),
            fallback_chain,
        }
    }

    /// Builds the client for one [`GoProxyHop`] — a leaf with an empty `fallback_chain`,
    /// shared by [`Self::register_chain`] for every hop after the first.
    fn hop_client(cache: &Arc<HttpCache>, hop: &GoProxyHop) -> Arc<Self> {
        Arc::new(match hop {
            GoProxyHop::Url(url) => Self::with_base(Arc::clone(cache), url, Vec::new()),
            GoProxyHop::Direct | GoProxyHop::Off => Self::terminal(Arc::clone(cache), Vec::new()),
        })
    }

    /// Builds the full hop chain for one [`GoProxyChain`] and inserts the head into
    /// `root.alternates` under `chain.key`. Idempotent per key (a repeat registration for the
    /// same key is a no-op), capacity-capped at `MAX_ALTERNATE_REGISTRIES`. Mirrors
    /// `deps_pypi::PypiRegistry::register_chain` exactly in shape.
    pub fn register_chain(root: &Arc<Self>, chain: &GoProxyChain) {
        let Some((first_hop, rest_hops)) = chain.hops.split_first() else {
            // Defensive: `GoEnvConfig::resolved_chains` never produces an empty-hop chain.
            return;
        };

        // Read before `entry()`: `DashMap::len` read-locks every shard, and `entry()` holds a
        // write guard on one — checking capacity from inside the `Vacant` arm would
        // self-deadlock on that shard.
        let at_capacity = root.alternates.len() >= MAX_ALTERNATE_REGISTRIES;

        if let dashmap::mapref::entry::Entry::Vacant(slot) =
            root.alternates.entry(chain.key.clone())
        {
            if at_capacity {
                tracing::warn!(
                    key = %chain.key,
                    cap = MAX_ALTERNATE_REGISTRIES,
                    "Go alternate proxy cap reached; not registering a new chain"
                );
                return;
            }

            // `chain.separators[i]` is the separator between `hops[i]` and `hops[i + 1]`
            // (spec 034 S2); `rest_hops[i]` is `hops[i + 1]`, so both are indexed by `i`
            // here. A shorter/empty `separators` (every hand-built test chain, and the
            // single-hop `GOPRIVATE` chain) defaults every transition to `NotFoundOnly`.
            let fallback_chain: Vec<(ChainSeparator, Arc<Self>)> = rest_hops
                .iter()
                .enumerate()
                .map(|(i, hop)| {
                    let sep = chain
                        .separators
                        .get(i)
                        .copied()
                        .unwrap_or(ChainSeparator::NotFoundOnly);
                    (sep, Self::hop_client(&root.cache, hop))
                })
                .collect();

            let head = match first_hop {
                GoProxyHop::Url(url) => {
                    Self::with_base(Arc::clone(&root.cache), url, fallback_chain)
                }
                GoProxyHop::Direct | GoProxyHop::Off => {
                    Self::terminal(Arc::clone(&root.cache), fallback_chain)
                }
            };
            slot.insert(Arc::new(head));
        }
    }

    /// The registered client for `index` (a [`GoProxyChain::key`] or
    /// [`crate::config::GOPRIVATE_CHAIN_KEY`]), if any — read-only, performs no registration,
    /// no validation.
    ///
    /// Only ever meaningful on the **root**: a chain-hop leaf's own `alternates` map is
    /// always empty by construction (`Self::with_base`/`Self::terminal` never populate
    /// it).
    #[must_use]
    pub fn alternate_client(&self, index: &str) -> Option<Arc<Self>> {
        self.alternates.get(index).map(|entry| Arc::clone(&entry))
    }

    /// S3 (spec 034 review): tries `/@latest` first — mirrors the public-path
    /// `Registry::get_latest_matching` fast path — falling back to `/@v/list` on an `/@latest`
    /// miss. `/@v/list` alone is incomplete for an untagged/pseudo-version-only module (#364);
    /// a chain hop that only ever tried `/@v/list` silently lost version data for that case.
    async fn get_versions_with_latest_fallback(&self, module_path: &str) -> Result<Vec<GoVersion>> {
        if let Ok(latest) = self.get_latest(module_path).await {
            return Ok(vec![latest]);
        }
        self.get_versions(module_path).await
    }

    /// FR-005/NFR-006: tries `self` (hop 0) first, then each already-resolved
    /// `Self::fallback_chain` entry in order (each via
    /// [`Self::get_versions_with_latest_fallback`], S3). A [`GoProxyHop::Direct`]/
    /// [`GoProxyHop::Off`] hop's `Terminal`-tier fetch always returns `PackageNotFound` with
    /// no network request, which this loop treats the same as an ordinary not-found response
    /// and falls through past — implementing FR-005's "explicit not-found continues to the
    /// next hop" rule uniformly for a proxy 404/410 and for reaching a terminal sentinel
    /// (US-003).
    ///
    /// A transport failure (connection error, timeout, 5xx) on a hop is terminal for the
    /// whole chain **unless** the [`ChainSeparator`] governing the transition to the next hop
    /// is [`ChainSeparator::AnyError`] (spec 034 S2, the `|`-separator case) — mirrors
    /// `deps-pypi`'s identical FR-005(c) trade-off for the default `,`-separated case:
    /// silently falling through on transport failure risks resolving a module through a
    /// fallback the user did not intend for the reachability state they are actually in.
    async fn get_versions_chained(&self, module_path: &str) -> Result<Vec<GoVersion>> {
        let mut last_miss: Result<Vec<GoVersion>> = Err(DepsError::PackageNotFound {
            package: module_path.to_string(),
            registry: REGISTRY,
        });

        // `next_seps[k]` is the separator governing hop `k`'s fallback to hop `k + 1` — `None`
        // past the last hop (nothing to fall through to, so any error there is unconditionally
        // terminal regardless of separator).
        let hops: Vec<&Self> = std::iter::once(self)
            .chain(self.fallback_chain.iter().map(|(_, hop)| hop.as_ref()))
            .collect();
        let next_seps: Vec<Option<ChainSeparator>> = self
            .fallback_chain
            .iter()
            .map(|(sep, _)| Some(*sep))
            .chain(std::iter::once(None))
            .collect();

        for (hop, next_sep) in hops.iter().zip(next_seps.iter()) {
            match hop.get_versions_with_latest_fallback(module_path).await {
                Ok(versions) if !versions.is_empty() => return Ok(versions),
                Ok(empty) => last_miss = Ok(empty),
                Err(DepsError::PackageNotFound { .. }) => {
                    last_miss = Err(DepsError::PackageNotFound {
                        package: module_path.to_string(),
                        registry: REGISTRY,
                    });
                }
                Err(other) => match next_sep {
                    Some(ChainSeparator::AnyError) => {
                        tracing::warn!(
                            module = module_path,
                            error = %other,
                            "Go alternate-proxy chain hop failed, but the `|` separator \
                             tolerates any error; falling through to the next hop"
                        );
                        last_miss = Err(other);
                    }
                    _ => {
                        tracing::warn!(
                            module = module_path,
                            error = %other,
                            "Go alternate-proxy chain resolution halted on a transport error — \
                             not falling back to proxy.golang.org or the next configured hop"
                        );
                        return Err(DepsError::ChainResolutionHalted);
                    }
                },
            }
        }

        last_miss
    }

    /// Fetches all versions for a module from the `/@v/list` endpoint.
    ///
    /// Returns versions in registry order (not sorted). Includes pseudo-versions.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - HTTP request fails
    /// - Response body is invalid UTF-8
    /// - Module does not exist (404)
    /// - Module path is invalid or too long
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use deps_go::GoRegistry;
    /// # use deps_core::HttpCache;
    /// # use std::sync::Arc;
    /// # #[tokio::main]
    /// # async fn main() {
    /// let cache = Arc::new(HttpCache::new());
    /// let registry = GoRegistry::new(cache);
    ///
    /// let versions = registry.get_versions("github.com/gin-gonic/gin").await.unwrap();
    /// assert!(!versions.is_empty());
    /// # }
    /// ```
    pub async fn get_versions(&self, module_path: &str) -> Result<Vec<GoVersion>> {
        if self.tier == GoRegistryTier::Terminal {
            return Err(DepsError::PackageNotFound {
                package: module_path.to_string(),
                registry: REGISTRY,
            });
        }
        validate_module_path(module_path)?;

        let url = versions_list_url_at(&self.proxy_base, module_path);

        let data = match self.tier {
            GoRegistryTier::Public => self.cache.get_cached(&url).await,
            GoRegistryTier::WorkspaceDeclared => self.cache.get_cached_workspace(&url).await,
            GoRegistryTier::Terminal => unreachable!("short-circuited above"),
        }
        .map_err(|e| not_found_or(e, module_path))?;

        parse_version_list(&data)
    }

    /// Fetches version metadata from the `/@v/{version}.info` endpoint.
    ///
    /// Returns version with timestamp information.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - HTTP request fails
    /// - JSON parsing fails
    /// - Module path or version string is invalid
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use deps_go::GoRegistry;
    /// # use deps_core::HttpCache;
    /// # use std::sync::Arc;
    /// # #[tokio::main]
    /// # async fn main() {
    /// let cache = Arc::new(HttpCache::new());
    /// let registry = GoRegistry::new(cache);
    ///
    /// let info = registry.get_version_info("github.com/gin-gonic/gin", "v1.9.1").await.unwrap();
    /// assert_eq!(info.version, "v1.9.1");
    /// # }
    /// ```
    pub async fn get_version_info(&self, module_path: &str, version: &str) -> Result<GoVersion> {
        if self.tier == GoRegistryTier::Terminal {
            return Err(DepsError::PackageNotFound {
                package: module_path.to_string(),
                registry: REGISTRY,
            });
        }
        validate_module_path(module_path)?;
        validate_version_string(version)?;

        let url = version_url_at(&self.proxy_base, module_path, version, "info");

        let data = match self.tier {
            GoRegistryTier::Public => self.cache.get_cached(&url).await,
            GoRegistryTier::WorkspaceDeclared => self.cache.get_cached_workspace(&url).await,
            GoRegistryTier::Terminal => unreachable!("short-circuited above"),
        }
        .map_err(|e| not_found_or(e, module_path))?;

        parse_version_info(module_path, &data)
    }

    /// Fetches latest version using the `/@latest` endpoint.
    ///
    /// Returns the latest stable version (non-pseudo).
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - HTTP request fails
    /// - JSON parsing fails
    /// - Module path is invalid
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use deps_go::GoRegistry;
    /// # use deps_core::HttpCache;
    /// # use std::sync::Arc;
    /// # #[tokio::main]
    /// # async fn main() {
    /// let cache = Arc::new(HttpCache::new());
    /// let registry = GoRegistry::new(cache);
    ///
    /// let latest = registry.get_latest("github.com/gin-gonic/gin").await.unwrap();
    /// assert!(!latest.is_pseudo);
    /// # }
    /// ```
    pub async fn get_latest(&self, module_path: &str) -> Result<GoVersion> {
        if self.tier == GoRegistryTier::Terminal {
            return Err(DepsError::PackageNotFound {
                package: module_path.to_string(),
                registry: REGISTRY,
            });
        }
        validate_module_path(module_path)?;

        let escaped = escape_module_path(module_path);
        let url = format!("{}/{escaped}/@latest", self.proxy_base);

        let data = match self.tier {
            GoRegistryTier::Public => self.cache.get_cached(&url).await,
            GoRegistryTier::WorkspaceDeclared => self.cache.get_cached_workspace(&url).await,
            GoRegistryTier::Terminal => unreachable!("short-circuited above"),
        }
        .map_err(|e| not_found_or(e, module_path))?;

        parse_version_info(module_path, &data)
    }

    /// Fetches the go.mod file for a specific version.
    ///
    /// Returns the raw content of the go.mod file.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - HTTP request fails
    /// - Response body is invalid UTF-8
    /// - Module path or version string is invalid
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use deps_go::GoRegistry;
    /// # use deps_core::HttpCache;
    /// # use std::sync::Arc;
    /// # #[tokio::main]
    /// # async fn main() {
    /// let cache = Arc::new(HttpCache::new());
    /// let registry = GoRegistry::new(cache);
    ///
    /// let go_mod = registry.get_go_mod("github.com/gin-gonic/gin", "v1.9.1").await.unwrap();
    /// assert!(go_mod.contains("module github.com/gin-gonic/gin"));
    /// # }
    /// ```
    pub async fn get_go_mod(&self, module_path: &str, version: &str) -> Result<String> {
        if self.tier == GoRegistryTier::Terminal {
            return Err(DepsError::PackageNotFound {
                package: module_path.to_string(),
                registry: REGISTRY,
            });
        }
        validate_module_path(module_path)?;
        validate_version_string(version)?;

        let url = version_url_at(&self.proxy_base, module_path, version, "mod");

        let data = match self.tier {
            GoRegistryTier::Public => self.cache.get_cached(&url).await,
            GoRegistryTier::WorkspaceDeclared => self.cache.get_cached_workspace(&url).await,
            GoRegistryTier::Terminal => unreachable!("short-circuited above"),
        }
        .map_err(|e| not_found_or(e, module_path))?;

        std::str::from_utf8(&data)
            .map(std::string::ToString::to_string)
            .map_err(|e| DepsError::CacheError(format!("Invalid UTF-8 in go.mod: {e}")))
    }
}

/// Version info response from proxy.golang.org.
#[derive(Deserialize)]
struct VersionInfo {
    #[serde(rename = "Version")]
    version: String,
    #[serde(rename = "Time")]
    time: String,
}

/// Parses newline-separated version list from `/@v/list` endpoint.
///
/// Versions are sorted in descending order (newest first) to ensure
/// `find_latest_stable` returns the correct latest version.
fn parse_version_list(data: &[u8]) -> Result<Vec<GoVersion>> {
    let content = std::str::from_utf8(data).map_err(|e| {
        DepsError::CacheError(format!("Invalid UTF-8 in version list response: {e}"))
    })?;

    // Parse versions with precomputed sort keys (Schwartzian transform)
    // This avoids repeated regex/semver parsing during sort comparisons
    let mut versions_with_keys: Vec<(GoVersion, Option<semver::Version>)> = content
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let is_pseudo = is_pseudo_version(line);
            let sort_key = parse_sort_key(line, is_pseudo);
            let version = GoVersion {
                version: line.into(),
                // `/@v/list` carries no dates — a documented Go-specific
                // limitation of this Ch2 path, not a parse failure.
                published_at: None,
                is_pseudo,
                retracted: false,
            };
            (version, sort_key)
        })
        .collect();

    // Sort by precomputed keys (descending - newest first)
    versions_with_keys.sort_by(|a, b| match (&b.1, &a.1) {
        (Some(v1), Some(v2)) => v1.cmp(v2),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => b.0.version.as_str().cmp(a.0.version.as_str()),
    });

    Ok(versions_with_keys.into_iter().map(|(v, _)| v).collect())
}

/// Parses a version string into a semver::Version for sorting.
/// Uses precomputed is_pseudo flag to avoid regex during sort.
fn parse_sort_key(version: &str, is_pseudo: bool) -> Option<semver::Version> {
    use crate::version::base_version_from_pseudo;

    let clean = version.trim_start_matches('v').replace("+incompatible", "");
    let cmp_str = if is_pseudo {
        base_version_from_pseudo(version).unwrap_or(clean)
    } else {
        clean
    };

    // Parse only the X.Y.Z part, ignoring prerelease suffix
    let base = cmp_str.split('-').next().unwrap_or(&cmp_str);
    semver::Version::parse(base.trim_start_matches('v')).ok()
}

/// Parses JSON version info from `/@v/{version}.info` or `/@latest` endpoint.
fn parse_version_info(module_path: &str, data: &[u8]) -> Result<GoVersion> {
    let info: VersionInfo =
        deps_core::parse_json_checked(data).map_err(|e| DepsError::ApiResponse {
            package: module_path.to_string(),
            registry: REGISTRY,
            source: e,
        })?;

    let is_pseudo = is_pseudo_version(&info.version);
    Ok(GoVersion {
        version: info.version.into(),
        published_at: deps_core::PublishTime::parse_rfc3339(&info.time),
        is_pseudo,
        retracted: false,
    })
}

impl deps_core::Registry for GoRegistry {
    fn get_versions<'a>(
        &'a self,
        name: &'a deps_core::PackageName,
    ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn deps_core::Version>>>>
    {
        Box::pin(async move {
            let versions = self.get_versions(name.as_str()).await?;
            Ok(versions
                .into_iter()
                .map(|v| Box::new(v) as Box<dyn deps_core::Version>)
                .collect())
        })
    }

    fn get_latest_matching<'a>(
        &'a self,
        name: &'a deps_core::PackageName,
        _req: &'a deps_core::VersionReq,
    ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Option<Box<dyn deps_core::Version>>>>
    {
        Box::pin(async move {
            // Try /@latest first (fast path)
            if let Ok(version) = self.get_latest(name.as_str()).await {
                return Ok(Some(Box::new(version) as Box<dyn deps_core::Version>));
            }
            // Fallback to /@v/list (/@latest is optional per Go proxy spec)
            let versions = self.get_versions(name.as_str()).await?;
            let latest = versions.into_iter().find(|v| !v.is_pseudo && !v.retracted);
            Ok(latest.map(|v| Box::new(v) as Box<dyn deps_core::Version>))
        })
    }

    /// Dispatches by `source` (spec 034 FR-013): an `AlternateRegistry` whose index has a
    /// registered client routes through `GoRegistry::get_versions_chained` (FR-005's chain
    /// walk); one with **no** registered client is `PackageNotFound`, never a fall back to
    /// `proxy.golang.org` (Go always sets `mirrors_crates_io: false`, so Cargo's
    /// mirror-degradation arm is dead here and must not be written — falling back would send
    /// a private module path to the public proxy, the exact class of leak FR-008/FR-009
    /// close). Every other source keeps today's public-registry path unchanged.
    fn get_versions_from<'a>(
        &'a self,
        name: &'a deps_core::PackageName,
        source: &'a DependencySource,
        freshness: deps_core::FreshnessSettings,
    ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn deps_core::Version>>>>
    {
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
    /// "never fall back to `proxy.golang.org` for an unregistered `AlternateRegistry`"
    /// invariant. Derived from `GoRegistry::get_versions_chained` +
    /// [`deps_core::Registry::select_latest_matching`] (mirrors `deps-pypi`'s identical
    /// derivation) rather than an independent per-hop matching walk — the winning hop (first
    /// hop with a non-empty version list) is selected once, and matching happens only within
    /// that single hop's list. No `/@latest` fast path for a chain hop (unlike the plain
    /// public-registry path below): phase 1 keeps this simple and correct rather than
    /// optimizing an extra request off the private-proxy path.
    fn get_latest_matching_from<'a>(
        &'a self,
        name: &'a deps_core::PackageName,
        source: &'a DependencySource,
        req: &'a deps_core::VersionReq,
        _minimum_stability: Option<&'a str>,
    ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Option<Box<dyn deps_core::Version>>>>
    {
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
                            let idx = deps_core::Registry::select_latest_matching(
                                client.as_ref(),
                                &versions,
                                req,
                            );
                            Ok(idx.and_then(|i| versions.into_iter().nth(i)))
                        }
                        None => Err(DepsError::PackageNotFound {
                            package: name.to_string(),
                            registry: "alternate registry (not registered)",
                        }),
                    }
                }
                // Preserves the plain public-registry path's existing `/@latest`
                // fast-path/`/@v/list`-fallback behavior unchanged (NFR-005).
                _ => deps_core::Registry::get_latest_matching(self, name, req).await,
            }
        })
    }

    fn search<'a>(
        &'a self,
        _query: &'a str,
        _limit: usize,
    ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::Result<Vec<Box<dyn deps_core::Metadata>>>>
    {
        // proxy.golang.org doesn't support search
        Box::pin(async move { Ok(vec![]) })
    }

    fn select_latest_matching(
        &self,
        versions: &[Box<dyn deps_core::Version>],
        _req: &deps_core::VersionReq,
    ) -> Option<usize> {
        // Mirrors the `/@v/list` fallback branch of the inherent `get_latest_matching`
        // above (the `/@latest` fast path isn't reachable here: this method is a pure,
        // no-I/O pick over an already-fetched list). `req` is ignored, matching that
        // fallback — Go module requirements are exact pins/MVS, not ranges.
        //
        // Go deliberately opts out of the shared existence-check ladder
        // (`deps_core::select_latest_for_existence`, see #364): Go has no real per-version
        // retraction (`retracted` is hardcoded `false`, see `reports_yanked` below), so the
        // ladder's rung 3 would return `Some(0)` unconditionally on an all-prerelease `/@v/
        // list` and short-circuit the `/@latest` fallback in `lifecycle.rs`, which resolves
        // pseudo-versions `/@v/list` never enumerates.
        versions
            .iter()
            .position(|v| !v.is_prerelease() && !v.removal_status().blocks_resolution())
    }

    // `Version::removal_status` is hardcoded to `Available` (`registry.rs:354`, `:401`) —
    // the proxy's `/@v/list` fast path never surfaces `retract` data, so a
    // yanked-check probe here would always come back empty (#233).
    fn reports_yanked(&self) -> bool {
        false
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_version_list() {
        let data = b"v1.0.0\nv1.0.1\nv1.1.0\nv2.0.0\n";

        let versions = parse_version_list(data).unwrap();
        assert_eq!(versions.len(), 4);
        // Sorted descending (newest first)
        assert_eq!(versions[0].version, "v2.0.0");
        assert_eq!(versions[1].version, "v1.1.0");
        assert_eq!(versions[2].version, "v1.0.1");
        assert_eq!(versions[3].version, "v1.0.0");
        assert!(!versions[0].is_pseudo);
    }

    #[test]
    fn test_parse_version_list_with_pseudo() {
        let data = b"v1.0.0\nv0.0.0-20191109021931-daa7c04131f5\nv1.1.0\n";

        let versions = parse_version_list(data).unwrap();
        assert_eq!(versions.len(), 3);
        // Sorted descending: v1.1.0, v1.0.0, v0.0.0-... (pseudo based on v0.0.0)
        assert_eq!(versions[0].version, "v1.1.0");
        assert!(!versions[0].is_pseudo);
        assert_eq!(versions[1].version, "v1.0.0");
        assert!(!versions[1].is_pseudo);
        assert!(versions[2].is_pseudo);
    }

    #[test]
    fn test_parse_version_list_empty() {
        let data = b"";
        let versions = parse_version_list(data).unwrap();
        assert_eq!(versions.len(), 0);
    }

    #[test]
    fn test_parse_version_list_blank_lines() {
        let data = b"\n\n\n";
        let versions = parse_version_list(data).unwrap();
        assert_eq!(versions.len(), 0);
    }

    #[test]
    fn test_parse_version_info() {
        let json = r#"{"Version":"v1.9.1","Time":"2023-07-18T14:30:00Z"}"#;
        let version = parse_version_info("github.com/gin-gonic/gin", json.as_bytes()).unwrap();
        assert_eq!(version.version, "v1.9.1");
        assert_eq!(
            version.published_at,
            deps_core::PublishTime::parse_rfc3339("2023-07-18T14:30:00Z")
        );
        assert!(!version.is_pseudo);
    }

    #[test]
    fn test_parse_version_info_with_malformed_time() {
        let json = r#"{"Version":"v1.9.1","Time":"not-a-timestamp"}"#;
        let version = parse_version_info("github.com/gin-gonic/gin", json.as_bytes()).unwrap();
        assert!(
            version.published_at.is_none(),
            "malformed Time degrades to None, not an error"
        );
    }

    #[test]
    fn test_parse_version_info_pseudo() {
        let json =
            r#"{"Version":"v0.0.0-20191109021931-daa7c04131f5","Time":"2019-11-09T02:19:31Z"}"#;
        let version = parse_version_info("github.com/gin-gonic/gin", json.as_bytes()).unwrap();
        assert_eq!(version.version, "v0.0.0-20191109021931-daa7c04131f5");
        assert!(version.is_pseudo);
    }

    #[test]
    fn test_parse_version_info_invalid_json() {
        let json = b"not json";
        let result = parse_version_info("github.com/gin-gonic/gin", json);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_version_info_nesting_at_max_depth_accepted() {
        let depth = deps_core::MAX_JSON_NESTING_DEPTH;
        let json = format!(
            r#"{{"Version": "v1.0.0", "Time": "2024-01-01T00:00:00Z", "extra": {}1{}}}"#,
            "[".repeat(depth - 1),
            "]".repeat(depth - 1)
        );
        assert!(parse_version_info("github.com/gin-gonic/gin", json.as_bytes()).is_ok());
    }

    #[test]
    fn test_parse_version_info_nesting_over_max_depth_rejected() {
        let depth = deps_core::MAX_JSON_NESTING_DEPTH + 1;
        let json = format!(
            r#"{{"Version": "v1.0.0", "Time": "2024-01-01T00:00:00Z", "extra": {}1{}}}"#,
            "[".repeat(depth),
            "]".repeat(depth)
        );
        assert!(parse_version_info("github.com/gin-gonic/gin", json.as_bytes()).is_err());
    }

    #[test]
    fn test_not_found_or_maps_404_to_package_not_found() {
        let err = DepsError::HttpStatus {
            url: "https://proxy.golang.org/github.com/x/y/@v/list".into(),
            status: 404,
        };
        let result = not_found_or(err, "github.com/x/y");
        assert!(matches!(
            result,
            DepsError::PackageNotFound { package, registry }
                if package == "github.com/x/y" && registry == REGISTRY
        ));
    }

    #[test]
    fn test_not_found_or_passes_through_non_404() {
        let err = DepsError::HttpStatus {
            url: "https://proxy.golang.org/github.com/x/y/@v/list".into(),
            status: 500,
        };
        let result = not_found_or(err, "github.com/x/y");
        assert!(matches!(result, DepsError::HttpStatus { status: 500, .. }));
    }

    /// C1: a `410 Gone` response (Athens/Artifactory/Nexus/GitLab's not-found status) maps to
    /// `PackageNotFound` exactly like `404`, so FR-005's chain fallback fires for it too.
    #[test]
    fn test_not_found_or_maps_410_to_package_not_found() {
        let err = DepsError::HttpStatus {
            url: "https://goproxy.mycorp.example/github.com/x/y/@v/list".into(),
            status: 410,
        };
        let result = not_found_or(err, "github.com/x/y");
        assert!(matches!(
            result,
            DepsError::PackageNotFound { package, registry }
                if package == "github.com/x/y" && registry == REGISTRY
        ));
    }

    #[test]
    fn test_package_url() {
        assert_eq!(
            package_url("github.com/gin-gonic/gin"),
            "https://pkg.go.dev/github.com/gin-gonic/gin"
        );
        assert_eq!(
            package_url("golang.org/x/crypto"),
            "https://pkg.go.dev/golang.org/x/crypto"
        );
    }

    #[test]
    fn test_package_url_encodes_malicious_chars() {
        let url = package_url("github.com/evil](https://evil.example)[pkg");
        assert!(!url.contains('('));
        assert!(!url.contains(')'));
        assert!(!url.contains('['));
        assert!(!url.contains(']'));
        assert!(
            url.contains("github.com/evil"),
            "legitimate path preserved: {url}"
        );
    }

    #[test]
    fn test_package_url_encodes_newline_autolink_and_percent() {
        let url = package_url("github.com/evil\n<https://evil%zz.example>");
        assert!(!url.contains('\n'));
        assert!(!url.contains('<'));
        assert!(!url.contains('>'));
        assert!(url.contains("%25"));
    }

    #[test]
    fn test_package_url_empty_module_path() {
        assert_eq!(package_url(""), "https://pkg.go.dev/");
    }

    /// Exercises `version_url` — the exact helper `get_version_info`/`get_go_mod` call —
    /// with a legitimate version, proving no regression: the URL is the expected literal
    /// string, not just "doesn't panic". Binds the guard to the production sink: deleting
    /// escaping from `version_url` would fail this test.
    #[test]
    fn test_info_url_construction_legitimate_version() {
        let url = version_url_at(PROXY_BASE, "github.com/gin-gonic/gin", "v1.9.1", "info");
        assert_eq!(
            url,
            "https://proxy.golang.org/github.com/gin-gonic/gin/@v/v1.9.1.info"
        );
    }

    /// Same as above for a pseudo-version, which carries a `-` and digits only — must
    /// also pass through unescaped.
    #[test]
    fn test_info_url_construction_pseudo_version() {
        let url = version_url_at(
            PROXY_BASE,
            "github.com/user/repo",
            "v0.0.0-20210101000000-abcdef123456",
            "info",
        );
        assert_eq!(
            url,
            "https://proxy.golang.org/github.com/user/repo/@v/v0.0.0-20210101000000-abcdef123456.info"
        );
    }

    /// #377 regression guard: a version string carrying `?`/`#`/space (which
    /// `validate_version_string` does NOT reject — only `..`, `/`, `\` are rejected) must
    /// not be able to inject a query string or fragment into the `.info` URL. Calls
    /// `version_url` directly (the same helper `get_version_info` calls) rather than
    /// duplicating its `format!` logic, so removing the escaping from the production sink
    /// fails this test.
    #[test]
    fn test_info_url_construction_rejects_query_and_fragment_injection() {
        let cases = [
            ("v1?a=b", "v1%3Fa%3Db"),
            ("v1#frag", "v1%23frag"),
            ("v1 x", "v1%20x"),
            ("v1&x=y", "v1%26x%3Dy"),
        ];

        for (raw_version, expected_escaped) in cases {
            let url = version_url_at(PROXY_BASE, "github.com/gin-gonic/gin", raw_version, "info");
            let expected_url = format!(
                "https://proxy.golang.org/github.com/gin-gonic/gin/@v/{expected_escaped}.info"
            );
            assert_eq!(url, expected_url, "raw version: {raw_version:?}");

            // The base URL up to the module path is fixed and query/fragment-free;
            // everything after MUST stay within the path component.
            let after_base = url
                .strip_prefix("https://proxy.golang.org/")
                .expect("URL must start with the proxy base");
            assert!(
                !after_base.contains('?'),
                "constructed URL must not contain a bare '?' for input {raw_version:?}: {url}"
            );
            assert!(
                !after_base.contains('#'),
                "constructed URL must not contain a bare '#' for input {raw_version:?}: {url}"
            );
            assert!(
                !after_base.contains(' '),
                "constructed URL must not contain a raw space for input {raw_version:?}: {url}"
            );
        }
    }

    /// Same construction proof for `get_go_mod`'s `.mod` URL via `version_url`.
    #[test]
    fn test_mod_url_construction_legitimate_version() {
        let url = version_url_at(PROXY_BASE, "github.com/gin-gonic/gin", "v1.9.1", "mod");
        assert_eq!(
            url,
            "https://proxy.golang.org/github.com/gin-gonic/gin/@v/v1.9.1.mod"
        );
    }

    /// #377 regression guard for the `.mod` endpoint — same injection proof as
    /// `test_info_url_construction_rejects_query_and_fragment_injection`, mirroring
    /// `get_go_mod`'s URL construction instead of `get_version_info`'s.
    #[test]
    fn test_mod_url_construction_rejects_query_and_fragment_injection() {
        let cases = [
            ("v1?a=b", "v1%3Fa%3Db"),
            ("v1#frag", "v1%23frag"),
            ("v1 x", "v1%20x"),
        ];

        for (raw_version, expected_escaped) in cases {
            let url = version_url_at(PROXY_BASE, "github.com/gin-gonic/gin", raw_version, "mod");
            let expected_url = format!(
                "https://proxy.golang.org/github.com/gin-gonic/gin/@v/{expected_escaped}.mod"
            );
            assert_eq!(url, expected_url, "raw version: {raw_version:?}");

            let after_base = url
                .strip_prefix("https://proxy.golang.org/")
                .expect("URL must start with the proxy base");
            assert!(!after_base.contains('?'), "raw version: {raw_version:?}");
            assert!(!after_base.contains('#'), "raw version: {raw_version:?}");
        }
    }

    /// #377 S1 regression guard: `version_url` must case-fold uppercase in the version
    /// segment the same way `escape_module_path` folds module paths — a raw uppercase
    /// segment 404s against the real proxy (live-verified during review).
    #[test]
    fn test_info_url_construction_case_folds_uppercase_version() {
        let url = version_url_at(PROXY_BASE, "github.com/user/repo", "v1.7.0-RC", "info");
        assert_eq!(
            url,
            "https://proxy.golang.org/github.com/user/repo/@v/v1.7.0-!r!c.info"
        );
    }

    #[tokio::test]
    async fn test_registry_creation() {
        let cache = Arc::new(HttpCache::new());
        let _registry = GoRegistry::new(cache);
    }

    /// #365 end-to-end coverage (critic S2): exercises the real production
    /// `get_versions` — not a reimplemented gate+sink pair — proving the gate is actually
    /// wired into the call path a real completion/hover/diagnostic request would take. No
    /// mock is needed: the gate must reject before any network request is issued.
    /// The dot-segment gate rejects with `DepsError::InvalidVersionReq`, not
    /// `PackageNotFound` — this crate's existing not-found mapping is unrelated to the
    /// dot-segment gate and is left unchanged.
    #[tokio::test]
    async fn test_get_versions_rejects_bare_dot_dot_segment() {
        let registry = GoRegistry::new(Arc::new(HttpCache::new()));
        let err = registry
            .get_versions("github.com/user/..")
            .await
            .unwrap_err();
        assert!(matches!(err, DepsError::InvalidVersionReq(_)));
    }

    #[tokio::test]
    async fn test_registry_clone() {
        let cache = Arc::new(HttpCache::new());
        let registry = GoRegistry::new(cache);
        let _cloned = registry;
    }

    #[tokio::test]
    #[ignore]
    async fn test_fetch_real_gin_versions() {
        let cache = Arc::new(HttpCache::new());
        let registry = GoRegistry::new(cache);
        let versions = registry
            .get_versions("github.com/gin-gonic/gin")
            .await
            .unwrap();

        assert!(!versions.is_empty());
        assert!(
            versions
                .iter()
                .any(|v| v.version.as_str().starts_with("v1."))
        );
    }

    #[tokio::test]
    #[ignore]
    async fn test_fetch_real_version_info() {
        let cache = Arc::new(HttpCache::new());
        let registry = GoRegistry::new(cache);
        let info = registry
            .get_version_info("github.com/gin-gonic/gin", "v1.9.1")
            .await
            .unwrap();

        assert_eq!(info.version, "v1.9.1");
        assert!(info.published_at.is_some());
    }

    #[tokio::test]
    #[ignore]
    async fn test_fetch_real_latest() {
        let cache = Arc::new(HttpCache::new());
        let registry = GoRegistry::new(cache);
        let latest = registry
            .get_latest("github.com/gin-gonic/gin")
            .await
            .unwrap();

        assert!(latest.version.as_str().starts_with('v'));
        assert!(!latest.is_pseudo);
    }

    #[tokio::test]
    #[ignore]
    async fn test_fetch_real_go_mod() {
        let cache = Arc::new(HttpCache::new());
        let registry = GoRegistry::new(cache);
        let go_mod = registry
            .get_go_mod("github.com/gin-gonic/gin", "v1.9.1")
            .await
            .unwrap();

        assert!(go_mod.contains("module github.com/gin-gonic/gin"));
    }

    #[tokio::test]
    #[ignore]
    async fn test_module_not_found() {
        let cache = Arc::new(HttpCache::new());
        let registry = GoRegistry::new(cache);
        let result = registry
            .get_versions("github.com/nonexistent/module12345")
            .await;
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_version_list_mixed_stable_and_pseudo() {
        let data = b"v1.0.0\nv1.1.0-0.20200101000000-abcdefabcdef\nv1.2.0\nv1.2.1-beta.1\n";
        let versions = parse_version_list(data).unwrap();
        assert_eq!(versions.len(), 4);
        // Sorted descending: v1.2.1-beta.1, v1.2.0, v1.1.0-0...(pseudo), v1.0.0
        assert_eq!(versions[0].version, "v1.2.1-beta.1");
        assert!(!versions[0].is_pseudo); // prerelease, not pseudo
        assert_eq!(versions[1].version, "v1.2.0");
        assert!(!versions[1].is_pseudo);
        assert!(versions[2].is_pseudo); // pseudo-version based on v1.1.0
        assert_eq!(versions[3].version, "v1.0.0");
        assert!(!versions[3].is_pseudo);
    }

    #[test]
    fn test_parse_version_list_invalid_utf8() {
        let data = &[0xFF, 0xFE, 0xFD]; // Invalid UTF-8
        let result = parse_version_list(data);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_version_info_missing_fields() {
        let json = r#"{"Version":"v1.0.0"}"#; // Missing Time field
        let result = parse_version_info("github.com/gin-gonic/gin", json.as_bytes());
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_module_path_empty() {
        let result = validate_module_path("");
        match result {
            Err(DepsError::InvalidVersionReq(msg)) => assert_eq!(msg, "module path is empty"),
            other => panic!("expected InvalidVersionReq, got {other:?}"),
        }
    }

    #[test]
    fn test_validate_module_path_too_long() {
        let long_path = "a".repeat(MAX_MODULE_PATH_LENGTH + 1);
        let result = validate_module_path(&long_path);
        assert!(result.is_err());
        assert!(matches!(result, Err(DepsError::InvalidVersionReq(_))));
    }

    #[test]
    fn test_validate_module_path_valid() {
        let result = validate_module_path("github.com/user/repo");
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_module_path_rejects_bare_dot_dot_segment() {
        let result = validate_module_path("github.com/user/..");
        assert!(result.is_err());
        assert!(matches!(result, Err(DepsError::InvalidVersionReq(_))));
    }

    #[test]
    fn test_validate_module_path_rejects_bare_dot_segment() {
        let result = validate_module_path("./evil");
        assert!(result.is_err());
        assert!(matches!(result, Err(DepsError::InvalidVersionReq(_))));
    }

    #[test]
    fn test_validate_module_path_accepts_dots_within_a_segment() {
        // A dot inside a segment (a real Go module path, e.g. a domain component) is not a
        // dot-segment and must stay valid.
        assert!(validate_module_path("golang.org/x/mod").is_ok());
    }

    /// Demonstrates the vulnerability the `validate_module_path` dot-segment check exists
    /// to prevent: `versions_list_url` alone (with no caller-side guard) builds a URL that,
    /// once parsed, has escaped the module path segment entirely.
    #[test]
    fn test_versions_list_url_bare_dot_dot_normalizes_above_proxy_root() {
        let url = versions_list_url_at(PROXY_BASE, "..");
        let parsed = url::Url::parse(&url).unwrap();
        assert_eq!(parsed.path(), "/@v/list", "parsed path: {}", parsed.path());
    }

    /// #365 regression sweep: exercises the real production pair (`validate_module_path`
    /// gate + `versions_list_url` sink) against the shared adversarial input set, guarding
    /// against a 6th recurrence of the dot-segment defect class in this crate.
    #[test]
    fn test_versions_list_url_dot_segment_sweep() {
        deps_core::test_util::assert_dot_segment_gated_or_contained(
            |seg| {
                validate_module_path(seg)
                    .ok()
                    .map(|()| versions_list_url_at(PROXY_BASE, seg))
            },
            "proxy.golang.org",
            "/",
        );
    }

    #[test]
    fn test_validate_version_string_empty() {
        let result = validate_version_string("");
        match result {
            Err(DepsError::InvalidVersionReq(msg)) => assert_eq!(msg, "version string is empty"),
            other => panic!("expected InvalidVersionReq, got {other:?}"),
        }
    }

    #[test]
    fn test_validate_version_string_too_long() {
        let long_version = "v".to_string() + &"1".repeat(MAX_VERSION_LENGTH);
        let result = validate_version_string(&long_version);
        assert!(result.is_err());
        assert!(matches!(result, Err(DepsError::InvalidVersionReq(_))));
    }

    #[test]
    fn test_validate_version_string_path_traversal() {
        let result = validate_version_string("v1.0.0/../etc/passwd");
        assert!(result.is_err());
        assert!(matches!(result, Err(DepsError::InvalidVersionReq(_))));
    }

    #[test]
    fn test_validate_version_string_slashes() {
        let result = validate_version_string("v1.0.0/malicious");
        assert!(result.is_err());

        let result = validate_version_string("v1.0.0\\malicious");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_version_string_valid() {
        let result = validate_version_string("v1.0.0");
        assert!(result.is_ok());

        let result = validate_version_string("v0.0.0-20191109021931-daa7c04131f5");
        assert!(result.is_ok());
    }

    /// S8 regression guard: `select_latest_matching`'s pure pick must agree with
    /// `get_latest_matching`'s `/@v/list` fallback branch (the `/@latest` fast path is
    /// unreachable from `select_latest_matching`, which is pure and has no I/O) for an
    /// ordinary, non-empty version list — the exact class of divergence Maven's S3/S7 hit.
    #[test]
    fn test_select_latest_matching_agrees_with_get_latest_matching_list_fallback() {
        use deps_core::{Registry, VersionReq};

        let cache = Arc::new(HttpCache::new());
        let registry = GoRegistry::new(cache);
        let typed = vec![
            GoVersion {
                version: "v2.0.0-pseudo".into(),
                published_at: None,
                is_pseudo: true,
                retracted: false,
            },
            GoVersion {
                version: "v1.5.0".into(),
                published_at: None,
                is_pseudo: false,
                retracted: true,
            },
            GoVersion {
                version: "v1.0.0".into(),
                published_at: None,
                is_pseudo: false,
                retracted: false,
            },
        ];

        // Mirrors get_latest_matching's `/@v/list` fallback branch exactly.
        let fallback_pick = typed
            .iter()
            .find(|v| !v.is_pseudo && !v.retracted)
            .map(|v| v.version.to_string());

        let boxed: Vec<Box<dyn deps_core::Version>> = typed
            .into_iter()
            .map(|v| Box::new(v) as Box<dyn deps_core::Version>)
            .collect();
        let idx = registry
            .select_latest_matching(&boxed, &VersionReq::new("*"))
            .expect("non-empty list must select an index");

        assert_eq!(Some(boxed[idx].version_string().to_string()), fallback_pick);
        assert_eq!(fallback_pick.as_deref(), Some("v1.0.0"));
    }

    #[test]
    fn test_select_latest_matching_not_default_none() {
        use deps_core::{Registry, VersionReq};

        let cache = Arc::new(HttpCache::new());
        let registry = GoRegistry::new(cache);
        let versions: Vec<Box<dyn deps_core::Version>> = vec![
            Box::new(GoVersion {
                version: "v2.0.0".into(),
                published_at: None,
                is_pseudo: false,
                retracted: true,
            }),
            Box::new(GoVersion {
                version: "v1.0.0".into(),
                published_at: None,
                is_pseudo: false,
                retracted: false,
            }),
        ];
        let req = VersionReq::new("*");
        assert_eq!(registry.select_latest_matching(&versions, &req), Some(1));
    }

    /// #364 regression guard: Go deliberately does NOT adopt the shared existence-check
    /// ladder's rung 3 (`deps_core::select_latest_for_existence`'s unconditional "newest
    /// overall" fallback). A non-empty but all-pseudo-version `/@v/list` (every entry
    /// `is_prerelease()`) must still yield `None` here so the fetch loop's `/@latest`
    /// fallback in `lifecycle.rs` keeps firing — adopting rung 3 would return `Some(0)`
    /// unconditionally and short-circuit that fallback, silently returning a pseudo-version
    /// instead of resolving through the more complete `/@latest` endpoint.
    #[test]
    fn test_select_latest_matching_all_prerelease_stays_none_go_opts_out_of_ladder() {
        use deps_core::{Registry, VersionReq};

        let cache = Arc::new(HttpCache::new());
        let registry = GoRegistry::new(cache);
        let versions: Vec<Box<dyn deps_core::Version>> = vec![
            Box::new(GoVersion {
                version: "v0.0.0-20191109021931-daa7c04131f5".into(),
                published_at: None,
                is_pseudo: true,
                retracted: false,
            }),
            Box::new(GoVersion {
                version: "v1.0.0-beta.1".into(),
                published_at: None,
                is_pseudo: false,
                retracted: false,
            }),
        ];
        let req = VersionReq::new("*");
        assert_eq!(
            registry.select_latest_matching(&versions, &req),
            None,
            "Go must not fall through to rung 3; a non-empty all-prerelease list must \
             still yield None so the /@latest fallback fires"
        );
    }

    // --- spec 034: GOPROXY/GOPRIVATE chain routing ---

    use deps_core::net_policy::{RegistryAccessPolicy, WorkspaceRegistryAccess};

    fn all_policy() -> RegistryAccessPolicy {
        RegistryAccessPolicy::new(WorkspaceRegistryAccess::All)
    }

    fn url_hop(raw: &str, policy: &RegistryAccessPolicy) -> GoProxyHop {
        GoProxyHop::Url(GoProxyUrl::new(raw, policy).unwrap())
    }

    #[test]
    fn test_register_chain_and_alternate_client_roundtrip() {
        let cache = Arc::new(HttpCache::new());
        let root = Arc::new(GoRegistry::new(Arc::clone(&cache)));
        let chain = GoProxyChain {
            key: "go-proxy:test".to_string(),
            hops: vec![url_hop("https://goproxy.mycorp.example", &all_policy())],
            ..Default::default()
        };
        GoRegistry::register_chain(&root, &chain);
        assert!(root.alternate_client("go-proxy:test").is_some());
        assert!(root.alternate_client("nonexistent").is_none());
    }

    #[test]
    fn test_register_chain_idempotent() {
        let cache = Arc::new(HttpCache::new());
        let root = Arc::new(GoRegistry::new(Arc::clone(&cache)));
        let chain = GoProxyChain {
            key: "go-proxy:test".to_string(),
            hops: vec![url_hop("https://goproxy.mycorp.example", &all_policy())],
            ..Default::default()
        };
        GoRegistry::register_chain(&root, &chain);
        let first = root.alternate_client("go-proxy:test").unwrap();
        GoRegistry::register_chain(&root, &chain);
        let second = root.alternate_client("go-proxy:test").unwrap();
        assert!(Arc::ptr_eq(&first, &second));
    }

    /// US-001: a registered single-hop chain routes `get_versions_from` there instead of
    /// `proxy.golang.org`.
    #[tokio::test]
    async fn test_get_versions_from_routes_to_registered_alternate() {
        use deps_core::{FreshnessSettings, Registry};

        let mut alt_server = mockito::Server::new_async().await;
        alt_server
            .mock("GET", "/github.com/gin-gonic/gin/@v/list")
            .with_status(200)
            .with_body("v1.9.1\n")
            .create_async()
            .await;

        let cache = Arc::new(HttpCache::new());
        cache.set_registry_policy(WorkspaceRegistryAccess::All);
        let root = Arc::new(GoRegistry::new(Arc::clone(&cache)));
        let policy = all_policy();
        let chain = GoProxyChain {
            key: "go-proxy:test".to_string(),
            hops: vec![url_hop(&alt_server.url(), &policy)],
            ..Default::default()
        };
        GoRegistry::register_chain(&root, &chain);

        let source = DependencySource::AlternateRegistry {
            index: "go-proxy:test".to_string(),
            mirrors_crates_io: false,
        };
        let versions = root
            .get_versions_from(
                &deps_core::PackageName::new("github.com/gin-gonic/gin"),
                &source,
                FreshnessSettings::default(),
            )
            .await
            .unwrap();
        assert_eq!(versions.len(), 1);
    }

    /// FR-005: a module absent from hop 0 (explicit not-found) falls through to hop 1.
    #[tokio::test]
    async fn test_get_versions_from_falls_through_on_not_found() {
        use deps_core::{FreshnessSettings, Registry};

        let mut hop0 = mockito::Server::new_async().await;
        hop0.mock("GET", mockito::Matcher::Any)
            .with_status(404)
            .create_async()
            .await;
        let mut hop1 = mockito::Server::new_async().await;
        hop1.mock("GET", "/github.com/gin-gonic/gin/@v/list")
            .with_status(200)
            .with_body("v1.9.1\n")
            .create_async()
            .await;

        let cache = Arc::new(HttpCache::new());
        cache.set_registry_policy(WorkspaceRegistryAccess::All);
        let root = Arc::new(GoRegistry::new(Arc::clone(&cache)));
        let policy = all_policy();
        let chain = GoProxyChain {
            key: "go-proxy:test".to_string(),
            hops: vec![url_hop(&hop0.url(), &policy), url_hop(&hop1.url(), &policy)],
            ..Default::default()
        };
        GoRegistry::register_chain(&root, &chain);

        let source = DependencySource::AlternateRegistry {
            index: "go-proxy:test".to_string(),
            mirrors_crates_io: false,
        };
        let versions = root
            .get_versions_from(
                &deps_core::PackageName::new("github.com/gin-gonic/gin"),
                &source,
                FreshnessSettings::default(),
            )
            .await
            .unwrap();
        assert_eq!(versions.len(), 1);
    }

    /// C1: a `410 Gone` not-found response (Athens/Artifactory/Nexus/GitLab's shape) falls
    /// through to the next hop exactly like a `404` — the primary GOPROXY chain-fallback
    /// scenario (US-001) against the real-world proxies this feature targets.
    #[tokio::test]
    async fn test_get_versions_from_falls_through_on_410() {
        use deps_core::{FreshnessSettings, Registry};

        let mut hop0 = mockito::Server::new_async().await;
        hop0.mock("GET", mockito::Matcher::Any)
            .with_status(410)
            .create_async()
            .await;
        let mut hop1 = mockito::Server::new_async().await;
        hop1.mock("GET", "/github.com/gin-gonic/gin/@v/list")
            .with_status(200)
            .with_body("v1.9.1\n")
            .create_async()
            .await;

        let cache = Arc::new(HttpCache::new());
        cache.set_registry_policy(WorkspaceRegistryAccess::All);
        let root = Arc::new(GoRegistry::new(Arc::clone(&cache)));
        let policy = all_policy();
        let chain = GoProxyChain {
            key: "go-proxy:test".to_string(),
            hops: vec![url_hop(&hop0.url(), &policy), url_hop(&hop1.url(), &policy)],
            ..Default::default()
        };
        GoRegistry::register_chain(&root, &chain);

        let source = DependencySource::AlternateRegistry {
            index: "go-proxy:test".to_string(),
            mirrors_crates_io: false,
        };
        let versions = root
            .get_versions_from(
                &deps_core::PackageName::new("github.com/gin-gonic/gin"),
                &source,
                FreshnessSettings::default(),
            )
            .await
            .unwrap();
        assert_eq!(versions.len(), 1);
    }

    /// FR-005: a transport failure (5xx) on hop 0 is terminal for the whole chain — never
    /// silently falls through to hop 1.
    #[tokio::test]
    async fn test_get_versions_from_transport_failure_is_terminal() {
        use deps_core::{FreshnessSettings, Registry};

        let mut hop0 = mockito::Server::new_async().await;
        hop0.mock("GET", mockito::Matcher::Any)
            .with_status(500)
            .create_async()
            .await;
        let mut hop1 = mockito::Server::new_async().await;
        let hop1_mock = hop1
            .mock("GET", mockito::Matcher::Any)
            .with_status(200)
            .with_body("v1.9.1\n")
            .expect(0)
            .create_async()
            .await;

        let cache = Arc::new(HttpCache::new());
        cache.set_registry_policy(WorkspaceRegistryAccess::All);
        let root = Arc::new(GoRegistry::new(Arc::clone(&cache)));
        let policy = all_policy();
        let chain = GoProxyChain {
            key: "go-proxy:test".to_string(),
            hops: vec![url_hop(&hop0.url(), &policy), url_hop(&hop1.url(), &policy)],
            ..Default::default()
        };
        GoRegistry::register_chain(&root, &chain);

        let source = DependencySource::AlternateRegistry {
            index: "go-proxy:test".to_string(),
            mirrors_crates_io: false,
        };
        let result = root
            .get_versions_from(
                &deps_core::PackageName::new("github.com/gin-gonic/gin"),
                &source,
                FreshnessSettings::default(),
            )
            .await;
        assert!(matches!(result, Err(DepsError::ChainResolutionHalted)));
        hop1_mock.assert_async().await;
    }

    /// S2: with a `|`-separated chain, a transport failure (5xx) on hop 0 falls through to
    /// hop 1 instead of halting — the opposite of the `,`-separated default tested above.
    #[tokio::test]
    async fn test_pipe_separator_falls_through_on_transport_failure() {
        use deps_core::{FreshnessSettings, Registry};

        let mut hop0 = mockito::Server::new_async().await;
        hop0.mock("GET", mockito::Matcher::Any)
            .with_status(500)
            .create_async()
            .await;
        let mut hop1 = mockito::Server::new_async().await;
        hop1.mock("GET", "/github.com/gin-gonic/gin/@v/list")
            .with_status(200)
            .with_body("v1.9.1\n")
            .create_async()
            .await;

        let cache = Arc::new(HttpCache::new());
        cache.set_registry_policy(WorkspaceRegistryAccess::All);
        let root = Arc::new(GoRegistry::new(Arc::clone(&cache)));
        let policy = all_policy();
        let chain = GoProxyChain {
            key: "go-proxy:test".to_string(),
            hops: vec![url_hop(&hop0.url(), &policy), url_hop(&hop1.url(), &policy)],
            separators: vec![ChainSeparator::AnyError],
        };
        GoRegistry::register_chain(&root, &chain);

        let source = DependencySource::AlternateRegistry {
            index: "go-proxy:test".to_string(),
            mirrors_crates_io: false,
        };
        let versions = root
            .get_versions_from(
                &deps_core::PackageName::new("github.com/gin-gonic/gin"),
                &source,
                FreshnessSettings::default(),
            )
            .await
            .unwrap();
        assert_eq!(versions.len(), 1);
    }

    /// S3: a chain hop whose `/@v/list` is empty (an untagged/pseudo-version-only module, the
    /// same class of module #364 added the `/@latest` fallback for on the public path) still
    /// yields version data via `/@latest`, instead of silently losing it.
    #[tokio::test]
    async fn test_chain_hop_falls_back_to_latest_when_list_is_empty() {
        use deps_core::{FreshnessSettings, Registry};

        let mut hop = mockito::Server::new_async().await;
        hop.mock("GET", "/github.com/gin-gonic/gin/@latest")
            .with_status(200)
            .with_body(
                r#"{"Version":"v0.0.0-20191109021931-daa7c04131f5","Time":"2019-11-09T02:19:31Z"}"#,
            )
            .create_async()
            .await;
        hop.mock("GET", "/github.com/gin-gonic/gin/@v/list")
            .with_status(200)
            .with_body("")
            .create_async()
            .await;

        let cache = Arc::new(HttpCache::new());
        cache.set_registry_policy(WorkspaceRegistryAccess::All);
        let root = Arc::new(GoRegistry::new(Arc::clone(&cache)));
        let policy = all_policy();
        let chain = GoProxyChain {
            key: "go-proxy:test".to_string(),
            hops: vec![url_hop(&hop.url(), &policy)],
            ..Default::default()
        };
        GoRegistry::register_chain(&root, &chain);

        let source = DependencySource::AlternateRegistry {
            index: "go-proxy:test".to_string(),
            mirrors_crates_io: false,
        };
        let versions = root
            .get_versions_from(
                &deps_core::PackageName::new("github.com/gin-gonic/gin"),
                &source,
                FreshnessSettings::default(),
            )
            .await
            .unwrap();
        assert_eq!(versions.len(), 1);
        assert!(
            versions[0].is_prerelease(),
            "expected the pseudo-version from /@latest"
        );
    }

    /// US-003/FR-006: falling through past every proxy hop to a `direct` terminal hop shows
    /// no data, with zero requests for that hop.
    #[tokio::test]
    async fn test_direct_terminal_hop_shows_no_data_zero_requests() {
        use deps_core::{FreshnessSettings, Registry};

        let mut hop0 = mockito::Server::new_async().await;
        hop0.mock("GET", mockito::Matcher::Any)
            .with_status(404)
            .create_async()
            .await;

        let cache = Arc::new(HttpCache::new());
        cache.set_registry_policy(WorkspaceRegistryAccess::All);
        let root = Arc::new(GoRegistry::new(Arc::clone(&cache)));
        let policy = all_policy();
        let chain = GoProxyChain {
            key: "go-proxy:test".to_string(),
            hops: vec![url_hop(&hop0.url(), &policy), GoProxyHop::Direct],
            ..Default::default()
        };
        GoRegistry::register_chain(&root, &chain);

        let source = DependencySource::AlternateRegistry {
            index: "go-proxy:test".to_string(),
            mirrors_crates_io: false,
        };
        let result = root
            .get_versions_from(
                &deps_core::PackageName::new("github.com/gin-gonic/gin"),
                &source,
                FreshnessSettings::default(),
            )
            .await;
        assert!(matches!(result, Err(DepsError::PackageNotFound { .. })));
    }

    /// SC-002 (issue #559 follow-up): a `GOPRIVATE`-matched module's resolved source routes
    /// to the bypass chain *and* the registered `GOPROXY` chain never receives a request for
    /// it — combined into one resolution call, where previously each half was proven by a
    /// separate unit test.
    #[tokio::test]
    async fn test_goprivate_bypass_sends_zero_requests_to_goproxy() {
        use deps_core::{FreshnessSettings, Registry};

        let mut public_proxy = mockito::Server::new_async().await;
        let public_mock = public_proxy
            .mock("GET", mockito::Matcher::Any)
            .with_status(200)
            .with_body("v1.9.1\n")
            .expect(0)
            .create_async()
            .await;

        let content = format!(
            "GOPROXY={},direct\nGOPRIVATE=git.mycorp.example/*\n",
            public_proxy.url()
        );
        let policy = all_policy();
        let go_config = crate::config::GoEnvConfig::parse(&content, &policy);
        let source = go_config.resolve_source_for("git.mycorp.example/internal/auth");
        assert_eq!(
            source,
            DependencySource::AlternateRegistry {
                index: crate::config::GOPRIVATE_CHAIN_KEY.to_string(),
                mirrors_crates_io: false,
            }
        );

        let cache = Arc::new(HttpCache::new());
        cache.set_registry_policy(WorkspaceRegistryAccess::All);
        let root = Arc::new(GoRegistry::new(Arc::clone(&cache)));
        for chain in go_config.resolved_chains() {
            GoRegistry::register_chain(&root, &chain);
        }

        let result = root
            .get_versions_from(
                &deps_core::PackageName::new("git.mycorp.example/internal/auth"),
                &source,
                FreshnessSettings::default(),
            )
            .await;
        assert!(matches!(result, Err(DepsError::PackageNotFound { .. })));
        public_mock.assert_async().await;
    }

    /// US-004: `GOPROXY=off` shows no data and issues zero requests.
    #[tokio::test]
    async fn test_off_hop_zero_requests() {
        use deps_core::{FreshnessSettings, Registry};

        let cache = Arc::new(HttpCache::new());
        let root = Arc::new(GoRegistry::new(Arc::clone(&cache)));
        let chain = GoProxyChain {
            key: "go-proxy:off".to_string(),
            hops: vec![GoProxyHop::Off],
            ..Default::default()
        };
        GoRegistry::register_chain(&root, &chain);

        let source = DependencySource::AlternateRegistry {
            index: "go-proxy:off".to_string(),
            mirrors_crates_io: false,
        };
        let result = root
            .get_versions_from(
                &deps_core::PackageName::new("github.com/gin-gonic/gin"),
                &source,
                FreshnessSettings::default(),
            )
            .await;
        assert!(matches!(result, Err(DepsError::PackageNotFound { .. })));
    }

    /// An `AlternateRegistry` source whose index has no registered client is
    /// `PackageNotFound`, never resolved by falling through to the plain public-registry
    /// path.
    #[tokio::test]
    async fn test_unregistered_alternate_never_falls_back_to_public() {
        use deps_core::{FreshnessSettings, Registry};

        let cache = Arc::new(HttpCache::new());
        let root = Arc::new(GoRegistry::new(cache));
        let source = DependencySource::AlternateRegistry {
            index: "never-registered".to_string(),
            mirrors_crates_io: false,
        };
        let result = root
            .get_versions_from(
                &deps_core::PackageName::new("github.com/gin-gonic/gin"),
                &source,
                FreshnessSettings::default(),
            )
            .await;
        assert!(matches!(
            result,
            Err(DepsError::PackageNotFound {
                registry: "alternate registry (not registered)",
                ..
            })
        ));
    }

    /// FR-013: `get_latest_matching_from` routes an `AlternateRegistry` source to the
    /// registered chain and picks the matching version.
    #[tokio::test]
    async fn test_get_latest_matching_from_routes_to_alternate() {
        use deps_core::{Registry, VersionReq};

        let mut alt_server = mockito::Server::new_async().await;
        alt_server
            .mock("GET", "/github.com/gin-gonic/gin/@v/list")
            .with_status(200)
            .with_body("v1.9.0\nv1.9.1\n")
            .create_async()
            .await;

        let cache = Arc::new(HttpCache::new());
        cache.set_registry_policy(WorkspaceRegistryAccess::All);
        let root = Arc::new(GoRegistry::new(Arc::clone(&cache)));
        let policy = all_policy();
        let chain = GoProxyChain {
            key: "go-proxy:test".to_string(),
            hops: vec![url_hop(&alt_server.url(), &policy)],
            ..Default::default()
        };
        GoRegistry::register_chain(&root, &chain);

        let source = DependencySource::AlternateRegistry {
            index: "go-proxy:test".to_string(),
            mirrors_crates_io: false,
        };
        let latest = root
            .get_latest_matching_from(
                &deps_core::PackageName::new("github.com/gin-gonic/gin"),
                &source,
                &VersionReq::new("*"),
                None,
            )
            .await
            .unwrap();
        assert!(latest.is_some());
    }

    /// A plain `DependencySource::Registry` source keeps the existing public-registry path
    /// (`/@latest` fast path) unchanged (NFR-005).
    #[tokio::test]
    async fn test_get_versions_from_plain_registry_source_unchanged() {
        use deps_core::{FreshnessSettings, Registry};

        let cache = Arc::new(HttpCache::new());
        let root = GoRegistry::new(cache);
        let result = root
            .get_versions_from(
                &deps_core::PackageName::new("github.com/nonexistent/module12345"),
                &DependencySource::Registry,
                FreshnessSettings::default(),
            )
            .await;
        // No network mock configured — a real request would error, proving this path still
        // goes through the ordinary public fetch rather than being silently no-op'd.
        assert!(result.is_err());
    }

    #[test]
    fn test_alternate_registries_cap_enforced() {
        let cache = Arc::new(HttpCache::new());
        let root = Arc::new(GoRegistry::new(cache));
        let policy = all_policy();
        for i in 0..MAX_ALTERNATE_REGISTRIES {
            let chain = GoProxyChain {
                key: format!("go-proxy:cap-{i}"),
                hops: vec![url_hop("https://goproxy.mycorp.example", &policy)],
                ..Default::default()
            };
            GoRegistry::register_chain(&root, &chain);
        }
        assert_eq!(root.alternates.len(), MAX_ALTERNATE_REGISTRIES);

        let overflow = GoProxyChain {
            key: "go-proxy:overflow".to_string(),
            hops: vec![url_hop("https://goproxy.mycorp.example", &policy)],
            ..Default::default()
        };
        GoRegistry::register_chain(&root, &overflow);
        assert_eq!(root.alternates.len(), MAX_ALTERNATE_REGISTRIES);
        assert!(root.alternate_client("go-proxy:overflow").is_none());
    }
}
