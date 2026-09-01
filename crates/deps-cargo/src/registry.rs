//! crates.io registry client, and the [`CargoRegistry`] router dispatching a resolved
//! alternate/private registry to its own [`crate::sparse::SparseIndexClient`].
//!
//! Provides access to crates.io via:
//! - Sparse index protocol (<https://index.crates.io>) for version lookups
//! - REST API (<https://crates.io/api/v1>) for search
//!
//! All HTTP requests are cached aggressively using ETag/Last-Modified headers.
//!
//! # Examples
//!
//! ```no_run
//! use deps_cargo::CratesIoRegistry;
//! use deps_core::HttpCache;
//! use std::sync::Arc;
//!
//! #[tokio::main]
//! async fn main() {
//!     let cache = Arc::new(HttpCache::new());
//!     let registry = CratesIoRegistry::new(cache);
//!
//!     let versions = registry.get_versions("serde").await.unwrap();
//!     println!("Latest serde: {}", versions[0].num);
//! }
//! ```

use crate::config::{AuthToken, RegistryIndex};
use crate::sparse::SparseIndexClient;
use crate::types::{CargoVersion, CrateInfo};
use deps_core::parser::DependencySource;
use deps_core::{DepsError, HttpCache, PackageName, Result};
use semver::{Version, VersionReq};
use serde::Deserialize;
use std::any::Any;
use std::sync::Arc;

const SPARSE_INDEX_BASE: &str = "https://index.crates.io";
const SEARCH_API_BASE: &str = "https://crates.io/api/v1";

/// Display name for crates.io used in not-found and API-response error messages.
pub const REGISTRY: &str = "crates.io";

/// Base URL for crate pages on crates.io
pub const CRATES_IO_URL: &str = "https://crates.io/crates";

/// Returns the URL for a crate's page on crates.io.
///
/// Display link only, never fetched by this process — unlike the sparse-index
/// registry-fetch URL (`sparse_index_path`), so it is deliberately not gated against a
/// `.`/`..` name (see [`deps_core::is_dot_segment`]'s doc for the fetch-sink-vs-display-link
/// scope split, #379).
pub fn crate_url(name: &str) -> String {
    format!("{CRATES_IO_URL}/{}", urlencoding::encode(name))
}

/// Client for interacting with crates.io registry.
///
/// Uses the sparse index protocol for fast version lookups (via [`SparseIndexClient`]) and
/// the REST API for package search. All requests are cached via the provided HttpCache.
#[derive(Clone)]
pub struct CratesIoRegistry {
    sparse: SparseIndexClient,
    cache: Arc<HttpCache>,
}

impl CratesIoRegistry {
    /// Creates a new registry client with the given HTTP cache.
    pub fn new(cache: Arc<HttpCache>) -> Self {
        Self {
            sparse: SparseIndexClient::new(SPARSE_INDEX_BASE.to_string(), Arc::clone(&cache)),
            cache,
        }
    }

    /// Fetches all versions for a crate from the sparse index.
    ///
    /// Returns versions sorted newest-first. Includes yanked versions.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - HTTP request fails
    /// - Response body is invalid UTF-8
    /// - JSON parsing fails
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use deps_cargo::CratesIoRegistry;
    /// # use deps_core::HttpCache;
    /// # use std::sync::Arc;
    /// # #[tokio::main]
    /// # async fn main() {
    /// let cache = Arc::new(HttpCache::new());
    /// let registry = CratesIoRegistry::new(cache);
    ///
    /// let versions = registry.get_versions("serde").await.unwrap();
    /// assert!(!versions.is_empty());
    /// # }
    /// ```
    pub async fn get_versions(&self, name: &str) -> Result<Vec<CargoVersion>> {
        self.sparse.get_versions(name).await
    }

    /// Finds the latest version matching the given semver requirement.
    ///
    /// Only returns non-yanked versions.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Version requirement string is invalid semver
    /// - HTTP request fails
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use deps_cargo::CratesIoRegistry;
    /// # use deps_core::HttpCache;
    /// # use std::sync::Arc;
    /// # #[tokio::main]
    /// # async fn main() {
    /// let cache = Arc::new(HttpCache::new());
    /// let registry = CratesIoRegistry::new(cache);
    ///
    /// let latest = registry.get_latest_matching("serde", "^1.0").await.unwrap();
    /// assert!(latest.is_some());
    /// # }
    /// ```
    pub async fn get_latest_matching(
        &self,
        name: &str,
        req_str: &str,
    ) -> Result<Option<CargoVersion>> {
        self.sparse.get_latest_matching(name, req_str).await
    }

    /// Searches for crates by name/keywords.
    ///
    /// Returns up to `limit` results sorted by relevance.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - HTTP request fails
    /// - JSON parsing fails
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use deps_cargo::CratesIoRegistry;
    /// # use deps_core::HttpCache;
    /// # use std::sync::Arc;
    /// # #[tokio::main]
    /// # async fn main() {
    /// let cache = Arc::new(HttpCache::new());
    /// let registry = CratesIoRegistry::new(cache);
    ///
    /// let results = registry.search("serde", 10).await.unwrap();
    /// assert!(!results.is_empty());
    /// # }
    /// ```
    pub async fn search(&self, query: &str, limit: usize) -> Result<Vec<CrateInfo>> {
        let url = format!(
            "{}/crates?q={}&per_page={}&sort=downloads",
            SEARCH_API_BASE,
            urlencoding::encode(query),
            limit
        );

        let data = self.cache.get_cached(&url).await?;
        parse_search_response(&data)
    }
}

/// Response from crates.io search API.
#[derive(Deserialize)]
struct SearchResponse {
    crates: Vec<SearchCrate>,
}

/// Crate entry in search response.
#[derive(Deserialize)]
struct SearchCrate {
    name: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    repository: Option<String>,
    #[serde(default)]
    documentation: Option<String>,
    max_version: String,
}

/// Parses JSON response from crates.io search API.
fn parse_search_response(data: &[u8]) -> Result<Vec<CrateInfo>> {
    let response: SearchResponse = deps_core::parse_json_checked(data)?;

    Ok(response
        .crates
        .into_iter()
        .map(|c| CrateInfo {
            name: c.name.into(),
            description: c.description,
            repository: c.repository,
            documentation: c.documentation,
            max_version: c.max_version.into(),
        })
        .collect())
}

/// Index-by-position pick of the latest version matching `req`, shared by
/// [`CratesIoRegistry`] and [`CargoRegistry`] (both ultimately backed by the same sparse
/// wire format, so the same `semver`-based selection logic applies regardless of which
/// index served the list).
fn select_latest_matching_impl(
    versions: &[Box<dyn deps_core::Version>],
    req: &deps_core::VersionReq,
) -> Option<usize> {
    if deps_core::is_existence_wildcard(req) {
        return deps_core::select_latest_for_existence(versions, |v| v.as_ref());
    }
    let parsed_req: VersionReq = req.as_str().parse().ok()?;
    versions.iter().position(|v| {
        v.version_string()
            .as_str()
            .parse::<Version>()
            .is_ok_and(|ver| parsed_req.matches(&ver) && !v.removal_status().blocks_resolution())
    })
}

impl deps_core::Registry for CratesIoRegistry {
    fn get_versions<'a>(
        &'a self,
        name: &'a deps_core::PackageName,
    ) -> deps_core::ecosystem::BoxFuture<'a, Result<Vec<Box<dyn deps_core::Version>>>> {
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
        req: &'a deps_core::VersionReq,
    ) -> deps_core::ecosystem::BoxFuture<'a, Result<Option<Box<dyn deps_core::Version>>>> {
        Box::pin(async move {
            let version = self
                .get_latest_matching(name.as_str(), req.as_str())
                .await?;
            Ok(version.map(|v| Box::new(v) as Box<dyn deps_core::Version>))
        })
    }

    fn select_latest_matching(
        &self,
        versions: &[Box<dyn deps_core::Version>],
        req: &deps_core::VersionReq,
    ) -> Option<usize> {
        select_latest_matching_impl(versions, req)
    }

    fn search<'a>(
        &'a self,
        query: &'a str,
        limit: usize,
    ) -> deps_core::ecosystem::BoxFuture<'a, Result<Vec<Box<dyn deps_core::Metadata>>>> {
        Box::pin(async move {
            let results = self.search(query, limit).await?;
            Ok(results
                .into_iter()
                .map(|m| Box::new(m) as Box<dyn deps_core::Metadata>)
                .collect())
        })
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// A [`deps_core::Registry`] implementation over one [`SparseIndexClient`] directly — used
/// for a resolved alternate registry, so completion (which needs a concrete `&dyn Registry`
/// to hand to `deps_core::completion`'s shared generic helpers) can address one specific
/// alternate index without going through [`CargoRegistry`]'s source-based dispatch.
///
/// `search` is always empty: the sparse index protocol has no search endpoint (spec
/// Out-of-Scope), so an alternate registry can never support package-name completion —
/// only crates.io's REST API does.
impl deps_core::Registry for SparseIndexClient {
    fn get_versions<'a>(
        &'a self,
        name: &'a deps_core::PackageName,
    ) -> deps_core::ecosystem::BoxFuture<'a, Result<Vec<Box<dyn deps_core::Version>>>> {
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
        req: &'a deps_core::VersionReq,
    ) -> deps_core::ecosystem::BoxFuture<'a, Result<Option<Box<dyn deps_core::Version>>>> {
        Box::pin(async move {
            let version = self
                .get_latest_matching(name.as_str(), req.as_str())
                .await?;
            Ok(version.map(|v| Box::new(v) as Box<dyn deps_core::Version>))
        })
    }

    fn select_latest_matching(
        &self,
        versions: &[Box<dyn deps_core::Version>],
        req: &deps_core::VersionReq,
    ) -> Option<usize> {
        select_latest_matching_impl(versions, req)
    }

    fn search<'a>(
        &'a self,
        _query: &'a str,
        _limit: usize,
    ) -> deps_core::ecosystem::BoxFuture<'a, Result<Vec<Box<dyn deps_core::Metadata>>>> {
        Box::pin(async move { Ok(Vec::new()) })
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Upper bound on [`CargoRegistry::alternates`]' entry count (spec NFR-007). Generous for
/// any realistic `.cargo/config.toml` registry count; exists only to keep this DashMap,
/// keyed by workspace-controlled URLs, from growing unbounded for the process lifetime.
/// Once at capacity, a *new* index is simply never registered (see
/// [`CargoRegistry::register_alternate`]) rather than evicted — a dependency on an
/// unregistered alternate index degrades to [`DepsError::PackageNotFound`], never to a
/// crates.io lookup by name.
const MAX_ALTERNATE_REGISTRIES: usize = 256;

/// Router in front of crates.io and every resolved alternate/private registry a workspace's
/// `.cargo/config.toml` hierarchy names.
///
/// The value behind `CargoEcosystem::registry` (formerly a bare
/// [`CratesIoRegistry`]). [`deps_core::Registry::get_versions`]/`get_latest_matching`/`search`
/// (the source-blind trait methods) always mean crates.io, matching pre-1a behavior exactly
/// (spec NFR-008); only the source-aware `get_versions_from`/`get_latest_matching_from`
/// entry points route to an alternate index, and only for a
/// [`DependencySource::AlternateRegistry`] source.
///
/// # Examples
///
/// ```no_run
/// use deps_cargo::CargoRegistry;
/// use deps_core::HttpCache;
/// use std::sync::Arc;
///
/// let cache = Arc::new(HttpCache::new());
/// let registry = CargoRegistry::new(cache);
/// ```
pub struct CargoRegistry {
    crates_io: CratesIoRegistry,
    /// Resolved alternate-registry clients, keyed by their validated index URL. Populated
    /// by [`Self::register_alternate`] at parse time (see `crate::ecosystem`'s
    /// `parse_manifest` override) — the *only* place an [`AuthToken`] is ever attached to a
    /// client, since only that call site has the [`crate::config::CargoConfig`] resolution
    /// in hand. A fetch that lands here with an unregistered index (never resolved, or
    /// dropped for capacity) has no way to recover a token and must not fall back to
    /// crates.io — see [`Self::alternate_client`].
    alternates: dashmap::DashMap<RegistryIndex, Arc<SparseIndexClient>>,
    cache: Arc<HttpCache>,
}

impl CargoRegistry {
    /// Creates a new router with the given HTTP cache, backing both crates.io and every
    /// alternate registry client this router later registers.
    pub fn new(cache: Arc<HttpCache>) -> Self {
        Self {
            crates_io: CratesIoRegistry::new(Arc::clone(&cache)),
            alternates: dashmap::DashMap::new(),
            cache,
        }
    }

    /// Registers (or reuses an existing registration for) `index`, with `auth` attached to
    /// every request against it.
    ///
    /// A no-op when `index` is already registered — the first successful registration for
    /// a given index URL sticks for the process lifetime; a later registration attempt
    /// carrying a *different* `auth` for the same already-registered `index` is silently
    /// ignored. This is a known, accepted limitation for a P4-priority feature (see
    /// `ECOSYSTEM_GUIDE.md`): it can only matter if the same index URL is reachable through
    /// two different resolution paths with different tokens across the process's lifetime,
    /// which no current call site does.
    ///
    /// Also a no-op, with a `tracing::warn!`, once `MAX_ALTERNATE_REGISTRIES` is reached
    /// and `index` is not already present (spec NFR-007) — the dependency stays
    /// unregistered rather than evicting an existing, possibly still-in-use, client.
    pub fn register_alternate(&self, index: RegistryIndex, auth: Option<AuthToken>) {
        if self.alternates.contains_key(&index) {
            return;
        }
        if self.alternates.len() >= MAX_ALTERNATE_REGISTRIES {
            tracing::warn!(
                index = %index,
                cap = MAX_ALTERNATE_REGISTRIES,
                "alternate registry cap reached; not registering a new index"
            );
            return;
        }
        let client = Arc::new(SparseIndexClient::with_auth(
            index.as_str().to_string(),
            Arc::clone(&self.cache),
            auth,
            "alternate registry",
        ));
        self.alternates.entry(index).or_insert(client);
    }

    /// The registered client for `index`, if any — read-only, performs no registration.
    ///
    /// Used by completion (`crate::ecosystem::CargoEcosystem::generate_completions`, FR-012)
    /// to address one specific alternate index directly via [`deps_core::Registry`]'s
    /// generic helpers, without going through this router's source-based dispatch.
    #[must_use]
    pub fn alternate_client(&self, index: &str) -> Option<Arc<SparseIndexClient>> {
        let index = RegistryIndex::new(index).ok()?;
        self.alternates.get(&index).map(|entry| Arc::clone(&entry))
    }

    async fn get_versions_for_source(
        &self,
        name: &PackageName,
        source: &DependencySource,
    ) -> Result<Vec<CargoVersion>> {
        match source {
            DependencySource::AlternateRegistry { index } => {
                let client =
                    self.alternate_client(index)
                        .ok_or_else(|| DepsError::PackageNotFound {
                            package: name.to_string(),
                            registry: "alternate registry (not registered)",
                        })?;
                client.get_versions(name.as_str()).await
            }
            _ => self.crates_io.get_versions(name.as_str()).await,
        }
    }

    async fn get_latest_matching_for_source(
        &self,
        name: &PackageName,
        source: &DependencySource,
        req: &deps_core::VersionReq,
    ) -> Result<Option<CargoVersion>> {
        match source {
            DependencySource::AlternateRegistry { index } => {
                let client =
                    self.alternate_client(index)
                        .ok_or_else(|| DepsError::PackageNotFound {
                            package: name.to_string(),
                            registry: "alternate registry (not registered)",
                        })?;
                client
                    .get_latest_matching(name.as_str(), req.as_str())
                    .await
            }
            _ => {
                self.crates_io
                    .get_latest_matching(name.as_str(), req.as_str())
                    .await
            }
        }
    }
}

impl deps_core::Registry for CargoRegistry {
    fn get_versions<'a>(
        &'a self,
        name: &'a PackageName,
    ) -> deps_core::ecosystem::BoxFuture<'a, Result<Vec<Box<dyn deps_core::Version>>>> {
        deps_core::Registry::get_versions(&self.crates_io, name)
    }

    fn get_versions_with<'a>(
        &'a self,
        name: &'a PackageName,
        freshness: deps_core::freshness::FreshnessSettings,
    ) -> deps_core::ecosystem::BoxFuture<'a, Result<Vec<Box<dyn deps_core::Version>>>> {
        deps_core::Registry::get_versions_with(&self.crates_io, name, freshness)
    }

    fn get_versions_from<'a>(
        &'a self,
        name: &'a PackageName,
        source: &'a DependencySource,
        _freshness: deps_core::freshness::FreshnessSettings,
    ) -> deps_core::ecosystem::BoxFuture<'a, Result<Vec<Box<dyn deps_core::Version>>>> {
        Box::pin(async move {
            let versions = self.get_versions_for_source(name, source).await?;
            Ok(versions
                .into_iter()
                .map(|v| Box::new(v) as Box<dyn deps_core::Version>)
                .collect())
        })
    }

    fn get_latest_matching<'a>(
        &'a self,
        name: &'a PackageName,
        req: &'a deps_core::VersionReq,
    ) -> deps_core::ecosystem::BoxFuture<'a, Result<Option<Box<dyn deps_core::Version>>>> {
        deps_core::Registry::get_latest_matching(&self.crates_io, name, req)
    }

    fn get_latest_matching_with_context<'a>(
        &'a self,
        name: &'a PackageName,
        req: &'a deps_core::VersionReq,
        minimum_stability: Option<&'a str>,
    ) -> deps_core::ecosystem::BoxFuture<'a, Result<Option<Box<dyn deps_core::Version>>>> {
        deps_core::Registry::get_latest_matching_with_context(
            &self.crates_io,
            name,
            req,
            minimum_stability,
        )
    }

    fn get_latest_matching_from<'a>(
        &'a self,
        name: &'a PackageName,
        source: &'a DependencySource,
        req: &'a deps_core::VersionReq,
        _minimum_stability: Option<&'a str>,
    ) -> deps_core::ecosystem::BoxFuture<'a, Result<Option<Box<dyn deps_core::Version>>>> {
        Box::pin(async move {
            let version = self
                .get_latest_matching_for_source(name, source, req)
                .await?;
            Ok(version.map(|v| Box::new(v) as Box<dyn deps_core::Version>))
        })
    }

    fn select_latest_matching(
        &self,
        versions: &[Box<dyn deps_core::Version>],
        req: &deps_core::VersionReq,
    ) -> Option<usize> {
        select_latest_matching_impl(versions, req)
    }

    /// Always crates.io — the sparse index protocol has no search endpoint, so this is
    /// unreachable for an alternate source by construction (spec FR-001).
    fn search<'a>(
        &'a self,
        query: &'a str,
        limit: usize,
    ) -> deps_core::ecosystem::BoxFuture<'a, Result<Vec<Box<dyn deps_core::Metadata>>>> {
        deps_core::Registry::search(&self.crates_io, query, limit)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// Live-network smoke test against the real crates.io search API. Restored (review
    /// finding #8) after being dropped, undisclosed, during the `SparseIndexClient`
    /// extraction — `search` stayed on `CratesIoRegistry`, so this test's home is
    /// unchanged from before that refactor. `#[ignore]`d: not run in CI, only on demand.
    #[tokio::test]
    #[ignore]
    async fn test_search_real() {
        let cache = Arc::new(HttpCache::new());
        let registry = CratesIoRegistry::new(cache);
        let results = registry.search("serde", 5).await.unwrap();

        assert!(!results.is_empty());
        assert!(results.iter().any(|r| r.name == "serde"));
    }

    #[test]
    fn test_parse_search_response() {
        let json = r#"{
            "crates": [
                {
                    "name": "serde",
                    "description": "A serialization framework",
                    "repository": "https://github.com/serde-rs/serde",
                    "documentation": "https://docs.rs/serde",
                    "max_version": "1.0.214"
                }
            ]
        }"#;

        let results = parse_search_response(json.as_bytes()).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "serde");
        assert_eq!(results[0].max_version, "1.0.214");
    }

    #[test]
    fn test_parse_search_response_empty() {
        let json = r#"{"crates": []}"#;
        let results = parse_search_response(json.as_bytes()).unwrap();
        assert_eq!(results.len(), 0);
    }

    #[test]
    fn test_parse_search_response_missing_optional_fields() {
        let json = r#"{
            "crates": [
                {
                    "name": "minimal",
                    "max_version": "1.0.0"
                }
            ]
        }"#;

        let results = parse_search_response(json.as_bytes()).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "minimal");
        assert_eq!(results[0].description, None);
        assert_eq!(results[0].repository, None);
    }

    #[test]
    fn test_parse_search_response_nesting_at_max_depth_accepted() {
        let depth = deps_core::MAX_JSON_NESTING_DEPTH;
        let json = format!(
            r#"{{"crates": [], "extra": {}1{}}}"#,
            "[".repeat(depth - 1),
            "]".repeat(depth - 1)
        );
        assert!(parse_search_response(json.as_bytes()).is_ok());
    }

    #[test]
    fn test_parse_search_response_nesting_over_max_depth_rejected() {
        let depth = deps_core::MAX_JSON_NESTING_DEPTH + 1;
        let json = format!(
            r#"{{"crates": [], "extra": {}1{}}}"#,
            "[".repeat(depth),
            "]".repeat(depth)
        );
        assert!(parse_search_response(json.as_bytes()).is_err());
    }

    #[test]
    fn test_crate_url() {
        assert_eq!(crate_url("serde"), "https://crates.io/crates/serde");
        assert_eq!(crate_url("tokio"), "https://crates.io/crates/tokio");
    }

    #[test]
    fn test_crate_url_with_hyphens() {
        assert_eq!(
            crate_url("serde-json"),
            "https://crates.io/crates/serde-json"
        );
    }

    #[test]
    fn test_crate_url_encodes_malicious_name() {
        let url = crate_url("evil](https://evil.example)[pkg");
        assert!(!url.contains('('));
        assert!(!url.contains(')'));
        assert!(!url.contains('['));
        assert!(!url.contains(']'));
    }

    #[test]
    fn test_crate_url_encodes_newline_autolink_and_percent() {
        let url = crate_url("evil\n<https://evil%zz.example>");
        assert!(!url.contains('\n'));
        assert!(!url.contains('<'));
        assert!(!url.contains('>'));
        assert!(url.contains("%25"));
    }

    #[test]
    fn test_crate_url_empty_name() {
        assert_eq!(crate_url(""), "https://crates.io/crates/");
    }

    #[tokio::test]
    async fn test_registry_creation() {
        let cache = Arc::new(HttpCache::new());
        let _registry = CratesIoRegistry::new(cache);
    }

    #[tokio::test]
    async fn test_registry_clone() {
        let cache = Arc::new(HttpCache::new());
        let registry = CratesIoRegistry::new(cache);
        let _cloned = registry;
    }

    #[test]
    fn test_select_latest_matching_not_default_none() {
        use deps_core::{Registry, VersionReq};

        let cache = Arc::new(HttpCache::new());
        let registry = CratesIoRegistry::new(cache);
        let versions: Vec<Box<dyn deps_core::Version>> = vec![
            Box::new(CargoVersion {
                num: "2.0.0".into(),
                yanked: true,
                features: HashMap::new(),
                published_at: None,
            }),
            Box::new(CargoVersion {
                num: "1.0.0".into(),
                yanked: false,
                features: HashMap::new(),
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
        let registry = CratesIoRegistry::new(cache);
        let versions: Vec<Box<dyn deps_core::Version>> = vec![
            Box::new(CargoVersion {
                num: "2.0.0".into(),
                yanked: true,
                features: HashMap::new(),
                published_at: None,
            }),
            Box::new(CargoVersion {
                num: "1.0.0".into(),
                yanked: true,
                features: HashMap::new(),
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
        let registry = CratesIoRegistry::new(cache);
        let versions: Vec<Box<dyn deps_core::Version>> = vec![
            Box::new(CargoVersion {
                num: "2.0.0-beta.1".into(),
                yanked: false,
                features: HashMap::new(),
                published_at: None,
            }),
            Box::new(CargoVersion {
                num: "1.0.0-alpha.1".into(),
                yanked: false,
                features: HashMap::new(),
                published_at: None,
            }),
        ];
        let req = VersionReq::new("*");
        assert_eq!(registry.select_latest_matching(&versions, &req), Some(0));
    }

    #[tokio::test]
    async fn test_cargo_registry_creation() {
        let cache = Arc::new(HttpCache::new());
        let _registry = CargoRegistry::new(cache);
    }

    #[tokio::test]
    async fn test_cargo_registry_unregistered_alternate_returns_not_found() {
        use deps_core::Registry;

        let cache = Arc::new(HttpCache::new());
        let registry = CargoRegistry::new(cache);
        let source = DependencySource::AlternateRegistry {
            index: "https://index.mycorp.dev".to_string(),
        };
        let name = PackageName::new("internal-crate");
        let result = registry
            .get_versions_from(
                &name,
                &source,
                deps_core::freshness::FreshnessSettings::default(),
            )
            .await;
        assert!(matches!(result, Err(DepsError::PackageNotFound { .. })));
    }

    #[tokio::test]
    async fn test_cargo_registry_register_alternate_is_idempotent() {
        let cache = Arc::new(HttpCache::new());
        let registry = CargoRegistry::new(cache);
        let index = RegistryIndex::new("https://index.mycorp.dev").unwrap();

        registry.register_alternate(index.clone(), None);
        assert!(
            registry
                .alternate_client("https://index.mycorp.dev/")
                .is_some()
        );

        // Re-registering the same index with a different auth must not replace the
        // already-registered client (documented limitation).
        registry.register_alternate(index, Some(AuthToken::new("token".to_string())));
        assert!(
            registry
                .alternate_client("https://index.mycorp.dev/")
                .is_some()
        );
    }

    #[tokio::test]
    async fn test_cargo_registry_alternate_cap_skips_registration() {
        let cache = Arc::new(HttpCache::new());
        let registry = CargoRegistry::new(cache);
        for i in 0..MAX_ALTERNATE_REGISTRIES {
            let index = RegistryIndex::new(&format!("https://index{i}.example")).unwrap();
            registry.register_alternate(index, None);
        }
        assert_eq!(registry.alternates.len(), MAX_ALTERNATE_REGISTRIES);

        let overflow = RegistryIndex::new("https://overflow.example").unwrap();
        registry.register_alternate(overflow, None);
        assert_eq!(registry.alternates.len(), MAX_ALTERNATE_REGISTRIES);
        assert!(
            registry
                .alternate_client("https://overflow.example/")
                .is_none()
        );
    }
}
