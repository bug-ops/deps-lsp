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
            sparse: SparseIndexClient::new(
                RegistryIndex::builtin(SPARSE_INDEX_BASE),
                Arc::clone(&cache),
            ),
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
    /// Resolved alternate-registry clients, keyed by [`RegistryIndex::as_str`] (plan-1b
    /// §1.2, critic S2: re-keyed from `RegistryIndex` to `String` so registration
    /// (`Self::register_alternate`) and lookup (`Self::alternate_client`) both key off one
    /// already-validated `RegistryIndex::as_str()`, symmetrically — a lookup no longer needs
    /// to reconstruct and re-validate a `RegistryIndex` of its own, which would otherwise
    /// need its own `IndexTrust`/policy argument just to answer a plain map lookup).
    /// Populated by [`Self::register_alternate`] at parse time (see `crate::ecosystem`'s
    /// `parse_manifest` override) — the *only* place an [`AuthToken`] is ever attached to a
    /// client, since only that call site has the [`crate::config::CargoConfig`]/
    /// [`crate::config::SourceReplacement`] resolution in hand. A fetch that lands here with
    /// an unregistered index (never resolved, or dropped for capacity) has no way to
    /// recover a token and must not fall back to crates.io unless the dependency is a
    /// verified crates.io mirror (`mirrors_crates_io`, spec plan-1b §6 M2) — see
    /// [`Self::get_versions_for_source`]/[`Self::get_latest_matching_for_source`].
    alternates: dashmap::DashMap<String, Arc<SparseIndexClient>>,
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
    ///
    /// Issue #455, C3: a re-registration of an *already-registered* index URL now folds to
    /// the stricter of the stored and incoming [`crate::config::IndexTrust`] tier, dropping
    /// any stored credential when the fold actually tightens — closing the shape where a
    /// `Trusted`+token registration of URL X (from `$CARGO_HOME`) makes a later
    /// `WorkspaceDeclared` registration of the same X a no-op, leaving a workspace-controlled
    /// alias fetch through the looser `Trusted`-tier client. A re-registration that does not
    /// tighten the tier keeps the existing client (and its credential) untouched — this is a
    /// stricter, not weaker, version of the pre-existing idempotency contract this method's
    /// summary line above documents.
    pub fn register_alternate(&self, index: RegistryIndex, auth: Option<AuthToken>) {
        // Read before `entry()`: `DashMap::len` read-locks every shard, and `entry()` holds a
        // write guard on one — checking capacity from inside the `Vacant` arm below would
        // self-deadlock on that shard.
        let at_capacity = self.alternates.len() >= MAX_ALTERNATE_REGISTRIES;
        let key = index.as_str().to_string();
        let incoming_trust = index.trust();
        let index_display = index.to_string();

        match self.alternates.entry(key) {
            dashmap::mapref::entry::Entry::Occupied(mut slot) => {
                let stored_trust = slot.get().trust();
                let folded = stored_trust.min(incoming_trust);
                if folded != stored_trust {
                    tracing::warn!(
                        index = %index_display,
                        "re-registration folds an alternate registry to the stricter trust \
                         tier; dropping any stored credential"
                    );
                    slot.insert(Arc::new(SparseIndexClient::with_auth(
                        index,
                        Arc::clone(&self.cache),
                        None,
                        "alternate registry",
                    )));
                }
            }
            dashmap::mapref::entry::Entry::Vacant(slot) => {
                if at_capacity {
                    tracing::warn!(
                        index = %index_display,
                        cap = MAX_ALTERNATE_REGISTRIES,
                        "alternate registry cap reached; not registering a new index"
                    );
                    return;
                }
                slot.insert(Arc::new(SparseIndexClient::with_auth(
                    index,
                    Arc::clone(&self.cache),
                    auth,
                    "alternate registry",
                )));
            }
        }
    }

    /// The registered client for `index`, if any — read-only, performs no registration, no
    /// validation. A plain map lookup: `index` only ever originates from an already-validated
    /// [`RegistryIndex::as_str`], on both sides — registration above, and a dependency's own
    /// resolved `index` string (`crate::parser`) — so normalization stays symmetric with no
    /// need to reconstruct a `RegistryIndex` (and the `IndexTrust`/policy that would require)
    /// just to look one up (plan-1b §1.2, critic S2).
    ///
    /// Used by completion (`crate::ecosystem::CargoEcosystem::generate_completions`, FR-012)
    /// to address one specific alternate index directly via [`deps_core::Registry`]'s
    /// generic helpers, without going through this router's source-based dispatch.
    #[must_use]
    pub fn alternate_client(&self, index: &str) -> Option<Arc<SparseIndexClient>> {
        self.alternates.get(index).map(|entry| Arc::clone(&entry))
    }

    async fn get_versions_for_source(
        &self,
        name: &PackageName,
        source: &DependencySource,
    ) -> Result<Vec<CargoVersion>> {
        match source {
            DependencySource::AlternateRegistry {
                index,
                mirrors_crates_io,
            } => match self.alternate_client(index) {
                Some(client) => client.get_versions(name.as_str()).await,
                // M2 (plan-1b §6): an unregistered *verified crates.io mirror* degrades to
                // crates.io rather than blanking the whole manifest — correct for a mirror
                // (Cargo verifies per-version checksum equality against crates.io for it),
                // wrong for a genuinely private/unregistered registry, which must keep
                // failing `PackageNotFound` below.
                None if *mirrors_crates_io => self.crates_io.get_versions(name.as_str()).await,
                None => Err(DepsError::PackageNotFound {
                    package: name.to_string(),
                    registry: "alternate registry (not registered)",
                }),
            },
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
            DependencySource::AlternateRegistry {
                index,
                mirrors_crates_io,
            } => match self.alternate_client(index) {
                Some(client) => {
                    client
                        .get_latest_matching(name.as_str(), req.as_str())
                        .await
                }
                // M2 (plan-1b §6, N4): the hover-fallback/background-fetch-mirror dispatch
                // site needs the identical arm — this exact enumeration has been wrong twice
                // during design review, so both sites are asserted independently in tests.
                None if *mirrors_crates_io => {
                    self.crates_io
                        .get_latest_matching(name.as_str(), req.as_str())
                        .await
                }
                None => Err(DepsError::PackageNotFound {
                    package: name.to_string(),
                    registry: "alternate registry (not registered)",
                }),
            },
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
    use crate::config::IndexTrust;
    use deps_core::net_policy::RegistryAccessPolicy;
    use std::assert_matches;
    use std::collections::HashMap;

    /// Wraps `raw` into a [`RegistryIndex`] for test call sites — see `sparse.rs`'s
    /// identical helper for why an all-allow-equivalent (`Trusted`) policy is used.
    fn test_index(raw: &str) -> RegistryIndex {
        let policy = RegistryAccessPolicy::default();
        RegistryIndex::new(raw, IndexTrust::Trusted, &policy).unwrap()
    }

    /// Like [`test_index`], but takes an explicit [`IndexTrust`] — issue #455's C3 fold test
    /// needs to construct indices at both `Trusted` and `WorkspaceDeclared`, unlike every other
    /// test in this module.
    fn test_index_with_trust(raw: &str, trust: IndexTrust) -> RegistryIndex {
        let policy = RegistryAccessPolicy::new(deps_core::net_policy::WorkspaceRegistryAccess::All);
        RegistryIndex::new(raw, trust, &policy).unwrap()
    }

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
            mirrors_crates_io: false,
        };
        let name = PackageName::new("internal-crate");
        let result = registry
            .get_versions_from(
                &name,
                &source,
                deps_core::freshness::FreshnessSettings::default(),
            )
            .await;
        assert_matches!(result.err(), Some(DepsError::PackageNotFound { .. }));
    }

    /// Builds a `CargoRegistry` whose `crates_io` field points at `mockito_url` instead of
    /// the real crates.io index — direct struct-literal construction (both `CratesIoRegistry`
    /// and `CargoRegistry`'s fields are private, but this test module is a descendant of
    /// their defining module) is the only way to make the M2 fallback observable without a
    /// real network request.
    fn cargo_registry_with_mocked_crates_io(
        mockito_url: &str,
        cache: Arc<HttpCache>,
    ) -> CargoRegistry {
        let sparse = SparseIndexClient::new(test_index(mockito_url), Arc::clone(&cache));
        CargoRegistry {
            crates_io: CratesIoRegistry {
                sparse,
                cache: Arc::clone(&cache),
            },
            alternates: dashmap::DashMap::new(),
            cache,
        }
    }

    /// M2 (plan-1b §6, N4), dispatch site 1 of 2: an unregistered `mirrors_crates_io: true`
    /// source must fall back to crates.io through `get_versions_for_source` — a missed
    /// registration degrades gracefully instead of blanking the whole manifest.
    #[tokio::test]
    async fn test_get_versions_for_source_unregistered_mirror_falls_back_to_crates_io() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/se/rd/serde")
            .with_status(200)
            .with_body(r#"{"name":"serde","vers":"1.0.0","yanked":false,"features":{},"deps":[]}"#)
            .create_async()
            .await;

        let cache = Arc::new(HttpCache::new());
        let registry = cargo_registry_with_mocked_crates_io(&server.url(), cache);

        let source = DependencySource::AlternateRegistry {
            index: "https://index.never-registered.example".to_string(),
            mirrors_crates_io: true,
        };
        let name = PackageName::new("serde");
        let versions = registry
            .get_versions_for_source(&name, &source)
            .await
            .expect("an unregistered mirror must fall back to crates.io, not error");
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0].num, "1.0.0");
        mock.assert_async().await;
    }

    /// M2, dispatch site 2 of 2: the hover-fallback/background-fetch-mirror path
    /// (`get_latest_matching_for_source`) needs the identical arm — this exact enumeration
    /// has been wrong twice during design review, so both sites are asserted independently.
    #[tokio::test]
    async fn test_get_latest_matching_for_source_unregistered_mirror_falls_back_to_crates_io() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/se/rd/serde")
            .with_status(200)
            .with_body(r#"{"name":"serde","vers":"1.0.0","yanked":false,"features":{},"deps":[]}"#)
            .create_async()
            .await;

        let cache = Arc::new(HttpCache::new());
        let registry = cargo_registry_with_mocked_crates_io(&server.url(), cache);

        let source = DependencySource::AlternateRegistry {
            index: "https://index.never-registered.example".to_string(),
            mirrors_crates_io: true,
        };
        let name = PackageName::new("serde");
        let req = deps_core::VersionReq::new("^1.0");
        let latest = registry
            .get_latest_matching_for_source(&name, &source, &req)
            .await
            .expect("an unregistered mirror must fall back to crates.io, not error");
        assert_eq!(latest.expect("a matching version").num, "1.0.0");
        mock.assert_async().await;
    }

    /// The non-mirror counterpart: an unregistered, genuinely private (`mirrors_crates_io:
    /// false`) alternate index must keep failing `PackageNotFound` — the M2 fallback is
    /// scoped strictly to verified crates.io mirrors.
    #[tokio::test]
    async fn test_get_latest_matching_for_source_unregistered_non_mirror_stays_not_found() {
        let cache = Arc::new(HttpCache::new());
        let registry = CargoRegistry::new(cache);
        let source = DependencySource::AlternateRegistry {
            index: "https://index.never-registered.example".to_string(),
            mirrors_crates_io: false,
        };
        let name = PackageName::new("internal-crate");
        let req = deps_core::VersionReq::new("^1.0");
        let result = registry
            .get_latest_matching_for_source(&name, &source, &req)
            .await;
        assert_matches!(result, Err(DepsError::PackageNotFound { .. }));
    }

    #[tokio::test]
    async fn test_cargo_registry_register_alternate_is_idempotent() {
        let cache = Arc::new(HttpCache::new());
        let registry = CargoRegistry::new(cache);
        let index = test_index("https://index.mycorp.dev");

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

    // Issue #455, test-plan item 10 (C3 fold): a `Trusted`+token registration of index X,
    // followed by a `WorkspaceDeclared` re-registration of the same X, folds the stored client
    // to `WorkspaceDeclared` and drops the credential — closing the shape where the old
    // `contains_key` no-op left the workspace alias fetching through the looser Trusted-tier
    // client.
    #[tokio::test]
    async fn test_cargo_registry_register_alternate_folds_to_stricter_trust_trusted_then_workspace()
    {
        let cache = Arc::new(HttpCache::new());
        let registry = CargoRegistry::new(cache);
        let url = "https://index.mycorp.dev";

        registry.register_alternate(
            test_index_with_trust(url, IndexTrust::Trusted),
            Some(AuthToken::new("token".to_string())),
        );
        let client = registry
            .alternate_client("https://index.mycorp.dev/")
            .expect("registered");
        assert_eq!(client.trust(), IndexTrust::Trusted);
        assert!(client.has_auth());

        registry.register_alternate(
            test_index_with_trust(url, IndexTrust::WorkspaceDeclared),
            None,
        );
        let client = registry
            .alternate_client("https://index.mycorp.dev/")
            .expect("still registered");
        assert_eq!(client.trust(), IndexTrust::WorkspaceDeclared);
        assert!(
            !client.has_auth(),
            "the fold must drop the stored credential"
        );
    }

    // Reverse order: a `WorkspaceDeclared` registration first must not be loosened by a later
    // `Trusted` re-registration attempt for the same URL — the fold only ever moves toward
    // `WorkspaceDeclared`, never away from it.
    #[tokio::test]
    async fn test_cargo_registry_register_alternate_folds_to_stricter_trust_workspace_then_trusted()
    {
        let cache = Arc::new(HttpCache::new());
        let registry = CargoRegistry::new(cache);
        let url = "https://index.mycorp.dev";

        registry.register_alternate(
            test_index_with_trust(url, IndexTrust::WorkspaceDeclared),
            None,
        );
        registry.register_alternate(
            test_index_with_trust(url, IndexTrust::Trusted),
            Some(AuthToken::new("token".to_string())),
        );

        let client = registry
            .alternate_client("https://index.mycorp.dev/")
            .expect("still registered");
        assert_eq!(client.trust(), IndexTrust::WorkspaceDeclared);
        assert!(
            !client.has_auth(),
            "a WorkspaceDeclared registration must not gain a credential from a later Trusted \
             re-registration attempt"
        );
    }

    // The cap regression guard (D2a): the hoisted capacity check must still see each of the
    // first MAX_ALTERNATE_REGISTRIES registrations as under capacity and the overflow one as
    // at capacity.
    #[tokio::test]
    async fn test_cargo_registry_alternate_cap_skips_registration() {
        let cache = Arc::new(HttpCache::new());
        let registry = CargoRegistry::new(cache);
        for i in 0..MAX_ALTERNATE_REGISTRIES {
            let index = test_index(&format!("https://index{i}.example"));
            registry.register_alternate(index, None);
        }
        assert_eq!(registry.alternates.len(), MAX_ALTERNATE_REGISTRIES);

        let overflow = test_index("https://overflow.example");
        registry.register_alternate(overflow, None);
        assert_eq!(registry.alternates.len(), MAX_ALTERNATE_REGISTRIES);
        assert!(
            registry
                .alternate_client("https://overflow.example/")
                .is_none()
        );
    }
}
