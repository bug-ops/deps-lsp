//! NuGet V3 registry client.
//!
//! NuGet base URLs are not hardcodable: the service index
//! (`https://api.nuget.org/v3/index.json`) must be resolved first, then consulted for the
//! flat-container ("PackageBaseAddress"), search ("SearchQueryService"), and registration
//! ("RegistrationsBaseUrl") resource URLs — the last one backs both publish-time freshness
//! and [`NuGetRegistry::unlisted_versions_for_hover`]'s hover-only unlisted enrichment (D1).

use crate::config::{NuGetFeedUrl, NuGetSourceChain};
use crate::types::{NuGetVersion, PackageInfo};
use crate::version::compare_versions;
use dashmap::DashMap;
use deps_core::net_policy::{PolicyGate, RegistryAccessPolicy};
use deps_core::parser::DependencySource;
use deps_core::{
    DepsError, FreshnessSettings, HOVER_RECENT_VERSIONS, HttpCache, PublishTime, Result,
};
use serde::Deserialize;
use std::any::Any;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::OnceCell;

/// The real public NuGet service index — used both as the default root registry's own feed
/// and, via [`is_public_registry_url`], to identify "the nuget.org source" by normalized URL
/// rather than by a source's configured `key` (issue #523, R3: a hostile config can name a
/// private feed `"nuget.org"`).
pub(crate) const NUGET_ORG_INDEX_URL: &str = "https://api.nuget.org/v3/index.json";

/// Safety bound on external (non-inline) registration page fetches per `get_versions_with`
/// call. Real packages need at most one (§1.1); this only guards a pathological feed.
const MAX_EXTERNAL_PAGE_FETCHES: usize = 2;

/// Upper bound on [`NuGetRegistry::alternates`]' entry count. Mirrors `deps-npm`'s/
/// `deps-pypi`'s identical `MAX_ALTERNATE_REGISTRIES`. Once at capacity, a *new* chain is
/// simply never registered (see [`NuGetRegistry::register_chain`]) — a dependency resolved to
/// an unregistered chain degrades to [`DepsError::PackageNotFound`], never to an api.nuget.org
/// lookup by name.
const MAX_ALTERNATE_REGISTRIES: usize = 256;

/// Display name for NuGet used in not-found and API-response error messages.
pub const REGISTRY: &str = "NuGet";

/// Returns `true` when `url` (an already-[`NuGetFeedUrl`]-normalized string) is the real
/// public NuGet service index — never true for a source merely *named* `"nuget.org"` (issue
/// #523, R3). Used to decide whether a `<packageSourceMapping>` group that resolves to exactly
/// this one source should keep plain [`DependencySource::Registry`] (and so the
/// OSV/deps.dev/hover-trust signal `SourcePolicy::source_is_public_registry_content` gates).
pub(crate) fn is_public_registry_url(url: &str) -> bool {
    url == NUGET_ORG_INDEX_URL
}

/// Which transport a [`NuGetRegistry`] instance fetches through (issue #523, mirrors
/// `deps-pypi`'s/`deps-npm`'s identical tier split).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NuGetRegistryTier {
    /// `api.nuget.org` (or a test override) — `HttpCache::get_cached`, today's path,
    /// unchanged, `PolicyGate::Skip`.
    Public,
    /// A `NuGet.Config`-declared feed — `HttpCache::get_cached_workspace`, so every redirect
    /// hop is re-classified against the live [`RegistryAccessPolicy`], and each service-index
    /// resource `@id` is validated with `PolicyGate::Enforce` before being trusted.
    WorkspaceDeclared,
}

#[derive(Debug, Deserialize)]
struct ServiceIndexResponse {
    /// A malformed feed may send a non-array `resources` value (or omit it) — both must
    /// degrade to "no resources" rather than failing the whole document (issue #523, M1: R5
    /// was originally half-implemented, covering only `@type`/`@id`'s *entry-level* shapes).
    /// Also filters out any individual resource entry that fails to deserialize at all
    /// (`serde_json::from_value(..).ok()`), rather than failing the whole array for one bad
    /// entry.
    #[serde(default, deserialize_with = "deserialize_resources")]
    resources: Vec<ServiceResource>,
}

#[derive(Debug, Deserialize)]
struct ServiceResource {
    /// A malformed feed may send a non-string `@id` (e.g. `123`) — must degrade to "this
    /// resource cannot be picked" rather than failing deserialization of the *entire*
    /// document (issue #523, M1: `Option<String>` alone does not catch a type *mismatch*,
    /// only an absent/null value). See [`deserialize_optional_string`].
    #[serde(
        rename = "@id",
        default,
        deserialize_with = "deserialize_optional_string"
    )]
    id: Option<String>,
    /// A JSON-LD `@type` may legitimately be an array, and a malformed feed may send a
    /// non-string scalar (`123`) — either shape must degrade to "this resource doesn't match
    /// any type we look for" rather than failing deserialization of the *entire* service
    /// index document (issue #523, R5). See [`deserialize_type_list`].
    #[serde(rename = "@type", default, deserialize_with = "deserialize_type_list")]
    r#type: Vec<String>,
}

/// Lenient `resources` deserializer: a non-array value (or an absent field, via `#[serde(default)]`
/// on the caller) degrades to an empty list, and each array entry that itself fails to
/// deserialize as a [`ServiceResource`] is dropped rather than failing the whole array.
fn deserialize_resources<'de, D>(
    deserializer: D,
) -> std::result::Result<Vec<ServiceResource>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = serde_json::Value::deserialize(deserializer)?;
    Ok(match value {
        serde_json::Value::Array(items) => items
            .into_iter()
            .filter_map(|v| serde_json::from_value(v).ok())
            .collect(),
        _ => Vec::new(),
    })
}

/// Lenient `Option<String>` deserializer: any non-string, non-null JSON shape (a number, an
/// object, an array) degrades to `None` rather than failing deserialization of the containing
/// document — the counterpart to [`deserialize_type_list`] for a single-string field.
fn deserialize_optional_string<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = serde_json::Value::deserialize(deserializer)?;
    Ok(match value {
        serde_json::Value::String(s) => Some(s),
        _ => None,
    })
}

/// Lenient `@type` deserializer: accepts a single string, an array of values (keeping only the
/// string entries), or degrades any other shape (a bare number, `null`, an object) to an empty
/// list — never an error, so one malformed resource entry cannot fail the whole document. No
/// existing lenient-deserialization helper exists elsewhere in this workspace to reuse.
fn deserialize_type_list<'de, D>(deserializer: D) -> std::result::Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = serde_json::Value::deserialize(deserializer)?;
    Ok(match value {
        serde_json::Value::String(s) => vec![s],
        serde_json::Value::Array(items) => items
            .into_iter()
            .filter_map(|v| match v {
                serde_json::Value::String(s) => Some(s),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    })
}

/// Resolved base URLs from the NuGet service index.
#[derive(Debug, Clone)]
struct ServiceIndex {
    /// `PackageBaseAddress/3.0.0` — flat-container version enumeration.
    package_base_address: String,
    /// `SearchQueryService/3.5.0` (preferred) or bare `SearchQueryService`. `Option`
    /// (FR-016): a private V3 feed (e.g. GitHub Packages) may omit this resource entirely —
    /// `search_typed` degrades to an empty result rather than failing.
    search_query_service: Option<String>,
    /// `RegistrationsBaseUrl/3.6.0` (SemVer 2.0.0, preferred), falling back to `3.4.0`
    /// (SemVer 1) or the bare, undated resource. `Option`, not error-gated: a private V3
    /// feed (Azure Artifacts, BaGet, GitHub Packages) may omit this resource entirely, in
    /// which case freshness degrades to `published_at == None` everywhere rather than
    /// failing `get_versions` for that feed.
    registrations_base_url: Option<String>,
}

fn pick_resource(resources: &[ServiceResource], type_preference: &[&str]) -> Option<String> {
    for want in type_preference {
        if let Some(r) = resources
            .iter()
            .find(|r| r.id.is_some() && r.r#type.iter().any(|t| t == want))
        {
            return r
                .id
                .as_deref()
                .map(|id| id.trim_end_matches('/').to_string());
        }
    }
    None
}

impl ServiceIndex {
    /// Resolves the service index's resources. For [`NuGetRegistryTier::WorkspaceDeclared`]
    /// (issue #523, Q3), each picked resource `@id` is validated against `policy` before being
    /// trusted — `HttpCache::get_cached_workspace`'s own doc states it does not re-check the
    /// initial request URL's host class, only DNS-resolved addresses and redirect hops, so this
    /// name-level gate is load-bearing. A rejected `PackageBaseAddress` fails the whole feed
    /// (fail closed); a rejected `RegistrationsBaseUrl`/`SearchQueryService` degrades to
    /// absent, matching how a feed that never declared the resource at all is already handled.
    /// [`NuGetRegistryTier::Public`] never gates (`PolicyGate::Skip` equivalent) — the default
    /// public registry is trusted unconditionally, matching every other ecosystem's baseline.
    fn resolve(
        response: &ServiceIndexResponse,
        tier: NuGetRegistryTier,
        policy: &RegistryAccessPolicy,
    ) -> Result<Self> {
        let package_base_address =
            pick_resource(&response.resources, &["PackageBaseAddress/3.0.0"]).ok_or_else(|| {
                deps_core::DepsError::ParseError {
                    file_type: "NuGet service index".into(),
                    source: Box::new(std::io::Error::other(
                        "missing PackageBaseAddress/3.0.0 resource",
                    )),
                }
            })?;
        let search_query_service = pick_resource(
            &response.resources,
            &["SearchQueryService/3.5.0", "SearchQueryService"],
        );
        let registrations_base_url = pick_resource(
            &response.resources,
            &[
                "RegistrationsBaseUrl/3.6.0",
                "RegistrationsBaseUrl/3.4.0",
                "RegistrationsBaseUrl",
            ],
        );

        if tier != NuGetRegistryTier::WorkspaceDeclared {
            return Ok(Self {
                package_base_address,
                search_query_service,
                registrations_base_url,
            });
        }

        let gate = PolicyGate::Enforce(policy);
        deps_core::net_policy::validate_index_url(
            &package_base_address,
            &package_base_address,
            "nuget",
            gate,
        )
        .map_err(|e| deps_core::DepsError::ParseError {
            file_type: "NuGet service index".into(),
            source: Box::new(std::io::Error::other(format!(
                "PackageBaseAddress blocked by workspace registry policy: {e}"
            ))),
        })?;
        let search_query_service = search_query_service
            .filter(|u| deps_core::net_policy::validate_index_url(u, u, "nuget", gate).is_ok());
        let registrations_base_url = registrations_base_url
            .filter(|u| deps_core::net_policy::validate_index_url(u, u, "nuget", gate).is_ok());

        Ok(Self {
            package_base_address,
            search_query_service,
            registrations_base_url,
        })
    }
}

/// Registration hive index (`RegistrationsBaseUrl/{id}/index.json`): a list of pages, each
/// either inline (`items` present) or an external stub (`items` absent, fetched via `id`).
#[derive(Debug, Deserialize)]
struct RegistrationIndex {
    #[serde(default)]
    items: Vec<RegistrationPage>,
}

#[derive(Debug, Deserialize)]
struct RegistrationPage {
    #[serde(rename = "@id")]
    id: String,
    /// Present for an inline page; `None` for an externalized page, which must be fetched
    /// separately at `id` to obtain the same shape as [`RegistrationPageBody`].
    #[serde(default)]
    items: Option<Vec<CatalogEntryWrapper>>,
}

/// Body of a fetched external registration page — structurally identical to a
/// [`RegistrationPage`]'s inline `items`.
#[derive(Debug, Deserialize)]
struct RegistrationPageBody {
    #[serde(default)]
    items: Vec<CatalogEntryWrapper>,
}

#[derive(Debug, Deserialize)]
struct CatalogEntryWrapper {
    #[serde(rename = "catalogEntry")]
    catalog_entry: CatalogEntry,
}

#[derive(Debug, Deserialize)]
struct CatalogEntry {
    version: String,
    /// Absent/malformed degrades to no publish time for that version, not an error. The
    /// unlisted sentinel (`1900-01-01T00:00:00+00:00`) parses successfully but is filtered
    /// out by [`accumulate_catalog_entries`] rather than rendered as a bogus 126-year age.
    #[serde(default)]
    published: Option<String>,
    /// Explicit unlist flag on current registrations. Absent on registrations predating this
    /// field, which instead used `published`'s epoch sentinel to signal unlisted — see
    /// [`accumulate_catalog_entries`] for how both signals are combined (D1, #451).
    #[serde(default)]
    listed: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct FlatContainerIndex {
    #[serde(default)]
    versions: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct SearchResponse {
    #[serde(default)]
    data: Vec<SearchResultDoc>,
}

#[derive(Debug, Deserialize)]
struct SearchResultDoc {
    id: String,
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default, rename = "projectUrl")]
    project_url: Option<String>,
}

/// Returns the nuget.org package page URL for `name`.
///
/// Display link only, never fetched by this process — unlike [`flat_container_url`]/
/// [`registration_index_url`] (fetch sinks), so it is deliberately not gated against a
/// `.`/`..` name (see [`deps_core::is_dot_segment`]'s doc for the fetch-sink-vs-display-link
/// scope split, #379).
pub fn package_url(name: &str) -> String {
    format!(
        "https://www.nuget.org/packages/{}",
        urlencoding::encode(name)
    )
}

/// Rejects a dot-segment `name` before it would reach [`flat_container_url`]/
/// [`registration_index_url`], as `DepsError::PackageNotFound` — mirroring `deps-npm`'s/
/// `deps-dart`'s identical guard for the same vulnerability class (#341/#349/#365): a `name`
/// of exactly `.`/`..`, once lowercased and percent-encoded, is followed by a real `/`
/// separator before `index.json`, so it forms an exact dot-segment that a URL parser's
/// dot-segment normalization collapses, escaping the intended `PackageBaseAddress`/
/// `RegistrationsBaseUrl` prefix.
fn reject_dot_segment(name: &str) -> Result<()> {
    if deps_core::is_dot_segment(name) {
        deps_core::lsp_helpers::warn_rejected_value(
            "is_dot_segment",
            "NuGet flat-container/registration request URL",
            name,
        );
        return Err(deps_core::DepsError::PackageNotFound {
            package: name.to_string(),
            registry: REGISTRY,
        });
    }
    Ok(())
}

#[derive(Clone)]
pub struct NuGetRegistry {
    cache: Arc<HttpCache>,
    service_index_url: String,
    service_index: Arc<OnceCell<ServiceIndex>>,
    tier: NuGetRegistryTier,
    /// Consulted only when [`Self::tier`] is [`NuGetRegistryTier::WorkspaceDeclared`] — see
    /// [`ServiceIndex::resolve`]'s per-`@id` validation. A `Public`-tier instance carries a
    /// default policy that is never consulted (`resolve` skips the gate entirely for that
    /// tier), so `new`/`with_service_index_url` need not thread a live policy through.
    policy: Arc<RegistryAccessPolicy>,
    /// Resolved chain-router clients, keyed by [`NuGetSourceChain::key`]. Only the root
    /// (`Public`-tier) instance this crate constructs via [`Self::new`] ever registers into
    /// this or is ever looked up by [`Self::alternate_client`] — a chain-hop leaf's own map is
    /// always empty by construction, the same invariant `deps-npm`'s/`deps-pypi`'s identical
    /// field documents. `Arc<DashMap<..>>` (not a bare `DashMap`) since `NuGetRegistry` is
    /// `Clone` — a bare field would silently fork the map.
    alternates: Arc<DashMap<String, Arc<Self>>>,
    /// Resolved, already-constructed hop clients this instance falls through to when it (hop
    /// 0) misses. Empty for the `Public`-tier root and every leaf hop; populated only on the
    /// *head* client [`Self::register_chain`] builds for a multi-hop chain. Never looked up by
    /// string key at fetch time; `Self::get_versions_chained` walks this `Vec` positionally.
    fallback_chain: Vec<Arc<Self>>,
}

impl NuGetRegistry {
    pub fn new(cache: Arc<HttpCache>) -> Self {
        Self::with_service_index_url(cache, NUGET_ORG_INDEX_URL.to_string())
    }

    pub(crate) fn with_service_index_url(cache: Arc<HttpCache>, service_index_url: String) -> Self {
        Self {
            cache,
            service_index_url,
            service_index: Arc::new(OnceCell::new()),
            tier: NuGetRegistryTier::Public,
            policy: Arc::new(RegistryAccessPolicy::default()),
            alternates: Arc::new(DashMap::new()),
            fallback_chain: Vec::new(),
        }
    }

    /// Creates a [`NuGetRegistry`] client for one resolved `NuGet.Config`-declared feed
    /// (issue #523) — `WorkspaceDeclared`-tier so it fetches through
    /// `HttpCache::get_cached_workspace` and validates each service-index resource `@id`
    /// against `policy`.
    ///
    /// `fallback_chain` is empty for every call except the *head* client
    /// [`Self::register_chain`] builds for a multi-hop chain — every other hop is a dead end
    /// with nothing further to fall through to. Its own `alternates` map starts empty and is
    /// never populated — only the root ever registers a chain.
    #[must_use]
    pub fn with_base(
        cache: Arc<HttpCache>,
        feed: &NuGetFeedUrl,
        policy: Arc<RegistryAccessPolicy>,
        fallback_chain: Vec<Arc<Self>>,
    ) -> Self {
        Self {
            cache,
            service_index_url: feed.as_str().to_string(),
            service_index: Arc::new(OnceCell::new()),
            tier: NuGetRegistryTier::WorkspaceDeclared,
            policy,
            alternates: Arc::new(DashMap::new()),
            fallback_chain,
        }
    }

    /// Builds the full hop tree for one [`NuGetSourceChain`] and inserts the head into
    /// `root.alternates` under `chain.key`. Idempotent per key, capacity-capped at
    /// `MAX_ALTERNATE_REGISTRIES`. Called only from `NuGetEcosystem::parse_manifest`, at
    /// parse time.
    ///
    /// The implicit-public final hop (when `chain.implicit_public_fallback` is set) is a
    /// **freshly-constructed `Public`-tier client** pointed at `root`'s own
    /// `service_index_url` (never `Arc::clone(root)`, which would create a
    /// root→alternates→head→fallback_chain→root reference cycle).
    pub fn register_chain(
        root: &Arc<Self>,
        chain: &NuGetSourceChain,
        policy: &Arc<RegistryAccessPolicy>,
    ) {
        let Some((first_hop, rest_hops)) = chain.hops.split_first() else {
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
                    "NuGet alternate registry cap reached; not registering a new chain"
                );
                return;
            }

            let mut fallback_chain: Vec<Arc<Self>> = rest_hops
                .iter()
                .map(|hop| {
                    Arc::new(Self::with_base(
                        Arc::clone(&root.cache),
                        hop,
                        Arc::clone(policy),
                        Vec::new(),
                    ))
                })
                .collect();
            if chain.implicit_public_fallback {
                fallback_chain.push(Arc::new(Self::with_service_index_url(
                    Arc::clone(&root.cache),
                    root.service_index_url.clone(),
                )));
            }

            let head = Self::with_base(
                Arc::clone(&root.cache),
                first_hop,
                Arc::clone(policy),
                fallback_chain,
            );
            slot.insert(Arc::new(head));
        }
    }

    /// The registered client for `index` (a [`NuGetSourceChain::key`]), if any — read-only,
    /// performs no registration. Intentionally only ever meaningful on the **root**: a
    /// chain-hop leaf's own `alternates` map is always empty by construction.
    #[must_use]
    pub fn alternate_client(&self, index: &str) -> Option<Arc<Self>> {
        self.alternates.get(index).map(|entry| Arc::clone(&entry))
    }

    /// FR-005/FR-007: tries `self` (hop 0) first, then each already-resolved
    /// [`Self::fallback_chain`] entry in order. Mirrors `deps-pypi`'s
    /// `get_versions_chained`'s three-way failure taxonomy: `Ok(versions)` non-empty is
    /// terminal success; a not-found response (`DepsError::PackageNotFound`, or — unlike
    /// pypi, which converts this earlier — a raw `HttpStatus{404}` from a real NuGet
    /// flat-container response for an unknown package id, both covered by
    /// [`DepsError::is_not_found`]) or an empty `Ok` continues to the next hop; any other
    /// `Err` (5xx, timeout, network error) is terminal, reported as
    /// [`DepsError::ChainResolutionHalted`] rather than the underlying error unchanged — never
    /// falling back to api.nuget.org or the next configured feed, which would leak the
    /// package's name past a merely-unreachable private feed.
    async fn get_versions_chained(&self, name: &str) -> Result<Vec<NuGetVersion>> {
        let mut last_miss: Result<Vec<NuGetVersion>> = Err(DepsError::PackageNotFound {
            package: name.to_string(),
            registry: REGISTRY,
        });

        for hop in std::iter::once(self).chain(self.fallback_chain.iter().map(Arc::as_ref)) {
            match hop.get_versions_typed(name).await {
                Ok(versions) if !versions.is_empty() => return Ok(versions),
                Ok(empty) => last_miss = Ok(empty),
                Err(error) if error.is_not_found() => {
                    last_miss = Err(DepsError::PackageNotFound {
                        package: name.to_string(),
                        registry: REGISTRY,
                    });
                }
                Err(other) => {
                    tracing::warn!(
                        package = name,
                        error = %other,
                        "NuGet alternate-feed chain resolution halted on a transport error \
                         — not falling back to api.nuget.org or the next configured feed"
                    );
                    return Err(DepsError::ChainResolutionHalted);
                }
            }
        }

        last_miss
    }

    /// Resolves the service index once per process, retrying on the next call if
    /// resolution failed. `get_or_try_init` (not `get_or_init`) is load-bearing: it leaves
    /// the cell empty on `Err` so a transient failure does not permanently poison lookups,
    /// and it serializes concurrent initializers so a cold start with many dependencies
    /// does not stampede the index endpoint.
    async fn service_index(&self) -> Result<&ServiceIndex> {
        self.service_index
            .get_or_try_init(|| async {
                let data = match self.tier {
                    NuGetRegistryTier::Public => {
                        self.cache.get_cached(&self.service_index_url).await?
                    }
                    NuGetRegistryTier::WorkspaceDeclared => {
                        self.cache
                            .get_cached_workspace(&self.service_index_url)
                            .await?
                    }
                };
                let response: ServiceIndexResponse = deps_core::parse_json_checked(&data)?;
                ServiceIndex::resolve(&response, self.tier, &self.policy)
            })
            .await
    }

    /// Fetches all available versions for `name` from the flat-container endpoint,
    /// sorted newest-first.
    ///
    /// Delegates to [`Self::get_versions_typed_with`] with freshness disabled so the two
    /// paths cannot drift apart.
    ///
    /// # Errors
    ///
    /// Returns an error if the service index cannot be resolved or the flat-container
    /// request fails.
    pub async fn get_versions_typed(&self, name: &str) -> Result<Vec<NuGetVersion>> {
        self.get_versions_typed_with(name, false).await
    }

    /// Same as [`Self::get_versions_typed`], but attaches [`NuGetVersion::published_at`]
    /// from the registration hive when `freshness_enabled` and the feed exposes a
    /// `RegistrationsBaseUrl` resource.
    ///
    /// The flat-container fetch (version list) and the registration-index fetch (for
    /// publish times) are independent once the service index is resolved, so they run
    /// concurrently via `tokio::join!` rather than sequentially — this matters because
    /// `complete_versions_generic` is a per-keystroke completion path and `HttpCache` has
    /// no TTL, so every call revalidates over the network.
    ///
    /// A registration-index fetch or parse failure degrades to no publish times, never to
    /// an error: the version list itself must be unaffected by a listing problem.
    ///
    /// Both fetches go through `HttpCache::get_cached_trusted_origin`, scoped to the
    /// resolved `PackageBaseAddress`/`RegistrationsBaseUrl` respectively — not just the
    /// external registration pages `publish_times_from_index` walks. Every *redirect* this
    /// method's requests can follow (index, flat container, registration index, and — down
    /// in `publish_times_from_index` — the page `@id`s the index itself supplies) is
    /// checked against its trusted prefix, since `get_cached_trusted_origin` selects a
    /// redirect-policy-scoped client — it does not itself validate the *initial* request
    /// URL. That initial URL's safety instead comes from `reject_dot_segment`, which gates
    /// `name` before `flat_container_url`/`registration_index_url` are ever called (#365
    /// M5).
    ///
    /// # Errors
    ///
    /// Returns an error if the service index cannot be resolved or the flat-container
    /// request fails.
    pub async fn get_versions_typed_with(
        &self,
        name: &str,
        freshness_enabled: bool,
    ) -> Result<Vec<NuGetVersion>> {
        reject_dot_segment(name)?;
        let index = self.service_index().await?;
        let flat_url = flat_container_url(&index.package_base_address, name);

        if self.tier == NuGetRegistryTier::WorkspaceDeclared {
            // Q3/M2 (issue #523): workspace-gated transport, so every redirect hop is
            // re-classified against the live policy — but this trades away
            // `get_cached_trusted_origin`'s origin-pinning (a redirect off the resolved
            // `PackageBaseAddress` to any other `Global` host is permitted under
            // `public_only`), and registration-hive enrichment (publish times, hover-only
            // unlisted markers) is deliberately not attempted for alternate feeds in phase 1
            // — see `Self::unlisted_versions_for_hover`'s identical tier gate. Both are
            // documented residual-risk/scope reductions, not oversights.
            let data = self.cache.get_cached_workspace(&flat_url).await?;
            return parse_flat_container(&data);
        }

        let flat_trusted_prefix = format!("{}/", index.package_base_address);
        let registration_base = if freshness_enabled {
            index.registrations_base_url.clone()
        } else {
            None
        };

        if let Some(base) = registration_base {
            let registration_url = registration_index_url(&base, name);
            let registration_trusted_prefix = format!("{base}/");
            let (flat_result, registration_result) = tokio::join!(
                self.cache
                    .get_cached_trusted_origin(&flat_url, &flat_trusted_prefix),
                self.cache
                    .get_cached_trusted_origin(&registration_url, &registration_trusted_prefix),
            );
            let mut versions = parse_flat_container(&flat_result?)?;
            match registration_result {
                Ok(registration_body) => {
                    let enrichment = self
                        .registration_enrichment_from_index(
                            &registration_body,
                            &registration_trusted_prefix,
                        )
                        .await;
                    attach_publish_times(&mut versions, &enrichment.published);
                }
                Err(e) => {
                    tracing::debug!(package = %name, error = %e, "registration index fetch failed, publish times unavailable");
                }
            }
            Ok(versions)
        } else {
            let data = self
                .cache
                .get_cached_trusted_origin(&flat_url, &flat_trusted_prefix)
                .await?;
            parse_flat_container(&data)
        }
    }

    /// Walks the registration hive backwards from the last page, collecting `published`
    /// dates and unlisted markers until at least [`HOVER_RECENT_VERSIONS`] entries have been
    /// examined.
    ///
    /// Pages are ordered ascending by version (mirroring the flat container's descending
    /// order in reverse), so the tail of `index.items` holds the most recent versions —
    /// exactly what hover renders. Terminates on whichever comes first: enough entries
    /// collected, the index exhausted (packages with fewer total versions than the target),
    /// or [`MAX_EXTERNAL_PAGE_FETCHES`] external pages fetched (a safety bound; real
    /// packages need at most one, per the live measurements this plan is based on).
    ///
    /// Never fails the caller: a malformed index, an unreachable page, or a page `@id`
    /// outside `trusted_prefix` all degrade to fewer (or zero) entries in the returned
    /// [`RegistrationEnrichment`].
    async fn registration_enrichment_from_index(
        &self,
        index_body: &[u8],
        trusted_prefix: &str,
    ) -> RegistrationEnrichment {
        let mut enrichment = RegistrationEnrichment::default();
        let Ok(index) = deps_core::parse_json_checked::<RegistrationIndex>(index_body) else {
            return enrichment;
        };

        let mut collected = 0usize;
        let mut external_fetches = 0usize;

        for page in index.items.iter().rev() {
            if collected >= HOVER_RECENT_VERSIONS {
                break;
            }

            match &page.items {
                Some(inline) => {
                    accumulate_catalog_entries(&mut enrichment, &mut collected, inline);
                }
                None => {
                    // A page `@id` outside the resolved registration base is skipped, not
                    // trusted — the feed chooses `@id` values. `get_cached_trusted_origin`
                    // additionally stops any redirect that would otherwise escape
                    // `trusted_prefix` after this initial check passes (S2/M2).
                    if !page.id.starts_with(trusted_prefix) {
                        continue;
                    }
                    if external_fetches >= MAX_EXTERNAL_PAGE_FETCHES {
                        break;
                    }
                    external_fetches += 1;
                    let Ok(body) = self
                        .cache
                        .get_cached_trusted_origin(&page.id, trusted_prefix)
                        .await
                    else {
                        continue;
                    };
                    let Ok(parsed) = deps_core::parse_json_checked::<RegistrationPageBody>(&body)
                    else {
                        continue;
                    };
                    accumulate_catalog_entries(&mut enrichment, &mut collected, &parsed.items);
                }
            }
        }

        enrichment
    }

    /// Hover-only enrichment (D1, #451): returns the subset of `name`'s recent versions
    /// (the same [`HOVER_RECENT_VERSIONS`]-bounded window `registration_enrichment_from_index`
    /// walks) that the registry currently reports as unlisted.
    ///
    /// Deliberately **not** wired into [`Self::get_versions_typed_with`]/[`NuGetVersion`]:
    /// that shared path backs `get_versions_with`, which both hover *and*
    /// `complete_versions_generic` (completion) call, and its results also feed the
    /// per-document version cache that inlay hints and diagnostics render from. Threading
    /// `listed` through [`deps_core::Version::removal_status`] there would make an unlisted
    /// version silently vanish from completion suggestions too
    /// (`prepare_version_display_items` filters on `removal_status().blocks_resolution()`
    /// unconditionally) — the wrong tradeoff the spec calls out. This method is instead
    /// called only from [`crate::ecosystem::NuGetEcosystem`]'s `generate_hover` override,
    /// so only a hover request ever pays for it.
    ///
    /// Degrades to an empty set (never an error) on any fetch/parse failure, or when the
    /// feed has no `RegistrationsBaseUrl` resource at all — hover must still render the
    /// ordinary version list rather than disappear because this optional decoration failed.
    ///
    /// # Errors
    ///
    /// Returns an error only if `name` is rejected as a dot-segment or the service index
    /// itself cannot be resolved — both of which also fail the hover response's main
    /// version fetch, so this never surfaces a *distinct* failure mode to the caller.
    pub async fn unlisted_versions_for_hover(&self, name: &str) -> Result<HashSet<String>> {
        // Issue #523, M2: registration-hive enrichment is deliberately not attempted for
        // alternate feeds in phase 1 (`Transport::origin_pinned` and the workspace-gated
        // guard are mutually exclusive in today's `HttpCache`) — see
        // `Self::get_versions_typed_with`'s identical tier gate.
        if self.tier == NuGetRegistryTier::WorkspaceDeclared {
            return Ok(HashSet::new());
        }
        reject_dot_segment(name)?;
        let index = self.service_index().await?;
        let Some(base) = index.registrations_base_url.clone() else {
            return Ok(HashSet::new());
        };
        let registration_url = registration_index_url(&base, name);
        let trusted_prefix = format!("{base}/");
        let Ok(body) = self
            .cache
            .get_cached_trusted_origin(&registration_url, &trusted_prefix)
            .await
        else {
            return Ok(HashSet::new());
        };
        Ok(self
            .registration_enrichment_from_index(&body, &trusted_prefix)
            .await
            .unlisted)
    }

    /// Finds the highest version of `name` matching `req` (exact pin, interval notation,
    /// or floating pattern). Prerelease versions are excluded unless `req` itself is
    /// prerelease-bearing.
    ///
    /// # Errors
    ///
    /// Returns an error if the service index cannot be resolved or the flat-container
    /// request fails.
    pub async fn get_latest_matching_typed(
        &self,
        name: &str,
        req: &str,
    ) -> Result<Option<NuGetVersion>> {
        let versions = self.get_versions_typed(name).await?;
        Ok(pick_latest_matching(versions, req))
    }

    /// Searches the NuGet `SearchQueryService` for `query`, returning up to `limit` results.
    ///
    /// # Errors
    ///
    /// Returns an error if the service index cannot be resolved or the search request fails.
    pub async fn search_typed(&self, query: &str, limit: usize) -> Result<Vec<PackageInfo>> {
        let index = self.service_index().await?;
        // FR-016: a feed may omit `SearchQueryService` entirely (e.g. GitHub Packages).
        let Some(search_base) = index.search_query_service.as_deref() else {
            return Ok(Vec::new());
        };
        let url = search_url(search_base, query, limit);

        let data = match self.tier {
            NuGetRegistryTier::Public => self.cache.get_cached(&url).await?,
            NuGetRegistryTier::WorkspaceDeclared => self.cache.get_cached_workspace(&url).await?,
        };
        parse_search_response(&data, limit)
    }
}

/// Builds the flat-container version-enumeration URL for `name`.
///
/// The package id is lowercased (NuGet ids are case-insensitive and every V3 API path
/// segment is lowercased) and percent-encoded before being interpolated into the path.
/// Encoding is load-bearing, not cosmetic: an unencoded id lets a crafted
/// `PackageReference Include="..."` value inject path segments (`../../etc/passwd`
/// collapses dot-segments) or truncate the path at `#`/`?`/control characters, making
/// deps-lsp silently resolve and display a *different* real package's version data under
/// an attacker-chosen name.
pub fn flat_container_url(base: &str, name: &str) -> String {
    let lower = name.to_lowercase();
    format!("{base}/{}/index.json", urlencoding::encode(&lower))
}

/// Builds the registration-hive index URL for `name`. Same lowercasing/encoding rationale
/// as [`flat_container_url`].
pub fn registration_index_url(base: &str, name: &str) -> String {
    let lower = name.to_lowercase();
    format!("{base}/{}/index.json", urlencoding::encode(&lower))
}

/// Attaches `published_at` to each version whose string matches an entry in `times`.
///
/// A version present in `versions` but absent from `times` (or vice versa) is not an
/// error: it simply keeps/never gets a `published_at`. Order is untouched.
fn attach_publish_times(versions: &mut [NuGetVersion], times: &HashMap<String, PublishTime>) {
    for v in versions {
        v.published_at = times.get(v.version.as_str()).copied();
    }
}

/// Per-package result of walking a slice of the registration hive: publish timestamps
/// keyed by version string, and the subset of examined versions the registry reports as
/// unlisted. See [`NuGetRegistry::registration_enrichment_from_index`].
#[derive(Debug, Default)]
struct RegistrationEnrichment {
    published: HashMap<String, PublishTime>,
    unlisted: HashSet<String>,
}

/// Extracts publish times and unlisted markers from a page's catalog entries into
/// `enrichment`. A version is unlisted when the entry carries an explicit `"listed": false`,
/// or — for registrations that predate that field — when `published` is the unlisted
/// sentinel epoch (`<= 1970-01-01T00:00:00Z`); `published` itself still filters that same
/// sentinel out (and any unparseable timestamp) so it's never rendered as a bogus 126-year
/// age. Advances `collected` by the entry count regardless of what was extracted, since the
/// walk target in [`NuGetRegistry::registration_enrichment_from_index`] is "entries
/// examined", not "entries successfully timed".
fn accumulate_catalog_entries(
    enrichment: &mut RegistrationEnrichment,
    collected: &mut usize,
    entries: &[CatalogEntryWrapper],
) {
    for entry in entries {
        let ce = &entry.catalog_entry;
        let parsed_published = ce.published.as_deref().and_then(PublishTime::parse_rfc3339);
        let is_sentinel = parsed_published.is_some_and(|t| t.as_unix_secs() <= 0);

        if let Some(published) = parsed_published.filter(|t| t.as_unix_secs() > 0) {
            enrichment.published.insert(ce.version.clone(), published);
        }

        let unlisted = ce.listed == Some(false) || (ce.listed.is_none() && is_sentinel);
        if unlisted {
            enrichment.unlisted.insert(ce.version.clone());
        }

        *collected += 1;
    }
}

/// Builds the `SearchQueryService` URL for `query`, limited to `limit` results.
///
/// `semVerLevel=2.0.0` is mandatory (spec §1) — omitting it silently hides every package
/// whose latest version uses a dotted prerelease label.
pub fn search_url(base: &str, query: &str, limit: usize) -> String {
    format!(
        "{base}?q={}&take={limit}&prerelease=false&semVerLevel=2.0.0",
        urlencoding::encode(query),
    )
}

/// Parses a flat-container `index.json` response into descending-sorted versions.
pub fn parse_flat_container(data: &[u8]) -> Result<Vec<NuGetVersion>> {
    let parsed: FlatContainerIndex = deps_core::parse_json_checked(data)?;

    let mut versions = parsed.versions;
    // Sort locally, descending: the flat container's observed ascending order is not a
    // documented contract, so relying on `.reverse()` would silently corrupt "latest" if
    // the CDN/backend ever changes it (rev2, S3).
    versions.sort_by(|a, b| compare_versions(b, a));

    Ok(versions
        .into_iter()
        .map(|version| NuGetVersion {
            version: version.into(),
            published_at: None,
        })
        .collect())
}

/// Picks the highest version matching `req` from an already-fetched, descending-sorted
/// version list. `req` is treated as `"*"` when empty. Prerelease versions are excluded
/// unless `req` itself is prerelease-bearing (contains `-`) or is a floating pattern whose
/// own prerelease inclusion is handled by `crate::version::resolve_float`.
///
/// Under an existence-check wildcard (`req` trimmed is `""` or `"*"`), a normal match that
/// comes up empty falls back to [`deps_core::select_latest_for_existence`] so a
/// prerelease-only package still reports its newest version instead of `None` — see that
/// function's doc comment for the 3-rung contract. Non-wildcard requirements (e.g.
/// `"*-*"`, `"1.*"`) are unaffected: this fallback never fires for them.
fn pick_latest_matching(versions: Vec<NuGetVersion>, req: &str) -> Option<NuGetVersion> {
    if versions.is_empty() {
        return None;
    }

    let req = if req.is_empty() { "*" } else { req };

    let matched = if req.contains('*') {
        let strings: Vec<String> = versions.iter().map(|v| v.version.to_string()).collect();
        crate::version::resolve_float(&strings, req).map(|v| NuGetVersion {
            version: v.into(),
            published_at: None,
        })
    } else {
        let req_is_prerelease_bearing = req.contains('-');
        versions
            .iter()
            .find(|v| {
                crate::version::satisfies(v.version.as_str(), req)
                    && (req_is_prerelease_bearing
                        || !crate::version::is_prerelease(v.version.as_str()))
            })
            .cloned()
    };

    matched.or_else(|| {
        if deps_core::is_existence_wildcard_str(req) {
            let idx = deps_core::select_latest_for_existence(&versions, |v| {
                v as &dyn deps_core::Version
            })?;
            Some(versions[idx].clone())
        } else {
            None
        }
    })
}

fn parse_search_response(data: &[u8], limit: usize) -> Result<Vec<PackageInfo>> {
    let response: SearchResponse = deps_core::parse_json_checked(data)?;

    Ok(response
        .data
        .into_iter()
        .take(limit)
        .map(|d| PackageInfo {
            name: d.id.into(),
            description: d.description,
            repository: d.project_url,
            documentation: None,
            latest_version: d.version.unwrap_or_default().into(),
        })
        .collect())
}

impl deps_core::Registry for NuGetRegistry {
    fn get_versions<'a>(
        &'a self,
        name: &'a deps_core::PackageName,
    ) -> deps_core::ecosystem::BoxFuture<'a, Result<Vec<Box<dyn deps_core::Version>>>> {
        Box::pin(async move {
            let versions = self.get_versions_typed(name.as_str()).await?;
            Ok(versions
                .into_iter()
                .map(|v| Box::new(v) as Box<dyn deps_core::Version>)
                .collect())
        })
    }

    fn get_versions_with<'a>(
        &'a self,
        name: &'a deps_core::PackageName,
        freshness: deps_core::FreshnessSettings,
    ) -> deps_core::ecosystem::BoxFuture<'a, Result<Vec<Box<dyn deps_core::Version>>>> {
        Box::pin(async move {
            let versions = self
                .get_versions_typed_with(name.as_str(), freshness.enabled)
                .await?;
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
                .get_latest_matching_typed(name.as_str(), req.as_str())
                .await?;
            Ok(version.map(|v| Box::new(v) as Box<dyn deps_core::Version>))
        })
    }

    /// Dispatches by `source` (issue #523): an `AlternateRegistry` whose index has a
    /// registered client routes through `Self::get_versions_chained`; one with **no**
    /// registered client is `PackageNotFound`, never a fall back to api.nuget.org (falling
    /// back would send a private package name to the public registry — the dependency
    /// confusion leak this feature closes). Every other source keeps today's public-registry
    /// path unchanged.
    fn get_versions_from<'a>(
        &'a self,
        name: &'a deps_core::PackageName,
        source: &'a DependencySource,
        freshness: FreshnessSettings,
    ) -> deps_core::ecosystem::BoxFuture<'a, Result<Vec<Box<dyn deps_core::Version>>>> {
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
    /// "never fall back to api.nuget.org for an unregistered `AlternateRegistry`" invariant.
    /// The winning hop (first hop with a non-empty version list, chosen once by
    /// `Self::get_versions_chained`) is where `req` is matched — a hop with no match is
    /// terminal (`Ok(None)`), not a trigger to search later hops for a "better" match.
    fn get_latest_matching_from<'a>(
        &'a self,
        name: &'a deps_core::PackageName,
        source: &'a DependencySource,
        req: &'a deps_core::VersionReq,
        _minimum_stability: Option<&'a str>,
    ) -> deps_core::ecosystem::BoxFuture<'a, Result<Option<Box<dyn deps_core::Version>>>> {
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
                    let version = self
                        .get_latest_matching_typed(name.as_str(), req.as_str())
                        .await?;
                    Ok(version.map(|v| Box::new(v) as Box<dyn deps_core::Version>))
                }
            }
        })
    }

    fn search<'a>(
        &'a self,
        query: &'a str,
        limit: usize,
    ) -> deps_core::ecosystem::BoxFuture<'a, Result<Vec<Box<dyn deps_core::Metadata>>>> {
        Box::pin(async move {
            let results = self.search_typed(query, limit).await?;
            Ok(results
                .into_iter()
                .map(|m| Box::new(m) as Box<dyn deps_core::Metadata>)
                .collect())
        })
    }

    fn select_latest_matching(
        &self,
        versions: &[Box<dyn deps_core::Version>],
        req: &deps_core::VersionReq,
    ) -> Option<usize> {
        if versions.is_empty() {
            return None;
        }
        let req_str = req.as_str();
        let req_str = if req_str.is_empty() { "*" } else { req_str };

        let matched = if req_str.contains('*') {
            let strings: Vec<String> = versions
                .iter()
                .map(|v| v.version_string().to_string())
                .collect();
            crate::version::resolve_float(&strings, req_str)
                .and_then(|matched| strings.iter().position(|s| s == matched))
        } else {
            let req_is_prerelease_bearing = req_str.contains('-');
            versions.iter().position(|v| {
                crate::version::satisfies(v.version_string().as_str(), req_str)
                    && (req_is_prerelease_bearing
                        || !crate::version::is_prerelease(v.version_string().as_str()))
            })
        };

        matched.or_else(|| {
            deps_core::is_existence_wildcard_str(req_str)
                .then(|| deps_core::select_latest_for_existence(versions, |v| v.as_ref()))
                .flatten()
        })
    }

    // `Version::removal_status` uses the trait's default `Available` (no override in
    // `types.rs`) — `get_versions`/`get_latest_matching` (this trait's freshness-blind
    // entry points, per `reports_yanked`'s own contract) always resolve through the flat
    // container, which carries no `listed` flag, so `removal_status()` can never reflect
    // real registry data there (#233). `Self::unlisted_versions_for_hover` (D1, #451) is a
    // separate, hover-only enrichment that deliberately bypasses `Version` entirely —
    // see its doc comment — so it does not change this answer.
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

    fn service_index_body(package_base_address: &str, search_query_service: &str) -> String {
        format!(
            r#"{{
                "version": "3.0.0",
                "resources": [
                    {{"@id": "{package_base_address}", "@type": "PackageBaseAddress/3.0.0"}},
                    {{"@id": "{search_query_service}", "@type": "SearchQueryService/3.5.0"}}
                ]
            }}"#
        )
    }

    fn service_index_body_with_registrations(
        package_base_address: &str,
        search_query_service: &str,
        registrations_base_url: &str,
    ) -> String {
        format!(
            r#"{{
                "version": "3.0.0",
                "resources": [
                    {{"@id": "{package_base_address}", "@type": "PackageBaseAddress/3.0.0"}},
                    {{"@id": "{search_query_service}", "@type": "SearchQueryService/3.5.0"}},
                    {{"@id": "{registrations_base_url}", "@type": "RegistrationsBaseUrl/3.6.0"}}
                ]
            }}"#
        )
    }

    #[test]
    fn test_package_url() {
        assert_eq!(
            package_url("Newtonsoft.Json"),
            "https://www.nuget.org/packages/Newtonsoft.Json"
        );
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
        assert!(url.contains("%25"));
    }

    #[test]
    fn test_package_url_empty_name() {
        assert_eq!(package_url(""), "https://www.nuget.org/packages/");
    }

    #[test]
    fn test_flat_container_url_lowercases_and_encodes() {
        assert_eq!(
            flat_container_url("https://api.nuget.org/v3-flatcontainer", "Newtonsoft.Json"),
            "https://api.nuget.org/v3-flatcontainer/newtonsoft.json/index.json"
        );
    }

    #[test]
    fn test_flat_container_url_encodes_path_traversal_attempt() {
        // A crafted `Include="../../../../etc/passwd"` must not produce raw dot-segments
        // that a URL-parsing layer could collapse across path boundaries.
        let url = flat_container_url(
            "https://api.nuget.org/v3-flatcontainer",
            "../../../../etc/passwd",
        );
        assert_eq!(
            url,
            "https://api.nuget.org/v3-flatcontainer/..%2F..%2F..%2F..%2Fetc%2Fpasswd/index.json"
        );
        assert!(
            !url.contains("/../"),
            "raw path traversal segment leaked into URL: {url}"
        );
    }

    #[test]
    fn test_flat_container_url_encodes_fragment_and_query_delimiters() {
        // '#'/'?' must not be able to truncate the path and silently resolve as a
        // different, shorter package name.
        assert_eq!(
            flat_container_url("https://api.nuget.org/v3-flatcontainer", "Foo#x"),
            "https://api.nuget.org/v3-flatcontainer/foo%23x/index.json"
        );
        assert_eq!(
            flat_container_url("https://api.nuget.org/v3-flatcontainer", "Foo?x=1"),
            "https://api.nuget.org/v3-flatcontainer/foo%3Fx%3D1/index.json"
        );
    }

    #[test]
    fn test_flat_container_url_encodes_control_characters() {
        let url = flat_container_url("https://api.nuget.org/v3-flatcontainer", "Foo\tBar");
        assert_eq!(
            url,
            "https://api.nuget.org/v3-flatcontainer/foo%09bar/index.json"
        );
    }

    #[test]
    fn test_reject_dot_segment_rejects_bare_dot_dot() {
        assert!(reject_dot_segment("..").is_err());
    }

    #[test]
    fn test_reject_dot_segment_rejects_bare_dot() {
        assert!(reject_dot_segment(".").is_err());
    }

    #[test]
    fn test_reject_dot_segment_accepts_normal_names() {
        assert!(reject_dot_segment("Newtonsoft.Json").is_ok());
    }

    /// Demonstrates the vulnerability `reject_dot_segment` exists to prevent:
    /// `flat_container_url` alone (with no caller-side guard) builds a URL that, once
    /// parsed, has already lost the `v3-flatcontainer` path component.
    #[test]
    fn test_flat_container_url_bare_dot_dot_normalizes_above_base_prefix() {
        let url = flat_container_url("https://api.nuget.org/v3-flatcontainer", "..");
        let parsed = url::Url::parse(&url).unwrap();
        assert_eq!(
            parsed.path(),
            "/index.json",
            "parsed path: {}",
            parsed.path()
        );
    }

    /// #365 regression sweep: exercises the real production `reject_dot_segment` gate and
    /// `flat_container_url` sink together against the shared adversarial input set,
    /// guarding against a 6th recurrence of the dot-segment defect class in this crate.
    #[test]
    fn test_flat_container_url_dot_segment_sweep() {
        deps_core::test_util::assert_dot_segment_gated_or_contained(
            |seg| {
                reject_dot_segment(seg)
                    .ok()
                    .map(|()| flat_container_url("https://api.nuget.org/v3-flatcontainer", seg))
            },
            "api.nuget.org",
            "/v3-flatcontainer/",
        );
    }

    #[test]
    fn test_search_url_includes_mandatory_semver_level_and_prerelease_false() {
        let url = search_url("https://azuresearch-usnc.nuget.org/query", "json", 10);
        assert_eq!(
            url,
            "https://azuresearch-usnc.nuget.org/query?q=json&take=10&prerelease=false&semVerLevel=2.0.0"
        );
    }

    #[test]
    fn test_search_url_encodes_query() {
        let url = search_url("https://azuresearch-usnc.nuget.org/query", "a b&c", 5);
        assert!(url.contains("q=a%20b%26c"), "query not encoded: {url}");
    }

    fn public_policy() -> RegistryAccessPolicy {
        RegistryAccessPolicy::default()
    }

    #[test]
    fn test_service_index_resolve_success() {
        let response: ServiceIndexResponse = serde_json::from_str(&service_index_body(
            "https://api.nuget.org/v3-flatcontainer/",
            "https://azuresearch-usnc.nuget.org/query",
        ))
        .unwrap();
        let index =
            ServiceIndex::resolve(&response, NuGetRegistryTier::Public, &public_policy()).unwrap();
        assert_eq!(
            index.package_base_address,
            "https://api.nuget.org/v3-flatcontainer"
        );
        assert_eq!(
            index.search_query_service.as_deref(),
            Some("https://azuresearch-usnc.nuget.org/query")
        );
    }

    #[test]
    fn test_service_index_resolve_missing_resource_errors() {
        let response: ServiceIndexResponse = serde_json::from_str(
            r#"{"version": "3.0.0", "resources": [{"@id": "https://x", "@type": "SomeOtherType"}]}"#,
        )
        .unwrap();
        assert!(
            ServiceIndex::resolve(&response, NuGetRegistryTier::Public, &public_policy()).is_err()
        );
    }

    #[test]
    fn test_service_index_search_query_service_fallback() {
        let response: ServiceIndexResponse = serde_json::from_str(
            r#"{"version": "3.0.0", "resources": [
                {"@id": "https://flat/", "@type": "PackageBaseAddress/3.0.0"},
                {"@id": "https://search/", "@type": "SearchQueryService"}
            ]}"#,
        )
        .unwrap();
        let index =
            ServiceIndex::resolve(&response, NuGetRegistryTier::Public, &public_policy()).unwrap();
        assert_eq!(
            index.search_query_service.as_deref(),
            Some("https://search")
        );
    }

    /// R5: a JSON-LD `@type` array must still resolve the resource, not fail the document.
    #[test]
    fn test_service_index_resolve_type_as_array() {
        let response: ServiceIndexResponse = serde_json::from_str(
            r#"{"version": "3.0.0", "resources": [
                {"@id": "https://flat/", "@type": ["PackageBaseAddress/3.0.0", "Other"]},
                {"@id": "https://search/", "@type": "SearchQueryService"}
            ]}"#,
        )
        .unwrap();
        let index =
            ServiceIndex::resolve(&response, NuGetRegistryTier::Public, &public_policy()).unwrap();
        assert_eq!(index.package_base_address, "https://flat");
    }

    /// R5: a malformed non-string `@type` scalar must degrade to "doesn't match", not fail
    /// deserialization of the whole document.
    #[test]
    fn test_service_index_resolve_type_malformed_scalar_degrades() {
        let response: ServiceIndexResponse = serde_json::from_str(
            r#"{"version": "3.0.0", "resources": [
                {"@id": "https://malformed/", "@type": 123},
                {"@id": "https://flat/", "@type": "PackageBaseAddress/3.0.0"},
                {"@id": "https://search/", "@type": "SearchQueryService"}
            ]}"#,
        )
        .unwrap();
        let index =
            ServiceIndex::resolve(&response, NuGetRegistryTier::Public, &public_policy()).unwrap();
        assert_eq!(index.package_base_address, "https://flat");
    }

    /// R5: a resource with a missing `@id` must be skipped, not crash resolution.
    #[test]
    fn test_service_index_resolve_missing_id_skipped() {
        let response: ServiceIndexResponse = serde_json::from_str(
            r#"{"version": "3.0.0", "resources": [
                {"@type": "PackageBaseAddress/3.0.0"},
                {"@id": "https://flat/", "@type": "PackageBaseAddress/3.0.0"},
                {"@id": "https://search/", "@type": "SearchQueryService"}
            ]}"#,
        )
        .unwrap();
        let index =
            ServiceIndex::resolve(&response, NuGetRegistryTier::Public, &public_policy()).unwrap();
        assert_eq!(index.package_base_address, "https://flat");
    }

    /// FR-016: a feed omitting `SearchQueryService` entirely must resolve — this is a real
    /// GitHub Packages shape, not an error.
    #[test]
    fn test_service_index_resolve_no_search_query_service_is_none() {
        let response: ServiceIndexResponse = serde_json::from_str(
            r#"{"version": "3.0.0", "resources": [
                {"@id": "https://flat/", "@type": "PackageBaseAddress/3.0.0"}
            ]}"#,
        )
        .unwrap();
        let index =
            ServiceIndex::resolve(&response, NuGetRegistryTier::Public, &public_policy()).unwrap();
        assert!(index.search_query_service.is_none());
    }

    /// Q3: for a `WorkspaceDeclared`-tier feed, a `PackageBaseAddress` resolving to a
    /// policy-blocked host class must fail the whole feed (fail closed), not be silently
    /// trusted the way the `Public` tier is.
    #[test]
    fn test_service_index_resolve_workspace_tier_blocks_disallowed_package_base_address() {
        let response: ServiceIndexResponse = serde_json::from_str(
            r#"{"version": "3.0.0", "resources": [
                {"@id": "https://10.0.0.5/flat", "@type": "PackageBaseAddress/3.0.0"}
            ]}"#,
        )
        .unwrap();
        let policy =
            RegistryAccessPolicy::new(deps_core::net_policy::WorkspaceRegistryAccess::PublicOnly);
        assert!(
            ServiceIndex::resolve(&response, NuGetRegistryTier::WorkspaceDeclared, &policy)
                .is_err()
        );
    }

    /// Q3: a blocked `RegistrationsBaseUrl` degrades to absent rather than failing the feed.
    #[test]
    fn test_service_index_resolve_workspace_tier_degrades_blocked_registrations_base() {
        let response: ServiceIndexResponse = serde_json::from_str(
            r#"{"version": "3.0.0", "resources": [
                {"@id": "https://feed.example/flat", "@type": "PackageBaseAddress/3.0.0"},
                {"@id": "https://10.0.0.5/reg", "@type": "RegistrationsBaseUrl/3.6.0"}
            ]}"#,
        )
        .unwrap();
        let policy =
            RegistryAccessPolicy::new(deps_core::net_policy::WorkspaceRegistryAccess::PublicOnly);
        let index = ServiceIndex::resolve(&response, NuGetRegistryTier::WorkspaceDeclared, &policy)
            .unwrap();
        assert!(index.registrations_base_url.is_none());
    }

    #[test]
    fn test_parse_flat_container_sorted_descending() {
        let data = br#"{"versions": ["12.0.1", "13.0.3", "13.0.0-beta1"]}"#;
        let versions = parse_flat_container(data).unwrap();
        let strings: Vec<&str> = versions.iter().map(|v| v.version.as_str()).collect();
        assert_eq!(strings, vec!["13.0.3", "13.0.0-beta1", "12.0.1"]);
    }

    #[test]
    fn test_parse_flat_container_empty() {
        let data = br#"{"versions": []}"#;
        let versions = parse_flat_container(data).unwrap();
        assert!(versions.is_empty());
    }

    #[test]
    fn test_parse_flat_container_invalid_json_errors() {
        assert!(parse_flat_container(b"not json").is_err());
    }

    #[test]
    fn test_parse_search_response() {
        let data = br#"{"totalHits": 1, "data": [{"id": "Newtonsoft.Json", "version": "13.0.3", "description": "JSON framework", "projectUrl": "https://example.com"}]}"#;
        let results = parse_search_response(data, 10).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "Newtonsoft.Json");
        assert_eq!(results[0].latest_version, "13.0.3");
        assert_eq!(
            results[0].repository.as_deref(),
            Some("https://example.com")
        );
    }

    #[test]
    fn test_parse_search_response_respects_limit() {
        let data = br#"{"totalHits": 2, "data": [
            {"id": "A", "version": "1.0.0"},
            {"id": "B", "version": "2.0.0"}
        ]}"#;
        let results = parse_search_response(data, 1).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "A");
    }

    fn v(s: &str) -> NuGetVersion {
        NuGetVersion {
            version: s.into(),
            published_at: None,
        }
    }

    #[test]
    fn test_pick_latest_matching_wildcard_excludes_prerelease() {
        let versions = vec![v("1.0.0"), v("1.1.0-rc.1")];
        let latest = pick_latest_matching(versions, "*");
        assert_eq!(latest.unwrap().version, "1.0.0");
    }

    #[test]
    fn test_pick_latest_matching_empty_req_behaves_like_wildcard() {
        let versions = vec![v("1.0.0"), v("1.1.0-rc.1")];
        let latest = pick_latest_matching(versions, "");
        assert_eq!(latest.unwrap().version, "1.0.0");
    }

    #[test]
    fn test_pick_latest_matching_exact_pin() {
        let versions = vec![v("1.0.1"), v("1.0.0")];
        let matched = pick_latest_matching(versions, "[1.0.0]");
        assert_eq!(matched.unwrap().version, "1.0.0");
    }

    #[test]
    fn test_pick_latest_matching_floating_prefix() {
        let versions = vec![v("1.2.0"), v("1.1.5"), v("1.1.0")];
        let matched = pick_latest_matching(versions, "1.1.*");
        assert_eq!(matched.unwrap().version, "1.1.5");
    }

    #[test]
    fn test_pick_latest_matching_prerelease_bearing_requirement_allows_prerelease() {
        let versions = vec![v("1.0.0-rc.2"), v("0.9.0")];
        let matched = pick_latest_matching(versions, "[1.0.0-rc.2]");
        assert_eq!(matched.unwrap().version, "1.0.0-rc.2");
    }

    #[test]
    fn test_pick_latest_matching_empty_versions_returns_none() {
        assert!(pick_latest_matching(vec![], "*").is_none());
    }

    #[test]
    fn test_pick_latest_matching_no_match_returns_none() {
        let versions = vec![v("2.0.0")];
        assert!(pick_latest_matching(versions, "[1.0.0]").is_none());
    }

    /// Regression for #423: a package whose only releases so far are all prerelease must
    /// still resolve under a wildcard requirement — matching `deps-cargo`/`deps-composer`'s
    /// existence-check behavior — instead of `pick_latest_matching` returning `None`.
    #[test]
    fn test_pick_latest_matching_wildcard_prerelease_only_still_resolves() {
        let versions = vec![v("2.0.0-beta2"), v("2.0.0-beta1")];
        let matched = pick_latest_matching(versions, "*");
        assert_eq!(matched.unwrap().version, "2.0.0-beta2");
    }

    /// Regression for #423: empty `req` is treated as `"*"`, so it must also rescue a
    /// prerelease-only package instead of returning `None`.
    #[test]
    fn test_pick_latest_matching_empty_req_prerelease_only_still_resolves() {
        let versions = vec![v("2.0.0-beta2"), v("2.0.0-beta1")];
        let matched = pick_latest_matching(versions, "");
        assert_eq!(matched.unwrap().version, "2.0.0-beta2");
    }

    /// Regression guard for #423: `"*-*"` is prerelease-bearing but not an existence-check
    /// wildcard (`is_existence_wildcard_str` requires trimmed `""`/`"*"`), so it must keep
    /// resolving via `resolve_float`'s own best-match logic, unaffected by the new fallback.
    #[test]
    fn test_pick_latest_matching_prerelease_bearing_wildcard_unaffected_by_rescue() {
        let versions = vec![v("2.0.0-rc"), v("1.5.0"), v("1.0.0")];
        let matched = pick_latest_matching(versions, "*-*");
        assert_eq!(matched.unwrap().version, "2.0.0-rc");
    }

    /// Regression guard for #423: a concrete non-wildcard requirement must NOT be rescued
    /// by the existence-check fallback, even over a prerelease-only version list — the gate
    /// is `is_existence_wildcard_str`, not "contains a `*`". If that gate were ever loosened
    /// to `req.contains('*')`, a floating pattern like `1.*` would start getting rescued
    /// too; this pins `None` so such a regression fails loudly instead of silently.
    #[test]
    fn test_pick_latest_matching_concrete_floating_requirement_not_rescued() {
        let versions = vec![v("2.0.0-beta2"), v("2.0.0-beta1")];
        assert!(pick_latest_matching(versions, "1.*").is_none());
    }

    /// Regression guard for #423: an exact-pin requirement that matches nothing in a
    /// prerelease-only list must NOT be rescued either — mirrors
    /// `test_pick_latest_matching_concrete_floating_requirement_not_rescued` for the
    /// non-floating (exact-pin) matcher branch.
    #[test]
    fn test_pick_latest_matching_exact_pin_not_rescued() {
        let versions = vec![v("2.0.0-beta2"), v("2.0.0-beta1")];
        assert!(pick_latest_matching(versions, "[9.9.9]").is_none());
    }

    #[test]
    fn test_registry_creation_and_trait_impls() {
        use deps_core::Registry;
        let cache = Arc::new(HttpCache::new());
        let registry = NuGetRegistry::new(cache);
        assert!(registry.as_any().is::<NuGetRegistry>());
    }

    /// #365 end-to-end coverage (critic S2): exercises the real production
    /// `get_versions_typed_with` — not a reimplemented gate+sink pair — proving the gate is
    /// actually wired into the call path a real completion/hover/diagnostic request would
    /// take. No mock is needed: `reject_dot_segment` runs before `service_index()`, so the
    /// gate must reject before any network request is issued.
    ///
    /// Asserts the exact `PackageNotFound` variant (gate rejected before any request), not
    /// the broader `is_not_found()` (also true for a live 404 `HttpStatus`) — critic R1:
    /// `api.nuget.org` 404ing for this path today would make a deleted gate go undetected
    /// by this test.
    #[tokio::test]
    async fn test_get_versions_typed_with_rejects_bare_dot_dot_as_not_found() {
        let registry = NuGetRegistry::new(Arc::new(HttpCache::new()));
        let err = registry
            .get_versions_typed_with("..", false)
            .await
            .unwrap_err();
        assert!(matches!(err, deps_core::DepsError::PackageNotFound { .. }));
    }

    #[test]
    fn test_with_service_index_url_used_by_new() {
        let cache = Arc::new(HttpCache::new());
        let registry = NuGetRegistry::new(cache);
        assert_eq!(registry.service_index_url, NUGET_ORG_INDEX_URL);
    }

    #[test]
    fn test_select_latest_matching_not_default_none() {
        use deps_core::{Registry, VersionReq};

        let cache = Arc::new(HttpCache::new());
        let registry = NuGetRegistry::new(cache);
        let versions: Vec<Box<dyn deps_core::Version>> =
            vec![Box::new(v("1.1.0-rc.1")), Box::new(v("1.0.0"))];
        let req = VersionReq::new("*");
        assert_eq!(registry.select_latest_matching(&versions, &req), Some(1));
    }

    /// Regression for #423: the trait impl's `select_latest_matching` must rescue a
    /// prerelease-only package under a wildcard requirement too, mirroring
    /// `test_pick_latest_matching_wildcard_prerelease_only_still_resolves`.
    #[test]
    fn test_select_latest_matching_wildcard_prerelease_only_still_resolves() {
        use deps_core::{Registry, VersionReq};

        let cache = Arc::new(HttpCache::new());
        let registry = NuGetRegistry::new(cache);
        let versions: Vec<Box<dyn deps_core::Version>> =
            vec![Box::new(v("2.0.0-beta2")), Box::new(v("2.0.0-beta1"))];
        let req = VersionReq::new("*");
        assert_eq!(registry.select_latest_matching(&versions, &req), Some(0));
    }

    /// Regression for #423: empty `req` on the trait impl must also rescue a
    /// prerelease-only package, matching the free-function behavior.
    #[test]
    fn test_select_latest_matching_empty_req_prerelease_only_still_resolves() {
        use deps_core::{Registry, VersionReq};

        let cache = Arc::new(HttpCache::new());
        let registry = NuGetRegistry::new(cache);
        let versions: Vec<Box<dyn deps_core::Version>> =
            vec![Box::new(v("2.0.0-beta2")), Box::new(v("2.0.0-beta1"))];
        let req = VersionReq::new("");
        assert_eq!(registry.select_latest_matching(&versions, &req), Some(0));
    }

    /// Regression guard for #423: `"*-*"` is not an existence-check wildcard, so the trait
    /// impl must keep resolving via `resolve_float`'s best-match logic, unaffected by the
    /// new fallback — mirrors
    /// `test_pick_latest_matching_prerelease_bearing_wildcard_unaffected_by_rescue`.
    #[test]
    fn test_select_latest_matching_prerelease_bearing_wildcard_unaffected_by_rescue() {
        use deps_core::{Registry, VersionReq};

        let cache = Arc::new(HttpCache::new());
        let registry = NuGetRegistry::new(cache);
        let versions: Vec<Box<dyn deps_core::Version>> = vec![
            Box::new(v("2.0.0-rc")),
            Box::new(v("1.5.0")),
            Box::new(v("1.0.0")),
        ];
        let req = VersionReq::new("*-*");
        assert_eq!(registry.select_latest_matching(&versions, &req), Some(0));
    }

    /// Regression guard for #423: a concrete floating requirement must NOT be rescued by
    /// the trait impl's existence-check fallback, even over a prerelease-only list — mirrors
    /// `test_pick_latest_matching_concrete_floating_requirement_not_rescued`.
    #[test]
    fn test_select_latest_matching_concrete_floating_requirement_not_rescued() {
        use deps_core::{Registry, VersionReq};

        let cache = Arc::new(HttpCache::new());
        let registry = NuGetRegistry::new(cache);
        let versions: Vec<Box<dyn deps_core::Version>> =
            vec![Box::new(v("2.0.0-beta2")), Box::new(v("2.0.0-beta1"))];
        let req = VersionReq::new("1.*");
        assert_eq!(registry.select_latest_matching(&versions, &req), None);
    }

    /// Regression guard for #423: a concrete exact-pin requirement matching nothing in a
    /// prerelease-only list must NOT be rescued either — mirrors
    /// `test_pick_latest_matching_exact_pin_not_rescued` for the trait impl.
    #[test]
    fn test_select_latest_matching_exact_pin_not_rescued() {
        use deps_core::{Registry, VersionReq};

        let cache = Arc::new(HttpCache::new());
        let registry = NuGetRegistry::new(cache);
        let versions: Vec<Box<dyn deps_core::Version>> =
            vec![Box::new(v("2.0.0-beta2")), Box::new(v("2.0.0-beta1"))];
        let req = VersionReq::new("[9.9.9]");
        assert_eq!(registry.select_latest_matching(&versions, &req), None);
    }

    // --- ServiceIndex::resolve: registrations_base_url preference (S2/rev2 OQ6) ---

    #[test]
    fn test_service_index_resolve_registrations_base_url_prefers_3_6_0() {
        let response: ServiceIndexResponse = serde_json::from_str(
            r#"{"version": "3.0.0", "resources": [
                {"@id": "https://flat/", "@type": "PackageBaseAddress/3.0.0"},
                {"@id": "https://search/", "@type": "SearchQueryService"},
                {"@id": "https://reg-semver1/", "@type": "RegistrationsBaseUrl/3.4.0"},
                {"@id": "https://reg-semver2/", "@type": "RegistrationsBaseUrl/3.6.0"}
            ]}"#,
        )
        .unwrap();
        let index =
            ServiceIndex::resolve(&response, NuGetRegistryTier::Public, &public_policy()).unwrap();
        assert_eq!(
            index.registrations_base_url.as_deref(),
            Some("https://reg-semver2")
        );
    }

    #[test]
    fn test_service_index_resolve_registrations_base_url_falls_back_to_3_4_0() {
        let response: ServiceIndexResponse = serde_json::from_str(
            r#"{"version": "3.0.0", "resources": [
                {"@id": "https://flat/", "@type": "PackageBaseAddress/3.0.0"},
                {"@id": "https://search/", "@type": "SearchQueryService"},
                {"@id": "https://reg-semver1/", "@type": "RegistrationsBaseUrl/3.4.0"}
            ]}"#,
        )
        .unwrap();
        let index =
            ServiceIndex::resolve(&response, NuGetRegistryTier::Public, &public_policy()).unwrap();
        assert_eq!(
            index.registrations_base_url.as_deref(),
            Some("https://reg-semver1")
        );
    }

    #[test]
    fn test_service_index_resolve_registrations_base_url_absent_is_none() {
        let response: ServiceIndexResponse =
            serde_json::from_str(&service_index_body("https://flat/", "https://search/")).unwrap();
        let index =
            ServiceIndex::resolve(&response, NuGetRegistryTier::Public, &public_policy()).unwrap();
        assert!(index.registrations_base_url.is_none());
    }

    #[test]
    fn test_registration_index_url_lowercases_and_encodes() {
        assert_eq!(
            registration_index_url(
                "https://api.nuget.org/v3/registration5-gz-semver2",
                "Newtonsoft.Json"
            ),
            "https://api.nuget.org/v3/registration5-gz-semver2/newtonsoft.json/index.json"
        );
    }

    /// #365 regression sweep: exercises the real production `reject_dot_segment` gate and
    /// `registration_index_url` sink together against the shared adversarial input set,
    /// mirroring `test_flat_container_url_dot_segment_sweep` for the sibling sink (#380).
    #[test]
    fn test_registration_index_url_dot_segment_sweep() {
        deps_core::test_util::assert_dot_segment_gated_or_contained(
            |seg| {
                reject_dot_segment(seg).ok().map(|()| {
                    registration_index_url("https://api.nuget.org/v3/registration5-gz-semver2", seg)
                })
            },
            "api.nuget.org",
            "/v3/registration5-gz-semver2/",
        );
    }

    // --- attach_publish_times ---

    #[test]
    fn test_attach_publish_times_matches_by_version_string() {
        let mut versions = vec![v("1.0.0"), v("2.0.0")];
        let mut times = HashMap::new();
        times.insert(
            "1.0.0".to_string(),
            PublishTime::parse_rfc3339("2020-01-01T00:00:00Z").unwrap(),
        );
        attach_publish_times(&mut versions, &times);
        assert_eq!(
            versions[0].published_at,
            PublishTime::parse_rfc3339("2020-01-01T00:00:00Z")
        );
        assert_eq!(versions[1].published_at, None);
    }

    #[test]
    fn test_attach_publish_times_empty_map_leaves_all_none() {
        let mut versions = vec![v("1.0.0"), v("2.0.0")];
        attach_publish_times(&mut versions, &HashMap::new());
        assert!(versions.iter().all(|ver| ver.published_at.is_none()));
    }

    // --- registration_enrichment_from_index: pure fixtures, no network for inline pages ---

    fn inline_registration_index(base: &str, entries: &[(&str, Option<&str>)]) -> String {
        inline_registration_index_with_listed(
            base,
            &entries
                .iter()
                .map(|(v, p)| (*v, *p, None))
                .collect::<Vec<_>>(),
        )
    }

    fn inline_registration_index_with_listed(
        base: &str,
        entries: &[(&str, Option<&str>, Option<bool>)],
    ) -> String {
        let items: Vec<String> = entries
            .iter()
            .map(|(version, published, listed)| {
                let published_field = published
                    .map(|p| format!(r#", "published": "{p}""#))
                    .unwrap_or_default();
                let listed_field = listed
                    .map(|l| format!(r#", "listed": {l}"#))
                    .unwrap_or_default();
                format!(
                    r#"{{"catalogEntry": {{"version": "{version}"{published_field}{listed_field}}}}}"#
                )
            })
            .collect();
        format!(
            r#"{{"count": 1, "items": [{{"@id": "{base}/pkg/page/0.json", "count": {n}, "items": [{items}]}}]}}"#,
            n = entries.len(),
            items = items.join(",")
        )
    }

    #[tokio::test]
    async fn test_registration_enrichment_from_index_inline_happy_path() {
        let registry = NuGetRegistry::new(Arc::new(HttpCache::new()));
        let body = inline_registration_index(
            "https://api.nuget.org/v3/reg",
            &[
                ("1.0.0", Some("2020-01-01T00:00:00Z")),
                ("2.0.0", Some("2021-01-01T00:00:00Z")),
            ],
        );
        let enrichment = registry
            .registration_enrichment_from_index(body.as_bytes(), "https://api.nuget.org/v3/reg/")
            .await;
        assert_eq!(
            enrichment.published.get("2.0.0").copied(),
            PublishTime::parse_rfc3339("2021-01-01T00:00:00Z")
        );
        assert_eq!(enrichment.published.len(), 2);
        assert!(enrichment.unlisted.is_empty());
    }

    #[tokio::test]
    async fn test_registration_enrichment_from_index_sentinel_filtered() {
        let registry = NuGetRegistry::new(Arc::new(HttpCache::new()));
        let body = inline_registration_index(
            "https://api.nuget.org/v3/reg",
            &[
                ("1.0.0", Some("1900-01-01T00:00:00+00:00")),
                ("2.0.0", Some("2021-01-01T00:00:00Z")),
            ],
        );
        let enrichment = registry
            .registration_enrichment_from_index(body.as_bytes(), "https://api.nuget.org/v3/reg/")
            .await;
        assert!(!enrichment.published.contains_key("1.0.0"));
        assert!(enrichment.published.contains_key("2.0.0"));
    }

    /// D1/#451: a registration predating the `listed` field signals unlisted solely via the
    /// sentinel `published` epoch — the same entry `test_registration_enrichment_from_index_sentinel_filtered`
    /// already proves is excluded from `published`, but it must still land in `unlisted`.
    #[tokio::test]
    async fn test_registration_enrichment_from_index_legacy_sentinel_marks_unlisted() {
        let registry = NuGetRegistry::new(Arc::new(HttpCache::new()));
        let body = inline_registration_index(
            "https://api.nuget.org/v3/reg",
            &[
                ("1.0.0", Some("1900-01-01T00:00:00+00:00")),
                ("2.0.0", Some("2021-01-01T00:00:00Z")),
            ],
        );
        let enrichment = registry
            .registration_enrichment_from_index(body.as_bytes(), "https://api.nuget.org/v3/reg/")
            .await;
        assert!(enrichment.unlisted.contains("1.0.0"));
        assert!(!enrichment.unlisted.contains("2.0.0"));
    }

    /// D1/#451: a current registration signals unlisted via an explicit `"listed": false`,
    /// independent of `published` (which can be a perfectly ordinary, non-sentinel date).
    #[tokio::test]
    async fn test_registration_enrichment_from_index_explicit_listed_false_marks_unlisted() {
        let registry = NuGetRegistry::new(Arc::new(HttpCache::new()));
        let body = inline_registration_index_with_listed(
            "https://api.nuget.org/v3/reg",
            &[
                ("1.0.0", Some("2020-01-01T00:00:00Z"), Some(false)),
                ("2.0.0", Some("2021-01-01T00:00:00Z"), Some(true)),
            ],
        );
        let enrichment = registry
            .registration_enrichment_from_index(body.as_bytes(), "https://api.nuget.org/v3/reg/")
            .await;
        assert!(enrichment.unlisted.contains("1.0.0"));
        assert!(!enrichment.unlisted.contains("2.0.0"));
        // `listed: false` doesn't suppress an otherwise-valid publish date.
        assert!(enrichment.published.contains_key("1.0.0"));
    }

    #[tokio::test]
    async fn test_registration_enrichment_from_index_missing_published_is_absent_rest_intact() {
        let registry = NuGetRegistry::new(Arc::new(HttpCache::new()));
        let body = inline_registration_index(
            "https://api.nuget.org/v3/reg",
            &[("1.0.0", None), ("2.0.0", Some("2021-01-01T00:00:00Z"))],
        );
        let enrichment = registry
            .registration_enrichment_from_index(body.as_bytes(), "https://api.nuget.org/v3/reg/")
            .await;
        assert!(!enrichment.published.contains_key("1.0.0"));
        assert!(enrichment.published.contains_key("2.0.0"));
        // No `published` and no explicit `listed` is not itself an unlisted signal.
        assert!(!enrichment.unlisted.contains("1.0.0"));
    }

    #[tokio::test]
    async fn test_registration_enrichment_from_index_malformed_json_returns_empty() {
        let registry = NuGetRegistry::new(Arc::new(HttpCache::new()));
        let enrichment = registry
            .registration_enrichment_from_index(b"not json", "https://api.nuget.org/v3/reg/")
            .await;
        assert!(enrichment.published.is_empty());
        assert!(enrichment.unlisted.is_empty());
    }

    #[tokio::test]
    async fn test_registration_enrichment_from_index_foreign_origin_page_skipped_no_request() {
        // A page @id outside `base`'s origin must be skipped without ever being fetched —
        // if the implementation issued a real request here, this test would hang/fail on
        // network access rather than complete instantly.
        let registry = NuGetRegistry::new(Arc::new(HttpCache::new()));
        let body = r#"{"count": 1, "items": [
            {"@id": "https://evil.example/pkg/page/0.json", "count": 1}
        ]}"#;
        let enrichment = registry
            .registration_enrichment_from_index(body.as_bytes(), "https://api.nuget.org/v3/reg/")
            .await;
        assert!(enrichment.published.is_empty());
        assert!(enrichment.unlisted.is_empty());
    }

    #[tokio::test]
    async fn test_registration_enrichment_from_index_lookalike_origin_page_skipped_no_request() {
        // A prefix-lookalike host (`…nuget.org.evil.test`) must also be rejected — the
        // trailing-slash check in the trust boundary is what catches this.
        let registry = NuGetRegistry::new(Arc::new(HttpCache::new()));
        let body = r#"{"count": 1, "items": [
            {"@id": "https://api.nuget.org.evil.test/v3/reg/pkg/page/0.json", "count": 1}
        ]}"#;
        let enrichment = registry
            .registration_enrichment_from_index(body.as_bytes(), "https://api.nuget.org/v3/reg/")
            .await;
        assert!(enrichment.published.is_empty());
        assert!(enrichment.unlisted.is_empty());
    }

    // --- unlisted_versions_for_hover: end-to-end (mockito) ---

    #[tokio::test]
    async fn test_unlisted_versions_for_hover_reports_explicit_and_legacy_unlisted() {
        let mut server = mockito::Server::new_async().await;
        let base = server.url();

        let _service_index_mock = server
            .mock("GET", "/index.json")
            .with_status(200)
            .with_body(service_index_body_with_registrations(
                &format!("{base}/flatcontainer"),
                &format!("{base}/query"),
                &format!("{base}/registrations"),
            ))
            .create_async()
            .await;
        let registration_body = inline_registration_index_with_listed(
            &format!("{base}/registrations"),
            &[
                ("1.0.0", Some("1900-01-01T00:00:00+00:00"), None),
                ("2.0.0", Some("2021-01-01T00:00:00Z"), Some(false)),
                ("3.0.0", Some("2022-01-01T00:00:00Z"), Some(true)),
            ],
        );
        let _reg_mock = server
            .mock("GET", "/registrations/widget/index.json")
            .with_status(200)
            .with_body(registration_body)
            .create_async()
            .await;

        let registry = NuGetRegistry::with_service_index_url(
            Arc::new(HttpCache::new()),
            format!("{base}/index.json"),
        );
        let unlisted = registry
            .unlisted_versions_for_hover("widget")
            .await
            .unwrap();

        assert!(unlisted.contains("1.0.0"));
        assert!(unlisted.contains("2.0.0"));
        assert!(!unlisted.contains("3.0.0"));
    }

    #[tokio::test]
    async fn test_unlisted_versions_for_hover_no_registrations_base_url_degrades_to_empty() {
        let mut server = mockito::Server::new_async().await;
        let base = server.url();

        let _service_index_mock = server
            .mock("GET", "/index.json")
            .with_status(200)
            .with_body(service_index_body(
                &format!("{base}/flatcontainer"),
                &format!("{base}/query"),
            ))
            .create_async()
            .await;

        let registry = NuGetRegistry::with_service_index_url(
            Arc::new(HttpCache::new()),
            format!("{base}/index.json"),
        );
        let unlisted = registry
            .unlisted_versions_for_hover("widget")
            .await
            .unwrap();
        assert!(unlisted.is_empty());
    }

    #[tokio::test]
    async fn test_unlisted_versions_for_hover_fetch_failure_degrades_to_empty() {
        let mut server = mockito::Server::new_async().await;
        let base = server.url();

        let _service_index_mock = server
            .mock("GET", "/index.json")
            .with_status(200)
            .with_body(service_index_body_with_registrations(
                &format!("{base}/flatcontainer"),
                &format!("{base}/query"),
                &format!("{base}/registrations"),
            ))
            .create_async()
            .await;
        let _reg_mock = server
            .mock("GET", "/registrations/widget/index.json")
            .with_status(500)
            .create_async()
            .await;

        let registry = NuGetRegistry::with_service_index_url(
            Arc::new(HttpCache::new()),
            format!("{base}/index.json"),
        );
        let unlisted = registry
            .unlisted_versions_for_hover("widget")
            .await
            .unwrap();
        assert!(unlisted.is_empty());
    }

    #[tokio::test]
    async fn test_unlisted_versions_for_hover_rejects_bare_dot_dot_as_not_found() {
        let registry = NuGetRegistry::new(Arc::new(HttpCache::new()));
        let err = registry
            .unlisted_versions_for_hover("..")
            .await
            .unwrap_err();
        assert!(matches!(err, deps_core::DepsError::PackageNotFound { .. }));
    }

    // --- get_versions_typed_with: end-to-end gating and registration-hive walk (mockito) ---

    #[tokio::test]
    async fn test_get_versions_typed_with_disabled_issues_zero_registration_requests() {
        let mut server = mockito::Server::new_async().await;
        let base = server.url();

        let _service_index_mock = server
            .mock("GET", "/index.json")
            .with_status(200)
            .with_body(service_index_body_with_registrations(
                &format!("{base}/flatcontainer"),
                &format!("{base}/query"),
                &format!("{base}/registrations"),
            ))
            .create_async()
            .await;
        let _flat_mock = server
            .mock("GET", "/flatcontainer/widget/index.json")
            .with_status(200)
            .with_body(r#"{"versions": ["1.0.0", "2.0.0"]}"#)
            .create_async()
            .await;
        // No mock registered for /registrations/* — a request there would fail the test.

        let registry = NuGetRegistry::with_service_index_url(
            Arc::new(HttpCache::new()),
            format!("{base}/index.json"),
        );

        let versions = registry
            .get_versions_typed_with("widget", false)
            .await
            .unwrap();
        assert_eq!(versions.len(), 2);
        assert!(versions.iter().all(|v| v.published_at.is_none()));
    }

    #[tokio::test]
    async fn test_get_versions_typed_with_enabled_matches_disabled_set_and_order() {
        // FR-006 regression guard: enabling freshness must not change the returned list's
        // set or order, only populate `published_at`.
        let mut server = mockito::Server::new_async().await;
        let base = server.url();

        let _service_index_mock = server
            .mock("GET", "/index.json")
            .with_status(200)
            .with_body(service_index_body_with_registrations(
                &format!("{base}/flatcontainer"),
                &format!("{base}/query"),
                &format!("{base}/registrations"),
            ))
            .create_async()
            .await;
        let _flat_mock = server
            .mock("GET", "/flatcontainer/widget/index.json")
            .with_status(200)
            .with_body(r#"{"versions": ["1.0.0", "2.0.0"]}"#)
            .create_async()
            .await;
        let registration_body = inline_registration_index(
            &format!("{base}/registrations"),
            &[
                ("1.0.0", Some("2020-01-01T00:00:00Z")),
                ("2.0.0", Some("2021-01-01T00:00:00Z")),
            ],
        );
        let _reg_mock = server
            .mock("GET", "/registrations/widget/index.json")
            .with_status(200)
            .with_body(registration_body)
            .create_async()
            .await;

        let registry = NuGetRegistry::with_service_index_url(
            Arc::new(HttpCache::new()),
            format!("{base}/index.json"),
        );

        let disabled = registry
            .get_versions_typed_with("widget", false)
            .await
            .unwrap();
        let enabled = registry
            .get_versions_typed_with("widget", true)
            .await
            .unwrap();

        let disabled_strings: Vec<&str> = disabled.iter().map(|v| v.version.as_str()).collect();
        let enabled_strings: Vec<&str> = enabled.iter().map(|v| v.version.as_str()).collect();
        assert_eq!(disabled_strings, enabled_strings);
        assert!(enabled.iter().all(|v| v.published_at.is_some()));
    }

    #[tokio::test]
    async fn test_get_versions_typed_with_externalized_index_fetches_only_needed_pages() {
        let mut server = mockito::Server::new_async().await;
        let base = server.url();
        let reg_base = format!("{base}/registrations");

        let _service_index_mock = server
            .mock("GET", "/index.json")
            .with_status(200)
            .with_body(service_index_body_with_registrations(
                &format!("{base}/flatcontainer"),
                &format!("{base}/query"),
                &reg_base,
            ))
            .create_async()
            .await;
        let _flat_mock = server
            .mock("GET", "/flatcontainer/widget/index.json")
            .with_status(200)
            .with_body(r#"{"versions": ["9.0.0", "8.0.0", "7.0.0"]}"#)
            .create_async()
            .await;

        // Two external stub pages; only the last one (page 1) should ever be requested,
        // since it alone already covers >= HOVER_RECENT_VERSIONS entries.
        let index_body = format!(
            r#"{{"count": 2, "items": [
                {{"@id": "{reg_base}/widget/page/0.json", "count": 5}},
                {{"@id": "{reg_base}/widget/page/1.json", "count": 5}}
            ]}}"#
        );
        let _reg_mock = server
            .mock("GET", "/registrations/widget/index.json")
            .with_status(200)
            .with_body(index_body)
            .create_async()
            .await;

        // Page 1 alone carries HOVER_RECENT_VERSIONS (8) entries, so the walk must stop
        // here and never touch page 0.
        let page1_body = r#"{"items": [
            {"catalogEntry": {"version": "2.0.0", "published": "2015-01-01T00:00:00Z"}},
            {"catalogEntry": {"version": "3.0.0", "published": "2016-01-01T00:00:00Z"}},
            {"catalogEntry": {"version": "4.0.0", "published": "2017-01-01T00:00:00Z"}},
            {"catalogEntry": {"version": "5.0.0", "published": "2018-01-01T00:00:00Z"}},
            {"catalogEntry": {"version": "6.0.0", "published": "2019-01-01T00:00:00Z"}},
            {"catalogEntry": {"version": "7.0.0", "published": "2020-01-01T00:00:00Z"}},
            {"catalogEntry": {"version": "8.0.0", "published": "2021-01-01T00:00:00Z"}},
            {"catalogEntry": {"version": "9.0.0", "published": "2022-01-01T00:00:00Z"}}
        ]}"#;
        let page1_mock = server
            .mock("GET", "/registrations/widget/page/1.json")
            .with_status(200)
            .with_body(page1_body)
            .expect(1)
            .create_async()
            .await;
        let page0_mock = server
            .mock("GET", "/registrations/widget/page/0.json")
            .with_status(200)
            .with_body(r#"{"items": []}"#)
            .expect(0)
            .create_async()
            .await;

        let registry = NuGetRegistry::with_service_index_url(
            Arc::new(HttpCache::new()),
            format!("{base}/index.json"),
        );
        let versions = registry
            .get_versions_typed_with("widget", true)
            .await
            .unwrap();

        assert_eq!(versions.len(), 3);
        assert!(versions.iter().all(|v| v.published_at.is_some()));
        page1_mock.assert_async().await;
        page0_mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_get_versions_typed_with_external_fetch_cap_stops_walk_at_two_pages() {
        // Tester gap: MAX_EXTERNAL_PAGE_FETCHES = 2 was never actually hit by any prior
        // test. Three external pages, each carrying too few entries to reach
        // HOVER_RECENT_VERSIONS alone or even combined two-at-a-time, so the walk must stop
        // after exactly 2 external fetches (pages 2 and 1) and never touch page 0 — proving
        // the cap terminates the walk rather than the count or exhaustion terminators.
        let mut server = mockito::Server::new_async().await;
        let base = server.url();
        let reg_base = format!("{base}/registrations");

        let _service_index_mock = server
            .mock("GET", "/index.json")
            .with_status(200)
            .with_body(service_index_body_with_registrations(
                &format!("{base}/flatcontainer"),
                &format!("{base}/query"),
                &reg_base,
            ))
            .create_async()
            .await;
        let _flat_mock = server
            .mock("GET", "/flatcontainer/widget/index.json")
            .with_status(200)
            .with_body(r#"{"versions": ["6.0.0", "5.0.0", "4.0.0", "3.0.0", "2.0.0", "1.0.0"]}"#)
            .create_async()
            .await;

        let index_body = format!(
            r#"{{"count": 3, "items": [
                {{"@id": "{reg_base}/widget/page/0.json", "count": 2}},
                {{"@id": "{reg_base}/widget/page/1.json", "count": 2}},
                {{"@id": "{reg_base}/widget/page/2.json", "count": 2}}
            ]}}"#
        );
        let _reg_mock = server
            .mock("GET", "/registrations/widget/index.json")
            .with_status(200)
            .with_body(index_body)
            .create_async()
            .await;

        let page2_body = r#"{"items": [
            {"catalogEntry": {"version": "5.0.0", "published": "2021-01-01T00:00:00Z"}},
            {"catalogEntry": {"version": "6.0.0", "published": "2022-01-01T00:00:00Z"}}
        ]}"#;
        let page2_mock = server
            .mock("GET", "/registrations/widget/page/2.json")
            .with_status(200)
            .with_body(page2_body)
            .expect(1)
            .create_async()
            .await;

        let page1_body = r#"{"items": [
            {"catalogEntry": {"version": "3.0.0", "published": "2019-01-01T00:00:00Z"}},
            {"catalogEntry": {"version": "4.0.0", "published": "2020-01-01T00:00:00Z"}}
        ]}"#;
        let page1_mock = server
            .mock("GET", "/registrations/widget/page/1.json")
            .with_status(200)
            .with_body(page1_body)
            .expect(1)
            .create_async()
            .await;

        // Only 4 entries collected across the two allowed external fetches (< 8), so a
        // buggy implementation would keep walking into page 0. This mock must see zero hits.
        let page0_mock = server
            .mock("GET", "/registrations/widget/page/0.json")
            .with_status(200)
            .with_body(
                r#"{"items": [
                {"catalogEntry": {"version": "1.0.0", "published": "2017-01-01T00:00:00Z"}},
                {"catalogEntry": {"version": "2.0.0", "published": "2018-01-01T00:00:00Z"}}
            ]}"#,
            )
            .expect(0)
            .create_async()
            .await;

        let registry = NuGetRegistry::with_service_index_url(
            Arc::new(HttpCache::new()),
            format!("{base}/index.json"),
        );
        let versions = registry
            .get_versions_typed_with("widget", true)
            .await
            .unwrap();

        assert_eq!(versions.len(), 6);
        // Only the 4 versions covered by the two allowed external pages got a date.
        for v in ["3.0.0", "4.0.0", "5.0.0", "6.0.0"] {
            assert!(
                versions
                    .iter()
                    .find(|ver| ver.version == v)
                    .unwrap()
                    .published_at
                    .is_some(),
                "{v} should have a published_at"
            );
        }
        for v in ["1.0.0", "2.0.0"] {
            assert!(
                versions
                    .iter()
                    .find(|ver| ver.version == v)
                    .unwrap()
                    .published_at
                    .is_none(),
                "{v} is beyond the external-fetch cap and must have no published_at"
            );
        }
        page2_mock.assert_async().await;
        page1_mock.assert_async().await;
        page0_mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_get_versions_typed_with_single_version_package_terminates() {
        // S3 regression: a package with fewer total versions than HOVER_RECENT_VERSIONS
        // must terminate via index exhaustion rather than hanging or looping.
        let mut server = mockito::Server::new_async().await;
        let base = server.url();

        let _service_index_mock = server
            .mock("GET", "/index.json")
            .with_status(200)
            .with_body(service_index_body_with_registrations(
                &format!("{base}/flatcontainer"),
                &format!("{base}/query"),
                &format!("{base}/registrations"),
            ))
            .create_async()
            .await;
        let _flat_mock = server
            .mock("GET", "/flatcontainer/orchard.core/index.json")
            .with_status(200)
            .with_body(r#"{"versions": ["1.0.0"]}"#)
            .create_async()
            .await;
        let registration_body = inline_registration_index(
            &format!("{base}/registrations"),
            &[("1.0.0", Some("2020-01-01T00:00:00Z"))],
        );
        let _reg_mock = server
            .mock("GET", "/registrations/orchard.core/index.json")
            .with_status(200)
            .with_body(registration_body)
            .create_async()
            .await;

        let registry = NuGetRegistry::with_service_index_url(
            Arc::new(HttpCache::new()),
            format!("{base}/index.json"),
        );
        let versions = registry
            .get_versions_typed_with("orchard.core", true)
            .await
            .unwrap();

        assert_eq!(versions.len(), 1);
        assert!(versions[0].published_at.is_some());
    }

    #[tokio::test]
    async fn test_get_versions_typed_with_no_registrations_base_url_degrades_gracefully() {
        let mut server = mockito::Server::new_async().await;
        let base = server.url();

        let _service_index_mock = server
            .mock("GET", "/index.json")
            .with_status(200)
            .with_body(service_index_body(
                &format!("{base}/flatcontainer"),
                &format!("{base}/query"),
            ))
            .create_async()
            .await;
        let _flat_mock = server
            .mock("GET", "/flatcontainer/widget/index.json")
            .with_status(200)
            .with_body(r#"{"versions": ["1.0.0"]}"#)
            .create_async()
            .await;

        let registry = NuGetRegistry::with_service_index_url(
            Arc::new(HttpCache::new()),
            format!("{base}/index.json"),
        );
        let versions = registry
            .get_versions_typed_with("widget", true)
            .await
            .unwrap();

        assert_eq!(versions.len(), 1);
        assert!(versions[0].published_at.is_none());
    }

    // --- NFR-006 live verification (real network, run explicitly with `--ignored`) ---

    #[tokio::test]
    #[ignore]
    async fn test_live_nuget_attaches_publish_times() {
        let registry = NuGetRegistry::new(Arc::new(HttpCache::new()));
        let versions = registry
            .get_versions_typed_with("Newtonsoft.Json", true)
            .await
            .unwrap();

        assert!(!versions.is_empty());
        assert!(versions.iter().take(5).any(|v| v.published_at.is_some()));
    }

    // --- get_versions_chained: 3-way failure taxonomy (tester gap #1) ---

    fn all_policy() -> Arc<RegistryAccessPolicy> {
        Arc::new(RegistryAccessPolicy::new(
            deps_core::net_policy::WorkspaceRegistryAccess::All,
        ))
    }

    fn workspace_client(base: &str, policy: &Arc<RegistryAccessPolicy>) -> NuGetRegistry {
        let feed = NuGetFeedUrl::new(&format!("{base}/index.json"), policy).unwrap();
        NuGetRegistry::with_base(
            Arc::new(HttpCache::new()),
            &feed,
            Arc::clone(policy),
            Vec::new(),
        )
    }

    #[tokio::test]
    async fn test_get_versions_chained_falls_through_on_package_not_found() {
        let mut hop0 = mockito::Server::new_async().await;
        let hop0_index = hop0
            .mock("GET", "/index.json")
            .with_status(200)
            .with_body(service_index_body(
                &format!("{}/flat", hop0.url()),
                &format!("{}/search", hop0.url()),
            ))
            .create_async()
            .await;
        let hop0_flat = hop0
            .mock("GET", "/flat/pkg/index.json")
            .with_status(404)
            .create_async()
            .await;

        let mut hop1 = mockito::Server::new_async().await;
        let hop1_index = hop1
            .mock("GET", "/index.json")
            .with_status(200)
            .with_body(service_index_body(
                &format!("{}/flat", hop1.url()),
                &format!("{}/search", hop1.url()),
            ))
            .create_async()
            .await;
        let hop1_flat = hop1
            .mock("GET", "/flat/pkg/index.json")
            .with_status(200)
            .with_body(r#"{"versions": ["2.0.0"]}"#)
            .create_async()
            .await;

        let policy = all_policy();
        let cache = Arc::new(HttpCache::new());
        let hop1_feed = NuGetFeedUrl::new(&format!("{}/index.json", hop1.url()), &policy).unwrap();
        let hop1_client = Arc::new(NuGetRegistry::with_base(
            Arc::clone(&cache),
            &hop1_feed,
            Arc::clone(&policy),
            Vec::new(),
        ));
        let hop0_feed = NuGetFeedUrl::new(&format!("{}/index.json", hop0.url()), &policy).unwrap();
        let head =
            NuGetRegistry::with_base(cache, &hop0_feed, Arc::clone(&policy), vec![hop1_client]);

        let versions = head.get_versions_chained("pkg").await.unwrap();
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0].version.as_str(), "2.0.0");

        hop0_index.assert_async().await;
        hop0_flat.assert_async().await;
        hop1_index.assert_async().await;
        hop1_flat.assert_async().await;
    }

    #[tokio::test]
    async fn test_get_versions_chained_falls_through_on_empty_listing() {
        let mut hop0 = mockito::Server::new_async().await;
        hop0.mock("GET", "/index.json")
            .with_status(200)
            .with_body(service_index_body(
                &format!("{}/flat", hop0.url()),
                &format!("{}/search", hop0.url()),
            ))
            .create_async()
            .await;
        hop0.mock("GET", "/flat/pkg/index.json")
            .with_status(200)
            .with_body(r#"{"versions": []}"#)
            .create_async()
            .await;

        let mut hop1 = mockito::Server::new_async().await;
        hop1.mock("GET", "/index.json")
            .with_status(200)
            .with_body(service_index_body(
                &format!("{}/flat", hop1.url()),
                &format!("{}/search", hop1.url()),
            ))
            .create_async()
            .await;
        hop1.mock("GET", "/flat/pkg/index.json")
            .with_status(200)
            .with_body(r#"{"versions": ["3.0.0"]}"#)
            .create_async()
            .await;

        let policy = all_policy();
        let cache = Arc::new(HttpCache::new());
        let hop1_client = Arc::new(workspace_client(&hop1.url(), &policy));
        let head = {
            let feed = NuGetFeedUrl::new(&format!("{}/index.json", hop0.url()), &policy).unwrap();
            NuGetRegistry::with_base(cache, &feed, Arc::clone(&policy), vec![hop1_client])
        };

        let versions = head.get_versions_chained("pkg").await.unwrap();
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0].version.as_str(), "3.0.0");
    }

    /// A terminal transport error on hop 0 halts the chain — hop 1's `.expect(0)` mock fails
    /// the test if the chain wrongly fell through instead.
    #[tokio::test]
    async fn test_get_versions_chained_terminates_on_transport_error_never_tries_next_hop() {
        let mut hop0 = mockito::Server::new_async().await;
        hop0.mock("GET", "/index.json")
            .with_status(200)
            .with_body(service_index_body(
                &format!("{}/flat", hop0.url()),
                &format!("{}/search", hop0.url()),
            ))
            .create_async()
            .await;
        hop0.mock("GET", "/flat/pkg/index.json")
            .with_status(503)
            .create_async()
            .await;

        let mut hop1 = mockito::Server::new_async().await;
        let hop1_flat = hop1
            .mock("GET", "/flat/pkg/index.json")
            .expect(0)
            .create_async()
            .await;

        let policy = all_policy();
        let cache = Arc::new(HttpCache::new());
        let hop1_client = Arc::new(workspace_client(&hop1.url(), &policy));
        let head = {
            let feed = NuGetFeedUrl::new(&format!("{}/index.json", hop0.url()), &policy).unwrap();
            NuGetRegistry::with_base(cache, &feed, Arc::clone(&policy), vec![hop1_client])
        };

        let err = head.get_versions_chained("pkg").await.unwrap_err();
        assert!(
            matches!(err, DepsError::ChainResolutionHalted),
            "expected ChainResolutionHalted, got: {err:?}"
        );
        hop1_flat.assert_async().await;
    }

    // --- register_chain: multi-hop fallback_chain construction (tester gap #2) ---

    /// End-to-end proof that `register_chain` wires a 2-declared-hop chain plus the
    /// implicit-public-fallback hop into a working, positionally-ordered `fallback_chain`:
    /// hop 0 misses, hop 1 misses, the implicit public hop (root's own service index)
    /// succeeds — every prior test registers only single-hop chains.
    #[tokio::test]
    async fn test_register_chain_multi_hop_fallback_chain_walks_every_hop_in_order() {
        let mut hop0 = mockito::Server::new_async().await;
        hop0.mock("GET", "/index.json")
            .with_status(200)
            .with_body(service_index_body(
                &format!("{}/flat", hop0.url()),
                &format!("{}/search", hop0.url()),
            ))
            .create_async()
            .await;
        hop0.mock("GET", "/flat/pkg/index.json")
            .with_status(404)
            .create_async()
            .await;

        let mut hop1 = mockito::Server::new_async().await;
        hop1.mock("GET", "/index.json")
            .with_status(200)
            .with_body(service_index_body(
                &format!("{}/flat", hop1.url()),
                &format!("{}/search", hop1.url()),
            ))
            .create_async()
            .await;
        hop1.mock("GET", "/flat/pkg/index.json")
            .with_status(404)
            .create_async()
            .await;

        let mut public = mockito::Server::new_async().await;
        public
            .mock("GET", "/index.json")
            .with_status(200)
            .with_body(service_index_body(
                &format!("{}/flat", public.url()),
                &format!("{}/search", public.url()),
            ))
            .create_async()
            .await;
        public
            .mock("GET", "/flat/pkg/index.json")
            .with_status(200)
            .with_body(r#"{"versions": ["9.0.0"]}"#)
            .create_async()
            .await;

        let policy = all_policy();
        let cache = Arc::new(HttpCache::new());
        let root = Arc::new(NuGetRegistry::with_service_index_url(
            Arc::clone(&cache),
            format!("{}/index.json", public.url()),
        ));

        let hop0_feed = NuGetFeedUrl::new(&format!("{}/index.json", hop0.url()), &policy).unwrap();
        let hop1_feed = NuGetFeedUrl::new(&format!("{}/index.json", hop1.url()), &policy).unwrap();
        let chain = NuGetSourceChain {
            key: "nuget-chain:test-multi-hop".to_string(),
            hops: vec![hop0_feed, hop1_feed],
            implicit_public_fallback: true,
        };
        NuGetRegistry::register_chain(&root, &chain, &policy);

        let client = root
            .alternate_client(&chain.key)
            .expect("chain must be registered");
        assert_eq!(
            client.fallback_chain.len(),
            2,
            "expected [hop1, implicit-public] in the head's fallback_chain"
        );

        let versions = client.get_versions_chained("pkg").await.unwrap();
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0].version.as_str(), "9.0.0");
    }
}
