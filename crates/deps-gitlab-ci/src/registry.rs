//! `GitlabCiRegistry` — the `deps_core::Registry` implementation for GitLab CI.
//!
//! Routes every dependency against its `(host, endpoint)` route (spec §7a), a process-wide
//! route table capped at [`MAX_GITLAB_ROUTES`] (spec §4.6), and a per-host rate-limit gate
//! (spec §9.3).

use dashmap::DashMap;
use deps_core::error::{DepsError, Result};
use deps_core::github::normalize_tag;
use deps_core::{PackageName, PublishTime};
use std::any::Any;
use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::client::{
    GitlabApiClient, GitlabRelease, GitlabTag, MAX_GITLAB_PAGES, gitlab_rate_limit_error,
    parse_releases_page, parse_tags_page,
};
use crate::host::GitlabHost;
use crate::types::{EndpointKind, GitlabCiVersion, GitlabRoute, PinStyle};

/// Display name for the registry backing GitLab CI version lookups.
pub const REGISTRY: &str = "GitLab";

/// Upper bound on [`GitlabCiRegistry::routes`]' entry count.
///
/// Mirrors `deps_go::registry::MAX_ALTERNATE_REGISTRIES` exactly, including its core
/// semantics: at capacity a *new* route is simply never registered. Since a route is
/// `(origin, endpoint)`, this bounds distinct origins at 256 too — the same ceiling
/// `deps-nuget` already imposes on `HttpCache::trusted_clients` growth.
pub const MAX_GITLAB_ROUTES: usize = 256;

/// How long [`RateLimitGate`] keeps a host's fetches short-circuiting locally after a
/// rate-limited/untokened-auth-failure response, before allowing another live request.
const RATE_LIMIT_COOLDOWN_SECS: u64 = 300;

fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Per-host (not process-wide, spec §9.3) gate: one self-hosted instance rate-limiting must
/// not disable lookups against `gitlab.com` or any other host.
#[derive(Debug, Default)]
struct RateLimitGate {
    reset_at: AtomicU64,
}

impl RateLimitGate {
    fn is_tripped(&self) -> bool {
        let reset_at = self.reset_at.load(Ordering::Relaxed);
        reset_at != 0 && now_epoch_secs() < reset_at
    }

    fn trip(&self) {
        self.reset_at.store(
            now_epoch_secs() + RATE_LIMIT_COOLDOWN_SECS,
            Ordering::Relaxed,
        );
    }
}

/// Per-`(endpoint, name)` tag/release-name -> commit-SHA cross-reference.
///
/// Mirrors `deps_github_actions::registry::TagIndex` in shape — lets a SHA pin render a
/// readable `**Resolved**` hover line, and lets a `PinStyle::Tag` pin render a "Pin to
/// commit SHA" quickfix (issue #634). Populated from whichever endpoint the route used: tag
/// names for `project:`, release names for `component:`.
///
/// Keyed by `(EndpointKind, PackageName)`, not `PackageName` alone (validation finding S2,
/// see [`crate::types::IncludeKind::endpoint`]'s doc): a `component:`'s host-qualified name
/// can textually collide with an unrelated `project:` include's own name, and a
/// `PackageName`-only key would let the two share one entry — resolving a quickfix's SHA
/// from the wrong repository.
#[derive(Debug, Default)]
pub struct TagIndex {
    pub tag_to_sha: std::collections::HashMap<String, String>,
    pub sha_to_tag: std::collections::HashMap<String, String>,
}

/// Maximum number of [`GitlabCiRegistry::tag_index`] entries.
const MAX_TAG_INDEX_ENTRIES: usize = 256;

fn evict_if_full<K: std::hash::Hash + Eq + Clone, V>(map: &DashMap<K, V>, max_entries: usize) {
    if map.len() < max_entries {
        return;
    }
    let victim = map.iter().next().map(|e| e.key().clone());
    if let Some(key) = victim {
        map.remove(&key);
    }
}

/// Populates one `TagIndex` entry from raw `(name, sha)` pairs — independent of whatever
/// semver filter the caller's own version-list conversion (`tags_to_versions`) applies.
///
/// A non-semver-shaped tag (e.g. a literal tool-name tag like `cargo-deny`, or a bare-major
/// moving tag) would otherwise never reach a `TagIndex` entry for a `project:` include,
/// since `tags_to_versions` silently drops anything that doesn't parse as a full
/// `major.minor.patch` semver — making the registry-confirmed-`PinStyle::Branch` diagnostic
/// path (issue #551's discipline) and any future SHA-pin quickfix widening unreachable in
/// production for such a tag (validation finding C1). Mirrors
/// `deps_github_actions::registry::GithubActionsRegistry::populate_tag_index`'s identical
/// "index straight from the raw response" fix for the same class of bug. Still gated on
/// [`deps_core::lsp_helpers::is_full_sha`] (security S-3): the SHA is later spliced
/// verbatim into a manifest text edit and a hover string.
pub(crate) fn populate_tag_index_entries<'a>(
    index: &DashMap<(EndpointKind, PackageName), Arc<TagIndex>>,
    key: (EndpointKind, PackageName),
    entries: impl Iterator<Item = (&'a str, &'a str)>,
) {
    let mut built = TagIndex::default();
    for (name, sha) in entries {
        if !deps_core::lsp_helpers::is_full_sha(sha) {
            continue;
        }
        built
            .sha_to_tag
            .entry(sha.to_string())
            .or_insert_with(|| name.to_string());
        built
            .tag_to_sha
            .entry(name.to_string())
            .or_insert_with(|| sha.to_string());
    }
    if !index.contains_key(&key) {
        evict_if_full(index, MAX_TAG_INDEX_ENTRIES);
    }
    index.insert(key, Arc::new(built));
}

/// Converts a fetched tags page into a newest-first, semver-filtered version list.
///
/// Drops any tag whose `commit.id` is not a full 40-hex SHA (security S-3 precedent from
/// `deps-github-actions`): a `GitlabCiVersion`'s `sha` is later spliced verbatim into hover
/// text.
fn tags_to_versions(tags: Vec<GitlabTag>) -> Vec<GitlabCiVersion> {
    let mut seen = HashSet::new();
    let mut with_parsed: Vec<(GitlabCiVersion, semver::Version)> = tags
        .into_iter()
        .filter_map(|tag| {
            if !deps_core::lsp_helpers::is_full_sha(&tag.commit.id) {
                return None;
            }
            let normalized = normalize_tag(&tag.name).to_string();
            let parsed = semver::Version::parse(&normalized).ok()?;
            if !seen.insert(normalized) {
                return None;
            }
            let prerelease = !parsed.pre.is_empty();
            Some((
                GitlabCiVersion {
                    version: tag.name.into(),
                    sha: tag.commit.id,
                    prerelease,
                    published_at: None,
                },
                parsed,
            ))
        })
        .collect();
    with_parsed.sort_unstable_by(|a, b| b.1.cmp(&a.1));
    with_parsed.into_iter().map(|(v, _)| v).collect()
}

/// Converts a fetched releases page into a version list — deliberately **not**
/// semver-filtered, unlike [`tags_to_versions`]: [`crate::component::resolve_component_pin`]'s
/// exact-match/branch step (FR-007) must be able to match a release whose name doesn't look
/// like a version at all (e.g. a release literally named `stable`), so every release with a
/// valid commit SHA is kept. Semver-parseable entries sort newest-first; non-parseable ones
/// keep their release-date-descending fetch order and sort after (stable sort).
fn releases_to_versions(releases: Vec<GitlabRelease>) -> Vec<GitlabCiVersion> {
    let mut versions: Vec<GitlabCiVersion> = releases
        .into_iter()
        .filter_map(|r| {
            if !deps_core::lsp_helpers::is_full_sha(&r.commit.id) {
                return None;
            }
            let published_at = r
                .released_at
                .as_deref()
                .and_then(PublishTime::parse_rfc3339);
            let prerelease =
                semver::Version::parse(normalize_tag(&r.tag_name)).is_ok_and(|v| !v.pre.is_empty());
            Some(GitlabCiVersion {
                version: r.tag_name.into(),
                sha: r.commit.id,
                prerelease,
                published_at,
            })
        })
        .collect();

    versions.sort_by(|a, b| {
        match (
            semver::Version::parse(normalize_tag(a.version.as_str())),
            semver::Version::parse(normalize_tag(b.version.as_str())),
        ) {
            (Ok(pa), Ok(pb)) => pb.cmp(&pa),
            (Ok(_), Err(_)) => std::cmp::Ordering::Less,
            (Err(_), Ok(_)) => std::cmp::Ordering::Greater,
            (Err(_), Err(_)) => std::cmp::Ordering::Equal,
        }
    });
    versions
}

/// Derives `project_path` (and, for a [`EndpointKind::Releases`] route, strips the trailing
/// component-name segment) from a host-qualified `name` (spec §3.1) and the route's bare
/// host.
fn project_path_from_name(name: &str, host_bare: &str, endpoint: EndpointKind) -> Option<String> {
    let remainder = name.strip_prefix(host_bare)?.strip_prefix('/')?;
    match endpoint {
        EndpointKind::Tags => Some(remainder.to_string()),
        EndpointKind::Releases => remainder
            .rsplit_once('/')
            .map(|(path, _component)| path.to_string()),
    }
}

/// `deps_core::Registry` implementation for GitLab CI, routing every fetch across the
/// registered `(host, endpoint)` table (spec §7a).
#[derive(Clone)]
pub struct GitlabCiRegistry {
    client: Arc<GitlabApiClient>,
    routes: Arc<DashMap<String, GitlabRoute>>,
    rate_limits: Arc<DashMap<String, Arc<RateLimitGate>>>,
    tag_index: Arc<DashMap<(EndpointKind, PackageName), Arc<TagIndex>>>,
}

impl GitlabCiRegistry {
    /// Creates a new registry sharing `client`.
    #[must_use]
    pub fn new(client: Arc<GitlabApiClient>) -> Self {
        Self {
            client,
            routes: Arc::new(DashMap::new()),
            rate_limits: Arc::new(DashMap::new()),
            tag_index: Arc::new(DashMap::new()),
        }
    }

    /// Shares this registry's [`TagIndex`] map with [`crate::formatter::GitlabCiFormatter`].
    #[must_use]
    pub fn tag_index(&self) -> Arc<DashMap<(EndpointKind, PackageName), Arc<TagIndex>>> {
        Arc::clone(&self.tag_index)
    }

    /// Shares this registry's route table with [`crate::formatter::GitlabCiFormatter`],
    /// which needs it to distinguish a `project:` (Tags) route from a `component:`
    /// (Releases) route for the hover-heading-link carve-out (spec §8.2).
    #[must_use]
    pub fn routes(&self) -> Arc<DashMap<String, GitlabRoute>> {
        Arc::clone(&self.routes)
    }

    /// Registers every `(route_key, route)` pair in `routes` (idempotent per key), capacity-
    /// capped at [`MAX_GITLAB_ROUTES`], and returns the set of `route_key`s that were
    /// refused because the cap was already reached (spec §3.2/§4.6's downgrade pass —
    /// `GitlabCiEcosystem::parse_manifest` rewrites every dependency carrying a refused key
    /// to `CustomRegistry` + `HostRef::Unresolved` before returning the parse result).
    pub fn register_routes(&self, routes: &[(String, GitlabRoute)]) -> HashSet<String> {
        let mut refused = HashSet::new();
        let mut warned_once = false;
        for (key, route) in routes {
            if self.routes.contains_key(key) {
                continue;
            }
            if self.routes.len() >= MAX_GITLAB_ROUTES {
                if !warned_once {
                    tracing::warn!(
                        cap = MAX_GITLAB_ROUTES,
                        "GitLab CI route cap reached; not registering further routes"
                    );
                    warned_once = true;
                }
                refused.insert(key.clone());
                continue;
            }
            self.routes.insert(key.clone(), route.clone());
        }
        refused
    }

    fn rate_limit_gate(&self, origin: &str) -> Arc<RateLimitGate> {
        if let Some(existing) = self.rate_limits.get(origin) {
            return Arc::clone(&existing);
        }
        Arc::clone(
            self.rate_limits
                .entry(origin.to_string())
                .or_insert_with(|| Arc::new(RateLimitGate::default()))
                .value(),
        )
    }

    /// Maps a raw fetch error to its `DepsError` classification (spec §9.3 — GitLab's status
    /// semantics differ from GitHub's, so this is not a verbatim copy of
    /// `GithubActionsRegistry::map_tags_error`'s arms) and, for a `429` or an untokened
    /// `401`/`403`, trips `origin`'s rate-limit gate so every other dependency on the same
    /// host short-circuits locally instead of also firing (and losing) its own doomed
    /// request.
    ///
    /// H3 (#466 review): a bare `400` reaching this point means
    /// [`crate::client::GitlabApiClient::fetch_tags_page`]'s own `order_by=version` fallback
    /// (which now covers every page, not just the first) still didn't resolve it — some
    /// other client-side request defect (an unroutable/malformed project path). Classified as
    /// [`DepsError::PackageNotFound`], the same graceful, actionable outcome a `404` already
    /// gets, rather than an opaque transport error that aborts the whole version list.
    fn map_error(&self, origin: &str, name: &str, e: DepsError) -> DepsError {
        match &e {
            DepsError::HttpStatus { status: 429, .. } => {
                self.rate_limit_gate(origin).trip();
                gitlab_rate_limit_error()
            }
            // A *tokened* 401/403 is scoped to this one project (private/insufficient-scope),
            // not treated as a workspace-wide outage — mirrors
            // `deps_github_actions::registry::GithubActionsRegistry::map_tags_error`'s
            // identical `has_token()` split.
            DepsError::HttpStatus {
                status: 401 | 403, ..
            } if !self.client.has_token() => {
                self.rate_limit_gate(origin).trip();
                gitlab_rate_limit_error()
            }
            DepsError::HttpStatus {
                status: 404 | 400, ..
            } => DepsError::PackageNotFound {
                package: name.to_string(),
                registry: REGISTRY,
            },
            _ => e,
        }
    }

    /// Fetches and converts the version list for `name` via `route`, gated by the route's
    /// origin-scoped rate-limit gate.
    async fn fetch_route(
        &self,
        name: &PackageName,
        route: &GitlabRoute,
    ) -> Result<Vec<GitlabCiVersion>> {
        let gate = self.rate_limit_gate(&route.origin);
        if gate.is_tripped() {
            return Err(gitlab_rate_limit_error());
        }

        let host = GitlabHost::trusted(&route.origin);
        let Some(project_path) = project_path_from_name(name.as_str(), host.host(), route.endpoint)
        else {
            return Err(DepsError::PackageNotFound {
                package: name.to_string(),
                registry: REGISTRY,
            });
        };

        let versions = match route.endpoint {
            EndpointKind::Tags => {
                let client = &self.client;
                let path = project_path.as_str();
                let tags = deps_core::pagination::paginate_pages(
                    "GitLab",
                    "GitLab CI",
                    "tags",
                    name.as_str(),
                    MAX_GITLAB_PAGES,
                    |page| client.fetch_tags_page(&host, path, page),
                    |data| parse_tags_page(data),
                )
                .await
                .map_err(|e| self.map_error(&route.origin, name.as_str(), e))?;
                // C1 (validation finding): index straight from the raw, unfiltered `tags`
                // response, not `tags_to_versions`' semver-filtered output — see
                // `populate_tag_index_entries`'s doc.
                populate_tag_index_entries(
                    &self.tag_index,
                    (EndpointKind::Tags, name.clone()),
                    tags.iter().map(|t| (t.name.as_str(), t.commit.id.as_str())),
                );
                tags_to_versions(tags)
            }
            EndpointKind::Releases => {
                let client = &self.client;
                let path = project_path.as_str();
                let releases = deps_core::pagination::paginate_pages(
                    "GitLab",
                    "GitLab CI",
                    "releases",
                    name.as_str(),
                    MAX_GITLAB_PAGES,
                    |page| client.fetch_releases_page(&host, path, page),
                    |data| parse_releases_page(data),
                )
                .await
                .map_err(|e| self.map_error(&route.origin, name.as_str(), e))?;
                // `releases_to_versions` never drops an entry on shape grounds (unlike
                // `tags_to_versions`), so this is not affected by C1 — kept symmetric with
                // the Tags arm anyway, and keyed by `EndpointKind::Releases` (S2 fix).
                populate_tag_index_entries(
                    &self.tag_index,
                    (EndpointKind::Releases, name.clone()),
                    releases
                        .iter()
                        .map(|r| (r.tag_name.as_str(), r.commit.id.as_str())),
                );
                releases_to_versions(releases)
            }
        };

        Ok(versions)
    }

    /// Resolves a `component:` include's already-classified pin against `route`'s
    /// published releases via spec FR-007's priority ladder
    /// ([`crate::component::resolve_component_pin`]) — H1 (#466 review): this is the real
    /// production call path that ladder was missing; previously it was exercised only by its
    /// own unit tests.
    ///
    /// Fetches (and caches, via the same `Self::fetch_route` path `get_versions_from`
    /// uses) `route`'s full release list, never the raw tag list (FR-004/FR-007) — an
    /// unreleased tag is not a usable component version. `route.endpoint` is expected to be
    /// [`EndpointKind::Releases`]; called with a [`EndpointKind::Tags`] route this still
    /// returns a result (the shared ladder degrades to its `Sha`/`Tag`/`Branch` arms, which
    /// are valid for a tag list too), but callers only need it for `component:` includes —
    /// a `project:` include's SHA pin already resolves via [`Self::tag_index`] with no extra
    /// fetch.
    ///
    /// # Errors
    ///
    /// Propagates the underlying fetch error unchanged (rate limit, not-found, etc).
    pub async fn resolve_component_pin(
        &self,
        name: &PackageName,
        route: &GitlabRoute,
        pin: &PinStyle,
        raw: &str,
    ) -> Result<Option<GitlabCiVersion>> {
        let releases = self.fetch_route(name, route).await?;
        Ok(crate::component::resolve_component_pin(pin, raw, &releases))
    }
}

impl deps_core::Registry for GitlabCiRegistry {
    /// Unconditional [`DepsError::PackageNotFound`], never a host guess (spec §7a) — this
    /// crate's dependencies are only ever routable via `get_versions_from`'s
    /// `AlternateRegistry` dispatch; a `&PackageName` alone carries no host.
    fn get_versions<'a>(
        &'a self,
        name: &'a PackageName,
    ) -> deps_core::ecosystem::BoxFuture<'a, Result<Vec<Box<dyn deps_core::Version>>>> {
        Box::pin(async move {
            Err(DepsError::PackageNotFound {
                package: name.to_string(),
                registry: "gitlab-ci (no route; source required)",
            })
        })
    }

    fn get_versions_from<'a>(
        &'a self,
        name: &'a PackageName,
        source: &'a deps_core::parser::DependencySource,
        _freshness: deps_core::FreshnessSettings,
    ) -> deps_core::ecosystem::BoxFuture<'a, Result<Vec<Box<dyn deps_core::Version>>>> {
        Box::pin(async move {
            let deps_core::parser::DependencySource::AlternateRegistry { index, .. } = source
            else {
                return Err(DepsError::PackageNotFound {
                    package: name.to_string(),
                    registry: "gitlab-ci (no route; source required)",
                });
            };
            let Some(route) = self.routes.get(index).map(|r| r.clone()) else {
                return Err(DepsError::PackageNotFound {
                    package: name.to_string(),
                    registry: "gitlab-ci (unregistered route)",
                });
            };
            let versions = self.fetch_route(name, &route).await?;
            Ok(versions
                .into_iter()
                .map(|v| Box::new(v) as Box<dyn deps_core::Version>)
                .collect())
        })
    }

    /// Unconditional [`DepsError::PackageNotFound`] — this trait method's counterpart to
    /// `get_versions`; equally unroutable without a source.
    fn get_latest_matching<'a>(
        &'a self,
        name: &'a PackageName,
        _req: &'a deps_core::VersionReq,
    ) -> deps_core::ecosystem::BoxFuture<'a, Result<Option<Box<dyn deps_core::Version>>>> {
        Box::pin(async move {
            Err(DepsError::PackageNotFound {
                package: name.to_string(),
                registry: "gitlab-ci (no route; source required)",
            })
        })
    }

    fn get_latest_matching_from<'a>(
        &'a self,
        name: &'a PackageName,
        source: &'a deps_core::parser::DependencySource,
        req: &'a deps_core::VersionReq,
        _minimum_stability: Option<&'a str>,
    ) -> deps_core::ecosystem::BoxFuture<'a, Result<Option<Box<dyn deps_core::Version>>>> {
        Box::pin(async move {
            let versions: Vec<Box<dyn deps_core::Version>> = self
                .get_versions_from(name, source, deps_core::FreshnessSettings::default())
                .await?;
            let idx = self.select_latest_matching(&versions, req);
            Ok(idx.and_then(|i| versions.into_iter().nth(i)))
        })
    }

    /// No cheap GitLab search endpoint under the NFR-002 rate-limit budget.
    fn search<'a>(
        &'a self,
        _query: &'a str,
        _limit: usize,
    ) -> deps_core::ecosystem::BoxFuture<'a, Result<Vec<Box<dyn deps_core::Metadata>>>> {
        Box::pin(async move { Ok(vec![]) })
    }

    /// M-b (#466 review): a bare partial-shaped requirement (`"1.2"`) is parsed with
    /// GitLab's own tilde semantics via [`crate::component::gitlab_version_req`], not the
    /// `semver` crate's implicit-caret default — and a literal `~latest` (which
    /// `semver::VersionReq::parse` cannot parse at all, since `"latest"` is not a version)
    /// is special-cased to pick the highest non-prerelease version, mirroring
    /// [`crate::component::resolve_component_pin`]'s `Latest` arm.
    fn select_latest_matching(
        &self,
        versions: &[Box<dyn deps_core::Version>],
        req: &deps_core::VersionReq,
    ) -> Option<usize> {
        if deps_core::is_existence_wildcard(req) {
            return deps_core::select_latest_for_existence(versions, |v| v.as_ref());
        }
        if req.as_str() == crate::component::LATEST {
            return versions
                .iter()
                .enumerate()
                .filter(|(_, v)| !v.is_prerelease())
                .filter_map(|(i, v)| {
                    semver::Version::parse(normalize_tag(v.version_string().as_str()))
                        .ok()
                        .map(|ver| (i, ver))
                })
                .max_by(|(_, a), (_, b)| a.cmp(b))
                .map(|(i, _)| i);
        }
        let parsed_req = crate::component::gitlab_version_req(req.as_str())?;
        versions.iter().position(|v| {
            semver::Version::parse(normalize_tag(v.version_string().as_str()))
                .is_ok_and(|ver| parsed_req.matches(&ver))
        })
    }

    /// GitLab exposes no yank/deprecation signal for either endpoint.
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
    use crate::host::GitlabInstanceHost;
    use deps_core::Registry;
    use deps_core::net_policy::RegistryAccessPolicy;
    use deps_core::parser::DependencySource;
    use std::sync::RwLock;

    /// A client backed by an in-memory cache and no configured instance host — sufficient
    /// for every test in this module that never actually issues a live request (route-table
    /// and error-mapping tests), and reused as the base for tests that do via `mockito`.
    fn test_client() -> Arc<GitlabApiClient> {
        let policy = Arc::new(RegistryAccessPolicy::default());
        let instance_host = Arc::new(GitlabInstanceHost::new(Arc::new(RwLock::new(None)), policy));
        Arc::new(GitlabApiClient::new(
            Arc::new(deps_core::HttpCache::new()),
            instance_host,
        ))
    }

    fn route(origin: &str, endpoint: EndpointKind) -> GitlabRoute {
        GitlabRoute {
            origin: origin.to_string(),
            endpoint,
        }
    }

    // --- get_versions / get_latest_matching: unconditional PackageNotFound (no route) ---

    #[tokio::test]
    async fn test_get_versions_unconditional_package_not_found() {
        let registry = GitlabCiRegistry::new(test_client());
        let name = PackageName::new("gitlab.com/org/proj");
        match registry.get_versions(&name).await {
            Err(e) => assert!(matches!(e, DepsError::PackageNotFound { .. })),
            Ok(_) => panic!("expected PackageNotFound"),
        }
    }

    #[tokio::test]
    async fn test_get_latest_matching_unconditional_package_not_found() {
        let registry = GitlabCiRegistry::new(test_client());
        let name = PackageName::new("gitlab.com/org/proj");
        let req = deps_core::VersionReq::new("*");
        match registry.get_latest_matching(&name, &req).await {
            Err(e) => assert!(matches!(e, DepsError::PackageNotFound { .. })),
            Ok(_) => panic!("expected PackageNotFound"),
        }
    }

    /// An unrouted `AlternateRegistry` index must be `PackageNotFound` even when the route
    /// table already has *other* entries registered — proving the lookup is keyed on the
    /// exact index, not e.g. falling through to whatever route happens to be registered.
    #[tokio::test]
    async fn test_get_versions_from_unrouted_index_is_package_not_found_even_with_other_routes() {
        let registry = GitlabCiRegistry::new(test_client());
        let refused = registry.register_routes(&[(
            "gitlab:known".to_string(),
            route("https://gitlab.com", EndpointKind::Tags),
        )]);
        assert!(refused.is_empty());

        let name = PackageName::new("gitlab.com/org/other");
        let source = DependencySource::AlternateRegistry {
            index: "gitlab:unknown".to_string(),
            mirrors_crates_io: false,
        };
        match registry
            .get_versions_from(&name, &source, deps_core::FreshnessSettings::default())
            .await
        {
            Err(e) => assert!(matches!(e, DepsError::PackageNotFound { .. })),
            Ok(_) => panic!("expected PackageNotFound"),
        }

        let req = deps_core::VersionReq::new("*");
        match registry
            .get_latest_matching_from(&name, &source, &req, None)
            .await
        {
            Err(e) => assert!(matches!(e, DepsError::PackageNotFound { .. })),
            Ok(_) => panic!("expected PackageNotFound"),
        }
    }

    // --- register_routes: MAX_GITLAB_ROUTES cap refusal ---

    #[test]
    fn test_register_routes_refuses_route_257() {
        let registry = GitlabCiRegistry::new(test_client());
        let routes: Vec<(String, GitlabRoute)> = (0..=MAX_GITLAB_ROUTES)
            .map(|i| {
                (
                    format!("gitlab:route{i}"),
                    route(&format!("https://host{i}.example.com"), EndpointKind::Tags),
                )
            })
            .collect();
        assert_eq!(routes.len(), MAX_GITLAB_ROUTES + 1);

        let refused = registry.register_routes(&routes);

        assert_eq!(refused.len(), 1);
        assert!(refused.contains(&format!("gitlab:route{MAX_GITLAB_ROUTES}")));
        assert_eq!(registry.routes.len(), MAX_GITLAB_ROUTES);
    }

    #[test]
    fn test_register_routes_under_cap_refuses_nothing() {
        let registry = GitlabCiRegistry::new(test_client());
        let routes: Vec<(String, GitlabRoute)> = (0..MAX_GITLAB_ROUTES)
            .map(|i| {
                (
                    format!("gitlab:route{i}"),
                    route(&format!("https://host{i}.example.com"), EndpointKind::Tags),
                )
            })
            .collect();
        let refused = registry.register_routes(&routes);
        assert!(refused.is_empty());
        assert_eq!(registry.routes.len(), MAX_GITLAB_ROUTES);
    }

    // --- endpoint dispatch: a Releases route calls /releases, never /repository/tags ---

    #[tokio::test]
    async fn test_releases_route_dispatch_calls_releases_never_tags() {
        let mut server = mockito::Server::new_async().await;
        let sha = "a".repeat(40);
        let releases_mock = server
            .mock("GET", "/api/v4/projects/org%2Fproj/releases")
            .match_query(mockito::Matcher::Any)
            .with_status(200)
            .with_body(format!(
                r#"[{{"tag_name":"1.0.0","commit":{{"id":"{sha}"}}}}]"#
            ))
            .create_async()
            .await;
        let tags_mock = server
            .mock("GET", "/api/v4/projects/org%2Fproj/repository/tags")
            .match_query(mockito::Matcher::Any)
            .with_status(200)
            .with_body("[]")
            .expect(0)
            .create_async()
            .await;

        let registry = GitlabCiRegistry::new(test_client());
        let host_bare = server.url();
        let gitlab_route = route(&host_bare, EndpointKind::Releases);
        let name = PackageName::new(format!("{host_bare}/org/proj/comp"));

        let versions = registry.fetch_route(&name, &gitlab_route).await.unwrap();

        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0].version.as_str(), "1.0.0");
        releases_mock.assert_async().await;
        tags_mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_tags_route_dispatch_calls_tags_never_releases() {
        let mut server = mockito::Server::new_async().await;
        let sha = "a".repeat(40);
        let tags_mock = server
            .mock("GET", "/api/v4/projects/org%2Fproj/repository/tags")
            .match_query(mockito::Matcher::Any)
            .with_status(200)
            .with_body(format!(r#"[{{"name":"1.0.0","commit":{{"id":"{sha}"}}}}]"#))
            .create_async()
            .await;
        let releases_mock = server
            .mock("GET", "/api/v4/projects/org%2Fproj/releases")
            .match_query(mockito::Matcher::Any)
            .with_status(200)
            .with_body("[]")
            .expect(0)
            .create_async()
            .await;

        let registry = GitlabCiRegistry::new(test_client());
        let host_bare = server.url();
        let gitlab_route = route(&host_bare, EndpointKind::Tags);
        let name = PackageName::new(format!("{host_bare}/org/proj"));

        let versions = registry.fetch_route(&name, &gitlab_route).await.unwrap();

        assert_eq!(versions.len(), 1);
        tags_mock.assert_async().await;
        releases_mock.assert_async().await;
    }

    // --- validation finding C1: TagIndex must not lose a non-semver-shaped tag ---

    /// A literal tool-name tag (e.g. `cargo-deny`, the same shape issue #551's own example
    /// uses) fails `tags_to_versions`' full-semver filter and so never appears in the
    /// version list `fetch_route` returns — but it must still reach a `TagIndex` entry,
    /// since that's the only way the registry-confirmed-`PinStyle::Branch` diagnostic path
    /// (and any future SHA-pin quickfix widening) can ever fire for a `project:` include
    /// pinned to such a tag. Regression for the bug `populate_tag_index_entries` fixes: the
    /// previous `populate_tag_index` was fed `tags_to_versions`' already-filtered output,
    /// making this path unreachable in production.
    #[tokio::test]
    async fn test_fetch_route_tags_indexes_non_semver_tag_for_registry_confirmation() {
        let mut server = mockito::Server::new_async().await;
        let sha = "a".repeat(40);
        let _tags_mock = server
            .mock("GET", "/api/v4/projects/org%2Fproj/repository/tags")
            .match_query(mockito::Matcher::Any)
            .with_status(200)
            .with_body(format!(
                r#"[{{"name":"cargo-deny","commit":{{"id":"{sha}"}}}}]"#
            ))
            .create_async()
            .await;

        let registry = GitlabCiRegistry::new(test_client());
        let host_bare = server.url();
        let gitlab_route = route(&host_bare, EndpointKind::Tags);
        let name = PackageName::new(format!("{host_bare}/org/proj"));

        let versions = registry.fetch_route(&name, &gitlab_route).await.unwrap();
        assert!(
            versions.is_empty(),
            "a non-semver tag must not appear in the outdated-diagnostic version list"
        );

        let index = registry
            .tag_index
            .get(&(EndpointKind::Tags, name))
            .expect("expected a TagIndex entry despite the tag failing the semver filter");
        assert_eq!(index.tag_to_sha.get("cargo-deny"), Some(&sha));
    }

    // --- validation finding S2: TagIndex must not collide across (endpoint, name) ---

    /// A `project:` include and a `component:` include can produce the identical
    /// host-qualified `PackageName` text for two entirely unrelated GitLab resources (a
    /// project literally named `org/proj/comp`, versus a component named `comp` inside
    /// project `org/proj`) — spec §3.1's documented residual collision covers only the
    /// same-project case, not this cross-resource one. Without `EndpointKind` in the
    /// `TagIndex` key, whichever fetch ran last would silently overwrite the other's entry,
    /// letting a quickfix resolve a SHA from the wrong repository. Regression for the fix:
    /// both routes populate distinct entries for the same `PackageName`.
    #[tokio::test]
    async fn test_tag_index_keyed_by_endpoint_no_cross_kind_collision() {
        let mut server = mockito::Server::new_async().await;
        let project_sha = "a".repeat(40);
        let component_sha = "b".repeat(40);
        let _tags_mock = server
            .mock("GET", "/api/v4/projects/org%2Fproj%2Fcomp/repository/tags")
            .match_query(mockito::Matcher::Any)
            .with_status(200)
            .with_body(format!(
                r#"[{{"name":"v1.0.0","commit":{{"id":"{project_sha}"}}}}]"#
            ))
            .create_async()
            .await;
        let _releases_mock = server
            .mock("GET", "/api/v4/projects/org%2Fproj/releases")
            .match_query(mockito::Matcher::Any)
            .with_status(200)
            .with_body(format!(
                r#"[{{"tag_name":"v1.0.0","commit":{{"id":"{component_sha}"}}}}]"#
            ))
            .create_async()
            .await;

        let registry = GitlabCiRegistry::new(test_client());
        let host_bare = server.url();
        // Same `PackageName` text for both: a `project:` include for repo `org/proj/comp`,
        // and a `component:` include naming component `comp` inside project `org/proj`.
        let name = PackageName::new(format!("{host_bare}/org/proj/comp"));

        let project_versions = registry
            .fetch_route(&name, &route(&host_bare, EndpointKind::Tags))
            .await
            .unwrap();
        let component_versions = registry
            .fetch_route(&name, &route(&host_bare, EndpointKind::Releases))
            .await
            .unwrap();

        assert_eq!(project_versions[0].sha, project_sha);
        assert_eq!(component_versions[0].sha, component_sha);

        let project_index = registry
            .tag_index
            .get(&(EndpointKind::Tags, name.clone()))
            .expect("expected a Tags-endpoint TagIndex entry");
        let component_index = registry
            .tag_index
            .get(&(EndpointKind::Releases, name))
            .expect("expected a Releases-endpoint TagIndex entry");
        assert_eq!(project_index.tag_to_sha.get("v1.0.0"), Some(&project_sha));
        assert_eq!(
            component_index.tag_to_sha.get("v1.0.0"),
            Some(&component_sha)
        );
    }

    // --- resolve_component_pin: H1 (#466 review) — FR-007 wired to a real caller ---

    #[tokio::test]
    async fn test_resolve_component_pin_partial_picks_highest_matching_release() {
        let mut server = mockito::Server::new_async().await;
        let sha_a = "a".repeat(40);
        let sha_b = "b".repeat(40);
        let sha_c = "c".repeat(40);
        let _releases_mock = server
            .mock("GET", "/api/v4/projects/org%2Fproj/releases")
            .match_query(mockito::Matcher::Any)
            .with_status(200)
            .with_body(format!(
                r#"[{{"tag_name":"1.2.0","commit":{{"id":"{sha_a}"}}}},
                    {{"tag_name":"1.2.5","commit":{{"id":"{sha_b}"}}}},
                    {{"tag_name":"1.3.0","commit":{{"id":"{sha_c}"}}}}]"#
            ))
            .create_async()
            .await;

        let registry = GitlabCiRegistry::new(test_client());
        let host_bare = server.url();
        let gitlab_route = route(&host_bare, EndpointKind::Releases);
        let name = PackageName::new(format!("{host_bare}/org/proj/comp"));

        let resolved = registry
            .resolve_component_pin(&name, &gitlab_route, &PinStyle::Partial, "1.2")
            .await
            .unwrap()
            .expect("a matching release exists");

        assert_eq!(resolved.version.as_str(), "1.2.5");
        assert_eq!(resolved.sha, sha_b);
    }

    #[tokio::test]
    async fn test_resolve_component_pin_no_match_returns_none() {
        let mut server = mockito::Server::new_async().await;
        let sha = "a".repeat(40);
        let _releases_mock = server
            .mock("GET", "/api/v4/projects/org%2Fproj/releases")
            .match_query(mockito::Matcher::Any)
            .with_status(200)
            .with_body(format!(
                r#"[{{"tag_name":"2.0.0","commit":{{"id":"{sha}"}}}}]"#
            ))
            .create_async()
            .await;

        let registry = GitlabCiRegistry::new(test_client());
        let host_bare = server.url();
        let gitlab_route = route(&host_bare, EndpointKind::Releases);
        let name = PackageName::new(format!("{host_bare}/org/proj/comp"));

        let resolved = registry
            .resolve_component_pin(&name, &gitlab_route, &PinStyle::Partial, "1.2")
            .await
            .unwrap();
        assert!(resolved.is_none());
    }

    // --- map_error ---

    #[test]
    fn test_map_error_404_is_package_not_found() {
        let registry = GitlabCiRegistry::new(test_client());
        let err = registry.map_error(
            "https://gitlab.com",
            "org/proj",
            DepsError::HttpStatus {
                url: "https://gitlab.com/x".into(),
                status: 404,
            },
        );
        assert!(matches!(err, DepsError::PackageNotFound { .. }));
    }

    /// H3 (#466 review): a residual `400` (the client-level `order_by=version` fallback
    /// already exhausted) degrades to `PackageNotFound`, not a raw, unclassified transport
    /// error.
    #[test]
    fn test_map_error_400_is_package_not_found() {
        let registry = GitlabCiRegistry::new(test_client());
        let err = registry.map_error(
            "https://gitlab.com",
            "org/proj",
            DepsError::HttpStatus {
                url: "https://gitlab.com/x".into(),
                status: 400,
            },
        );
        assert!(matches!(err, DepsError::PackageNotFound { .. }));
    }

    #[test]
    fn test_map_error_429_trips_rate_limit_gate() {
        let registry = GitlabCiRegistry::new(test_client());
        let err = registry.map_error(
            "https://gitlab.com",
            "org/proj",
            DepsError::HttpStatus {
                url: "https://gitlab.com/x".into(),
                status: 429,
            },
        );
        assert!(matches!(err, DepsError::RateLimited { .. }));
        assert!(registry.rate_limit_gate("https://gitlab.com").is_tripped());
    }

    // --- select_latest_matching: M-b partial-pin and ~latest semantics ---

    fn version(v: &str, prerelease: bool) -> Box<dyn deps_core::Version> {
        Box::new(GitlabCiVersion {
            version: v.into(),
            sha: "a".repeat(40),
            prerelease,
            published_at: None,
        })
    }

    #[test]
    fn test_select_latest_matching_partial_pin_uses_tilde_not_caret() {
        let registry = GitlabCiRegistry::new(test_client());
        // Newest-first, mirroring `releases_to_versions`/`tags_to_versions`'s actual
        // output order — `select_latest_matching` is a first-match `position()` over an
        // already-sorted list, not a max-search.
        let versions = vec![
            version("1.3.0", false),
            version("1.2.5", false),
            version("1.2.0", false),
        ];
        // GitLab tilde semantics: "1.2" matches only 1.2.*, never 1.3.0 the way an implicit
        // caret (`^1.2`) would.
        let idx = registry
            .select_latest_matching(&versions, &deps_core::VersionReq::new("1.2"))
            .unwrap();
        assert_eq!(versions[idx].version_string().as_str(), "1.2.5");
    }

    #[test]
    fn test_select_latest_matching_tilde_latest_picks_highest_non_prerelease() {
        let registry = GitlabCiRegistry::new(test_client());
        let versions = vec![
            version("1.0.0", false),
            version("2.0.0", false),
            version("3.0.0-beta.1", true),
        ];
        let idx = registry
            .select_latest_matching(&versions, &deps_core::VersionReq::new("~latest"))
            .unwrap();
        assert_eq!(versions[idx].version_string().as_str(), "2.0.0");
    }
}
