//! GitHub Actions registry using the GitHub tags API.
//!
//! Fetches tags for `owner/repo` action/workflow repositories. Non-GitHub identities are
//! rejected before any request is made (`validate_owner_repo`).

use dashmap::DashMap;
use deps_core::github::{
    GithubTag, GithubTagsClient, ReleaseDatesCache, normalize_tag, paginate_tags,
    validate_owner_repo,
};
use deps_core::{DepsError, HttpCache, PackageName, PublishTime, Result};
use std::any::Any;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::types::GithubActionsVersion;

/// Display name for the registry backing GitHub Actions version lookups, used in
/// not-found and API-response error messages.
pub const REGISTRY: &str = "GitHub";

/// Maximum number of repositories held in [`GithubActionsRegistry::tag_index`] at once.
const MAX_TAG_INDEX_ENTRIES: usize = 256;

/// Maximum number of repositories with a coalescing lock outstanding in
/// [`GithubActionsRegistry::in_flight`] at once.
const MAX_IN_FLIGHT_ENTRIES: usize = 256;

/// How long [`RateLimitGate`] keeps `get_versions` short-circuiting locally after a
/// 403-without-token response, before allowing another live request.
///
/// GitHub's unauthenticated rate limit resets on a rolling hourly window whose exact
/// reset instant this crate has no way to learn: [`DepsError::HttpStatus`] carries only a
/// bare status code, not response headers, so the `x-ratelimit-reset` header GitHub
/// returns on a 403 is not observable here without widening `deps-core`'s shared HTTP
/// error type for one caller. A fixed, conservative cooldown is the documented trade-off
/// (critic C1) — long enough to meaningfully stop hammering a workspace with many unique
/// actions, short enough to recover without a restart.
const RATE_LIMIT_COOLDOWN_SECS: u64 = 300;

fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Local, process-lifetime gate that short-circuits further GitHub API requests once a
/// 403-without-token response has been seen, instead of letting every remaining unique
/// repository in a workspace fire (and lose) its own doomed request (critic C1).
///
/// `HttpCache::get_cached_with_headers_via` stores nothing on a failed fetch, so without
/// this gate, per-repository in-flight coalescing alone does not help: each waiter still
/// finds an empty cache and issues its own request once the first one fails.
#[derive(Debug, Default)]
struct RateLimitGate {
    /// Unix-epoch seconds at which the gate clears; `0` means "not tripped".
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

    #[cfg(test)]
    fn trip_until_epoch_secs(&self, reset_at: u64) {
        self.reset_at.store(reset_at, Ordering::Relaxed);
    }
}

/// Per-repository tag/SHA cross-reference.
///
/// Populated on every successful tags fetch (the `/tags` response already carries
/// `commit.sha` — zero extra requests). Read by
/// [`crate::formatter::GithubActionsFormatter`] to resolve a SHA-pin edit's replacement
/// text and by the hover override to resolve a tag or SHA's counterpart for display.
///
/// Fields are `pub` (not `pub(crate)`) so a cross-crate integration test that exercises
/// the shared `deps_core::collect_update_all_edits`/hover machinery — which never itself
/// drives a live registry fetch — can seed a repository's entry directly via
/// [`GithubActionsRegistry::tag_index`].
#[derive(Debug, Default)]
pub struct TagIndex {
    /// Tag text (as published) -> the commit SHA it points at.
    pub tag_to_sha: HashMap<String, String>,
    /// Commit SHA -> the tag text (as published) it corresponds to.
    pub sha_to_tag: HashMap<String, String>,
}

/// Evicts entries from `map` when it is already at `max_entries`, ahead of an insert that
/// would otherwise grow it further — the single oldest-inserted entry, approximated by
/// removing an arbitrary entry (this map has no per-entry timestamp; unlike
/// `deps-swift`'s TTL-based memo, a repeated fetch simply repopulates whichever entry was
/// dropped). The O(n) scan runs only on an insert that finds the map full.
fn evict_if_full<V>(map: &DashMap<PackageName, V>, max_entries: usize) {
    if map.len() < max_entries {
        return;
    }
    // The victim key is resolved in its own `let` binding, fully dropping the
    // iterator (and whatever shard guard it holds) before `remove` runs — folding
    // this into a single `if let Some(key) = map.iter()....` risks the iterator's
    // temporary being scope-extended across the `remove` call (Rust's `if let`
    // temporary-lifetime-extension rule), which can deadlock against DashMap's
    // internal per-shard locking.
    let victim = map.iter().next().map(|e| e.key().clone());
    if let Some(key) = victim {
        map.remove(&key);
    }
}

/// Evicts entries from the in-flight coalescing map, but — unlike [`evict_if_full`] —
/// **only** an entry whose `Arc<Mutex<()>>` is not currently held by another waiter
/// (`Arc::strong_count() == 1`, meaning the map's own reference is the only one left).
///
/// Evicting a held lock would silently defeat coalescing under exactly the load it
/// targets: the next caller for that repository would create a *fresh* mutex and proceed
/// concurrently with the fetch already in flight (critic C2), degrading to pre-coalescing
/// behavior rather than corrupting anything, but undermining the whole point of #208's S2
/// fix.
fn evict_in_flight_if_full(map: &DashMap<PackageName, Arc<tokio::sync::Mutex<()>>>) {
    if map.len() < MAX_IN_FLIGHT_ENTRIES {
        return;
    }
    // See `evict_if_full`'s comment: the victim is resolved in its own `let`
    // binding so the iterator's shard guard is fully released before `remove` runs.
    let victim = map
        .iter()
        .find(|e| Arc::strong_count(e.value()) == 1)
        .map(|e| e.key().clone());
    if let Some(key) = victim {
        map.remove(&key);
    }
}

/// Client for fetching GitHub Actions version information from the GitHub tags API.
#[derive(Clone)]
pub struct GithubActionsRegistry {
    github: GithubTagsClient,
    tag_index: Arc<DashMap<PackageName, Arc<TagIndex>>>,
    in_flight: Arc<DashMap<PackageName, Arc<tokio::sync::Mutex<()>>>>,
    rate_limit: Arc<RateLimitGate>,
    /// Per-repository memoized GitHub Release publish times (#486, mirroring
    /// `deps-swift`'s identical need — see [`ReleaseDatesCache`]). `Arc` because
    /// `GithubActionsRegistry` is `Clone` and clones must share one memo, the same
    /// reason `github`'s cache is an `Arc`.
    release_dates: Arc<ReleaseDatesCache>,
}

impl GithubActionsRegistry {
    /// Creates a new GitHub Actions registry client with the given HTTP cache.
    ///
    /// Reads `GITHUB_TOKEN` from the environment for authenticated requests (5000 req/h
    /// vs 60 req/h unauthenticated) — identical to `deps_swift::registry::SwiftRegistry`,
    /// and note the 60 req/h unauthenticated budget is per-IP and **shared** with any
    /// `deps-swift` traffic in the same process.
    #[must_use]
    pub fn new(cache: Arc<HttpCache>) -> Self {
        Self {
            github: GithubTagsClient::new(cache),
            tag_index: Arc::new(DashMap::new()),
            in_flight: Arc::new(DashMap::new()),
            rate_limit: Arc::new(RateLimitGate::default()),
            release_dates: Arc::new(ReleaseDatesCache::new()),
        }
    }

    /// Creates a registry pointed at a `mockito`-backed URL instead of the real GitHub API
    /// (critic finding C1 regression coverage, #550) — `pub(crate)`, not module-private, so
    /// `crate::ecosystem`'s tests can build a [`crate::ecosystem::GithubActionsEcosystem`]
    /// around a registry whose fetches are fully mocked, letting an end-to-end
    /// `generate_hover` test reproduce a genuinely empty-but-successful live fetch
    /// (`available_versions == Some([])`) without a real network call.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn for_test(
        cache: Arc<HttpCache>,
        api_base: impl Into<String>,
        has_token: bool,
    ) -> Self {
        Self {
            github: GithubTagsClient::for_test(cache, api_base, has_token),
            tag_index: Arc::new(DashMap::new()),
            in_flight: Arc::new(DashMap::new()),
            rate_limit: Arc::new(RateLimitGate::default()),
            release_dates: Arc::new(ReleaseDatesCache::new()),
        }
    }

    /// Shares this registry's [`TagIndex`] map with a [`crate::formatter::GithubActionsFormatter`],
    /// so a formatted SHA-pin edit can resolve the new SHA for a given tag.
    ///
    /// `pub`, not `pub(crate)`: an integration test that exercises the shared
    /// `deps_core` code-action/code-lens/hover machinery against this ecosystem —
    /// which never itself drives a live registry fetch — needs a way to seed a
    /// repository's [`TagIndex`] entry directly, without going through a mocked HTTP
    /// fetch that path never calls.
    #[must_use]
    pub fn tag_index(&self) -> Arc<DashMap<PackageName, Arc<TagIndex>>> {
        Arc::clone(&self.tag_index)
    }

    fn rate_limited_error() -> DepsError {
        deps_core::github::github_rate_limit_error()
    }

    fn map_tags_error(&self, name: &str, e: DepsError) -> DepsError {
        match &e {
            // Trip the process-wide gate only for the no-token case this cooldown
            // exists for: a *tokened* 403 is far more likely an org-policy/SAML
            // restriction or a genuinely inaccessible private repo, scoped to that one
            // repository — tripping the shared gate on it would disable GHA lookups
            // workspace-wide for every other (accessible) repository too (critic M3).
            DepsError::HttpStatus { status: 403, .. } if self.github.has_token() => e,
            DepsError::HttpStatus { status: 403, .. } => {
                self.rate_limit.trip();
                Self::rate_limited_error()
            }
            DepsError::HttpStatus { status: 404, .. } => DepsError::PackageNotFound {
                package: name.to_string(),
                registry: REGISTRY,
            },
            _ => e,
        }
    }

    fn acquire_in_flight_lock(&self, name: &PackageName) -> Arc<tokio::sync::Mutex<()>> {
        if let Some(existing) = self.in_flight.get(name) {
            return Arc::clone(&existing);
        }
        if !self.in_flight.contains_key(name) {
            evict_in_flight_if_full(&self.in_flight);
        }
        Arc::clone(
            self.in_flight
                .entry(name.clone())
                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
                .value(),
        )
    }

    /// Populates the SHA-pin lookup index from the raw tags API response, independent of
    /// [`tags_to_versions`]' full-`major.minor.patch`-semver filter.
    ///
    /// A bare-major moving tag like `v3`/`v4` — the most common real-world GitHub Actions
    /// pinning convention — normalizes to `"3"`/`"4"`, which `semver::Version::parse`
    /// rejects, so it never appears in the semver-filtered `versions` list `get_versions`
    /// returns. Indexing straight from `tags` instead means the "Pin to commit SHA"
    /// quickfix (issue #473) can resolve *any* literal tag ref present on the repository,
    /// not only the unusual full `vX.Y.Z` pin form (#503). Still gated on
    /// [`crate::parser::is_full_sha`] (security S-3): the SHA is later spliced verbatim
    /// into a manifest text edit and a hover string.
    ///
    /// `sha_to_tag` (the hover `**Resolved**` line) prefers a full-semver-parseable tag
    /// name over a bare moving one when several tags share a commit SHA: GitHub's `/tags`
    /// ordering is undocumented, and a first-wins pass over raw tag order can otherwise
    /// resolve a SHA to a less-specific tag (`v1`) instead of the precise release
    /// (`v0.1.15`) it was actually cut from (#503 critic S1). `tag_to_sha` has no such
    /// ambiguity — it is keyed by the workflow's own literal ref text — so it stays a
    /// plain first-wins index over the raw tags.
    fn populate_tag_index(&self, name: &PackageName, tags: &[GithubTag]) {
        let mut index = TagIndex::default();
        let valid_tags: Vec<&GithubTag> = tags
            .iter()
            .filter(|tag| crate::parser::is_full_sha(&tag.commit.sha))
            .collect();

        for tag in &valid_tags {
            if semver::Version::parse(normalize_tag(&tag.name)).is_ok() {
                index
                    .sha_to_tag
                    .entry(tag.commit.sha.clone())
                    .or_insert_with(|| tag.name.clone());
            }
        }
        for tag in &valid_tags {
            index
                .sha_to_tag
                .entry(tag.commit.sha.clone())
                .or_insert_with(|| tag.name.clone());
            index
                .tag_to_sha
                .entry(tag.name.clone())
                .or_insert_with(|| tag.commit.sha.clone());
        }
        if !self.tag_index.contains_key(name) {
            evict_if_full(&self.tag_index, MAX_TAG_INDEX_ENTRIES);
        }
        self.tag_index.insert(name.clone(), Arc::new(index));
    }

    /// Fetches all semver-tagged versions for `name` (`owner/repo`).
    ///
    /// Returns versions sorted newest-first. Non-semver tags are skipped. Follows GitHub
    /// tags pagination up to `MAX_TAG_PAGES` pages, coalesced per-repository so that N
    /// concurrent callers for the same repository on a cold cache issue one request, not
    /// N (S2) — and short-circuits locally, without touching the network, once the
    /// rate-limit gate has been tripped by an earlier 403 (critic C1).
    pub async fn get_versions(&self, name: &str) -> Result<Vec<GithubActionsVersion>> {
        validate_owner_repo(name)?;
        if self.rate_limit.is_tripped() {
            return Err(Self::rate_limited_error());
        }

        let package_name = PackageName::new(name);
        let lock = self.acquire_in_flight_lock(&package_name);
        let _guard = lock.lock().await;

        // Re-check: an earlier waiter may have tripped the gate, or already
        // populated the tag index, while this task waited for the lock.
        if self.rate_limit.is_tripped() {
            return Err(Self::rate_limited_error());
        }

        let tags = paginate_tags("GitHub Actions", name, |page| async move {
            self.github
                .fetch_tags_page(name, page)
                .await
                .map_err(|e| self.map_tags_error(name, e))
        })
        .await?;

        self.populate_tag_index(&package_name, &tags);
        Ok(tags_to_versions(tags))
    }

    /// Like [`GithubActionsRegistry::get_versions`], but also attaches GitHub Release
    /// publish times, joined by normalized tag name (#486, mirroring
    /// `deps_swift::registry::SwiftRegistry::get_versions_with_release_dates`).
    ///
    /// Runs the tags fetch and the release-dates fetch concurrently (`tokio::join!`) —
    /// the release-dates fetch is infallible (empty map on any failure), so it can
    /// never perturb `get_versions`'s error propagation, rate-limit gate, or in-flight
    /// coalescing.
    ///
    /// Known limitation (#486 critic M2): the release-dates fetch does not consult the
    /// rate-limit gate. This is harmless in the untokened case (`ReleaseDatesCache::
    /// fetch` already short-circuits on a missing `GITHUB_TOKEN` before issuing any
    /// request), but a *tokened* client exhausting its 5000/h quota keeps retrying
    /// `/releases` every error TTL (90s) per repository rather than backing off —
    /// gating this call on `RateLimitGate::is_tripped` would not help: `map_tags_error`
    /// deliberately never trips the gate for a tokened 403 (that case is scoped to one
    /// repository, not treated as a workspace-wide outage), so the gate never becomes
    /// tripped while a token is present. Left unfixed rather than adding a check that
    /// would never fire in the tokened case it targets.
    pub async fn get_versions_with_release_dates(
        &self,
        name: &str,
    ) -> Result<Vec<GithubActionsVersion>> {
        let (versions, dates) = tokio::join!(
            self.get_versions(name),
            self.release_dates
                .fetch(&self.github, name, "GitHub Actions")
        );
        let mut versions = versions?;
        attach_publish_times(&mut versions, &dates);
        Ok(versions)
    }

    /// Finds the latest version satisfying the given semver requirement.
    pub async fn get_latest_matching(
        &self,
        name: &str,
        req_str: &str,
    ) -> Result<Option<GithubActionsVersion>> {
        let versions = self.get_versions(name).await?;
        let req = match semver::VersionReq::parse(normalize_tag(req_str)) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("Failed to parse version req '{}': {}", req_str, e);
                return Ok(None);
            }
        };
        Ok(versions.into_iter().find(|v| {
            semver::Version::parse(normalize_tag(v.version.as_str()))
                .is_ok_and(|ver| req.matches(&ver))
        }))
    }
}

/// Converts raw tags (possibly accumulated across pages) into a newest-first
/// `GithubActionsVersion` list. Non-semver tags are skipped; dedupe by normalized
/// semver, first (page-order) occurrence wins.
///
/// Also drops any tag whose `commit.sha` is not [`crate::parser::is_full_sha`]-shaped
/// (security S-3): a `GithubActionsVersion`'s `sha` is later spliced verbatim into a
/// manifest text edit (`GithubActionsFormatter::format_version_replacing_for`'s
/// `PinStyle::Sha` branch) and a hover string — the one registry-supplied value in this
/// crate that otherwise bypasses every allowlist gate (`is_safe_version_string` covers
/// the *version*, not the SHA). [`GithubActionsRegistry::populate_tag_index`] applies
/// the identical filter independently for `TagIndex`, since it indexes from the raw
/// tags rather than this function's semver-filtered output (#503).
fn tags_to_versions(tags: Vec<GithubTag>) -> Vec<GithubActionsVersion> {
    let mut seen = std::collections::HashSet::new();
    let mut versions_with_parsed: Vec<(GithubActionsVersion, semver::Version)> = tags
        .into_iter()
        .filter_map(|tag| {
            let normalized = normalize_tag(&tag.name).to_string();
            let parsed = semver::Version::parse(&normalized).ok()?;
            if !seen.insert(normalized) {
                return None;
            }
            if !crate::parser::is_full_sha(&tag.commit.sha) {
                return None;
            }
            let prerelease = !parsed.pre.is_empty();
            Some((
                GithubActionsVersion {
                    version: tag.name.into(),
                    sha: tag.commit.sha,
                    prerelease,
                    published_at: None,
                },
                parsed,
            ))
        })
        .collect();

    versions_with_parsed.sort_unstable_by(|a, b| b.1.cmp(&a.1));
    versions_with_parsed.into_iter().map(|(v, _)| v).collect()
}

/// Attaches release publish times onto an already-fetched version list, in place.
///
/// Pure and network-free: `versions` came from [`GithubActionsRegistry::get_versions`],
/// `dates` from [`ReleaseDatesCache::fetch`]. Joins by [`normalize_tag`] since
/// `version.version` keeps the tag exactly as published (possibly `v`-prefixed) while
/// `dates`'s keys are normalized. A version with no matching entry in `dates` keeps
/// `published_at: None` — exactly the pre-#486 rendering.
fn attach_publish_times(
    versions: &mut [GithubActionsVersion],
    dates: &HashMap<String, PublishTime>,
) {
    for version in versions {
        version.published_at = dates.get(normalize_tag(version.version.as_str())).copied();
    }
}

impl deps_core::Registry for GithubActionsRegistry {
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

    fn get_versions_with<'a>(
        &'a self,
        name: &'a deps_core::PackageName,
        freshness: deps_core::FreshnessSettings,
    ) -> deps_core::ecosystem::BoxFuture<'a, Result<Vec<Box<dyn deps_core::Version>>>> {
        Box::pin(async move {
            let versions = if freshness.enabled {
                self.get_versions_with_release_dates(name.as_str()).await?
            } else {
                self.get_versions(name.as_str()).await?
            };
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

    /// Always empty for the MVP (S2/registry docs): a name-completion search would burn
    /// the 60 req/h unauthenticated budget per keystroke, since GitHub has no
    /// action-specific search endpoint cheaper than repository search.
    fn search<'a>(
        &'a self,
        _query: &'a str,
        _limit: usize,
    ) -> deps_core::ecosystem::BoxFuture<'a, Result<Vec<Box<dyn deps_core::Metadata>>>> {
        Box::pin(async move { Ok(vec![]) })
    }

    fn select_latest_matching(
        &self,
        versions: &[Box<dyn deps_core::Version>],
        req: &deps_core::VersionReq,
    ) -> Option<usize> {
        if deps_core::is_existence_wildcard(req) {
            return deps_core::select_latest_for_existence(versions, |v| v.as_ref());
        }
        let parsed_req = semver::VersionReq::parse(normalize_tag(req.as_str())).ok()?;
        versions.iter().position(|v| {
            semver::Version::parse(normalize_tag(v.version_string().as_str()))
                .is_ok_and(|ver| parsed_req.matches(&ver))
        })
    }

    /// GitHub's tags API exposes no yank/deprecation signal for actions.
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
    fn test_parse_tags_response() {
        let sha1 = "a".repeat(40);
        let sha2 = "b".repeat(40);
        let sha3 = "c".repeat(40);
        let json = format!(
            r#"[
            {{"name": "v4.2.0", "commit": {{"sha": "{sha1}"}}}},
            {{"name": "v4.1.0", "commit": {{"sha": "{sha2}"}}}},
            {{"name": "not-semver", "commit": {{"sha": "{sha3}"}}}}
        ]"#
        );
        let tags: Vec<GithubTag> = deps_core::github::parse_tags_page(json.as_bytes()).unwrap();
        let versions = tags_to_versions(tags);
        assert_eq!(versions.len(), 2);
        assert_eq!(versions[0].version, "v4.2.0");
        assert_eq!(versions[0].sha, sha1);
        assert_eq!(versions[1].version, "v4.1.0");
    }

    #[test]
    fn test_tags_to_versions_keeps_v_prefix_as_published() {
        let sha = "a".repeat(40);
        let json = format!(r#"[{{"name": "4.2.0", "commit": {{"sha": "{sha}"}}}}]"#);
        let tags: Vec<GithubTag> = deps_core::github::parse_tags_page(json.as_bytes()).unwrap();
        let versions = tags_to_versions(tags);
        assert_eq!(versions[0].version, "4.2.0");
    }

    #[test]
    fn test_tags_to_versions_dedupes_by_normalized_semver_first_wins() {
        let first_sha = "a".repeat(40);
        let second_sha = "b".repeat(40);
        let json = format!(
            r#"[
            {{"name": "v1.0.0", "commit": {{"sha": "{first_sha}"}}}},
            {{"name": "1.0.0", "commit": {{"sha": "{second_sha}"}}}}
        ]"#
        );
        let tags: Vec<GithubTag> = deps_core::github::parse_tags_page(json.as_bytes()).unwrap();
        let versions = tags_to_versions(tags);
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0].sha, first_sha);
    }

    #[test]
    fn test_tags_to_versions_sorts_mixed_v_prefix_and_bare_by_semver() {
        // Required test-matrix row (testing handoff): sort order across a mix of
        // `v`-prefixed and bare tags for genuinely *different* versions — distinct
        // from the dedupe test above, which mixes prefixes for the *same* version.
        // Descending by parsed semver regardless of prefix: 5.0.0 > 4.0.0 > 3.0.0.
        let sha_a = "a".repeat(40);
        let sha_b = "b".repeat(40);
        let sha_c = "c".repeat(40);
        let json = format!(
            r#"[
            {{"name": "4.0.0", "commit": {{"sha": "{sha_a}"}}}},
            {{"name": "v5.0.0", "commit": {{"sha": "{sha_b}"}}}},
            {{"name": "v3.0.0", "commit": {{"sha": "{sha_c}"}}}}
        ]"#
        );
        let tags: Vec<GithubTag> = deps_core::github::parse_tags_page(json.as_bytes()).unwrap();
        let versions = tags_to_versions(tags);
        assert_eq!(
            versions
                .iter()
                .map(|v| v.version.as_str())
                .collect::<Vec<_>>(),
            vec!["v5.0.0", "4.0.0", "v3.0.0"]
        );
    }

    #[test]
    fn test_parse_tags_all_non_semver_skipped() {
        let sha = "a".repeat(40);
        let json = format!(r#"[{{"name": "latest", "commit": {{"sha": "{sha}"}}}}]"#);
        let tags: Vec<GithubTag> = deps_core::github::parse_tags_page(json.as_bytes()).unwrap();
        assert!(tags_to_versions(tags).is_empty());
    }

    #[test]
    fn test_tags_to_versions_rejects_tag_with_non_full_sha() {
        // Security S-3: a tag whose `commit.sha` is not a full 40-hex SHA must never
        // reach `TagIndex`/a version list, since it is later spliced verbatim into a
        // manifest text edit and a hover string with no other allowlist gate.
        let json = r#"[{"name": "v1.0.0", "commit": {"sha": "not-a-real-sha"}}]"#;
        let tags: Vec<GithubTag> = deps_core::github::parse_tags_page(json.as_bytes()).unwrap();
        assert!(tags_to_versions(tags).is_empty());
    }

    // `validate_owner_repo`, `page_has_more`, `warn_if_pagination_truncated`,
    // `paginate_tags`, and `parse_tags_page` are now shared with `deps-swift` via
    // `deps_core::github` (#472); their unit tests moved there.

    // --- RateLimitGate ---

    #[test]
    fn test_rate_limit_gate_starts_untripped() {
        let gate = RateLimitGate::default();
        assert!(!gate.is_tripped());
    }

    #[test]
    fn test_rate_limit_gate_trips_and_stays_tripped_within_cooldown() {
        let gate = RateLimitGate::default();
        gate.trip();
        assert!(gate.is_tripped());
    }

    #[test]
    fn test_rate_limit_gate_clears_after_reset_time_passes() {
        let gate = RateLimitGate::default();
        gate.trip_until_epoch_secs(1); // far in the past
        assert!(!gate.is_tripped());
    }

    fn mock_registry(base: &str, has_token: bool) -> GithubActionsRegistry {
        GithubActionsRegistry::for_test(Arc::new(HttpCache::new()), base, has_token)
    }

    #[tokio::test]
    async fn test_get_versions_populates_tag_index() {
        let sha = "abc123".repeat(7); // 42 chars, trimmed below to exactly 40
        let sha = &sha[..40];
        let mut server = mockito::Server::new_async().await;
        let _mock = server
            .mock("GET", "/repos/actions/checkout/tags")
            .match_query(mockito::Matcher::Any)
            .with_status(200)
            .with_body(format!(
                r#"[{{"name": "v4.2.0", "commit": {{"sha": "{sha}"}}}}]"#
            ))
            .create_async()
            .await;

        let registry = mock_registry(&server.url(), false);
        let versions = registry.get_versions("actions/checkout").await.unwrap();
        assert_eq!(versions.len(), 1);

        let name = PackageName::new("actions/checkout");
        let index = registry.tag_index.get(&name).unwrap();
        assert_eq!(index.tag_to_sha.get("v4.2.0"), Some(&sha.to_string()));
        assert_eq!(index.sha_to_tag.get(sha), Some(&"v4.2.0".to_string()));
    }

    /// Regression for #503: a bare-major moving tag like `v4` fails
    /// `semver::Version::parse` (needs `major.minor.patch`), so it never appears in the
    /// semver-filtered `versions` list — but the SHA-pin index must still resolve it,
    /// since it's the most common real-world GitHub Actions pinning convention.
    #[tokio::test]
    async fn test_get_versions_populates_tag_index_for_bare_major_tag() {
        let sha = "abc123".repeat(7);
        let sha = &sha[..40];
        let mut server = mockito::Server::new_async().await;
        let _mock = server
            .mock("GET", "/repos/actions/checkout/tags")
            .match_query(mockito::Matcher::Any)
            .with_status(200)
            .with_body(format!(
                r#"[{{"name": "v4", "commit": {{"sha": "{sha}"}}}}]"#
            ))
            .create_async()
            .await;

        let registry = mock_registry(&server.url(), false);
        let versions = registry.get_versions("actions/checkout").await.unwrap();
        assert!(
            versions.is_empty(),
            "a bare-major tag must not parse as a full semver version"
        );

        let name = PackageName::new("actions/checkout");
        let index = registry.tag_index.get(&name).unwrap();
        assert_eq!(
            index.tag_to_sha.get("v4"),
            Some(&sha.to_string()),
            "the SHA-pin index must resolve a bare-major tag even though it's not a version"
        );
        assert_eq!(index.sha_to_tag.get(sha), Some(&"v4".to_string()));
    }

    /// Regression for #503: a tag with a non-full-SHA `commit.sha` must still be excluded
    /// from the SHA-pin index, matching `tags_to_versions`' security S-3 filter — the raw
    /// tags list is no longer routed through that filter, so `populate_tag_index` must
    /// apply its own.
    #[tokio::test]
    async fn test_get_versions_tag_index_excludes_non_full_sha() {
        let mut server = mockito::Server::new_async().await;
        let _mock = server
            .mock("GET", "/repos/actions/checkout/tags")
            .match_query(mockito::Matcher::Any)
            .with_status(200)
            .with_body(r#"[{"name": "v4", "commit": {"sha": "not-a-real-sha"}}]"#)
            .create_async()
            .await;

        let registry = mock_registry(&server.url(), false);
        registry.get_versions("actions/checkout").await.unwrap();

        let name = PackageName::new("actions/checkout");
        let index = registry.tag_index.get(&name).unwrap();
        assert!(index.tag_to_sha.is_empty());
        assert!(index.sha_to_tag.is_empty());
    }

    /// Regression for #503 critic S1: when two tags share one commit SHA — a moving
    /// bare-major tag and the precise release it currently points at — `sha_to_tag`
    /// must resolve to the semver-parseable one regardless of the raw `/tags` API's
    /// (undocumented) ordering, since a hover's `**Resolved**` line should name the
    /// precise release, not the moving alias.
    #[tokio::test]
    async fn test_get_versions_sha_to_tag_prefers_semver_tag_over_bare_moving_tag() {
        let sha = "a".repeat(40);
        let mut server = mockito::Server::new_async().await;
        // The moving tag ("v1") is listed before the precise release ("v0.1.15") —
        // mirrors the live ordering observed for softprops/action-gh-release.
        let _mock = server
            .mock("GET", "/repos/owner/repo/tags")
            .match_query(mockito::Matcher::Any)
            .with_status(200)
            .with_body(format!(
                r#"[{{"name": "v1", "commit": {{"sha": "{sha}"}}}}, {{"name": "v0.1.15", "commit": {{"sha": "{sha}"}}}}]"#
            ))
            .create_async()
            .await;

        let registry = mock_registry(&server.url(), false);
        registry.get_versions("owner/repo").await.unwrap();

        let name = PackageName::new("owner/repo");
        let index = registry.tag_index.get(&name).unwrap();
        assert_eq!(
            index.sha_to_tag.get(&sha),
            Some(&"v0.1.15".to_string()),
            "sha_to_tag must prefer the semver-parseable tag over the bare moving one"
        );
        // tag_to_sha has no such ambiguity (keyed by the workflow's own literal ref
        // text) — both names must still resolve to the shared SHA.
        assert_eq!(index.tag_to_sha.get("v1"), Some(&sha));
        assert_eq!(index.tag_to_sha.get("v0.1.15"), Some(&sha));
    }

    #[tokio::test]
    async fn test_get_versions_404_maps_to_package_not_found() {
        let mut server = mockito::Server::new_async().await;
        let _mock = server
            .mock("GET", "/repos/owner/missing/tags")
            .match_query(mockito::Matcher::Any)
            .with_status(404)
            .with_body("{}")
            .create_async()
            .await;

        let registry = mock_registry(&server.url(), false);
        let err = registry.get_versions("owner/missing").await.unwrap_err();
        assert!(matches!(err, DepsError::PackageNotFound { .. }));
    }

    #[tokio::test]
    async fn test_get_versions_403_no_token_gets_actionable_message() {
        let mut server = mockito::Server::new_async().await;
        let _mock = server
            .mock("GET", "/repos/owner/repo/tags")
            .match_query(mockito::Matcher::Any)
            .with_status(403)
            .with_body("{}")
            .create_async()
            .await;

        let registry = mock_registry(&server.url(), false);
        let err = registry.get_versions("owner/repo").await.unwrap_err();
        // Guards the variant itself (#478), not just the rendered text: a
        // regression that left the old, differently-classified error type in
        // place while keeping "GITHUB_TOKEN" in its `Display` text would pass
        // a `to_string().contains(...)` check but must fail here.
        assert!(
            matches!(err, DepsError::RateLimited { .. }),
            "expected DepsError::RateLimited, got {err:?}"
        );
        assert!(err.to_string().contains("GITHUB_TOKEN"));

        // Trace the real production error all the way to the diagnostic-facing
        // classification: a rate-limited fetch must become an `Actionable`
        // `FetchFailure` carrying the same hint, never `Transient`.
        let failure = err.fetch_failure();
        assert!(
            matches!(&failure, deps_core::error::FetchFailure::Actionable(hint) if hint.contains("GITHUB_TOKEN")),
            "expected Actionable hint mentioning GITHUB_TOKEN, got {failure:?}"
        );

        // And through the same `HashMap<String, FetchFailure>` shape
        // `deps-lsp`'s document lifecycle threads into
        // `generate_diagnostics_from_cache`.
        let fetch_failed: HashMap<String, deps_core::error::FetchFailure> =
            HashMap::from([("owner/repo".to_string(), failure)]);
        assert!(matches!(
            fetch_failed.get("owner/repo"),
            Some(deps_core::error::FetchFailure::Actionable(_))
        ));
    }

    #[tokio::test]
    async fn test_get_versions_403_trips_gate_and_short_circuits_next_call() {
        let mut server = mockito::Server::new_async().await;
        // `.expect(1)`: the second `get_versions` call below must NOT reach the network.
        let mock = server
            .mock("GET", "/repos/owner/repo/tags")
            .match_query(mockito::Matcher::Any)
            .with_status(403)
            .with_body("{}")
            .expect(1)
            .create_async()
            .await;

        let registry = mock_registry(&server.url(), false);
        assert!(registry.get_versions("owner/repo").await.is_err());
        assert!(registry.rate_limit.is_tripped());

        let err = registry.get_versions("owner/repo").await.unwrap_err();
        assert!(err.to_string().contains("GITHUB_TOKEN"));
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_get_versions_403_with_token_does_not_trip_shared_gate() {
        // Critic M3: a 403 received *despite* a valid GITHUB_TOKEN (org-policy/SAML
        // restriction, or a genuinely inaccessible private repo) is scoped to that one
        // repository and must not disable GHA lookups workspace-wide for every other,
        // accessible repository.
        let mut server = mockito::Server::new_async().await;
        let _mock = server
            .mock("GET", "/repos/owner/private-repo/tags")
            .match_query(mockito::Matcher::Any)
            .with_status(403)
            .with_body("{}")
            .create_async()
            .await;

        let registry = mock_registry(&server.url(), true);
        let err = registry
            .get_versions("owner/private-repo")
            .await
            .unwrap_err();
        assert!(matches!(err, DepsError::HttpStatus { status: 403, .. }));
        assert!(!registry.rate_limit.is_tripped());
    }

    #[tokio::test]
    async fn test_get_versions_rejects_invalid_owner_repo_with_zero_requests() {
        let registry = mock_registry("http://127.0.0.1:1", false);
        let err = registry.get_versions("../../etc/passwd").await.unwrap_err();
        assert!(matches!(err, DepsError::InvalidUri(_)));
    }

    #[tokio::test]
    async fn test_get_latest_matching_finds_matching_version() {
        let mut server = mockito::Server::new_async().await;
        let _mock = server
            .mock("GET", "/repos/owner/repo/tags")
            .match_query(mockito::Matcher::Any)
            .with_status(200)
            .with_body(format!(
                r#"[{{"name": "v2.0.0", "commit": {{"sha": "{}"}}}}, {{"name": "v1.0.0", "commit": {{"sha": "{}"}}}}]"#,
                "a".repeat(40),
                "b".repeat(40)
            ))
            .create_async()
            .await;

        let registry = mock_registry(&server.url(), false);
        let latest = registry
            .get_latest_matching("owner/repo", "^1.0.0")
            .await
            .unwrap();
        assert_eq!(
            latest.map(|v| v.version.to_string()),
            Some("v1.0.0".to_string())
        );
    }

    #[tokio::test]
    async fn test_select_latest_matching_wildcard_uses_existence_ladder() {
        use deps_core::{Registry, VersionReq};

        let versions: Vec<Box<dyn deps_core::Version>> = vec![Box::new(GithubActionsVersion {
            version: "v2.0.0-beta.1".into(),
            sha: "a".repeat(40),
            prerelease: true,
            published_at: None,
        })];
        let registry = mock_registry("http://127.0.0.1:1", false);
        let req = VersionReq::new("*");
        assert_eq!(registry.select_latest_matching(&versions, &req), Some(0));
    }

    #[test]
    fn test_evict_in_flight_never_evicts_held_lock() {
        // Deterministic, not probabilistic (critic M4): every entry but one is held
        // (a live second `Arc` reference simulating an in-flight waiter), so exactly
        // one entry has `strong_count() == 1` and is the only possible victim —
        // regardless of `DashMap`'s iteration order. The old version left
        // `MAX_IN_FLIGHT_ENTRIES` unheld entries alongside the one held entry, so a
        // buggy implementation with no `strong_count` filter would still pick the held
        // entry only ~1-in-257 times and pass anyway.
        let map: DashMap<PackageName, Arc<tokio::sync::Mutex<()>>> = DashMap::new();
        let unheld_key = PackageName::new("owner/unheld");
        let mut still_held = Vec::new();

        for i in 0..MAX_IN_FLIGHT_ENTRIES {
            let key = PackageName::new(format!("owner/held{i}"));
            let lock = Arc::new(tokio::sync::Mutex::new(()));
            still_held.push(Arc::clone(&lock));
            map.insert(key, lock);
        }
        map.insert(unheld_key.clone(), Arc::new(tokio::sync::Mutex::new(())));
        assert!(map.len() >= MAX_IN_FLIGHT_ENTRIES);
        // `still_held` must live at least this long: each pushed `Arc` clone is what
        // keeps every "owner/heldN" entry's `strong_count() > 1` (in-flight) for the
        // eviction call below.
        assert_eq!(still_held.len(), MAX_IN_FLIGHT_ENTRIES);

        evict_in_flight_if_full(&map);

        assert!(
            !map.contains_key(&unheld_key),
            "the only unheld entry must be the one evicted"
        );
        for i in 0..MAX_IN_FLIGHT_ENTRIES {
            assert!(
                map.contains_key(&PackageName::new(format!("owner/held{i}"))),
                "a held (in-flight) coalescing lock must never be evicted"
            );
        }
        drop(still_held);
    }

    #[test]
    fn test_evict_in_flight_evicts_an_unheld_lock_when_full() {
        let map: DashMap<PackageName, Arc<tokio::sync::Mutex<()>>> = DashMap::new();
        for i in 0..MAX_IN_FLIGHT_ENTRIES {
            map.insert(
                PackageName::new(format!("owner/repo{i}")),
                Arc::new(tokio::sync::Mutex::new(())),
            );
        }
        evict_in_flight_if_full(&map);
        assert_eq!(map.len(), MAX_IN_FLIGHT_ENTRIES - 1);
    }

    #[tokio::test]
    async fn test_concurrent_get_versions_for_same_repo_both_succeed() {
        // `HttpCache::get_cached_with_headers_via` always sends a conditional
        // revalidation request even on a cache hit (RFC 7232 ETag semantics), so a
        // strict "exactly one HTTP request" assertion here would be testing a
        // guarantee this architecture does not make. What per-repository coalescing
        // *does* guarantee — no two callers racing to fill a cold, empty cache at
        // once — is covered directly by `test_acquire_in_flight_lock_returns_shared_arc`
        // below; this integration test only proves coalescing never breaks a
        // concurrent pair of calls for the same repository.
        let mut server = mockito::Server::new_async().await;
        let _mock = server
            .mock("GET", "/repos/owner/repo/tags")
            .match_query(mockito::Matcher::Any)
            .with_status(200)
            .with_body(format!(
                r#"[{{"name": "v1.0.0", "commit": {{"sha": "{}"}}}}]"#,
                "a".repeat(40)
            ))
            .create_async()
            .await;

        let registry = mock_registry(&server.url(), false);
        let (a, b) = tokio::join!(
            registry.get_versions("owner/repo"),
            registry.get_versions("owner/repo")
        );
        assert!(a.is_ok());
        assert!(b.is_ok());
    }

    #[test]
    fn test_acquire_in_flight_lock_returns_shared_arc_for_same_repo() {
        let registry = mock_registry("http://127.0.0.1:1", false);
        let a = registry.acquire_in_flight_lock(&PackageName::new("owner/repo"));
        let b = registry.acquire_in_flight_lock(&PackageName::new("owner/repo"));
        assert!(Arc::ptr_eq(&a, &b));
    }

    #[test]
    fn test_acquire_in_flight_lock_returns_distinct_arc_for_different_repos() {
        let registry = mock_registry("http://127.0.0.1:1", false);
        let a = registry.acquire_in_flight_lock(&PackageName::new("owner/repo-a"));
        let b = registry.acquire_in_flight_lock(&PackageName::new("owner/repo-b"));
        assert!(!Arc::ptr_eq(&a, &b));
    }

    /// Regression for #472 critic M3: `get_versions` must label its pagination-cap
    /// truncation warning `"GitHub Actions"`, not some other ecosystem's name. A
    /// hardcoded/rearranged `paginate_tags("GitHub Actions", ...)` call site would
    /// silently break this without failing any other test, since `deps_core::github`'s
    /// own tests only exercise `paginate_tags` with an arbitrary ecosystem string.
    #[tokio::test]
    async fn test_get_versions_pagination_cap_warning_is_labeled_github_actions() {
        use deps_core::test_util::capture_tracing_output_async;

        let sha = "a".repeat(40);
        let mut server = mockito::Server::new_async().await;
        let full_page: String = format!(
            "[{}]",
            (0..100)
                .map(|i| format!(r#"{{"name":"{i}.0.0","commit":{{"sha":"{sha}"}}}}"#))
                .collect::<Vec<_>>()
                .join(",")
        );
        let _mock = server
            .mock("GET", "/repos/owner/repo/tags")
            .match_query(mockito::Matcher::Any)
            .with_status(200)
            .with_body(full_page)
            .expect(deps_core::github::MAX_TAG_PAGES as usize)
            .create_async()
            .await;

        let registry = mock_registry(&server.url(), false);
        let output = capture_tracing_output_async(async {
            registry.get_versions("owner/repo").await.unwrap();
        })
        .await;

        assert!(output.contains("GitHub Actions"), "output was: {output}");
        assert!(output.contains("cap"), "output was: {output}");
    }

    // --- attach_publish_times (#486) ---

    #[test]
    fn test_attach_publish_times_match_strips_v_prefix() {
        // `version` keeps the `v` prefix as published, but `dates`'s keys are
        // normalized (mirrors `ReleaseDatesCache`'s release-tag_name join key) — the
        // join must strip it before looking up.
        let mut versions = vec![GithubActionsVersion {
            version: "v4.2.0".into(),
            sha: "a".repeat(40),
            prerelease: false,
            published_at: None,
        }];
        let published = PublishTime::parse_rfc3339("2026-01-02T08:56:05Z").unwrap();
        let dates = HashMap::from([("4.2.0".to_string(), published)]);
        attach_publish_times(&mut versions, &dates);
        assert_eq!(versions[0].published_at, Some(published));
    }

    #[test]
    fn test_attach_publish_times_missing_release_stays_none() {
        let mut versions = vec![GithubActionsVersion {
            version: "v4.2.0".into(),
            sha: "a".repeat(40),
            prerelease: false,
            published_at: None,
        }];
        attach_publish_times(&mut versions, &HashMap::new());
        assert_eq!(versions[0].published_at, None);
    }

    // --- Registry::get_versions_with: freshness.enabled gate (#486) ---

    #[tokio::test]
    async fn test_get_versions_with_disabled_freshness_skips_release_dates_fetch() {
        use deps_core::{FreshnessSettings, Registry};

        let mut server = mockito::Server::new_async().await;
        let sha = "a".repeat(40);
        let _tags_mock = server
            .mock("GET", "/repos/owner/repo/tags")
            .match_query(mockito::Matcher::Any)
            .with_status(200)
            .with_body(format!(
                r#"[{{"name": "v1.0.0", "commit": {{"sha": "{sha}"}}}}]"#
            ))
            .create_async()
            .await;
        // Asserted at the end: the disabled path must never touch the releases
        // endpoint at all, not merely tolerate it failing.
        let releases_mock = server
            .mock("GET", "/repos/owner/repo/releases")
            .match_query(mockito::Matcher::Any)
            .with_status(200)
            .with_body("[]")
            .expect(0)
            .create_async()
            .await;

        let registry = mock_registry(&server.url(), true);
        let name = PackageName::new("owner/repo");
        let freshness = FreshnessSettings {
            enabled: false,
            ..Default::default()
        };

        let versions = registry.get_versions_with(&name, freshness).await.unwrap();

        assert_eq!(versions.len(), 1);
        assert!(versions.iter().all(|v| v.published_at().is_none()));
        releases_mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_get_versions_with_enabled_freshness_attaches_publish_dates() {
        use deps_core::{FreshnessSettings, Registry};

        let mut server = mockito::Server::new_async().await;
        let sha = "a".repeat(40);
        let _tags_mock = server
            .mock("GET", "/repos/owner/repo/tags")
            .match_query(mockito::Matcher::Any)
            .with_status(200)
            .with_body(format!(
                r#"[{{"name": "v1.0.0", "commit": {{"sha": "{sha}"}}}}]"#
            ))
            .create_async()
            .await;
        let _releases_mock = server
            .mock("GET", "/repos/owner/repo/releases")
            .match_query(mockito::Matcher::Any)
            .with_status(200)
            .with_body(
                r#"[{"tag_name": "v1.0.0", "published_at": "2026-01-02T08:56:05Z", "draft": false}]"#,
            )
            .create_async()
            .await;

        let registry = mock_registry(&server.url(), true);
        let name = PackageName::new("owner/repo");
        let freshness = FreshnessSettings {
            enabled: true,
            ..Default::default()
        };

        let versions = registry.get_versions_with(&name, freshness).await.unwrap();

        assert_eq!(versions.len(), 1);
        assert!(versions.iter().all(|v| v.published_at().is_some()));
    }

    #[tokio::test]
    async fn test_get_versions_with_enabled_freshness_missing_release_stays_none() {
        use deps_core::{FreshnessSettings, Registry};

        let mut server = mockito::Server::new_async().await;
        let sha = "a".repeat(40);
        let _tags_mock = server
            .mock("GET", "/repos/owner/repo/tags")
            .match_query(mockito::Matcher::Any)
            .with_status(200)
            .with_body(format!(
                r#"[{{"name": "v1.0.0", "commit": {{"sha": "{sha}"}}}}]"#
            ))
            .create_async()
            .await;
        // The repo has releases, but none for this tag.
        let _releases_mock = server
            .mock("GET", "/repos/owner/repo/releases")
            .match_query(mockito::Matcher::Any)
            .with_status(200)
            .with_body(
                r#"[{"tag_name": "v0.9.0", "published_at": "2025-01-01T00:00:00Z", "draft": false}]"#,
            )
            .create_async()
            .await;

        let registry = mock_registry(&server.url(), true);
        let name = PackageName::new("owner/repo");
        let freshness = FreshnessSettings {
            enabled: true,
            ..Default::default()
        };

        let versions = registry.get_versions_with(&name, freshness).await.unwrap();

        assert_eq!(versions.len(), 1);
        assert!(versions.iter().all(|v| v.published_at().is_none()));
    }

    #[tokio::test]
    async fn test_get_versions_with_enabled_freshness_releases_fetch_error_falls_back_to_none() {
        use deps_core::{FreshnessSettings, Registry};

        let mut server = mockito::Server::new_async().await;
        let sha = "a".repeat(40);
        let _tags_mock = server
            .mock("GET", "/repos/owner/repo/tags")
            .match_query(mockito::Matcher::Any)
            .with_status(200)
            .with_body(format!(
                r#"[{{"name": "v1.0.0", "commit": {{"sha": "{sha}"}}}}]"#
            ))
            .create_async()
            .await;
        let _releases_mock = server
            .mock("GET", "/repos/owner/repo/releases")
            .match_query(mockito::Matcher::Any)
            .with_status(500)
            .create_async()
            .await;
        // The tags fetch must still succeed even though the releases fetch errors:
        // `ReleaseDatesCache::fetch` treats any fetch failure as an empty map, never
        // propagated into the tags fetch's own success.
        let registry = mock_registry(&server.url(), true);
        let name = PackageName::new("owner/repo");
        let freshness = FreshnessSettings {
            enabled: true,
            ..Default::default()
        };

        let versions = registry.get_versions_with(&name, freshness).await.unwrap();

        assert_eq!(versions.len(), 1);
        assert!(versions.iter().all(|v| v.published_at().is_none()));
    }
}
