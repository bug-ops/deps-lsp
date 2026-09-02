//! GitHub Actions registry using the GitHub tags API.
//!
//! Fetches tags for `owner/repo` action/workflow repositories. Non-GitHub identities are
//! rejected before any request is made (`validate_owner_repo`).

use bytes::Bytes;
use dashmap::DashMap;
use deps_core::{
    DepsError, HttpCache, PackageName, Result, is_dot_segment, lsp_helpers::warn_rejected_value,
};
use serde::Deserialize;
use std::any::Any;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::types::GithubActionsVersion;

const GITHUB_API: &str = "https://api.github.com";

/// Display name for the registry backing GitHub Actions version lookups, used in
/// not-found and API-response error messages.
pub const REGISTRY: &str = "GitHub";

/// Maximum number of `tags` pages fetched per repository (100 tags/page). Mirrors
/// `deps-swift`'s bound for the identical endpoint — S2's revision reverted an earlier,
/// arithmetically unjustified `10`: no realistic action/workflow repository has more than
/// a few hundred tags, so page 2+ is already rare, and diverging from the sibling crate
/// bought nothing.
const MAX_TAG_PAGES: u32 = 30;

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

/// Validates that `name` is a valid `owner/repo` GitHub identifier.
///
/// Mirrors `deps_swift::registry::validate_owner_repo`: accepts
/// [`crate::is_valid_github_identity`]'s charset, and additionally rejects a `.`/`..`
/// segment (not neutralized by URL construction — #357's class of bug) before `name`
/// reaches this registry's `{api_base}/repos/{name}/tags` fetch as a bare path segment.
fn validate_owner_repo(name: &str) -> Result<()> {
    if crate::is_valid_github_identity(name) {
        return Ok(());
    }
    if let Some((owner, repo)) = name.split_once('/')
        && (is_dot_segment(owner) || is_dot_segment(repo))
    {
        warn_rejected_value("is_dot_segment", "GitHub owner/repo request URL", name);
    }
    Err(DepsError::InvalidUri(format!(
        "invalid owner/repo format: '{name}'"
    )))
}

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
    cache: Arc<HttpCache>,
    auth_headers: Vec<(reqwest::header::HeaderName, String)>,
    has_token: bool,
    /// Base URL for the GitHub API, `GITHUB_API` in production; overridable in tests to
    /// point at a `mockito` server.
    api_base: String,
    tag_index: Arc<DashMap<PackageName, Arc<TagIndex>>>,
    in_flight: Arc<DashMap<PackageName, Arc<tokio::sync::Mutex<()>>>>,
    rate_limit: Arc<RateLimitGate>,
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
        let token = std::env::var("GITHUB_TOKEN").ok().filter(|t| !t.is_empty());
        let has_token = token.is_some();
        let auth_headers = token
            .map(|token| {
                tracing::info!("GITHUB_TOKEN detected, using authenticated GitHub API requests");
                vec![(reqwest::header::AUTHORIZATION, format!("Bearer {token}"))]
            })
            .unwrap_or_default();

        Self {
            cache,
            auth_headers,
            has_token,
            api_base: GITHUB_API.to_string(),
            tag_index: Arc::new(DashMap::new()),
            in_flight: Arc::new(DashMap::new()),
            rate_limit: Arc::new(RateLimitGate::default()),
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

    fn headers(&self) -> Vec<(reqwest::header::HeaderName, &str)> {
        self.auth_headers
            .iter()
            .map(|(k, v): &(reqwest::header::HeaderName, String)| (k.clone(), v.as_str()))
            .collect()
    }

    fn rate_limited_error() -> DepsError {
        DepsError::CacheError(
            "GitHub API rate limit exceeded. Set GITHUB_TOKEN to increase the limit (5000 req/h). Run: export GITHUB_TOKEN=$(gh auth token)".into(),
        )
    }

    fn map_tags_error(&self, name: &str, e: DepsError) -> DepsError {
        match &e {
            // Trip the process-wide gate only for the no-token case this cooldown
            // exists for: a *tokened* 403 is far more likely an org-policy/SAML
            // restriction or a genuinely inaccessible private repo, scoped to that one
            // repository — tripping the shared gate on it would disable GHA lookups
            // workspace-wide for every other (accessible) repository too (critic M3).
            DepsError::HttpStatus { status: 403, .. } if self.has_token => e,
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

    fn populate_tag_index(&self, name: &PackageName, tags: &[GithubActionsVersion]) {
        let mut index = TagIndex::default();
        for tag in tags {
            let tag_str = tag.version.as_str().to_string();
            index
                .sha_to_tag
                .entry(tag.sha.clone())
                .or_insert_with(|| tag_str.clone());
            index
                .tag_to_sha
                .entry(tag_str)
                .or_insert_with(|| tag.sha.clone());
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

        let tags = paginate_tags(name, |page| async move {
            let url = format!(
                "{}/repos/{name}/tags?per_page=100&page={page}",
                self.api_base
            );
            self.cache
                .get_cached_with_headers(&url, &self.headers())
                .await
                .map_err(|e| self.map_tags_error(name, e))
        })
        .await?;

        let versions = tags_to_versions(tags);
        self.populate_tag_index(&package_name, &versions);
        Ok(versions)
    }

    /// Finds the latest version satisfying the given semver requirement.
    pub async fn get_latest_matching(
        &self,
        name: &str,
        req_str: &str,
    ) -> Result<Option<GithubActionsVersion>> {
        let versions = self.get_versions(name).await?;
        let req = match semver::VersionReq::parse(normalize_semver_input(req_str).as_str()) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("Failed to parse version req '{}': {}", req_str, e);
                return Ok(None);
            }
        };
        Ok(versions.into_iter().find(|v| {
            semver::Version::parse(normalize_semver_input(v.version.as_str()).as_str())
                .is_ok_and(|ver| req.matches(&ver))
        }))
    }
}

/// GitHub tags API response item.
#[derive(Debug, Deserialize)]
struct GithubTag {
    name: String,
    commit: GithubTagCommit,
}

#[derive(Debug, Deserialize)]
struct GithubTagCommit {
    sha: String,
}

/// GitHub API error response (rate limit, not found, etc.).
#[derive(Deserialize)]
struct GithubErrorResponse {
    message: String,
}

/// Returns `true` when a fetched page came back full (`per_page=100` entries), meaning a
/// subsequent page may exist and should be fetched too.
const fn page_has_more(page_len: usize) -> bool {
    page_len >= 100
}

fn warn_if_pagination_truncated(name: &str, page: u32, page_len: usize) {
    if page == MAX_TAG_PAGES && page_has_more(page_len) {
        tracing::warn!(
            package = name,
            pages_fetched = MAX_TAG_PAGES,
            "GitHub Actions tags pagination for '{name}' stopped at the {MAX_TAG_PAGES}-page \
             cap while GitHub reported more pages available; the fetched version list may be \
             truncated"
        );
    }
}

/// Drives the GitHub tags pagination loop. Mirrors `deps_swift::registry::paginate_tags`.
async fn paginate_tags<F, Fut>(name: &str, mut fetch_page: F) -> Result<Vec<GithubTag>>
where
    F: FnMut(u32) -> Fut,
    Fut: std::future::Future<Output = Result<Bytes>>,
{
    let mut tags = Vec::new();
    for page in 1..=MAX_TAG_PAGES {
        let data = fetch_page(page).await?;
        let page_tags = parse_tags_page(&data)?;
        let page_len = page_tags.len();
        tags.extend(page_tags);
        if !page_has_more(page_len) {
            break;
        }
        warn_if_pagination_truncated(name, page, page_len);
    }
    Ok(tags)
}

/// Parses a single GitHub tags API response page into raw tag entries.
fn parse_tags_page(data: &[u8]) -> Result<Vec<GithubTag>> {
    match deps_core::parse_json_checked(data) {
        Ok(tags) => Ok(tags),
        Err(_) => {
            if let Ok(err) = deps_core::parse_json_checked::<GithubErrorResponse>(data) {
                Err(DepsError::CacheError(format!(
                    "GitHub API error: {}",
                    err.message
                )))
            } else {
                Ok(vec![])
            }
        }
    }
}

/// Strips a leading `v`/`V` tag prefix for semver parsing only — the returned
/// `GithubActionsVersion::version` keeps the tag exactly as published (the pin contract's
/// "tag as published" rule).
fn normalize_semver_input(name: &str) -> String {
    name.strip_prefix(['v', 'V']).unwrap_or(name).to_string()
}

/// Converts raw tags (possibly accumulated across pages) into a newest-first
/// `GithubActionsVersion` list. Non-semver tags are skipped; dedupe by normalized
/// semver, first (page-order) occurrence wins.
///
/// Also drops any tag whose `commit.sha` is not [`crate::parser::is_full_sha`]-shaped
/// (security S-3): the SHA reaches `TagIndex` unfiltered from here, and is later
/// spliced verbatim into a manifest text edit (`GithubActionsFormatter::
/// format_version_replacing_for`'s `PinStyle::Sha` branch) and a hover string — the one
/// registry-supplied value in this crate that otherwise bypasses every allowlist gate
/// (`is_safe_version_string` covers the *version*, not the SHA). Filtering at ingestion
/// covers both consumers from one place.
fn tags_to_versions(tags: Vec<GithubTag>) -> Vec<GithubActionsVersion> {
    let mut seen = std::collections::HashSet::new();
    let mut versions_with_parsed: Vec<(GithubActionsVersion, semver::Version)> = tags
        .into_iter()
        .filter_map(|tag| {
            let normalized = normalize_semver_input(&tag.name);
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
                },
                parsed,
            ))
        })
        .collect();

    versions_with_parsed.sort_unstable_by(|a, b| b.1.cmp(&a.1));
    versions_with_parsed.into_iter().map(|(v, _)| v).collect()
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
        let parsed_req =
            semver::VersionReq::parse(normalize_semver_input(req.as_str()).as_str()).ok()?;
        versions.iter().position(|v| {
            semver::Version::parse(normalize_semver_input(v.version_string().as_str()).as_str())
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
    use deps_core::test_util::{capture_tracing_output, capture_tracing_output_async};

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
        let tags: Vec<GithubTag> = parse_tags_page(json.as_bytes()).unwrap();
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
        let tags: Vec<GithubTag> = parse_tags_page(json.as_bytes()).unwrap();
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
        let tags: Vec<GithubTag> = parse_tags_page(json.as_bytes()).unwrap();
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
        let tags: Vec<GithubTag> = parse_tags_page(json.as_bytes()).unwrap();
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
        let tags: Vec<GithubTag> = parse_tags_page(json.as_bytes()).unwrap();
        assert!(tags_to_versions(tags).is_empty());
    }

    #[test]
    fn test_tags_to_versions_rejects_tag_with_non_full_sha() {
        // Security S-3: a tag whose `commit.sha` is not a full 40-hex SHA must never
        // reach `TagIndex`/a version list, since it is later spliced verbatim into a
        // manifest text edit and a hover string with no other allowlist gate.
        let json = r#"[{"name": "v1.0.0", "commit": {"sha": "not-a-real-sha"}}]"#;
        let tags: Vec<GithubTag> = parse_tags_page(json.as_bytes()).unwrap();
        assert!(tags_to_versions(tags).is_empty());
    }

    #[test]
    fn test_parse_tags_invalid_json_returns_empty() {
        let result = parse_tags_page(b"not json").unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_parse_tags_github_rate_limit_returns_error() {
        let json = r#"{"message":"API rate limit exceeded for 1.2.3.4."}"#;
        let result = parse_tags_page(json.as_bytes());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("rate limit"));
    }

    #[test]
    fn test_validate_owner_repo_valid_and_invalid() {
        assert!(validate_owner_repo("actions/checkout").is_ok());
        assert!(validate_owner_repo("no-slash").is_err());
        assert!(validate_owner_repo("owner/..").is_err());
        assert!(validate_owner_repo("../repo").is_err());
    }

    #[test]
    fn test_page_has_more() {
        assert!(page_has_more(100));
        assert!(!page_has_more(99));
    }

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
        let auth_headers = if has_token {
            vec![(
                reqwest::header::AUTHORIZATION,
                "Bearer test-token".to_string(),
            )]
        } else {
            Vec::new()
        };
        GithubActionsRegistry {
            cache: Arc::new(HttpCache::new()),
            auth_headers,
            has_token,
            api_base: base.to_string(),
            tag_index: Arc::new(DashMap::new()),
            in_flight: Arc::new(DashMap::new()),
            rate_limit: Arc::new(RateLimitGate::default()),
        }
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
        assert!(err.to_string().contains("GITHUB_TOKEN"));
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

    #[test]
    fn test_pagination_warns_when_truncated_at_cap() {
        let output = capture_tracing_output(|| {
            warn_if_pagination_truncated("owner/repo", MAX_TAG_PAGES, 100);
        });
        assert!(output.contains("owner/repo"), "output was: {output}");
        assert!(output.contains("cap"), "output was: {output}");
    }

    #[tokio::test]
    async fn test_paginate_tags_stops_after_partial_page() {
        use std::sync::atomic::{AtomicU32, Ordering};

        fn tags_page_json(count: usize) -> Bytes {
            let entries: Vec<String> = (0..count)
                .map(|i| format!(r#"{{"name":"v{i}.0.0","commit":{{"sha":"s{i}"}}}}"#))
                .collect();
            Bytes::from(format!("[{}]", entries.join(",")))
        }

        let calls = AtomicU32::new(0);
        let output = capture_tracing_output_async(async {
            let result = paginate_tags("owner/repo", |page| {
                calls.fetch_add(1, Ordering::SeqCst);
                async move {
                    match page {
                        1 => Ok(tags_page_json(100)),
                        2 => Ok(tags_page_json(42)),
                        _ => panic!("page {page} must not be fetched after a partial page"),
                    }
                }
            })
            .await
            .unwrap();
            assert_eq!(result.len(), 142);
        })
        .await;
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert!(output.is_empty(), "output was: {output}");
    }
}
