//! Supply-chain trust signal via [deps.dev API v3](https://docs.deps.dev/api/v3/).
//!
//! [`DepsDevClient::trust_signal`] assembles an [`SupplyChainTrustSignal`]
//! (OpenSSF Scorecard + SLSA/attestation provenance) for one resolved
//! `(system, name, version)` from two sequential deps.dev calls, and is
//! infallible by construction: every failure — network, timeout, non-2xx,
//! malformed JSON, no linked source repository — degrades to `None` rather
//! than propagating an error into hover (FR-006), mirroring
//! [`crate::osv::OsvClient::scan`] and `github::ReleaseDatesCache::fetch`.
//!
//! deps.dev sends no `ETag`/`Last-Modified` on either endpoint (live-verified
//! 2026-09-03), so [`crate::cache::HttpCache`]'s conditional-GET entry cache
//! cannot apply here — this client reuses only `HttpCache`'s transport
//! (HTTPS enforcement, DNS guard, body cap, origin-pinned redirects) via
//! [`crate::cache::HttpCache::get_transport_only_with_headers_limited_trusted_origin`]
//! and layers its own TTL memo over the *assembled* signal instead, the same
//! deviation `crate::osv` already documents for OSV.dev's identical
//! missing-validators case.
//!
//! ## `SOURCE_REPO` selection and the self-reported disclosure
//!
//! A package's `relatedProjects[]` commonly carries several `SOURCE_REPO`
//! entries, differing only in `relationProvenance`. `choose_project_key`
//! prefers an `SLSA_ATTESTATION`-backed entry over an `UNVERIFIED_METADATA`
//! (package-self-reported) one: the latter is derived from the package's own
//! manifest metadata, so an unranked pick would let a hostile package point
//! its repository field at a reputable, high-scoring repo and inherit that
//! repo's Scorecard. When only a self-reported relation exists,
//! [`ScorecardSummary::self_reported`] carries that fact to the hover
//! renderer, which discloses it rather than presenting the score with the
//! same confidence as an attested relation.

mod types;

use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::{DashMap, DashSet};

use types::{DepsDevProject, DepsDevVersionInfo, ProvenanceEntry, RelatedProject};
pub use types::{ProvenanceStatus, ScorecardSummary, SupplyChainTrustSignal};

use crate::EcosystemId;
use crate::cache::{BodyLimit, HttpCache};
use crate::error::DepsError;

const DEPS_DEV_API: &str = "https://api.deps.dev";

/// Per-call timeout inside [`DepsDevClient::trust_signal`]'s two-call
/// sequence. Deliberately shorter than the hover-side wait budget
/// (`DEPS_DEV_WAIT_BUDGET` in `lsp_helpers::hover`) so a hung version call
/// can never by itself consume the whole budget and starve the project call
/// of any chance to return within it.
const DEPS_DEV_CALL_TIMEOUT: Duration = Duration::from_millis(400);

/// TTL for a successfully assembled signal, or a definitive HTTP 404 —
/// matches deps.dev's own declared `cache-control: max-age=3600`. A 404 gets
/// this same positive TTL, not the shorter error TTL: it is deps.dev
/// authoritatively saying "no record", not a transient fault, and treating
/// it as transient would re-fire 1-2 requests every error-TTL window for
/// every hover of any private/internal/brand-new package.
const DEPS_DEV_SUCCESS_TTL: Duration = Duration::from_hours(1);

/// TTL for a network error, timeout, 5xx, or malformed response — short
/// enough that a transient outage self-heals within a couple of minutes of
/// hovering, matching `github::RELEASE_DATES_ERROR_TTL`'s reasoning.
const DEPS_DEV_ERROR_TTL: Duration = Duration::from_secs(90);

/// Entry-count bound shared by both memos, mirroring
/// `github::MAX_RELEASE_DATES_MEMO_ENTRIES`'s reasoning: comfortably above
/// the distinct-package count of any realistic workspace.
const MAX_MEMO_ENTRIES: usize = 512;

/// Response body size cap for both deps.dev endpoints — their bodies are a
/// few KB at most; this is defense-in-depth, not a tuned budget.
const DEPS_DEV_BODY_LIMIT: usize = 1024 * 1024;

/// Key for [`DepsDevClient`]'s version-level memo.
///
/// A typed struct, not a `\0`-joined string: `name` comes from a manifest
/// and `version` from `in_use_version` (whose lockfile `ConcreteVersion`
/// branch is never charset-validated), so a joined-string key could let
/// `("a\0b", "c")` and `("a", "b\0c")` collide and serve another package's
/// trust signal. A derived `Hash`/`Eq` over four fields cannot collide by
/// construction. `base` is included for the same reason
/// `github::ReleaseDatesCache` keys on `(api_base, name)`: a mock-server hit
/// in tests must never serve a real-API read from a shared client instance.
#[derive(Debug, Hash, PartialEq, Eq, Clone)]
struct MemoKey {
    base: String,
    system: &'static str,
    name: String,
    version: String,
}

struct MemoEntry {
    fetched_at: Instant,
    ttl: Duration,
    /// The outcome, negative results included — memoizing `None` is what
    /// makes "zero requests on a repeat call" hold on the failure path too.
    signal: Option<SupplyChainTrustSignal>,
}

/// Key for [`DepsDevClient`]'s project-level memo — the Scorecard is a
/// property of the *project*, not the version, so this is keyed separately
/// from [`MemoKey`] to avoid one project call per version of a package a
/// user hovers repeatedly (e.g. several `@babel/*` packages sharing one
/// project).
#[derive(Debug, Hash, PartialEq, Eq, Clone)]
struct ProjectKeyMemo {
    base: String,
    /// Already validated by [`is_valid_project_key`] before it reaches here.
    project_key: String,
}

/// Stores the raw score only — **never** a [`ScorecardSummary`]. The
/// `self_reported` disclosure is a property of the *hovering package's own
/// relation* to the project (spec §6, plan D5/O5), not of the project
/// itself, so it must never be cached alongside the score: two packages
/// sharing one `project_key` can have different `self_reported` values, and
/// caching a resolved `ScorecardSummary` here would let whichever package
/// warms the entry first silently fix the disclosure marker for every later
/// package sharing that key (security M1/critic C1).
struct ProjectMemoEntry {
    fetched_at: Instant,
    ttl: Duration,
    overall_score: Option<f32>,
}

/// Releases an in-flight claim on drop — including on panic — so a claim can
/// never leak and permanently block later calls for the same key.
struct InFlightGuard<'a> {
    set: &'a DashSet<MemoKey>,
    key: MemoKey,
}

impl Drop for InFlightGuard<'_> {
    fn drop(&mut self) {
        self.set.remove(&self.key);
    }
}

/// Evicts entries from `map` when it is already at `max_entries`, ahead of
/// an insert that would otherwise grow it further: first every entry expired
/// against its own TTL, then — only if that freed nothing — the single
/// oldest entry by `fetched_at`. Mirrors
/// `github::evict_release_dates_if_full`'s policy, generalized over both of
/// this module's memo maps.
fn evict_if_full<K, V>(
    map: &DashMap<K, V>,
    max_entries: usize,
    fetched_at: impl Fn(&V) -> Instant,
    ttl: impl Fn(&V) -> Duration,
) where
    K: Eq + std::hash::Hash + Clone,
{
    if map.len() < max_entries {
        return;
    }
    let now = Instant::now();
    map.retain(|_, v| now.duration_since(fetched_at(v)) < ttl(v));
    if map.len() >= max_entries
        && let Some(oldest) = map
            .iter()
            .min_by_key(|e| fetched_at(e.value()))
            .map(|e| e.key().clone())
    {
        map.remove(&oldest);
    }
}

/// Maps a deps-lsp [`EcosystemId`] to deps.dev's `system` path segment.
///
/// Exhaustive, with **no wildcard arm**: the six ecosystems deps.dev does
/// not cover (FR-011: Composer, Dart, Swift; plus Gradle, Deno, and GitHub
/// Actions, out of this spec's enumerated seven — plan.md §7 D8) are named
/// explicitly rather than falling through a `_ => None`. Adding a
/// fourteenth [`EcosystemId`] variant is therefore a compile error until
/// someone decides which side it belongs on — stronger than a trait default
/// that would silently opt a new ecosystem out, and this is what makes
/// FR-005/FR-011 hold by construction rather than by convention.
#[must_use]
pub(crate) const fn deps_dev_system(id: EcosystemId) -> Option<&'static str> {
    match id {
        EcosystemId::Npm => Some("npm"),
        EcosystemId::Cargo => Some("cargo"),
        EcosystemId::Go => Some("go"),
        EcosystemId::Maven => Some("maven"),
        EcosystemId::Pypi => Some("pypi"),
        EcosystemId::Bundler => Some("rubygems"),
        EcosystemId::NuGet => Some("nuget"),
        EcosystemId::Composer
        | EcosystemId::Dart
        | EcosystemId::Swift
        | EcosystemId::Gradle
        | EcosystemId::Deno
        | EcosystemId::GithubActions
        | EcosystemId::GitlabCi => None,
    }
}

/// Whether `segment` is a bare, `[A-Za-z0-9-]`-only DNS label, neither
/// empty nor starting/ending with `-`.
fn is_host_label(segment: &str) -> bool {
    !segment.is_empty()
        && !segment.starts_with('-')
        && !segment.ends_with('-')
        && segment
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// Validates `key` (deps.dev's `projectKey.id`, e.g.
/// `github.com/expressjs/express`) before it is interpolated into a request
/// path, per plan.md §5.
///
/// Encoding the key as one path segment already defeats traversal on its
/// own (`evil/../secret` percent-encodes to `evil%2F..%2Fsecret`, which
/// contains no `..` *segment*); this validation's real value is rejecting
/// junk — a malformed third-party id — before it costs a request. The
/// host-shape rule on the first segment deliberately over-rejects
/// non-ASCII repository names, accepted as the cost of not hand-auditing
/// Unicode in a URL path.
fn is_valid_project_key(key: &str) -> bool {
    let segments: Vec<&str> = key.split('/').collect();
    if !(2..=4).contains(&segments.len()) || segments.iter().any(|s| s.is_empty()) {
        return false;
    }
    if segments
        .iter()
        .any(|s| crate::lsp_helpers::is_dot_segment(s))
    {
        return false;
    }
    // `split_first` cannot return `None`: the length check above already guarantees
    // `segments` has at least 2 entries.
    let (host, rest) = segments
        .split_first()
        .expect("segments has at least 2 entries");
    if !host.contains('.') || !host.split('.').all(is_host_label) {
        return false;
    }
    rest.iter().all(|s| {
        s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    })
}

/// Classifies FR-004's three-state provenance verdict from a version's
/// `slsaProvenances[]`/`attestations[]` arrays.
fn classify_provenance(
    slsa: &[ProvenanceEntry],
    attestations: &[ProvenanceEntry],
) -> ProvenanceStatus {
    if slsa.is_empty() && attestations.is_empty() {
        ProvenanceStatus::None
    } else if slsa.iter().chain(attestations).any(|e| e.verified) {
        ProvenanceStatus::Verified
    } else {
        ProvenanceStatus::Unverified
    }
}

/// Picks the `SOURCE_REPO` project key to fetch a Scorecard for, per
/// plan.md §5's ranked selection. Returns the chosen, **validated**
/// project key and whether the pick fell back to a self-reported
/// (`UNVERIFIED_METADATA`) relation.
fn choose_project_key(projects: &[RelatedProject]) -> Option<(String, bool)> {
    let attested = projects
        .iter()
        .find(|p| p.relation_type == "SOURCE_REPO" && p.relation_provenance == "SLSA_ATTESTATION");
    let (chosen, self_reported) = attested.map(|p| (p, false)).or_else(|| {
        projects
            .iter()
            .find(|p| p.relation_type == "SOURCE_REPO")
            .map(|p| (p, true))
    })?;

    is_valid_project_key(&chosen.project_key.id)
        .then(|| (chosen.project_key.id.clone(), self_reported))
}

/// Assembles [`SupplyChainTrustSignal`]s from deps.dev's two-call sequence.
///
/// Layers its own TTL memo over [`HttpCache`]'s reused transport — see the module
/// docs for the caching/failure-handling rationale.
pub struct DepsDevClient {
    cache: Arc<HttpCache>,
    base_url: String,
    trusted_origin: String,
    memo: DashMap<MemoKey, MemoEntry>,
    projects: DashMap<ProjectKeyMemo, ProjectMemoEntry>,
    in_flight: DashSet<MemoKey>,
}

/// Manual, non-exhaustive impl: `VersionData` derives `Debug` and holds this behind
/// `Option<&Arc<DepsDevClient>>`, but the memo maps' entry types have no reason to
/// derive `Debug` of their own.
impl std::fmt::Debug for DepsDevClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DepsDevClient").finish_non_exhaustive()
    }
}

impl DepsDevClient {
    /// Creates a client that reuses `cache`'s HTTP transport for both
    /// deps.dev calls, pointed at the real deps.dev API.
    #[must_use]
    pub fn new(cache: Arc<HttpCache>) -> Self {
        Self::with_base_url(cache, DEPS_DEV_API.to_string())
    }

    /// Creates a client pointed at `base_url` instead of the real deps.dev
    /// API, for `mockito`-backed tests.
    #[cfg(any(test, feature = "test-util"))]
    #[must_use]
    pub fn for_test(cache: Arc<HttpCache>, base_url: impl Into<String>) -> Self {
        Self::with_base_url(cache, base_url.into())
    }

    fn with_base_url(cache: Arc<HttpCache>, base_url: String) -> Self {
        let trusted_origin = format!("{base_url}/");
        Self {
            cache,
            base_url,
            trusted_origin,
            memo: DashMap::new(),
            projects: DashMap::new(),
            in_flight: DashSet::new(),
        }
    }

    /// Returns the supply-chain trust signal for one resolved
    /// `(system, name, version)`, or `None` when nothing is available to
    /// render.
    ///
    /// Infallible by construction (FR-006) — every failure degrades to
    /// `None`, memoized under the short error TTL so a transient outage
    /// does not re-fire on every hover. A call for a key another concurrent
    /// call is already fetching returns `None` immediately rather than
    /// duplicating the fetch (N1) — the caller's own memo read on its next
    /// call picks up the result once the in-flight fetch completes and
    /// writes it.
    pub async fn trust_signal(
        &self,
        system: &'static str,
        name: &str,
        version: &str,
    ) -> Option<SupplyChainTrustSignal> {
        let key = MemoKey {
            base: self.base_url.clone(),
            system,
            name: name.to_string(),
            version: version.to_string(),
        };

        if let Some(entry) = self.memo.get(&key)
            && entry.fetched_at.elapsed() < entry.ttl
        {
            return entry.signal.clone();
        }

        if !self.in_flight.insert(key.clone()) {
            return None;
        }
        let _guard = InFlightGuard {
            set: &self.in_flight,
            key: key.clone(),
        };

        let (signal, ttl) = self.fetch(system, name, version).await;
        self.store_memo(key, signal.clone(), ttl);
        signal
    }

    fn store_memo(&self, key: MemoKey, signal: Option<SupplyChainTrustSignal>, ttl: Duration) {
        if !self.memo.contains_key(&key) {
            evict_if_full(&self.memo, MAX_MEMO_ENTRIES, |e| e.fetched_at, |e| e.ttl);
        }
        self.memo.insert(
            key,
            MemoEntry {
                fetched_at: Instant::now(),
                ttl,
                signal,
            },
        );
    }

    fn store_project_memo(&self, key: ProjectKeyMemo, overall_score: Option<f32>, ttl: Duration) {
        if !self.projects.contains_key(&key) {
            evict_if_full(
                &self.projects,
                MAX_MEMO_ENTRIES,
                |e| e.fetched_at,
                |e| e.ttl,
            );
        }
        self.projects.insert(
            key,
            ProjectMemoEntry {
                fetched_at: Instant::now(),
                ttl,
                overall_score,
            },
        );
    }

    /// One GET through the shared, transport-only, origin-pinned call site —
    /// no entry-map caching (this client's own memos own that), bounded by
    /// [`DEPS_DEV_CALL_TIMEOUT`].
    async fn get(&self, url: &str) -> Result<bytes::Bytes, DepsDevFetchError> {
        match tokio::time::timeout(
            DEPS_DEV_CALL_TIMEOUT,
            self.cache
                .get_transport_only_with_headers_limited_trusted_origin(
                    url,
                    &[],
                    BodyLimit::new(DEPS_DEV_BODY_LIMIT),
                    &self.trusted_origin,
                ),
        )
        .await
        {
            Ok(Ok(bytes)) => Ok(bytes),
            Ok(Err(e)) if e.is_not_found() => Err(DepsDevFetchError::NotFound),
            Ok(Err(e)) => Err(DepsDevFetchError::Failed(e)),
            Err(_) => Err(DepsDevFetchError::TimedOut),
        }
    }

    /// The two-call sequence (plan.md §4): the version call first, then —
    /// only if it yields a usable project key — the project call. Each step
    /// fails independently: a project-call failure keeps the provenance
    /// already resolved from the version call (spec §6).
    async fn fetch(
        &self,
        system: &'static str,
        name: &str,
        version: &str,
    ) -> (Option<SupplyChainTrustSignal>, Duration) {
        let version_url = format!(
            "{}/v3/systems/{system}/packages/{}/versions/{}",
            self.base_url,
            urlencoding::encode(name),
            urlencoding::encode(version),
        );

        let (provenance, related_projects) = match self.get(&version_url).await {
            Ok(bytes) => match crate::parser::parse_json_checked::<DepsDevVersionInfo>(&bytes) {
                Ok(info) => {
                    let provenance =
                        classify_provenance(&info.slsa_provenances, &info.attestations);
                    (Some(provenance), info.related_projects)
                }
                Err(e) => {
                    tracing::debug!(error = %e, "deps.dev version response parse failed");
                    return (None, DEPS_DEV_ERROR_TTL);
                }
            },
            Err(DepsDevFetchError::NotFound) => return (None, DEPS_DEV_SUCCESS_TTL),
            Err(DepsDevFetchError::Failed(e)) => {
                tracing::debug!(error = %e, "deps.dev version fetch failed");
                return (None, DEPS_DEV_ERROR_TTL);
            }
            Err(DepsDevFetchError::TimedOut) => {
                tracing::debug!(package = name, "deps.dev version fetch timed out");
                return (None, DEPS_DEV_ERROR_TTL);
            }
        };

        // `project_ttl` is `DEPS_DEV_SUCCESS_TTL` when no project key exists at all (nothing
        // to downgrade for) or the project call succeeded/404'd, and `DEPS_DEV_ERROR_TTL`
        // when it genuinely failed — `.min` below then downgrades the *whole signal's* memo
        // TTL whenever the project call was the thing that failed (review C2/critic C2): a
        // successful version call must not paper over a transient project-call failure with
        // a full hour of "no Scorecard".
        let (scorecard, project_ttl) = match choose_project_key(&related_projects) {
            Some((project_key, self_reported)) => {
                let (raw_score, ttl) = self.fetch_scorecard(&project_key).await;
                let scorecard = raw_score.map(|overall_score| ScorecardSummary {
                    overall_score,
                    self_reported,
                });
                (scorecard, ttl)
            }
            None => (None, DEPS_DEV_SUCCESS_TTL),
        };

        let signal = SupplyChainTrustSignal {
            scorecard,
            provenance,
        };
        (Some(signal), DEPS_DEV_SUCCESS_TTL.min(project_ttl))
    }

    /// Fetches (or serves from the project memo) the raw Scorecard score for
    /// a single, already-validated `project_key`, plus the TTL this outcome
    /// should be cached under.
    ///
    /// Returns the raw score only, **not** a [`ScorecardSummary`] — the
    /// `self_reported` disclosure is applied by the caller from its own
    /// per-relation knowledge, never cached here (see [`ProjectMemoEntry`]'s
    /// docs; security M1/critic C1).
    async fn fetch_scorecard(&self, project_key: &str) -> (Option<f32>, Duration) {
        let memo_key = ProjectKeyMemo {
            base: self.base_url.clone(),
            project_key: project_key.to_string(),
        };

        if let Some(entry) = self.projects.get(&memo_key)
            && entry.fetched_at.elapsed() < entry.ttl
        {
            return (entry.overall_score, entry.ttl);
        }

        let url = format!(
            "{}/v3/projects/{}",
            self.base_url,
            urlencoding::encode(project_key),
        );

        let (overall_score, ttl) = match self.get(&url).await {
            Ok(bytes) => match crate::parser::parse_json_checked::<DepsDevProject>(&bytes) {
                Ok(project) => {
                    let overall_score = project
                        .scorecard
                        .and_then(|s| s.overall_score)
                        .filter(|score| (0.0..=10.0).contains(score));
                    (overall_score, DEPS_DEV_SUCCESS_TTL)
                }
                Err(e) => {
                    tracing::debug!(error = %e, "deps.dev project response parse failed");
                    (None, DEPS_DEV_ERROR_TTL)
                }
            },
            Err(DepsDevFetchError::NotFound) => (None, DEPS_DEV_SUCCESS_TTL),
            Err(DepsDevFetchError::Failed(e)) => {
                tracing::debug!(error = %e, "deps.dev project fetch failed");
                (None, DEPS_DEV_ERROR_TTL)
            }
            Err(DepsDevFetchError::TimedOut) => {
                tracing::debug!(project_key, "deps.dev project fetch timed out");
                (None, DEPS_DEV_ERROR_TTL)
            }
        };

        self.store_project_memo(memo_key, overall_score, ttl);
        (overall_score, ttl)
    }
}

/// Internal classification of a single deps.dev call's failure, so
/// [`DepsDevClient::fetch`]/[`DepsDevClient::fetch_scorecard`] can pick the
/// right memo TTL without duplicating the match at every call site.
enum DepsDevFetchError {
    NotFound,
    Failed(DepsError),
    TimedOut,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client() -> DepsDevClient {
        DepsDevClient::new(Arc::new(HttpCache::new()))
    }

    async fn mock_client() -> (mockito::ServerGuard, DepsDevClient) {
        let server = mockito::Server::new_async().await;
        let client = DepsDevClient::for_test(Arc::new(HttpCache::new()), server.url());
        (server, client)
    }

    const EXPRESS_VERSION_NO_PROVENANCE: &str = r#"{
        "slsaProvenances": [],
        "attestations": [],
        "relatedProjects": [
            {"projectKey": {"id": "github.com/expressjs/express"}, "relationType": "SOURCE_REPO", "relationProvenance": "UNVERIFIED_METADATA"},
            {"projectKey": {"id": "github.com/expressjs/express"}, "relationType": "SOURCE_REPO", "relationProvenance": "SLSA_ATTESTATION"}
        ]
    }"#;

    const SIGSTORE_VERSION_VERIFIED: &str = r#"{
        "slsaProvenances": [{"verified": true, "sourceRepository": "github.com/sigstore/sigstore-js"}],
        "attestations": [],
        "relatedProjects": [
            {"projectKey": {"id": "github.com/sigstore/sigstore-js"}, "relationType": "SOURCE_REPO", "relationProvenance": "SLSA_ATTESTATION"}
        ]
    }"#;

    const EXPRESS_PROJECT: &str = r#"{"scorecard": {"overallScore": 8.5}}"#;

    // --- deps_dev_system ---

    #[test]
    fn deps_dev_system_covers_seven_ecosystems() {
        assert_eq!(deps_dev_system(EcosystemId::Npm), Some("npm"));
        assert_eq!(deps_dev_system(EcosystemId::Cargo), Some("cargo"));
        assert_eq!(deps_dev_system(EcosystemId::Go), Some("go"));
        assert_eq!(deps_dev_system(EcosystemId::Maven), Some("maven"));
        assert_eq!(deps_dev_system(EcosystemId::Pypi), Some("pypi"));
        assert_eq!(deps_dev_system(EcosystemId::Bundler), Some("rubygems"));
        assert_eq!(deps_dev_system(EcosystemId::NuGet), Some("nuget"));
    }

    #[test]
    fn deps_dev_system_excludes_uncovered_ecosystems() {
        assert_eq!(deps_dev_system(EcosystemId::Composer), None);
        assert_eq!(deps_dev_system(EcosystemId::Dart), None);
        assert_eq!(deps_dev_system(EcosystemId::Swift), None);
        assert_eq!(deps_dev_system(EcosystemId::Gradle), None);
        assert_eq!(deps_dev_system(EcosystemId::Deno), None);
        assert_eq!(deps_dev_system(EcosystemId::GithubActions), None);
    }

    // --- is_valid_project_key ---

    #[test]
    fn is_valid_project_key_accepts_github_style_key() {
        assert!(is_valid_project_key("github.com/expressjs/express"));
    }

    #[test]
    fn is_valid_project_key_rejects_traversal() {
        assert!(!is_valid_project_key("github.com/../../etc"));
        assert!(!is_valid_project_key("github.com/expressjs/.."));
    }

    #[test]
    fn is_valid_project_key_rejects_non_host_first_segment() {
        assert!(!is_valid_project_key("not-a-host/expressjs/express"));
    }

    #[test]
    fn is_valid_project_key_rejects_too_few_or_too_many_segments() {
        assert!(!is_valid_project_key("github.com"));
        assert!(!is_valid_project_key("github.com/a/b/c/d"));
    }

    // --- classify_provenance ---

    #[test]
    fn classify_provenance_both_empty_is_none() {
        assert_eq!(classify_provenance(&[], &[]), ProvenanceStatus::None);
    }

    #[test]
    fn classify_provenance_any_verified_is_verified() {
        let entries = [ProvenanceEntry { verified: true }];
        assert_eq!(
            classify_provenance(&entries, &[]),
            ProvenanceStatus::Verified
        );
    }

    #[test]
    fn classify_provenance_nonempty_unverified_is_unverified() {
        let entries = [ProvenanceEntry { verified: false }];
        assert_eq!(
            classify_provenance(&entries, &[]),
            ProvenanceStatus::Unverified
        );
    }

    // --- trust_signal: end-to-end against mockito ---

    #[tokio::test]
    async fn trust_signal_renders_score_and_verified_provenance() {
        let (mut server, client) = mock_client().await;
        let _version = server
            .mock("GET", "/v3/systems/npm/packages/sigstore/versions/2.3.1")
            .with_status(200)
            .with_body(SIGSTORE_VERSION_VERIFIED)
            .create_async()
            .await;
        let _project = server
            .mock("GET", "/v3/projects/github.com%2Fsigstore%2Fsigstore-js")
            .with_status(200)
            .with_body(r#"{"scorecard": {"overallScore": 9.1}}"#)
            .create_async()
            .await;

        let signal = client
            .trust_signal("npm", "sigstore", "2.3.1")
            .await
            .expect("signal expected");
        assert_eq!(signal.provenance, Some(ProvenanceStatus::Verified));
        let scorecard = signal.scorecard.expect("scorecard expected");
        assert!((scorecard.overall_score - 9.1).abs() < f32::EPSILON);
        assert!(!scorecard.self_reported);
    }

    #[tokio::test]
    async fn trust_signal_self_reported_relation_is_marked() {
        let (mut server, client) = mock_client().await;
        let _version = server
            .mock("GET", "/v3/systems/npm/packages/left-pad/versions/1.0.0")
            .with_status(200)
            .with_body(
                r#"{"slsaProvenances": [], "attestations": [], "relatedProjects": [
                    {"projectKey": {"id": "github.com/example/left-pad"}, "relationType": "SOURCE_REPO", "relationProvenance": "UNVERIFIED_METADATA"}
                ]}"#,
            )
            .create_async()
            .await;
        let _project = server
            .mock("GET", "/v3/projects/github.com%2Fexample%2Fleft-pad")
            .with_status(200)
            .with_body(EXPRESS_PROJECT)
            .create_async()
            .await;

        let signal = client
            .trust_signal("npm", "left-pad", "1.0.0")
            .await
            .expect("signal expected");
        let scorecard = signal.scorecard.expect("scorecard expected");
        assert!(scorecard.self_reported);
        assert_eq!(signal.provenance, Some(ProvenanceStatus::None));
    }

    #[tokio::test]
    async fn trust_signal_both_endpoints_fail_returns_none() {
        let (mut server, client) = mock_client().await;
        let _version = server
            .mock("GET", "/v3/systems/npm/packages/express/versions/4.19.2")
            .with_status(500)
            .create_async()
            .await;

        let signal = client.trust_signal("npm", "express", "4.19.2").await;
        assert!(signal.is_none());
    }

    #[tokio::test]
    async fn trust_signal_project_call_fails_keeps_provenance() {
        let (mut server, client) = mock_client().await;
        let _version = server
            .mock("GET", "/v3/systems/npm/packages/sigstore/versions/2.3.1")
            .with_status(200)
            .with_body(SIGSTORE_VERSION_VERIFIED)
            .create_async()
            .await;
        let _project = server
            .mock("GET", "/v3/projects/github.com%2Fsigstore%2Fsigstore-js")
            .with_status(500)
            .create_async()
            .await;

        let signal = client
            .trust_signal("npm", "sigstore", "2.3.1")
            .await
            .expect("signal expected");
        assert_eq!(signal.provenance, Some(ProvenanceStatus::Verified));
        assert!(signal.scorecard.is_none());
    }

    #[tokio::test]
    async fn trust_signal_no_source_repo_omits_scorecard_keeps_provenance() {
        let (mut server, client) = mock_client().await;
        let _version = server
            .mock("GET", "/v3/systems/npm/packages/express/versions/4.19.2")
            .with_status(200)
            .with_body(EXPRESS_VERSION_NO_PROVENANCE)
            .create_async()
            .await;
        let _project = server
            .mock("GET", "/v3/projects/github.com%2Fexpressjs%2Fexpress")
            .with_status(200)
            .with_body(EXPRESS_PROJECT)
            .create_async()
            .await;

        let signal = client
            .trust_signal("npm", "express", "4.19.2")
            .await
            .expect("signal expected");
        assert_eq!(signal.provenance, Some(ProvenanceStatus::None));
        let scorecard = signal.scorecard.expect("scorecard expected");
        assert!((scorecard.overall_score - 8.5).abs() < f32::EPSILON);
    }

    #[tokio::test]
    async fn trust_signal_malformed_json_returns_none() {
        let (mut server, client) = mock_client().await;
        let _version = server
            .mock("GET", "/v3/systems/npm/packages/express/versions/4.19.2")
            .with_status(200)
            .with_body("not json")
            .create_async()
            .await;

        let signal = client.trust_signal("npm", "express", "4.19.2").await;
        assert!(signal.is_none());
    }

    #[tokio::test]
    async fn trust_signal_404_plaintext_body_returns_none_no_panic() {
        let (mut server, client) = mock_client().await;
        let _version = server
            .mock("GET", "/v3/systems/npm/packages/missing/versions/1.0.0")
            .with_status(404)
            .with_body("version not found")
            .create_async()
            .await;

        let signal = client.trust_signal("npm", "missing", "1.0.0").await;
        assert!(signal.is_none());
    }

    #[tokio::test]
    async fn trust_signal_scorecard_overall_score_absent_omits_scorecard_never_zero() {
        let (mut server, client) = mock_client().await;
        let _version = server
            .mock("GET", "/v3/systems/npm/packages/express/versions/4.19.2")
            .with_status(200)
            .with_body(EXPRESS_VERSION_NO_PROVENANCE)
            .create_async()
            .await;
        let _project = server
            .mock("GET", "/v3/projects/github.com%2Fexpressjs%2Fexpress")
            .with_status(200)
            .with_body(r#"{"scorecard": {}}"#)
            .create_async()
            .await;

        let signal = client
            .trust_signal("npm", "express", "4.19.2")
            .await
            .expect("signal expected (provenance still present)");
        assert!(signal.scorecard.is_none());
    }

    #[tokio::test]
    async fn trust_signal_second_call_within_ttl_issues_zero_requests() {
        let (mut server, client) = mock_client().await;
        let version = server
            .mock("GET", "/v3/systems/npm/packages/express/versions/4.19.2")
            .with_status(200)
            .with_body(EXPRESS_VERSION_NO_PROVENANCE)
            .expect(1)
            .create_async()
            .await;
        let project = server
            .mock("GET", "/v3/projects/github.com%2Fexpressjs%2Fexpress")
            .with_status(200)
            .with_body(EXPRESS_PROJECT)
            .expect(1)
            .create_async()
            .await;

        client.trust_signal("npm", "express", "4.19.2").await;
        client.trust_signal("npm", "express", "4.19.2").await;

        version.assert_async().await;
        project.assert_async().await;
    }

    #[tokio::test]
    async fn trust_signal_404_is_not_requeried_within_success_ttl() {
        let (mut server, client) = mock_client().await;
        let version = server
            .mock("GET", "/v3/systems/npm/packages/missing/versions/1.0.0")
            .with_status(404)
            .expect(1)
            .create_async()
            .await;

        client.trust_signal("npm", "missing", "1.0.0").await;
        client.trust_signal("npm", "missing", "1.0.0").await;

        version.assert_async().await;
    }

    #[tokio::test]
    async fn trust_signal_two_packages_sharing_project_key_issue_one_project_call() {
        let (mut server, client) = mock_client().await;
        let _v1 = server
            .mock("GET", "/v3/systems/npm/packages/pkg-a/versions/1.0.0")
            .with_status(200)
            .with_body(
                r#"{"slsaProvenances": [], "attestations": [], "relatedProjects": [
                    {"projectKey": {"id": "github.com/babel/babel"}, "relationType": "SOURCE_REPO", "relationProvenance": "SLSA_ATTESTATION"}
                ]}"#,
            )
            .create_async()
            .await;
        let _v2 = server
            .mock("GET", "/v3/systems/npm/packages/pkg-b/versions/1.0.0")
            .with_status(200)
            .with_body(
                r#"{"slsaProvenances": [], "attestations": [], "relatedProjects": [
                    {"projectKey": {"id": "github.com/babel/babel"}, "relationType": "SOURCE_REPO", "relationProvenance": "SLSA_ATTESTATION"}
                ]}"#,
            )
            .create_async()
            .await;
        let project = server
            .mock("GET", "/v3/projects/github.com%2Fbabel%2Fbabel")
            .with_status(200)
            .with_body(r#"{"scorecard": {"overallScore": 7.0}}"#)
            .expect(1)
            .create_async()
            .await;

        client.trust_signal("npm", "pkg-a", "1.0.0").await;
        client.trust_signal("npm", "pkg-b", "1.0.0").await;

        project.assert_async().await;
    }

    #[tokio::test]
    async fn trust_signal_percent_encodes_go_module_path() {
        let (mut server, client) = mock_client().await;
        let version = server
            .mock(
                "GET",
                "/v3/systems/go/packages/golang.org%2Fx%2Ftext/versions/v0.4.0",
            )
            .with_status(200)
            .with_body(r#"{"slsaProvenances": [], "attestations": [], "relatedProjects": []}"#)
            .expect(1)
            .create_async()
            .await;

        client
            .trust_signal("go", "golang.org/x/text", "v0.4.0")
            .await;

        version.assert_async().await;
    }

    #[tokio::test]
    async fn trust_signal_percent_encodes_scoped_npm_name() {
        let (mut server, client) = mock_client().await;
        let version = server
            .mock(
                "GET",
                "/v3/systems/npm/packages/%40types%2Fnode/versions/20.0.0",
            )
            .with_status(200)
            .with_body(r#"{"slsaProvenances": [], "attestations": [], "relatedProjects": []}"#)
            .expect(1)
            .create_async()
            .await;

        client.trust_signal("npm", "@types/node", "20.0.0").await;

        version.assert_async().await;
    }

    #[tokio::test]
    async fn trust_signal_percent_encodes_maven_coordinate() {
        let (mut server, client) = mock_client().await;
        let version = server
            .mock(
                "GET",
                "/v3/systems/maven/packages/com.google.guava%3Aguava/versions/32.0.0",
            )
            .with_status(200)
            .with_body(r#"{"slsaProvenances": [], "attestations": [], "relatedProjects": []}"#)
            .expect(1)
            .create_async()
            .await;

        client
            .trust_signal("maven", "com.google.guava:guava", "32.0.0")
            .await;

        version.assert_async().await;
    }

    #[tokio::test]
    async fn trust_signal_memo_keys_do_not_alias_on_control_characters() {
        let client = client();
        client.store_memo(
            MemoKey {
                base: "https://api.deps.dev".to_string(),
                system: "npm",
                name: "a\0b".to_string(),
                version: "c".to_string(),
            },
            Some(SupplyChainTrustSignal::default()),
            DEPS_DEV_SUCCESS_TTL,
        );
        assert!(!client.memo.contains_key(&MemoKey {
            base: "https://api.deps.dev".to_string(),
            system: "npm",
            name: "a".to_string(),
            version: "b\0c".to_string(),
        }));
    }

    #[tokio::test]
    async fn trust_signal_invalid_project_key_issues_zero_project_requests() {
        let (mut server, client) = mock_client().await;
        let _version = server
            .mock("GET", "/v3/systems/npm/packages/evil/versions/1.0.0")
            .with_status(200)
            .with_body(
                r#"{"slsaProvenances": [], "attestations": [], "relatedProjects": [
                    {"projectKey": {"id": "github.com/../../etc"}, "relationType": "SOURCE_REPO", "relationProvenance": "SLSA_ATTESTATION"}
                ]}"#,
            )
            .create_async()
            .await;
        let project = server
            .mock("GET", mockito::Matcher::Regex(r"^/v3/projects/.*".into()))
            .expect(0)
            .create_async()
            .await;

        let signal = client
            .trust_signal("npm", "evil", "1.0.0")
            .await
            .expect("signal expected (provenance still present)");
        assert!(signal.scorecard.is_none());
        project.assert_async().await;
    }

    #[tokio::test]
    async fn trust_signal_concurrent_calls_for_same_key_issue_one_request() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let (mut server, client) = mock_client().await;
        let call_count = Arc::new(AtomicUsize::new(0));
        let call_count_clone = Arc::clone(&call_count);
        let client = Arc::new(client);

        let _version = server
            .mock("GET", "/v3/systems/npm/packages/express/versions/4.19.2")
            .with_status(200)
            .with_body_from_request(move |_req| {
                call_count_clone.fetch_add(1, Ordering::SeqCst);
                EXPRESS_VERSION_NO_PROVENANCE.as_bytes().to_vec()
            })
            .create_async()
            .await;
        let _project = server
            .mock("GET", "/v3/projects/github.com%2Fexpressjs%2Fexpress")
            .with_status(200)
            .with_body(EXPRESS_PROJECT)
            .create_async()
            .await;

        let (a, b) = tokio::join!(
            {
                let client = Arc::clone(&client);
                async move { client.trust_signal("npm", "express", "4.19.2").await }
            },
            {
                let client = Arc::clone(&client);
                async move { client.trust_signal("npm", "express", "4.19.2").await }
            }
        );
        // Exactly one of the two concurrent calls does the fetch; the other
        // sees the key already claimed and returns `None` immediately.
        assert!(a.is_some() || b.is_some());
        assert_eq!(call_count.load(Ordering::SeqCst), 1);
    }

    /// `lsp_helpers::hover::generate_hover` wraps a `tokio::spawn`ed
    /// `trust_signal` call in `tokio::time::timeout(DEPS_DEV_WAIT_BUDGET, ..)`
    /// and drops the `JoinHandle` when that elapses (plan.md §8's
    /// "spawn-and-warm" design, critic S1/N1). Dropping a `JoinHandle` does
    /// *not* abort the underlying task in tokio, so the fetch must keep
    /// running and still write the memo — this is what makes an over-budget
    /// hover's *next* hover on the same dependency a memo hit rather than a
    /// repeated fetch. Modelled here with a small artificial "budget"
    /// (5ms) against a slower (60ms) mock response, rather than the real
    /// 700ms/400ms production constants, to keep the test fast and
    /// non-flaky while exercising the identical mechanism.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn trust_signal_survives_dropped_join_handle_and_warms_memo() {
        let (mut server, client) = mock_client().await;
        let client = Arc::new(client);
        let version = server
            .mock("GET", "/v3/systems/npm/packages/express/versions/4.19.2")
            .with_status(200)
            .with_body_from_request(|_req| {
                std::thread::sleep(Duration::from_millis(60));
                EXPRESS_VERSION_NO_PROVENANCE.as_bytes().to_vec()
            })
            .expect(1)
            .create_async()
            .await;

        let spawn_client = Arc::clone(&client);
        let handle =
            tokio::spawn(
                async move { spawn_client.trust_signal("npm", "express", "4.19.2").await },
            );
        // Deliberately much shorter than the mock's 60ms response — this must
        // reliably elapse first.
        let outcome = tokio::time::timeout(Duration::from_millis(5), handle).await;
        assert!(
            outcome.is_err(),
            "the artificial budget must elapse before the mock responds"
        );
        // `outcome`'s `Err` (elapsed) drops the `JoinHandle` here; the spawned
        // task keeps running regardless.

        // Give the detached task ample real time to finish (60ms response +
        // scheduling slack) and write the memo.
        tokio::time::sleep(Duration::from_millis(250)).await;

        let second = client.trust_signal("npm", "express", "4.19.2").await;
        assert!(
            second.is_some(),
            "the memo warmed by the detached task must serve the next call"
        );
        version.assert_async().await;
    }

    /// Regression for security M1 / critic C1: the project memo must never
    /// let one package's `self_reported` value leak into another package
    /// sharing the same project key. Package A resolves the project via an
    /// `SLSA_ATTESTATION` relation (warming the memo first); package B's
    /// only relation to the same project is `UNVERIFIED_METADATA` — B's
    /// score must still be marked self-reported even though A's fetch (or
    /// memo write) happened first, and vice versa for a same-key call made
    /// in the other order.
    #[tokio::test]
    async fn trust_signal_project_memo_never_leaks_self_reported_across_packages() {
        let (mut server, client) = mock_client().await;
        let _version_a = server
            .mock("GET", "/v3/systems/npm/packages/pkg-a/versions/1.0.0")
            .with_status(200)
            .with_body(
                r#"{"slsaProvenances": [], "attestations": [], "relatedProjects": [
                    {"projectKey": {"id": "github.com/babel/babel"}, "relationType": "SOURCE_REPO", "relationProvenance": "SLSA_ATTESTATION"}
                ]}"#,
            )
            .create_async()
            .await;
        let _version_b = server
            .mock("GET", "/v3/systems/npm/packages/pkg-b/versions/1.0.0")
            .with_status(200)
            .with_body(
                r#"{"slsaProvenances": [], "attestations": [], "relatedProjects": [
                    {"projectKey": {"id": "github.com/babel/babel"}, "relationType": "SOURCE_REPO", "relationProvenance": "UNVERIFIED_METADATA"}
                ]}"#,
            )
            .create_async()
            .await;
        let project = server
            .mock("GET", "/v3/projects/github.com%2Fbabel%2Fbabel")
            .with_status(200)
            .with_body(r#"{"scorecard": {"overallScore": 7.0}}"#)
            .expect(1)
            .create_async()
            .await;

        // A first (attested), warming the shared project memo.
        let signal_a = client
            .trust_signal("npm", "pkg-a", "1.0.0")
            .await
            .expect("signal expected");
        assert!(
            !signal_a
                .scorecard
                .expect("scorecard expected")
                .self_reported,
            "A's attested relation must not be marked self-reported"
        );

        // B second, hitting the now-warm project memo, but with its own
        // (self-reported) relation.
        let signal_b = client
            .trust_signal("npm", "pkg-b", "1.0.0")
            .await
            .expect("signal expected");
        assert!(
            signal_b
                .scorecard
                .expect("scorecard expected")
                .self_reported,
            "B's UNVERIFIED_METADATA relation must be marked self-reported even though A's \
             attested fetch warmed the shared project memo first"
        );

        // Exactly one project call for both packages sharing the key.
        project.assert_async().await;
    }

    /// Regression for review C2 / critic C2: a transient failure on the
    /// *project* call must not blank the Scorecard for the full 1h success
    /// TTL — the version-level memo entry's own TTL must be downgraded to
    /// the short error TTL whenever the project call is what failed.
    #[tokio::test]
    async fn trust_signal_project_call_failure_downgrades_version_memo_ttl() {
        let (mut server, client) = mock_client().await;
        let _version = server
            .mock("GET", "/v3/systems/npm/packages/express/versions/4.19.2")
            .with_status(200)
            .with_body(EXPRESS_VERSION_NO_PROVENANCE)
            .create_async()
            .await;
        let _project = server
            .mock("GET", "/v3/projects/github.com%2Fexpressjs%2Fexpress")
            .with_status(500)
            .create_async()
            .await;

        let signal = client
            .trust_signal("npm", "express", "4.19.2")
            .await
            .expect("signal expected (provenance still present)");
        assert!(signal.scorecard.is_none());

        let key = MemoKey {
            base: client.base_url.clone(),
            system: "npm",
            name: "express".to_string(),
            version: "4.19.2".to_string(),
        };
        let entry_ttl = client.memo.get(&key).expect("memo entry expected").ttl;
        assert_eq!(
            entry_ttl, DEPS_DEV_ERROR_TTL,
            "a failed project call must downgrade the whole signal's memo TTL to the short \
             error TTL, not the 1h success TTL"
        );
    }

    /// S3 variant (tester gap): the project response's `overallScore` can be
    /// present but the wrong JSON type (a schema drift, not merely absent),
    /// which fails to deserialize `DepsDevScorecardWire` at all — must
    /// degrade exactly like a project-call failure (scorecard omitted,
    /// provenance kept, never rendered as a defaulted `0`).
    #[tokio::test]
    async fn trust_signal_project_overall_score_wrong_type_omits_scorecard_never_panics() {
        let (mut server, client) = mock_client().await;
        let _version = server
            .mock("GET", "/v3/systems/npm/packages/express/versions/4.19.2")
            .with_status(200)
            .with_body(EXPRESS_VERSION_NO_PROVENANCE)
            .create_async()
            .await;
        let _project = server
            .mock("GET", "/v3/projects/github.com%2Fexpressjs%2Fexpress")
            .with_status(200)
            .with_body(r#"{"scorecard": {"overallScore": "not-a-number"}}"#)
            .create_async()
            .await;

        let signal = client
            .trust_signal("npm", "express", "4.19.2")
            .await
            .expect("signal expected (provenance still present)");
        assert!(signal.scorecard.is_none());
    }

    /// N1 variant (tester gap): the in-flight claim must be released even
    /// when the fetch itself fails, not only on the success path already
    /// covered by `trust_signal_concurrent_calls_for_same_key_issue_one_request`.
    #[tokio::test]
    async fn trust_signal_in_flight_claim_released_after_failure() {
        let (mut server, client) = mock_client().await;
        let _version = server
            .mock("GET", "/v3/systems/npm/packages/express/versions/4.19.2")
            .with_status(500)
            .create_async()
            .await;

        let signal = client.trust_signal("npm", "express", "4.19.2").await;
        assert!(signal.is_none());

        let key = MemoKey {
            base: client.base_url.clone(),
            system: "npm",
            name: "express".to_string(),
            version: "4.19.2".to_string(),
        };
        assert!(
            !client.in_flight.contains(&key),
            "the in-flight claim must be released after a failed fetch, not just a successful one"
        );
    }

    /// Tester gap #2: directly asserts the memoized TTL, rather than only
    /// the resulting `None` value, for a *version*-call failure — the
    /// counterpart to `trust_signal_project_call_failure_downgrades_version_memo_ttl`,
    /// which covers the project-call side.
    #[tokio::test]
    async fn trust_signal_version_call_failure_ttl_is_error_ttl() {
        let (mut server, client) = mock_client().await;
        let _version = server
            .mock("GET", "/v3/systems/npm/packages/express/versions/4.19.2")
            .with_status(500)
            .create_async()
            .await;

        let signal = client.trust_signal("npm", "express", "4.19.2").await;
        assert!(signal.is_none());

        let key = MemoKey {
            base: client.base_url.clone(),
            system: "npm",
            name: "express".to_string(),
            version: "4.19.2".to_string(),
        };
        let entry_ttl = client.memo.get(&key).expect("memo entry expected").ttl;
        assert_eq!(
            entry_ttl, DEPS_DEV_ERROR_TTL,
            "a failed version call must memoize the short error TTL, not the 1h success TTL"
        );
    }

    /// Tester gap #6 (perf's finding): the 512-entry cap on the *version*
    /// memo must actually bound `self.memo`'s size under sustained inserts,
    /// mirroring `github::evict_release_dates_if_full`'s own boundary tests.
    #[test]
    fn memo_evicts_when_max_entries_reached() {
        let client = client();
        for i in 0..MAX_MEMO_ENTRIES {
            client.store_memo(
                MemoKey {
                    base: "https://api.deps.dev".to_string(),
                    system: "npm",
                    name: format!("pkg-{i}"),
                    version: "1.0.0".to_string(),
                },
                None,
                DEPS_DEV_SUCCESS_TTL,
            );
        }
        assert_eq!(client.memo.len(), MAX_MEMO_ENTRIES);

        client.store_memo(
            MemoKey {
                base: "https://api.deps.dev".to_string(),
                system: "npm",
                name: "overflow".to_string(),
                version: "1.0.0".to_string(),
            },
            None,
            DEPS_DEV_SUCCESS_TTL,
        );

        assert!(
            client.memo.len() <= MAX_MEMO_ENTRIES,
            "memo must stay bounded at MAX_MEMO_ENTRIES, got {}",
            client.memo.len()
        );
    }

    /// Same boundary guarantee for the project-level memo (`self.projects`),
    /// which has its own independent cap enforcement.
    #[test]
    fn project_memo_evicts_when_max_entries_reached() {
        let client = client();
        for i in 0..MAX_MEMO_ENTRIES {
            client.store_project_memo(
                ProjectKeyMemo {
                    base: "https://api.deps.dev".to_string(),
                    project_key: format!("github.com/org/repo-{i}"),
                },
                Some(8.0),
                DEPS_DEV_SUCCESS_TTL,
            );
        }
        assert_eq!(client.projects.len(), MAX_MEMO_ENTRIES);

        client.store_project_memo(
            ProjectKeyMemo {
                base: "https://api.deps.dev".to_string(),
                project_key: "github.com/org/overflow".to_string(),
            },
            Some(8.0),
            DEPS_DEV_SUCCESS_TTL,
        );

        assert!(
            client.projects.len() <= MAX_MEMO_ENTRIES,
            "projects memo must stay bounded at MAX_MEMO_ENTRIES, got {}",
            client.projects.len()
        );
    }
}
