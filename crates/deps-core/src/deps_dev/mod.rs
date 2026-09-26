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
mod typosquat;

use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use dashmap::mapref::entry::Entry;
use tokio::sync::watch;

use types::{
    DependentsWire, DepsDevProject, DepsDevVersionInfo, GetPackageWire, ProvenanceEntry,
    RelatedProject, SimilarlyNamedPackagesWire,
};
pub use types::{ProvenanceStatus, ScorecardSummary, SupplyChainTrustSignal};
pub use typosquat::TyposquatSignal;
use typosquat::{SimilarPackageCandidate, TYPOSQUAT_MAX_CANDIDATES_CHECKED, evaluate_candidates};

use crate::EcosystemId;
use crate::cache::{BodyLimit, HttpCache};
use crate::error::DepsError;
use crate::lsp_helpers::{is_dot_segment, warn_rejected_value};

const DEPS_DEV_API: &str = "https://api.deps.dev";

/// Per-call timeout inside [`DepsDevClient::trust_signal`]'s two-call
/// sequence. Deliberately shorter than the hover-side wait budget
/// (`DEPS_DEV_WAIT_BUDGET` in `lsp_helpers::hover`) so a hung version call
/// can never by itself consume the whole budget and starve the project call
/// of any chance to return within it.
const DEPS_DEV_CALL_TIMEOUT: Duration = Duration::from_millis(400);

/// Per-call timeout for the typosquat client's deps.dev calls (issue #1437, impl-critic
/// S4) — deliberately more generous than [`DEPS_DEV_CALL_TIMEOUT`]. That constant was
/// tuned for `trust_signal`'s synchronous, hover-request-path budget
/// (`DEPS_DEV_WAIT_BUDGET = 700ms`, itself tight for two sequential 400ms calls);
/// typosquat resolution instead runs from a background document-lifecycle prefetch (not
/// on any live-request path — see `deps-lsp::document::osv_scan::run_typosquat_prefetch`),
/// so there is no reason to keep the same tight per-call budget. Live measurement found
/// `GetPackage` for popular packages (`react`, `typescript`, `next`, `aws-sdk`) routinely
/// takes 0.4-0.52s — i.e. these would silently time out (and, per FR-005's graceful
/// degradation, produce no signal at all) under the tighter constant, dropping exactly
/// the popular candidates the ratio math most needs.
const TYPOSQUAT_CALL_TIMEOUT: Duration = Duration::from_secs(3);

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
/// and `version` from `resolve_in_use_version` (whose lockfile `ConcreteVersion`
/// branch is never charset-validated), so a joined-string key could let
/// `("a\0b", "c")` and `("a", "b\0c")` collide and serve another package's
/// trust signal. A derived `Hash`/`Eq` over four fields cannot collide by
/// construction. `base` is included for the same reason
/// `github::ReleaseDatesCache` keys on `(api_base, name)`: a mock-server hit
/// in tests must never serve a real-API read from a shared client instance.
#[derive(Debug, Hash, PartialEq, Eq, Clone)]
struct MemoKey {
    base: String,
    system: DepsDevSystem,
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

/// Key for [`DepsDevClient`]'s similarity memo (issue #1437) — package-level, not
/// version-level: `GetSimilarlyNamedPackages` has no version parameter, mirroring
/// [`ProjectKeyMemo`]'s precedent for a memo scoped narrower than [`MemoKey`].
#[derive(Debug, Hash, PartialEq, Eq, Clone)]
struct SimilarityMemoKey {
    base: String,
    system: DepsDevSystem,
    name: String,
}

struct SimilarityMemoEntry {
    fetched_at: Instant,
    ttl: Duration,
    candidates: Vec<SimilarPackageCandidate>,
}

/// Key for [`DepsDevClient`]'s popularity memo (issue #1437) — likewise package-level: a
/// package's `GetDependents`-derived popularity is a property of its own *default* version
/// (resolved internally via `GetPackage`), not of whatever version a caller happens to ask
/// about.
#[derive(Debug, Hash, PartialEq, Eq, Clone)]
struct PopularityMemoKey {
    base: String,
    system: DepsDevSystem,
    name: String,
}

struct PopularityMemoEntry {
    fetched_at: Instant,
    ttl: Duration,
    /// `None` on any resolution failure (`GetPackage`, no default version found, or
    /// `GetDependents`) — memoized the same way [`MemoEntry::signal`] memoizes negative
    /// outcomes.
    dependent_count: Option<u64>,
}

/// Releases an in-flight claim on drop — including on panic — so a claim can
/// never leak and permanently block later calls for the same key.
///
/// Generic over both the key type and the in-flight map's value type (issue #1454 widened
/// this from a `DashSet`-only guard to the `DashMap<K, watch::Receiver<..>>` shape
/// [`coalesce`] uses), so [`DepsDevClient::trust_signal`]/[`DepsDevClient::similar_packages`]/
/// [`DepsDevClient::popularity`] all share the identical cleanup mechanism instead of
/// hand-rolling their own.
struct InFlightGuard<'a, K: std::hash::Hash + Eq, W> {
    map: &'a DashMap<K, W>,
    key: K,
}

impl<K: std::hash::Hash + Eq, W> Drop for InFlightGuard<'_, K, W> {
    fn drop(&mut self) {
        self.map.remove(&self.key);
    }
}

/// A [`coalesce`] watch-channel payload: "leader hasn't finished yet" vs. "leader finished
/// with `V`". A dedicated enum rather than `Option<V>` (clippy `option_option`): two of
/// [`coalesce`]'s three callers have `V` itself an `Option` (`Option<SupplyChainTrustSignal>`,
/// `Option<u64>`), which would otherwise nest as `Option<Option<_>>`.
#[derive(Debug, Clone)]
enum Slot<V> {
    /// The leader's `fetch` has not completed (or panicked) yet.
    Pending,
    /// The leader's `fetch` completed with this value.
    Ready(V),
}

/// Either claims `key` as the leader (installing a fresh, `Pending` channel) or joins as a
/// follower of whichever channel the current leader already installed — a plain, synchronous
/// function so the returned [`dashmap::mapref::entry::Entry`] guard is dropped before
/// [`coalesce`] ever reaches an `.await` (this workspace's `clippy.toml` denies holding one
/// across an await point on principle, regardless of whether a given case is provably safe).
fn claim_or_follow<K, V>(
    in_flight: &DashMap<K, watch::Receiver<Slot<V>>>,
    key: K,
) -> Result<watch::Sender<Slot<V>>, watch::Receiver<Slot<V>>>
where
    K: std::hash::Hash + Eq,
{
    match in_flight.entry(key) {
        Entry::Occupied(occupied) => Err(occupied.get().clone()),
        Entry::Vacant(vacant) => {
            let (tx, rx) = watch::channel(Slot::Pending);
            vacant.insert(rx);
            Ok(tx)
        }
    }
}

/// Bounds how many times [`coalesce`] takes over as a new leader after the previous one was
/// cancelled before sending (issue #1455 critic S2), so a leader that keeps getting cancelled
/// (or keeps panicking deterministically) cannot loop forever — the last attempt's caller
/// either produces a real value or lets a genuine panic propagate to its own task, and every
/// caller that loses that final round falls back to `V::default()`.
const MAX_COALESCE_TAKEOVER_ATTEMPTS: u8 = 2;

/// Coalesces concurrent callers for the same in-flight `key`: the first caller (the leader)
/// runs `fetch` and broadcasts its result to every other concurrent caller for the same key
/// (the followers) via a [`watch`] channel, instead of a follower returning a default value
/// immediately (issue #1454) — the pre-existing behavior, which made a typosquat candidate or
/// declared package that merely lost a concurrent-fetch race silently disappear from the
/// result instead of being reported once the leader's fetch completed.
///
/// A follower whose leader is cancelled — it panics, or the task calling `coalesce` is
/// `AbortHandle::abort()`-ed by something outside this function (a `tokio::time::timeout`
/// around the whole call, or a superseding-task abort, e.g. `deps-lsp`'s
/// `ServerState::track_typosquat_task`) — takes over as the new leader and calls `fetch` itself
/// instead of silently degrading to `V::default()` (issue #1455 critic S2: the original
/// panic-only design reintroduced almost exactly the false-negative shape #1454 set out to fix,
/// since #1455's own new abort paths made leader cancellation routine rather than exotic).
/// Bounded by
/// [`MAX_COALESCE_TAKEOVER_ATTEMPTS`]; `in_flight`'s entry for `key` is removed on every path
/// (including a panic or abort), via [`InFlightGuard`]'s `Drop` impl, so the entry is never
/// stale by the time a takeover's `claim_or_follow` call runs.
async fn coalesce<K, V, F, Fut>(
    in_flight: &DashMap<K, watch::Receiver<Slot<V>>>,
    key: K,
    fetch: F,
) -> V
where
    K: std::hash::Hash + Eq + Clone + Send + Sync,
    V: Clone + Default + Send + Sync,
    F: Fn() -> Fut + Send,
    Fut: std::future::Future<Output = V> + Send,
{
    for attempt in 0..=MAX_COALESCE_TAKEOVER_ATTEMPTS {
        match claim_or_follow(in_flight, key.clone()) {
            Ok(tx) => {
                let _guard = InFlightGuard {
                    map: in_flight,
                    key,
                };
                let value = fetch().await;
                let _ = tx.send(Slot::Ready(value.clone()));
                return value;
            }
            Err(mut rx) => loop {
                let slot = rx.borrow_and_update().clone();
                if let Slot::Ready(value) = slot {
                    return value;
                }
                if rx.changed().await.is_err() {
                    tracing::debug!(
                        attempt,
                        "coalesce: in-flight leader was cancelled before completing; taking \
                         over as leader"
                    );
                    break;
                }
            },
        }
    }

    tracing::debug!(
        "coalesce: gave up after {} leader-takeover attempts; falling back to a default value",
        MAX_COALESCE_TAKEOVER_ATTEMPTS + 1
    );
    V::default()
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
///
/// No longer `lsp-responses`-gated (issue #1437): [`DepsDevClient::typosquat_signal`]'s
/// diagnostics-path caller (`lsp_helpers::diagnostics::fetch_typosquat_signals`, reached
/// through `Ecosystem::generate_diagnostics`'s default impl) must compile without that
/// feature — diagnostics generation is deliberately available to `deps-cli`, which does not
/// enable `lsp-responses` (see that feature's own doc comment in `Cargo.toml`).
#[must_use]
pub(crate) const fn deps_dev_system(id: EcosystemId) -> Option<DepsDevSystem> {
    match id {
        EcosystemId::Npm => Some(DepsDevSystem::Npm),
        EcosystemId::Cargo => Some(DepsDevSystem::Cargo),
        EcosystemId::Go => Some(DepsDevSystem::Go),
        EcosystemId::Maven => Some(DepsDevSystem::Maven),
        EcosystemId::Pypi => Some(DepsDevSystem::Pypi),
        EcosystemId::Bundler => Some(DepsDevSystem::Rubygems),
        EcosystemId::NuGet => Some(DepsDevSystem::NuGet),
        EcosystemId::Composer
        | EcosystemId::Dart
        | EcosystemId::Swift
        | EcosystemId::Gradle
        | EcosystemId::Deno
        | EcosystemId::GithubActions
        | EcosystemId::GitlabCi => None,
    }
}

/// deps.dev's `system` URL path segment (issue #1455 batch item 2).
///
/// Exhaustively covers the seven ecosystems `deps_dev_system` maps to it — replaces a raw
/// `&'static str` threaded through every deps.dev call site and memo key, so a typo'd or
/// copy-pasted-wrong system string is a compile error instead of a silently wrong URL or a
/// memo key that aliases the wrong ecosystem's cache entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DepsDevSystem {
    /// npm.
    Npm,
    /// crates.io, via Cargo.
    Cargo,
    /// Go modules.
    Go,
    /// Maven Central and other Maven-coordinate repositories.
    Maven,
    /// PyPI.
    Pypi,
    /// RubyGems, via Bundler — deps.dev's own name for this ecosystem.
    Rubygems,
    /// NuGet.
    NuGet,
}

impl DepsDevSystem {
    /// The exact `system` path segment deps.dev's `v3`/`v3alpha` APIs expect.
    #[must_use]
    const fn as_path_segment(self) -> &'static str {
        match self {
            Self::Npm => "npm",
            Self::Cargo => "cargo",
            Self::Go => "go",
            Self::Maven => "maven",
            Self::Pypi => "pypi",
            Self::Rubygems => "rubygems",
            Self::NuGet => "nuget",
        }
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
    if segments.iter().any(|s| is_dot_segment(s)) {
        return false;
    }
    #[expect(
        clippy::expect_used,
        reason = "split_first cannot return None: the length check above already guarantees \
                  segments has at least 2 entries"
    )]
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
    /// In-flight claims for [`Self::memo`] — a losing concurrent caller awaits the leader's
    /// result via [`coalesce`] rather than returning `None` immediately (issue #1454).
    in_flight: DashMap<MemoKey, watch::Receiver<Slot<Option<SupplyChainTrustSignal>>>>,
    /// Issue #1437: `GetSimilarlyNamedPackages` results, keyed package-level (see
    /// [`SimilarityMemoKey`]).
    similarity: DashMap<SimilarityMemoKey, SimilarityMemoEntry>,
    /// In-flight claims for [`Self::similarity`], mirroring [`Self::in_flight`]'s dedup
    /// rationale — `fetch_typosquat_signals`'s concurrent fan-out across a document's
    /// dependencies can otherwise issue duplicate `GetSimilarlyNamedPackages` requests for two
    /// dependencies that happen to share a raw name before either write lands in the memo. A
    /// losing caller awaits the leader's result via [`coalesce`] instead of returning an empty
    /// `Vec` immediately (issue #1454).
    similarity_in_flight:
        DashMap<SimilarityMemoKey, watch::Receiver<Slot<Vec<SimilarPackageCandidate>>>>,
    /// Issue #1437: `GetPackage` + `GetDependents`-derived popularity, keyed package-level
    /// (see [`PopularityMemoKey`]) — shared by every declared dependency and candidate that
    /// resolves the same package name, the same way `projects` is shared across packages
    /// sharing a Scorecard project key.
    popularity: DashMap<PopularityMemoKey, PopularityMemoEntry>,
    /// In-flight claims for [`Self::popularity`] — the more valuable of the two dedup maps,
    /// since a popular typosquat target (e.g. `lodash`) is exactly the kind of candidate
    /// multiple concurrently-resolved declared dependencies are likely to share. A losing
    /// caller awaits the leader's result via [`coalesce`] instead of returning `None`
    /// immediately (issue #1454) — previously the more damaging of the two typosquat dedup
    /// maps, since a package-level popularity collision is common enough that
    /// `typosquat_signal_concurrent_calls_share_one_candidate_popularity_request` used to
    /// accept one of two real typosquats going unreported.
    popularity_in_flight: DashMap<PopularityMemoKey, watch::Receiver<Slot<Option<u64>>>>,
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
            in_flight: DashMap::new(),
            similarity: DashMap::new(),
            similarity_in_flight: DashMap::new(),
            popularity: DashMap::new(),
            popularity_in_flight: DashMap::new(),
        }
    }

    /// Returns the supply-chain trust signal for one resolved
    /// `(system, name, version)`, or `None` when nothing is available to
    /// render.
    ///
    /// Infallible by construction (FR-006) — every failure degrades to
    /// `None`, memoized under the short error TTL so a transient outage
    /// does not re-fire on every hover. A call for a key another concurrent
    /// call is already fetching awaits that leader's result via `coalesce`
    /// rather than returning `None` immediately (issue #1454).
    pub async fn trust_signal(
        &self,
        system: DepsDevSystem,
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

        coalesce(&self.in_flight, key.clone(), || async {
            // Re-check the memo now that this call has actually won the leader claim (issue
            // #1455 critic M1): a leader that finished and wrote the memo between the check
            // above and this call's claim attempt would otherwise cost a wholly avoidable
            // duplicate fetch.
            if let Some(entry) = self.memo.get(&key)
                && entry.fetched_at.elapsed() < entry.ttl
            {
                return entry.signal.clone();
            }
            let (signal, ttl) = self.fetch(system, name, version).await;
            self.store_memo(key.clone(), signal.clone(), ttl);
            signal
        })
        .await
    }

    fn store_memo(&self, key: MemoKey, signal: Option<SupplyChainTrustSignal>, ttl: Duration) {
        if !self.memo.contains_key(&key) {
            crate::cache_policy::evict_expired_then_oldest(
                &self.memo,
                MAX_MEMO_ENTRIES,
                |e| e.fetched_at,
                |e| e.ttl,
            );
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
            crate::cache_policy::evict_expired_then_oldest(
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
    /// `timeout`. Callers on the synchronous hover wait-budget pass
    /// [`DEPS_DEV_CALL_TIMEOUT`]; the typosquat background prefetch (issue #1437, not on
    /// any live-request path since impl-critic S4) passes the more generous
    /// [`TYPOSQUAT_CALL_TIMEOUT`] — live measurement found popular packages (`react`,
    /// `typescript`, `next`, `aws-sdk`) routinely take 0.4-0.52s to resolve, which the
    /// original single shared 400ms timeout dropped as silent (spec-compliant, but
    /// self-defeating) degradation.
    #[tracing::instrument(
        skip(self),
        fields(url = %crate::redact::RedactedUrl::new(url))
    )]
    async fn get(&self, url: &str, timeout: Duration) -> Result<bytes::Bytes, DepsDevFetchError> {
        match tokio::time::timeout(
            timeout,
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
        system: DepsDevSystem,
        name: &str,
        version: &str,
    ) -> (Option<SupplyChainTrustSignal>, Duration) {
        if is_dot_segment(name) {
            warn_rejected_value("is_dot_segment", "deps.dev trust-signal request URL", name);
            return (None, DEPS_DEV_SUCCESS_TTL);
        }
        if is_dot_segment(version) {
            warn_rejected_value(
                "is_dot_segment",
                "deps.dev trust-signal request URL",
                version,
            );
            return (None, DEPS_DEV_SUCCESS_TTL);
        }

        let version_url = format!(
            "{}/v3/systems/{}/packages/{}/versions/{}",
            self.base_url,
            system.as_path_segment(),
            urlencoding::encode(name),
            urlencoding::encode(version),
        );

        let (provenance, related_projects, licenses) = match self
            .get(&version_url, DEPS_DEV_CALL_TIMEOUT)
            .await
        {
            Ok(bytes) => match crate::parser::parse_json_checked::<DepsDevVersionInfo>(&bytes) {
                Ok(info) => {
                    let provenance =
                        classify_provenance(&info.slsa_provenances, &info.attestations);
                    (Some(provenance), info.related_projects, info.licenses)
                }
                Err(e) => {
                    tracing::debug!(error = %e, "deps.dev version response parse failed");
                    return (None, DEPS_DEV_ERROR_TTL);
                }
            },
            Err(DepsDevFetchError::NotFound) => return (None, DEPS_DEV_SUCCESS_TTL),
            // #756: never interpolate `e`'s `Display` (`DepsError::safe_tracing_summary`) —
            // kept consistent with `Self::get` above even though this URL is credential-free.
            Err(DepsDevFetchError::Failed(e)) => {
                let (status, cause) = e.safe_tracing_summary();
                tracing::debug!(status = ?status, cause, "deps.dev version fetch failed");
                return (None, DEPS_DEV_ERROR_TTL);
            }
            Err(DepsDevFetchError::TimedOut) => {
                tracing::debug!(
                    package = %crate::redact::redact_declaration_key(name),
                    "deps.dev version fetch timed out"
                );
                return (None, DEPS_DEV_ERROR_TTL);
            }
        };

        // `project_ttl` is `DEPS_DEV_ERROR_TTL` only when the project call genuinely failed;
        // `.min` below then downgrades the whole signal's memo TTL in that case (review
        // C2/critic C2), so a successful version call can't paper over a transient
        // project-call failure with a full hour of "no Scorecard".
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
            licenses,
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

        let (overall_score, ttl) = match self.get(&url, DEPS_DEV_CALL_TIMEOUT).await {
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
            // Same rationale as `Self::fetch`'s equivalent branch above.
            Err(DepsDevFetchError::Failed(e)) => {
                let (status, cause) = e.safe_tracing_summary();
                tracing::debug!(status = ?status, cause, "deps.dev project fetch failed");
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

    /// Returns a typosquat-suspect signal for one declared dependency (issue #1437, spec
    /// 071), or `None` when nothing clears the ratio gate.
    ///
    /// Infallible by construction (NFR-001/FR-005), exactly like [`Self::trust_signal`]:
    /// every failure at any stage — a below-threshold ratio included — degrades to `None`.
    /// Does **not** itself check `system`/ecosystem coverage or any config opt-in switch;
    /// callers (`lsp_helpers::diagnostics::fetch_typosquat_signals`) are responsible for
    /// only calling this for a `system` `deps_dev_system` actually maps to, and only when
    /// the feature is enabled (FR-002/FR-009) — mirroring how [`Self::trust_signal`] itself
    /// never checks ecosystem coverage either.
    pub async fn typosquat_signal(
        &self,
        system: DepsDevSystem,
        name: &str,
    ) -> Option<TyposquatSignal> {
        let candidates = self.similar_packages(system, name).await;
        if candidates.is_empty() {
            return None;
        }

        // `candidates` is already self-match-filtered and capped at
        // `TYPOSQUAT_MAX_CANDIDATES_CHECKED` by `Self::similar_packages` itself (issue
        // #1437 security review M1/N2) — filtered and capped *before* the memo caches it,
        // not just here at read time, so a large `packages[]` response never sits resident
        // in the memo either.
        //
        // The declared package's own popularity and every candidate's are resolved
        // concurrently, not sequentially (issue #1437 impl-critic N2): none depends on any
        // other's result, only the final `evaluate_candidates` call below does. Sequential
        // resolution could cost up to `2 * (1 + TYPOSQUAT_MAX_CANDIDATES_CHECKED)` deps.dev
        // round trips end-to-end for one dependency — concurrent resolution collapses that
        // to roughly the cost of the single slowest branch.
        let candidate_futures = candidates.iter().map(|candidate| async move {
            let dependent_count = self.popularity(system, &candidate.name).await;
            (candidate.name.clone(), dependent_count)
        });
        let (declared_dependent_count, resolved_candidates) = futures::future::join(
            self.popularity(system, name),
            futures::future::join_all(candidate_futures),
        )
        .await;
        let declared_dependent_count = declared_dependent_count?;

        let resolved: Vec<(String, u64)> = resolved_candidates
            .into_iter()
            .filter_map(|(name, dependent_count)| dependent_count.map(|count| (name, count)))
            .collect();

        evaluate_candidates(name, declared_dependent_count, &resolved)
    }

    /// Fetches (or serves from the similarity memo) `GetSimilarlyNamedPackages`'s
    /// `packages[]` for `name` — identity only, no popularity (plan.md §1).
    async fn similar_packages(
        &self,
        system: DepsDevSystem,
        name: &str,
    ) -> Vec<SimilarPackageCandidate> {
        if is_dot_segment(name) {
            warn_rejected_value(
                "is_dot_segment",
                "deps.dev similarly-named-packages request URL",
                name,
            );
            return Vec::new();
        }

        let key = SimilarityMemoKey {
            base: self.base_url.clone(),
            system,
            name: name.to_string(),
        };

        if let Some(entry) = self.similarity.get(&key)
            && entry.fetched_at.elapsed() < entry.ttl
        {
            return entry.candidates.clone();
        }

        coalesce(&self.similarity_in_flight, key.clone(), || async {
            // Re-check the memo now that this call has actually won the leader claim (issue
            // #1455 critic M1) — see `trust_signal`'s identical recheck for why.
            if let Some(entry) = self.similarity.get(&key)
                && entry.fetched_at.elapsed() < entry.ttl
            {
                return entry.candidates.clone();
            }
            let url = format!(
                "{}/v3alpha/systems/{}/packages/{}:similarlyNamedPackages",
                self.base_url,
                system.as_path_segment(),
                urlencoding::encode(name),
            );

            let (candidates, ttl) = match self.get(&url, TYPOSQUAT_CALL_TIMEOUT).await {
                Ok(bytes) => {
                    match crate::parser::parse_json_checked::<SimilarlyNamedPackagesWire>(&bytes) {
                        Ok(wire) => {
                            // Filtered and capped *before* caching (issue #1437 security
                            // review N2), not just at read time in `typosquat_signal`:
                            // `GetSimilarlyNamedPackages` documents no upper bound on
                            // `packages[]` (up to ~30k entries under the 1 MiB body cap), so
                            // storing the full, uncapped list in the memo would keep that
                            // worst case resident in memory across every memo entry.
                            let candidates = wire
                                .packages
                                .into_iter()
                                .map(|p| SimilarPackageCandidate {
                                    name: p.package_key.name,
                                })
                                .filter(|candidate| candidate.name != name)
                                .take(TYPOSQUAT_MAX_CANDIDATES_CHECKED)
                                .collect();
                            (candidates, DEPS_DEV_SUCCESS_TTL)
                        }
                        Err(e) => {
                            tracing::debug!(
                                error = %e,
                                "deps.dev similarly-named-packages response parse failed"
                            );
                            (Vec::new(), DEPS_DEV_ERROR_TTL)
                        }
                    }
                }
                Err(DepsDevFetchError::NotFound) => (Vec::new(), DEPS_DEV_SUCCESS_TTL),
                Err(DepsDevFetchError::Failed(e)) => {
                    let (status, cause) = e.safe_tracing_summary();
                    tracing::debug!(
                        status = ?status,
                        cause,
                        "deps.dev similarly-named-packages fetch failed"
                    );
                    (Vec::new(), DEPS_DEV_ERROR_TTL)
                }
                Err(DepsDevFetchError::TimedOut) => {
                    tracing::debug!(
                        package = %crate::redact::redact_declaration_key(name),
                        "deps.dev similarly-named-packages fetch timed out"
                    );
                    (Vec::new(), DEPS_DEV_ERROR_TTL)
                }
            };

            self.store_similarity_memo(key.clone(), candidates.clone(), ttl);
            candidates
        })
        .await
    }

    fn store_similarity_memo(
        &self,
        key: SimilarityMemoKey,
        candidates: Vec<SimilarPackageCandidate>,
        ttl: Duration,
    ) {
        if !self.similarity.contains_key(&key) {
            crate::cache_policy::evict_expired_then_oldest(
                &self.similarity,
                MAX_MEMO_ENTRIES,
                |e| e.fetched_at,
                |e| e.ttl,
            );
        }
        self.similarity.insert(
            key,
            SimilarityMemoEntry {
                fetched_at: Instant::now(),
                ttl,
                candidates,
            },
        );
    }

    /// Resolves (or serves from the popularity memo) `name`'s `GetDependents`-derived
    /// `dependentCount` for its default version, via `GetPackage` (plan.md §1).
    async fn popularity(&self, system: DepsDevSystem, name: &str) -> Option<u64> {
        let key = PopularityMemoKey {
            base: self.base_url.clone(),
            system,
            name: name.to_string(),
        };

        if let Some(entry) = self.popularity.get(&key)
            && entry.fetched_at.elapsed() < entry.ttl
        {
            return entry.dependent_count;
        }

        coalesce(&self.popularity_in_flight, key.clone(), || async {
            // Re-check the memo now that this call has actually won the leader claim (issue
            // #1455 critic M1) — see `trust_signal`'s identical recheck for why.
            if let Some(entry) = self.popularity.get(&key)
                && entry.fetched_at.elapsed() < entry.ttl
            {
                return entry.dependent_count;
            }
            let (dependent_count, ttl) = self.fetch_popularity(system, name).await;
            self.store_popularity_memo(key.clone(), dependent_count, ttl);
            dependent_count
        })
        .await
    }

    fn store_popularity_memo(
        &self,
        key: PopularityMemoKey,
        dependent_count: Option<u64>,
        ttl: Duration,
    ) {
        if !self.popularity.contains_key(&key) {
            crate::cache_policy::evict_expired_then_oldest(
                &self.popularity,
                MAX_MEMO_ENTRIES,
                |e| e.fetched_at,
                |e| e.ttl,
            );
        }
        self.popularity.insert(
            key,
            PopularityMemoEntry {
                fetched_at: Instant::now(),
                ttl,
                dependent_count,
            },
        );
    }

    /// The `GetPackage` -> default version -> `GetDependents` sequence (plan.md §1). Each
    /// step fails independently to `(None, ..)`, mirroring [`Self::fetch`]'s per-step
    /// degradation.
    async fn fetch_popularity(&self, system: DepsDevSystem, name: &str) -> (Option<u64>, Duration) {
        if is_dot_segment(name) {
            warn_rejected_value("is_dot_segment", "deps.dev package request URL", name);
            return (None, DEPS_DEV_SUCCESS_TTL);
        }

        let package_url = format!(
            "{}/v3alpha/systems/{}/packages/{}",
            self.base_url,
            system.as_path_segment(),
            urlencoding::encode(name),
        );

        let default_version = match self.get(&package_url, TYPOSQUAT_CALL_TIMEOUT).await {
            Ok(bytes) => match crate::parser::parse_json_checked::<GetPackageWire>(&bytes) {
                Ok(package) => match package.versions.into_iter().find(|v| v.is_default) {
                    Some(v) => v.version_key.version,
                    None => return (None, DEPS_DEV_SUCCESS_TTL),
                },
                Err(e) => {
                    tracing::debug!(error = %e, "deps.dev package response parse failed");
                    return (None, DEPS_DEV_ERROR_TTL);
                }
            },
            Err(DepsDevFetchError::NotFound) => return (None, DEPS_DEV_SUCCESS_TTL),
            Err(DepsDevFetchError::Failed(e)) => {
                let (status, cause) = e.safe_tracing_summary();
                tracing::debug!(status = ?status, cause, "deps.dev package fetch failed");
                return (None, DEPS_DEV_ERROR_TTL);
            }
            Err(DepsDevFetchError::TimedOut) => {
                tracing::debug!(
                    package = %crate::redact::redact_declaration_key(name),
                    "deps.dev package fetch timed out"
                );
                return (None, DEPS_DEV_ERROR_TTL);
            }
        };

        if is_dot_segment(&default_version) {
            warn_rejected_value(
                "is_dot_segment",
                "deps.dev dependents request URL",
                &default_version,
            );
            return (None, DEPS_DEV_SUCCESS_TTL);
        }

        let dependents_url = format!(
            "{}/v3alpha/systems/{}/packages/{}/versions/{}:dependents",
            self.base_url,
            system.as_path_segment(),
            urlencoding::encode(name),
            urlencoding::encode(&default_version),
        );

        match self.get(&dependents_url, TYPOSQUAT_CALL_TIMEOUT).await {
            Ok(bytes) => match crate::parser::parse_json_checked::<DependentsWire>(&bytes) {
                Ok(wire) => (Some(wire.dependent_count), DEPS_DEV_SUCCESS_TTL),
                Err(e) => {
                    tracing::debug!(error = %e, "deps.dev dependents response parse failed");
                    (None, DEPS_DEV_ERROR_TTL)
                }
            },
            // Error TTL, not success (impl-critic addendum): unlike `GetPackage`'s own 404
            // (a genuine "package doesn't exist"), a 404 here can be a transient race — the
            // package's default version changed between the `GetPackage` call above and
            // this one — not authoritative absence, so a short retry window is correct.
            Err(DepsDevFetchError::NotFound) => (None, DEPS_DEV_ERROR_TTL),
            Err(DepsDevFetchError::Failed(e)) => {
                let (status, cause) = e.safe_tracing_summary();
                tracing::debug!(status = ?status, cause, "deps.dev dependents fetch failed");
                (None, DEPS_DEV_ERROR_TTL)
            }
            Err(DepsDevFetchError::TimedOut) => {
                tracing::debug!(
                    package = %crate::redact::redact_declaration_key(name),
                    "deps.dev dependents fetch timed out"
                );
                (None, DEPS_DEV_ERROR_TTL)
            }
        }
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

    #[test]
    fn deps_dev_system_covers_seven_ecosystems() {
        assert_eq!(deps_dev_system(EcosystemId::Npm), Some(DepsDevSystem::Npm));
        assert_eq!(
            deps_dev_system(EcosystemId::Cargo),
            Some(DepsDevSystem::Cargo)
        );
        assert_eq!(deps_dev_system(EcosystemId::Go), Some(DepsDevSystem::Go));
        assert_eq!(
            deps_dev_system(EcosystemId::Maven),
            Some(DepsDevSystem::Maven)
        );
        assert_eq!(
            deps_dev_system(EcosystemId::Pypi),
            Some(DepsDevSystem::Pypi)
        );
        assert_eq!(
            deps_dev_system(EcosystemId::Bundler),
            Some(DepsDevSystem::Rubygems)
        );
        assert_eq!(
            deps_dev_system(EcosystemId::NuGet),
            Some(DepsDevSystem::NuGet)
        );
    }

    #[test]
    fn deps_dev_system_as_path_segment_matches_deps_dev_api() {
        assert_eq!(DepsDevSystem::Npm.as_path_segment(), "npm");
        assert_eq!(DepsDevSystem::Cargo.as_path_segment(), "cargo");
        assert_eq!(DepsDevSystem::Go.as_path_segment(), "go");
        assert_eq!(DepsDevSystem::Maven.as_path_segment(), "maven");
        assert_eq!(DepsDevSystem::Pypi.as_path_segment(), "pypi");
        assert_eq!(DepsDevSystem::Rubygems.as_path_segment(), "rubygems");
        assert_eq!(DepsDevSystem::NuGet.as_path_segment(), "nuget");
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
            .trust_signal(DepsDevSystem::Npm, "sigstore", "2.3.1")
            .await
            .expect("signal expected");
        assert_eq!(signal.provenance, Some(ProvenanceStatus::Verified));
        let scorecard = signal.scorecard.expect("scorecard expected");
        assert!((scorecard.overall_score - 9.1).abs() < f32::EPSILON);
        assert!(!scorecard.self_reported);
    }

    /// Issue #204: `licenses[]` on the same version-call response `provenance` is
    /// parsed from is threaded into `SupplyChainTrustSignal.licenses`, with no new
    /// deps.dev endpoint or call.
    #[tokio::test]
    async fn trust_signal_parses_licenses_from_version_response() {
        let (mut server, client) = mock_client().await;
        let _version = server
            .mock("GET", "/v3/systems/npm/packages/sigstore/versions/2.3.1")
            .with_status(200)
            .with_body(
                r#"{"slsaProvenances": [], "attestations": [], "relatedProjects": [], "licenses": ["MIT", "Apache-2.0"]}"#,
            )
            .create_async()
            .await;

        let signal = client
            .trust_signal(DepsDevSystem::Npm, "sigstore", "2.3.1")
            .await
            .expect("signal expected");
        assert_eq!(
            signal.licenses,
            vec!["MIT".to_string(), "Apache-2.0".to_string()]
        );
    }

    /// A version response with no `licenses` key must degrade to an empty `Vec`,
    /// never a panic or a default `None`-then-unwrap.
    #[tokio::test]
    async fn trust_signal_missing_licenses_field_is_empty_vec() {
        let (mut server, client) = mock_client().await;
        let _version = server
            .mock("GET", "/v3/systems/npm/packages/express/versions/4.19.2")
            .with_status(200)
            .with_body(EXPRESS_VERSION_NO_PROVENANCE)
            .create_async()
            .await;

        let signal = client
            .trust_signal(DepsDevSystem::Npm, "express", "4.19.2")
            .await
            .expect("signal expected");
        assert!(signal.licenses.is_empty());
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
            .trust_signal(DepsDevSystem::Npm, "left-pad", "1.0.0")
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

        let signal = client
            .trust_signal(DepsDevSystem::Npm, "express", "4.19.2")
            .await;
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
            .trust_signal(DepsDevSystem::Npm, "sigstore", "2.3.1")
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
            .trust_signal(DepsDevSystem::Npm, "express", "4.19.2")
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

        let signal = client
            .trust_signal(DepsDevSystem::Npm, "express", "4.19.2")
            .await;
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

        let signal = client
            .trust_signal(DepsDevSystem::Npm, "missing", "1.0.0")
            .await;
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
            .trust_signal(DepsDevSystem::Npm, "express", "4.19.2")
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

        client
            .trust_signal(DepsDevSystem::Npm, "express", "4.19.2")
            .await;
        client
            .trust_signal(DepsDevSystem::Npm, "express", "4.19.2")
            .await;

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

        client
            .trust_signal(DepsDevSystem::Npm, "missing", "1.0.0")
            .await;
        client
            .trust_signal(DepsDevSystem::Npm, "missing", "1.0.0")
            .await;

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

        client
            .trust_signal(DepsDevSystem::Npm, "pkg-a", "1.0.0")
            .await;
        client
            .trust_signal(DepsDevSystem::Npm, "pkg-b", "1.0.0")
            .await;

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
            .trust_signal(DepsDevSystem::Go, "golang.org/x/text", "v0.4.0")
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

        client
            .trust_signal(DepsDevSystem::Npm, "@types/node", "20.0.0")
            .await;

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
            .trust_signal(DepsDevSystem::Maven, "com.google.guava:guava", "32.0.0")
            .await;

        version.assert_async().await;
    }

    #[tokio::test]
    async fn trust_signal_memo_keys_do_not_alias_on_control_characters() {
        let client = client();
        client.store_memo(
            MemoKey {
                base: "https://api.deps.dev".to_string(),
                system: DepsDevSystem::Npm,
                name: "a\0b".to_string(),
                version: "c".to_string(),
            },
            Some(SupplyChainTrustSignal::default()),
            DEPS_DEV_SUCCESS_TTL,
        );
        assert!(!client.memo.contains_key(&MemoKey {
            base: "https://api.deps.dev".to_string(),
            system: DepsDevSystem::Npm,
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
            .trust_signal(DepsDevSystem::Npm, "evil", "1.0.0")
            .await
            .expect("signal expected (provenance still present)");
        assert!(signal.scorecard.is_none());
        project.assert_async().await;
    }

    /// #1452: `name` of exactly `.`/`..` must be rejected before it reaches the
    /// `/v3/systems/{system}/packages/{name}/versions/{v}` fetch, mirroring every other
    /// registry client's `is_dot_segment` fetch-sink guard (#341/#349/#365).
    #[tokio::test]
    async fn trust_signal_dot_segment_name_rejected_before_request() {
        let (mut server, client) = mock_client().await;
        let call = server
            .mock("GET", mockito::Matcher::Any)
            .expect(0)
            .create_async()
            .await;

        assert!(
            client
                .trust_signal(DepsDevSystem::Npm, ".", "1.0.0")
                .await
                .is_none()
        );
        assert!(
            client
                .trust_signal(DepsDevSystem::Npm, "..", "1.0.0")
                .await
                .is_none()
        );
        call.assert_async().await;
    }

    /// #1452: `version` of exactly `.`/`..` must be rejected the same way — it interpolates
    /// into the same request path as `name`.
    #[tokio::test]
    async fn trust_signal_dot_segment_version_rejected_before_request() {
        let (mut server, client) = mock_client().await;
        let call = server
            .mock("GET", mockito::Matcher::Any)
            .expect(0)
            .create_async()
            .await;

        assert!(
            client
                .trust_signal(DepsDevSystem::Npm, "left-pad", ".")
                .await
                .is_none()
        );
        assert!(
            client
                .trust_signal(DepsDevSystem::Npm, "left-pad", "..")
                .await
                .is_none()
        );
        call.assert_async().await;
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
                async move {
                    client
                        .trust_signal(DepsDevSystem::Npm, "express", "4.19.2")
                        .await
                }
            },
            {
                let client = Arc::clone(&client);
                async move {
                    client
                        .trust_signal(DepsDevSystem::Npm, "express", "4.19.2")
                        .await
                }
            }
        );
        // Exactly one of the two concurrent calls does the fetch; the other awaits the
        // leader's result via `coalesce` instead of returning `None` immediately (issue
        // #1454), so both must see the real signal.
        assert!(a.is_some());
        assert!(b.is_some());
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
        let handle = tokio::spawn(async move {
            spawn_client
                .trust_signal(DepsDevSystem::Npm, "express", "4.19.2")
                .await
        });
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

        let second = client
            .trust_signal(DepsDevSystem::Npm, "express", "4.19.2")
            .await;
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
            .trust_signal(DepsDevSystem::Npm, "pkg-a", "1.0.0")
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
            .trust_signal(DepsDevSystem::Npm, "pkg-b", "1.0.0")
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
            .trust_signal(DepsDevSystem::Npm, "express", "4.19.2")
            .await
            .expect("signal expected (provenance still present)");
        assert!(signal.scorecard.is_none());

        let key = MemoKey {
            base: client.base_url.clone(),
            system: DepsDevSystem::Npm,
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
            .trust_signal(DepsDevSystem::Npm, "express", "4.19.2")
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

        let signal = client
            .trust_signal(DepsDevSystem::Npm, "express", "4.19.2")
            .await;
        assert!(signal.is_none());

        let key = MemoKey {
            base: client.base_url.clone(),
            system: DepsDevSystem::Npm,
            name: "express".to_string(),
            version: "4.19.2".to_string(),
        };
        assert!(
            !client.in_flight.contains_key(&key),
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

        let signal = client
            .trust_signal(DepsDevSystem::Npm, "express", "4.19.2")
            .await;
        assert!(signal.is_none());

        let key = MemoKey {
            base: client.base_url.clone(),
            system: DepsDevSystem::Npm,
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
                    system: DepsDevSystem::Npm,
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
                system: DepsDevSystem::Npm,
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

    /// Issue #204, live-verified against the real deps.dev API (curl-equivalent
    /// checks during implementation confirmed `licenses[]` on all 7 covered
    /// systems): the real npm `express` version response carries a non-empty
    /// `licenses[]` array, threaded through into `SupplyChainTrustSignal.licenses`.
    #[tokio::test]
    #[ignore = "requires network access"]
    async fn trust_signal_real_npm_express_carries_license() {
        let client = client();
        let signal = client
            .trust_signal(DepsDevSystem::Npm, "express", "4.19.2")
            .await
            .expect("signal expected for a real, well-known package");
        assert!(
            !signal.licenses.is_empty(),
            "expected express@4.19.2 to report a real license"
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

    /// Live-verified evidence pair (plan.md §1): `crossenv` (3 dependents) vs `cross-env`
    /// (900 dependents) — a ~300x ratio, well past both the 50x threshold and the
    /// 50-dependent floor.
    #[tokio::test]
    async fn typosquat_signal_positive_case_fires_above_threshold() {
        let (mut server, client) = mock_client().await;
        let _similarity = server
            .mock(
                "GET",
                "/v3alpha/systems/npm/packages/crossenv:similarlyNamedPackages",
            )
            .with_status(200)
            .with_body(
                r#"{"packageKey": {"name": "crossenv"}, "packages": [{"packageKey": {"name": "cross-env"}}]}"#,
            )
            .create_async()
            .await;
        let _declared_package = server
            .mock("GET", "/v3alpha/systems/npm/packages/crossenv")
            .with_status(200)
            .with_body(r#"{"versions": [{"versionKey": {"version": "1.0.0"}, "isDefault": true}]}"#)
            .create_async()
            .await;
        let _declared_dependents = server
            .mock(
                "GET",
                "/v3alpha/systems/npm/packages/crossenv/versions/1.0.0:dependents",
            )
            .with_status(200)
            .with_body(r#"{"dependentCount": 3}"#)
            .create_async()
            .await;
        let _candidate_package = server
            .mock("GET", "/v3alpha/systems/npm/packages/cross-env")
            .with_status(200)
            .with_body(r#"{"versions": [{"versionKey": {"version": "7.0.0"}, "isDefault": true}]}"#)
            .create_async()
            .await;
        let _candidate_dependents = server
            .mock(
                "GET",
                "/v3alpha/systems/npm/packages/cross-env/versions/7.0.0:dependents",
            )
            .with_status(200)
            .with_body(r#"{"dependentCount": 900}"#)
            .create_async()
            .await;

        let signal = client
            .typosquat_signal(DepsDevSystem::Npm, "crossenv")
            .await
            .expect("300x ratio must fire");
        assert_eq!(signal.suspected_name, "cross-env");
        assert_eq!(signal.declared_dependent_count, 3);
        assert_eq!(signal.suspected_dependent_count, 900);
    }

    /// Negative counterpart: a legitimate similarly-named pair whose ratio never clears
    /// `TYPOSQUAT_RATIO_THRESHOLD` must not fire (spec NFR-003).
    #[tokio::test]
    async fn typosquat_signal_negative_case_below_threshold_returns_none() {
        let (mut server, client) = mock_client().await;
        let _similarity = server
            .mock(
                "GET",
                "/v3alpha/systems/npm/packages/coffeescript:similarlyNamedPackages",
            )
            .with_status(200)
            .with_body(
                r#"{"packageKey": {"name": "coffeescript"}, "packages": [{"packageKey": {"name": "coffee-script"}}]}"#,
            )
            .create_async()
            .await;
        let _declared_package = server
            .mock("GET", "/v3alpha/systems/npm/packages/coffeescript")
            .with_status(200)
            .with_body(r#"{"versions": [{"versionKey": {"version": "2.0.0"}, "isDefault": true}]}"#)
            .create_async()
            .await;
        let _declared_dependents = server
            .mock(
                "GET",
                "/v3alpha/systems/npm/packages/coffeescript/versions/2.0.0:dependents",
            )
            .with_status(200)
            .with_body(r#"{"dependentCount": 1213}"#)
            .create_async()
            .await;
        let _candidate_package = server
            .mock("GET", "/v3alpha/systems/npm/packages/coffee-script")
            .with_status(200)
            .with_body(r#"{"versions": [{"versionKey": {"version": "1.0.0"}, "isDefault": true}]}"#)
            .create_async()
            .await;
        let _candidate_dependents = server
            .mock(
                "GET",
                "/v3alpha/systems/npm/packages/coffee-script/versions/1.0.0:dependents",
            )
            .with_status(200)
            .with_body(r#"{"dependentCount": 8377}"#)
            .create_async()
            .await;

        let signal = client
            .typosquat_signal(DepsDevSystem::Npm, "coffeescript")
            .await;
        assert!(
            signal.is_none(),
            "a ~6.9x ratio must stay well under the 50x threshold"
        );
    }

    #[tokio::test]
    async fn typosquat_signal_404_on_similarity_returns_none_no_further_calls() {
        let (mut server, client) = mock_client().await;
        let _similarity = server
            .mock(
                "GET",
                "/v3alpha/systems/npm/packages/missing:similarlyNamedPackages",
            )
            .with_status(404)
            .create_async()
            .await;
        let package_call = server
            .mock(
                "GET",
                mockito::Matcher::Regex(r"^/v3alpha/systems/npm/packages/missing$".into()),
            )
            .expect(0)
            .create_async()
            .await;

        let signal = client.typosquat_signal(DepsDevSystem::Npm, "missing").await;
        assert!(signal.is_none());
        package_call.assert_async().await;
    }

    #[tokio::test]
    async fn typosquat_signal_timeout_on_similarity_returns_none() {
        // Sleeps past `TYPOSQUAT_CALL_TIMEOUT` (3s, not `DEPS_DEV_CALL_TIMEOUT`'s 400ms —
        // see that constant's doc for why the typosquat client uses a more generous
        // per-call budget, issue #1437 impl-critic S4).
        let (mut server, client) = mock_client().await;
        let _similarity = server
            .mock(
                "GET",
                "/v3alpha/systems/npm/packages/slow:similarlyNamedPackages",
            )
            .with_status(200)
            .with_body_from_request(|_req| {
                std::thread::sleep(Duration::from_millis(3200));
                br#"{"packageKey": {"name": "slow"}, "packages": []}"#.to_vec()
            })
            .create_async()
            .await;

        let signal = client.typosquat_signal(DepsDevSystem::Npm, "slow").await;
        assert!(signal.is_none());
    }

    #[tokio::test]
    async fn typosquat_signal_malformed_json_on_similarity_returns_none() {
        let (mut server, client) = mock_client().await;
        let _similarity = server
            .mock(
                "GET",
                "/v3alpha/systems/npm/packages/broken:similarlyNamedPackages",
            )
            .with_status(200)
            .with_body("not json")
            .create_async()
            .await;

        let signal = client.typosquat_signal(DepsDevSystem::Npm, "broken").await;
        assert!(signal.is_none());
    }

    /// #1452 review M1: `fetch_popularity`'s *name* guard, reached via `popularity`, is
    /// the only guard `typosquat_signal` (mod.rs) exercises with a server-supplied (not
    /// declared) name — `typosquat_signal` feeds `candidate.name` from
    /// `GetSimilarlyNamedPackages`'s response straight into `popularity`, so a declared
    /// dot-segment name never reaches it (`similar_packages`'s own guard stops that
    /// earlier), but a malicious candidate name from the response can.
    #[tokio::test]
    async fn popularity_dot_segment_name_rejected_before_request() {
        let (mut server, client) = mock_client().await;
        let call = server
            .mock("GET", mockito::Matcher::Any)
            .expect(0)
            .create_async()
            .await;

        assert!(client.popularity(DepsDevSystem::Npm, ".").await.is_none());
        assert!(client.popularity(DepsDevSystem::Npm, "..").await.is_none());
        call.assert_async().await;
    }

    /// #1452: `GetPackage`'s server-supplied default version can itself be a `.`/`..`
    /// segment — it must be rejected before it reaches the
    /// `.../versions/{v}:dependents` fetch, the same as a caller-supplied dot-segment name.
    #[tokio::test]
    async fn popularity_dot_segment_default_version_rejected_before_dependents_request() {
        let (mut server, client) = mock_client().await;
        let _package = server
            .mock("GET", "/v3alpha/systems/npm/packages/evil")
            .with_status(200)
            .with_body(r#"{"versions": [{"versionKey": {"version": ".."}, "isDefault": true}]}"#)
            .create_async()
            .await;
        let dependents_call = server
            .mock(
                "GET",
                mockito::Matcher::Regex(
                    r"^/v3alpha/systems/npm/packages/evil/versions/.*:dependents$".into(),
                ),
            )
            .expect(0)
            .create_async()
            .await;

        let dependent_count = client.popularity(DepsDevSystem::Npm, "evil").await;
        assert!(dependent_count.is_none());
        dependents_call.assert_async().await;
    }

    /// Impl-critic addendum: a 404 from `GetDependents` can be a transient default-version
    /// race (the package's default version changed between the `GetPackage` call and this
    /// one), not authoritative absence like a `GetPackage` 404 — it must memoize the short
    /// [`DEPS_DEV_ERROR_TTL`], not the 1h [`DEPS_DEV_SUCCESS_TTL`], so a retry happens soon.
    #[tokio::test]
    async fn typosquat_signal_dependents_404_memoizes_error_ttl_not_success_ttl() {
        let (mut server, client) = mock_client().await;
        let _package = server
            .mock("GET", "/v3alpha/systems/npm/packages/racy")
            .with_status(200)
            .with_body(r#"{"versions": [{"versionKey": {"version": "1.0.0"}, "isDefault": true}]}"#)
            .create_async()
            .await;
        let _dependents = server
            .mock(
                "GET",
                "/v3alpha/systems/npm/packages/racy/versions/1.0.0:dependents",
            )
            .with_status(404)
            .create_async()
            .await;

        let dependent_count = client.popularity(DepsDevSystem::Npm, "racy").await;
        assert!(dependent_count.is_none());

        let key = PopularityMemoKey {
            base: client.base_url.clone(),
            system: DepsDevSystem::Npm,
            name: "racy".to_string(),
        };
        let entry_ttl = client
            .popularity
            .get(&key)
            .expect("popularity memo entry expected")
            .ttl;
        assert_eq!(
            entry_ttl, DEPS_DEV_ERROR_TTL,
            "a GetDependents 404 must memoize the short error TTL, not the 1h success TTL \
             a genuine GetPackage 404 (authoritative absence) uses"
        );
    }

    #[tokio::test]
    async fn typosquat_signal_empty_packages_returns_none_no_popularity_calls() {
        let (mut server, client) = mock_client().await;
        let _similarity = server
            .mock(
                "GET",
                "/v3alpha/systems/npm/packages/lonely:similarlyNamedPackages",
            )
            .with_status(200)
            .with_body(r#"{"packageKey": {"name": "lonely"}, "packages": []}"#)
            .create_async()
            .await;
        let package_call = server
            .mock(
                "GET",
                mockito::Matcher::Regex(r"^/v3alpha/systems/npm/packages/lonely$".into()),
            )
            .expect(0)
            .create_async()
            .await;

        let signal = client.typosquat_signal(DepsDevSystem::Npm, "lonely").await;
        assert!(signal.is_none());
        package_call.assert_async().await;
    }

    /// FR-006, at the client-integration level: a candidate that exactly matches the
    /// declared package's own name must never be treated as its own suspect, even if
    /// `GetSimilarlyNamedPackages` echoes it back.
    #[tokio::test]
    async fn typosquat_signal_excludes_self_match_candidate() {
        // `Self::similar_packages` filters a self-match out *before* caching (issue #1437
        // security review N2), so with the response's only candidate being a self-match,
        // the candidate list is empty by the time `typosquat_signal` sees it — it returns
        // `None` before ever resolving the declared package's own popularity, hence
        // `.expect(0)` on both package/dependents mocks below (not `.expect(1)`: with
        // filtering this early, resolving the declared package's popularity would be
        // wasted work with no candidate left to compare it against). The pure-gate
        // regression guard for FR-006 itself is
        // `typosquat::tests::evaluate_candidates_excludes_exact_name_match`.
        let (mut server, client) = mock_client().await;
        let similarity = server
            .mock(
                "GET",
                "/v3alpha/systems/npm/packages/self-echo:similarlyNamedPackages",
            )
            .with_status(200)
            .with_body(
                r#"{"packageKey": {"name": "self-echo"}, "packages": [{"packageKey": {"name": "self-echo"}}]}"#,
            )
            .expect(1)
            .create_async()
            .await;
        let declared_package = server
            .mock("GET", "/v3alpha/systems/npm/packages/self-echo")
            .expect(0)
            .create_async()
            .await;
        let declared_dependents = server
            .mock(
                "GET",
                "/v3alpha/systems/npm/packages/self-echo/versions/1.0.0:dependents",
            )
            .expect(0)
            .create_async()
            .await;

        let signal = client
            .typosquat_signal(DepsDevSystem::Npm, "self-echo")
            .await;
        assert!(signal.is_none());
        similarity.assert_async().await;
        declared_package.assert_async().await;
        declared_dependents.assert_async().await;
    }

    /// Issue #1437 security review M1: `GetSimilarlyNamedPackages` documents no upper bound
    /// on `packages[]`. A 20-candidate response must still only cost
    /// `TYPOSQUAT_MAX_CANDIDATES_CHECKED` (5) candidate-popularity resolutions (10 requests:
    /// `GetPackage` + `GetDependents` per candidate), not 20.
    #[tokio::test]
    async fn typosquat_signal_caps_candidates_checked_at_five() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let (mut server, client) = mock_client().await;
        let candidates_json: String = (0..20)
            .map(|i| format!(r#"{{"packageKey": {{"name": "cand-{i}"}}}}"#))
            .collect::<Vec<_>>()
            .join(",");
        let _similarity = server
            .mock(
                "GET",
                "/v3alpha/systems/npm/packages/tiny:similarlyNamedPackages",
            )
            .with_status(200)
            .with_body(format!(
                r#"{{"packageKey": {{"name": "tiny"}}, "packages": [{candidates_json}]}}"#
            ))
            .create_async()
            .await;
        let _declared_package = server
            .mock("GET", "/v3alpha/systems/npm/packages/tiny")
            .with_status(200)
            .with_body(r#"{"versions": [{"versionKey": {"version": "1.0.0"}, "isDefault": true}]}"#)
            .create_async()
            .await;
        let _declared_dependents = server
            .mock(
                "GET",
                "/v3alpha/systems/npm/packages/tiny/versions/1.0.0:dependents",
            )
            .with_status(200)
            .with_body(r#"{"dependentCount": 1}"#)
            .create_async()
            .await;

        let call_count = Arc::new(AtomicUsize::new(0));
        let package_call_count = Arc::clone(&call_count);
        let _candidate_packages = server
            .mock(
                "GET",
                mockito::Matcher::Regex(r"^/v3alpha/systems/npm/packages/cand-\d+$".into()),
            )
            .with_status(200)
            .with_body_from_request(move |_req| {
                package_call_count.fetch_add(1, Ordering::SeqCst);
                br#"{"versions": [{"versionKey": {"version": "1.0.0"}, "isDefault": true}]}"#
                    .to_vec()
            })
            .create_async()
            .await;
        let dependents_call_count = Arc::clone(&call_count);
        let _candidate_dependents = server
            .mock(
                "GET",
                mockito::Matcher::Regex(
                    r"^/v3alpha/systems/npm/packages/cand-\d+/versions/1\.0\.0:dependents$".into(),
                ),
            )
            .with_status(200)
            .with_body_from_request(move |_req| {
                dependents_call_count.fetch_add(1, Ordering::SeqCst);
                br#"{"dependentCount": 1000}"#.to_vec()
            })
            .create_async()
            .await;

        let signal = client.typosquat_signal(DepsDevSystem::Npm, "tiny").await;
        assert!(
            signal.is_some(),
            "at least one of the capped candidates should still qualify"
        );
        assert_eq!(
            call_count.load(Ordering::SeqCst),
            2 * TYPOSQUAT_MAX_CANDIDATES_CHECKED,
            "only TYPOSQUAT_MAX_CANDIDATES_CHECKED candidates should ever be resolved, \
             regardless of how many packages[] entries the response carries"
        );
    }

    /// #1452: `name` of exactly `.`/`..` must be rejected before it reaches the
    /// `.../packages/{name}:similarlyNamedPackages` fetch.
    #[tokio::test]
    async fn similar_packages_dot_segment_name_rejected_before_request() {
        let (mut server, client) = mock_client().await;
        let call = server
            .mock("GET", mockito::Matcher::Any)
            .expect(0)
            .create_async()
            .await;

        assert!(
            client
                .similar_packages(DepsDevSystem::Npm, ".")
                .await
                .is_empty()
        );
        assert!(
            client
                .similar_packages(DepsDevSystem::Npm, "..")
                .await
                .is_empty()
        );
        call.assert_async().await;
    }

    /// Issue #1437 security review N2: the similarity *memo* itself must hold only the
    /// filtered, capped set, not the full `packages[]` list `GetSimilarlyNamedPackages` can
    /// return (up to ~30k entries under the 1 MiB body cap) — otherwise a large response
    /// would sit resident in memory for the entire memo TTL regardless of the read-time cap
    /// in `typosquat_signal`.
    #[tokio::test]
    async fn similar_packages_memo_stores_filtered_and_capped_candidates() {
        let (mut server, client) = mock_client().await;
        let mut candidates_json: Vec<String> = (0..20)
            .map(|i| format!(r#"{{"packageKey": {{"name": "cand-{i}"}}}}"#))
            .collect();
        // A self-match mixed in among the 20 — must be filtered, not just excluded from the
        // ratio gate later.
        candidates_json.push(r#"{"packageKey": {"name": "tiny"}}"#.to_string());
        let _similarity = server
            .mock(
                "GET",
                "/v3alpha/systems/npm/packages/tiny:similarlyNamedPackages",
            )
            .with_status(200)
            .with_body(format!(
                r#"{{"packageKey": {{"name": "tiny"}}, "packages": [{}]}}"#,
                candidates_json.join(",")
            ))
            .create_async()
            .await;

        let candidates = client.similar_packages(DepsDevSystem::Npm, "tiny").await;

        assert_eq!(
            candidates.len(),
            TYPOSQUAT_MAX_CANDIDATES_CHECKED,
            "the returned (and thus cached) list must already be capped"
        );
        assert!(
            candidates.iter().all(|c| c.name != "tiny"),
            "the self-match must be filtered before caching, not just before the ratio gate"
        );

        let key = SimilarityMemoKey {
            base: client.base_url.clone(),
            system: DepsDevSystem::Npm,
            name: "tiny".to_string(),
        };
        let memo_len = client
            .similarity
            .get(&key)
            .expect("similarity memo entry expected")
            .candidates
            .len();
        assert_eq!(
            memo_len, TYPOSQUAT_MAX_CANDIDATES_CHECKED,
            "the memo entry itself must hold only the capped set, not the full 21-entry \
             response"
        );
    }

    #[tokio::test]
    async fn typosquat_signal_second_call_within_ttl_issues_zero_requests() {
        let (mut server, client) = mock_client().await;
        let similarity = server
            .mock(
                "GET",
                "/v3alpha/systems/npm/packages/crossenv:similarlyNamedPackages",
            )
            .with_status(200)
            .with_body(
                r#"{"packageKey": {"name": "crossenv"}, "packages": [{"packageKey": {"name": "cross-env"}}]}"#,
            )
            .expect(1)
            .create_async()
            .await;
        let declared_package = server
            .mock("GET", "/v3alpha/systems/npm/packages/crossenv")
            .with_status(200)
            .with_body(r#"{"versions": [{"versionKey": {"version": "1.0.0"}, "isDefault": true}]}"#)
            .expect(1)
            .create_async()
            .await;
        let declared_dependents = server
            .mock(
                "GET",
                "/v3alpha/systems/npm/packages/crossenv/versions/1.0.0:dependents",
            )
            .with_status(200)
            .with_body(r#"{"dependentCount": 3}"#)
            .expect(1)
            .create_async()
            .await;
        let candidate_package = server
            .mock("GET", "/v3alpha/systems/npm/packages/cross-env")
            .with_status(200)
            .with_body(r#"{"versions": [{"versionKey": {"version": "7.0.0"}, "isDefault": true}]}"#)
            .expect(1)
            .create_async()
            .await;
        let candidate_dependents = server
            .mock(
                "GET",
                "/v3alpha/systems/npm/packages/cross-env/versions/7.0.0:dependents",
            )
            .with_status(200)
            .with_body(r#"{"dependentCount": 900}"#)
            .expect(1)
            .create_async()
            .await;

        client
            .typosquat_signal(DepsDevSystem::Npm, "crossenv")
            .await;
        client
            .typosquat_signal(DepsDevSystem::Npm, "crossenv")
            .await;

        similarity.assert_async().await;
        declared_package.assert_async().await;
        declared_dependents.assert_async().await;
        candidate_package.assert_async().await;
        candidate_dependents.assert_async().await;
    }

    /// Issue #1437: the in-flight dedup on `Self::popularity` — two declared packages that
    /// happen to share a candidate (a realistic shape: a popular package like `lodash` is a
    /// typosquat target for more than one misspelling in the same document) resolved
    /// concurrently via `fetch_typosquat_signals`'s fan-out must issue exactly one
    /// `GetPackage` request for that shared candidate, mirroring
    /// `trust_signal_concurrent_calls_for_same_key_issue_one_request`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn typosquat_signal_concurrent_calls_share_one_candidate_popularity_request() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let (mut server, client) = mock_client().await;
        let client = Arc::new(client);
        let call_count = Arc::new(AtomicUsize::new(0));

        let _similarity_a = server
            .mock(
                "GET",
                "/v3alpha/systems/npm/packages/pkg-a:similarlyNamedPackages",
            )
            .with_status(200)
            .with_body(
                r#"{"packageKey": {"name": "pkg-a"}, "packages": [{"packageKey": {"name": "popular-candidate"}}]}"#,
            )
            .create_async()
            .await;
        let _similarity_b = server
            .mock(
                "GET",
                "/v3alpha/systems/npm/packages/pkg-b:similarlyNamedPackages",
            )
            .with_status(200)
            .with_body(
                r#"{"packageKey": {"name": "pkg-b"}, "packages": [{"packageKey": {"name": "popular-candidate"}}]}"#,
            )
            .create_async()
            .await;
        let _package_a = server
            .mock("GET", "/v3alpha/systems/npm/packages/pkg-a")
            .with_status(200)
            .with_body(r#"{"versions": [{"versionKey": {"version": "1.0.0"}, "isDefault": true}]}"#)
            .create_async()
            .await;
        let _package_b = server
            .mock("GET", "/v3alpha/systems/npm/packages/pkg-b")
            .with_status(200)
            .with_body(r#"{"versions": [{"versionKey": {"version": "1.0.0"}, "isDefault": true}]}"#)
            .create_async()
            .await;
        let _dependents_a = server
            .mock(
                "GET",
                "/v3alpha/systems/npm/packages/pkg-a/versions/1.0.0:dependents",
            )
            .with_status(200)
            .with_body(r#"{"dependentCount": 1}"#)
            .create_async()
            .await;
        let _dependents_b = server
            .mock(
                "GET",
                "/v3alpha/systems/npm/packages/pkg-b/versions/1.0.0:dependents",
            )
            .with_status(200)
            .with_body(r#"{"dependentCount": 1}"#)
            .create_async()
            .await;
        let call_count_clone = Arc::clone(&call_count);
        let _candidate_package = server
            .mock("GET", "/v3alpha/systems/npm/packages/popular-candidate")
            .with_status(200)
            .with_body_from_request(move |_req| {
                call_count_clone.fetch_add(1, Ordering::SeqCst);
                std::thread::sleep(Duration::from_millis(50));
                br#"{"versions": [{"versionKey": {"version": "1.0.0"}, "isDefault": true}]}"#
                    .to_vec()
            })
            .create_async()
            .await;
        let _candidate_dependents = server
            .mock(
                "GET",
                "/v3alpha/systems/npm/packages/popular-candidate/versions/1.0.0:dependents",
            )
            .with_status(200)
            .with_body(r#"{"dependentCount": 900}"#)
            .create_async()
            .await;

        let (a, b) = tokio::join!(
            {
                let client = Arc::clone(&client);
                async move { client.typosquat_signal(DepsDevSystem::Npm, "pkg-a").await }
            },
            {
                let client = Arc::clone(&client);
                async move { client.typosquat_signal(DepsDevSystem::Npm, "pkg-b").await }
            }
        );
        // Both concurrent calls must see the real, non-degraded candidate popularity
        // (issue #1454): the loser of the in-flight race awaits the leader's result via
        // `coalesce` instead of degrading to `None`.
        assert!(a.is_some(), "pkg-a must see the real typosquat signal");
        assert!(b.is_some(), "pkg-b must see the real typosquat signal");
        assert_eq!(
            call_count.load(Ordering::SeqCst),
            1,
            "exactly one of the two concurrent calls must fetch the shared candidate's \
             GetPackage; the other must await that in-flight fetch's result rather than \
             duplicating the request"
        );
    }

    /// Issue #1454 panic-safety, updated for #1455 critic S2's fix: a leader's `fetch`
    /// panicking must not deadlock or panic a follower awaiting it via [`coalesce`] — the
    /// follower now takes over as the new leader and recovers the *real* value from its own
    /// fetch (previously it fell back to `V::default()`, reintroducing #1454's own
    /// false-negative shape), and the in-flight entry is still cleaned up (via
    /// [`InFlightGuard`]'s `Drop`) so a later call for the same key is not permanently
    /// blocked.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn coalesce_leader_panic_lets_follower_take_over_and_recover_real_value() {
        let map: Arc<DashMap<u32, watch::Receiver<Slot<u32>>>> = Arc::new(DashMap::new());

        let leader_map = Arc::clone(&map);
        let leader = tokio::spawn(async move {
            coalesce(&leader_map, 1u32, || async {
                tokio::time::sleep(Duration::from_millis(50)).await;
                panic!("leader fetch panics");
                #[allow(unreachable_code)]
                0u32
            })
            .await
        });

        // Give the leader time to claim the in-flight entry before the follower starts.
        tokio::time::sleep(Duration::from_millis(10)).await;
        let follower = coalesce(&map, 1u32, || async { 99u32 }).await;

        assert!(
            leader.await.is_err(),
            "the leader's own task must observe the panic"
        );
        assert_eq!(
            follower, 99,
            "a follower whose leader panicked must take over and recover the real value from \
             its own fetch, never deadlock, panic itself, or silently degrade to V::default()"
        );
        assert!(
            !map.contains_key(&1u32),
            "the in-flight entry must be cleaned up after the leader panic and the follower's \
             own successful takeover"
        );
    }

    /// Issue #1455 critic S2: the same recovery as the panic test above, but for a leader
    /// cancelled by `AbortHandle::abort()` rather than a panic — the routine case #1455 itself
    /// introduced via `ServerState::track_typosquat_task`'s supersede-and-abort pattern, the
    /// whole-document `tokio::time::timeout` around `fetch_typosquat_signals`, and `did_close`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn coalesce_aborted_leader_lets_follower_take_over_and_recover_real_value() {
        let map: Arc<DashMap<u32, watch::Receiver<Slot<u32>>>> = Arc::new(DashMap::new());

        let leader_map = Arc::clone(&map);
        let leader = tokio::spawn(async move {
            coalesce(&leader_map, 1u32, || async {
                tokio::time::sleep(Duration::from_secs(10)).await;
                0u32
            })
            .await
        });
        // Give the leader time to claim the in-flight entry.
        tokio::time::sleep(Duration::from_millis(10)).await;

        let follower_map = Arc::clone(&map);
        let follower =
            tokio::spawn(async move { coalesce(&follower_map, 1u32, || async { 7u32 }).await });
        // Give the follower time to join (see the Occupied entry and start waiting on
        // `changed()`) before the leader is cancelled out from under it.
        tokio::time::sleep(Duration::from_millis(10)).await;

        leader.abort();

        let follower_result = follower.await.expect("follower task must not panic");
        assert_eq!(
            follower_result, 7,
            "a follower whose leader was aborted (not panicked) must take over and recover \
             the real value from its own fetch, not silently degrade to V::default()"
        );
        assert!(
            !map.contains_key(&1u32),
            "the in-flight entry must be cleaned up after the leader's abort and the \
             follower's own successful takeover"
        );
    }
}
