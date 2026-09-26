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

mod memo;
mod types;
mod typosquat;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use dashmap::DashSet;

use memo::{CallOutcome, CoalescedMemo, DEPS_DEV_TTLS, GOSSIP_TTLS, TtlMemo};
use types::{
    DependentsWire, DepsDevProject, DepsDevVersionInfo, GetPackageWire, GossipBatchRequestWire,
    GossipFindingType, GossipFindingsBatchRequestWire, GossipFindingsBatchWire, GossipFindingsWire,
    GossipPackageKeyRefWire, GossipVersionFindingsWire, ProvenanceEntry, RelatedProject,
    SimilarlyNamedPackagesWire,
};
pub use types::{
    GossipCooldown, GossipFindings, GossipLowUsage, GossipRiskLevel, ProvenanceStatus,
    ScorecardSummary, SupplyChainTrustSignal,
};
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

/// Whether a typosquat-signal evaluation's deps.dev calls all returned a definitive answer,
/// or at least one degraded to a failure (issue #1463).
///
/// `similar_packages`, `popularity` and [`DepsDevClient::typosquat_signal`] all report this
/// alongside their usual `None`/empty-on-any-failure degradation (FR-005/FR-006), because a
/// caller deciding whether a "no signal" result may be trusted as a completed check (versus
/// retried later) needs to tell "genuinely nothing found" apart from "couldn't ask". Threaded
/// through the similarity/popularity memos themselves (not just the fresh-fetch path), so a
/// cache hit inside `DEPS_DEV_ERROR_TTL`'s retry window still reports [`Self::Incomplete`]
/// instead of silently reporting [`Self::Complete`] for a result that was never actually
/// verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchCompleteness {
    /// Every call this evaluation needed returned a definitive answer — a successfully
    /// parsed response or an authoritative negative (e.g. a `GetPackage` 404), fresh or
    /// served from a success-TTL memo hit.
    Complete,
    /// At least one call failed, timed out, or returned unparseable data — fresh, or served
    /// from an error-TTL memo hit still within its retry window. A `None`/empty result under
    /// this variant is not a verified negative; the check simply never completed.
    Incomplete,
}

impl FetchCompleteness {
    /// Combines two completeness readings from calls that jointly determine one evaluation —
    /// `Incomplete` if either input is, matching how a chain of dependent or concurrent calls
    /// is only as complete as its least complete member.
    #[must_use]
    pub fn combine(self, other: Self) -> Self {
        if self == Self::Incomplete || other == Self::Incomplete {
            Self::Incomplete
        } else {
            Self::Complete
        }
    }
}

/// Per-call timeout for [`DepsDevClient::gossip_findings_for_version`] (issue #1456, spec
/// 072) — hover's live, version-scoped low-usage fetch. Mirrors [`DEPS_DEV_CALL_TIMEOUT`]'s
/// exact rationale: this call is awaited under hover's own `GOSSIP_WAIT_BUDGET`
/// (`lsp_helpers::hover`), a synchronous-request-path budget, not a background one.
const GOSSIP_CALL_TIMEOUT: Duration = Duration::from_millis(400);

/// Per-call timeout for [`DepsDevClient::gossip_findings_batch`] (issue #1456, spec 072) —
/// the per-document prefetch's `GetFindingsBatch` POST. Mirrors [`TYPOSQUAT_CALL_TIMEOUT`]'s
/// rationale: this runs from a background document-lifecycle prefetch, never on any live
/// hover/diagnostics request path, so it can afford a more generous budget than
/// [`GOSSIP_CALL_TIMEOUT`] — a batch covering an entire document's dependencies is expected
/// to take longer than one single-package call.
const GOSSIP_BATCH_CALL_TIMEOUT: Duration = Duration::from_secs(5);

/// Upper bound on how many `nextPageToken` pages [`DepsDevClient::gossip_findings_batch`]
/// will follow for one batch call, so a misbehaving or adversarial server cannot keep this
/// background prefetch looping indefinitely by never returning an empty `nextPageToken`.
const GOSSIP_BATCH_MAX_PAGES: usize = 20;

/// TTL for a successfully resolved GOSSIP result (batch or version-scoped), matching
/// [`DEPS_DEV_SUCCESS_TTL`]'s reasoning — plan.md §0 round 4 (N5) restores this memo
/// specifically so a document's 100ms-debounced re-prefetch trigger does not re-issue a
/// network call for a package already resolved within the last hour.
const GOSSIP_SUCCESS_TTL: Duration = Duration::from_hours(1);

/// TTL for a failed GOSSIP fetch (network error, timeout, non-2xx, malformed response),
/// matching [`DEPS_DEV_ERROR_TTL`]'s reasoning.
const GOSSIP_ERROR_TTL: Duration = Duration::from_secs(90);

/// Global cap on concurrent `GetFindingsBatch` calls across every open document (issue
/// #1456, spec 072 FR-012/N8) — mirrors `deps-lsp::document::state::FETCH_PERMITS`'s
/// server-wide-document-concurrency pattern, bounding the `disabled->enabled` config
/// transition (one batch call per already-open document, fired simultaneously) and a
/// cold-start multi-manifest workspace load, neither of which any within-document cap
/// (there isn't one — this is one POST per document, not a per-package fan-out) would
/// otherwise bound.
const GOSSIP_PREFETCH_CONCURRENCY: usize = 8;

/// Minimum interval between two [`DepsDevClient::force_refresh_gossip_findings`] calls for
/// the same package (issue #1456, spec 072 FR-011/M21a) — deps.dev's own ingestion lag
/// makes retrying a version-mismatch refetch more often than this pointless, since a newly
/// published release is unlikely to be re-indexed within minutes.
const GOSSIP_REFRESH_BACKOFF: Duration = Duration::from_mins(15);

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
/// Key for [`DepsDevClient`]'s similarity memo (issue #1437) — package-level, not
/// version-level: `GetSimilarlyNamedPackages` has no version parameter, mirroring
/// [`ProjectKeyMemo`]'s precedent for a memo scoped narrower than [`MemoKey`].
#[derive(Debug, Hash, PartialEq, Eq, Clone)]
struct SimilarityMemoKey {
    base: String,
    system: DepsDevSystem,
    name: String,
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

/// Key for [`DepsDevClient`]'s package-level GOSSIP memo (issue #1456, spec 072) — mirrors
/// [`PopularityMemoKey`]'s exact shape: `default_version`'s cooldown/low-usage data is a
/// property of the package's own current default version, not of whatever version a
/// caller happens to ask about, so this is keyed package-level, not version-level.
#[derive(Debug, Hash, PartialEq, Eq, Clone)]
struct GossipMemoKey {
    base: String,
    system: DepsDevSystem,
    name: String,
}

/// Key for [`DepsDevClient`]'s version-scoped GOSSIP memo (issue #1456, spec 072) — backs
/// [`DepsDevClient::gossip_findings_for_version`], hover's live low-usage fetch for the
/// pinned/resolved version, which is not necessarily the package's `defaultVersion` and so
/// cannot share [`GossipMemoKey`]'s package-level scope.
#[derive(Debug, Hash, PartialEq, Eq, Clone)]
struct GossipVersionMemoKey {
    base: String,
    system: DepsDevSystem,
    name: String,
    version: String,
}

/// Releases a `DashSet`-backed in-flight claim on drop — including on panic — for the
/// skip-and-defer (not coalesce-joined) GOSSIP dedup sets (issue #1456, spec 072 C1/M21d): a
/// name already claimed elsewhere is skipped this round, not awaited, so this guard's cleanup is
/// the minimal mechanism that design needs, independent of [`memo::CoalescedMemo`]'s true-join
/// in-flight tracking.
struct DashSetInFlightGuard<'a, K: std::hash::Hash + Eq> {
    set: &'a DashSet<K>,
    key: K,
}

impl<K: std::hash::Hash + Eq> Drop for DashSetInFlightGuard<'_, K> {
    fn drop(&mut self) {
        self.set.remove(&self.key);
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
    /// The trust-signal memo, coalesced (issue #1454): a losing concurrent caller awaits the
    /// leader's result via [`memo::CoalescedMemo::get_or_fetch`] rather than returning `None`
    /// immediately.
    signals: CoalescedMemo<MemoKey, Option<SupplyChainTrustSignal>>,
    /// Deliberately **not** coalesced, unlike [`Self::signals`]: a project-level Scorecard hit
    /// shared across every package sharing that `project_key` is already the dedup this memo
    /// exists for, so an added in-flight join would change no observable behavior for extra
    /// complexity's sake.
    projects: TtlMemo<ProjectKeyMemo, Option<f32>>,
    /// Issue #1437: `GetSimilarlyNamedPackages` results, keyed package-level (see
    /// [`SimilarityMemoKey`]), coalesced for the same reason as [`Self::signals`] —
    /// `fetch_typosquat_signals`'s concurrent fan-out across a document's dependencies can
    /// otherwise issue duplicate requests for two dependencies that happen to share a raw name
    /// before either write lands in the memo.
    similarity: CoalescedMemo<SimilarityMemoKey, Vec<SimilarPackageCandidate>>,
    /// Issue #1437: `GetPackage` + `GetDependents`-derived popularity, keyed package-level (see
    /// [`PopularityMemoKey`]), coalesced for the same reason as [`Self::signals`] — the more
    /// valuable of the coalesced memos, since a popular typosquat target (e.g. `lodash`) is
    /// exactly the kind of candidate multiple concurrently-resolved declared dependencies are
    /// likely to share.
    popularity: CoalescedMemo<PopularityMemoKey, Option<u64>>,
    /// Issue #1456: package-level GOSSIP findings memo, backing [`Self::gossip_findings_batch`]
    /// (see [`GossipMemoKey`]'s docs for why this is package-, not version-, scoped).
    /// Deliberately not coalesced — [`Self::gossip_in_flight`] already dedups concurrent batch
    /// calls at the skip-and-defer level.
    gossip: TtlMemo<GossipMemoKey, Option<GossipFindings>>,
    /// Issue #1456: in-flight claims for [`Self::gossip`] — a name already claimed by another
    /// concurrent batch call is skipped by this call rather than re-fetched; the claiming
    /// call's own memo write is what a losing caller's *next* prefetch trigger will see.
    gossip_in_flight: DashSet<GossipMemoKey>,
    /// Issue #1456: version-scoped GOSSIP findings memo, backing
    /// [`Self::gossip_findings_for_version`] (hover's live low-usage fetch). Deliberately not
    /// coalesced, like [`Self::gossip`] — converting it would change this memo's existing,
    /// intentional skip-and-defer semantics.
    gossip_versions: TtlMemo<GossipVersionMemoKey, Option<GossipFindings>>,
    /// Issue #1456: in-flight claims for [`Self::gossip_versions`].
    gossip_version_in_flight: DashSet<GossipVersionMemoKey>,
    /// Issue #1456, spec 072 FR-012/N8: bounds concurrent `GetFindingsBatch` calls across
    /// every open document server-wide — see [`GOSSIP_PREFETCH_CONCURRENCY`]'s doc.
    gossip_semaphore: tokio::sync::Semaphore,
    /// Issue #1456, spec 072 FR-011/M21: per-package last-attempt timestamp backing
    /// [`Self::force_refresh_gossip_findings`]'s >=15-minute backoff — bounded by the same
    /// [`crate::cache_policy::evict_expired_then_oldest`] discipline every other memo in
    /// this client uses (M21d), so a workspace touching many distinct packages over a long
    /// server lifetime cannot grow this map unboundedly.
    gossip_last_refresh_attempt: DashMap<GossipMemoKey, Instant>,
    /// Code-review finding #4: claims a key for the whole duration of
    /// [`Self::force_refresh_gossip_findings`]'s check-backoff/evict-memo/fetch/store-memo
    /// sequence for that name — without this, the backoff read
    /// (`gossip_last_refresh_attempt.get`) and write (`.insert`) are two separate,
    /// non-atomic `DashMap` operations, so two concurrent force-refresh calls for the same
    /// package can both observe "not throttled" before either writes, firing duplicate
    /// fetches. Mirrors [`Self::gossip_in_flight`]'s identical claim-before-fetch shape
    /// (the same fix already applied for [`Self::gossip_in_flight`] itself, code-review C1)
    /// — a name already claimed here is skipped this round rather than raced on.
    gossip_refresh_in_flight: DashSet<GossipMemoKey>,
}

/// Parses one `defaultVersion`/`requestedVersion` object into the consumer-facing
/// [`GossipFindings`] (issue #1456, spec 072). Shared by
/// [`DepsDevClient::gossip_findings_batch`] (via `defaultVersion`) and
/// [`DepsDevClient::gossip_findings_for_version`] (via `requestedVersion`, falling back to
/// `defaultVersion`).
///
/// Only the *first* `Cooldown`/`LowUsage` finding of each type is kept — deps.dev's schema
/// does not document more than one of the same type ever appearing in `findings[]` for one
/// version, so this is a defensive "first wins" rather than a documented merge rule.
fn gossip_findings_from_entry(entry: &GossipVersionFindingsWire) -> GossipFindings {
    let mut cooldown = None;
    let mut low_usage = None;

    for finding in &entry.findings {
        match finding.finding_type {
            GossipFindingType::Cooldown => {
                if cooldown.is_none()
                    && let Some(ctx) = &finding.cooldown_context
                    && let Some(end) = crate::PublishTime::parse_rfc3339(&ctx.end)
                {
                    cooldown = Some(GossipCooldown {
                        end,
                        risk: finding.risk.into(),
                    });
                }
            }
            GossipFindingType::LowUsage => {
                if low_usage.is_none() {
                    let alternative_packages = finding
                        .low_usage_context
                        .as_ref()
                        .map(|ctx| ctx.alternative_packages.clone())
                        .unwrap_or_default();
                    low_usage = Some(GossipLowUsage {
                        risk: finding.risk.into(),
                        alternative_packages,
                    });
                }
            }
            GossipFindingType::Other => {}
        }
    }

    // Issue #1456 security/impl-critic review, S2: no `COOLDOWN` finding was present, but
    // the version wrapper's own sibling `cooldownEnd` field is live-verified to always be
    // present regardless (a historical timestamp, not itself the active-cooldown signal —
    // see that field's own doc). Falling back to it here means `cooldown` ends up `Some`
    // for *any* version-matched response that carries end-date information at all — which
    // is exactly what lets `gossip_cooldown_for` (`lsp_helpers::mod`) tell "GOSSIP
    // authoritatively says not in cooldown" (`cooldown.is_active(now) == false`) apart from
    // "no GOSSIP data for this version at all" (`cooldown_prefetch` has no matching entry).
    if cooldown.is_none()
        && let Some(end) = entry
            .cooldown_end
            .as_deref()
            .and_then(crate::PublishTime::parse_rfc3339)
    {
        cooldown = Some(GossipCooldown {
            end,
            risk: GossipRiskLevel::Informational,
        });
    }

    GossipFindings {
        version: entry.version_key.version.clone(),
        cooldown,
        low_usage,
    }
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
            signals: CoalescedMemo::new(DEPS_DEV_TTLS),
            projects: TtlMemo::new(DEPS_DEV_TTLS),
            similarity: CoalescedMemo::new(DEPS_DEV_TTLS),
            popularity: CoalescedMemo::new(DEPS_DEV_TTLS),
            gossip: TtlMemo::new(GOSSIP_TTLS),
            gossip_in_flight: DashSet::new(),
            gossip_versions: TtlMemo::new(GOSSIP_TTLS),
            gossip_version_in_flight: DashSet::new(),
            gossip_semaphore: tokio::sync::Semaphore::new(GOSSIP_PREFETCH_CONCURRENCY),
            gossip_last_refresh_attempt: DashMap::new(),
            gossip_refresh_in_flight: DashSet::new(),
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

        self.signals
            .get_or_fetch(key, || self.fetch(system, name, version))
            .await
            .into_value()
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

    /// One [`Self::get`] plus its JSON parse, collapsing the identical three-way
    /// parse-failure/fetch-failure/timeout tracing and error mapping every deps.dev call site
    /// used to duplicate. `NotFound` is reported as [`CallFailure::NotFound`] rather than
    /// mapped here — whether a 404 is authoritative absence or a transient race is a
    /// per-call-site decision (e.g. `fetch_popularity`'s dependents call treats it as the
    /// latter), so only the call site can pick the right [`CallOutcome`] for it.
    async fn get_json<W: serde::de::DeserializeOwned>(
        &self,
        url: &str,
        timeout: Duration,
        call: DepsDevCall<'_>,
    ) -> Result<W, CallFailure> {
        let label = call.label();
        match self.get(url, timeout).await {
            Ok(bytes) => match crate::parser::parse_json_checked::<W>(&bytes) {
                Ok(value) => Ok(value),
                Err(e) => {
                    tracing::debug!(error = %e, "deps.dev {label} response parse failed");
                    Err(CallFailure::Transient)
                }
            },
            Err(DepsDevFetchError::NotFound) => Err(CallFailure::NotFound),
            // #756: never interpolate `e`'s `Display` (`DepsError::safe_tracing_summary`).
            Err(DepsDevFetchError::Failed(e)) => {
                let (status, cause) = e.safe_tracing_summary();
                tracing::debug!(status = ?status, cause, "deps.dev {label} fetch failed");
                Err(CallFailure::Transient)
            }
            Err(DepsDevFetchError::TimedOut) => {
                if let DepsDevCall::Project { key } = &call {
                    tracing::debug!(project_key = key, "deps.dev {label} fetch timed out");
                } else if let Some(name) = call.timed_out_name() {
                    tracing::debug!(
                        package = %crate::redact::redact_declaration_key(name),
                        "deps.dev {label} fetch timed out"
                    );
                }
                Err(CallFailure::Transient)
            }
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
    ) -> CallOutcome<Option<SupplyChainTrustSignal>> {
        if is_dot_segment(name) {
            warn_rejected_value("is_dot_segment", "deps.dev trust-signal request URL", name);
            return CallOutcome::Definitive(None);
        }
        if is_dot_segment(version) {
            warn_rejected_value(
                "is_dot_segment",
                "deps.dev trust-signal request URL",
                version,
            );
            return CallOutcome::Definitive(None);
        }

        let version_url = format!(
            "{}/v3/systems/{}/packages/{}/versions/{}",
            self.base_url,
            system.as_path_segment(),
            urlencoding::encode(name),
            urlencoding::encode(version),
        );

        let (provenance, related_projects, licenses) = match self
            .get_json::<DepsDevVersionInfo>(
                &version_url,
                DEPS_DEV_CALL_TIMEOUT,
                DepsDevCall::Version { name },
            )
            .await
        {
            Ok(info) => {
                let provenance = classify_provenance(&info.slsa_provenances, &info.attestations);
                (Some(provenance), info.related_projects, info.licenses)
            }
            Err(CallFailure::NotFound) => return CallOutcome::Definitive(None),
            Err(CallFailure::Transient) => return CallOutcome::Degraded(None),
        };

        // `project_completeness` is `Incomplete` only when the project call genuinely failed
        // (review C2/critic C2), so a successful version call can't paper over a transient
        // project-call failure with a full hour of "no Scorecard".
        let (scorecard, project_completeness) = match choose_project_key(&related_projects) {
            Some((project_key, self_reported)) => {
                let (raw_score, completeness) =
                    self.fetch_scorecard(&project_key).await.into_parts();
                let scorecard = raw_score.map(|overall_score| ScorecardSummary {
                    overall_score,
                    self_reported,
                });
                (scorecard, completeness)
            }
            None => (None, FetchCompleteness::Complete),
        };

        let signal = SupplyChainTrustSignal {
            scorecard,
            provenance,
            licenses,
        };
        CallOutcome::with_completeness(Some(signal), project_completeness)
    }

    /// Fetches (or serves from the project memo) the raw Scorecard score for a single,
    /// already-validated `project_key`.
    ///
    /// Returns the raw score only, **not** a [`ScorecardSummary`] — the `self_reported`
    /// disclosure is applied by the caller from its own per-relation knowledge, never cached
    /// here (security M1/critic C1). Not coalesced, unlike [`Self::signals`] — see
    /// [`Self::projects`]'s field doc.
    async fn fetch_scorecard(&self, project_key: &str) -> CallOutcome<Option<f32>> {
        let memo_key = ProjectKeyMemo {
            base: self.base_url.clone(),
            project_key: project_key.to_string(),
        };

        if let Some(outcome) = self.projects.get_fresh(&memo_key) {
            return outcome;
        }

        let url = format!(
            "{}/v3/projects/{}",
            self.base_url,
            urlencoding::encode(project_key),
        );

        let outcome = match self
            .get_json::<DepsDevProject>(
                &url,
                DEPS_DEV_CALL_TIMEOUT,
                DepsDevCall::Project { key: project_key },
            )
            .await
        {
            Ok(project) => {
                let overall_score = project
                    .scorecard
                    .and_then(|s| s.overall_score)
                    .filter(|score| (0.0..=10.0).contains(score));
                CallOutcome::Definitive(overall_score)
            }
            Err(CallFailure::NotFound) => CallOutcome::Definitive(None),
            Err(CallFailure::Transient) => CallOutcome::Degraded(None),
        };

        self.projects.insert(memo_key, outcome.clone());
        outcome
    }

    /// Returns a typosquat-suspect signal for one declared dependency (issue #1437, spec
    /// 071), or `None` when nothing clears the ratio gate, paired with whether every
    /// deps.dev call this evaluation needed actually completed (issue #1463) — see
    /// [`FetchCompleteness`].
    ///
    /// Infallible by construction (NFR-001/FR-005), exactly like [`Self::trust_signal`]:
    /// every failure at any stage — a below-threshold ratio included — degrades to `None`,
    /// never a propagated error. [`FetchCompleteness::Incomplete`] is the caller-facing signal
    /// that a `None`/empty degradation of *this specific* kind happened; it does not itself
    /// change what this function returns as the signal. Does **not** itself check
    /// `system`/ecosystem coverage or any config opt-in switch; callers
    /// (`lsp_helpers::diagnostics::fetch_typosquat_signals`) are responsible for only calling
    /// this for a `system` `deps_dev_system` actually maps to, and only when the feature is
    /// enabled (FR-002/FR-009) — mirroring how [`Self::trust_signal`] itself never checks
    /// ecosystem coverage either.
    pub async fn typosquat_signal(
        &self,
        system: DepsDevSystem,
        name: &str,
    ) -> (Option<TyposquatSignal>, FetchCompleteness) {
        let (candidates, similarity_completeness) = self.similar_packages(system, name).await;
        if candidates.is_empty() {
            return (None, similarity_completeness);
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
            let (dependent_count, completeness) = self.popularity(system, &candidate.name).await;
            (candidate.name.clone(), dependent_count, completeness)
        });
        let ((declared_dependent_count, declared_completeness), resolved_candidates) =
            futures::future::join(
                self.popularity(system, name),
                futures::future::join_all(candidate_futures),
            )
            .await;

        // Issue #1463: a candidate's popularity call failing is just as much an incomplete
        // evaluation as the similarity/declared-popularity calls failing — that candidate
        // might have been the qualifying suspect, so its absence from `resolved` below must
        // not be reported as a verified "nothing found".
        let completeness = resolved_candidates.iter().fold(
            similarity_completeness.combine(declared_completeness),
            |acc, (_, _, c)| acc.combine(*c),
        );

        let Some(declared_dependent_count) = declared_dependent_count else {
            return (None, completeness);
        };

        let resolved: Vec<(String, u64)> = resolved_candidates
            .into_iter()
            .filter_map(|(name, dependent_count, _)| dependent_count.map(|count| (name, count)))
            .collect();

        (
            evaluate_candidates(name, declared_dependent_count, &resolved),
            completeness,
        )
    }

    /// Fetches (or serves from the similarity memo) `GetSimilarlyNamedPackages`'s
    /// `packages[]` for `name` — identity only, no popularity (plan.md §1) — paired with
    /// whether this result reflects a completed fetch (issue #1463; see
    /// [`FetchCompleteness`]).
    async fn similar_packages(
        &self,
        system: DepsDevSystem,
        name: &str,
    ) -> (Vec<SimilarPackageCandidate>, FetchCompleteness) {
        if is_dot_segment(name) {
            warn_rejected_value(
                "is_dot_segment",
                "deps.dev similarly-named-packages request URL",
                name,
            );
            // Rejected before any request, and before the memo: retrying can never succeed
            // for this name, so there is nothing left "incomplete" about it.
            return (Vec::new(), FetchCompleteness::Complete);
        }

        let key = SimilarityMemoKey {
            base: self.base_url.clone(),
            system,
            name: name.to_string(),
        };

        self.similarity
            .get_or_fetch(key, || self.fetch_similar_packages(system, name))
            .await
            .into_parts()
    }

    /// `GetSimilarlyNamedPackages` call backing [`Self::similar_packages`].
    async fn fetch_similar_packages(
        &self,
        system: DepsDevSystem,
        name: &str,
    ) -> CallOutcome<Vec<SimilarPackageCandidate>> {
        let url = format!(
            "{}/v3alpha/systems/{}/packages/{}:similarlyNamedPackages",
            self.base_url,
            system.as_path_segment(),
            urlencoding::encode(name),
        );

        match self
            .get_json::<SimilarlyNamedPackagesWire>(
                &url,
                TYPOSQUAT_CALL_TIMEOUT,
                DepsDevCall::SimilarlyNamed { name },
            )
            .await
        {
            Ok(wire) => {
                // Filtered and capped *before* caching (issue #1437 security review N2), not
                // just at read time in `typosquat_signal`: `GetSimilarlyNamedPackages`
                // documents no upper bound on `packages[]` (up to ~30k entries under the 1
                // MiB body cap), so storing the full, uncapped list in the memo would keep
                // that worst case resident in memory across every memo entry.
                let candidates = wire
                    .packages
                    .into_iter()
                    .map(|p| SimilarPackageCandidate {
                        name: p.package_key.name,
                    })
                    .filter(|candidate| candidate.name != name)
                    .take(TYPOSQUAT_MAX_CANDIDATES_CHECKED)
                    .collect();
                CallOutcome::Definitive(candidates)
            }
            Err(CallFailure::NotFound) => CallOutcome::Definitive(Vec::new()),
            Err(CallFailure::Transient) => CallOutcome::Degraded(Vec::new()),
        }
    }

    /// Resolves (or serves from the popularity memo) `name`'s `GetDependents`-derived
    /// `dependentCount` for its default version, via `GetPackage` (plan.md §1) — paired with
    /// whether this result reflects a completed fetch (issue #1463; see
    /// [`FetchCompleteness`]).
    async fn popularity(
        &self,
        system: DepsDevSystem,
        name: &str,
    ) -> (Option<u64>, FetchCompleteness) {
        let key = PopularityMemoKey {
            base: self.base_url.clone(),
            system,
            name: name.to_string(),
        };

        self.popularity
            .get_or_fetch(key, || self.fetch_popularity(system, name))
            .await
            .into_parts()
    }

    /// The `GetPackage` -> default version -> `GetDependents` sequence (plan.md §1). Each step
    /// fails independently, mirroring [`Self::fetch`]'s per-step degradation.
    async fn fetch_popularity(
        &self,
        system: DepsDevSystem,
        name: &str,
    ) -> CallOutcome<Option<u64>> {
        if is_dot_segment(name) {
            warn_rejected_value("is_dot_segment", "deps.dev package request URL", name);
            return CallOutcome::Definitive(None);
        }

        let package_url = format!(
            "{}/v3alpha/systems/{}/packages/{}",
            self.base_url,
            system.as_path_segment(),
            urlencoding::encode(name),
        );

        let default_version = match self
            .get_json::<GetPackageWire>(
                &package_url,
                TYPOSQUAT_CALL_TIMEOUT,
                DepsDevCall::Package { name },
            )
            .await
        {
            Ok(package) => match package.versions.into_iter().find(|v| v.is_default) {
                Some(v) => v.version_key.version,
                None => return CallOutcome::Definitive(None),
            },
            Err(CallFailure::NotFound) => return CallOutcome::Definitive(None),
            Err(CallFailure::Transient) => return CallOutcome::Degraded(None),
        };

        if is_dot_segment(&default_version) {
            warn_rejected_value(
                "is_dot_segment",
                "deps.dev dependents request URL",
                &default_version,
            );
            return CallOutcome::Definitive(None);
        }

        let dependents_url = format!(
            "{}/v3alpha/systems/{}/packages/{}/versions/{}:dependents",
            self.base_url,
            system.as_path_segment(),
            urlencoding::encode(name),
            urlencoding::encode(&default_version),
        );

        match self
            .get_json::<DependentsWire>(
                &dependents_url,
                TYPOSQUAT_CALL_TIMEOUT,
                DepsDevCall::Dependents { name },
            )
            .await
        {
            Ok(wire) => CallOutcome::Definitive(Some(wire.dependent_count)),
            // Error TTL, not success (impl-critic addendum): unlike `GetPackage`'s own 404 (a
            // genuine "package doesn't exist"), a 404 here can be a transient race — the
            // package's default version changed between the `GetPackage` call above and this
            // one — not authoritative absence, so a short retry window is correct, and (issue
            // #1463) it is an incomplete result, not a verified negative.
            Err(CallFailure::NotFound | CallFailure::Transient) => CallOutcome::Degraded(None),
        }
    }

    /// Returns GOSSIP cooldown/low-usage findings for every name in `names` whose
    /// package-level `defaultVersion` carries a resolvable result (issue #1456, spec 072)
    /// — one `POST /v3alpha/findingsbatch` call for the memo-misses, never one call per
    /// name.
    ///
    /// A name already served from `Self::gossip`'s memo (within `GOSSIP_SUCCESS_TTL`/
    /// `GOSSIP_ERROR_TTL`) contributes nothing to the outbound request and lands directly
    /// in the returned map. A name already claimed by another concurrent call to this
    /// method is skipped by this call rather than fetched a second time (mirrors
    /// `Self::similar_packages`'s identical in-flight trade-off) — the claiming call's own
    /// memo write is what the losing caller's *next* prefetch trigger will see, rather than
    /// this call joining that in-flight fetch directly.
    ///
    /// The returned map only ever contains a name when GOSSIP reported a resolvable
    /// `defaultVersion` for it — a name with no resolvable default version (e.g. a
    /// package-level `NOT_FOUND`) is simply absent, not present with an empty
    /// [`GossipFindings`] (NFR-002).
    ///
    /// Does **not** itself check `system`/ecosystem coverage or any config opt-in switch —
    /// mirrors every other public method on this client (see [`Self::typosquat_signal`]'s
    /// doc for why that's the caller's responsibility).
    pub async fn gossip_findings_batch(
        &self,
        system: DepsDevSystem,
        names: &[String],
    ) -> HashMap<String, GossipFindings> {
        let mut result = HashMap::new();
        let mut misses: Vec<String> = Vec::new();

        for name in names {
            let key = self.gossip_key(system, name);
            if let Some(outcome) = self.gossip.get_fresh(&key) {
                if let Some(findings) = outcome.into_value() {
                    result.insert(name.clone(), findings);
                }
                continue;
            }
            misses.push(name.clone());
        }

        if misses.is_empty() {
            return result;
        }

        let mut claimed: Vec<String> = Vec::with_capacity(misses.len());
        // Security review C1/impl-critic C1: held across the whole fetch below (including
        // the semaphore wait), not removed manually only on the normal-return path — a
        // `tokio::time::timeout` around this call (as `run_gossip_prefetch` uses) can drop
        // this future mid-`.await`, and a manual `self.gossip_in_flight.remove(..)` placed
        // after the fetch would then never run, permanently leaking the claim for that
        // package (every later call sees it as still in-flight and skips it forever, and
        // the memo is never written either). `InFlightGuard`'s `Drop` impl runs on
        // cancellation too, exactly like every other in-flight set in this client
        // (`Self::in_flight`, `Self::similarity_in_flight`, `Self::popularity_in_flight`,
        // `Self::gossip_version_in_flight`) already relies on.
        let mut guards: Vec<DashSetInFlightGuard<'_, GossipMemoKey>> =
            Vec::with_capacity(misses.len());
        for name in misses {
            let key = self.gossip_key(system, &name);
            if self.gossip_in_flight.insert(key.clone()) {
                guards.push(DashSetInFlightGuard {
                    set: &self.gossip_in_flight,
                    key,
                });
                claimed.push(name);
            }
        }
        if claimed.is_empty() {
            return result;
        }

        // N8: bounds concurrent batch calls across every open document, not just within
        // this one call. `self.gossip_semaphore` is a plain in-process `Semaphore` this
        // client owns exclusively and never closes, so `acquire` cannot return `Closed`.
        #[expect(
            clippy::expect_used,
            reason = "gossip_semaphore is never closed for the lifetime of this client"
        )]
        let _permit = self
            .gossip_semaphore
            .acquire()
            .await
            .expect("gossip_semaphore is never closed");

        let fetched = self.fetch_gossip_batch(system, &claimed).await;

        // The fetch completed normally (a cancellation before this point would have
        // dropped `guards` already, releasing every claim) — release them explicitly here
        // too, rather than waiting for this whole method's stack frame to unwind, so a
        // concurrent caller waiting on the same key doesn't wait longer than necessary.
        drop(guards);

        for name in claimed {
            // A name absent from `fetched` (the whole call failed, or this specific name
            // was missing from `responses[]`) memoizes as `Degraded` so it is retried soon;
            // a name present — even as `None`, a resolvable "no cooldown/low-usage finding"
            // answer — memoizes as `Definitive`.
            let outcome = match fetched.get(&name) {
                Some(findings) => CallOutcome::Definitive(findings.clone()),
                None => CallOutcome::Degraded(None),
            };
            if let Some(findings) = outcome.clone().into_value() {
                result.insert(name.clone(), findings);
            }
            self.gossip.insert(self.gossip_key(system, &name), outcome);
        }

        result
    }

    /// Force-refetches GOSSIP findings for `names`, bypassing whatever the per-package memo
    /// currently holds (issue #1456, spec 072 FR-011/M21a) — the counterpart to
    /// [`Self::gossip_findings_batch`]'s normal, memo-respecting path, for a caller that has
    /// already detected a genuine staleness signal (a version-equality mismatch, FR-008) and
    /// knows a memo-respecting call would just return the same stale answer.
    ///
    /// Each name is independently throttled to at most once every `GOSSIP_REFRESH_BACKOFF`
    /// (M21a) via `Self::gossip_last_refresh_attempt` — a name still within its backoff
    /// window is silently skipped (absent from the returned map, exactly like a name with no
    /// resolvable `defaultVersion`), so a caller does not need its own throttling logic on
    /// top of this. Does **not** itself decide which packages need refreshing, which
    /// documents to republish for, or filter for privacy — see
    /// `deps-lsp::document::gossip_prefetch`'s mismatch-detection function (M21b/M21c), the
    /// sole intended caller, which owns the `source_is_public_registry_content` gate.
    ///
    /// Code-review C1-mirroring fix (finding #4): the backoff check-then-write is not two
    /// independent `DashMap` operations here — `Self::gossip_refresh_in_flight` claims each
    /// name for the whole check/evict/fetch/store sequence, so two concurrent calls for the
    /// same package can never both observe "not throttled" before either writes; the loser
    /// simply skips that name this round (mirrors `Self::gossip_in_flight`'s identical
    /// claim-before-fetch shape). Also acquires `Self::gossip_semaphore` before fetching
    /// (finding #3) — without it, this path bypassed FR-012/N8's global concurrency cap
    /// entirely, since it calls `Self::fetch_gossip_batch` directly rather than going
    /// through [`Self::gossip_findings_batch`] (which already acquires it).
    pub async fn force_refresh_gossip_findings(
        &self,
        system: DepsDevSystem,
        names: &[String],
    ) -> HashMap<String, GossipFindings> {
        let mut eligible: Vec<String> = Vec::with_capacity(names.len());
        let mut guards: Vec<DashSetInFlightGuard<'_, GossipMemoKey>> =
            Vec::with_capacity(names.len());
        let now = Instant::now();

        for name in names {
            let key = self.gossip_key(system, name);
            if !self.gossip_refresh_in_flight.insert(key.clone()) {
                continue;
            }
            let guard = DashSetInFlightGuard {
                set: &self.gossip_refresh_in_flight,
                key: key.clone(),
            };

            let throttled = self
                .gossip_last_refresh_attempt
                .get(&key)
                .is_some_and(|last| now.duration_since(*last) < GOSSIP_REFRESH_BACKOFF);
            if throttled {
                drop(guard);
                continue;
            }
            if !self.gossip_last_refresh_attempt.contains_key(&key) {
                crate::cache_policy::evict_expired_then_oldest(
                    &self.gossip_last_refresh_attempt,
                    MAX_MEMO_ENTRIES,
                    |attempt| *attempt,
                    |_| GOSSIP_REFRESH_BACKOFF,
                );
            }
            self.gossip_last_refresh_attempt.insert(key, now);
            eligible.push(name.clone());
            guards.push(guard);
        }

        if eligible.is_empty() {
            return HashMap::new();
        }

        // M21a: evict the main memo entry before fetching, so this call cannot serve the
        // same stale `defaultVersion` it was triggered to correct.
        for name in &eligible {
            self.gossip.remove(&self.gossip_key(system, name));
        }

        // Finding #3: same global cap `gossip_findings_batch` already applies.
        #[expect(
            clippy::expect_used,
            reason = "gossip_semaphore is never closed for the lifetime of this client"
        )]
        let _permit = self
            .gossip_semaphore
            .acquire()
            .await
            .expect("gossip_semaphore is never closed");

        let fetched = self.fetch_gossip_batch(system, &eligible).await;

        // Release every refresh claim now that the fetch completed (a cancellation before
        // this point would have dropped `guards` already, same as `gossip_findings_batch`'s
        // C1 fix).
        drop(guards);

        let mut result = HashMap::new();
        for name in eligible {
            let outcome = match fetched.get(&name) {
                Some(findings) => CallOutcome::Definitive(findings.clone()),
                None => CallOutcome::Degraded(None),
            };
            if let Some(findings) = outcome.clone().into_value() {
                result.insert(name.clone(), findings);
            }
            self.gossip.insert(self.gossip_key(system, &name), outcome);
        }
        result
    }

    fn gossip_key(&self, system: DepsDevSystem, name: &str) -> GossipMemoKey {
        GossipMemoKey {
            base: self.base_url.clone(),
            system,
            name: name.to_string(),
        }
    }

    /// One (possibly paginated) `POST /v3alpha/findingsbatch` call for `names`
    /// (live-verified request/response shape 2026-09-26, `npm/vite` + `npm/left-pad`).
    ///
    /// Maps each resolved name to `Some(findings)`, or `None` when GOSSIP reported no
    /// resolvable `defaultVersion` for it. The whole call failing (network, timeout,
    /// non-2xx, malformed response, or a page exceeding [`DEPS_DEV_BODY_LIMIT`] — N8, this
    /// guard applies to *every* page, not only the first) yields an empty map, so every
    /// name [`Self::gossip_findings_batch`] asked for falls through to [`GOSSIP_ERROR_TTL`]
    /// there rather than this method needing its own per-name failure bookkeeping.
    async fn fetch_gossip_batch(
        &self,
        system: DepsDevSystem,
        names: &[String],
    ) -> HashMap<String, Option<GossipFindings>> {
        let url = format!("{}/v3alpha/findingsbatch", self.base_url);
        let system_upper = system.as_path_segment().to_uppercase();
        let requests: Vec<GossipBatchRequestWire<'_>> = names
            .iter()
            .map(|name| GossipBatchRequestWire {
                package_key: GossipPackageKeyRefWire {
                    system: &system_upper,
                    name,
                },
            })
            .collect();

        let mut result = HashMap::new();
        let mut page_token: Option<String> = None;

        for _ in 0..GOSSIP_BATCH_MAX_PAGES {
            let body = GossipFindingsBatchRequestWire {
                requests: &requests,
                page_token: page_token.as_deref(),
            };

            let bytes = match tokio::time::timeout(
                GOSSIP_BATCH_CALL_TIMEOUT,
                self.cache.post_json_limited_trusted_origin(
                    &url,
                    &body,
                    BodyLimit::new(DEPS_DEV_BODY_LIMIT),
                    &self.trusted_origin,
                ),
            )
            .await
            {
                Ok(Ok(bytes)) => bytes,
                Ok(Err(e)) => {
                    let (status, cause) = e.safe_tracing_summary();
                    tracing::debug!(
                        status = ?status,
                        cause,
                        "deps.dev GOSSIP findings batch fetch failed"
                    );
                    return HashMap::new();
                }
                Err(_) => {
                    tracing::debug!("deps.dev GOSSIP findings batch fetch timed out");
                    return HashMap::new();
                }
            };

            let wire = match crate::parser::parse_json_checked::<GossipFindingsBatchWire>(&bytes) {
                Ok(wire) => wire,
                Err(e) => {
                    tracing::debug!(
                        error = %e,
                        "deps.dev GOSSIP findings batch response parse failed"
                    );
                    return HashMap::new();
                }
            };

            for entry in wire.responses {
                let name = entry.request.package_key.name;
                let findings = entry
                    .findings
                    .default_version
                    .as_ref()
                    .map(gossip_findings_from_entry);
                result.insert(name, findings);
            }

            if wire.next_page_token.is_empty() {
                break;
            }
            page_token = Some(wire.next_page_token);
        }

        result
    }

    /// Returns GOSSIP findings for one exact, resolved `(system, name, version)` — hover's
    /// only live, per-request GOSSIP fetch (issue #1456, spec 072 FR-005): the
    /// pinned/resolved version may not be the package's `defaultVersion`, so
    /// [`Self::gossip_findings_batch`]'s package-level result cannot cover it.
    ///
    /// Infallible by construction, exactly like [`Self::trust_signal`]: every failure
    /// degrades to `None`, memoized under `GOSSIP_ERROR_TTL` so a transient outage does
    /// not re-fire on every hover. Backed by `Self::gossip_versions` (version-keyed, not
    /// `Self::gossip`'s package-level memo) so a response landing past hover's
    /// `GOSSIP_WAIT_BUDGET` (`lsp_helpers::hover`) still warms something usable by the next
    /// hover on the same pinned version, mirroring [`Self::trust_signal`]'s
    /// spawn-and-warm design.
    pub async fn gossip_findings_for_version(
        &self,
        system: DepsDevSystem,
        name: &str,
        version: &str,
    ) -> Option<GossipFindings> {
        let key = GossipVersionMemoKey {
            base: self.base_url.clone(),
            system,
            name: name.to_string(),
            version: version.to_string(),
        };

        if let Some(outcome) = self.gossip_versions.get_fresh(&key) {
            return outcome.into_value();
        }

        if !self.gossip_version_in_flight.insert(key.clone()) {
            return None;
        }
        let _guard = DashSetInFlightGuard {
            set: &self.gossip_version_in_flight,
            key: key.clone(),
        };

        let outcome = self.fetch_gossip_version(system, name, version).await;
        let findings = outcome.clone().into_value();
        self.gossip_versions.insert(key, outcome);
        findings
    }

    /// Version-scoped `GET .../versions/{version}:findings` call backing
    /// [`Self::gossip_findings_for_version`]. Reads only `requestedVersion` (the exact
    /// version asked about) — an absent `requestedVersion` means nothing to report for this
    /// exact version, never falls back to `defaultVersion`, which would misattribute a
    /// different (default/resolved) version's findings to the requested one (code-review
    /// finding M2).
    async fn fetch_gossip_version(
        &self,
        system: DepsDevSystem,
        name: &str,
        version: &str,
    ) -> CallOutcome<Option<GossipFindings>> {
        if is_dot_segment(name) {
            warn_rejected_value(
                "is_dot_segment",
                "deps.dev GOSSIP findings request URL",
                name,
            );
            return CallOutcome::Definitive(None);
        }
        if is_dot_segment(version) {
            warn_rejected_value(
                "is_dot_segment",
                "deps.dev GOSSIP findings request URL",
                version,
            );
            return CallOutcome::Definitive(None);
        }

        let url = format!(
            "{}/v3alpha/systems/{}/packages/{}/versions/{}:findings",
            self.base_url,
            system.as_path_segment(),
            urlencoding::encode(name),
            urlencoding::encode(version),
        );

        match self
            .get_json::<GossipFindingsWire>(
                &url,
                GOSSIP_CALL_TIMEOUT,
                DepsDevCall::GossipVersionFindings { name },
            )
            .await
        {
            Ok(wire) => {
                // Security/impl-critic review M2: must NOT fall back to `default_version` —
                // this call asked for `version` specifically (a pinned/resolved version that
                // may differ from the package's default), so falling back would attribute
                // `defaultVersion`'s low-usage/cooldown data to a version it was never
                // computed for. An absent `requestedVersion` means "nothing to report for
                // this exact version".
                let findings = wire
                    .requested_version
                    .as_ref()
                    .map(gossip_findings_from_entry);
                CallOutcome::Definitive(findings)
            }
            Err(CallFailure::NotFound) => CallOutcome::Definitive(None),
            Err(CallFailure::Transient) => CallOutcome::Degraded(None),
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

/// Which deps.dev call [`DepsDevClient::get_json`] is making — carries just enough (a
/// `'static` label plus the identifying name/key) to produce the exact per-call tracing every
/// call site used to write out by hand.
enum DepsDevCall<'a> {
    /// `GET .../versions/{version}` (the trust-signal client's version call).
    Version { name: &'a str },
    /// `GET /v3/projects/{key}` (the Scorecard project call).
    Project { key: &'a str },
    /// `GET .../{name}:similarlyNamedPackages`.
    SimilarlyNamed { name: &'a str },
    /// `GET .../packages/{name}` (`GetPackage`).
    Package { name: &'a str },
    /// `GET .../versions/{version}:dependents` (`GetDependents`).
    Dependents { name: &'a str },
    /// `GET .../versions/{version}:findings` (GOSSIP's version-scoped findings call).
    GossipVersionFindings { name: &'a str },
}

impl DepsDevCall<'_> {
    /// The exact label every `"deps.dev {label} ..."` tracing message used to hard-code.
    const fn label(&self) -> &'static str {
        match self {
            Self::Version { .. } => "version",
            Self::Project { .. } => "project",
            Self::SimilarlyNamed { .. } => "similarly-named-packages",
            Self::Package { .. } => "package",
            Self::Dependents { .. } => "dependents",
            Self::GossipVersionFindings { .. } => "GOSSIP version findings",
        }
    }

    /// The declaration-key name to redact for a timeout's tracing, for every variant except
    /// [`Self::Project`] (which logs its own `project_key` field instead, unredacted — see
    /// [`DepsDevClient::get_json`]'s `TimedOut` arm).
    const fn timed_out_name(&self) -> Option<&str> {
        match self {
            Self::Version { name }
            | Self::SimilarlyNamed { name }
            | Self::Package { name }
            | Self::Dependents { name }
            | Self::GossipVersionFindings { name } => Some(name),
            Self::Project { .. } => None,
        }
    }
}

/// [`DepsDevClient::get_json`]'s error shape — the two-way split every deps.dev call site
/// actually branches on: whether a 404 was returned (a per-call-site decision on whether that
/// means authoritative absence or a transient race), or everything else (parse failure,
/// non-2xx, or timeout — all three degrade a [`CallOutcome`] the same way).
enum CallFailure {
    /// The server returned 404.
    NotFound,
    /// A parse failure, non-2xx response, or timeout.
    Transient,
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
        client.signals.memo().insert(
            MemoKey {
                base: "https://api.deps.dev".to_string(),
                system: DepsDevSystem::Npm,
                name: "a\0b".to_string(),
                version: "c".to_string(),
            },
            CallOutcome::Definitive(Some(SupplyChainTrustSignal::default())),
        );
        assert!(!client.signals.memo().contains_key(&MemoKey {
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
        let entry_ttl = client
            .signals
            .memo()
            .ttl_of(&key)
            .expect("memo entry expected");
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
            !client.signals.in_flight_contains(&key),
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
        let entry_ttl = client
            .signals
            .memo()
            .ttl_of(&key)
            .expect("memo entry expected");
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
            client.signals.memo().insert(
                MemoKey {
                    base: "https://api.deps.dev".to_string(),
                    system: DepsDevSystem::Npm,
                    name: format!("pkg-{i}"),
                    version: "1.0.0".to_string(),
                },
                CallOutcome::Definitive(None),
            );
        }
        assert_eq!(client.signals.memo().len(), MAX_MEMO_ENTRIES);

        client.signals.memo().insert(
            MemoKey {
                base: "https://api.deps.dev".to_string(),
                system: DepsDevSystem::Npm,
                name: "overflow".to_string(),
                version: "1.0.0".to_string(),
            },
            CallOutcome::Definitive(None),
        );

        assert!(
            client.signals.memo().len() <= MAX_MEMO_ENTRIES,
            "memo must stay bounded at MAX_MEMO_ENTRIES, got {}",
            client.signals.memo().len()
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
            client.projects.insert(
                ProjectKeyMemo {
                    base: "https://api.deps.dev".to_string(),
                    project_key: format!("github.com/org/repo-{i}"),
                },
                CallOutcome::Definitive(Some(8.0)),
            );
        }
        assert_eq!(client.projects.len(), MAX_MEMO_ENTRIES);

        client.projects.insert(
            ProjectKeyMemo {
                base: "https://api.deps.dev".to_string(),
                project_key: "github.com/org/overflow".to_string(),
            },
            CallOutcome::Definitive(Some(8.0)),
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

        let (signal, completeness) = client
            .typosquat_signal(DepsDevSystem::Npm, "crossenv")
            .await;
        let signal = signal.expect("300x ratio must fire");
        assert_eq!(signal.suspected_name, "cross-env");
        assert_eq!(signal.declared_dependent_count, 3);
        assert_eq!(signal.suspected_dependent_count, 900);
        assert_eq!(completeness, FetchCompleteness::Complete);
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

        let (signal, completeness) = client
            .typosquat_signal(DepsDevSystem::Npm, "coffeescript")
            .await;
        assert!(
            signal.is_none(),
            "a ~6.9x ratio must stay well under the 50x threshold"
        );
        assert_eq!(completeness, FetchCompleteness::Complete);
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

        let (signal, completeness) = client.typosquat_signal(DepsDevSystem::Npm, "missing").await;
        assert!(signal.is_none());
        assert_eq!(
            completeness,
            FetchCompleteness::Complete,
            "a 404 is deps.dev's authoritative negative, not a failure to retry"
        );
        package_call.assert_async().await;
    }

    /// Issue #1463: a per-call timeout must report [`FetchCompleteness::Incomplete`], not
    /// silently the same [`FetchCompleteness::Complete`] a genuine "no similar packages"
    /// result would report — this is exactly the distinction
    /// `deps-lsp::document::osv_scan::run_typosquat_prefetch`'s gate relies on to know a
    /// failed attempt must be retried.
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

        let (signal, completeness) = client.typosquat_signal(DepsDevSystem::Npm, "slow").await;
        assert!(signal.is_none());
        assert_eq!(completeness, FetchCompleteness::Incomplete);
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

        let (signal, completeness) = client.typosquat_signal(DepsDevSystem::Npm, "broken").await;
        assert!(signal.is_none());
        assert_eq!(completeness, FetchCompleteness::Incomplete);
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

        assert!(client.popularity(DepsDevSystem::Npm, ".").await.0.is_none());
        assert!(
            client
                .popularity(DepsDevSystem::Npm, "..")
                .await
                .0
                .is_none()
        );
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

        let (dependent_count, _) = client.popularity(DepsDevSystem::Npm, "evil").await;
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

        let (dependent_count, completeness) = client.popularity(DepsDevSystem::Npm, "racy").await;
        assert!(dependent_count.is_none());
        assert_eq!(
            completeness,
            FetchCompleteness::Incomplete,
            "issue #1463: a transient default-version race is not a verified negative and \
             must not be reported as a completed check"
        );

        let key = PopularityMemoKey {
            base: client.base_url.clone(),
            system: DepsDevSystem::Npm,
            name: "racy".to_string(),
        };
        let entry = client
            .popularity
            .memo()
            .get_fresh(&key)
            .expect("popularity memo entry expected");
        assert_eq!(
            client
                .popularity
                .memo()
                .ttl_of(&key)
                .expect("popularity memo entry expected"),
            DEPS_DEV_ERROR_TTL,
            "a GetDependents 404 must memoize the short error TTL, not the 1h success TTL \
             a genuine GetPackage 404 (authoritative absence) uses"
        );
        assert_eq!(
            entry.completeness(),
            FetchCompleteness::Incomplete,
            "issue #1463: the memoized entry itself must carry the incomplete marker, so a \
             retry within the error TTL still reports Incomplete instead of a stale Complete"
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

        let (signal, completeness) = client.typosquat_signal(DepsDevSystem::Npm, "lonely").await;
        assert!(signal.is_none());
        assert_eq!(completeness, FetchCompleteness::Complete);
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

        let (signal, completeness) = client
            .typosquat_signal(DepsDevSystem::Npm, "self-echo")
            .await;
        assert!(signal.is_none());
        assert_eq!(completeness, FetchCompleteness::Complete);
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

        let (signal, completeness) = client.typosquat_signal(DepsDevSystem::Npm, "tiny").await;
        assert!(
            signal.is_some(),
            "at least one of the capped candidates should still qualify"
        );
        assert_eq!(completeness, FetchCompleteness::Complete);
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
                .0
                .is_empty()
        );
        assert!(
            client
                .similar_packages(DepsDevSystem::Npm, "..")
                .await
                .0
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

        let (candidates, completeness) = client.similar_packages(DepsDevSystem::Npm, "tiny").await;
        assert_eq!(completeness, FetchCompleteness::Complete);

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
            .memo()
            .get_fresh(&key)
            .expect("similarity memo entry expected")
            .into_value()
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

        let ((a, a_completeness), (b, b_completeness)) = tokio::join!(
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
        assert_eq!(a_completeness, FetchCompleteness::Complete);
        assert_eq!(b_completeness, FetchCompleteness::Complete);
        assert_eq!(
            call_count.load(Ordering::SeqCst),
            1,
            "exactly one of the two concurrent calls must fetch the shared candidate's \
             GetPackage; the other must await that in-flight fetch's result rather than \
             duplicating the request"
        );
    }

    // --- GOSSIP (issue #1456, spec 072) ---

    /// Live-captured response shape (2026-09-26, `POST /v3alpha/findingsbatch` against
    /// `npm/vite` + `npm/left-pad`) — the regression fixture every batch test below reuses.
    /// Also the fixture that caught a real bug during implementation: `GossipRiskWire`'s
    /// variants must deserialize `"RISK_HIGH"`/`"RISK_MEDIUM"`, not a bare `"HIGH"`/
    /// `"MEDIUM"` (a `#[serde(rename_all = "SCREAMING_SNAKE_CASE")]` alone produces the
    /// latter, silently failing on every real deps.dev risk value).
    const GOSSIP_BATCH_VITE_AND_LEFT_PAD: &str = r#"{"responses":[
        {"request":{"packageKey":{"system":"NPM","name":"vite"}},
         "findings":{"packageKey":{"system":"NPM","name":"vite"},"recommendedVersions":[],
             "defaultVersion":{"versionKey":{"system":"NPM","name":"vite","version":"8.3.1"},
                 "isDefault":true,
                 "findings":[{"type":"COOLDOWN","risk":"RISK_HIGH",
                     "cooldownContext":{"end":"2026-10-09T12:26:19Z"}}],
                 "cooldownEnd":"2026-10-09T12:26:19Z"},
             "packageFindings":[]}},
        {"request":{"packageKey":{"system":"NPM","name":"left-pad"}},
         "findings":{"packageKey":{"system":"NPM","name":"left-pad"},
             "recommendedVersions":[{"versionKey":{"system":"NPM","name":"left-pad","version":"1.3.0"},
                 "isDefault":true,
                 "findings":[{"type":"DEPRECATED","risk":"RISK_MEDIUM",
                     "deprecatedContext":{"reason":"use String.prototype.padStart()"}}],
                 "cooldownEnd":"2018-04-24T01:10:45Z"}],
             "defaultVersion":{"versionKey":{"system":"NPM","name":"left-pad","version":"1.3.0"},
                 "isDefault":true,
                 "findings":[{"type":"DEPRECATED","risk":"RISK_MEDIUM",
                     "deprecatedContext":{"reason":"use String.prototype.padStart()"}}],
                 "cooldownEnd":"2018-04-24T01:10:45Z"},
             "packageFindings":[{"type":"DEPRECATED","risk":"RISK_MEDIUM"}]}}
    ], "nextPageToken":""}"#;

    #[tokio::test]
    async fn gossip_findings_batch_parses_active_cooldown() {
        let (mut server, client) = mock_client().await;
        let _batch = server
            .mock("POST", "/v3alpha/findingsbatch")
            .with_status(200)
            .with_body(GOSSIP_BATCH_VITE_AND_LEFT_PAD)
            .create_async()
            .await;

        let result = client
            .gossip_findings_batch(
                DepsDevSystem::Npm,
                &["vite".to_string(), "left-pad".to_string()],
            )
            .await;

        let vite = result.get("vite").expect("vite findings expected");
        assert_eq!(vite.version, "8.3.1");
        let cooldown = vite.cooldown.expect("active cooldown expected");
        assert_eq!(cooldown.risk, GossipRiskLevel::High);
        assert!(cooldown.is_active(crate::PublishTime::from_unix_secs(0)));

        // `left-pad`'s only real finding is `DEPRECATED`, which collapses into
        // `GossipFindingType::Other` and is never surfaced as a cooldown/low-usage finding
        // — but S2's fix means `cooldown` is still `Some`, sourced from the sibling
        // `cooldownEnd` field (2018, long past) rather than a `COOLDOWN` finding — this is
        // exactly the tri-state fix: GOSSIP data is present and authoritatively says "not
        // active", distinguishable from "no GOSSIP data at all".
        let left_pad = result.get("left-pad").expect("left-pad findings expected");
        let left_pad_cooldown = left_pad
            .cooldown
            .expect("cooldownEnd fallback must still populate cooldown");
        assert!(!left_pad_cooldown.is_active(crate::PublishTime::now()));
        assert!(left_pad.low_usage.is_none());
    }

    #[tokio::test]
    async fn gossip_findings_batch_no_default_version_omits_name() {
        let (mut server, client) = mock_client().await;
        let _batch = server
            .mock("POST", "/v3alpha/findingsbatch")
            .with_status(200)
            .with_body(
                r#"{"responses":[{"request":{"packageKey":{"system":"NPM","name":"missing"}},
                    "findings":{"packageKey":{"system":"NPM","name":"missing"},
                        "recommendedVersions":[],
                        "packageFindings":[{"type":"NOT_FOUND","risk":"RISK_CRITICAL"}]}}],
                    "nextPageToken":""}"#,
            )
            .create_async()
            .await;

        let result = client
            .gossip_findings_batch(DepsDevSystem::Npm, &["missing".to_string()])
            .await;

        assert!(
            !result.contains_key("missing"),
            "NFR-002: a name with no resolvable defaultVersion must be absent, not present \
             with an empty GossipFindings"
        );
    }

    #[tokio::test]
    async fn gossip_findings_batch_second_call_within_ttl_issues_zero_requests() {
        let (mut server, client) = mock_client().await;
        let batch = server
            .mock("POST", "/v3alpha/findingsbatch")
            .with_status(200)
            .with_body(GOSSIP_BATCH_VITE_AND_LEFT_PAD)
            .expect(1)
            .create_async()
            .await;

        client
            .gossip_findings_batch(
                DepsDevSystem::Npm,
                &["vite".to_string(), "left-pad".to_string()],
            )
            .await;
        client
            .gossip_findings_batch(
                DepsDevSystem::Npm,
                &["vite".to_string(), "left-pad".to_string()],
            )
            .await;

        batch.assert_async().await;
    }

    #[tokio::test]
    async fn gossip_findings_batch_follows_next_page_token() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let (mut server, client) = mock_client().await;
        let call_count = Arc::new(AtomicUsize::new(0));
        let call_count_clone = Arc::clone(&call_count);
        let _batch = server
            .mock("POST", "/v3alpha/findingsbatch")
            .with_status(200)
            .with_body_from_request(move |req| {
                let body = req.body().map(|b| String::from_utf8_lossy(b).into_owned());
                let is_page2 = body.is_ok_and(|b| b.contains("pageToken"));
                call_count_clone.fetch_add(1, Ordering::SeqCst);
                if is_page2 {
                    br#"{"responses":[{"request":{"packageKey":{"system":"NPM","name":"left-pad"}},
                        "findings":{"packageKey":{"system":"NPM","name":"left-pad"},
                            "recommendedVersions":[],
                            "defaultVersion":{"versionKey":{"system":"NPM","name":"left-pad","version":"1.3.0"}},
                            "packageFindings":[]}}],
                        "nextPageToken":""}"#
                        .to_vec()
                } else {
                    br#"{"responses":[{"request":{"packageKey":{"system":"NPM","name":"vite"}},
                        "findings":{"packageKey":{"system":"NPM","name":"vite"},
                            "recommendedVersions":[],
                            "defaultVersion":{"versionKey":{"system":"NPM","name":"vite","version":"8.3.1"},
                                "isDefault":true,
                                "findings":[{"type":"COOLDOWN","risk":"RISK_HIGH",
                                    "cooldownContext":{"end":"2026-10-09T12:26:19Z"}}]},
                            "packageFindings":[]}}],
                        "nextPageToken":"page2"}"#
                        .to_vec()
                }
            })
            .create_async()
            .await;

        let result = client
            .gossip_findings_batch(
                DepsDevSystem::Npm,
                &["vite".to_string(), "left-pad".to_string()],
            )
            .await;

        assert!(
            result.contains_key("vite"),
            "page 1's result must be included"
        );
        assert!(
            result.contains_key("left-pad"),
            "page 2's result must be included"
        );
        assert_eq!(
            call_count.load(Ordering::SeqCst),
            2,
            "exactly two pages must be fetched"
        );
    }

    #[tokio::test]
    async fn gossip_findings_batch_oversized_page_returns_empty_and_no_panic() {
        let (mut server, client) = mock_client().await;
        let _batch = server
            .mock("POST", "/v3alpha/findingsbatch")
            .with_status(200)
            // `DEPS_DEV_BODY_LIMIT` (1 MiB) — comfortably exceeded by this padded body.
            .with_body(format!(
                r#"{{"responses":[],"nextPageToken":"","padding":"{}"}}"#,
                "x".repeat(DEPS_DEV_BODY_LIMIT + 1)
            ))
            .create_async()
            .await;

        let result = client
            .gossip_findings_batch(DepsDevSystem::Npm, &["vite".to_string()])
            .await;
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn gossip_findings_batch_non_2xx_returns_empty_and_memoizes_error_ttl() {
        let (mut server, client) = mock_client().await;
        let _batch = server
            .mock("POST", "/v3alpha/findingsbatch")
            .with_status(500)
            .create_async()
            .await;

        let result = client
            .gossip_findings_batch(DepsDevSystem::Npm, &["vite".to_string()])
            .await;
        assert!(result.is_empty());

        let entry_ttl = client
            .gossip
            .ttl_of(&GossipMemoKey {
                base: client.base_url.clone(),
                system: DepsDevSystem::Npm,
                name: "vite".to_string(),
            })
            .expect("memo entry expected even on failure");
        assert_eq!(entry_ttl, GOSSIP_ERROR_TTL);
    }

    #[tokio::test]
    async fn gossip_findings_batch_sends_uppercase_system() {
        let (mut server, client) = mock_client().await;
        let batch = server
            .mock("POST", "/v3alpha/findingsbatch")
            .match_body(mockito::Matcher::Regex(r#""system":"NPM""#.to_string()))
            .with_status(200)
            .with_body(r#"{"responses":[],"nextPageToken":""}"#)
            .expect(1)
            .create_async()
            .await;

        client
            .gossip_findings_batch(DepsDevSystem::Npm, &["vite".to_string()])
            .await;

        batch.assert_async().await;
    }

    /// Security/impl-critic review C1 regression, positive-behavior half: two concurrent
    /// `gossip_findings_batch` calls for the *same* name must issue exactly one network
    /// request — the loser sees the name already claimed and skips it (skip-and-defer),
    /// mirroring `typosquat_signal_concurrent_calls_share_one_candidate_popularity_request`'s
    /// identical in-flight-dedup pattern for the sibling `popularity` memo.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn gossip_findings_batch_concurrent_calls_for_same_name_issue_one_request() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let (mut server, client) = mock_client().await;
        let client = Arc::new(client);
        let call_count = Arc::new(AtomicUsize::new(0));
        let call_count_clone = Arc::clone(&call_count);
        let _batch = server
            .mock("POST", "/v3alpha/findingsbatch")
            .with_status(200)
            .with_body_from_request(move |_req| {
                call_count_clone.fetch_add(1, Ordering::SeqCst);
                std::thread::sleep(Duration::from_millis(60));
                GOSSIP_BATCH_VITE_AND_LEFT_PAD.as_bytes().to_vec()
            })
            .create_async()
            .await;

        let (a, b) = tokio::join!(
            {
                let client = Arc::clone(&client);
                async move {
                    client
                        .gossip_findings_batch(DepsDevSystem::Npm, &["vite".to_string()])
                        .await
                }
            },
            {
                let client = Arc::clone(&client);
                async move {
                    client
                        .gossip_findings_batch(DepsDevSystem::Npm, &["vite".to_string()])
                        .await
                }
            }
        );
        // The claim winner gets the real result; the loser sees the name already claimed
        // and returns without it this round (its own next prefetch trigger gets it from
        // the memo the winner warms).
        assert!(a.contains_key("vite") || b.contains_key("vite"));
        assert_eq!(
            call_count.load(Ordering::SeqCst),
            1,
            "exactly one of the two concurrent calls must issue the network request; the \
             other must see the in-flight claim and skip it rather than duplicate the \
             request"
        );
    }

    /// Security/impl-critic review C1 regression, negative-behavior half — the actual bug:
    /// after a `gossip_findings_batch` call is cancelled mid-flight (its future dropped
    /// while `.await`ing the fetch, exactly like `run_gossip_prefetch`'s
    /// `tokio::time::timeout` wrapper can do under realistic load), the claimed name must
    /// NOT stay permanently in-flight — a later call for the same name must be able to
    /// claim and fetch it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn gossip_findings_batch_cancellation_releases_in_flight_claim() {
        let (mut server, client) = mock_client().await;
        let client = Arc::new(client);
        let batch = server
            .mock("POST", "/v3alpha/findingsbatch")
            .with_status(200)
            .with_body_from_request(|_req| {
                std::thread::sleep(Duration::from_millis(60));
                GOSSIP_BATCH_VITE_AND_LEFT_PAD.as_bytes().to_vec()
            })
            .expect(1)
            .create_async()
            .await;

        let spawn_client = Arc::clone(&client);
        let handle = tokio::spawn(async move {
            spawn_client
                .gossip_findings_batch(DepsDevSystem::Npm, &["vite".to_string()])
                .await
        });
        // Deliberately shorter than the mock's 60ms response — cancels (drops) the
        // spawned future's `JoinHandle` before the fetch completes.
        let outcome = tokio::time::timeout(Duration::from_millis(5), handle).await;
        assert!(
            outcome.is_err(),
            "the artificial budget must elapse before the mock responds"
        );

        // Give the cancelled task's own future time to actually finish unwinding (the
        // `tokio::spawn`ed task itself is NOT aborted by the timeout above — only this
        // test's `JoinHandle` await was — so the task and its `InFlightGuard`s still run
        // to completion in the background).
        tokio::time::sleep(Duration::from_millis(250)).await;

        let second = client
            .gossip_findings_batch(DepsDevSystem::Npm, &["vite".to_string()])
            .await;
        assert!(
            second.contains_key("vite"),
            "a leaked in-flight claim would make this call skip \"vite\" forever — got: \
             {second:?}"
        );
        batch.assert_async().await;
    }

    /// Issue #1456, spec 072 FR-012/N8 regression: the global `GOSSIP_PREFETCH_CONCURRENCY`
    /// semaphore must actually cap how many `GetFindingsBatch` calls are in flight at once
    /// across documents, not just be wired without effect.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn gossip_findings_batch_respects_global_concurrency_semaphore() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let (mut server, client) = mock_client().await;
        let client = Arc::new(client);
        let concurrent = Arc::new(AtomicUsize::new(0));
        let max_concurrent = Arc::new(AtomicUsize::new(0));
        let concurrent_clone = Arc::clone(&concurrent);
        let max_clone = Arc::clone(&max_concurrent);
        let _batch = server
            .mock("POST", "/v3alpha/findingsbatch")
            .with_status(200)
            .with_body_from_request(move |_req| {
                let now = concurrent_clone.fetch_add(1, Ordering::SeqCst) + 1;
                max_clone.fetch_max(now, Ordering::SeqCst);
                std::thread::sleep(Duration::from_millis(60));
                concurrent_clone.fetch_sub(1, Ordering::SeqCst);
                br#"{"responses":[],"nextPageToken":""}"#.to_vec()
            })
            .create_async()
            .await;

        // Distinct names, so none of these dedupe against each other via the in-flight
        // set — every one of them must reach the network and contend for the semaphore.
        let handles: Vec<_> = (0..(GOSSIP_PREFETCH_CONCURRENCY * 2))
            .map(|i| {
                let client = Arc::clone(&client);
                tokio::spawn(async move {
                    client
                        .gossip_findings_batch(DepsDevSystem::Npm, &[format!("pkg-{i}")])
                        .await
                })
            })
            .collect();
        for handle in handles {
            handle.await.expect("task must not panic");
        }

        let observed = max_concurrent.load(Ordering::SeqCst);
        assert!(
            observed <= GOSSIP_PREFETCH_CONCURRENCY,
            "observed {observed} concurrent GetFindingsBatch calls, expected at most \
             {GOSSIP_PREFETCH_CONCURRENCY}"
        );
    }

    /// Issue #1456, spec 072 FR-012/N8 regression: `DEPS_DEV_BODY_LIMIT` must reject an
    /// oversized *second* page too, not only the first — the existing
    /// `gossip_findings_batch_oversized_page_returns_empty_and_no_panic` test only covers
    /// an oversized first page.
    #[tokio::test]
    async fn gossip_findings_batch_oversized_second_page_rejects_whole_result() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let (mut server, client) = mock_client().await;
        let call_count = Arc::new(AtomicUsize::new(0));
        let call_count_clone = Arc::clone(&call_count);
        let _batch = server
            .mock("POST", "/v3alpha/findingsbatch")
            .with_status(200)
            .with_body_from_request(move |req| {
                let body = req.body().map(|b| String::from_utf8_lossy(b).into_owned());
                let is_page2 = body.is_ok_and(|b| b.contains("pageToken"));
                call_count_clone.fetch_add(1, Ordering::SeqCst);
                if is_page2 {
                    format!(
                        r#"{{"responses":[],"nextPageToken":"","padding":"{}"}}"#,
                        "x".repeat(DEPS_DEV_BODY_LIMIT + 1)
                    )
                    .into_bytes()
                } else {
                    br#"{"responses":[{"request":{"packageKey":{"system":"NPM","name":"vite"}},
                        "findings":{"packageKey":{"system":"NPM","name":"vite"},
                            "recommendedVersions":[],
                            "defaultVersion":{"versionKey":{"system":"NPM","name":"vite","version":"8.3.1"},
                                "isDefault":true,"findings":[]},
                            "packageFindings":[]}}],"nextPageToken":"page2"}"#
                        .to_vec()
                }
            })
            .create_async()
            .await;

        let result = client
            .gossip_findings_batch(DepsDevSystem::Npm, &["vite".to_string()])
            .await;
        assert!(
            result.is_empty(),
            "an oversized second page must reject the whole batch result (M1's accepted \
             all-or-nothing parsing) — got: {result:?}"
        );
        assert_eq!(
            call_count.load(Ordering::SeqCst),
            2,
            "both pages must have actually been requested"
        );
    }

    /// Issue #1456, spec 072 FR-011/M21a regression: the whole point of
    /// `force_refresh_gossip_findings` is to reach the network even when
    /// `gossip_findings_batch` would have served a fresh, non-expired memo entry — a
    /// literal "just call the normal path again" would be a no-op.
    #[tokio::test]
    async fn force_refresh_gossip_findings_bypasses_fresh_memo_entry() {
        let (mut server, client) = mock_client().await;
        let batch = server
            .mock("POST", "/v3alpha/findingsbatch")
            .with_status(200)
            .with_body(GOSSIP_BATCH_VITE_AND_LEFT_PAD)
            .expect(2)
            .create_async()
            .await;

        // Warms the memo with a fresh (well within `GOSSIP_SUCCESS_TTL`) entry.
        client
            .gossip_findings_batch(DepsDevSystem::Npm, &["vite".to_string()])
            .await;

        let refreshed = client
            .force_refresh_gossip_findings(DepsDevSystem::Npm, &["vite".to_string()])
            .await;
        assert!(
            refreshed.contains_key("vite"),
            "force refresh must still return a result, not just bypass the memo silently"
        );
        batch.assert_async().await;
    }

    /// A second `force_refresh_gossip_findings` call for the same package within
    /// `GOSSIP_REFRESH_BACKOFF` must be throttled — no second network call.
    #[tokio::test]
    async fn force_refresh_gossip_findings_throttles_within_backoff_window() {
        let (mut server, client) = mock_client().await;
        let batch = server
            .mock("POST", "/v3alpha/findingsbatch")
            .with_status(200)
            .with_body(GOSSIP_BATCH_VITE_AND_LEFT_PAD)
            .expect(1)
            .create_async()
            .await;

        let first = client
            .force_refresh_gossip_findings(DepsDevSystem::Npm, &["vite".to_string()])
            .await;
        assert!(first.contains_key("vite"));

        let second = client
            .force_refresh_gossip_findings(DepsDevSystem::Npm, &["vite".to_string()])
            .await;
        assert!(
            second.is_empty(),
            "a second force-refresh within the backoff window must be throttled, not \
             fetched again"
        );

        batch.assert_async().await;
    }

    /// Two distinct packages are throttled independently — refreshing one must not
    /// throttle the other.
    #[tokio::test]
    async fn force_refresh_gossip_findings_throttle_is_per_package() {
        let (mut server, client) = mock_client().await;
        let batch = server
            .mock("POST", "/v3alpha/findingsbatch")
            .with_status(200)
            .with_body(GOSSIP_BATCH_VITE_AND_LEFT_PAD)
            .expect(2)
            .create_async()
            .await;

        client
            .force_refresh_gossip_findings(DepsDevSystem::Npm, &["vite".to_string()])
            .await;
        client
            .force_refresh_gossip_findings(DepsDevSystem::Npm, &["left-pad".to_string()])
            .await;

        // The real proof: the mock's `.expect(2)` above only passes if refreshing
        // "left-pad" actually reached the network — a per-package (not global) backoff
        // would have let it through; a global one would have wrongly throttled it.
        batch.assert_async().await;
    }

    /// Issue #1456, spec 072 FR-011/M21d: the backoff map must stay bounded at
    /// `MAX_MEMO_ENTRIES`, mirroring every other memo's boundary test in this module.
    #[test]
    fn gossip_last_refresh_attempt_evicts_when_max_entries_reached() {
        let client = client();
        let now = Instant::now();
        for i in 0..MAX_MEMO_ENTRIES {
            client.gossip_last_refresh_attempt.insert(
                GossipMemoKey {
                    base: "https://api.deps.dev".to_string(),
                    system: DepsDevSystem::Npm,
                    name: format!("pkg-{i}"),
                },
                now,
            );
        }
        assert_eq!(client.gossip_last_refresh_attempt.len(), MAX_MEMO_ENTRIES);

        crate::cache_policy::evict_expired_then_oldest(
            &client.gossip_last_refresh_attempt,
            MAX_MEMO_ENTRIES,
            |attempt| *attempt,
            |_| GOSSIP_REFRESH_BACKOFF,
        );
        client.gossip_last_refresh_attempt.insert(
            GossipMemoKey {
                base: "https://api.deps.dev".to_string(),
                system: DepsDevSystem::Npm,
                name: "overflow".to_string(),
            },
            now,
        );

        assert!(
            client.gossip_last_refresh_attempt.len() <= MAX_MEMO_ENTRIES,
            "backoff map must stay bounded at MAX_MEMO_ENTRIES, got {}",
            client.gossip_last_refresh_attempt.len()
        );
    }

    #[tokio::test]
    async fn gossip_findings_for_version_returns_requested_version_cooldown() {
        let (mut server, client) = mock_client().await;
        let _findings = server
            .mock("GET", "/v3alpha/systems/npm/packages/vite/versions/8.3.1:findings")
            .with_status(200)
            .with_body(
                r#"{"versionKey":{"system":"NPM","name":"vite","version":"8.3.1"},
                    "recommendedVersions":[],
                    "requestedVersion":{"versionKey":{"system":"NPM","name":"vite","version":"8.3.1"},
                        "isDefault":true,
                        "findings":[{"type":"COOLDOWN","risk":"RISK_HIGH",
                            "cooldownContext":{"end":"2026-10-09T12:26:19Z"}}]},
                    "defaultVersion":{"versionKey":{"system":"NPM","name":"vite","version":"8.3.1"},
                        "isDefault":true,
                        "findings":[{"type":"COOLDOWN","risk":"RISK_HIGH",
                            "cooldownContext":{"end":"2026-10-09T12:26:19Z"}}]},
                    "packageFindings":[]}"#,
            )
            .create_async()
            .await;

        let findings = client
            .gossip_findings_for_version(DepsDevSystem::Npm, "vite", "8.3.1")
            .await
            .expect("findings expected");
        assert_eq!(findings.version, "8.3.1");
        assert!(findings.cooldown.is_some());
    }

    #[tokio::test]
    async fn gossip_findings_for_version_low_usage_context_parses_alternative_packages() {
        let (mut server, client) = mock_client().await;
        let _findings = server
            .mock(
                "GET",
                "/v3alpha/systems/npm/packages/slopsquat-pkg/versions/1.0.0:findings",
            )
            .with_status(200)
            .with_body(
                r#"{"versionKey":{"system":"NPM","name":"slopsquat-pkg","version":"1.0.0"},
                    "recommendedVersions":[],
                    "requestedVersion":{"versionKey":{"system":"NPM","name":"slopsquat-pkg","version":"1.0.0"},
                        "isDefault":true,
                        "findings":[{"type":"LOW_USAGE","risk":"RISK_MEDIUM",
                            "lowUsageContext":{"alternativePackages":["popular-pkg"]}}]},
                    "packageFindings":[]}"#,
            )
            .create_async()
            .await;

        let findings = client
            .gossip_findings_for_version(DepsDevSystem::Npm, "slopsquat-pkg", "1.0.0")
            .await
            .expect("findings expected");
        let low_usage = findings.low_usage.expect("low-usage finding expected");
        assert_eq!(low_usage.risk, GossipRiskLevel::Medium);
        assert_eq!(
            low_usage.alternative_packages,
            vec!["popular-pkg".to_string()]
        );
    }

    #[tokio::test]
    async fn gossip_findings_for_version_second_call_within_ttl_issues_zero_requests() {
        let (mut server, client) = mock_client().await;
        let findings = server
            .mock("GET", "/v3alpha/systems/npm/packages/vite/versions/8.3.1:findings")
            .with_status(200)
            .with_body(
                r#"{"versionKey":{"system":"NPM","name":"vite","version":"8.3.1"},
                    "recommendedVersions":[],
                    "requestedVersion":{"versionKey":{"system":"NPM","name":"vite","version":"8.3.1"},
                        "isDefault":true,"findings":[]}}"#,
            )
            .expect(1)
            .create_async()
            .await;

        client
            .gossip_findings_for_version(DepsDevSystem::Npm, "vite", "8.3.1")
            .await;
        client
            .gossip_findings_for_version(DepsDevSystem::Npm, "vite", "8.3.1")
            .await;

        findings.assert_async().await;
    }

    /// Test gap (impl-critic review, item 5): the version-scoped counterpart of
    /// `trust_signal_survives_dropped_join_handle_and_warms_memo` — a late
    /// `gossip_findings_for_version` response arriving after `GOSSIP_WAIT_BUDGET` has
    /// elapsed (hover's own budget, `lsp_helpers::hover`) must still land in the
    /// version-keyed memo, so the *next* hover on the same pinned version is a memo hit
    /// rather than a repeated fetch.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn gossip_findings_for_version_survives_dropped_join_handle_and_warms_memo() {
        let (mut server, client) = mock_client().await;
        let client = Arc::new(client);
        let findings = server
            .mock("GET", "/v3alpha/systems/npm/packages/vite/versions/8.3.1:findings")
            .with_status(200)
            .with_body_from_request(|_req| {
                std::thread::sleep(Duration::from_millis(60));
                br#"{"versionKey":{"system":"NPM","name":"vite","version":"8.3.1"},
                    "recommendedVersions":[],
                    "requestedVersion":{"versionKey":{"system":"NPM","name":"vite","version":"8.3.1"},
                        "isDefault":true,
                        "findings":[{"type":"COOLDOWN","risk":"RISK_HIGH",
                            "cooldownContext":{"end":"2026-10-09T12:26:19Z"}}]}}"#
                    .to_vec()
            })
            .expect(1)
            .create_async()
            .await;

        let spawn_client = Arc::clone(&client);
        let handle = tokio::spawn(async move {
            spawn_client
                .gossip_findings_for_version(DepsDevSystem::Npm, "vite", "8.3.1")
                .await
        });
        // Deliberately much shorter than the mock's 60ms response — this must reliably
        // elapse first, mirroring `trust_signal_survives_dropped_join_handle_and_warms_memo`'s
        // identical artificial-budget technique.
        let outcome = tokio::time::timeout(Duration::from_millis(5), handle).await;
        assert!(
            outcome.is_err(),
            "the artificial budget must elapse before the mock responds"
        );

        // Give the detached task ample real time to finish (60ms response + scheduling
        // slack) and write the version-keyed memo.
        tokio::time::sleep(Duration::from_millis(250)).await;

        let second = client
            .gossip_findings_for_version(DepsDevSystem::Npm, "vite", "8.3.1")
            .await;
        assert!(
            second.is_some(),
            "the memo warmed by the detached task must serve the next call"
        );
        findings.assert_async().await;
    }

    /// #1452-style guard: a `.`/`..` name or version must never reach the request URL.
    #[tokio::test]
    async fn gossip_findings_for_version_dot_segment_rejected_before_request() {
        let (mut server, client) = mock_client().await;
        let call = server
            .mock("GET", mockito::Matcher::Any)
            .expect(0)
            .create_async()
            .await;

        assert!(
            client
                .gossip_findings_for_version(DepsDevSystem::Npm, ".", "1.0.0")
                .await
                .is_none()
        );
        assert!(
            client
                .gossip_findings_for_version(DepsDevSystem::Npm, "left-pad", "..")
                .await
                .is_none()
        );
        call.assert_async().await;
    }

    #[tokio::test]
    async fn gossip_findings_for_version_404_returns_none_no_panic() {
        let (mut server, client) = mock_client().await;
        let _findings = server
            .mock(
                "GET",
                "/v3alpha/systems/npm/packages/missing/versions/1.0.0:findings",
            )
            .with_status(404)
            .create_async()
            .await;

        let findings = client
            .gossip_findings_for_version(DepsDevSystem::Npm, "missing", "1.0.0")
            .await;
        assert!(findings.is_none());
    }

    /// Security/impl-critic review M2 regression: when `requestedVersion` is absent from a
    /// version-scoped `GetFindings` response, `defaultVersion`'s data must NOT be returned
    /// as if it applied to the requested version — that would misattribute one version's
    /// low-usage/cooldown finding to a different (pinned/resolved) version.
    #[tokio::test]
    async fn gossip_findings_for_version_no_requested_version_does_not_fall_back_to_default() {
        let (mut server, client) = mock_client().await;
        let _findings = server
            .mock(
                "GET",
                "/v3alpha/systems/npm/packages/vite/versions/7.0.0:findings",
            )
            .with_status(200)
            .with_body(
                r#"{"versionKey":{"system":"NPM","name":"vite","version":"7.0.0"},
                    "recommendedVersions":[],
                    "defaultVersion":{"versionKey":{"system":"NPM","name":"vite","version":"8.3.1"},
                        "isDefault":true,
                        "findings":[{"type":"LOW_USAGE","risk":"RISK_MEDIUM"}]},
                    "packageFindings":[]}"#,
            )
            .create_async()
            .await;

        let findings = client
            .gossip_findings_for_version(DepsDevSystem::Npm, "vite", "7.0.0")
            .await;
        assert!(
            findings.is_none(),
            "must not return defaultVersion's (8.3.1) low-usage finding for the requested \
             (7.0.0) version — got: {findings:?}"
        );
    }
}
