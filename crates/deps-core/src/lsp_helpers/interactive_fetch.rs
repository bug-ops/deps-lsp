//! Fail-fast gate for the interactive (hover, code action) registry await.
//!
//! [`REGISTRY_FETCH_BUDGET`] bounds one interactive `get_versions_from` await, but a bound
//! alone has no memory: against a registry that never answers, every request re-pays the
//! whole budget and four of them occupy every `buffer_unordered(4)` LSP dispatch slot
//! (#1830). [`InteractiveFetchGate`] adds the memory and the concurrency cap:
//!
//! - a short-lived, source-qualified failure memo, seeded from the background fetch's
//!   [`DependencyOutcomes`] and written by interactive awaits that fail or time out;
//! - a semaphore that leaves at least one dispatch slot free for non-registry requests.
//!
//! The gate lives in `deps-core` once (FR-012) and is consulted through
//! [`await_interactive_fetch`], which hover and code actions share.
//!
//! [`DependencyOutcomes`]: super::DependencyOutcomes

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use tokio::sync::Semaphore;

use super::{REGISTRY_FETCH_BUDGET, VersionData};
use crate::cache_policy::evict_expired_then_oldest_at;
use crate::{DependencySource, EcosystemId, FetchFailure, NetworkMode, PackageName};

/// How long a failed or timed-out lookup keeps interactive requests off the registry.
const INTERACTIVE_FAILURE_TTL: Duration = Duration::from_secs(30);

/// Hard cap on memo entries, so a manifest with thousands of failing dependencies cannot
/// grow the memo without bound.
const INTERACTIVE_MEMO_CAP: usize = 1024;

/// Why an interactive request has no live version list, which decides how speculative code
/// actions treat it.
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::NoLiveList;
///
/// assert_ne!(NoLiveList::Failed, NoLiveList::Unverified);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoLiveList {
    /// The registry answered this very request with an error: a yank check is genuinely
    /// unavailable, so speculative fix actions pass through unfiltered (unchanged from before
    /// #1204). Never replayed from the memo, which serves [`Self::Unverified`] instead.
    Failed,
    /// The answer is unknown — the deadline elapsed, the failure was only inferred from the
    /// background fetch, or the concurrency cap was hit. Speculative fix actions are
    /// dropped: an unverified yank check must not fail open.
    Unverified,
}

/// Result of an interactive registry await.
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::{InteractiveFetch, NoLiveList};
///
/// let live: InteractiveFetch<u8> = InteractiveFetch::Live(7);
/// assert_eq!(live.into_live(), Some(7));
///
/// let degraded: InteractiveFetch<u8> = InteractiveFetch::Degraded(NoLiveList::Unverified);
/// assert_eq!(degraded.into_live(), None);
/// ```
#[derive(Debug)]
pub enum InteractiveFetch<T> {
    /// The registry answered with a version list.
    Live(T),
    /// No live list is available for the stated reason.
    Degraded(NoLiveList),
}

impl<T> InteractiveFetch<T> {
    /// Returns the live value, discarding the degrade reason.
    #[must_use]
    pub fn into_live(self) -> Option<T> {
        match self {
            Self::Live(value) => Some(value),
            Self::Degraded(_) => None,
        }
    }
}

/// Which interactive surface is awaiting, for log fields only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchContext {
    /// `textDocument/hover`.
    Hover,
    /// `textDocument/codeAction`.
    CodeAction,
}

impl FetchContext {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Hover => "hover",
            Self::CodeAction => "code action",
        }
    }
}

/// Everything [`await_interactive_fetch`] needs to identify the package under the cursor.
#[derive(Debug, Clone, Copy)]
pub struct InteractiveFetchRequest<'a> {
    versions: VersionData<'a>,
    manifest: &'a url::Url,
    package: &'a PackageName,
    normalized_name: &'a str,
    source: &'a DependencySource,
    context: FetchContext,
}

impl<'a> InteractiveFetchRequest<'a> {
    /// Bundles the lookup identity: `manifest` is the document being served, `package` the raw
    /// manifest name (log output only), `normalized_name` the formatter-normalized name the
    /// outcomes map and the memo key use.
    ///
    /// The manifest scopes the memo: a default-registry dependency
    /// ([`DependencySource::Registry`]) resolves against a registry chosen by per-project
    /// configuration (`.npmrc`, Cargo source replacement) that `deps-core` cannot see, so two
    /// documents never share a record.
    #[must_use]
    pub const fn new(
        versions: VersionData<'a>,
        manifest: &'a url::Url,
        package: &'a PackageName,
        normalized_name: &'a str,
        source: &'a DependencySource,
        context: FetchContext,
    ) -> Self {
        Self {
            versions,
            manifest,
            package,
            normalized_name,
            source,
            context,
        }
    }

    /// The gate and key this request is memoized under, or `None` when the request must take
    /// the plain bounded await: no gate attached, no ecosystem to qualify the key with, or
    /// offline mode (FR-013).
    fn gated(&self) -> Option<(&'a InteractiveFetchGate, InteractiveFetchKey)> {
        let gate = self.versions.interactive_fetch?;
        let ecosystem = self.versions.ecosystem?;
        match self.versions.network {
            NetworkMode::Offline => None,
            NetworkMode::Online => Some((
                gate,
                InteractiveFetchKey {
                    ecosystem,
                    package: PackageName::new(self.normalized_name),
                    manifest: ManifestFingerprint::of(self.manifest),
                    source: SourceFingerprint::of(self.source),
                },
            )),
        }
    }

    /// True when the background fetch recorded a failure that says nothing is reachable.
    fn background_failure_known(&self) -> bool {
        let failure = self
            .versions
            .outcomes
            .and_then(|outcomes| outcomes.fetch_failure(self.normalized_name));
        match failure {
            Some(FetchFailure::Actionable(_) | FetchFailure::Transient) => true,
            // Never attempted is not evidence the registry is unreachable (FR-009).
            Some(FetchFailure::NotAttempted) | None => false,
        }
    }
}

/// Hash of a [`DependencySource`], so the memo key distinguishes registries without storing
/// their (possibly credential-bearing) URLs (FR-004, FR-010).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct SourceFingerprint(u64);

impl SourceFingerprint {
    fn of(source: &DependencySource) -> Self {
        Self(hash64(source))
    }
}

/// Hash of the manifest URL the request is served for (see [`InteractiveFetchRequest::new`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct ManifestFingerprint(u64);

impl ManifestFingerprint {
    fn of(manifest: &url::Url) -> Self {
        Self(hash64(manifest))
    }
}

fn hash64(value: &impl Hash) -> u64 {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct InteractiveFetchKey {
    ecosystem: EcosystemId,
    package: PackageName,
    manifest: ManifestFingerprint,
    source: SourceFingerprint,
}

/// Provenance of a memo record: a record inferred from the background outcomes must stop
/// applying once those outcomes clear, an interactive one is authoritative until its TTL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecordState {
    SeededFromOutcome,
    /// An interactive await errored or elapsed. Always served back as
    /// [`NoLiveList::Unverified`]: only the request that received the error itself may
    /// fail open, so a recovered registry re-enables the yank filter within the TTL.
    InteractiveFailed,
    /// A live await succeeded while the background outcomes still report a failure for the
    /// package: it keeps those stale outcomes from re-seeding a degrade until they refresh.
    InteractiveSucceeded,
}

#[derive(Debug)]
struct InteractiveRecord {
    state: RecordState,
    recorded_at: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FastFail {
    Seeded,
    Memo,
}

impl FastFail {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Seeded => "seeded from background outcome",
            Self::Memo => "interactive failure memo",
        }
    }
}

#[derive(Debug)]
enum Decision {
    Live,
    Degrade(NoLiveList, FastFail),
}

/// Taken from the tokio clock so TTL and eviction agree under `start_paused`.
fn now() -> Instant {
    tokio::time::Instant::now().into_std()
}

/// Shared failure memo and concurrency cap for interactive registry awaits.
///
/// One instance lives for the server's lifetime and is attached to hover and code-action
/// requests through [`VersionData::with_interactive_fetch_gate`]. Records are keyed by
/// ecosystem, normalized package name, and a fingerprint of the dependency source, so a
/// failure against one registry never degrades the same name resolved from another.
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::InteractiveFetchGate;
/// use std::num::NonZeroUsize;
///
/// let gate = InteractiveFetchGate::new(NonZeroUsize::new(4).unwrap());
/// assert!(gate.is_empty());
/// gate.invalidate_all();
/// assert_eq!(gate.len(), 0);
/// ```
#[derive(Debug)]
pub struct InteractiveFetchGate {
    memo: DashMap<InteractiveFetchKey, InteractiveRecord>,
    permits: Semaphore,
    generation: AtomicU64,
}

impl InteractiveFetchGate {
    /// Creates a gate for a server dispatching `dispatch_concurrency` requests at once.
    ///
    /// Allows `dispatch_concurrency - 1` simultaneous live awaits (at least one) so a slot
    /// always stays free for requests that never touch a registry.
    #[must_use]
    pub fn new(dispatch_concurrency: NonZeroUsize) -> Self {
        let permits = dispatch_concurrency.get().saturating_sub(1).max(1);
        Self {
            memo: DashMap::new(),
            permits: Semaphore::new(permits),
            generation: AtomicU64::new(0),
        }
    }

    /// Forgets every record and discards the result of any await already in flight.
    ///
    /// Call when a configuration change (registry URL, token, proxy) or a reparse makes the
    /// recorded failures untrustworthy (FR-006).
    pub fn invalidate_all(&self) {
        self.generation.fetch_add(1, Ordering::SeqCst);
        self.memo.clear();
    }

    /// Number of live records.
    #[must_use]
    pub fn len(&self) -> usize {
        self.memo.len()
    }

    /// True when no record is stored.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.memo.is_empty()
    }

    fn decide(
        &self,
        key: &InteractiveFetchKey,
        background_failure_known: bool,
        generation: u64,
        now: Instant,
    ) -> Decision {
        let existing = self
            .memo
            .get(key)
            .map(|record| (record.state, record.recorded_at));
        match existing {
            Some((state, recorded_at))
                if now.saturating_duration_since(recorded_at) < INTERACTIVE_FAILURE_TTL =>
            {
                match state {
                    RecordState::SeededFromOutcome if background_failure_known => {
                        Decision::Degrade(NoLiveList::Unverified, FastFail::Seeded)
                    }
                    RecordState::SeededFromOutcome => {
                        // The background fetch has since succeeded (or been cleared).
                        self.memo.remove_if(key, |_, record| {
                            record.state == RecordState::SeededFromOutcome
                        });
                        Decision::Live
                    }
                    RecordState::InteractiveFailed => {
                        Decision::Degrade(NoLiveList::Unverified, FastFail::Memo)
                    }
                    RecordState::InteractiveSucceeded => Decision::Live,
                }
            }
            Some(_) => Decision::Live,
            None if background_failure_known => {
                self.record(key, RecordState::SeededFromOutcome, generation);
                Decision::Degrade(NoLiveList::Unverified, FastFail::Seeded)
            }
            None => Decision::Live,
        }
    }

    fn insert(&self, key: InteractiveFetchKey, state: RecordState, now: Instant) {
        evict_expired_then_oldest_at(
            &self.memo,
            INTERACTIVE_MEMO_CAP,
            now,
            |record| record.recorded_at,
            |_| INTERACTIVE_FAILURE_TTL,
        );
        self.memo.insert(
            key,
            InteractiveRecord {
                state,
                recorded_at: now,
            },
        );
    }

    fn generation(&self) -> u64 {
        self.generation.load(Ordering::SeqCst)
    }

    /// Writes `state` unless [`Self::invalidate_all`] ran since `generation` was read.
    fn record(&self, key: &InteractiveFetchKey, state: RecordState, generation: u64) {
        self.insert(key.clone(), state, now());
        // Re-checked after the insert: an invalidation between a pre-check and the insert
        // would otherwise leave a stale record behind.
        if self.generation.load(Ordering::SeqCst) != generation {
            self.memo.remove(key);
        }
    }

    async fn live<T, E>(
        &self,
        fetch: impl std::future::Future<Output = Result<T, E>>,
        key: &InteractiveFetchKey,
        request: &InteractiveFetchRequest<'_>,
        background_failure_known: bool,
        generation: u64,
    ) -> InteractiveFetch<T> {
        // Overflow degrades immediately and is deliberately not memoized: the package itself
        // may be perfectly reachable.
        let Ok(_permit) = self.permits.try_acquire() else {
            tracing::debug!(
                package = %request.package.for_tracing(),
                context = request.context.as_str(),
                reason = "interactive fetch concurrency cap reached",
                "interactive registry await skipped"
            );
            return InteractiveFetch::Degraded(NoLiveList::Unverified);
        };
        let result = match bounded_await(fetch, request).await {
            // The background fetch still reports this package as failing, so a stale seeded
            // record must not flip to fail-open after one TTL.
            InteractiveFetch::Degraded(NoLiveList::Failed) if background_failure_known => {
                InteractiveFetch::Degraded(NoLiveList::Unverified)
            }
            other => other,
        };
        match (&result, background_failure_known) {
            (InteractiveFetch::Degraded(_), _) => {
                self.record(key, RecordState::InteractiveFailed, generation);
            }
            (InteractiveFetch::Live(_), true) => {
                self.record(key, RecordState::InteractiveSucceeded, generation);
            }
            // Nothing a success record could override, so it must not occupy the capped memo.
            (InteractiveFetch::Live(_), false) => {
                self.memo.remove(key);
            }
        }
        result
    }
}

/// Awaits `fetch` for hover or a code action, bounded by [`REGISTRY_FETCH_BUDGET`] and
/// short-circuited by the request's [`InteractiveFetchGate`] when it carries one.
///
/// Without a gate, an ecosystem, or while offline this is the plain bounded await (FR-013).
/// With one, a package whose lookup is known to have failed — recorded by the background
/// fetch or by an earlier interactive await — returns [`InteractiveFetch::Degraded`] without
/// polling `fetch` at all, and live awaits are capped so dispatch slots stay free.
/// [`NoLiveList::Unverified`] marks every case where the answer is unknown rather than
/// reported by the registry.
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::{
///     FetchContext, InteractiveFetch, InteractiveFetchRequest, await_interactive_fetch,
/// };
/// use deps_core::{DependencySource, PackageName, VersionData};
/// use std::collections::HashMap;
///
/// let cached = HashMap::new();
/// let resolved = HashMap::new();
/// let package = PackageName::new("serde");
/// let source = DependencySource::Registry;
/// let manifest = url::Url::parse("file:///project/Cargo.toml").unwrap();
/// let request = InteractiveFetchRequest::new(
///     VersionData::new(&cached, &resolved),
///     &manifest,
///     &package,
///     "serde",
///     &source,
///     FetchContext::Hover,
/// );
///
/// let runtime = tokio::runtime::Builder::new_current_thread()
///     .enable_time()
///     .build()
///     .unwrap();
/// let result =
///     runtime.block_on(await_interactive_fetch(async { Ok::<_, ()>(42_u8) }, request));
/// assert!(matches!(result, InteractiveFetch::Live(42)));
/// ```
pub async fn await_interactive_fetch<T, E>(
    fetch: impl std::future::Future<Output = Result<T, E>>,
    request: InteractiveFetchRequest<'_>,
) -> InteractiveFetch<T> {
    let Some((gate, key)) = request.gated() else {
        return bounded_await(fetch, &request).await;
    };
    // Read before the outcomes so an invalidation racing this request discards its writes.
    let generation = gate.generation();
    let background_failure_known = request.background_failure_known();
    match gate.decide(&key, background_failure_known, generation, now()) {
        Decision::Degrade(kind, reason) => {
            tracing::debug!(
                package = %request.package.for_tracing(),
                context = request.context.as_str(),
                reason = reason.as_str(),
                "interactive registry await skipped"
            );
            InteractiveFetch::Degraded(kind)
        }
        // TODO(#1843): single-flight concurrent interactive fetches of one key (FR-007)
        // TODO(#1844): host-level breaker so N distinct first hovers on a dead host cost one await
        Decision::Live => {
            gate.live(fetch, &key, &request, background_failure_known, generation)
                .await
        }
    }
}

async fn bounded_await<T, E>(
    fetch: impl std::future::Future<Output = Result<T, E>>,
    request: &InteractiveFetchRequest<'_>,
) -> InteractiveFetch<T> {
    match tokio::time::timeout(REGISTRY_FETCH_BUDGET, fetch).await {
        Ok(Ok(value)) => InteractiveFetch::Live(value),
        Ok(Err(_)) => InteractiveFetch::Degraded(NoLiveList::Failed),
        Err(_) => {
            tracing::warn!(
                package = %request.package.for_tracing(),
                context = request.context.as_str(),
                timeout_secs = REGISTRY_FETCH_BUDGET.as_secs(),
                "primary registry version fetch timed out"
            );
            InteractiveFetch::Degraded(NoLiveList::Unverified)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::assert_matches;
    use std::collections::HashMap;
    use std::sync::atomic::AtomicUsize;

    use super::*;
    use crate::lsp_helpers::DependencyOutcomes;
    use crate::{ConcreteVersion, FetchFailure};

    #[derive(Clone, Copy)]
    enum Fetch {
        Succeed,
        Fail,
        Stall,
    }

    struct Fixture {
        gate: InteractiveFetchGate,
        cached: HashMap<PackageName, crate::PackageVersions>,
        resolved: HashMap<PackageName, ConcreteVersion>,
        calls: AtomicUsize,
        manifest: url::Url,
    }

    fn manifest(path: &str) -> url::Url {
        url::Url::parse(&format!("file://{path}")).unwrap()
    }

    impl Fixture {
        fn new() -> Self {
            Self {
                gate: InteractiveFetchGate::new(NonZeroUsize::new(4).unwrap()),
                cached: HashMap::new(),
                resolved: HashMap::new(),
                calls: AtomicUsize::new(0),
                manifest: manifest("/project/Cargo.toml"),
            }
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }

        async fn run_full(
            &self,
            manifest: &url::Url,
            name: &str,
            source: &DependencySource,
            outcomes: &DependencyOutcomes,
            network: NetworkMode,
            fetch: Fetch,
        ) -> InteractiveFetch<u8> {
            let package = PackageName::new(name);
            let versions = VersionData::new(&self.cached, &self.resolved)
                .with_ecosystem(EcosystemId::Cargo)
                .with_network(network)
                .with_outcomes(outcomes)
                .with_interactive_fetch_gate(&self.gate);
            let request = InteractiveFetchRequest::new(
                versions,
                manifest,
                &package,
                name,
                source,
                FetchContext::Hover,
            );
            await_interactive_fetch(
                async {
                    self.calls.fetch_add(1, Ordering::SeqCst);
                    match fetch {
                        Fetch::Succeed => Ok(1),
                        Fetch::Fail => Err(()),
                        Fetch::Stall => {
                            tokio::time::sleep(REGISTRY_FETCH_BUDGET + Duration::from_secs(5))
                                .await;
                            Ok(1)
                        }
                    }
                },
                request,
            )
            .await
        }

        async fn run(
            &self,
            name: &str,
            outcomes: &DependencyOutcomes,
            fetch: Fetch,
        ) -> InteractiveFetch<u8> {
            self.run_full(
                &self.manifest,
                name,
                &DependencySource::Registry,
                outcomes,
                NetworkMode::Online,
                fetch,
            )
            .await
        }
    }

    fn failing(name: &str, failure: FetchFailure) -> DependencyOutcomes {
        DependencyOutcomes::new().with_fetch_failure(name, failure)
    }

    fn assert_degraded<T: std::fmt::Debug>(result: &InteractiveFetch<T>, expected: NoLiveList) {
        assert_matches!(
            result,
            InteractiveFetch::Degraded(kind) if *kind == expected,
            "expected Degraded({expected:?})"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn seeded_transient_failure_skips_the_live_call() {
        let fixture = Fixture::new();
        let outcomes = failing("serde", FetchFailure::Transient);

        let result = fixture.run("serde", &outcomes, Fetch::Succeed).await;

        assert_degraded(&result, NoLiveList::Unverified);
        assert_eq!(fixture.calls(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn seeded_actionable_failure_skips_the_live_call() {
        let fixture = Fixture::new();
        let outcomes = failing("serde", FetchFailure::Actionable("rate limited".into()));

        let result = fixture.run("serde", &outcomes, Fetch::Succeed).await;

        assert_degraded(&result, NoLiveList::Unverified);
        assert_eq!(fixture.calls(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn not_attempted_is_not_a_known_failure() {
        let fixture = Fixture::new();
        let outcomes = failing("serde", FetchFailure::NotAttempted);

        let result = fixture.run("serde", &outcomes, Fetch::Succeed).await;

        assert_matches!(result, InteractiveFetch::Live(1));
        assert_eq!(fixture.calls(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn seeded_record_is_ignored_once_outcomes_clear() {
        let fixture = Fixture::new();
        let outcomes = failing("serde", FetchFailure::Transient);
        fixture.run("serde", &outcomes, Fetch::Succeed).await;
        assert_eq!(fixture.gate.len(), 1);

        let result = fixture
            .run("serde", &DependencyOutcomes::new(), Fetch::Succeed)
            .await;

        assert_matches!(result, InteractiveFetch::Live(1));
        assert_eq!(fixture.calls(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn live_success_keeps_stale_background_outcomes_from_reseeding() {
        let fixture = Fixture::new();
        let outcomes = failing("serde", FetchFailure::Transient);
        fixture.run("serde", &outcomes, Fetch::Succeed).await;
        tokio::time::advance(INTERACTIVE_FAILURE_TTL + Duration::from_secs(1)).await;
        let recovered = fixture.run("serde", &outcomes, Fetch::Succeed).await;
        assert_matches!(recovered, InteractiveFetch::Live(1));

        let next = fixture.run("serde", &outcomes, Fetch::Succeed).await;

        assert_matches!(next, InteractiveFetch::Live(1));
        assert_eq!(
            fixture.calls(),
            2,
            "the first request only seeded; two live calls"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn live_success_without_a_background_failure_leaves_the_memo_empty() {
        let fixture = Fixture::new();
        let none = DependencyOutcomes::new();
        fixture.run("serde", &none, Fetch::Fail).await;
        tokio::time::advance(INTERACTIVE_FAILURE_TTL + Duration::from_secs(1)).await;

        let result = fixture.run("serde", &none, Fetch::Succeed).await;

        assert_matches!(result, InteractiveFetch::Live(1));
        assert!(fixture.gate.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn seeding_is_discarded_when_the_gate_was_invalidated_after_the_read() {
        let fixture = Fixture::new();
        let package = PackageName::new("serde");
        let source = DependencySource::Registry;
        let outcomes = failing("serde", FetchFailure::Transient);
        let request = InteractiveFetchRequest::new(
            VersionData::new(&fixture.cached, &fixture.resolved)
                .with_ecosystem(EcosystemId::Cargo)
                .with_outcomes(&outcomes)
                .with_interactive_fetch_gate(&fixture.gate),
            &fixture.manifest,
            &package,
            "serde",
            &source,
            FetchContext::Hover,
        );
        let (gate, key) = request.gated().unwrap();
        let generation = gate.generation();
        gate.invalidate_all();

        let decision = gate.decide(&key, true, generation, now());

        assert_matches!(
            decision,
            Decision::Degrade(NoLiveList::Unverified, FastFail::Seeded)
        );
        assert!(
            gate.is_empty(),
            "a seed read before the invalidation must not survive"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn elapse_is_memoized_so_the_next_request_makes_no_call() {
        let fixture = Fixture::new();
        let none = DependencyOutcomes::new();

        let first = fixture.run("serde", &none, Fetch::Stall).await;
        let second = fixture.run("serde", &none, Fetch::Stall).await;

        assert_degraded(&first, NoLiveList::Unverified);
        assert_degraded(&second, NoLiveList::Unverified);
        assert_eq!(fixture.calls(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn memo_expires_after_the_ttl() {
        let fixture = Fixture::new();
        let none = DependencyOutcomes::new();
        fixture.run("serde", &none, Fetch::Stall).await;

        tokio::time::advance(INTERACTIVE_FAILURE_TTL + Duration::from_secs(1)).await;
        let result = fixture.run("serde", &none, Fetch::Succeed).await;

        assert_matches!(result, InteractiveFetch::Live(1));
        assert_eq!(fixture.calls(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn stale_seeded_record_gets_one_live_retry() {
        let fixture = Fixture::new();
        let outcomes = failing("serde", FetchFailure::Transient);
        fixture.run("serde", &outcomes, Fetch::Succeed).await;

        tokio::time::advance(INTERACTIVE_FAILURE_TTL + Duration::from_secs(1)).await;
        let result = fixture.run("serde", &outcomes, Fetch::Succeed).await;

        assert_matches!(result, InteractiveFetch::Live(1));
        assert_eq!(fixture.calls(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn memoized_error_is_replayed_as_unverified() {
        let fixture = Fixture::new();
        let none = DependencyOutcomes::new();

        let first = fixture.run("serde", &none, Fetch::Fail).await;
        let second = fixture.run("serde", &none, Fetch::Succeed).await;

        assert_degraded(&first, NoLiveList::Failed);
        assert_degraded(&second, NoLiveList::Unverified);
        assert_eq!(fixture.calls(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn stale_seeded_record_stays_unverified_when_the_failure_persists() {
        let fixture = Fixture::new();
        let outcomes = failing("serde", FetchFailure::Transient);
        fixture.run("serde", &outcomes, Fetch::Fail).await;

        tokio::time::advance(INTERACTIVE_FAILURE_TTL + Duration::from_secs(1)).await;
        let retry = fixture.run("serde", &outcomes, Fetch::Fail).await;

        assert_degraded(&retry, NoLiveList::Unverified);
        assert_eq!(fixture.calls(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn same_name_in_two_manifests_does_not_share_a_record() {
        let fixture = Fixture::new();
        let none = DependencyOutcomes::new();
        let other = manifest("/other-project/Cargo.toml");
        fixture.run("serde", &none, Fetch::Fail).await;

        let result = fixture
            .run_full(
                &other,
                "serde",
                &DependencySource::Registry,
                &none,
                NetworkMode::Online,
                Fetch::Succeed,
            )
            .await;

        assert_matches!(result, InteractiveFetch::Live(1));
        assert_eq!(fixture.calls(), 2);
        assert_eq!(
            fixture.gate.len(),
            1,
            "only the first manifest's failure is recorded"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn same_name_from_two_sources_is_tracked_independently() {
        let fixture = Fixture::new();
        let none = DependencyOutcomes::new();
        let alternate = DependencySource::AlternateRegistry {
            index: "https://203.0.113.7/".into(),
            mirrors_crates_io: false,
        };
        fixture
            .run_full(
                &fixture.manifest,
                "serde",
                &alternate,
                &none,
                NetworkMode::Online,
                Fetch::Stall,
            )
            .await;

        let default_source = fixture.run("serde", &none, Fetch::Succeed).await;

        assert_matches!(default_source, InteractiveFetch::Live(1));
        assert_eq!(fixture.calls(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn saturated_gate_degrades_immediately_without_a_memo_write() {
        let fixture = Fixture::new();
        let none = DependencyOutcomes::new();

        let (_, _, _, fourth) = tokio::join!(
            fixture.run("a", &none, Fetch::Stall),
            fixture.run("b", &none, Fetch::Stall),
            fixture.run("c", &none, Fetch::Stall),
            async {
                let result = fixture.run("d", &none, Fetch::Succeed).await;
                assert_eq!(fixture.gate.len(), 0, "saturation must not be memoized");
                result
            },
        );

        assert_degraded(&fourth, NoLiveList::Unverified);
        assert_eq!(fixture.calls(), 3);
        assert_eq!(fixture.gate.len(), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn invalidation_during_an_await_discards_its_record() {
        let fixture = Fixture::new();
        let none = DependencyOutcomes::new();

        let (stalled, ()) = tokio::join!(fixture.run("serde", &none, Fetch::Stall), async {
            tokio::time::sleep(Duration::from_secs(1)).await;
            fixture.gate.invalidate_all();
        });

        assert_degraded(&stalled, NoLiveList::Unverified);
        assert!(fixture.gate.is_empty());
        let retry = fixture.run("serde", &none, Fetch::Succeed).await;
        assert_matches!(retry, InteractiveFetch::Live(1));
        assert_eq!(fixture.calls(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn offline_mode_ignores_the_gate() {
        let fixture = Fixture::new();
        let outcomes = failing("serde", FetchFailure::Transient);

        let result = fixture
            .run_full(
                &fixture.manifest,
                "serde",
                &DependencySource::Registry,
                &outcomes,
                NetworkMode::Offline,
                Fetch::Succeed,
            )
            .await;

        assert_matches!(result, InteractiveFetch::Live(1));
        assert!(fixture.gate.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn request_without_a_gate_is_the_plain_bounded_await() {
        let cached = HashMap::new();
        let resolved = HashMap::new();
        let package = PackageName::new("serde");
        let source = DependencySource::Registry;
        let outcomes = failing("serde", FetchFailure::Transient);
        let document = manifest("/project/Cargo.toml");
        let request = InteractiveFetchRequest::new(
            VersionData::new(&cached, &resolved)
                .with_ecosystem(EcosystemId::Cargo)
                .with_outcomes(&outcomes),
            &document,
            &package,
            "serde",
            &source,
            FetchContext::CodeAction,
        );

        let result = await_interactive_fetch(async { Ok::<_, ()>(1_u8) }, request).await;

        assert_matches!(result, InteractiveFetch::Live(1));
    }

    #[tokio::test(start_paused = true)]
    async fn memo_stays_within_the_cap_and_sweeps_expired_entries() {
        let fixture = Fixture::new();
        let none = DependencyOutcomes::new();
        for index in 0..INTERACTIVE_MEMO_CAP {
            fixture
                .run(&format!("pkg{index}"), &none, Fetch::Fail)
                .await;
        }
        assert_eq!(fixture.gate.len(), INTERACTIVE_MEMO_CAP);

        fixture.run("overflow-1", &none, Fetch::Fail).await;
        assert_eq!(fixture.gate.len(), INTERACTIVE_MEMO_CAP);

        tokio::time::advance(INTERACTIVE_FAILURE_TTL + Duration::from_secs(1)).await;
        fixture.run("overflow-2", &none, Fetch::Fail).await;
        assert_eq!(fixture.gate.len(), 1);
    }
}
