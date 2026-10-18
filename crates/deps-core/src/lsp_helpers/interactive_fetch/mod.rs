//! Fail-fast gate for the interactive (hover, code action) registry await.
//!
//! [`REGISTRY_FETCH_BUDGET`](super::REGISTRY_FETCH_BUDGET) bounds one interactive `get_versions_from` await, but a bound
//! alone has no memory: against a registry that never answers, every request re-pays the
//! whole budget and four of them occupy every `buffer_unordered(4)` LSP dispatch slot
//! (#1830). [`InteractiveFetchGate`] adds the memory and the concurrency cap:
//!
//! - a short-lived, source-qualified failure memo, seeded from the background fetch's
//!   [`DependencyOutcomes`] and written by interactive awaits that fail or time out;
//! - a semaphore that leaves at least one dispatch slot free for non-registry requests;
//! - single-flight for version lists, so concurrent requests for one package share one
//!   registry poll ([`await_interactive_versions`]).
//!
//! The gate lives in `deps-core` once (FR-012) and is consulted through
//! [`await_interactive_versions`] (hover and code actions) or the uncoalesced
//! [`await_interactive_fetch`].
//!
//! [`DependencyOutcomes`]: super::DependencyOutcomes

mod attempt;
mod breaker;
mod flight;
mod key;
mod memo;
#[cfg(test)]
mod tests;

use std::future::Future;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use dashmap::DashMap;
use tokio::sync::{Semaphore, watch};

use self::attempt::{Attempted, bounded_await_until};
use self::breaker::EndpointBreaker;
use self::flight::{FlightKey, FlightResult, ListShape};
use self::key::{
    EndpointKey, InteractiveFetchKey, LookupKind, ManifestFingerprint, SourceFingerprint,
};
use self::memo::{Decision, InteractiveRecord};
use super::VersionData;
use crate::freshness::FreshnessSettings;
use crate::single_flight::Slot;
use crate::{DependencySource, FetchFailure, NetworkMode, PackageName, Registry, Version};

/// A version list shared between the requests of one flight.
///
/// Cloning is a reference-count bump, so every follower of a leader sees the same list.
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::SharedVersions;
///
/// let list = SharedVersions::from(Vec::new());
/// assert!(list.is_empty());
/// ```
pub type SharedVersions = Arc<[Box<dyn Version>]>;

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

/// An interactive lookup other than a package's version list, which
/// [`await_interactive_fetch`] gates with its own failure memo and budget.
///
/// Each kind is memoized separately, so a stalled decoration never degrades the version list
/// of the same package, and the other way round.
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::AuxiliaryLookup;
///
/// assert_ne!(AuxiliaryLookup::Decoration, AuxiliaryLookup::PinResolution);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuxiliaryLookup {
    /// Optional enrichment of an already-rendered answer, such as NuGet's unlisted markers.
    /// It may be served by another host than the version list, so it never opens or closes
    /// the endpoint breaker (it is still refused while the breaker is open for a hover).
    Decoration,
    /// Resolution of a floating pin to a concrete release, such as a GitLab CI component's
    /// `~latest`. It is served by the dependency's own endpoint, so its pace counts for the
    /// endpoint breaker like a version list's.
    PinResolution,
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
    fn gated(&self, kind: LookupKind) -> Option<(&'a InteractiveFetchGate, InteractiveFetchKey)> {
        let gate = self.versions.interactive_fetch?;
        let ecosystem = self.versions.ecosystem?;
        match self.versions.network {
            NetworkMode::Offline => None,
            NetworkMode::Online => Some((
                gate,
                InteractiveFetchKey {
                    endpoint: EndpointKey {
                        ecosystem,
                        manifest: ManifestFingerprint::of(self.manifest),
                        source: SourceFingerprint::of(self.source),
                    },
                    package: PackageName::new(self.normalized_name),
                    kind,
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

/// Taken from the tokio clock so TTL and eviction agree under `start_paused`.
fn now() -> Instant {
    tokio::time::Instant::now().into_std()
}

fn log_skipped(request: &InteractiveFetchRequest<'_>, reason: &str) {
    tracing::debug!(
        package = %request.package.for_tracing(),
        context = request.context.as_str(),
        reason,
        "interactive registry await skipped"
    );
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
    version_flights: DashMap<FlightKey, watch::Receiver<Slot<FlightResult>>>,
    breaker: EndpointBreaker,
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
            version_flights: DashMap::new(),
            breaker: EndpointBreaker::default(),
            permits: Semaphore::new(permits),
            generation: AtomicU64::new(0),
        }
    }

    /// Forgets every record and discards the result of any await already in flight.
    ///
    /// Call when a configuration change (registry URL, token, proxy) or a reparse makes the
    /// recorded failures and endpoint health untrustworthy (FR-006). Requests that start afterwards never join a
    /// flight begun before it.
    pub fn invalidate_all(&self) {
        self.generation.fetch_add(1, Ordering::SeqCst);
        self.memo.clear();
        self.breaker.clear();
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

    fn generation(&self) -> u64 {
        self.generation.load(Ordering::SeqCst)
    }

    async fn live<T, E>(
        &self,
        fetch: impl Future<Output = Result<T, E>>,
        key: &InteractiveFetchKey,
        request: &InteractiveFetchRequest<'_>,
        background_failure_known: bool,
        generation: u64,
    ) -> InteractiveFetch<T> {
        // Overflow degrades immediately and is deliberately not memoized: the package itself
        // may be perfectly reachable.
        let Ok(_permit) = self.permits.try_acquire() else {
            log_skipped(request, "interactive fetch concurrency cap reached");
            return InteractiveFetch::Degraded(NoLiveList::Unverified);
        };
        let deadline = tokio::time::Instant::now() + key.kind.budget();
        match self
            .attempt(
                fetch,
                deadline,
                key,
                request,
                background_failure_known,
                generation,
            )
            .await
        {
            Attempted::Polled(result) => result,
            Attempted::Refused => InteractiveFetch::Degraded(NoLiveList::Unverified),
        }
    }
}

/// Awaits `fetch` for hover or a code action, bounded by [`REGISTRY_FETCH_BUDGET`](super::REGISTRY_FETCH_BUDGET) and
/// short-circuited by the request's [`InteractiveFetchGate`] when it carries one.
///
/// Without a gate, an ecosystem, or while offline this is the plain bounded await (FR-013).
/// With one, a package whose lookup is known to have failed — recorded by the background
/// fetch or by an earlier interactive await — returns [`InteractiveFetch::Degraded`] without
/// polling `fetch` at all, and live awaits are capped so dispatch slots stay free.
/// [`NoLiveList::Unverified`] marks every case where the answer is unknown rather than
/// reported by the registry.
///
/// Concurrent calls for one package are not coalesced here; a version list should go through
/// [`await_interactive_versions`], which is.
///
/// # Examples
///
/// ```
/// use deps_core::lsp_helpers::{
///     AuxiliaryLookup, FetchContext, InteractiveFetch, InteractiveFetchRequest,
///     await_interactive_fetch,
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
///     runtime.block_on(await_interactive_fetch(
///     async { Ok::<_, ()>(42_u8) },
///     request,
///     AuxiliaryLookup::PinResolution,
/// ));
/// assert!(matches!(result, InteractiveFetch::Live(42)));
/// ```
pub async fn await_interactive_fetch<T, E>(
    fetch: impl Future<Output = Result<T, E>>,
    request: InteractiveFetchRequest<'_>,
    kind: AuxiliaryLookup,
) -> InteractiveFetch<T> {
    let kind = LookupKind::Auxiliary(kind);
    let Some((gate, key)) = request.gated(kind) else {
        return plain_bounded_await(fetch, &request, kind).await;
    };
    // Read before the outcomes so an invalidation racing this request discards its writes.
    let generation = gate.generation();
    let background_failure_known = request.background_failure_known();
    match gate.decide(&key, background_failure_known, generation, now()) {
        Decision::Degrade(kind, reason) => {
            log_skipped(&request, reason.as_str());
            InteractiveFetch::Degraded(kind)
        }
        Decision::Live => {
            gate.live(fetch, &key, &request, background_failure_known, generation)
                .await
        }
    }
}

/// Fetches the version list of `request`'s package from `registry` for hover or a code action.
///
/// Behaves like [`await_interactive_fetch`] (same budget, failure memo, and concurrency cap),
/// and additionally shares one registry poll between concurrent requests for the same package
/// (FR-007): the first request polls, the others receive the same [`SharedVersions`]. A
/// request that follows a leader which got no list reports [`NoLiveList::Unverified`], never
/// [`NoLiveList::Failed`], matching a memo replay; if the leader is cancelled, a follower takes
/// over and polls itself.
///
/// A request with [`FreshnessSettings::Disabled`] may reuse the list of one that enriched its
/// versions with publish times; the reverse never happens.
///
/// # Examples
///
/// ```
/// # #[cfg(feature = "test-util")] {
/// use deps_core::lsp_helpers::{
///     FetchContext, InteractiveFetch, InteractiveFetchRequest, await_interactive_versions,
/// };
/// use deps_core::test_util::{MockRegistry, MockVersion};
/// use deps_core::{DependencySource, FreshnessSettings, PackageName, VersionData};
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
/// let registry = MockRegistry::new().with_versions(vec![MockVersion::new("1.0.0")]);
///
/// let runtime = tokio::runtime::Builder::new_current_thread()
///     .enable_time()
///     .build()
///     .unwrap();
/// let result = runtime.block_on(await_interactive_versions(
///     &registry,
///     request,
///     FreshnessSettings::Disabled,
/// ));
/// assert!(matches!(result, InteractiveFetch::Live(list) if list.len() == 1));
/// # }
/// ```
pub async fn await_interactive_versions<R: Registry + ?Sized>(
    registry: &R,
    request: InteractiveFetchRequest<'_>,
    freshness: FreshnessSettings,
) -> InteractiveFetch<SharedVersions> {
    let fetch = async {
        registry
            .get_versions_from(request.package, request.source, freshness)
            .await
            .map(SharedVersions::from)
    };
    let Some((gate, key)) = request.gated(LookupKind::VersionList) else {
        return plain_bounded_await(fetch, &request, LookupKind::VersionList).await;
    };
    flight::await_shared(gate, key, fetch, &request, ListShape::of(freshness)).await
}

async fn plain_bounded_await<T, E>(
    fetch: impl Future<Output = Result<T, E>>,
    request: &InteractiveFetchRequest<'_>,
    kind: LookupKind,
) -> InteractiveFetch<T> {
    let (result, _) = bounded_await_until(
        fetch,
        tokio::time::Instant::now() + kind.budget(),
        request,
        kind,
    )
    .await;
    result
}
