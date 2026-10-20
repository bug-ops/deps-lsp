//! Fixtures for tests that pin how background and completion fetches feed the endpoint circuit
//! breaker: a loopback socket that never answers, the hover schedule that detects whether the
//! breaker opened, and a ready-made NuGet-style registry built on both.
//!
//! The breaker opens for hovers that merely wait on a request another task sent only if the
//! fetch under test tagged that request with an [`EndpointObserver`](crate::EndpointObserver)
//! (or [`observe_endpoint`](crate::observe_endpoint)).

use std::collections::HashMap;
use std::future::Future;
use std::net::{SocketAddr, TcpListener};
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::OnceCell;

use super::{StubFormatter, test_uri};
use crate::ecosystem::BoxFuture;
use crate::lsp_helpers::{
    DependencyOutcomes, FetchContext, InteractiveFetch, InteractiveFetchGate,
    InteractiveFetchRequest, NoLiveList, NormalizeName, SharedVersions, VersionData,
    await_interactive_versions,
};
use crate::{
    DependencySource, EcosystemId, EgressTier, FreshnessSettings, HttpCache, PackageName, Registry,
    RegistryEndpoint,
};

/// A loopback socket that accepts connections and never replies, standing in for a dead
/// registry host. Closes when dropped.
#[derive(Debug)]
pub struct SilentListener(TcpListener);

impl Default for SilentListener {
    fn default() -> Self {
        Self::new()
    }
}

impl SilentListener {
    /// Binds a fresh loopback port, so every instance names a distinct endpoint.
    ///
    /// # Panics
    ///
    /// Panics if no loopback port can be bound.
    #[must_use]
    pub fn new() -> Self {
        Self(TcpListener::bind("127.0.0.1:0").expect("a loopback port must be available"))
    }

    /// The address the socket listens on.
    ///
    /// # Panics
    ///
    /// Panics if the bound socket has no local address.
    #[must_use]
    pub fn addr(&self) -> SocketAddr {
        self.0
            .local_addr()
            .expect("a bound socket has a local address")
    }
}

/// Dispatch concurrency of the gate [`waiters_open_the_breaker_while`] creates.
const GATE_CONCURRENCY: NonZeroUsize = NonZeroUsize::MIN.saturating_add(3);

async fn hover<R: Registry + ?Sized>(
    registry: &R,
    gate: &InteractiveFetchGate,
    ecosystem: EcosystemId,
    name: &str,
) -> InteractiveFetch<SharedVersions> {
    let package = PackageName::new(name);
    let source = DependencySource::Registry;
    let outcomes = DependencyOutcomes::new();
    let normalized = StubFormatter::DEFAULT.normalize_package_name(&package);
    let (cached, resolved) = (HashMap::new(), HashMap::new());
    let manifest = test_uri("/project/stalled/manifest");
    let request = InteractiveFetchRequest::new(
        VersionData::new(&cached, &resolved)
            .with_ecosystem(ecosystem)
            .with_outcomes(&outcomes)
            .with_interactive_fetch_gate(gate),
        &manifest,
        &package,
        &normalized,
        &source,
        FetchContext::Hover,
    );
    await_interactive_versions(registry, request, FreshnessSettings::Disabled).await
}

async fn cancelled_hover<R: Registry + ?Sized>(
    registry: &R,
    gate: &InteractiveFetchGate,
    ecosystem: EcosystemId,
    name: &str,
    after: Duration,
) {
    let outcome = tokio::time::timeout(after, hover(registry, gate, ecosystem, name)).await;
    assert!(outcome.is_err(), "the hover must still be waiting");
}

/// Reports whether `background` (the production fetch under test) fed the endpoint's breaker.
///
/// It runs `background` next to hovers on the first two of `packages` that wait on `registry`'s
/// shared request from 0.5 s to 6.0 s and are then cancelled. A hover on the third at 6.1 s is
/// refused without polling only if `background` fed the evidence.
///
/// `registry` must coalesce its lookups onto the request `background` sends (a shared cell or
/// lock), `ecosystem` must be the one `background` observes, and `packages` must be names the
/// registry accepts. Needs a paused-clock test (`start_paused`).
///
/// # Examples
///
/// Not run, because it needs a paused-clock runtime and a real coalescing registry:
///
/// ```no_run
/// # #[cfg(feature = "test-util")] {
/// use deps_core::EcosystemId;
/// use deps_core::test_util::{StalledCoalescingRegistry, waiters_open_the_breaker_while};
///
/// # async fn demo() {
/// let registry = StalledCoalescingRegistry::new();
/// let background = async { /* the production fetch under test */ };
/// let opened = waiters_open_the_breaker_while(
///     &registry,
///     EcosystemId::Cargo,
///     ["hover-a", "hover-b", "hover-c"],
///     background,
/// )
/// .await;
/// assert!(opened);
/// # }
/// # }
/// ```
pub async fn waiters_open_the_breaker_while<R: Registry + ?Sized>(
    registry: &R,
    ecosystem: EcosystemId,
    packages: [&str; 3],
    background: impl Future<Output = ()>,
) -> bool {
    let [first, second, third] = packages;
    let gate = InteractiveFetchGate::new(GATE_CONCURRENCY);
    let hovers = async {
        tokio::time::sleep(Duration::from_millis(500)).await;
        futures::join!(
            cancelled_hover(
                registry,
                &gate,
                ecosystem,
                first,
                Duration::from_millis(5500)
            ),
            cancelled_hover(
                registry,
                &gate,
                ecosystem,
                second,
                Duration::from_millis(5500)
            ),
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
        let started = tokio::time::Instant::now();
        let third = hover(registry, &gate, ecosystem, third).await;
        matches!(third, InteractiveFetch::Degraded(NoLiveList::Unverified))
            && started.elapsed() < Duration::from_secs(1)
    };
    let ((), refused) = futures::join!(background, hovers);
    refused
}

/// A NuGet-style registry whose every lookup waits on one shared request that never gets an
/// answer; see [`Self::waiters_open_the_breaker_while`].
pub struct StalledCoalescingRegistry {
    cache: Arc<HttpCache>,
    url: String,
    endpoint: RegistryEndpoint,
    index: OnceCell<()>,
    _socket: SilentListener,
}

impl Default for StalledCoalescingRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl StalledCoalescingRegistry {
    /// A registry whose shared request goes to a fresh loopback socket that never answers.
    ///
    /// Every instance binds its own port, so its endpoint is unique within the process.
    #[must_use]
    pub fn new() -> Self {
        let socket = SilentListener::new();
        let url = format!("http://{}/index", socket.addr());
        Self {
            cache: Arc::new(HttpCache::new()),
            endpoint: RegistryEndpoint::from_base_str(&url, EgressTier::Baseline),
            url,
            index: OnceCell::new(),
            _socket: socket,
        }
    }

    async fn await_index(&self) -> crate::Result<()> {
        self.index
            .get_or_try_init(|| async { self.cache.get_cached(&self.url).await.map(drop) })
            .await?;
        Ok(())
    }

    /// [`waiters_open_the_breaker_while`] on this registry.
    pub async fn waiters_open_the_breaker_while(
        &self,
        ecosystem: EcosystemId,
        background: impl Future<Output = ()>,
    ) -> bool {
        waiters_open_the_breaker_while(
            self,
            ecosystem,
            ["hover-a", "hover-b", "hover-c"],
            background,
        )
        .await
    }
}

impl Registry for StalledCoalescingRegistry {
    fn get_versions<'a>(
        &'a self,
        _name: &'a PackageName,
    ) -> BoxFuture<'a, crate::Result<Vec<Box<dyn crate::Version>>>> {
        Box::pin(async move {
            self.await_index().await?;
            Ok(Vec::new())
        })
    }

    fn get_latest_matching<'a>(
        &'a self,
        _name: &'a PackageName,
        _req: &'a crate::VersionReq,
        _selection_context: &'a crate::SelectionContext,
    ) -> BoxFuture<'a, crate::Result<Option<Box<dyn crate::Version>>>> {
        Box::pin(async move {
            self.await_index().await?;
            Ok(None)
        })
    }

    fn search_raw<'a>(
        &'a self,
        _query: &'a str,
        _limit: usize,
    ) -> BoxFuture<'a, crate::Result<Vec<Box<dyn crate::Metadata>>>> {
        Box::pin(async move { Ok(Vec::new()) })
    }

    fn endpoint_for(&self, _name: &PackageName, _source: &DependencySource) -> RegistryEndpoint {
        self.endpoint
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
