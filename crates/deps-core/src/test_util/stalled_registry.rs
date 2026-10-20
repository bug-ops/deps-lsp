//! A registry whose one shared request never gets an answer, for tests that pin how background
//! and completion fetches feed the endpoint circuit breaker.
//!
//! It stands in for a NuGet-style registry: every lookup waits on one `OnceCell` whose
//! initialization sends a single request to a loopback socket that accepts and never replies.
//! A test hands the production fetch under test to
//! [`StalledCoalescingRegistry::waiters_open_the_breaker_while`]; the breaker opens for hovers
//! that merely wait on that request only if the fetch tagged it with
//! [`observe_ecosystem`](crate::observe_ecosystem) and [`observe_endpoint`](crate::observe_endpoint).

use std::collections::HashMap;
use std::future::Future;
use std::net::TcpListener;
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

/// A NuGet-style registry whose every lookup waits on one shared request that never gets an
/// answer; see [`Self::waiters_open_the_breaker_while`].
pub struct StalledCoalescingRegistry {
    cache: Arc<HttpCache>,
    url: String,
    endpoint: RegistryEndpoint,
    index: OnceCell<()>,
    _listener: TcpListener,
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
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/index", listener.local_addr().unwrap());
        Self {
            cache: Arc::new(HttpCache::new()),
            endpoint: RegistryEndpoint::from_base_str(&url, EgressTier::Baseline),
            url,
            index: OnceCell::new(),
            _listener: listener,
        }
    }

    async fn await_index(&self) -> crate::Result<()> {
        self.index
            .get_or_try_init(|| async { self.cache.get_cached(&self.url).await.map(drop) })
            .await?;
        Ok(())
    }

    async fn hover(
        &self,
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
        await_interactive_versions(self, request, FreshnessSettings::Disabled).await
    }

    async fn cancelled_hover(
        &self,
        gate: &InteractiveFetchGate,
        ecosystem: EcosystemId,
        name: &str,
        after: Duration,
    ) {
        let outcome = tokio::time::timeout(after, self.hover(gate, ecosystem, name)).await;
        assert!(outcome.is_err(), "the hover must still be waiting");
    }

    /// Runs `background` (the production fetch under test, started now) next to two hovers
    /// that wait on this registry's shared request from 0.5 s to 6.0 s and are then cancelled,
    /// and reports whether a third hover at 6.1 s is refused without polling, which only
    /// happens when `background` fed the endpoint's breaker evidence.
    ///
    /// Needs a paused-clock test (`start_paused`), and `ecosystem` must be the one `background`
    /// observes.
    pub async fn waiters_open_the_breaker_while(
        &self,
        ecosystem: EcosystemId,
        background: impl Future<Output = ()>,
    ) -> bool {
        let gate = InteractiveFetchGate::new(NonZeroUsize::new(4).unwrap());
        let hovers = async {
            tokio::time::sleep(Duration::from_millis(500)).await;
            tokio::join!(
                self.cancelled_hover(&gate, ecosystem, "hover-a", Duration::from_millis(5500)),
                self.cancelled_hover(&gate, ecosystem, "hover-b", Duration::from_millis(5500)),
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
            let started = tokio::time::Instant::now();
            let third = self.hover(&gate, ecosystem, "hover-c").await;
            matches!(third, InteractiveFetch::Degraded(NoLiveList::Unverified))
                && started.elapsed() < Duration::from_secs(1)
        };
        let ((), refused) = tokio::join!(background, hovers);
        refused
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
