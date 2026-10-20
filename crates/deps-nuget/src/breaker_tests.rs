//! The endpoint breaker opens for hovers that wait on the shared service-index request.

use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;

use deps_core::lsp_helpers::{
    DependencyOutcomes, FetchContext, InteractiveFetch, InteractiveFetchGate,
    InteractiveFetchRequest, NoLiveList, SharedVersions, VersionData, await_interactive_versions,
};
use deps_core::{
    DependencySource, EcosystemId, FreshnessSettings, HttpCache, PackageName, Registry,
    observe_ecosystem, observe_endpoint,
};

use crate::registry::NuGetRegistry;

struct Harness {
    registry: Arc<NuGetRegistry>,
    gate: InteractiveFetchGate,
    manifest: url::Url,
    _listener: std::net::TcpListener,
}

impl Harness {
    /// A registry whose service index lives on a socket that accepts and never answers.
    fn new() -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let index = format!("http://{}/v3/index.json", listener.local_addr().unwrap());
        Self {
            registry: Arc::new(NuGetRegistry::with_service_index_url(
                Arc::new(HttpCache::new()),
                index,
            )),
            gate: InteractiveFetchGate::new(NonZeroUsize::new(4).unwrap()),
            manifest: url::Url::parse("file:///project/App.csproj").unwrap(),
            _listener: listener,
        }
    }

    async fn hover(&self, name: &str) -> InteractiveFetch<SharedVersions> {
        let package = PackageName::new(name);
        let source = DependencySource::Registry;
        let outcomes = DependencyOutcomes::new();
        let (cached, resolved) = (HashMap::new(), HashMap::new());
        let normalized = deps_core::NormalizedName::for_test(name);
        let request = InteractiveFetchRequest::new(
            VersionData::new(&cached, &resolved)
                .with_ecosystem(EcosystemId::NuGet)
                .with_outcomes(&outcomes)
                .with_interactive_fetch_gate(&self.gate),
            &self.manifest,
            &package,
            &normalized,
            &source,
            FetchContext::Hover,
        );
        await_interactive_versions(&*self.registry, request, FreshnessSettings::Disabled).await
    }

    async fn cancelled_hover(&self, name: &str, after: Duration) {
        let outcome = tokio::time::timeout(after, self.hover(name)).await;
        assert!(outcome.is_err(), "the hover must still be waiting");
    }

    /// The background fetch of `name`, tagged the way the server tags it.
    async fn background_fetch(&self, name: &str) {
        let package = PackageName::new(name);
        let endpoint = self
            .registry
            .endpoint_for(&package, &DependencySource::Registry);
        observe_ecosystem(
            EcosystemId::NuGet,
            observe_endpoint(endpoint, async {
                let _ = self.registry.get_versions(name).await;
            }),
        )
        .await;
    }
}

#[tokio::test(start_paused = true)]
async fn hovers_waiting_on_the_service_index_cell_open_the_breaker() {
    let harness = Harness::new();
    let hovers = async {
        tokio::time::sleep(Duration::from_millis(500)).await;
        tokio::join!(
            harness.cancelled_hover("Serilog", Duration::from_millis(5500)),
            harness.cancelled_hover("Polly", Duration::from_millis(5500)),
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
        let started = tokio::time::Instant::now();
        let third = harness.hover("Newtonsoft.Json").await;
        (third, started.elapsed())
    };

    let (third, waited) = tokio::select! {
        () = harness.background_fetch("Newtonsoft.Json") => unreachable!("the index never answers"),
        outcome = hovers => outcome,
    };

    assert!(matches!(
        third,
        InteractiveFetch::Degraded(NoLiveList::Unverified)
    ));
    assert!(waited < Duration::from_secs(1), "refused after {waited:?}");
}
