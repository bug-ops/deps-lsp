//! The endpoint breaker opens for hovers that wait on a background fetch's per-repository lock.

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

use crate::registry::GithubActionsRegistry;

struct Harness {
    registry: GithubActionsRegistry,
    gate: InteractiveFetchGate,
    manifest: url::Url,
    _listener: std::net::TcpListener,
}

impl Harness {
    /// A registry whose API lives on a socket that accepts and never answers.
    fn new() -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let api_base = format!("http://{}", listener.local_addr().unwrap());
        Self {
            registry: GithubActionsRegistry::for_test(Arc::new(HttpCache::new()), api_base, false),
            gate: InteractiveFetchGate::new(NonZeroUsize::new(4).unwrap()),
            manifest: url::Url::parse("file:///project/.github/workflows/ci.yml").unwrap(),
            _listener: listener,
        }
    }

    async fn hover(&self, name: &str) -> InteractiveFetch<SharedVersions> {
        let package = PackageName::new(name);
        let source = DependencySource::Registry;
        let outcomes = DependencyOutcomes::new();
        let (cached, resolved) = (HashMap::new(), HashMap::new());
        let request = InteractiveFetchRequest::new(
            VersionData::new(&cached, &resolved)
                .with_ecosystem(EcosystemId::GithubActions)
                .with_outcomes(&outcomes)
                .with_interactive_fetch_gate(&self.gate),
            &self.manifest,
            &package,
            name,
            &source,
            FetchContext::Hover,
        );
        await_interactive_versions(&self.registry, request, FreshnessSettings::Disabled).await
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
            EcosystemId::GithubActions,
            observe_endpoint(endpoint, async {
                let _ = self.registry.get_versions(name).await;
            }),
        )
        .await;
    }
}

#[tokio::test(start_paused = true)]
async fn hovers_waiting_on_the_repository_lock_open_the_breaker() {
    let harness = Harness::new();
    let hovers = async {
        tokio::time::sleep(Duration::from_millis(500)).await;
        tokio::join!(
            harness.cancelled_hover("actions/checkout", Duration::from_millis(5500)),
            harness.cancelled_hover("actions/setup-node", Duration::from_millis(5500)),
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
        let started = tokio::time::Instant::now();
        let third = harness.hover("actions/cache").await;
        (third, started.elapsed())
    };

    let (third, waited) = tokio::select! {
        ((), (), ()) = async {
            tokio::join!(
                harness.background_fetch("actions/checkout"),
                harness.background_fetch("actions/setup-node"),
                harness.background_fetch("actions/cache"),
            )
        } => unreachable!("the API never answers"),
        outcome = hovers => outcome,
    };

    assert!(matches!(
        third,
        InteractiveFetch::Degraded(NoLiveList::Unverified)
    ));
    assert!(waited < Duration::from_secs(1), "refused after {waited:?}");
}
