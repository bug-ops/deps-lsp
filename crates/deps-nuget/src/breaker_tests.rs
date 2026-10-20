//! The endpoint breaker opens for hovers that wait on the shared service-index request.

use std::sync::Arc;

use deps_core::test_util::{SilentListener, waiters_open_the_breaker_while};
use deps_core::{
    DependencySource, EcosystemId, HttpCache, PackageName, Registry, observe_ecosystem,
    observe_endpoint,
};

use crate::registry::NuGetRegistry;

/// The background fetch of `name`, tagged the way the server tags it.
async fn background_fetch(registry: &NuGetRegistry, name: &str) {
    let package = PackageName::new(name);
    let endpoint = registry.endpoint_for(&package, &DependencySource::Registry);
    observe_ecosystem(
        EcosystemId::NuGet,
        observe_endpoint(endpoint, async {
            let _ = registry.get_versions(name).await;
        }),
    )
    .await;
}

#[tokio::test(start_paused = true)]
async fn hovers_waiting_on_the_service_index_cell_open_the_breaker() {
    let socket = SilentListener::new();
    let registry = NuGetRegistry::with_service_index_url(
        Arc::new(HttpCache::new()),
        format!("http://{}/v3/index.json", socket.addr()),
    );

    let opened = Box::pin(waiters_open_the_breaker_while(
        &registry,
        EcosystemId::NuGet,
        ["Serilog", "Polly", "Newtonsoft.Json"],
        background_fetch(&registry, "Newtonsoft.Json"),
    ))
    .await;

    assert!(opened);
}
