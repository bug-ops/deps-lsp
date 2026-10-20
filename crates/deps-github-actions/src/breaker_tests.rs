//! The endpoint breaker opens for hovers that wait on a background fetch's per-repository lock.

use std::sync::Arc;

use deps_core::test_util::{SilentListener, waiters_open_the_breaker_while};
use deps_core::{
    DependencySource, EcosystemId, HttpCache, PackageName, Registry, observe_ecosystem,
    observe_endpoint,
};

use crate::registry::GithubActionsRegistry;

/// The background fetch of `name`, tagged the way the server tags it.
async fn background_fetch(registry: &GithubActionsRegistry, name: &str) {
    let package = PackageName::new(name);
    let endpoint = registry.endpoint_for(&package, &DependencySource::Registry);
    observe_ecosystem(
        EcosystemId::GithubActions,
        observe_endpoint(endpoint, async {
            let _ = registry.get_versions(name).await;
        }),
    )
    .await;
}

#[tokio::test(start_paused = true)]
async fn hovers_waiting_on_the_repository_lock_open_the_breaker() {
    let socket = SilentListener::new();
    let registry = GithubActionsRegistry::for_test(
        Arc::new(HttpCache::new()),
        format!("http://{}", socket.addr()),
        false,
    );
    let background = async {
        tokio::join!(
            background_fetch(&registry, "actions/checkout"),
            background_fetch(&registry, "actions/setup-node"),
            background_fetch(&registry, "actions/cache"),
        );
    };

    let opened = Box::pin(waiters_open_the_breaker_while(
        &registry,
        EcosystemId::GithubActions,
        ["actions/checkout", "actions/setup-node", "actions/cache"],
        background,
    ))
    .await;

    assert!(opened);
}
