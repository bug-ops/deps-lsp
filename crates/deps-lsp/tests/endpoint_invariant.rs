//! Endpoint-identity invariant for the interactive fetch gate's circuit breaker (#1847).
//!
//! The gate shares breaker state between every lookup whose registry reports the same
//! [`RegistryEndpoint`], and scopes it to the manifest when the registry reports none. Each
//! production registry therefore has to say, for a representative `(name, source)`, whether it
//! resolves its endpoint, and lookups that travel different routes must not share one. The
//! sample table is an exhaustive `match` on [`EcosystemId`], so a new ecosystem cannot ship
//! without declaring what its registry reports.
//!
//! Compiled only with every ecosystem feature, so that all of [`EcosystemId::ALL`] is registered
//! and the test cannot pass vacuously.

#![cfg(all(
    feature = "cargo",
    feature = "npm",
    feature = "pypi",
    feature = "go",
    feature = "bundler",
    feature = "dart",
    feature = "maven",
    feature = "gradle",
    feature = "swift",
    feature = "composer",
    feature = "nuget",
    feature = "deno",
    feature = "github-actions",
    feature = "gitlab-ci",
))]

use deps_core::{DependencySource, EcosystemId, PackageName, RegistryEndpoint};
use deps_lsp::document::ServerState;

/// What a registry's `endpoint_for` must report for a sample.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Class {
    Resolved,
    Unresolved,
}

struct Sample {
    name: &'static str,
    source: DependencySource,
    class: Class,
}

fn sample(name: &'static str, source: DependencySource, class: Class) -> Sample {
    Sample {
        name,
        source,
        class,
    }
}

fn resolved(name: &'static str) -> Sample {
    sample(name, DependencySource::Registry, Class::Resolved)
}

fn unregistered_alternate() -> DependencySource {
    DependencySource::AlternateRegistry {
        index: "https://never-registered.example/".to_string(),
        mirrors_crates_io: false,
    }
}

/// Samples per ecosystem. Every sample reaches the registry the ecosystem ships, through the
/// route `get_versions_from` would take for it.
fn samples(id: EcosystemId) -> Vec<Sample> {
    match id {
        EcosystemId::Cargo => vec![resolved("serde")],
        EcosystemId::Npm => vec![resolved("react")],
        EcosystemId::Pypi => vec![resolved("flask")],
        EcosystemId::Go => vec![resolved("github.com/gin-gonic/gin")],
        EcosystemId::Bundler => vec![resolved("rails")],
        EcosystemId::Dart => vec![resolved("http")],
        EcosystemId::Maven | EcosystemId::Gradle => vec![
            resolved("androidx.core:core-ktx"),
            resolved("org.apache.commons:commons-lang3"),
        ],
        EcosystemId::Composer => vec![resolved("monolog/monolog")],
        EcosystemId::Swift => vec![resolved("apple/swift-argument-parser")],
        EcosystemId::NuGet => vec![resolved("Newtonsoft.Json")],
        EcosystemId::Deno => vec![resolved("jsr:@std/fs"), resolved("npm:react")],
        EcosystemId::GithubActions => vec![resolved("actions/checkout")],
        // The one registry that cannot name an endpoint without a registered route: the
        // default source carries no host.
        EcosystemId::GitlabCi => vec![
            sample(
                "gitlab.com/org/proj",
                DependencySource::Registry,
                Class::Unresolved,
            ),
            sample(
                "gitlab.com/org/proj",
                unregistered_alternate(),
                Class::Unresolved,
            ),
        ],
    }
}

fn class_of(endpoint: RegistryEndpoint) -> Class {
    match endpoint {
        RegistryEndpoint::Resolved(_) => Class::Resolved,
        RegistryEndpoint::Unresolved => Class::Unresolved,
    }
}

#[test]
fn every_ecosystem_reports_the_endpoint_class_its_sample_declares() {
    let state = ServerState::new();
    for &id in EcosystemId::ALL {
        let ecosystem = state
            .ecosystem_registry
            .get(id)
            .unwrap_or_else(|| panic!("{id} is not registered"));
        let registry = ecosystem.registry();
        for sample in samples(id) {
            let endpoint = registry.endpoint_for(&PackageName::new(sample.name), &sample.source);
            assert_eq!(
                class_of(endpoint),
                sample.class,
                "{id}: {} via {:?}",
                sample.name,
                sample.source
            );
        }
    }
}

#[test]
fn gradle_routes_like_maven() {
    let state = ServerState::new();
    let registry_of = |id| {
        state
            .ecosystem_registry
            .get(id)
            .expect("registered")
            .registry()
    };
    let (maven, gradle) = (
        registry_of(EcosystemId::Maven),
        registry_of(EcosystemId::Gradle),
    );
    for sample in samples(EcosystemId::Maven) {
        let name = PackageName::new(sample.name);
        assert_eq!(
            maven.endpoint_for(&name, &sample.source),
            gradle.endpoint_for(&name, &sample.source),
            "{}",
            sample.name
        );
    }
}

#[test]
fn samples_on_different_routes_get_different_endpoints() {
    let state = ServerState::new();
    for &id in EcosystemId::ALL {
        let ecosystem = state.ecosystem_registry.get(id).expect("registered");
        let registry = ecosystem.registry();
        let endpoints: Vec<(&str, RegistryEndpoint)> = samples(id)
            .into_iter()
            .filter(|sample| sample.class == Class::Resolved)
            .map(|sample| {
                let endpoint =
                    registry.endpoint_for(&PackageName::new(sample.name), &sample.source);
                (sample.name, endpoint)
            })
            .collect();
        for (index, (first_name, first)) in endpoints.iter().enumerate() {
            for (second_name, second) in &endpoints[index + 1..] {
                assert_ne!(
                    first, second,
                    "{id}: {first_name} and {second_name} travel different routes"
                );
            }
        }
    }
}
