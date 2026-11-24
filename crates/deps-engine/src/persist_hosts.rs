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
    feature = "github-actions",
    feature = "gitlab-ci",
    feature = "pre-commit",
    feature = "deno"
))]
//! Pins the disk-cache host allow-list against what every ecosystem fetches by default
//! (spec 051, #2140).
//!
//! `deps_core::cache::persistable_hosts()` is the closed `PersistableHost` list. Each ecosystem
//! crate exposes its default fetch bases as `DEFAULT_REGISTRY_BASES`. A new default registry
//! host (or a typo in the allow-list) must fail here instead of silently never being cached.

use std::collections::BTreeSet;

use deps_core::EcosystemId;
use deps_core::cache::persistable_hosts;
use url::{Host, Url};

/// Default fetch hosts that are deliberately not persistable, each with the reason.
const NOT_PERSISTABLE: [(&str, &str); 2] = [
    (
        "search.maven.org",
        "search-only host: its queries use parameters outside PersistKey's closed query list",
    ),
    (
        "packagist.org",
        "search-only host: its queries use parameters outside PersistKey's closed query list",
    ),
];

/// The ecosystem's default fetch base URLs. The match is exhaustive on purpose: a new
/// `EcosystemId` variant does not compile until its bases are declared here.
fn default_bases(id: EcosystemId) -> Vec<&'static str> {
    match id {
        EcosystemId::Cargo => deps_cargo::DEFAULT_REGISTRY_BASES.to_vec(),
        EcosystemId::Npm => deps_npm::DEFAULT_REGISTRY_BASES.to_vec(),
        EcosystemId::Pypi => deps_pypi::DEFAULT_REGISTRY_BASES.to_vec(),
        EcosystemId::Go => deps_go::DEFAULT_REGISTRY_BASES.to_vec(),
        EcosystemId::Bundler => deps_bundler::DEFAULT_REGISTRY_BASES.to_vec(),
        EcosystemId::Dart => deps_dart::DEFAULT_REGISTRY_BASES.to_vec(),
        EcosystemId::Maven | EcosystemId::Gradle => deps_maven::DEFAULT_REGISTRY_BASES.to_vec(),
        EcosystemId::Composer => deps_composer::DEFAULT_REGISTRY_BASES.to_vec(),
        EcosystemId::NuGet => deps_nuget::DEFAULT_REGISTRY_BASES.to_vec(),
        EcosystemId::Deno => deps_deno::DEFAULT_REGISTRY_BASES.to_vec(),
        EcosystemId::Swift | EcosystemId::GithubActions | EcosystemId::PreCommit => {
            vec![deps_core::github::GITHUB_API]
        }
        EcosystemId::GitlabCi => vec![deps_gitlab_ci::host::GITLAB_COM_ORIGIN],
    }
}

fn host_of(base: &str) -> String {
    let url = Url::parse(base).unwrap_or_else(|e| panic!("{base} is not a URL: {e}"));
    match url.host() {
        Some(Host::Domain(domain)) => domain.to_owned(),
        other => panic!("{base} must have a domain host, got {other:?}"),
    }
}

fn all_bases() -> Vec<(EcosystemId, &'static str)> {
    EcosystemId::ALL
        .iter()
        .flat_map(|&id| default_bases(id).into_iter().map(move |base| (id, base)))
        .collect()
}

fn base_hosts() -> BTreeSet<String> {
    all_bases()
        .into_iter()
        .map(|(_, base)| host_of(base))
        .collect()
}

#[test]
fn default_registry_bases_are_plain_https_urls_with_a_domain_host() {
    for (id, base) in all_bases() {
        let url = Url::parse(base).unwrap_or_else(|e| panic!("{id}: {base}: {e}"));
        assert_eq!(url.scheme(), "https", "{id}: {base}");
        assert_eq!(url.port(), None, "{id}: {base}");
        assert!(
            url.username().is_empty() && url.password().is_none(),
            "{id}: {base}"
        );
        host_of(base);
    }
}

#[test]
fn every_ecosystem_declares_at_least_one_default_base() {
    for &id in EcosystemId::ALL {
        assert!(
            !default_bases(id).is_empty(),
            "{id} declares no default base"
        );
    }
}

#[test]
fn every_default_base_host_is_persistable_or_explicitly_excluded() {
    let persistable: BTreeSet<&str> = persistable_hosts().collect();
    let excluded: BTreeSet<&str> = NOT_PERSISTABLE.iter().map(|(host, _)| *host).collect();
    for (id, base) in all_bases() {
        let host = host_of(base);
        assert!(
            persistable.contains(host.as_str()) || excluded.contains(host.as_str()),
            "{id}: {base} targets {host}, neither persistable nor on the exclusion list"
        );
    }
}

#[test]
fn every_persistable_host_is_the_host_of_some_default_base() {
    let hosts = base_hosts();
    for host in persistable_hosts() {
        assert!(
            hosts.contains(host),
            "{host} is persistable but no ecosystem fetches from it by default"
        );
    }
}

#[test]
fn every_excluded_host_is_refused_and_still_fetched() {
    let persistable: BTreeSet<&str> = persistable_hosts().collect();
    let hosts = base_hosts();
    for (host, reason) in NOT_PERSISTABLE {
        assert!(
            !persistable.contains(host),
            "{host} ({reason}) is persistable"
        );
        assert!(
            hosts.contains(host),
            "{host} is excluded but no base uses it: stale entry"
        );
    }
}
