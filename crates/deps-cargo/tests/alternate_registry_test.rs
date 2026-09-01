//! mockito-based integration tests for alternate/private registry routing
//! (spec `023-cargo-custom-registries` FR-001/SC-004/NFR-006).
//!
//! The design review's Risks section (plan.md) notes the routing enumeration was
//! incomplete twice during design — first missing several `Registry` network methods
//! entirely, then missing the `get_latest_matching`/`get_latest_matching_with_context`
//! fallback paths hover and the background fetch use when the list-based "latest" pick
//! fails. This file exists specifically so that class of gap cannot recur silently: it
//! exercises `get_versions_from` AND `get_latest_matching_from` against a mocked
//! alternate index, not only the happy-path version list.
//!
//! Note on the hover-fallback/background-fetch-mirror *conditional branch* specifically:
//! for Cargo, `CargoRegistry::select_latest_matching` resolves a wildcard requirement via
//! `deps_core::select_latest_for_existence`, whose rung-3 fallback unconditionally returns
//! an index for any *non-empty* version list — so the list-based pick can never fail on a
//! non-empty list the way Go's `/@v/list` (which omits pseudo-versions) can. It returns
//! `None` only when the list is empty. `hover.rs`'s fallback guard additionally requires a
//! non-empty list, so it is genuinely dead for Cargo — but `lifecycle.rs`'s
//! background-fetch-mirror fallback has no such precondition (it fires on any `None` from
//! the list-based pick, empty list included), so it **is** reachable for Cargo on an empty
//! alternate-index response. [`test_get_latest_matching_from_on_empty_list_routes_to_alternate_index`]
//! covers exactly that case.

use deps_cargo::config::{ConfigFileCache, IndexTrust};
use deps_cargo::{CargoConfig, CargoRegistry, DependencySource};
use deps_core::freshness::FreshnessSettings;
use deps_core::net_policy::RegistryAccessPolicy;
use deps_core::{HttpCache, PackageName, Registry, VersionReq};
use std::sync::Arc;

const SPARSE_ENTRY: &str =
    r#"{"name":"internal-crate","vers":"1.2.3","yanked":false,"features":{},"deps":[]}"#;

fn test_policy() -> RegistryAccessPolicy {
    RegistryAccessPolicy::new(deps_core::net_policy::WorkspaceRegistryAccess::All)
}

fn test_index(raw: &str) -> deps_cargo::config::RegistryIndex {
    deps_cargo::config::RegistryIndex::new(raw, IndexTrust::Trusted, &test_policy()).unwrap()
}

/// FR-001: `Registry::get_versions`/`get_versions_with`'s source-aware counterpart,
/// `get_versions_from`, routes an `AlternateRegistry` source to the alternate index — the
/// happy path every design round already covered, kept here as the baseline the other
/// tests in this file build on.
#[tokio::test]
async fn test_get_versions_from_routes_to_alternate_index() {
    let mut server = mockito::Server::new_async().await;
    let mock = server
        .mock("GET", "/in/te/internal-crate")
        .with_status(200)
        .with_body(SPARSE_ENTRY)
        .create_async()
        .await;

    let cache = Arc::new(HttpCache::new());
    let registry = CargoRegistry::new(cache);
    let index = test_index(&server.url());
    registry.register_alternate(index.clone(), None);

    let source = DependencySource::AlternateRegistry {
        index: index.as_str().to_string(),
        mirrors_crates_io: false,
    };
    let name = PackageName::new("internal-crate");
    let versions = registry
        .get_versions_from(&name, &source, FreshnessSettings::default())
        .await
        .expect("alternate registry fetch must succeed");

    assert_eq!(versions.len(), 1);
    assert_eq!(versions[0].version_string().as_str(), "1.2.3");
    mock.assert_async().await;
}

/// SC-004/NFR-006: `get_latest_matching_from` — the method both hover's fallback
/// (`hover.rs`'s `list_fallback_latest`) and `lifecycle.rs`'s background-fetch-mirror
/// fallback call — also routes an `AlternateRegistry` source to the alternate index, not
/// silently falling through to crates.io. This is the specific method the design review
/// found missing from the routing enumeration twice; asserted independently from
/// `get_versions_from` above so a regression narrowing routing back to only the
/// happy-path method is caught here.
#[tokio::test]
async fn test_get_latest_matching_from_routes_to_alternate_index() {
    let mut server = mockito::Server::new_async().await;
    let mock = server
        .mock("GET", "/in/te/internal-crate")
        .with_status(200)
        .with_body(SPARSE_ENTRY)
        .create_async()
        .await;

    let cache = Arc::new(HttpCache::new());
    let registry = CargoRegistry::new(cache);
    let index = test_index(&server.url());
    registry.register_alternate(index.clone(), None);

    let source = DependencySource::AlternateRegistry {
        index: index.as_str().to_string(),
        mirrors_crates_io: false,
    };
    let name = PackageName::new("internal-crate");
    let req = VersionReq::new("^1.0");
    let latest = registry
        .get_latest_matching_from(&name, &source, &req, None)
        .await
        .expect("alternate registry fetch must succeed");

    assert_eq!(
        latest
            .expect("a matching version must be found")
            .version_string()
            .as_str(),
        "1.2.3"
    );
    mock.assert_async().await;
}

/// SC-004/NFR-006 (review finding #5): `lifecycle.rs`'s background-fetch-mirror fallback
/// fires on *any* `None` from the list-based pick, empty list included — unlike hover's
/// fallback, which additionally requires a non-empty list and is therefore dead for
/// Cargo. An empty sparse-index response (a real, valid shape: a 200 with zero
/// newline-delimited entries) must still route through `get_latest_matching_from` to the
/// alternate index and degrade to `Ok(None)`, never an error and never crates.io.
#[tokio::test]
async fn test_get_latest_matching_from_on_empty_list_routes_to_alternate_index() {
    let mut server = mockito::Server::new_async().await;
    let mock = server
        .mock("GET", "/in/te/internal-crate")
        .with_status(200)
        .with_body("")
        .create_async()
        .await;

    let cache = Arc::new(HttpCache::new());
    let registry = CargoRegistry::new(cache);
    let index = test_index(&server.url());
    registry.register_alternate(index.clone(), None);

    let source = DependencySource::AlternateRegistry {
        index: index.as_str().to_string(),
        mirrors_crates_io: false,
    };
    let name = PackageName::new("internal-crate");
    let req = VersionReq::new("*");
    let latest = registry
        .get_latest_matching_from(&name, &source, &req, None)
        .await
        .expect("an empty alternate-index list must not be an error");

    assert!(
        latest.is_none(),
        "an empty version list has no latest to report"
    );
    mock.assert_async().await;
}

/// FR-008/FR-009: an authenticated request against an alternate index attaches the
/// `Authorization` header — end-to-end through `CargoRegistry`, not just
/// `SparseIndexClient` directly (that path is already covered in `sparse.rs`'s own unit
/// tests; this proves the router wires the credential through unchanged).
#[tokio::test]
async fn test_authenticated_alternate_registry_sends_authorization_header() {
    let mut server = mockito::Server::new_async().await;
    let mock = server
        .mock("GET", "/in/te/internal-crate")
        .match_header("authorization", "Bearer secret-token")
        .with_status(200)
        .with_body(SPARSE_ENTRY)
        .create_async()
        .await;

    let cache = Arc::new(HttpCache::new());
    let registry = CargoRegistry::new(cache);
    let index = test_index(&server.url());
    // No public constructor for `AuthToken` outside `deps_cargo::config` (by design —
    // see that module's security-model docs), so this test resolves a real
    // `$CARGO_HOME/config.toml`-shaped fixture through the public `resolve` API instead
    // of hand-constructing a token.
    let cargo_home = tempfile::tempdir().unwrap();
    std::fs::write(
        cargo_home.path().join("config.toml"),
        format!(
            "[registries.my-corp]\nindex = \"{}\"\ntoken = \"secret-token\"\n",
            server.url()
        ),
    )
    .unwrap();
    let aliases: std::collections::HashSet<String> =
        std::iter::once("my-corp".to_string()).collect();
    let config_cache = ConfigFileCache::new();
    let policy = test_policy();
    let (config, _): (CargoConfig, _) = deps_cargo::config::resolve(
        &aliases,
        &[],
        Some(&cargo_home.path().join("config.toml")),
        &config_cache,
        &policy,
    );
    let entry = config
        .get("my-corp")
        .expect("cargo-home entry must resolve");
    registry.register_alternate(index.clone(), entry.auth.clone());

    let source = DependencySource::AlternateRegistry {
        index: index.as_str().to_string(),
        mirrors_crates_io: false,
    };
    let name = PackageName::new("internal-crate");
    let versions = registry
        .get_versions_from(&name, &source, FreshnessSettings::default())
        .await
        .expect("authenticated alternate registry fetch must succeed");

    assert_eq!(versions.len(), 1);
    mock.assert_async().await;
}

/// The full pipeline, end to end: a real `.cargo/config.toml` + `Cargo.toml` fixture on
/// disk, parsed via the public `parse_cargo_toml`, registered into a `CargoRegistry`
/// exactly the way `CargoEcosystem::parse_manifest` does, then fetched — proving the
/// parser's alias resolution and the router's registration agree on the same index.
#[tokio::test]
async fn test_end_to_end_parse_register_and_fetch() {
    let mut server = mockito::Server::new_async().await;
    let mock = server
        .mock("GET", "/in/te/internal-crate")
        .with_status(200)
        .with_body(SPARSE_ENTRY)
        .create_async()
        .await;

    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(root.path().join(".cargo")).unwrap();
    std::fs::write(
        root.path().join(".cargo/config.toml"),
        format!("[registries.my-corp]\nindex = \"{}\"\n", server.url()),
    )
    .unwrap();

    let manifest_path = root.path().join("Cargo.toml");
    let manifest_content =
        "[dependencies]\ninternal-crate = { version = \"1.0\", registry = \"my-corp\" }\n";
    std::fs::write(&manifest_path, manifest_content).unwrap();
    let uri = tower_lsp_server::ls_types::Uri::from_file_path(&manifest_path).unwrap();

    // `All` policy: this test exercises the parse -> register -> fetch pipeline, not
    // #443's policy gate (covered separately) — a mockito loopback URL is otherwise
    // blocked under the default `PublicOnly` policy.
    let ctx = deps_cargo::parser::CargoParseContext {
        policy: Arc::new(test_policy()),
        config_cache: Arc::new(ConfigFileCache::new()),
    };
    let parse_result =
        deps_cargo::parser::parse_cargo_toml_with_context(manifest_content, &uri, &ctx).unwrap();

    let cache = Arc::new(HttpCache::new());
    let registry = CargoRegistry::new(cache);
    for (index, auth) in parse_result.resolved_registries {
        registry.register_alternate(index, auth);
    }

    let dep = &parse_result.dependencies[0];
    let DependencySource::AlternateRegistry {
        index,
        mirrors_crates_io,
    } = &dep.source
    else {
        panic!("expected AlternateRegistry, got {:?}", dep.source);
    };
    let source = DependencySource::AlternateRegistry {
        index: index.clone(),
        mirrors_crates_io: *mirrors_crates_io,
    };
    let versions = registry
        .get_versions_from(&dep.name, &source, FreshnessSettings::default())
        .await
        .expect("end-to-end alternate registry fetch must succeed");

    assert_eq!(versions.len(), 1);
    assert_eq!(versions[0].version_string().as_str(), "1.2.3");
    mock.assert_async().await;
}

/// An unregistered alternate index (never resolved, or dropped for capacity) must
/// degrade to "no version data" — never fall back to crates.io by name (the exact leak
/// class FR-001 closes).
#[tokio::test]
async fn test_unregistered_alternate_index_never_falls_back_to_crates_io() {
    let cache = Arc::new(HttpCache::new());
    let registry = CargoRegistry::new(cache);
    let source = DependencySource::AlternateRegistry {
        index: "https://index.never-registered.example".to_string(),
        mirrors_crates_io: false,
    };
    let name = PackageName::new("internal-crate");

    let result = registry
        .get_versions_from(&name, &source, FreshnessSettings::default())
        .await;
    assert!(
        result.is_err(),
        "an unregistered alternate index must error, not silently query crates.io"
    );
}
