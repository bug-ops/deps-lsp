//! Integration tests for `[source.crates-io] replace-with` resolution
//! (spec `023-cargo-custom-registries` FR-005/FR-006/FR-007, plan-1b §1.3/§1.4), exercised
//! through the crate's public parsing/formatter API rather than `config.rs`'s own
//! module-internal unit tests (which cover the chain-resolution algorithm itself).
//!
//! This file specifically proves the F1/F1b/F2 fix set plan-1b §0 identified in the code
//! #440 merged — every plain (`Registry`-sourced) dependency in a mirrored workspace was
//! silently losing OSV scanning (F1), its OSV cache key was colliding across differently
//! pinned occurrences (F1b), and its crates.io hover link was being suppressed (F2) — by
//! asserting the fixed behavior end to end against a mocked mirror.

use deps_cargo::config::ConfigFileCache;
use deps_cargo::parser::CargoParseContext;
use deps_cargo::{CargoFormatter, DependencySource};
use deps_core::lsp_helpers::{PackageRendering, SourcePolicy};
use deps_core::net_policy::{RegistryAccessPolicy, WorkspaceRegistryAccess};
use std::sync::Arc;
use tower_lsp_server::ls_types::Uri;

fn test_policy() -> RegistryAccessPolicy {
    RegistryAccessPolicy::new(WorkspaceRegistryAccess::All)
}

fn write_manifest(dir: &std::path::Path, content: &str) -> Uri {
    let path = dir.join("Cargo.toml");
    std::fs::write(&path, content).unwrap();
    Uri::from_file_path(&path).unwrap()
}

/// (a) plain dependencies carry `mirrors_crates_io: true`, and (b) the mirror index is the
/// one registered — the exact index a `CargoRegistry` would dispatch fetches to, proving the
/// parser's rewrite and the router's registration would agree on the same index.
#[tokio::test]
async fn test_mirrored_workspace_plain_deps_carry_mirrors_crates_io_and_resolve_mirror_index() {
    let server = mockito::Server::new_async().await;
    let mirror_url = server.url();

    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(root.path().join(".cargo")).unwrap();
    std::fs::write(
        root.path().join(".cargo/config.toml"),
        format!(
            "[source.crates-io]\nreplace-with = \"my-mirror\"\n\
             [source.my-mirror]\nregistry = \"sparse+{mirror_url}\"\n"
        ),
    )
    .unwrap();

    let manifest_content = "[dependencies]\nserde = \"1.0\"\ntokio = \"1.0\"\n";
    let uri = write_manifest(root.path(), manifest_content);

    let ctx = CargoParseContext {
        policy: Arc::new(test_policy()),
        config_cache: Arc::new(ConfigFileCache::new()),
    };
    let result =
        deps_cargo::parser::parse_cargo_toml_with_context(manifest_content, &uri, &ctx).unwrap();

    assert_eq!(result.dependencies.len(), 2);
    for dep in &result.dependencies {
        match &dep.source {
            DependencySource::AlternateRegistry {
                index,
                mirrors_crates_io,
            } => {
                assert!(
                    *mirrors_crates_io,
                    "{} must be marked as a crates.io mirror",
                    dep.name
                );
                assert_eq!(
                    index.trim_end_matches('/'),
                    mirror_url.trim_end_matches('/')
                );
            }
            other => panic!(
                "expected {} to be a resolved AlternateRegistry mirror, got {other:?}",
                dep.name
            ),
        }
    }

    // Exactly one resolved (index, auth) pair — every plain dependency shares the same
    // mirror registration, not one per dependency.
    assert_eq!(result.resolved_registries.len(), 1);
    assert!(result.resolved_registries[0].1.is_none());
}

/// (b), the fetch half: registering the resolved mirror into a `CargoRegistry` and fetching
/// through the mirrored `AlternateRegistry` source hits the mirror, never crates.io's real
/// index — `CargoRegistry::get_versions_for_source`'s `AlternateRegistry` arm is exercised,
/// not the crates.io default arm.
#[tokio::test]
async fn test_mirrored_dependency_fetch_hits_mirror_not_crates_io() {
    let mut server = mockito::Server::new_async().await;
    let mock = server
        .mock("GET", "/se/rd/serde")
        .with_status(200)
        .with_body(r#"{"name":"serde","vers":"1.2.3","yanked":false,"features":{},"deps":[]}"#)
        .create_async()
        .await;

    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(root.path().join(".cargo")).unwrap();
    std::fs::write(
        root.path().join(".cargo/config.toml"),
        format!(
            "[source.crates-io]\nreplace-with = \"my-mirror\"\n\
             [source.my-mirror]\nregistry = \"sparse+{}\"\n",
            server.url()
        ),
    )
    .unwrap();

    let manifest_content = "[dependencies]\nserde = \"1.0\"\n";
    let uri = write_manifest(root.path(), manifest_content);

    let ctx = CargoParseContext {
        policy: Arc::new(test_policy()),
        config_cache: Arc::new(ConfigFileCache::new()),
    };
    let result =
        deps_cargo::parser::parse_cargo_toml_with_context(manifest_content, &uri, &ctx).unwrap();

    let cache = Arc::new(deps_core::HttpCache::new());
    let registry = deps_cargo::CargoRegistry::new(cache);
    for (index, auth) in result.resolved_registries {
        registry.register_alternate(index, auth);
    }

    let dep = &result.dependencies[0];
    let versions = deps_core::Registry::get_versions_from(
        &registry,
        &dep.name,
        &dep.source,
        deps_core::freshness::FreshnessSettings::default(),
    )
    .await
    .expect("mirror fetch must succeed");

    assert_eq!(versions.len(), 1);
    mock.assert_async().await;
}

/// (c) the crates.io hover link is **not** suppressed for a verified mirror (spec FR-014/F2)
/// — `CargoFormatter::suppress_package_url` must return `false` for a `mirrors_crates_io:
/// true` source, unlike a genuinely different private registry.
#[test]
fn test_mirror_hover_link_not_suppressed() {
    let formatter = CargoFormatter;
    let mirror_source = DependencySource::AlternateRegistry {
        index: "https://mirror.corp.example".into(),
        mirrors_crates_io: true,
    };
    let private_source = DependencySource::AlternateRegistry {
        index: "https://index.mycorp.dev".into(),
        mirrors_crates_io: false,
    };

    assert!(
        !formatter.suppress_package_url(&mirror_source),
        "a verified crates.io mirror's hover link is still valid crates.io content"
    );
    assert!(
        formatter.suppress_package_url(&private_source),
        "a genuinely private registry's link must stay suppressed"
    );
}

/// (d) OSV scan targets still include the mirrored deps (F1) — `build_scan_targets`/
/// `collect_in_use_versions` (`deps-lsp`) gate inclusion on
/// `SourcePolicy::source_is_public_registry_content`, so this asserts the exact
/// predicate they call returns `true` for a mirror and `false` for a private registry — the
/// F1 regression gate, since `dep.source() == DependencySource::Registry` (the pre-fix gate)
/// would incorrectly return `false` for every mirrored dependency.
#[test]
fn test_mirror_counts_as_public_registry_content_for_osv_gating() {
    let formatter = CargoFormatter;
    let mirror_source = DependencySource::AlternateRegistry {
        index: "https://mirror.corp.example".into(),
        mirrors_crates_io: true,
    };
    let private_source = DependencySource::AlternateRegistry {
        index: "https://index.mycorp.dev".into(),
        mirrors_crates_io: false,
    };

    assert!(
        formatter.source_is_public_registry_content(&mirror_source),
        "a verified crates.io mirror must count as public-registry content for OSV scanning"
    );
    assert!(!formatter.source_is_public_registry_content(&private_source));
    assert!(formatter.source_is_public_registry_content(&DependencySource::Registry));
}

/// (e) two occurrences of one crate pinned to different versions produce **distinct**
/// `vulnerability_keys` signatures (F1b) — the pre-fix gate collapsed every mirrored
/// occurrence onto the shared `"n"` (non-registry) signature regardless of its pinned
/// version, which this test would catch by asserting the two keys collide when using the
/// stale `DependencySource::Registry`-equality gate instead of `source_is_public_registry_content`.
#[test]
fn test_mirror_distinct_pinned_versions_produce_distinct_vulnerability_keys() {
    use deps_core::{
        ConcreteVersion, Dependency, EcosystemId, PackageName, ParseResult, VersionReq,
    };
    use std::any::Any;
    use std::collections::HashMap;
    use tower_lsp_server::ls_types::{Position, Range};

    struct MirrorDep {
        version_req: VersionReq,
        name_range: Range,
    }
    impl Dependency for MirrorDep {
        fn name(&self) -> &PackageName {
            static NAME: std::sync::LazyLock<PackageName> =
                std::sync::LazyLock::new(|| PackageName::new("time"));
            &NAME
        }
        fn name_range(&self) -> Range {
            self.name_range
        }
        fn version_requirement(&self) -> Option<&VersionReq> {
            Some(&self.version_req)
        }
        fn version_range(&self) -> Option<Range> {
            None
        }
        fn source(&self) -> DependencySource {
            DependencySource::AlternateRegistry {
                index: "https://mirror.corp.example".into(),
                mirrors_crates_io: true,
            }
        }
        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    struct MirrorParseResult {
        deps: Vec<MirrorDep>,
        uri: Uri,
    }
    impl ParseResult for MirrorParseResult {
        fn dependencies(&self) -> Vec<&dyn Dependency> {
            self.deps.iter().map(|d| d as &dyn Dependency).collect()
        }
        fn workspace_root(&self) -> Option<&std::path::Path> {
            None
        }
        fn uri(&self) -> &Uri {
            &self.uri
        }
        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    let parse_result = MirrorParseResult {
        deps: vec![
            MirrorDep {
                version_req: VersionReq::new("=0.1.43"),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 4)),
            },
            MirrorDep {
                version_req: VersionReq::new("=0.1.44"),
                name_range: Range::new(Position::new(3, 0), Position::new(3, 4)),
            },
        ],
        uri: deps_core::test_util::test_uri("/test/Cargo.toml"),
    };

    // No lockfile-resolved versions; `in_use_version` falls back to the manifest
    // requirement, which is already concrete (`=X.Y.Z`) for both occurrences.
    let resolved: HashMap<PackageName, ConcreteVersion> = HashMap::new();
    let formatter = CargoFormatter;

    let keys = deps_core::osv::vulnerability_keys(
        &parse_result,
        &resolved,
        &formatter,
        EcosystemId::Cargo,
    );
    let deps = parse_result.dependencies();
    let key0 = keys.get(&deps[0].name_range()).unwrap();
    let key1 = keys.get(&deps[1].name_range()).unwrap();
    assert_ne!(
        key0, key1,
        "two mirrored occurrences pinned to different versions must get distinct OSV keys"
    );
}
