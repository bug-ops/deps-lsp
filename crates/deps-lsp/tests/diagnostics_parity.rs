//! FR-005 / SC-001 parity (spec 062 T025, #1803): the diagnostics `deps-cli check` reports and
//! the diagnostics `deps-lsp`'s pull handler publishes for the same manifests are the same set.
//!
//! Both sides run against the same fixture files and the same policy: a real `ServerState` is
//! loaded through `ensure_document_loaded` and queried with `handle_diagnostics`, and the CLI side
//! runs `walk` plus `check_manifest`. Each diagnostic is compared by range, severity, code and
//! message, so an input one adapter assembles differently (the `fetch_result.licenses` drop of
//! spec 062 review C2) shows up here.
//!
//! Offline, a Cargo or npm manifest yields only the document-level notice, so those cases
//! compare that notice and the absence of any other diagnostic; the GitHub Actions case also
//! compares a registry-free, dependency-anchored hint. The Cargo registry-derived case points a
//! project `.cargo/config.toml` alias at one mock sparse index and admits loopback through the
//! injected environment, so both adapters fetch from it.

#![cfg(any(feature = "cargo", feature = "npm", feature = "github-actions"))]
#![allow(clippy::expect_used)]

use deps_cli::report::{CheckContext, CheckFinding, check_manifest};
use deps_cli::walk::{self, DiscoveredManifest};
use deps_core::net_policy::{MapEnv, RegistryEnvironment};
use deps_core::osv::OsvClient;
use deps_core::policy_config::PolicyConfig;
use deps_core::{EcosystemRegistry, HttpCache, NetworkMode};
use deps_engine::setup::{EcosystemRuntime, register_ecosystems};
use deps_lsp::Backend;
use deps_lsp::config::DepsConfig;
use deps_lsp::document::{ServerState, ensure_document_loaded};
use deps_lsp::handlers::diagnostics::handle_diagnostics;
use deps_lsp::lsp_types_interop::{to_lsp_diagnostic, to_lsp_uri};
use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tower_lsp_server::Client;
use tower_lsp_server::LspService;
use tower_lsp_server::ls_types::NumberOrString;

/// A comparable projection of one diagnostic, identical for both adapters.
type Shape = (String, String, String, String);

fn shape(
    range: impl std::fmt::Debug,
    severity: impl std::fmt::Debug,
    code: Option<&str>,
    message: &str,
) -> Shape {
    (
        format!("{range:?}"),
        format!("{severity:?}"),
        code.unwrap_or_default().to_owned(),
        message.to_owned(),
    )
}

fn cli_shapes(findings: &[CheckFinding]) -> BTreeSet<Shape> {
    findings
        .iter()
        .map(|finding| {
            let lsp = to_lsp_diagnostic(
                deps_core::diagnostic::Diagnostic::new(
                    finding.kind.clone(),
                    finding.range,
                    finding.message.clone(),
                )
                .with_severity(finding.severity),
            );
            shape(lsp.range, lsp.severity, finding.code(), &finding.message)
        })
        .collect()
}

/// How the two adapters reach the network: offline, or online against a mock registry that the
/// environment's allowlist admits.
struct Setup {
    policy: PolicyConfig,
    environment: MapEnv,
}

impl Setup {
    fn offline() -> Self {
        let mut policy = PolicyConfig::default();
        policy.network.offline = true;
        Self {
            policy,
            environment: MapEnv::new(),
        }
    }

    #[cfg(feature = "cargo")]
    /// Online, vulnerability lookups off, workspace registries admitted for loopback only.
    fn online_loopback() -> Self {
        let mut policy = PolicyConfig::default();
        policy.diagnostics.vulnerabilities_enabled = false;
        policy.registries = deps_core::policy_config::RegistriesConfig::new()
            .with_workspace_registries(deps_core::policy_config::WorkspaceRegistriesSetting::All);
        Self {
            policy,
            environment: MapEnv::new().with_var(
                deps_core::net_policy::PRIVATE_REGISTRY_HOSTS_ENV,
                "127.0.0.1/32",
            ),
        }
    }

    fn network(&self) -> NetworkMode {
        NetworkMode::from_offline_flag(self.policy.network.offline)
    }
}

fn cli_context(setup: &Setup) -> (EcosystemRegistry, CheckContext) {
    let policy = setup.policy.clone();
    let runtime =
        EcosystemRuntime::from_policy(&policy, &RegistryEnvironment::read(&setup.environment));
    let cache = Arc::new(HttpCache::with_policy(Arc::clone(&runtime.policy)));
    cache.set_offline(setup.network());
    let registry = EcosystemRegistry::new();
    let _ = register_ecosystems(&registry, Arc::clone(&cache), &runtime);
    let ctx = CheckContext {
        cache: Arc::clone(&cache),
        osv: Arc::new(OsvClient::new(Arc::clone(&cache))),
        deps_dev: Arc::new(deps_core::DepsDevClient::new(Arc::clone(&cache))),
        lockfile_cache: Arc::new(deps_core::lockfile::LockFileCache::new()),
        policy,
    };
    (registry, ctx)
}

async fn cli_diagnostics(manifest: &DiscoveredManifest, ctx: &CheckContext) -> BTreeSet<Shape> {
    let content = std::fs::read_to_string(&manifest.path).expect("read fixture manifest");
    let result = check_manifest(
        &manifest.ecosystem,
        &manifest.uri_path,
        &manifest.display_path,
        &content,
        ctx,
    )
    .await
    .expect("check_manifest succeeds for a well-formed fixture");
    cli_shapes(&result.findings)
}

/// A real `Client` handle; the service is kept alive by the caller for the test's duration.
fn test_client() -> (LspService<Backend>, Client) {
    let slot = std::sync::Mutex::new(None);
    let (service, _socket) = LspService::new(|client| {
        *slot.lock().expect("client slot") = Some(client.clone());
        Backend::new(client)
    });
    let client = slot
        .into_inner()
        .expect("client slot")
        .expect("LspService::new hands the closure a client");
    (service, client)
}

async fn lsp_diagnostics(manifest: &DiscoveredManifest, setup: &Setup) -> BTreeSet<Shape> {
    let state = Arc::new(ServerState::from_env_source(&setup.environment));
    state.cache.set_offline(setup.network());
    state
        .cache
        .set_registry_policy(setup.policy.registries.workspace_registries.to_policy());
    let mut config = DepsConfig::default();
    config.policy = setup.policy.clone();
    let config = Arc::new(RwLock::new(config));
    let (_service, client) = test_client();

    let url = url::Url::from_file_path(&manifest.uri_path).expect("absolute fixture path");
    let uri = to_lsp_uri(&url);
    assert!(
        ensure_document_loaded(
            &uri,
            Arc::clone(&state),
            client.clone(),
            Arc::clone(&config)
        )
        .await,
        "{} must load",
        manifest.display_path.display()
    );
    tokio::time::timeout(Duration::from_secs(10), async {
        while !state
            .with_document(&uri, |doc| {
                matches!(
                    doc.loading_state(),
                    deps_core::LoadingState::Loaded | deps_core::LoadingState::Failed
                )
            })
            .unwrap_or(false)
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the document load settles");

    handle_diagnostics(state, &uri, client, config)
        .await
        .into_iter()
        .map(|d| {
            let code = d.code.as_ref().map(|code| match code {
                NumberOrString::String(s) => s.clone(),
                NumberOrString::Number(n) => n.to_string(),
            });
            shape(d.range, d.severity, code.as_deref(), &d.message)
        })
        .collect()
}

/// Writes `files` under a fresh temp dir and asserts, per discovered manifest, that both
/// adapters report the same diagnostics. Returns how many are anchored to a dependency rather
/// than the document-level offline notice, so a caller whose fixture can produce registry-free
/// diagnostics can prove the comparison was not vacuous.
async fn assert_parity(files: &[(&str, &str)]) -> usize {
    assert_parity_with(files, &Setup::offline()).await
}

async fn assert_parity_with(files: &[(&str, &str)], setup: &Setup) -> usize {
    let dir = tempfile::tempdir().expect("create temp dir");
    let root = dir.path().canonicalize().expect("canonical temp dir");
    for (name, content) in files {
        let path = root.join(name);
        std::fs::create_dir_all(path.parent().expect("fixture has a parent"))
            .expect("create fixture dir");
        std::fs::write(path, content).expect("write fixture");
    }

    let (registry, ctx) = cli_context(setup);
    let outcome = walk::walk(
        &[root],
        &registry,
        walk::GitignorePolicy::Ignore,
        walk::SymlinkPolicy::Skip,
    );
    assert!(!outcome.truncated);
    let manifests = outcome.manifests();
    assert!(!manifests.is_empty(), "fixture files must be discovered");

    let mut reported = 0;
    for manifest in manifests {
        let cli = cli_diagnostics(manifest, &ctx).await;
        let lsp = lsp_diagnostics(manifest, setup).await;
        assert_eq!(
            cli,
            lsp,
            "CLI and LSP diagnostics diverge for {}",
            manifest.display_path.display()
        );
        let document_level = format!("{:?}", tower_lsp_server::ls_types::Range::default());
        reported += cli
            .iter()
            .filter(|(range, ..)| *range != document_level)
            .count();
    }
    reported
}

#[cfg(feature = "cargo")]
#[tokio::test]
async fn cargo_manifest_with_lockfile_has_identical_diagnostics() {
    assert_parity(&[
        (
            "Cargo.toml",
            "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\n\n[dependencies]\n\
             serde = \"1.0\"\nunpinned = \"*\"\nlocal = { path = \"../local\" }\n\
             broken = \"not a version\"\n",
        ),
        (
            "Cargo.lock",
            "version = 3\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.100\"\n",
        ),
    ])
    .await;
}

#[cfg(feature = "npm")]
#[tokio::test]
async fn npm_manifest_has_identical_diagnostics() {
    assert_parity(&[(
        "package.json",
        "{\n  \"name\": \"fixture\",\n  \"version\": \"1.0.0\",\n  \"dependencies\": {\n    \
         \"left-pad\": \"^1.3.0\",\n    \"latest-dep\": \"latest\",\n    \
         \"git-dep\": \"github:owner/repo\"\n  }\n}\n",
    )])
    .await;
}

#[cfg(feature = "github-actions")]
#[tokio::test]
async fn github_actions_workflow_has_identical_diagnostics() {
    let anchored = assert_parity(&[(
        ".github/workflows/ci.yml",
        "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      \
         - uses: actions/checkout@v4\n      - uses: actions/cache@main\n",
    )])
    .await;
    assert!(
        anchored > 0,
        "the mutable-ref-pin hint needs no registry data"
    );
}

/// Registry-derived diagnostics (#1811): both adapters read the same project `.cargo/config.toml`
/// alias, which points at one mock sparse index. The alias is unique, so neither
/// `$CARGO_HOME` nor `CARGO_REGISTRIES_*` can define it.
#[cfg(feature = "cargo")]
#[tokio::test]
async fn cargo_registry_derived_diagnostics_are_identical() {
    let mut server = mockito::Server::new_async().await;
    let index = server
        .mock("GET", "/mo/ck/mockdep")
        .with_status(200)
        .with_body(
            "{\"name\":\"mockdep\",\"vers\":\"1.0.0\",\"deps\":[],\"cksum\":\"0\",\"features\":{},\"yanked\":false}\n\
             {\"name\":\"mockdep\",\"vers\":\"2.0.0\",\"deps\":[],\"cksum\":\"0\",\"features\":{},\"yanked\":false}\n",
        )
        .expect_at_least(2)
        .create_async()
        .await;
    let alias = format!(
        "deps-lsp-parity-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos()
    );
    let config = format!(
        "[registries.{alias}]\nindex = \"sparse+{}/\"\n",
        server.url()
    );
    let manifest = format!(
        "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\n\n[dependencies]\n\
         mockdep = {{ version = \"1.0\", registry = \"{alias}\" }}\n"
    );
    let anchored = assert_parity_with(
        &[
            (".cargo/config.toml", config.as_str()),
            ("Cargo.toml", manifest.as_str()),
        ],
        &Setup::online_loopback(),
    )
    .await;
    index.assert_async().await;
    assert!(
        anchored > 0,
        "the outdated diagnostic must come from the mock registry"
    );
}
