//! Test utilities for creating mock LSP clients and configs.

#[cfg(test)]
pub(crate) mod test_helpers {
    use crate::config::DepsConfig;
    use crate::server::Backend;
    use std::sync::Arc;
    use tokio::sync::RwLock;
    use tower_lsp_server::Client;

    /// Creates a test client and config for handler tests.
    ///
    /// Since handler tests pre-populate documents in state, the cold start
    /// logic is never triggered. These are just dummy values to satisfy
    /// the function signatures.
    pub(crate) fn create_test_client_and_config() -> (Client, Arc<RwLock<DepsConfig>>) {
        let (service, _socket) = tower_lsp_server::LspService::build(Backend::new).finish();
        let client = service.inner().client.clone();
        let config = Arc::new(RwLock::new(DepsConfig::default()));
        (client, config)
    }

    /// Seeds `ecosystem`'s shared `TagIndex` for `name` with one `tag -> sha` entry,
    /// downcasting through `Ecosystem::registry()`/`Registry::as_any()` — the tests that use it
    /// never drive a live registry fetch, so the index has to be seeded directly for a SHA-pin
    /// replacement to have anything to resolve.
    #[cfg(feature = "github-actions")]
    pub(crate) fn seed_gha_tag_index(
        ecosystem: &dyn deps_core::Ecosystem,
        name: &str,
        tag: &str,
        sha: &str,
    ) {
        let registry = ecosystem.registry();
        let gha_registry = registry
            .as_any()
            .downcast_ref::<deps_github_actions::GithubActionsRegistry>()
            .expect("github-actions ecosystem must back onto a GithubActionsRegistry");
        let commit_sha = deps_core::lsp_helpers::CommitSha::parse(sha)
            .expect("test fixture must pass a valid 40-hex SHA");
        let index = deps_core::lsp_helpers::TagIndex::from_tags([(tag, &commit_sha)]);
        gha_registry
            .tag_index()
            .insert(deps_core::PackageName::new(name), Arc::new(index));
    }

    /// The advisory id of [`advisory_state`]'s document.
    #[cfg(feature = "cargo")]
    pub(crate) const ADVISORY_ID: &str = "RUSTSEC-2020-0071";

    /// A server state holding one loaded Cargo document (`serde = "0.9.0"`, latest `1.0.5`) whose
    /// dependency carries an already-fetched advisory fixed by `1.0.5`.
    #[cfg(feature = "cargo")]
    pub(crate) async fn advisory_state() -> (
        Arc<crate::document::ServerState>,
        tower_lsp_server::ls_types::Uri,
    ) {
        use crate::document::{DocumentState, ServerState};
        use deps_core::osv::{
            Advisory, Capped, DependencyVulnerabilities, OsvVersion, ScanOutcome, UpgradeStatus,
            VulnSeverity, VulnerabilityMap,
        };

        let _guard = deps_core::fs_probe::snapshot_guard_async().await;
        let state = Arc::new(ServerState::new());
        let url = deps_core::test_util::test_uri("/test/Cargo.toml");
        let uri = crate::lsp_types_interop::to_lsp_uri(&url);
        let ecosystem = state
            .ecosystem_registry
            .get(deps_core::EcosystemId::Cargo)
            .unwrap();
        let content = "[dependencies]\nserde = \"0.9.0\"\n".to_string();
        let parse_result = ecosystem
            .parse_manifest(&content, &url)
            .await
            .expect("failed to parse manifest");
        let mut doc_state = DocumentState::new_from_parse_result(
            deps_core::EcosystemId::Cargo,
            content,
            parse_result,
        );
        let mut cached = std::collections::HashMap::new();
        cached.insert(
            deps_core::NormalizedName::for_test("serde"),
            deps_core::PackageVersions::new(
                "1.0.5".into(),
                Arc::from(vec!["1.0.5".into(), "0.9.0".into()]),
            ),
        );
        doc_state.update_cached_versions(cached);
        let mut vulnerabilities = VulnerabilityMap::new();
        vulnerabilities.insert(
            deps_core::test_util::vuln_key("serde"),
            ScanOutcome::Vulnerable(
                DependencyVulnerabilities::new(Capped::new(
                    vec![Arc::new(
                        Advisory::new(
                            ADVISORY_ID.to_string(),
                            "2023-01-01T00:00:00Z".to_string(),
                            VulnSeverity::High,
                        )
                        .expect("valid osv id")
                        .with_fixed_versions(vec![OsvVersion::new("1.0.5")]),
                    )],
                    1,
                ))
                .with_fix_target_status(UpgradeStatus::CandidateClean {
                    version: deps_core::ConcreteVersion::new("1.0.5"),
                }),
            ),
        );
        doc_state.signals.vulnerabilities = vulnerabilities;
        doc_state.set_loaded();
        state.update_document(uri.clone(), doc_state);
        (state, uri)
    }

    /// Sets `vulnerabilities_enabled` and `offline` on a test server's config.
    #[cfg(feature = "cargo")]
    pub(crate) async fn set_advisory_gates(
        config: &RwLock<DepsConfig>,
        vulnerabilities_enabled: bool,
        offline: bool,
    ) {
        let mut config = config.write().await;
        config.policy.diagnostics.vulnerabilities_enabled = vulnerabilities_enabled;
        config.policy.network.offline = offline;
    }

    /// Prefixes a Windows drive letter onto a Unix-shaped path literal so it is a valid
    /// absolute path on Windows too, mirroring `deps_core::test_util::test_uri`'s pattern —
    /// `ls_types::Uri::from_file_path`/`url::Url::from_file_path`/`Url::to_file_path` all
    /// require a drive letter for an absolute path on Windows, so a bare `/foo/bar` fixture
    /// (valid on Unix) fails there without this.
    pub(crate) fn platform_path(unix_path: &str) -> String {
        #[cfg(windows)]
        {
            format!("C:{unix_path}")
        }
        #[cfg(not(windows))]
        {
            unix_path.to_string()
        }
    }
}

/// A [`deps_core::ParsedManifest`] of `uri` paired with `ecosystem`, so the ecosystem's own
/// hooks serve it.
#[cfg(test)]
pub(crate) fn manifest_of<E: deps_core::TypedEcosystem>(
    ecosystem: &std::sync::Arc<E>,
    uri: &url::Url,
) -> Box<dyn deps_core::ParsedManifest> {
    use deps_core::Ecosystem;
    std::sync::Arc::clone(ecosystem)
        .parse_manifest_sync("", uri)
        .expect("a stub ecosystem parses synchronously")
}

/// Shared scaffolding for the `#319`/`#333` DashMap-Ref-across-await regression tests in
/// `handlers::{hover, completion, inlay_hints, diagnostics, code_lens}`: a no-op
/// [`Registry`]/[`EcosystemFormatter`]/[`ParseResult`] trio, plus a [`BlockingEcosystem`]
/// whose single selected `generate_*` method blocks on a [`tokio::sync::Barrier`] before
/// hanging forever — standing in for an override that performs real (never-returning)
/// I/O, the worst case for a shard `Ref` held across the call.
#[cfg(test)]
pub(crate) mod blocking_ecosystem {
    use deps_core::ecosystem::BoxFuture;
    use deps_core::ecosystem::private::Sealed;
    use deps_core::test_util::StubParseResult;
    use deps_core::{
        DiagnosticSeverities, EcosystemBase, EcosystemConfig, FreshnessSettings, Metadata,
        ParsedManifest, ParsedView, Registry, Version, VersionData, completion::Completions,
    };
    use std::sync::Arc;
    use tokio::sync::Barrier;
    use tower_lsp_server::ls_types::{CodeLens, InlayHint, Position};

    pub(crate) struct NoopRegistry;
    impl Registry for NoopRegistry {
        fn get_versions<'a>(
            &'a self,
            _name: &'a deps_core::PackageName,
        ) -> BoxFuture<'a, deps_core::Result<Vec<Box<dyn Version>>>> {
            Box::pin(async move { Ok(vec![]) })
        }
        fn get_latest_matching<'a>(
            &'a self,
            _name: &'a deps_core::PackageName,
            _req: &'a deps_core::VersionReq,
            _selection_context: &'a deps_core::SelectionContext,
        ) -> BoxFuture<'a, deps_core::Result<Option<Box<dyn Version>>>> {
            Box::pin(async move { Ok(None) })
        }
        fn search_raw<'a>(
            &'a self,
            _query: &'a str,
            _limit: usize,
        ) -> BoxFuture<'a, deps_core::Result<Vec<Box<dyn Metadata>>>> {
            Box::pin(async move { Ok(vec![]) })
        }
    }

    /// Which single `Ecosystem::generate_*` method [`BlockingEcosystem`] blocks on its
    /// `started` barrier. Every other `generate_*` method returns an empty result
    /// immediately, so a test selects exactly one hazard to exercise.
    pub(crate) enum BlockingHook {
        InlayHints,
        Diagnostics,
        CodeLenses,
        Completions,
    }

    pub(crate) struct BlockingEcosystem {
        pub(crate) started: Arc<Barrier>,
        pub(crate) hook: BlockingHook,
    }
    impl BlockingEcosystem {
        /// A paired manifest of `uri` whose hooks are this ecosystem's.
        pub(crate) fn manifest(self: &Arc<Self>, uri: &url::Url) -> Box<dyn ParsedManifest> {
            crate::test_utils::manifest_of(self, uri)
        }

        async fn block_on(&self, hook: BlockingHook) {
            if std::mem::discriminant(&self.hook) == std::mem::discriminant(&hook) {
                self.started.wait().await;
                std::future::pending::<()>().await;
                unreachable!("test aborts the handler task before this future resolves")
            }
        }
    }

    impl Sealed for BlockingEcosystem {}
    impl EcosystemBase for BlockingEcosystem {
        fn ecosystem_id(&self) -> deps_core::EcosystemId {
            deps_core::EcosystemId::Cargo
        }
        fn display_name(&self) -> &'static str {
            "cargo"
        }
        fn manifest_filenames(&self) -> &[&'static str] {
            &["Cargo.toml"]
        }
        fn registry(&self) -> Arc<dyn Registry> {
            Arc::new(NoopRegistry)
        }
        fn completion_insert_text(&self, _metadata: &dyn Metadata) -> Option<String> {
            unimplemented!()
        }
    }

    deps_core::impl_stub_typed_ecosystem!(BlockingEcosystem, {
        fn inlay_hints<'a>(
            &'a self,
            _parsed: ParsedView<'a, StubParseResult>,
            _versions: VersionData<'a>,
            _loading_state: deps_core::LoadingState,
            _config: &'a EcosystemConfig,
        ) -> BoxFuture<'a, Vec<InlayHint>> {
            Box::pin(async move {
                self.block_on(BlockingHook::InlayHints).await;
                vec![]
            })
        }

        fn decorate_diagnostics<'a>(
            &'a self,
            _parsed: ParsedView<'a, StubParseResult>,
            _severities: DiagnosticSeverities,
            _out: &'a mut Vec<deps_core::diagnostic::Diagnostic>,
        ) -> BoxFuture<'a, ()> {
            Box::pin(async move {
                self.block_on(BlockingHook::Diagnostics).await;
            })
        }

        fn code_lenses<'a>(
            &'a self,
            _parsed: ParsedView<'a, StubParseResult>,
            _content: &'a str,
            _versions: VersionData<'a>,
            _uri: &'a url::Url,
            _command_id: &'a str,
        ) -> BoxFuture<'a, Vec<CodeLens>> {
            Box::pin(async move {
                self.block_on(BlockingHook::CodeLenses).await;
                vec![]
            })
        }

        fn completions<'a>(
            &'a self,
            _parsed: ParsedView<'a, StubParseResult>,
            _position: Position,
            _content: &'a str,
            _freshness: FreshnessSettings,
        ) -> BoxFuture<'a, Completions> {
            Box::pin(async move {
                self.block_on(BlockingHook::Completions).await;
                Completions::default()
            })
        }
    });
}
