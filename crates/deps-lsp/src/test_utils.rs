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
    use deps_core::{
        Dependency, DiagnosticSeverities, Ecosystem, EcosystemConfig, EcosystemFormatter,
        FreshnessSettings, Metadata, ParseResult, Registry, Version, VersionData,
        completion::Completions,
    };
    use std::any::Any;
    use std::path::Path;
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
        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    pub(crate) struct MockParseResult {
        pub(crate) uri: url::Url,
    }
    impl ParseResult for MockParseResult {
        fn dependencies(&self) -> Vec<&dyn Dependency> {
            vec![]
        }
        fn workspace_root(&self) -> Option<&Path> {
            None
        }
        fn uri(&self) -> &url::Url {
            &self.uri
        }
        fn as_any(&self) -> &dyn Any {
            self
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
    impl Sealed for BlockingEcosystem {}
    impl Ecosystem for BlockingEcosystem {
        fn ecosystem_id(&self) -> deps_core::EcosystemId {
            deps_core::EcosystemId::Cargo
        }
        fn display_name(&self) -> &'static str {
            "cargo"
        }
        fn manifest_filenames(&self) -> &[&'static str] {
            &["Cargo.toml"]
        }
        fn parse_manifest<'a>(
            &'a self,
            _content: &'a str,
            _uri: &'a url::Url,
        ) -> BoxFuture<'a, deps_core::Result<Box<dyn ParseResult>>> {
            Box::pin(async move { unimplemented!() })
        }
        fn registry(&self) -> Arc<dyn Registry> {
            Arc::new(NoopRegistry)
        }
        fn formatter(&self) -> &dyn EcosystemFormatter {
            &deps_core::test_util::StubFormatter::DEFAULT
        }
        fn generate_inlay_hints<'a>(
            &'a self,
            _parse_result: &'a dyn ParseResult,
            _versions: VersionData<'a>,
            _loading_state: deps_core::LoadingState,
            _config: &'a EcosystemConfig,
        ) -> BoxFuture<'a, Vec<InlayHint>> {
            Box::pin(async move {
                if matches!(self.hook, BlockingHook::InlayHints) {
                    self.started.wait().await;
                    std::future::pending::<()>().await;
                    unreachable!("test aborts the handler task before this future resolves")
                }
                vec![]
            })
        }
        fn generate_diagnostics<'a>(
            &'a self,
            _parse_result: &'a dyn ParseResult,
            _versions: VersionData<'a>,
            _uri: &'a url::Url,
            _freshness: FreshnessSettings,
            _severities: DiagnosticSeverities,
        ) -> BoxFuture<'a, Vec<deps_core::diagnostic::Diagnostic>> {
            Box::pin(async move {
                if matches!(self.hook, BlockingHook::Diagnostics) {
                    self.started.wait().await;
                    std::future::pending::<()>().await;
                    unreachable!("test aborts the handler task before this future resolves")
                }
                vec![]
            })
        }
        fn generate_code_lenses<'a>(
            &'a self,
            _parse_result: &'a dyn ParseResult,
            _content: &'a str,
            _versions: VersionData<'a>,
            _uri: &'a url::Url,
            _command_id: &'a str,
        ) -> BoxFuture<'a, Vec<CodeLens>> {
            Box::pin(async move {
                if matches!(self.hook, BlockingHook::CodeLenses) {
                    self.started.wait().await;
                    std::future::pending::<()>().await;
                    unreachable!("test aborts the handler task before this future resolves")
                }
                vec![]
            })
        }
        fn generate_completions<'a>(
            &'a self,
            _parse_result: &'a dyn ParseResult,
            _position: Position,
            _content: &'a str,
            _freshness: FreshnessSettings,
        ) -> BoxFuture<'a, Completions> {
            Box::pin(async move {
                if matches!(self.hook, BlockingHook::Completions) {
                    self.started.wait().await;
                    std::future::pending::<()>().await;
                    unreachable!("test aborts the handler task before this future resolves")
                }
                Completions::default()
            })
        }
        fn complete_version<'a>(
            &'a self,
            _request: deps_core::completion::CompletionRequest<'a>,
            _package_name: deps_core::PackageName,
            _prefix: String,
        ) -> BoxFuture<'a, Completions> {
            unimplemented!()
        }
        fn completion_insert_text(&self, _metadata: &dyn deps_core::Metadata) -> Option<String> {
            unimplemented!()
        }
        fn as_any(&self) -> &dyn Any {
            self
        }
    }
}
