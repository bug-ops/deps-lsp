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
    };
    use std::any::Any;
    use std::path::Path;
    use std::sync::Arc;
    use tokio::sync::Barrier;
    use tower_lsp_server::ls_types::{
        CodeLens, CompletionItem, Diagnostic, InlayHint, Position, Uri,
    };

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
        fn search<'a>(
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

    pub(crate) struct NoopFormatter;
    impl EcosystemFormatter for NoopFormatter {
        fn format_version_for_text_edit(&self, version: &str) -> String {
            version.to_string()
        }
        fn package_url(&self, name: &deps_core::PackageName) -> String {
            format!("https://example.com/{name}")
        }
    }

    pub(crate) struct MockParseResult {
        pub(crate) uri: Uri,
    }
    impl ParseResult for MockParseResult {
        fn dependencies(&self) -> Vec<&dyn Dependency> {
            vec![]
        }
        fn workspace_root(&self) -> Option<&Path> {
            None
        }
        fn uri(&self) -> &Uri {
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
        fn id(&self) -> &'static str {
            "cargo"
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
            _uri: &'a Uri,
        ) -> BoxFuture<'a, deps_core::Result<Box<dyn ParseResult>>> {
            Box::pin(async move { unimplemented!() })
        }
        fn registry(&self) -> Arc<dyn Registry> {
            Arc::new(NoopRegistry)
        }
        fn formatter(&self) -> &dyn EcosystemFormatter {
            &NoopFormatter
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
            _uri: &'a Uri,
            _freshness: FreshnessSettings,
            _severities: DiagnosticSeverities,
        ) -> BoxFuture<'a, Vec<Diagnostic>> {
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
            _uri: &'a Uri,
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
        ) -> BoxFuture<'a, Vec<CompletionItem>> {
            Box::pin(async move {
                if matches!(self.hook, BlockingHook::Completions) {
                    self.started.wait().await;
                    std::future::pending::<()>().await;
                    unreachable!("test aborts the handler task before this future resolves")
                }
                vec![]
            })
        }
        fn as_any(&self) -> &dyn Any {
            self
        }
    }
}
