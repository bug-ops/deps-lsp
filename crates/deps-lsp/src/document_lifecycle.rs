//! Generic document lifecycle handlers.
//!
//! Provides unified open/change handlers that work with any ecosystem
//! implementing the EcosystemHandler trait. Eliminates duplication across
//! Cargo, npm, and PyPI document handlers in server.rs.

use crate::config::DepsConfig;
use crate::document::{DocumentState, Ecosystem, ServerState, UnifiedDependency, UnifiedVersion};
use crate::handlers::diagnostics;
use deps_core::parser::DependencyInfo;
use deps_core::registry::PackageRegistry;
use deps_core::{EcosystemHandler, Result};
use futures::future::join_all;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tower_lsp::Client;
use tower_lsp::lsp_types::Url;

/// Generic document open handler.
///
/// Parses manifest using the ecosystem's parser, creates document state,
/// and spawns a background task to fetch version information from the registry.
///
/// # Type Parameters
///
/// - `H`: Ecosystem handler implementing EcosystemHandler trait
/// - `Parser`: Function to parse manifest content
/// - `WrapDep`: Function to wrap parsed dependency into UnifiedDependency
/// - `WrapVer`: Function to wrap registry version into UnifiedVersion
///
/// # Arguments
///
/// - `uri`: Document URI
/// - `content`: Document text content
/// - `state`: Server state
/// - `client`: LSP client for publishing diagnostics
/// - `config`: Configuration for diagnostics
/// - `parse_fn`: Ecosystem-specific parser function
/// - `wrap_dep_fn`: Function to convert parsed dep to UnifiedDependency
/// - `wrap_ver_fn`: Function to convert registry version to UnifiedVersion
/// - `ecosystem`: Ecosystem identifier
/// - `should_fetch`: Function to determine if dependency needs version fetching
///
/// # Returns
///
/// Background task handle for version fetching, or error if parsing fails.
#[allow(clippy::too_many_arguments)]
pub async fn handle_document_open<H, Parser, WrapDep, WrapVer, ShouldFetch, ParseResult>(
    uri: Url,
    content: String,
    state: Arc<ServerState>,
    client: Client,
    config: Arc<RwLock<DepsConfig>>,
    parse_fn: Parser,
    wrap_dep_fn: WrapDep,
    wrap_ver_fn: WrapVer,
    ecosystem: Ecosystem,
    should_fetch: ShouldFetch,
) -> Result<JoinHandle<()>>
where
    H: EcosystemHandler<UnifiedDep = UnifiedDependency>,
    H::Dependency: DependencyInfo,
    H::Registry: PackageRegistry,
    Parser: FnOnce(&str, &Url) -> Result<ParseResult>,
    ParseResult: IntoIterator<Item = H::Dependency>,
    WrapDep: Fn(H::Dependency) -> UnifiedDependency + Send + 'static,
    WrapVer:
        Fn(<H::Registry as PackageRegistry>::Version) -> UnifiedVersion + Send + 'static + Clone,
    ShouldFetch: Fn(&H::Dependency) -> bool + Send + 'static + Clone,
{
    // Step 1: Parse manifest
    let parse_result = parse_fn(&content, &uri)?;
    let dependencies: Vec<H::Dependency> = parse_result.into_iter().collect();

    // Step 2: Wrap dependencies
    let unified_deps: Vec<UnifiedDependency> = dependencies.into_iter().map(wrap_dep_fn).collect();

    // Step 3: Try to parse lock file for instant version display
    let lockfile_versions = {
        let cache = Arc::clone(&state.cache);
        let handler = H::new(cache);

        if let Some(provider) = handler.lockfile_provider() {
            if let Some(lockfile_path) = provider.locate_lockfile(&uri) {
                match state
                    .lockfile_cache
                    .get_or_parse(provider.as_ref(), &lockfile_path)
                    .await
                {
                    Ok(resolved) => {
                        tracing::info!(
                            "Loaded lock file: {} packages from {}",
                            resolved.len(),
                            lockfile_path.display()
                        );
                        Some(resolved)
                    }
                    Err(e) => {
                        tracing::warn!("Failed to parse lock file: {}", e);
                        None
                    }
                }
            } else {
                tracing::debug!("No lock file found for {}", uri);
                None
            }
        } else {
            None
        }
    };

    // Step 4: Create document state with lock file versions if available
    let mut doc_state = DocumentState::new(ecosystem, content, unified_deps);
    if let Some(resolved) = lockfile_versions {
        let lock_versions: HashMap<String, UnifiedVersion> = resolved
            .iter()
            .map(|(name, pkg)| {
                // Create UnifiedVersion from lock file version string
                let unified_version = match ecosystem {
                    Ecosystem::Cargo => UnifiedVersion::Cargo(deps_cargo::CargoVersion {
                        num: pkg.version.clone(),
                        yanked: false,
                        features: HashMap::new(),
                    }),
                    Ecosystem::Npm => UnifiedVersion::Npm(deps_npm::NpmVersion {
                        version: pkg.version.clone(),
                        deprecated: false,
                    }),
                    Ecosystem::Pypi => UnifiedVersion::Pypi(deps_pypi::PypiVersion {
                        version: pkg.version.clone(),
                        yanked: false,
                    }),
                };
                (name.clone(), unified_version)
            })
            .collect();

        tracing::info!("Populated {} versions from lock file", lock_versions.len());
        doc_state.update_versions(lock_versions);
    }

    state.update_document(uri.clone(), doc_state);

    // Step 5: Spawn background version fetch task
    let uri_clone = uri.clone();
    let task = tokio::spawn(async move {
        let cache = Arc::clone(&state.cache);
        let handler = H::new(cache);
        let registry = handler.registry().clone();

        // Collect dependencies to fetch (avoid holding doc lock during fetch)
        let deps_to_fetch: Vec<_> = {
            let doc = match state.get_document(&uri_clone) {
                Some(d) => d,
                None => return,
            };

            doc.dependencies
                .iter()
                .filter_map(|dep| {
                    let typed_dep = H::extract_dependency(dep)?;
                    if !should_fetch(typed_dep) {
                        return None;
                    }
                    Some(typed_dep.name().to_string())
                })
                .collect()
        };

        // Parallel fetch all versions
        let futures: Vec<_> = deps_to_fetch
            .into_iter()
            .map(|name| {
                let registry = registry.clone();
                let wrap_ver_fn = wrap_ver_fn.clone();
                async move {
                    let versions = registry.get_versions(&name).await.ok()?;
                    let latest = versions.first()?.clone();
                    Some((name, wrap_ver_fn(latest)))
                }
            })
            .collect();

        let results = join_all(futures).await;
        let versions: HashMap<_, _> = results.into_iter().flatten().collect();

        // Update document with fetched versions
        if let Some(mut doc) = state.documents.get_mut(&uri_clone) {
            doc.update_versions(versions);
        }

        // Publish diagnostics
        let config_read = config.read().await;
        let diags = diagnostics::handle_diagnostics(
            Arc::clone(&state),
            &uri_clone,
            &config_read.diagnostics,
        )
        .await;

        client.publish_diagnostics(uri_clone, diags, None).await;
    });

    Ok(task)
}

/// Generic document change handler.
///
/// Re-parses manifest when document content changes and spawns a debounced
/// task to update diagnostics and request inlay hint refresh.
///
/// # Type Parameters
///
/// - `H`: Ecosystem handler implementing EcosystemHandler trait
/// - `Parser`: Function to parse manifest content
/// - `WrapDep`: Function to wrap parsed dependency into UnifiedDependency
///
/// # Arguments
///
/// - `uri`: Document URI
/// - `content`: Updated document text content
/// - `state`: Server state
/// - `client`: LSP client for publishing diagnostics
/// - `config`: Configuration for diagnostics
/// - `parse_fn`: Ecosystem-specific parser function
/// - `wrap_dep_fn`: Function to convert parsed dep to UnifiedDependency
/// - `ecosystem`: Ecosystem identifier
///
/// # Returns
///
/// Background task handle for debounced diagnostics update.
#[allow(clippy::too_many_arguments)]
pub async fn handle_document_change<H, Parser, WrapDep, ParseResult>(
    uri: Url,
    content: String,
    state: Arc<ServerState>,
    client: Client,
    config: Arc<RwLock<DepsConfig>>,
    parse_fn: Parser,
    wrap_dep_fn: WrapDep,
    ecosystem: Ecosystem,
) -> Result<JoinHandle<()>>
where
    H: EcosystemHandler<UnifiedDep = UnifiedDependency>,
    H::Dependency: DependencyInfo,
    Parser: FnOnce(&str, &Url) -> Result<ParseResult>,
    ParseResult: IntoIterator<Item = H::Dependency>,
    WrapDep: Fn(H::Dependency) -> UnifiedDependency,
{
    // Step 1: Parse manifest
    let parse_result = parse_fn(&content, &uri)?;
    let dependencies: Vec<H::Dependency> = parse_result.into_iter().collect();

    // Step 2: Wrap dependencies
    let unified_deps: Vec<UnifiedDependency> = dependencies.into_iter().map(wrap_dep_fn).collect();

    // Step 3: Update document state
    let doc_state = DocumentState::new(ecosystem, content, unified_deps);
    state.update_document(uri.clone(), doc_state);

    // Step 4: Spawn debounced diagnostics update task
    let uri_clone = uri.clone();
    let task = tokio::spawn(async move {
        // Debounce: wait 100ms for rapid edits to settle
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Publish diagnostics
        let config_read = config.read().await;
        let diags = diagnostics::handle_diagnostics(
            Arc::clone(&state),
            &uri_clone,
            &config_read.diagnostics,
        )
        .await;

        client
            .publish_diagnostics(uri_clone.clone(), diags, None)
            .await;

        // Request inlay hints refresh
        if let Err(e) = client.inlay_hint_refresh().await {
            tracing::debug!("inlay_hint_refresh not supported: {:?}", e);
        }
    });

    Ok(task)
}

/// Convenience wrapper for Cargo.toml open handler.
///
/// Uses deps_cargo parser and types.
pub async fn cargo_open(
    uri: Url,
    content: String,
    state: Arc<ServerState>,
    client: Client,
    config: Arc<RwLock<DepsConfig>>,
) -> Result<JoinHandle<()>> {
    use crate::handlers::cargo_handler_impl::CargoHandlerImpl;
    use deps_cargo::{DependencySource, parse_cargo_toml};

    handle_document_open::<CargoHandlerImpl, _, _, _, _, _>(
        uri,
        content,
        state,
        client,
        config,
        |content, uri| parse_cargo_toml(content, uri).map(|r| r.dependencies),
        UnifiedDependency::Cargo,
        UnifiedVersion::Cargo,
        Ecosystem::Cargo,
        |dep| matches!(dep.source, DependencySource::Registry),
    )
    .await
}

/// Convenience wrapper for Cargo.toml change handler.
pub async fn cargo_change(
    uri: Url,
    content: String,
    state: Arc<ServerState>,
    client: Client,
    config: Arc<RwLock<DepsConfig>>,
) -> Result<JoinHandle<()>> {
    use crate::handlers::cargo_handler_impl::CargoHandlerImpl;
    use deps_cargo::parse_cargo_toml;

    handle_document_change::<CargoHandlerImpl, _, _, _>(
        uri,
        content,
        state,
        client,
        config,
        |content, uri| parse_cargo_toml(content, uri).map(|r| r.dependencies),
        UnifiedDependency::Cargo,
        Ecosystem::Cargo,
    )
    .await
}

/// Convenience wrapper for package.json open handler.
pub async fn npm_open(
    uri: Url,
    content: String,
    state: Arc<ServerState>,
    client: Client,
    config: Arc<RwLock<DepsConfig>>,
) -> Result<JoinHandle<()>> {
    use crate::handlers::npm_handler_impl::NpmHandlerImpl;
    use deps_npm::parse_package_json;

    handle_document_open::<NpmHandlerImpl, _, _, _, _, _>(
        uri,
        content,
        state,
        client,
        config,
        |content, _uri| parse_package_json(content).map(|r| r.dependencies),
        UnifiedDependency::Npm,
        UnifiedVersion::Npm,
        Ecosystem::Npm,
        |_dep| true, // All npm deps are from registry
    )
    .await
}

/// Convenience wrapper for package.json change handler.
pub async fn npm_change(
    uri: Url,
    content: String,
    state: Arc<ServerState>,
    client: Client,
    config: Arc<RwLock<DepsConfig>>,
) -> Result<JoinHandle<()>> {
    use crate::handlers::npm_handler_impl::NpmHandlerImpl;
    use deps_npm::parse_package_json;

    handle_document_change::<NpmHandlerImpl, _, _, _>(
        uri,
        content,
        state,
        client,
        config,
        |content, _uri| parse_package_json(content).map(|r| r.dependencies),
        UnifiedDependency::Npm,
        Ecosystem::Npm,
    )
    .await
}

/// Convenience wrapper for pyproject.toml open handler.
pub async fn pypi_open(
    uri: Url,
    content: String,
    state: Arc<ServerState>,
    client: Client,
    config: Arc<RwLock<DepsConfig>>,
) -> Result<JoinHandle<()>> {
    use crate::handlers::pypi_handler_impl::PyPiHandlerImpl;
    use deps_pypi::{PypiDependencySource, PypiParser};

    handle_document_open::<PyPiHandlerImpl, _, _, _, _, _>(
        uri,
        content,
        state,
        client,
        config,
        |content, _uri| {
            let parser = PypiParser::new();
            parser
                .parse_content(content)
                .map(|r| r.dependencies)
                .map_err(|e| deps_core::DepsError::ParseError {
                    file_type: "pyproject.toml".into(),
                    source: Box::new(e),
                })
        },
        UnifiedDependency::Pypi,
        UnifiedVersion::Pypi,
        Ecosystem::Pypi,
        |dep| matches!(dep.source, PypiDependencySource::PyPI),
    )
    .await
}

/// Convenience wrapper for pyproject.toml change handler.
pub async fn pypi_change(
    uri: Url,
    content: String,
    state: Arc<ServerState>,
    client: Client,
    config: Arc<RwLock<DepsConfig>>,
) -> Result<JoinHandle<()>> {
    use crate::handlers::pypi_handler_impl::PyPiHandlerImpl;
    use deps_pypi::PypiParser;

    handle_document_change::<PyPiHandlerImpl, _, _, _>(
        uri,
        content,
        state,
        client,
        config,
        |content, _uri| {
            let parser = PypiParser::new();
            parser
                .parse_content(content)
                .map(|r| r.dependencies)
                .map_err(|e| deps_core::DepsError::ParseError {
                    file_type: "pyproject.toml".into(),
                    source: Box::new(e),
                })
        },
        UnifiedDependency::Pypi,
        Ecosystem::Pypi,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DepsConfig;
    use crate::document::{
        DocumentState, Ecosystem, ServerState, UnifiedDependency, UnifiedVersion,
    };
    use deps_cargo::{DependencySection, DependencySource, ParsedDependency};
    use deps_core::registry::{PackageMetadata, PackageRegistry, VersionInfo};
    use deps_core::{DepsError, EcosystemHandler, HttpCache};
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio::sync::RwLock;
    use tower_lsp::Client;
    use tower_lsp::lsp_types::{Position, Range, Url};

    // Mock types for testing
    #[derive(Clone)]
    struct MockVersion {
        version: String,
        yanked: bool,
    }

    impl VersionInfo for MockVersion {
        fn version_string(&self) -> &str {
            &self.version
        }

        fn is_yanked(&self) -> bool {
            self.yanked
        }

        fn features(&self) -> Vec<String> {
            vec![]
        }
    }

    #[derive(Clone)]
    struct MockMetadata {
        name: String,
    }

    impl PackageMetadata for MockMetadata {
        fn name(&self) -> &str {
            &self.name
        }

        fn description(&self) -> Option<&str> {
            None
        }

        fn repository(&self) -> Option<&str> {
            None
        }

        fn documentation(&self) -> Option<&str> {
            None
        }

        fn latest_version(&self) -> &str {
            "1.0.0"
        }
    }

    #[derive(Clone)]
    struct MockRegistry {
        versions: HashMap<String, Vec<MockVersion>>,
    }

    #[async_trait::async_trait]
    impl PackageRegistry for MockRegistry {
        type Version = MockVersion;
        type Metadata = MockMetadata;
        type VersionReq = String;

        async fn get_versions(&self, name: &str) -> deps_core::error::Result<Vec<Self::Version>> {
            self.versions.get(name).cloned().ok_or_else(|| {
                use std::io::{Error as IoError, ErrorKind};
                DepsError::Io(IoError::new(ErrorKind::NotFound, "package not found"))
            })
        }

        async fn get_latest_matching(
            &self,
            name: &str,
            _req: &Self::VersionReq,
        ) -> deps_core::error::Result<Option<Self::Version>> {
            Ok(self.versions.get(name).and_then(|v| v.first().cloned()))
        }

        async fn search(
            &self,
            _query: &str,
            _limit: usize,
        ) -> deps_core::error::Result<Vec<Self::Metadata>> {
            Ok(vec![])
        }
    }

    struct MockHandler {
        registry: MockRegistry,
    }

    #[async_trait::async_trait]
    impl EcosystemHandler for MockHandler {
        type Registry = MockRegistry;
        type Dependency = ParsedDependency;
        type UnifiedDep = UnifiedDependency;

        fn new(_cache: Arc<HttpCache>) -> Self {
            let mut versions = HashMap::new();
            versions.insert(
                "test-pkg".to_string(),
                vec![MockVersion {
                    version: "1.0.0".to_string(),
                    yanked: false,
                }],
            );

            Self {
                registry: MockRegistry { versions },
            }
        }

        fn registry(&self) -> &Self::Registry {
            &self.registry
        }

        fn extract_dependency(dep: &Self::UnifiedDep) -> Option<&Self::Dependency> {
            match dep {
                UnifiedDependency::Cargo(d) => Some(d),
                _ => None,
            }
        }

        fn package_url(name: &str) -> String {
            format!("https://test.io/{}", name)
        }

        fn ecosystem_display_name() -> &'static str {
            "Test"
        }

        fn is_version_latest(_version_req: &str, _latest: &str) -> bool {
            true
        }

        fn format_version_for_edit(_dep: &Self::Dependency, version: &str) -> String {
            format!("\"{}\"", version)
        }

        fn is_deprecated(_version: &MockVersion) -> bool {
            false
        }

        fn is_valid_version_syntax(_version_req: &str) -> bool {
            true
        }

        fn parse_version_req(version_req: &str) -> Option<String> {
            Some(version_req.to_string())
        }
    }

    // Mock LSP Client
    fn mock_client() -> Client {
        // Create a mock client using tower-lsp's testing utilities
        // For unit tests, we can use a mock that doesn't actually send messages
        let (service, _socket) =
            tower_lsp::LspService::build(|client| MockLanguageServer { client }).finish();
        service.inner().client.clone()
    }

    struct MockLanguageServer {
        client: Client,
    }

    #[tower_lsp::async_trait]
    impl tower_lsp::LanguageServer for MockLanguageServer {
        async fn initialize(
            &self,
            _: tower_lsp::lsp_types::InitializeParams,
        ) -> tower_lsp::jsonrpc::Result<tower_lsp::lsp_types::InitializeResult> {
            Ok(tower_lsp::lsp_types::InitializeResult::default())
        }

        async fn shutdown(&self) -> tower_lsp::jsonrpc::Result<()> {
            Ok(())
        }
    }

    fn create_test_dependency(name: &str, version: &str) -> ParsedDependency {
        ParsedDependency {
            name: name.to_string(),
            name_range: Range {
                start: Position {
                    line: 0,
                    character: 0,
                },
                end: Position {
                    line: 0,
                    character: name.len() as u32,
                },
            },
            version_req: Some(version.to_string()),
            version_range: Some(Range {
                start: Position {
                    line: 0,
                    character: 10,
                },
                end: Position {
                    line: 0,
                    character: 15,
                },
            }),
            features: vec![],
            features_range: None,
            source: DependencySource::Registry,
            workspace_inherited: false,
            section: DependencySection::Dependencies,
        }
    }

    #[tokio::test]
    async fn test_handle_document_open_empty_dependencies() {
        let uri = Url::parse("file:///test/Cargo.toml").unwrap();
        let content = "[dependencies]\n".to_string();
        let state = Arc::new(ServerState::new());
        let client = mock_client();
        let config = Arc::new(RwLock::new(DepsConfig::default()));

        let parse_fn = |_content: &str,
                        _uri: &Url|
         -> deps_core::error::Result<Vec<ParsedDependency>> { Ok(vec![]) };

        let wrap_ver_fn = |_v: MockVersion| -> UnifiedVersion {
            UnifiedVersion::Cargo(deps_cargo::CargoVersion {
                num: "1.0.0".to_string(),
                yanked: false,
                features: HashMap::new(),
            })
        };

        let result = handle_document_open::<MockHandler, _, _, _, _, _>(
            uri.clone(),
            content.clone(),
            state.clone(),
            client,
            config,
            parse_fn,
            UnifiedDependency::Cargo,
            wrap_ver_fn,
            Ecosystem::Cargo,
            |_| true,
        )
        .await;

        assert!(result.is_ok());

        // Verify document was stored
        let doc = state.get_document(&uri);
        assert!(doc.is_some());
        let doc = doc.unwrap();
        assert_eq!(doc.content, content);
        assert_eq!(doc.dependencies.len(), 0);
        assert_eq!(doc.ecosystem, Ecosystem::Cargo);
    }

    #[tokio::test]
    async fn test_handle_document_open_with_dependencies() {
        let uri = Url::parse("file:///test/Cargo.toml").unwrap();
        let content = "[dependencies]\ntest-pkg = \"1.0.0\"\n".to_string();
        let state = Arc::new(ServerState::new());
        let client = mock_client();
        let config = Arc::new(RwLock::new(DepsConfig::default()));

        let parse_fn =
            |_content: &str, _uri: &Url| -> deps_core::error::Result<Vec<ParsedDependency>> {
                Ok(vec![create_test_dependency("test-pkg", "1.0.0")])
            };

        let wrap_ver_fn = |_v: MockVersion| -> UnifiedVersion {
            UnifiedVersion::Cargo(deps_cargo::CargoVersion {
                num: "1.0.0".to_string(),
                yanked: false,
                features: HashMap::new(),
            })
        };

        let result = handle_document_open::<MockHandler, _, _, _, _, _>(
            uri.clone(),
            content.clone(),
            state.clone(),
            client,
            config,
            parse_fn,
            UnifiedDependency::Cargo,
            wrap_ver_fn,
            Ecosystem::Cargo,
            |dep| matches!(dep.source, DependencySource::Registry),
        )
        .await;

        assert!(result.is_ok());
        let task = result.unwrap();

        // Wait for background task to complete
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), task).await;

        // Verify document was stored
        let doc = state.get_document(&uri);
        assert!(doc.is_some());
        let doc = doc.unwrap();
        assert_eq!(doc.dependencies.len(), 1);
        assert_eq!(doc.dependencies[0].name(), "test-pkg");
    }

    #[tokio::test]
    async fn test_handle_document_open_parse_error() {
        let uri = Url::parse("file:///test/Cargo.toml").unwrap();
        let content = "invalid toml content".to_string();
        let state = Arc::new(ServerState::new());
        let client = mock_client();
        let config = Arc::new(RwLock::new(DepsConfig::default()));

        let parse_fn =
            |_content: &str, _uri: &Url| -> deps_core::error::Result<Vec<ParsedDependency>> {
                Err(DepsError::ParseError {
                    file_type: "Cargo.toml".to_string(),
                    source: Box::new(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "invalid toml",
                    )),
                })
            };

        let wrap_ver_fn = |_v: MockVersion| -> UnifiedVersion {
            UnifiedVersion::Cargo(deps_cargo::CargoVersion {
                num: "1.0.0".to_string(),
                yanked: false,
                features: HashMap::new(),
            })
        };

        let result = handle_document_open::<MockHandler, _, _, _, _, _>(
            uri.clone(),
            content,
            state.clone(),
            client,
            config,
            parse_fn,
            UnifiedDependency::Cargo,
            wrap_ver_fn,
            Ecosystem::Cargo,
            |_| true,
        )
        .await;

        assert!(result.is_err());

        // Document should not be stored on parse error
        let doc = state.get_document(&uri);
        assert!(doc.is_none());
    }

    #[tokio::test]
    async fn test_handle_document_change_updates_state() {
        let uri = Url::parse("file:///test/Cargo.toml").unwrap();
        let state = Arc::new(ServerState::new());
        let client = mock_client();
        let config = Arc::new(RwLock::new(DepsConfig::default()));

        // Initial document
        let initial_content = "[dependencies]\nold-pkg = \"1.0.0\"\n".to_string();
        let initial_doc = DocumentState::new(
            Ecosystem::Cargo,
            initial_content,
            vec![UnifiedDependency::Cargo(create_test_dependency(
                "old-pkg", "1.0.0",
            ))],
        );
        state.update_document(uri.clone(), initial_doc);

        // Update document
        let new_content = "[dependencies]\nnew-pkg = \"2.0.0\"\n".to_string();

        let parse_fn =
            |_content: &str, _uri: &Url| -> deps_core::error::Result<Vec<ParsedDependency>> {
                Ok(vec![create_test_dependency("new-pkg", "2.0.0")])
            };

        let result = handle_document_change::<MockHandler, _, _, _>(
            uri.clone(),
            new_content.clone(),
            state.clone(),
            client,
            config,
            parse_fn,
            UnifiedDependency::Cargo,
            Ecosystem::Cargo,
        )
        .await;

        assert!(result.is_ok());
        let task = result.unwrap();

        // Wait for debounced task
        let _ = tokio::time::timeout(std::time::Duration::from_millis(200), task).await;

        // Verify document was updated
        let doc = state.get_document(&uri);
        assert!(doc.is_some());
        let doc = doc.unwrap();
        assert_eq!(doc.content, new_content);
        assert_eq!(doc.dependencies.len(), 1);
        assert_eq!(doc.dependencies[0].name(), "new-pkg");
    }

    #[tokio::test]
    async fn test_handle_document_change_parse_error_graceful() {
        let uri = Url::parse("file:///test/Cargo.toml").unwrap();
        let state = Arc::new(ServerState::new());
        let client = mock_client();
        let config = Arc::new(RwLock::new(DepsConfig::default()));

        // Initial valid document
        let initial_doc = DocumentState::new(
            Ecosystem::Cargo,
            "[dependencies]\nvalid = \"1.0.0\"\n".to_string(),
            vec![],
        );
        state.update_document(uri.clone(), initial_doc);

        // Try to update with invalid content
        let invalid_content = "invalid toml".to_string();

        let parse_fn =
            |_content: &str, _uri: &Url| -> deps_core::error::Result<Vec<ParsedDependency>> {
                Err(DepsError::ParseError {
                    file_type: "Cargo.toml".to_string(),
                    source: Box::new(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "parse error",
                    )),
                })
            };

        let result = handle_document_change::<MockHandler, _, _, _>(
            uri.clone(),
            invalid_content,
            state.clone(),
            client,
            config,
            parse_fn,
            UnifiedDependency::Cargo,
            Ecosystem::Cargo,
        )
        .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_handle_document_change_empty_content() {
        let uri = Url::parse("file:///test/Cargo.toml").unwrap();
        let state = Arc::new(ServerState::new());
        let client = mock_client();
        let config = Arc::new(RwLock::new(DepsConfig::default()));

        let empty_content = "".to_string();

        let parse_fn = |_content: &str,
                        _uri: &Url|
         -> deps_core::error::Result<Vec<ParsedDependency>> { Ok(vec![]) };

        let result = handle_document_change::<MockHandler, _, _, _>(
            uri.clone(),
            empty_content.clone(),
            state.clone(),
            client,
            config,
            parse_fn,
            UnifiedDependency::Cargo,
            Ecosystem::Cargo,
        )
        .await;

        assert!(result.is_ok());

        // Verify empty content is stored
        let doc = state.get_document(&uri);
        assert!(doc.is_some());
        let doc = doc.unwrap();
        assert_eq!(doc.content, empty_content);
        assert_eq!(doc.dependencies.len(), 0);
    }

    #[tokio::test]
    async fn test_handle_document_open_filters_non_registry_deps() {
        let uri = Url::parse("file:///test/Cargo.toml").unwrap();
        let content = "[dependencies]\ntest-pkg = \"1.0.0\"\n".to_string();
        let state = Arc::new(ServerState::new());
        let client = mock_client();
        let config = Arc::new(RwLock::new(DepsConfig::default()));

        let parse_fn =
            |_content: &str, _uri: &Url| -> deps_core::error::Result<Vec<ParsedDependency>> {
                let mut dep = create_test_dependency("test-pkg", "1.0.0");
                dep.source = DependencySource::Git {
                    url: "https://github.com/test/test".to_string(),
                    rev: None,
                };
                Ok(vec![dep])
            };

        let wrap_ver_fn = |_v: MockVersion| -> UnifiedVersion {
            UnifiedVersion::Cargo(deps_cargo::CargoVersion {
                num: "1.0.0".to_string(),
                yanked: false,
                features: HashMap::new(),
            })
        };

        let result = handle_document_open::<MockHandler, _, _, _, _, _>(
            uri.clone(),
            content,
            state.clone(),
            client,
            config,
            parse_fn,
            UnifiedDependency::Cargo,
            wrap_ver_fn,
            Ecosystem::Cargo,
            |dep| matches!(dep.source, DependencySource::Registry),
        )
        .await;

        assert!(result.is_ok());
        let task = result.unwrap();

        // Wait for background task
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), task).await;

        // Document should have dependency, but no version fetch for git deps
        let doc = state.get_document(&uri);
        assert!(doc.is_some());
        let doc = doc.unwrap();
        assert_eq!(doc.dependencies.len(), 1);
    }

    #[tokio::test]
    async fn test_cargo_open_wrapper() {
        let uri = Url::parse("file:///test/Cargo.toml").unwrap();
        let content = "[dependencies]\nserde = \"1.0\"\n".to_string();
        let state = Arc::new(ServerState::new());
        let client = mock_client();
        let config = Arc::new(RwLock::new(DepsConfig::default()));

        let result = cargo_open(uri.clone(), content, state.clone(), client, config).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_cargo_change_wrapper() {
        let uri = Url::parse("file:///test/Cargo.toml").unwrap();
        let content = "[dependencies]\nserde = \"1.0\"\n".to_string();
        let state = Arc::new(ServerState::new());
        let client = mock_client();
        let config = Arc::new(RwLock::new(DepsConfig::default()));

        let result = cargo_change(uri.clone(), content, state.clone(), client, config).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_npm_open_wrapper() {
        let uri = Url::parse("file:///test/package.json").unwrap();
        let content = r#"{"dependencies": {"react": "^18.0.0"}}"#.to_string();
        let state = Arc::new(ServerState::new());
        let client = mock_client();
        let config = Arc::new(RwLock::new(DepsConfig::default()));

        let result = npm_open(uri.clone(), content, state.clone(), client, config).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_npm_change_wrapper() {
        let uri = Url::parse("file:///test/package.json").unwrap();
        let content = r#"{"dependencies": {"react": "^18.0.0"}}"#.to_string();
        let state = Arc::new(ServerState::new());
        let client = mock_client();
        let config = Arc::new(RwLock::new(DepsConfig::default()));

        let result = npm_change(uri.clone(), content, state.clone(), client, config).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_pypi_open_wrapper() {
        let uri = Url::parse("file:///test/pyproject.toml").unwrap();
        let content = r#"[project]
dependencies = ["requests>=2.28.0"]
"#
        .to_string();
        let state = Arc::new(ServerState::new());
        let client = mock_client();
        let config = Arc::new(RwLock::new(DepsConfig::default()));

        let result = pypi_open(uri.clone(), content, state.clone(), client, config).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_pypi_change_wrapper() {
        let uri = Url::parse("file:///test/pyproject.toml").unwrap();
        let content = r#"[project]
dependencies = ["requests>=2.28.0"]
"#
        .to_string();
        let state = Arc::new(ServerState::new());
        let client = mock_client();
        let config = Arc::new(RwLock::new(DepsConfig::default()));

        let result = pypi_change(uri.clone(), content, state.clone(), client, config).await;

        assert!(result.is_ok());
    }
}
