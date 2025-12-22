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

    // Step 3: Create document state
    let doc_state = DocumentState::new(ecosystem, content, unified_deps);
    state.update_document(uri.clone(), doc_state);

    // Step 4: Spawn background version fetch task
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
    #[test]
    fn test_module_compiles() {
        // Smoke test to ensure module compiles
        // Integration tests in server.rs will test actual functionality
    }
}
