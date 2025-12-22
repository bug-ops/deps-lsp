//! Generic LSP handler infrastructure.
//!
//! Provides traits and generic functions for implementing LSP operations
//! (inlay hints, hover, etc.) across different package ecosystems.

use crate::parser::DependencyInfo;
use crate::registry::{PackageRegistry, VersionInfo};
use crate::HttpCache;
use async_trait::async_trait;
use futures::future::join_all;
use std::collections::HashMap;
use std::sync::Arc;
use tower_lsp::lsp_types::{
    InlayHint, InlayHintKind, InlayHintLabel, InlayHintLabelPart, MarkupContent, MarkupKind,
    Range,
};

/// Generic handler for LSP operations across ecosystems.
///
/// This trait uses Generic Associated Types (GATs) to provide
/// a unified interface for handlers while maintaining strong typing.
///
/// Implementors provide ecosystem-specific behavior (registry access,
/// URL construction, version matching) while the generic handler
/// functions provide the common LSP logic.
///
/// # Examples
///
/// ```no_run
/// use deps_core::{EcosystemHandler, HttpCache, PackageRegistry, DependencyInfo};
/// use async_trait::async_trait;
/// use std::sync::Arc;
///
/// # #[derive(Clone)] struct MyVersion { version: String }
/// # impl deps_core::VersionInfo for MyVersion {
/// #     fn version_string(&self) -> &str { &self.version }
/// #     fn is_yanked(&self) -> bool { false }
/// # }
/// # #[derive(Clone)] struct MyMetadata { name: String }
/// # impl deps_core::PackageMetadata for MyMetadata {
/// #     fn name(&self) -> &str { &self.name }
/// #     fn description(&self) -> Option<&str> { None }
/// #     fn repository(&self) -> Option<&str> { None }
/// #     fn documentation(&self) -> Option<&str> { None }
/// #     fn latest_version(&self) -> &str { "1.0.0" }
/// # }
/// # #[derive(Clone)] struct MyDependency { name: String }
/// # impl DependencyInfo for MyDependency {
/// #     fn name(&self) -> &str { &self.name }
/// #     fn name_range(&self) -> tower_lsp::lsp_types::Range { tower_lsp::lsp_types::Range::default() }
/// #     fn version_requirement(&self) -> Option<&str> { None }
/// #     fn version_range(&self) -> Option<tower_lsp::lsp_types::Range> { None }
/// #     fn source(&self) -> deps_core::parser::DependencySource { deps_core::parser::DependencySource::Registry }
/// # }
/// # #[derive(Clone)] struct MyRegistry;
/// # #[async_trait]
/// # impl PackageRegistry for MyRegistry {
/// #     type Version = MyVersion;
/// #     type Metadata = MyMetadata;
/// #     type VersionReq = String;
/// #     async fn get_versions(&self, _name: &str) -> deps_core::error::Result<Vec<Self::Version>> { Ok(vec![]) }
/// #     async fn get_latest_matching(&self, _name: &str, _req: &Self::VersionReq) -> deps_core::error::Result<Option<Self::Version>> { Ok(None) }
/// #     async fn search(&self, _query: &str, _limit: usize) -> deps_core::error::Result<Vec<Self::Metadata>> { Ok(vec![]) }
/// # }
/// struct MyHandler {
///     registry: MyRegistry,
/// }
///
/// #[async_trait]
/// impl EcosystemHandler for MyHandler {
///     type Registry = MyRegistry;
///     type Dependency = MyDependency;
///
///     fn new(_cache: Arc<HttpCache>) -> Self {
///         Self {
///             registry: MyRegistry,
///         }
///     }
///
///     fn registry(&self) -> &Self::Registry {
///         &self.registry
///     }
///
///     fn extract_dependency<'a, UnifiedDep>(_dep: &'a UnifiedDep) -> Option<&'a Self::Dependency> {
///         // In real implementation, match on the enum variant
///         None
///     }
///
///     fn package_url(name: &str) -> String {
///         format!("https://myregistry.org/package/{}", name)
///     }
///
///     fn ecosystem_display_name() -> &'static str {
///         "MyRegistry"
///     }
///
///     fn is_version_latest(version_req: &str, latest: &str) -> bool {
///         version_req == latest
///     }
/// }
/// ```
#[async_trait]
pub trait EcosystemHandler: Send + Sync + Sized {
    /// Registry type for this ecosystem.
    type Registry: PackageRegistry + Clone;

    /// Dependency type for this ecosystem.
    type Dependency: DependencyInfo;

    /// Create a new handler with the given cache.
    fn new(cache: Arc<HttpCache>) -> Self;

    /// Get the registry instance.
    fn registry(&self) -> &Self::Registry;

    /// Extract typed dependency from a unified dependency enum.
    ///
    /// Returns Some if the unified dependency matches this handler's ecosystem,
    /// None otherwise.
    ///
    /// NOTE: UnifiedDep is typically deps_lsp::document::UnifiedDependency.
    /// We use a generic type here to avoid circular dependency between
    /// deps-core and deps-lsp.
    fn extract_dependency<'a, UnifiedDep>(dep: &'a UnifiedDep) -> Option<&'a Self::Dependency>;
    /// Package URL for this ecosystem (e.g., crates.io, npmjs.com).
    ///
    /// Used in inlay hint commands and hover tooltips.
    fn package_url(name: &str) -> String;

    /// Display name for the ecosystem (e.g., "crates.io", "PyPI").
    ///
    /// Used in LSP command titles.
    fn ecosystem_display_name() -> &'static str;

    /// Check if version is latest (ecosystem-specific logic).
    ///
    /// Returns true if the latest version satisfies the version requirement,
    /// meaning the dependency is up-to-date within its constraint.
    fn is_version_latest(version_req: &str, latest: &str) -> bool;
}

/// Configuration for inlay hint display.
///
/// This is a simplified version to avoid circular dependencies.
/// The actual type comes from deps-lsp/config.rs.
pub struct InlayHintsConfig {
    pub enabled: bool,
    pub up_to_date_text: String,
    pub needs_update_text: String,
}

impl Default for InlayHintsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            up_to_date_text: "✅".to_string(),
            needs_update_text: "❌ {}".to_string(),
        }
    }
}

/// Helper trait for accessing version string from unified version types.
///
/// Allows generic code to work with UnifiedVersion without circular dependency.
pub trait VersionStringGetter {
    fn version_string(&self) -> &str;
}

/// Helper trait for checking if a version is yanked.
///
/// Allows generic code to work with UnifiedVersion without circular dependency.
pub trait YankedChecker {
    fn is_yanked(&self) -> bool;
}

/// Generic inlay hints generator.
///
/// Handles the common logic of fetching versions, checking cache,
/// and creating hints. Ecosystem-specific behavior is delegated
/// to the EcosystemHandler trait.
///
/// # Type Parameters
///
/// * `H` - Ecosystem handler type
/// * `UnifiedDep` - Unified dependency enum (typically UnifiedDependency from deps-lsp)
/// * `UnifiedVer` - Unified version enum (typically UnifiedVersion from deps-lsp)
///
/// # Arguments
///
/// * `handler` - Ecosystem-specific handler instance
/// * `dependencies` - List of dependencies to process
/// * `cached_versions` - Previously cached version information
/// * `config` - Display configuration
///
/// # Returns
///
/// Vector of inlay hints for the LSP client.
pub async fn generate_inlay_hints<H, UnifiedDep, UnifiedVer>(
    handler: &H,
    dependencies: &[UnifiedDep],
    cached_versions: &HashMap<String, UnifiedVer>,
    config: &InlayHintsConfig,
) -> Vec<InlayHint>
where
    H: EcosystemHandler,
    UnifiedVer: VersionStringGetter + YankedChecker,
{
    let mut cached_deps = Vec::new();
    let mut fetch_deps = Vec::new();

    // Separate deps into cached and needs-fetch
    for dep in dependencies {
        let Some(typed_dep) = H::extract_dependency(dep) else {
            continue;
        };

        let Some(version_req) = typed_dep.version_requirement() else {
            continue;
        };
        let Some(version_range) = typed_dep.version_range() else {
            continue;
        };

        let name = typed_dep.name();
        if let Some(cached) = cached_versions.get(name) {
            cached_deps.push((
                name.to_string(),
                version_req.to_string(),
                version_range,
                cached.version_string().to_string(),
                cached.is_yanked(),
            ));
        } else {
            fetch_deps.push((name.to_string(), version_req.to_string(), version_range));
        }
    }

    tracing::debug!(
        "inlay hints: {} cached, {} to fetch",
        cached_deps.len(),
        fetch_deps.len()
    );

    // Fetch missing versions in parallel
    let registry = handler.registry().clone();
    let futures: Vec<_> = fetch_deps
        .into_iter()
        .map(|(name, version_req, version_range)| {
            let registry = registry.clone();
            async move {
                let result = registry.get_versions(&name).await;
                (name, version_req, version_range, result)
            }
        })
        .collect();

    let fetch_results = join_all(futures).await;

    let mut hints = Vec::new();

    // Process cached deps
    for (name, version_req, version_range, latest_version, is_yanked) in cached_deps {
        if is_yanked {
            continue;
        }
        let is_latest = H::is_version_latest(&version_req, &latest_version);
        hints.push(create_hint::<H>(
            &name,
            version_range,
            &latest_version,
            is_latest,
            config,
        ));
    }

    // Process fetched deps
    for (name, version_req, version_range, result) in fetch_results {
        let Ok(versions): std::result::Result<Vec<<H::Registry as PackageRegistry>::Version>, _> =
            result
        else {
            tracing::warn!("Failed to fetch versions for {}", name);
            continue;
        };

        let Some(latest) = versions
            .iter()
            .find(|v: &&<H::Registry as PackageRegistry>::Version| !v.is_yanked())
        else {
            continue;
        };

        let is_latest = H::is_version_latest(&version_req, latest.version_string());
        hints.push(create_hint::<H>(
            &name,
            version_range,
            latest.version_string(),
            is_latest,
            config,
        ));
    }

    hints
}

/// Generic hint creation.
///
/// Uses ecosystem-specific URL and display name from the handler trait.
fn create_hint<H: EcosystemHandler>(
    name: &str,
    version_range: Range,
    latest_version: &str,
    is_latest: bool,
    config: &InlayHintsConfig,
) -> InlayHint {
    let label_text = if is_latest {
        config.up_to_date_text.clone()
    } else {
        config.needs_update_text.replace("{}", latest_version)
    };

    let url = H::package_url(name);
    let tooltip_content = format!(
        "[{}]({}) - {}\n\nLatest: **{}**",
        name, url, url, latest_version
    );

    InlayHint {
        position: version_range.end,
        label: InlayHintLabel::LabelParts(vec![InlayHintLabelPart {
            value: label_text,
            tooltip: Some(
                tower_lsp::lsp_types::InlayHintLabelPartTooltip::MarkupContent(MarkupContent {
                    kind: MarkupKind::Markdown,
                    value: tooltip_content,
                }),
            ),
            location: None,
            command: Some(tower_lsp::lsp_types::Command {
                title: format!("Open on {}", H::ecosystem_display_name()),
                command: "vscode.open".into(),
                arguments: Some(vec![serde_json::json!(url)]),
            }),
        }]),
        kind: Some(InlayHintKind::TYPE),
        text_edits: None,
        tooltip: None,
        padding_left: Some(true),
        padding_right: None,
        data: None,
    }
}

/// Generic hover generator.
///
/// Fetches version information and generates markdown hover content
/// with version list and features (if supported).
///
/// # Type Parameters
///
/// * `H` - Ecosystem handler type
/// * `UnifiedDep` - Unified dependency enum (typically UnifiedDependency from deps-lsp)
pub async fn generate_hover<H, UnifiedDep>(
    handler: &H,
    dep: &UnifiedDep,
) -> Option<tower_lsp::lsp_types::Hover>
where
    H: EcosystemHandler,
{
    use tower_lsp::lsp_types::{Hover, HoverContents};

    let typed_dep = H::extract_dependency(dep)?;
    let registry = handler.registry();
    let versions: Vec<<H::Registry as PackageRegistry>::Version> =
        registry.get_versions(typed_dep.name()).await.ok()?;
    let latest: &<H::Registry as PackageRegistry>::Version = versions.first()?;

    let url = H::package_url(typed_dep.name());
    let mut markdown = format!("# [{}]({})\n\n", typed_dep.name(), url);

    if let Some(current) = typed_dep.version_requirement() {
        markdown.push_str(&format!("**Current**: `{}`\n\n", current));
    }

    if latest.is_yanked() {
        markdown.push_str("⚠️ **Warning**: This version has been yanked\n\n");
    }

    markdown.push_str("**Versions** *(use Cmd+. to update)*:\n");
    for (i, version) in versions.iter().take(8).enumerate() {
        if i == 0 {
            markdown.push_str(&format!("- {} *(latest)*\n", version.version_string()));
        } else {
            markdown.push_str(&format!("- {}\n", version.version_string()));
        }
    }
    if versions.len() > 8 {
        markdown.push_str(&format!("- *...and {} more*\n", versions.len() - 8));
    }

    // Features (if supported by ecosystem)
    let features = latest.features();
    if !features.is_empty() {
        markdown.push_str("\n**Features**:\n");
        for feature in features.iter().take(10) {
            markdown.push_str(&format!("- `{}`\n", feature));
        }
        if features.len() > 10 {
            markdown.push_str(&format!("- *...and {} more*\n", features.len() - 10));
        }
    }

    Some(Hover {
        contents: HoverContents::Markup(MarkupContent {
            kind: MarkupKind::Markdown,
            value: markdown,
        }),
        range: Some(typed_dep.name_range()),
    })
}
