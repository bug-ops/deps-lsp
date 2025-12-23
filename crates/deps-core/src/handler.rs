//! Generic LSP handler infrastructure.
//!
//! Provides traits and generic functions for implementing LSP operations
//! (inlay hints, hover, etc.) across different package ecosystems.
//!
//! # Deprecation Notice
//!
//! This module is being phased out in favor of the new `Ecosystem` trait.
//! The `EcosystemHandler` trait will be removed in a future version.
//! New implementations should use `crate::ecosystem::Ecosystem` instead.

use crate::HttpCache;
use crate::parser::DependencyInfo;
use crate::registry::{PackageRegistry, VersionInfo};
use async_trait::async_trait;
use futures::future::join_all;
use std::collections::HashMap;
use std::sync::Arc;
use tower_lsp::lsp_types::{
    InlayHint, InlayHintKind, InlayHintLabel, InlayHintLabelPart, MarkupContent, MarkupKind, Range,
};

/// Maximum number of versions to display in hover tooltips.
const MAX_VERSIONS_IN_HOVER: usize = 8;

/// Maximum number of features to display in hover tooltips.
const MAX_FEATURES_IN_HOVER: usize = 10;

/// Maximum number of versions to offer in code action suggestions.
const MAX_CODE_ACTION_VERSIONS: usize = 5;

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
/// # #[derive(Clone)] struct MyVersion { version: String, yanked: bool }
/// # impl deps_core::VersionInfo for MyVersion {
/// #     fn version_string(&self) -> &str { &self.version }
/// #     fn is_yanked(&self) -> bool { self.yanked }
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
///     type UnifiedDep = MyDependency; // In real implementation, this would be UnifiedDependency enum
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
///     fn extract_dependency(dep: &Self::UnifiedDep) -> Option<&Self::Dependency> {
///         // In real implementation, match on the enum variant
///         Some(dep)
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
///
///     fn format_version_for_edit(_dep: &Self::Dependency, version: &str) -> String {
///         format!("\"{}\"", version)
///     }
///
///     fn is_deprecated(version: &MyVersion) -> bool {
///         version.yanked
///     }
///
///     fn is_valid_version_syntax(_version_req: &str) -> bool {
///         true
///     }
///
///     fn parse_version_req(version_req: &str) -> Option<String> {
///         Some(version_req.to_string())
///     }
/// }
/// ```
#[async_trait]
pub trait EcosystemHandler: Send + Sync + Sized {
    /// Registry type for this ecosystem.
    type Registry: PackageRegistry + Clone;

    /// Dependency type for this ecosystem.
    type Dependency: DependencyInfo;

    /// Unified dependency type (typically deps_lsp::document::UnifiedDependency).
    ///
    /// This is an associated type to avoid unsafe transmute when extracting
    /// ecosystem-specific dependencies from the unified enum.
    type UnifiedDep;

    /// Create a new handler with the given cache.
    fn new(cache: Arc<HttpCache>) -> Self;

    /// Get the registry instance.
    fn registry(&self) -> &Self::Registry;

    /// Extract typed dependency from a unified dependency enum.
    ///
    /// Returns Some if the unified dependency matches this handler's ecosystem,
    /// None otherwise.
    fn extract_dependency(dep: &Self::UnifiedDep) -> Option<&Self::Dependency>;

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

    /// Format a version string for editing in the manifest.
    ///
    /// Different ecosystems have different formatting conventions:
    /// - Cargo: `"1.0.0"` (bare semver)
    /// - npm: `"1.0.0"` (bare version, caret added by package manager)
    /// - PyPI PEP 621: `>=1.0.0` (no quotes in array)
    /// - PyPI Poetry: `"^1.0.0"` (caret in quotes)
    fn format_version_for_edit(dep: &Self::Dependency, version: &str) -> String;

    /// Check if a version is deprecated/yanked.
    ///
    /// Returns true if the version should be filtered out from suggestions.
    fn is_deprecated(version: &<Self::Registry as PackageRegistry>::Version) -> bool;

    /// Validate version requirement syntax.
    ///
    /// Returns true if the version requirement is valid for this ecosystem.
    /// Used for diagnostic validation (semver for Cargo, PEP 440 for PyPI, etc.)
    fn is_valid_version_syntax(version_req: &str) -> bool;

    /// Parse a version requirement string into the registry's VersionReq type.
    ///
    /// Returns None if the version requirement is invalid.
    fn parse_version_req(
        version_req: &str,
    ) -> Option<<Self::Registry as PackageRegistry>::VersionReq>;

    /// Get lock file provider for this ecosystem.
    ///
    /// Returns `None` if the ecosystem doesn't support lock files.
    /// Default implementation returns `None`.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// // Override in handler implementation:
    /// fn lockfile_provider(&self) -> Option<Arc<dyn LockFileProvider>> {
    ///     Some(Arc::new(MyLockParser))
    /// }
    /// ```
    fn lockfile_provider(&self) -> Option<Arc<dyn crate::lockfile::LockFileProvider>> {
        None
    }
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
/// * `UnifiedVer` - Unified version enum (typically UnifiedVersion from deps-lsp)
///
/// # Arguments
///
/// * `handler` - Ecosystem-specific handler instance
/// * `dependencies` - List of dependencies to process
/// * `cached_versions` - Previously cached version information
/// * `resolved_versions` - Resolved versions from lock file
/// * `config` - Display configuration
///
/// # Returns
///
/// Vector of inlay hints for the LSP client.
pub async fn generate_inlay_hints<H, UnifiedVer>(
    handler: &H,
    dependencies: &[H::UnifiedDep],
    cached_versions: &HashMap<String, UnifiedVer>,
    resolved_versions: &HashMap<String, String>,
    config: &InlayHintsConfig,
) -> Vec<InlayHint>
where
    H: EcosystemHandler,
    UnifiedVer: VersionStringGetter + YankedChecker,
{
    let mut cached_deps = Vec::with_capacity(dependencies.len());
    let mut fetch_deps = Vec::with_capacity(dependencies.len());

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

    for (name, version_req, version_range, latest_version, is_yanked) in cached_deps {
        if is_yanked {
            continue;
        }
        // Use resolved version from lock file if available, otherwise fall back to requirement
        let version_to_compare = resolved_versions
            .get(&name)
            .map(String::as_str)
            .unwrap_or(&version_req);
        let is_latest = H::is_version_latest(version_to_compare, &latest_version);
        hints.push(create_hint::<H>(
            &name,
            version_range,
            &latest_version,
            is_latest,
            config,
        ));
    }

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
            tracing::warn!("No non-yanked versions found for '{}'", name);
            continue;
        };

        // Use resolved version from lock file if available, otherwise fall back to requirement
        let version_to_compare = resolved_versions
            .get(&name)
            .map(String::as_str)
            .unwrap_or(&version_req);
        let is_latest = H::is_version_latest(version_to_compare, latest.version_string());
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

#[inline]
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
///
/// # Arguments
///
/// * `handler` - Ecosystem handler instance
/// * `dep` - Dependency to generate hover for
/// * `resolved_version` - Optional resolved version from lock file (preferred over manifest version)
pub async fn generate_hover<H>(
    handler: &H,
    dep: &H::UnifiedDep,
    resolved_version: Option<&str>,
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

    if let Some(version) = resolved_version.or(typed_dep.version_requirement()) {
        markdown.push_str(&format!("**Current**: `{}`\n\n", version));
    }

    if latest.is_yanked() {
        markdown.push_str("⚠️ **Warning**: This version has been yanked\n\n");
    }

    markdown.push_str("**Versions** *(use Cmd+. to update)*:\n");
    for (i, version) in versions.iter().take(MAX_VERSIONS_IN_HOVER).enumerate() {
        if i == 0 {
            markdown.push_str(&format!("- {} *(latest)*\n", version.version_string()));
        } else {
            markdown.push_str(&format!("- {}\n", version.version_string()));
        }
    }
    if versions.len() > MAX_VERSIONS_IN_HOVER {
        markdown.push_str(&format!(
            "- *...and {} more*\n",
            versions.len() - MAX_VERSIONS_IN_HOVER
        ));
    }

    let features = latest.features();
    if !features.is_empty() {
        markdown.push_str("\n**Features**:\n");
        for feature in features.iter().take(MAX_FEATURES_IN_HOVER) {
            markdown.push_str(&format!("- `{}`\n", feature));
        }
        if features.len() > MAX_FEATURES_IN_HOVER {
            markdown.push_str(&format!(
                "- *...and {} more*\n",
                features.len() - MAX_FEATURES_IN_HOVER
            ));
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

/// Configuration for diagnostics display.
///
/// This is a simplified version to avoid circular dependencies.
pub struct DiagnosticsConfig {
    pub unknown_severity: tower_lsp::lsp_types::DiagnosticSeverity,
    pub yanked_severity: tower_lsp::lsp_types::DiagnosticSeverity,
    pub outdated_severity: tower_lsp::lsp_types::DiagnosticSeverity,
}

impl Default for DiagnosticsConfig {
    fn default() -> Self {
        use tower_lsp::lsp_types::DiagnosticSeverity;
        Self {
            unknown_severity: DiagnosticSeverity::WARNING,
            yanked_severity: DiagnosticSeverity::WARNING,
            outdated_severity: DiagnosticSeverity::HINT,
        }
    }
}

/// Generic code actions generator.
///
/// Fetches available versions and generates "Update to version X" quick fixes.
///
/// # Type Parameters
///
/// * `H` - Ecosystem handler type
///
/// # Arguments
///
/// * `handler` - Ecosystem-specific handler instance
/// * `dependencies` - List of dependencies with version ranges
/// * `uri` - Document URI
/// * `selected_range` - Range selected by user for code actions
///
/// # Returns
///
/// Vector of code actions (quick fixes) for the LSP client.
pub async fn generate_code_actions<H>(
    handler: &H,
    dependencies: &[H::UnifiedDep],
    uri: &tower_lsp::lsp_types::Url,
    selected_range: Range,
) -> Vec<tower_lsp::lsp_types::CodeActionOrCommand>
where
    H: EcosystemHandler,
{
    use tower_lsp::lsp_types::{
        CodeAction, CodeActionKind, CodeActionOrCommand, TextEdit, WorkspaceEdit,
    };

    let mut deps_to_check = Vec::new();
    for dep in dependencies {
        let Some(typed_dep) = H::extract_dependency(dep) else {
            continue;
        };

        let Some(version_range) = typed_dep.version_range() else {
            continue;
        };

        // Check if this dependency's version range overlaps with cursor position
        if !ranges_overlap(version_range, selected_range) {
            continue;
        }

        deps_to_check.push((typed_dep, version_range));
    }

    if deps_to_check.is_empty() {
        return vec![];
    }

    let registry = handler.registry().clone();
    let futures: Vec<_> = deps_to_check
        .iter()
        .map(|(dep, version_range)| {
            let name = dep.name().to_string();
            let version_range = *version_range;
            let registry = registry.clone();
            async move {
                let versions = registry.get_versions(&name).await;
                (name, dep, version_range, versions)
            }
        })
        .collect();

    let results = join_all(futures).await;

    let mut actions = Vec::new();
    for (name, dep, version_range, versions_result) in results {
        let Ok(versions) = versions_result else {
            tracing::warn!("Failed to fetch versions for {}", name);
            continue;
        };

        for (i, version) in versions
            .iter()
            .filter(|v| !H::is_deprecated(v))
            .take(MAX_CODE_ACTION_VERSIONS)
            .enumerate()
        {
            let new_text = H::format_version_for_edit(dep, version.version_string());

            let mut edits = std::collections::HashMap::new();
            edits.insert(
                uri.clone(),
                vec![TextEdit {
                    range: version_range,
                    new_text,
                }],
            );

            let title = if i == 0 {
                format!("Update {} to {} (latest)", name, version.version_string())
            } else {
                format!("Update {} to {}", name, version.version_string())
            };

            actions.push(CodeActionOrCommand::CodeAction(CodeAction {
                title,
                kind: Some(CodeActionKind::REFACTOR),
                edit: Some(WorkspaceEdit {
                    changes: Some(edits),
                    ..Default::default()
                }),
                is_preferred: Some(i == 0),
                ..Default::default()
            }));
        }
    }

    actions
}

fn ranges_overlap(a: Range, b: Range) -> bool {
    !(a.end.line < b.start.line
        || (a.end.line == b.start.line && a.end.character < b.start.character)
        || b.end.line < a.start.line
        || (b.end.line == a.start.line && b.end.character < a.start.character))
}

/// Generic diagnostics generator.
///
/// Checks dependencies for issues:
/// - Unknown packages (not found in registry)
/// - Invalid version syntax
/// - Yanked/deprecated versions
/// - Outdated versions
///
/// # Type Parameters
///
/// * `H` - Ecosystem handler type
///
/// # Arguments
///
/// * `handler` - Ecosystem-specific handler instance
/// * `dependencies` - List of dependencies to check
/// * `config` - Diagnostic severity configuration
///
/// # Returns
///
/// Vector of LSP diagnostics.
pub async fn generate_diagnostics<H>(
    handler: &H,
    dependencies: &[H::UnifiedDep],
    config: &DiagnosticsConfig,
) -> Vec<tower_lsp::lsp_types::Diagnostic>
where
    H: EcosystemHandler,
{
    use tower_lsp::lsp_types::{Diagnostic, DiagnosticSeverity};

    let mut deps_to_check = Vec::new();
    for dep in dependencies {
        let Some(typed_dep) = H::extract_dependency(dep) else {
            continue;
        };
        deps_to_check.push(typed_dep);
    }

    if deps_to_check.is_empty() {
        return vec![];
    }

    let registry = handler.registry().clone();
    let futures: Vec<_> = deps_to_check
        .iter()
        .map(|dep| {
            let name = dep.name().to_string();
            let registry = registry.clone();
            async move {
                let versions = registry.get_versions(&name).await;
                (name, versions)
            }
        })
        .collect();

    let version_results = join_all(futures).await;

    let mut diagnostics = Vec::new();

    for (i, dep) in deps_to_check.iter().enumerate() {
        let (name, version_result) = &version_results[i];

        let versions = match version_result {
            Ok(v) => v,
            Err(_) => {
                diagnostics.push(Diagnostic {
                    range: dep.name_range(),
                    severity: Some(config.unknown_severity),
                    message: format!("Unknown package '{}'", name),
                    source: Some("deps-lsp".into()),
                    ..Default::default()
                });
                continue;
            }
        };

        if let Some(version_req) = dep.version_requirement()
            && let Some(version_range) = dep.version_range()
        {
            let Some(parsed_version_req) = H::parse_version_req(version_req) else {
                diagnostics.push(Diagnostic {
                    range: version_range,
                    severity: Some(DiagnosticSeverity::ERROR),
                    message: format!("Invalid version requirement '{}'", version_req),
                    source: Some("deps-lsp".into()),
                    ..Default::default()
                });
                continue;
            };

            let matching = handler
                .registry()
                .get_latest_matching(name, &parsed_version_req)
                .await
                .ok()
                .flatten();

            if let Some(current) = &matching
                && H::is_deprecated(current)
            {
                diagnostics.push(Diagnostic {
                    range: version_range,
                    severity: Some(config.yanked_severity),
                    message: "This version has been yanked".into(),
                    source: Some("deps-lsp".into()),
                    ..Default::default()
                });
            }

            let latest = versions.iter().find(|v| !H::is_deprecated(v));
            if let (Some(latest), Some(current)) = (latest, &matching)
                && latest.version_string() != current.version_string()
            {
                diagnostics.push(Diagnostic {
                    range: version_range,
                    severity: Some(config.outdated_severity),
                    message: format!("Newer version available: {}", latest.version_string()),
                    source: Some("deps-lsp".into()),
                    ..Default::default()
                });
            }
        }
    }

    diagnostics
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::PackageMetadata;
    use tower_lsp::lsp_types::{Position, Range};

    #[derive(Clone)]
    struct MockVersion {
        version: String,
        yanked: bool,
        features: Vec<String>,
    }

    impl VersionInfo for MockVersion {
        fn version_string(&self) -> &str {
            &self.version
        }

        fn is_yanked(&self) -> bool {
            self.yanked
        }

        fn features(&self) -> Vec<String> {
            self.features.clone()
        }
    }

    #[derive(Clone)]
    struct MockMetadata {
        name: String,
        description: Option<String>,
        latest: String,
    }

    impl PackageMetadata for MockMetadata {
        fn name(&self) -> &str {
            &self.name
        }

        fn description(&self) -> Option<&str> {
            self.description.as_deref()
        }

        fn repository(&self) -> Option<&str> {
            None
        }

        fn documentation(&self) -> Option<&str> {
            None
        }

        fn latest_version(&self) -> &str {
            &self.latest
        }
    }

    #[derive(Clone)]
    struct MockDependency {
        name: String,
        version_req: Option<String>,
        version_range: Option<Range>,
        name_range: Range,
    }

    impl crate::parser::DependencyInfo for MockDependency {
        fn name(&self) -> &str {
            &self.name
        }

        fn name_range(&self) -> Range {
            self.name_range
        }

        fn version_requirement(&self) -> Option<&str> {
            self.version_req.as_deref()
        }

        fn version_range(&self) -> Option<Range> {
            self.version_range
        }

        fn source(&self) -> crate::parser::DependencySource {
            crate::parser::DependencySource::Registry
        }
    }

    struct MockRegistry {
        versions: std::collections::HashMap<String, Vec<MockVersion>>,
    }

    impl Clone for MockRegistry {
        fn clone(&self) -> Self {
            Self {
                versions: self.versions.clone(),
            }
        }
    }

    #[async_trait]
    impl crate::registry::PackageRegistry for MockRegistry {
        type Version = MockVersion;
        type Metadata = MockMetadata;
        type VersionReq = String;

        async fn get_versions(&self, name: &str) -> crate::error::Result<Vec<Self::Version>> {
            self.versions.get(name).cloned().ok_or_else(|| {
                use std::io::{Error as IoError, ErrorKind};
                crate::DepsError::Io(IoError::new(ErrorKind::NotFound, "package not found"))
            })
        }

        async fn get_latest_matching(
            &self,
            name: &str,
            req: &Self::VersionReq,
        ) -> crate::error::Result<Option<Self::Version>> {
            Ok(self
                .versions
                .get(name)
                .and_then(|versions| versions.iter().find(|v| v.version == *req).cloned()))
        }

        async fn search(
            &self,
            _query: &str,
            _limit: usize,
        ) -> crate::error::Result<Vec<Self::Metadata>> {
            Ok(vec![])
        }
    }

    struct MockHandler {
        registry: MockRegistry,
    }

    #[async_trait]
    impl EcosystemHandler for MockHandler {
        type Registry = MockRegistry;
        type Dependency = MockDependency;
        type UnifiedDep = MockDependency;

        fn new(_cache: Arc<HttpCache>) -> Self {
            let mut versions = std::collections::HashMap::new();
            versions.insert(
                "serde".to_string(),
                vec![
                    MockVersion {
                        version: "1.0.195".to_string(),
                        yanked: false,
                        features: vec!["derive".to_string(), "alloc".to_string()],
                    },
                    MockVersion {
                        version: "1.0.194".to_string(),
                        yanked: false,
                        features: vec![],
                    },
                ],
            );
            versions.insert(
                "yanked-pkg".to_string(),
                vec![MockVersion {
                    version: "1.0.0".to_string(),
                    yanked: true,
                    features: vec![],
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
            Some(dep)
        }

        fn package_url(name: &str) -> String {
            format!("https://test.io/pkg/{}", name)
        }

        fn ecosystem_display_name() -> &'static str {
            "Test Registry"
        }

        fn is_version_latest(version_req: &str, latest: &str) -> bool {
            version_req == latest
        }

        fn format_version_for_edit(_dep: &Self::Dependency, version: &str) -> String {
            format!("\"{}\"", version)
        }

        fn is_deprecated(version: &MockVersion) -> bool {
            version.yanked
        }

        fn is_valid_version_syntax(_version_req: &str) -> bool {
            true
        }

        fn parse_version_req(version_req: &str) -> Option<String> {
            Some(version_req.to_string())
        }
    }

    impl VersionStringGetter for MockVersion {
        fn version_string(&self) -> &str {
            &self.version
        }
    }

    impl YankedChecker for MockVersion {
        fn is_yanked(&self) -> bool {
            self.yanked
        }
    }

    #[test]
    fn test_inlay_hints_config_default() {
        let config = InlayHintsConfig::default();
        assert!(config.enabled);
        assert_eq!(config.up_to_date_text, "✅");
        assert_eq!(config.needs_update_text, "❌ {}");
    }

    #[tokio::test]
    async fn test_generate_inlay_hints_cached() {
        let cache = Arc::new(HttpCache::new());
        let handler = MockHandler::new(cache);

        let deps = vec![MockDependency {
            name: "serde".to_string(),
            version_req: Some("1.0.195".to_string()),
            version_range: Some(Range {
                start: Position {
                    line: 0,
                    character: 10,
                },
                end: Position {
                    line: 0,
                    character: 20,
                },
            }),
            name_range: Range::default(),
        }];

        let mut cached_versions = HashMap::new();
        cached_versions.insert(
            "serde".to_string(),
            MockVersion {
                version: "1.0.195".to_string(),
                yanked: false,
                features: vec![],
            },
        );

        let config = InlayHintsConfig::default();
        let resolved_versions: HashMap<String, String> = HashMap::new();
        let hints = generate_inlay_hints(
            &handler,
            &deps,
            &cached_versions,
            &resolved_versions,
            &config,
        )
        .await;

        assert_eq!(hints.len(), 1);
        assert_eq!(hints[0].position.line, 0);
        assert_eq!(hints[0].position.character, 20);
    }

    #[tokio::test]
    async fn test_generate_inlay_hints_fetch() {
        let cache = Arc::new(HttpCache::new());
        let handler = MockHandler::new(cache);

        let deps = vec![MockDependency {
            name: "serde".to_string(),
            version_req: Some("1.0.0".to_string()),
            version_range: Some(Range {
                start: Position {
                    line: 0,
                    character: 10,
                },
                end: Position {
                    line: 0,
                    character: 20,
                },
            }),
            name_range: Range::default(),
        }];

        let cached_versions: HashMap<String, MockVersion> = HashMap::new();
        let config = InlayHintsConfig::default();
        let resolved_versions: HashMap<String, String> = HashMap::new();
        let hints = generate_inlay_hints(
            &handler,
            &deps,
            &cached_versions,
            &resolved_versions,
            &config,
        )
        .await;

        assert_eq!(hints.len(), 1);
    }

    #[tokio::test]
    async fn test_generate_inlay_hints_skips_yanked() {
        let cache = Arc::new(HttpCache::new());
        let handler = MockHandler::new(cache);

        let deps = vec![MockDependency {
            name: "serde".to_string(),
            version_req: Some("1.0.195".to_string()),
            version_range: Some(Range {
                start: Position {
                    line: 0,
                    character: 10,
                },
                end: Position {
                    line: 0,
                    character: 20,
                },
            }),
            name_range: Range::default(),
        }];

        let mut cached_versions = HashMap::new();
        cached_versions.insert(
            "serde".to_string(),
            MockVersion {
                version: "1.0.195".to_string(),
                yanked: true,
                features: vec![],
            },
        );

        let config = InlayHintsConfig::default();
        let resolved_versions: HashMap<String, String> = HashMap::new();
        let hints = generate_inlay_hints(
            &handler,
            &deps,
            &cached_versions,
            &resolved_versions,
            &config,
        )
        .await;

        assert_eq!(hints.len(), 0);
    }

    #[tokio::test]
    async fn test_generate_inlay_hints_no_version_range() {
        let cache = Arc::new(HttpCache::new());
        let handler = MockHandler::new(cache);

        let deps = vec![MockDependency {
            name: "serde".to_string(),
            version_req: Some("1.0.195".to_string()),
            version_range: None,
            name_range: Range::default(),
        }];

        let cached_versions: HashMap<String, MockVersion> = HashMap::new();
        let config = InlayHintsConfig::default();
        let resolved_versions: HashMap<String, String> = HashMap::new();
        let hints = generate_inlay_hints(
            &handler,
            &deps,
            &cached_versions,
            &resolved_versions,
            &config,
        )
        .await;

        assert_eq!(hints.len(), 0);
    }

    #[tokio::test]
    async fn test_generate_inlay_hints_no_version_req() {
        let cache = Arc::new(HttpCache::new());
        let handler = MockHandler::new(cache);

        let deps = vec![MockDependency {
            name: "serde".to_string(),
            version_req: None,
            version_range: Some(Range {
                start: Position {
                    line: 0,
                    character: 10,
                },
                end: Position {
                    line: 0,
                    character: 20,
                },
            }),
            name_range: Range::default(),
        }];

        let cached_versions: HashMap<String, MockVersion> = HashMap::new();
        let config = InlayHintsConfig::default();
        let resolved_versions: HashMap<String, String> = HashMap::new();
        let hints = generate_inlay_hints(
            &handler,
            &deps,
            &cached_versions,
            &resolved_versions,
            &config,
        )
        .await;

        assert_eq!(hints.len(), 0);
    }

    #[test]
    fn test_create_hint_up_to_date() {
        let config = InlayHintsConfig::default();
        let range = Range {
            start: Position {
                line: 5,
                character: 10,
            },
            end: Position {
                line: 5,
                character: 20,
            },
        };

        let hint = create_hint::<MockHandler>("serde", range, "1.0.195", true, &config);

        assert_eq!(hint.position, range.end);
        if let InlayHintLabel::LabelParts(parts) = hint.label {
            assert_eq!(parts[0].value, "✅");
        } else {
            panic!("Expected LabelParts");
        }
    }

    #[test]
    fn test_create_hint_needs_update() {
        let config = InlayHintsConfig::default();
        let range = Range {
            start: Position {
                line: 5,
                character: 10,
            },
            end: Position {
                line: 5,
                character: 20,
            },
        };

        let hint = create_hint::<MockHandler>("serde", range, "1.0.200", false, &config);

        assert_eq!(hint.position, range.end);
        if let InlayHintLabel::LabelParts(parts) = hint.label {
            assert_eq!(parts[0].value, "❌ 1.0.200");
        } else {
            panic!("Expected LabelParts");
        }
    }

    #[test]
    fn test_create_hint_custom_config() {
        let config = InlayHintsConfig {
            enabled: true,
            up_to_date_text: "OK".to_string(),
            needs_update_text: "UPDATE: {}".to_string(),
        };
        let range = Range {
            start: Position {
                line: 0,
                character: 0,
            },
            end: Position {
                line: 0,
                character: 10,
            },
        };

        let hint = create_hint::<MockHandler>("test", range, "2.0.0", false, &config);

        if let InlayHintLabel::LabelParts(parts) = hint.label {
            assert_eq!(parts[0].value, "UPDATE: 2.0.0");
        } else {
            panic!("Expected LabelParts");
        }
    }

    #[tokio::test]
    async fn test_generate_hover() {
        let cache = Arc::new(HttpCache::new());
        let handler = MockHandler::new(cache);

        let dep = MockDependency {
            name: "serde".to_string(),
            version_req: Some("1.0.0".to_string()),
            version_range: Some(Range::default()),
            name_range: Range {
                start: Position {
                    line: 0,
                    character: 0,
                },
                end: Position {
                    line: 0,
                    character: 5,
                },
            },
        };

        let hover = generate_hover(&handler, &dep, None).await;

        assert!(hover.is_some());
        let hover = hover.unwrap();

        if let tower_lsp::lsp_types::HoverContents::Markup(content) = hover.contents {
            assert!(content.value.contains("serde"));
            assert!(content.value.contains("1.0.195"));
            assert!(content.value.contains("Current"));
            assert!(content.value.contains("Features"));
            assert!(content.value.contains("derive"));
        } else {
            panic!("Expected Markup content");
        }
    }

    #[tokio::test]
    async fn test_generate_hover_yanked_version() {
        let cache = Arc::new(HttpCache::new());
        let handler = MockHandler::new(cache);

        let dep = MockDependency {
            name: "yanked-pkg".to_string(),
            version_req: Some("1.0.0".to_string()),
            version_range: Some(Range::default()),
            name_range: Range::default(),
        };

        let hover = generate_hover(&handler, &dep, None).await;

        assert!(hover.is_some());
        let hover = hover.unwrap();

        if let tower_lsp::lsp_types::HoverContents::Markup(content) = hover.contents {
            assert!(content.value.contains("Warning"));
            assert!(content.value.contains("yanked"));
        } else {
            panic!("Expected Markup content");
        }
    }

    #[tokio::test]
    async fn test_generate_hover_no_versions() {
        let cache = Arc::new(HttpCache::new());
        let handler = MockHandler::new(cache);

        let dep = MockDependency {
            name: "nonexistent".to_string(),
            version_req: Some("1.0.0".to_string()),
            version_range: Some(Range::default()),
            name_range: Range::default(),
        };

        let hover = generate_hover(&handler, &dep, None).await;
        assert!(hover.is_none());
    }

    #[tokio::test]
    async fn test_generate_hover_no_version_req() {
        let cache = Arc::new(HttpCache::new());
        let handler = MockHandler::new(cache);

        let dep = MockDependency {
            name: "serde".to_string(),
            version_req: None,
            version_range: Some(Range::default()),
            name_range: Range::default(),
        };

        let hover = generate_hover(&handler, &dep, None).await;

        assert!(hover.is_some());
        let hover = hover.unwrap();

        if let tower_lsp::lsp_types::HoverContents::Markup(content) = hover.contents {
            assert!(!content.value.contains("Current"));
        } else {
            panic!("Expected Markup content");
        }
    }

    #[tokio::test]
    async fn test_generate_hover_with_resolved_version() {
        let cache = Arc::new(HttpCache::new());
        let handler = MockHandler::new(cache);

        let dep = MockDependency {
            name: "serde".to_string(),
            version_req: Some("1.0".to_string()), // Manifest has short version
            version_range: Some(Range::default()),
            name_range: Range {
                start: Position {
                    line: 0,
                    character: 0,
                },
                end: Position {
                    line: 0,
                    character: 5,
                },
            },
        };

        // Pass resolved version from lock file (full version)
        let hover = generate_hover(&handler, &dep, Some("1.0.195")).await;

        assert!(hover.is_some());
        let hover = hover.unwrap();

        if let tower_lsp::lsp_types::HoverContents::Markup(content) = hover.contents {
            // Should show the resolved version (1.0.195) not manifest version (1.0)
            assert!(content.value.contains("**Current**: `1.0.195`"));
            assert!(!content.value.contains("**Current**: `1.0`"));
        } else {
            panic!("Expected Markup content");
        }
    }

    #[tokio::test]
    async fn test_generate_code_actions_empty_when_up_to_date() {
        use tower_lsp::lsp_types::Url;

        let cache = Arc::new(HttpCache::new());
        let handler = MockHandler::new(cache);

        let deps = vec![MockDependency {
            name: "serde".to_string(),
            version_req: Some("1.0.195".to_string()),
            version_range: Some(Range {
                start: Position {
                    line: 0,
                    character: 10,
                },
                end: Position {
                    line: 0,
                    character: 20,
                },
            }),
            name_range: Range::default(),
        }];

        let uri = Url::parse("file:///test/Cargo.toml").unwrap();
        let selected_range = Range {
            start: Position {
                line: 0,
                character: 15,
            },
            end: Position {
                line: 0,
                character: 15,
            },
        };

        let actions = generate_code_actions(&handler, &deps, &uri, selected_range).await;

        assert!(!actions.is_empty());
    }

    #[tokio::test]
    async fn test_generate_code_actions_update_outdated() {
        use tower_lsp::lsp_types::{CodeActionOrCommand, Url};

        let cache = Arc::new(HttpCache::new());
        let handler = MockHandler::new(cache);

        let deps = vec![MockDependency {
            name: "serde".to_string(),
            version_req: Some("1.0.0".to_string()),
            version_range: Some(Range {
                start: Position {
                    line: 0,
                    character: 10,
                },
                end: Position {
                    line: 0,
                    character: 20,
                },
            }),
            name_range: Range::default(),
        }];

        let uri = Url::parse("file:///test/Cargo.toml").unwrap();
        let selected_range = Range {
            start: Position {
                line: 0,
                character: 15,
            },
            end: Position {
                line: 0,
                character: 15,
            },
        };

        let actions = generate_code_actions(&handler, &deps, &uri, selected_range).await;

        assert!(!actions.is_empty());
        assert!(actions.len() <= 5);

        if let CodeActionOrCommand::CodeAction(action) = &actions[0] {
            assert!(action.title.contains("1.0.195"));
            assert!(action.title.contains("latest"));
            assert_eq!(action.is_preferred, Some(true));
        } else {
            panic!("Expected CodeAction");
        }
    }

    #[tokio::test]
    async fn test_generate_code_actions_missing_version_range() {
        use tower_lsp::lsp_types::Url;

        let cache = Arc::new(HttpCache::new());
        let handler = MockHandler::new(cache);

        let deps = vec![MockDependency {
            name: "serde".to_string(),
            version_req: Some("1.0.0".to_string()),
            version_range: None,
            name_range: Range::default(),
        }];

        let uri = Url::parse("file:///test/Cargo.toml").unwrap();
        let selected_range = Range {
            start: Position {
                line: 0,
                character: 15,
            },
            end: Position {
                line: 0,
                character: 15,
            },
        };

        let actions = generate_code_actions(&handler, &deps, &uri, selected_range).await;

        assert_eq!(actions.len(), 0);
    }

    #[tokio::test]
    async fn test_generate_code_actions_no_overlap() {
        use tower_lsp::lsp_types::Url;

        let cache = Arc::new(HttpCache::new());
        let handler = MockHandler::new(cache);

        let deps = vec![MockDependency {
            name: "serde".to_string(),
            version_req: Some("1.0.0".to_string()),
            version_range: Some(Range {
                start: Position {
                    line: 0,
                    character: 10,
                },
                end: Position {
                    line: 0,
                    character: 20,
                },
            }),
            name_range: Range::default(),
        }];

        let uri = Url::parse("file:///test/Cargo.toml").unwrap();
        let selected_range = Range {
            start: Position {
                line: 5,
                character: 0,
            },
            end: Position {
                line: 5,
                character: 10,
            },
        };

        let actions = generate_code_actions(&handler, &deps, &uri, selected_range).await;

        assert_eq!(actions.len(), 0);
    }

    #[tokio::test]
    async fn test_generate_code_actions_filters_deprecated() {
        use tower_lsp::lsp_types::{CodeActionOrCommand, Url};

        let cache = Arc::new(HttpCache::new());
        let handler = MockHandler::new(cache);

        let deps = vec![MockDependency {
            name: "yanked-pkg".to_string(),
            version_req: Some("1.0.0".to_string()),
            version_range: Some(Range {
                start: Position {
                    line: 0,
                    character: 10,
                },
                end: Position {
                    line: 0,
                    character: 20,
                },
            }),
            name_range: Range::default(),
        }];

        let uri = Url::parse("file:///test/Cargo.toml").unwrap();
        let selected_range = Range {
            start: Position {
                line: 0,
                character: 15,
            },
            end: Position {
                line: 0,
                character: 15,
            },
        };

        let actions = generate_code_actions(&handler, &deps, &uri, selected_range).await;

        assert_eq!(actions.len(), 0);

        for action in actions {
            if let CodeActionOrCommand::CodeAction(a) = action {
                assert!(!a.title.contains("1.0.0"));
            }
        }
    }

    #[test]
    fn test_ranges_overlap_basic() {
        let range_a = Range {
            start: Position {
                line: 0,
                character: 10,
            },
            end: Position {
                line: 0,
                character: 20,
            },
        };

        let range_b = Range {
            start: Position {
                line: 0,
                character: 15,
            },
            end: Position {
                line: 0,
                character: 25,
            },
        };

        assert!(ranges_overlap(range_a, range_b));
    }

    #[test]
    fn test_ranges_no_overlap() {
        let range_a = Range {
            start: Position {
                line: 0,
                character: 10,
            },
            end: Position {
                line: 0,
                character: 20,
            },
        };

        let range_b = Range {
            start: Position {
                line: 0,
                character: 25,
            },
            end: Position {
                line: 0,
                character: 30,
            },
        };

        assert!(!ranges_overlap(range_a, range_b));
    }

    #[tokio::test]
    async fn test_generate_diagnostics_valid_version() {
        let cache = Arc::new(HttpCache::new());
        let handler = MockHandler::new(cache);

        let deps = vec![MockDependency {
            name: "serde".to_string(),
            version_req: Some("1.0.195".to_string()),
            version_range: Some(Range {
                start: Position {
                    line: 0,
                    character: 10,
                },
                end: Position {
                    line: 0,
                    character: 20,
                },
            }),
            name_range: Range::default(),
        }];

        let config = DiagnosticsConfig::default();
        let diagnostics = generate_diagnostics(&handler, &deps, &config).await;

        assert_eq!(diagnostics.len(), 0);
    }

    #[tokio::test]
    async fn test_generate_diagnostics_deprecated_version() {
        use tower_lsp::lsp_types::DiagnosticSeverity;

        let cache = Arc::new(HttpCache::new());
        let handler = MockHandler::new(cache);

        let deps = vec![MockDependency {
            name: "yanked-pkg".to_string(),
            version_req: Some("1.0.0".to_string()),
            version_range: Some(Range {
                start: Position {
                    line: 0,
                    character: 10,
                },
                end: Position {
                    line: 0,
                    character: 20,
                },
            }),
            name_range: Range::default(),
        }];

        let config = DiagnosticsConfig::default();
        let diagnostics = generate_diagnostics(&handler, &deps, &config).await;

        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].severity, Some(DiagnosticSeverity::WARNING));
        assert!(diagnostics[0].message.contains("yanked"));
    }

    #[tokio::test]
    async fn test_generate_diagnostics_unknown_package() {
        use tower_lsp::lsp_types::DiagnosticSeverity;

        let cache = Arc::new(HttpCache::new());
        let handler = MockHandler::new(cache);

        let deps = vec![MockDependency {
            name: "nonexistent".to_string(),
            version_req: Some("1.0.0".to_string()),
            version_range: Some(Range {
                start: Position {
                    line: 0,
                    character: 10,
                },
                end: Position {
                    line: 0,
                    character: 20,
                },
            }),
            name_range: Range {
                start: Position {
                    line: 0,
                    character: 0,
                },
                end: Position {
                    line: 0,
                    character: 10,
                },
            },
        }];

        let config = DiagnosticsConfig::default();
        let diagnostics = generate_diagnostics(&handler, &deps, &config).await;

        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].severity, Some(DiagnosticSeverity::WARNING));
        assert!(diagnostics[0].message.contains("Unknown package"));
        assert!(diagnostics[0].message.contains("nonexistent"));
    }

    #[tokio::test]
    async fn test_generate_diagnostics_missing_version() {
        let cache = Arc::new(HttpCache::new());
        let handler = MockHandler::new(cache);

        let deps = vec![MockDependency {
            name: "serde".to_string(),
            version_req: None,
            version_range: None,
            name_range: Range::default(),
        }];

        let config = DiagnosticsConfig::default();
        let diagnostics = generate_diagnostics(&handler, &deps, &config).await;

        assert_eq!(diagnostics.len(), 0);
    }

    #[tokio::test]
    async fn test_generate_diagnostics_outdated_version() {
        use tower_lsp::lsp_types::DiagnosticSeverity;

        let cache = Arc::new(HttpCache::new());
        let mut handler = MockHandler::new(cache);

        handler.registry.versions.insert(
            "outdated-pkg".to_string(),
            vec![
                MockVersion {
                    version: "2.0.0".to_string(),
                    yanked: false,
                    features: vec![],
                },
                MockVersion {
                    version: "1.0.0".to_string(),
                    yanked: false,
                    features: vec![],
                },
            ],
        );

        let deps = vec![MockDependency {
            name: "outdated-pkg".to_string(),
            version_req: Some("1.0.0".to_string()),
            version_range: Some(Range {
                start: Position {
                    line: 0,
                    character: 10,
                },
                end: Position {
                    line: 0,
                    character: 20,
                },
            }),
            name_range: Range::default(),
        }];

        let config = DiagnosticsConfig::default();
        let diagnostics = generate_diagnostics(&handler, &deps, &config).await;

        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].severity, Some(DiagnosticSeverity::HINT));
        assert!(diagnostics[0].message.contains("Newer version available"));
        assert!(diagnostics[0].message.contains("2.0.0"));
    }

    #[test]
    fn test_diagnostics_config_default() {
        use tower_lsp::lsp_types::DiagnosticSeverity;

        let config = DiagnosticsConfig::default();
        assert_eq!(config.unknown_severity, DiagnosticSeverity::WARNING);
        assert_eq!(config.yanked_severity, DiagnosticSeverity::WARNING);
        assert_eq!(config.outdated_severity, DiagnosticSeverity::HINT);
    }
}
