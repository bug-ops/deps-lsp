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
/// * `config` - Display configuration
///
/// # Returns
///
/// Vector of inlay hints for the LSP client.
pub async fn generate_inlay_hints<H, UnifiedVer>(
    handler: &H,
    dependencies: &[H::UnifiedDep],
    cached_versions: &HashMap<String, UnifiedVer>,
    config: &InlayHintsConfig,
) -> Vec<InlayHint>
where
    H: EcosystemHandler,
    UnifiedVer: VersionStringGetter + YankedChecker,
{
    let mut cached_deps = Vec::with_capacity(dependencies.len());
    let mut fetch_deps = Vec::with_capacity(dependencies.len());

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
pub async fn generate_hover<H>(
    handler: &H,
    dep: &H::UnifiedDep,
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
            _req: &Self::VersionReq,
        ) -> crate::error::Result<Option<Self::Version>> {
            Ok(self.versions.get(name).and_then(|v| v.first().cloned()))
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
        let hints = generate_inlay_hints(&handler, &deps, &cached_versions, &config).await;

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
        let hints = generate_inlay_hints(&handler, &deps, &cached_versions, &config).await;

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
        let hints = generate_inlay_hints(&handler, &deps, &cached_versions, &config).await;

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
        let hints = generate_inlay_hints(&handler, &deps, &cached_versions, &config).await;

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
        let hints = generate_inlay_hints(&handler, &deps, &cached_versions, &config).await;

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

        let hover = generate_hover(&handler, &dep).await;

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

        let hover = generate_hover(&handler, &dep).await;

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

        let hover = generate_hover(&handler, &dep).await;
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

        let hover = generate_hover(&handler, &dep).await;

        assert!(hover.is_some());
        let hover = hover.unwrap();

        if let tower_lsp::lsp_types::HoverContents::Markup(content) = hover.contents {
            assert!(!content.value.contains("Current"));
        } else {
            panic!("Expected Markup content");
        }
    }
}
