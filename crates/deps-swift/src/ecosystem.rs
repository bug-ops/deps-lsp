//! Swift ecosystem implementation for deps-lsp.

use std::any::Any;
use std::sync::Arc;
use tower_lsp_server::ls_types::{
    CompletionItem, CompletionTextEdit, Position, Range as LspRange, TextEdit, Uri,
};

use deps_core::{
    Ecosystem, ParseResult as ParseResultTrait, Registry, Result, is_safe_registry_url,
    lsp_helpers::EcosystemFormatter,
};

use crate::formatter::SwiftFormatter;
use crate::lockfile::SwiftLockParser;
use crate::registry::SwiftRegistry;
use crate::types::SwiftPackage;

/// Builds a completion item that inserts the full GitHub URL for `.package(url: "...")`.
///
/// The completion fires with the cursor inside the `url:` string literal (see
/// [`SwiftEcosystem::generate_completions`]), so the insertable text must always be a
/// full URL — never the bare `owner/repo` identity — regardless of how much of the
/// scheme the user has typed so far. `replace_range` should be the dependency's
/// `name_range()` (the byte span of the whole URL literal) whenever the caller can resolve
/// it — the base builder's own range is a placeholder `(0,0)-(0,0)` that does not contain
/// the real cursor position and would corrupt the document if used as-is. When `None` (the
/// dependency containing the cursor could not be found), falls back to `insert_text`-only
/// — the same safe pattern used by `create_package_completion_item` in `deps-lsp` — rather
/// than guessing a range.
///
/// Returns `None` when `url` doesn't pass [`is_safe_registry_url`] — a
/// malicious/compromised search result must not reach the manifest as an unsanitized
/// `TextEdit`, so the item is dropped rather than built with unsafe text.
fn build_url_completion(
    package: &SwiftPackage,
    replace_range: Option<LspRange>,
) -> Option<CompletionItem> {
    let url = package
        .repository
        .clone()
        .unwrap_or_else(|| format!("https://github.com/{}", package.name));

    if !is_safe_registry_url(&url) {
        return None;
    }

    let mut item = deps_core::completion::build_package_completion(package, LspRange::default());

    item.insert_text = Some(url.clone());
    item.filter_text = Some(url.clone());
    item.sort_text = Some(url.clone());
    item.text_edit = replace_range.map(|range| {
        CompletionTextEdit::Edit(TextEdit {
            range,
            new_text: url,
        })
    });

    Some(item)
}

/// Strips a leading `https://github.com/` (or `https://github.com`) scheme from a
/// completion prefix, leaving the search query GitHub's repository search expects.
fn strip_github_prefix(prefix: &str) -> &str {
    prefix
        .strip_prefix("https://github.com/")
        .or_else(|| prefix.strip_prefix("https://github.com"))
        .unwrap_or(prefix)
}

/// Swift/SPM ecosystem implementation.
///
/// Provides LSP functionality for Package.swift files, including:
/// - Dependency parsing with position tracking
/// - Version information from GitHub tags
/// - Inlay hints for latest versions
/// - Hover tooltips with package metadata
/// - Code actions for version updates
/// - Diagnostics for unknown packages
pub struct SwiftEcosystem {
    registry: Arc<SwiftRegistry>,
    formatter: SwiftFormatter,
    lockfile_provider: Arc<SwiftLockParser>,
}

impl SwiftEcosystem {
    /// Creates a new Swift ecosystem with the given HTTP cache.
    pub fn new(cache: Arc<deps_core::HttpCache>) -> Self {
        Self {
            registry: Arc::new(SwiftRegistry::new(cache)),
            formatter: SwiftFormatter,
            lockfile_provider: Arc::new(SwiftLockParser),
        }
    }

    async fn complete_package_urls(
        &self,
        query: &str,
        replace_range: Option<LspRange>,
    ) -> Vec<CompletionItem> {
        if !deps_core::completion::is_valid_completion_prefix_len(query) {
            return vec![];
        }

        let results = match self.registry.search(query, 20).await {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("Swift registry search failed for '{}': {}", query, e);
                return vec![];
            }
        };

        results
            .iter()
            .filter_map(|package| build_url_completion(package, replace_range))
            .collect()
    }

    async fn complete_versions(
        &self,
        package_name: &deps_core::PackageName,
        prefix: &str,
        freshness: deps_core::FreshnessSettings,
    ) -> Vec<CompletionItem> {
        deps_core::completion::complete_versions_generic(
            self.registry.as_ref(),
            package_name,
            prefix,
            &[],
            freshness,
        )
        .await
    }
}

impl deps_core::ecosystem::private::Sealed for SwiftEcosystem {}

impl Ecosystem for SwiftEcosystem {
    fn id(&self) -> &'static str {
        "swift"
    }

    fn display_name(&self) -> &'static str {
        "Swift (SPM)"
    }

    fn manifest_filenames(&self) -> &[&'static str] {
        &["Package.swift"]
    }

    fn lockfile_filenames(&self) -> &[&'static str] {
        &["Package.resolved"]
    }

    fn parse_manifest<'a>(
        &'a self,
        content: &'a str,
        uri: &'a Uri,
    ) -> deps_core::ecosystem::BoxFuture<'a, Result<Box<dyn ParseResultTrait>>> {
        Box::pin(async move {
            let result = crate::parser::parse_package_swift(content, uri)?;
            Ok(Box::new(result) as Box<dyn ParseResultTrait>)
        })
    }

    fn registry(&self) -> Arc<dyn Registry> {
        self.registry.clone() as Arc<dyn Registry>
    }

    fn lockfile_provider(&self) -> Option<Arc<dyn deps_core::lockfile::LockFileProvider>> {
        Some(self.lockfile_provider.clone() as Arc<dyn deps_core::lockfile::LockFileProvider>)
    }

    fn formatter(&self) -> &dyn EcosystemFormatter {
        &self.formatter
    }

    fn generate_completions<'a>(
        &'a self,
        parse_result: &'a dyn ParseResultTrait,
        position: Position,
        content: &'a str,
        freshness: deps_core::FreshnessSettings,
    ) -> deps_core::ecosystem::BoxFuture<'a, Vec<CompletionItem>> {
        Box::pin(async move {
            use deps_core::completion::{CompletionContext, detect_completion_context};

            let context = detect_completion_context(parse_result, position, content);

            match context {
                CompletionContext::PackageName { prefix, range } => {
                    // The completion context only fires with the cursor inside an existing
                    // dependency's url: "..." literal (see module docs), so `range` (the
                    // dependency's `name_range()`, computed by `detect_completion_context`)
                    // is already the exact span the completion must replace.
                    self.complete_package_urls(strip_github_prefix(&prefix), Some(range))
                        .await
                }
                CompletionContext::Version {
                    package_name,
                    prefix,
                } => {
                    self.complete_versions(&package_name, &prefix, freshness)
                        .await
                }
                CompletionContext::Feature { .. } => vec![],
                CompletionContext::None => vec![],
            }
        })
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_package(repository: Option<&str>) -> SwiftPackage {
        SwiftPackage {
            name: "apple/swift-nio".to_string().into(),
            description: Some("Networking framework".to_string()),
            repository: repository.map(str::to_string),
            homepage: None,
            latest_version: String::new(),
        }
    }

    fn test_range() -> LspRange {
        LspRange {
            start: Position::new(3, 20),
            end: Position::new(3, 45),
        }
    }

    #[test]
    fn test_build_url_completion_uses_repository_url() {
        let package = test_package(Some("https://github.com/apple/swift-nio"));
        let item = build_url_completion(&package, None).unwrap();

        assert_eq!(
            item.insert_text,
            Some("https://github.com/apple/swift-nio".to_string())
        );
    }

    #[test]
    fn test_build_url_completion_falls_back_to_constructed_url() {
        let package = test_package(None);
        let item = build_url_completion(&package, None).unwrap();

        assert_eq!(
            item.insert_text,
            Some("https://github.com/apple/swift-nio".to_string())
        );
    }

    #[test]
    fn test_build_url_completion_with_range_sets_text_edit() {
        let package = test_package(Some("https://github.com/apple/swift-nio"));
        let range = test_range();
        let item = build_url_completion(&package, Some(range)).unwrap();

        assert_eq!(
            item.text_edit,
            Some(CompletionTextEdit::Edit(TextEdit {
                range,
                new_text: "https://github.com/apple/swift-nio".to_string(),
            }))
        );
    }

    #[test]
    fn test_build_url_completion_without_range_has_no_text_edit() {
        // Defensive fallback: when the containing dependency's range can't be resolved,
        // insert_text-only is safer than guessing a range that might not contain the cursor.
        let package = test_package(Some("https://github.com/apple/swift-nio"));
        let item = build_url_completion(&package, None).unwrap();

        assert_eq!(item.text_edit, None);
    }

    #[test]
    fn test_build_url_completion_clears_detail_when_latest_version_empty() {
        let package = test_package(Some("https://github.com/apple/swift-nio"));
        assert!(package.latest_version.is_empty());
        let item = build_url_completion(&package, None).unwrap();

        assert_eq!(item.detail, None);
    }

    #[test]
    fn test_build_url_completion_keeps_detail_when_latest_version_present() {
        let mut package = test_package(Some("https://github.com/apple/swift-nio"));
        package.latest_version = "2.40.0".to_string();
        let item = build_url_completion(&package, None).unwrap();

        assert_eq!(item.detail, Some("v2.40.0".to_string()));
    }

    #[test]
    fn test_build_url_completion_rejects_string_literal_breakout_repository() {
        let package = test_package(Some(
            "https://evil.example\", .exact(\"1.0.0\")), .package(url: \"https://real",
        ));

        assert!(build_url_completion(&package, None).is_none());
    }

    #[test]
    fn test_build_url_completion_rejects_non_http_scheme() {
        let package = test_package(Some("file:///etc/passwd"));

        assert!(build_url_completion(&package, None).is_none());
    }

    #[test]
    fn test_build_url_completion_rejects_malicious_name_in_fallback_url() {
        let mut package = test_package(None);
        package.name = "apple/swift-nio\", .exact(\"1\")) //".to_string().into();

        assert!(build_url_completion(&package, None).is_none());
    }

    #[test]
    fn test_strip_github_prefix_with_trailing_slash() {
        assert_eq!(
            strip_github_prefix("https://github.com/apple/swift-n"),
            "apple/swift-n"
        );
    }

    #[test]
    fn test_strip_github_prefix_without_trailing_slash() {
        assert_eq!(strip_github_prefix("https://github.com"), "");
    }

    #[test]
    fn test_strip_github_prefix_no_scheme_typed_yet() {
        // Cursor is still within the scheme itself (e.g. "htt|"), so nothing to strip —
        // the raw partial text becomes the (short-lived, low-value) search query.
        assert_eq!(strip_github_prefix("htt"), "htt");
    }

    #[test]
    fn test_ecosystem_id() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = SwiftEcosystem::new(cache);
        assert_eq!(eco.id(), "swift");
    }

    #[test]
    fn test_ecosystem_display_name() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = SwiftEcosystem::new(cache);
        assert_eq!(eco.display_name(), "Swift (SPM)");
    }

    #[test]
    fn test_manifest_filenames() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = SwiftEcosystem::new(cache);
        assert_eq!(eco.manifest_filenames(), &["Package.swift"]);
        assert_eq!(eco.lockfile_filenames(), &["Package.resolved"]);
    }

    #[test]
    fn test_as_any() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = SwiftEcosystem::new(cache);
        assert!(eco.as_any().is::<SwiftEcosystem>());
    }

    #[test]
    fn test_lockfile_provider_some() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = SwiftEcosystem::new(cache);
        assert!(eco.lockfile_provider().is_some());
    }

    #[tokio::test]
    async fn test_parse_manifest_valid() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = SwiftEcosystem::new(cache);
        let uri = deps_core::test_util::test_uri("/test/Package.swift");
        let content = r#".package(url: "https://github.com/apple/swift-nio.git", from: "2.40.0")"#;
        let result = eco.parse_manifest(content, &uri).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().dependencies().len(), 1);
    }

    #[tokio::test]
    async fn test_parse_manifest_empty() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = SwiftEcosystem::new(cache);
        let uri = deps_core::test_util::test_uri("/test/Package.swift");
        let result = eco.parse_manifest("// empty file", &uri).await;
        assert!(result.is_ok());
        assert!(result.unwrap().dependencies().is_empty());
    }
}
