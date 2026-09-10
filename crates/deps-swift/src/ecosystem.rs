//! Swift ecosystem implementation for deps-lsp.

use std::any::Any;
use std::sync::Arc;
#[cfg(test)]
use tower_lsp_server::ls_types::Position;
use tower_lsp_server::ls_types::{
    CompletionItem, CompletionTextEdit, Range as LspRange, TextEdit, Uri,
};

use deps_core::{
    Ecosystem, ParseResult as ParseResultTrait, Registry, Result,
    completion::Completions,
    is_safe_registry_url,
    lsp_helpers::{EcosystemFormatter, warn_rejected_value},
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
/// Returns `None` when `url` doesn't pass [`is_safe_registry_url`], or when the base
/// builder itself rejects `package.name` — a malicious/compromised search result must
/// not reach the manifest as an unsanitized `TextEdit`, so the item is dropped rather
/// than built with unsafe text.
fn build_url_completion(
    package: &SwiftPackage,
    replace_range: Option<LspRange>,
) -> Option<CompletionItem> {
    let url = package
        .repository
        .clone()
        .unwrap_or_else(|| format!("https://github.com/{}", package.name));

    if !is_safe_registry_url(&url) {
        warn_rejected_value("is_safe_registry_url", "swift url completion", &url);
        return None;
    }

    let mut item = deps_core::completion::build_package_completion(package, LspRange::default())?;

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
    fn ecosystem_id(&self) -> deps_core::EcosystemId {
        deps_core::EcosystemId::Swift
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

    fn complete_package_name<'a>(
        &'a self,
        _request: deps_core::completion::CompletionRequest<'a>,
        prefix: String,
        range: LspRange,
    ) -> deps_core::ecosystem::BoxFuture<'a, Completions> {
        // The completion context only fires with the cursor inside an existing
        // dependency's url: "..." literal (see module docs), so `range` (the
        // dependency's `name_range()`, computed by `detect_completion_context`)
        // is already the exact span the completion must replace.
        Box::pin(async move {
            self.complete_package_urls(strip_github_prefix(&prefix), Some(range))
                .await
                .into()
        })
    }

    fn complete_version<'a>(
        &'a self,
        request: deps_core::completion::CompletionRequest<'a>,
        package_name: deps_core::PackageName,
        prefix: String,
    ) -> deps_core::ecosystem::BoxFuture<'a, Completions> {
        Box::pin(async move {
            self.complete_versions(&package_name, &prefix, request.freshness)
                .await
                .into()
        })
    }

    fn completion_insert_text(&self, metadata: &dyn deps_core::Metadata) -> Option<String> {
        let name = metadata.name();
        let latest = metadata.latest_version().as_str();
        let url = metadata
            .repository()
            .map_or_else(|| format!("https://github.com/{name}"), str::to_string);
        if !is_safe_registry_url(&url) {
            warn_rejected_value(
                "is_safe_registry_url",
                "swift package name completion item",
                &url,
            );
            return None;
        }
        if latest.is_empty() {
            Some(format!(".package(url: \"{url}\")"))
        } else {
            Some(format!(".package(url: \"{url}\", from: \"{latest}\")"))
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    /// Fetches `name`'s (`owner/repo`) SPDX license identifier from GitHub (issue
    /// #660/#688) — `version` is unused, since GitHub's `GET /repos/{owner}/{repo}`
    /// reflects the repository's default branch, not a resolved tag. See
    /// [`crate::registry::SwiftRegistry::get_license`].
    fn fetch_license<'a>(
        &'a self,
        name: &'a str,
        _version: &'a str,
    ) -> deps_core::ecosystem::BoxFuture<'a, Vec<String>> {
        Box::pin(self.registry.get_license(name))
    }

    /// GitHub's `license.spdx_id` is `licensee` detector output on the repo's default
    /// branch, not an author-declared registry field — see
    /// [`deps_core::LicenseSource::DetectedSpdx`].
    fn license_source(&self) -> deps_core::LicenseSource {
        deps_core::LicenseSource::DetectedSpdx
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
            latest_version: deps_core::ConcreteVersion::new(""),
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
        assert!(package.latest_version.as_str().is_empty());
        let item = build_url_completion(&package, None).unwrap();

        assert_eq!(item.detail, None);
    }

    #[test]
    fn test_build_url_completion_keeps_detail_when_latest_version_present() {
        let mut package = test_package(Some("https://github.com/apple/swift-nio"));
        package.latest_version = "2.40.0".into();
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
    fn test_build_url_completion_rejects_when_base_builder_rejects_name() {
        // `repository` is a safe URL (passes `is_safe_registry_url`), but
        // `package.name` fails `is_safe_package_name` (space, quote) — the base
        // builder must reject it, and that rejection must propagate through
        // `build_url_completion` even though the URL itself is fine.
        let mut package = test_package(Some("https://github.com/apple/swift-nio"));
        package.name = "apple swift-nio\" evil".to_string().into();

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

    // #758: exact-value `Ecosystem` conformance, replacing test_ecosystem_id,
    // test_ecosystem_display_name, test_manifest_filenames, and test_as_any.
    deps_core::ecosystem_conformance! {
        mod swift_ecosystem_conformance;
        build: SwiftEcosystem::new(Arc::new(deps_core::HttpCache::new()));
        ty: SwiftEcosystem;
        id: "swift";
        display_name: "Swift (SPM)";
        manifest_filenames: &["Package.swift"];
        lockfile_filenames: &["Package.resolved"];
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

    /// `Package.swift` dependencies are `.package(...)` calls matched anywhere in the
    /// file, not confined to a `dependencies: [...]` array — no raw-text section
    /// boundary, so no override.
    #[test]
    fn test_fallback_completion_prefix_default_none() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = SwiftEcosystem::new(cache);
        assert!(
            eco.fallback_completion_prefix("anything at all\n", Position::new(0, 0))
                .is_none()
        );
    }

    struct MockMetadata {
        name: deps_core::PackageName,
        repository: Option<&'static str>,
        latest_version: deps_core::ConcreteVersion,
    }
    impl deps_core::Metadata for MockMetadata {
        fn name(&self) -> &deps_core::PackageName {
            &self.name
        }
        fn description(&self) -> Option<&str> {
            None
        }
        fn repository(&self) -> Option<&str> {
            self.repository
        }
        fn documentation(&self) -> Option<&str> {
            None
        }
        fn latest_version(&self) -> &deps_core::ConcreteVersion {
            &self.latest_version
        }
        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    #[test]
    fn test_completion_insert_text_with_repository() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = SwiftEcosystem::new(cache);
        let meta = MockMetadata {
            name: deps_core::PackageName::new("apple/swift-nio"),
            repository: Some("https://github.com/apple/swift-nio"),
            latest_version: "2.62.0".into(),
        };
        assert_eq!(
            eco.completion_insert_text(&meta),
            Some(
                ".package(url: \"https://github.com/apple/swift-nio\", from: \"2.62.0\")"
                    .to_string()
            )
        );
    }

    #[test]
    fn test_completion_insert_text_empty_latest_omits_from_clause() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = SwiftEcosystem::new(cache);
        let meta = MockMetadata {
            name: deps_core::PackageName::new("apple/swift-nio"),
            repository: Some("https://github.com/apple/swift-nio"),
            latest_version: "".into(),
        };
        assert_eq!(
            eco.completion_insert_text(&meta),
            Some(".package(url: \"https://github.com/apple/swift-nio\")".to_string())
        );
    }

    #[test]
    fn test_completion_insert_text_no_repository_falls_back_to_name() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = SwiftEcosystem::new(cache);
        let meta = MockMetadata {
            name: deps_core::PackageName::new("apple/swift-nio"),
            repository: None,
            latest_version: "2.62.0".into(),
        };
        assert_eq!(
            eco.completion_insert_text(&meta),
            Some(
                ".package(url: \"https://github.com/apple/swift-nio\", from: \"2.62.0\")"
                    .to_string()
            )
        );
    }

    #[test]
    fn test_completion_insert_text_rejects_string_literal_breakout_repository() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = SwiftEcosystem::new(cache);
        let meta = MockMetadata {
            name: deps_core::PackageName::new("apple/swift-nio"),
            repository: Some(
                "https://evil.example\", .exact(\"1.0.0\")), .package(url: \"https://real",
            ),
            latest_version: "2.62.0".into(),
        };
        assert!(eco.completion_insert_text(&meta).is_none());
    }

    // --- #793 characterization: `generate_completions` dispatch, pinned before the
    // wildcard-match refactor.

    /// #793 S1/M8: pins that the `PackageName` arm strips the `https://github.com/` scheme
    /// off the raw prefix *before* the length guard runs — a migration that dropped or
    /// reordered `strip_github_prefix` would turn this deterministic empty result into a
    /// (still deterministic, but wrong) non-empty one, or vice versa.
    #[tokio::test]
    async fn test_generate_completions_package_name_context_strips_github_prefix_before_dispatch() {
        // `let x = "https://github.com/a"` — name_range spans the quoted content
        // (excluding quotes), byte-for-byte (ASCII, so UTF-16 offsets equal byte offsets).
        let content = "let x = \"https://github.com/a\"";
        let name_range = LspRange::new(Position::new(0, 9), Position::new(0, 29));
        let dep = crate::types::SwiftDependency {
            name: "unresolved/a".into(),
            name_range,
            version_req: None,
            version_range: None,
            version_literal: None,
            url: "https://github.com/a".to_string(),
            source: deps_core::parser::DependencySource::Registry,
        };
        let uri = deps_core::test_util::test_uri("/test/Package.swift");
        let parse_result = crate::types::SwiftParseResult {
            dependencies: vec![dep],
            uri,
        };
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = SwiftEcosystem::new(cache);

        // Cursor right after "a" — inside the name range, one prefix character past the
        // stripped scheme, below `is_valid_completion_prefix_len`'s 2-char minimum.
        let result = eco
            .generate_completions(
                &parse_result,
                Position::new(0, 29),
                content,
                deps_core::FreshnessSettings::default(),
            )
            .await;
        assert_eq!(result, Completions::default());
    }

    /// #793 S1: the `Feature` and `None` contexts (swift has no feature-flag syntax) must
    /// still fall through to an untouched empty result.
    #[tokio::test]
    async fn test_generate_completions_none_context_returns_empty() {
        let uri = deps_core::test_util::test_uri("/test/Package.swift");
        let parse_result = crate::types::SwiftParseResult {
            dependencies: vec![],
            uri,
        };
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = SwiftEcosystem::new(cache);

        let result = eco
            .generate_completions(
                &parse_result,
                Position::new(0, 0),
                "",
                deps_core::FreshnessSettings::default(),
            )
            .await;
        assert_eq!(result, Completions::default());
    }

    /// #793 S1 gap (flagged in review): the `Version` context had zero coverage —
    /// `complete_versions` has no offline guard and `SwiftRegistry` has no test-mockable
    /// constructor (unlike `deps_github_actions::registry::GithubActionsRegistry::
    /// for_test`), so this needs live GitHub API access. `#[ignore]`d rather than routed
    /// through an "unknown package" 404 (this crate's own convention, see
    /// `registry::tests::test_fetch_real_versions`) — an unauthenticated GitHub API call has
    /// a much tighter rate limit than crates.io/pub.dev/rubygems.org, so this crate never
    /// runs one un-ignored.
    #[tokio::test]
    #[ignore] // Requires network access
    async fn test_generate_completions_version_context_dispatches_to_registry() {
        let name_range = LspRange::new(Position::new(0, 9), Position::new(0, 40));
        let dep = crate::types::SwiftDependency {
            name: "apple/swift-nio".into(),
            name_range,
            version_req: Some("1.0.0".into()),
            version_range: Some(LspRange::new(Position::new(1, 0), Position::new(1, 5))),
            version_literal: None,
            url: "https://github.com/apple/swift-nio".to_string(),
            source: deps_core::parser::DependencySource::Registry,
        };
        let uri = deps_core::test_util::test_uri("/test/Package.swift");
        let parse_result = crate::types::SwiftParseResult {
            dependencies: vec![dep],
            uri,
        };
        let content = "let x = \"https://github.com/apple/swift-nio\"\n2.0.0";
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = SwiftEcosystem::new(cache);
        let freshness = deps_core::FreshnessSettings::default();
        let position = Position::new(1, 3);

        let context =
            deps_core::completion::detect_completion_context(&parse_result, position, content);
        let deps_core::completion::CompletionContext::Version {
            package_name,
            prefix,
        } = context
        else {
            panic!("expected Version context, got {context:?}");
        };
        let direct = eco
            .complete_versions(&package_name, &prefix, freshness)
            .await;
        let via_dispatch = eco
            .generate_completions(&parse_result, position, content, freshness)
            .await;
        // Route equivalence, not a specific live-data assertion: the point is that
        // `generate_completions`'s `Version` arm threads the same `package_name`/`prefix`
        // to the same `complete_versions` call the pre-#793 match did — not what GitHub's
        // API happens to return for `apple/swift-nio` today (a real GitHub API round trip,
        // subject to its own rate limiting).
        assert_eq!(via_dispatch.items, direct);
    }
}
