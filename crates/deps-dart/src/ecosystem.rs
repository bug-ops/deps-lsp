//! Dart ecosystem implementation for deps-lsp.

use std::any::Any;
use std::sync::Arc;
use tower_lsp_server::ls_types::{CompletionItem, Position, Range, Uri};

use deps_core::{
    Ecosystem, ParseResult as ParseResultTrait, Registry, Result, completion::Completions,
    lsp_helpers::EcosystemFormatter,
};

use crate::formatter::DartFormatter;
use crate::registry::PubDevRegistry;

/// [`Ecosystem`] implementation for Dart/Pub (`pubspec.yaml`).
pub struct DartEcosystem {
    registry: Arc<PubDevRegistry>,
    formatter: DartFormatter,
}

impl DartEcosystem {
    /// Creates a Dart ecosystem instance backed by the given shared HTTP cache.
    pub fn new(cache: Arc<deps_core::HttpCache>) -> Self {
        Self {
            registry: Arc::new(PubDevRegistry::new(cache)),
            formatter: DartFormatter,
        }
    }

    async fn complete_package_names(&self, prefix: &str, range: Range) -> Vec<CompletionItem> {
        deps_core::completion::complete_package_names_generic(
            self.registry.as_ref(),
            prefix,
            20,
            range,
        )
        .await
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
            &['^', '>', '<', '='],
            freshness,
        )
        .await
    }
}

impl deps_core::ecosystem::private::Sealed for DartEcosystem {}

impl Ecosystem for DartEcosystem {
    fn id(&self) -> &'static str {
        "dart"
    }

    fn display_name(&self) -> &'static str {
        "Dart (Pub)"
    }

    fn manifest_filenames(&self) -> &[&'static str] {
        &["pubspec.yaml"]
    }

    fn lockfile_filenames(&self) -> &[&'static str] {
        &["pubspec.lock"]
    }

    fn parse_manifest<'a>(
        &'a self,
        content: &'a str,
        uri: &'a Uri,
    ) -> deps_core::ecosystem::BoxFuture<'a, Result<Box<dyn ParseResultTrait>>> {
        Box::pin(async move {
            let result = crate::parser::parse_pubspec_yaml(content, uri)?;
            Ok(Box::new(result) as Box<dyn ParseResultTrait>)
        })
    }

    fn registry(&self) -> Arc<dyn Registry> {
        self.registry.clone() as Arc<dyn Registry>
    }

    fn lockfile_provider(&self) -> Option<Arc<dyn deps_core::lockfile::LockFileProvider>> {
        Some(Arc::new(crate::lockfile::PubspecLockParser))
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
    ) -> deps_core::ecosystem::BoxFuture<'a, Completions> {
        Box::pin(async move {
            use deps_core::completion::{CompletionContext, detect_completion_context};

            let context = detect_completion_context(parse_result, position, content);

            match context {
                CompletionContext::PackageName { prefix, range } => {
                    self.complete_package_names(&prefix, range).await
                }
                CompletionContext::Version {
                    package_name,
                    prefix,
                } => {
                    self.complete_versions(&package_name, &prefix, freshness)
                        .await
                }
                CompletionContext::Feature { .. } | CompletionContext::None | _ => vec![],
            }
            .into()
        })
    }

    fn fallback_completion_prefix<'a>(
        &self,
        content: &'a str,
        position: Position,
    ) -> Option<&'a str> {
        let line = deps_core::fallback_completion::line_at(content, position)?;
        if !is_in_dependencies_section(content, position.line as usize) {
            return None;
        }
        Some(extract_prefix(line, position.character))
    }

    fn completion_insert_text(&self, metadata: &dyn deps_core::Metadata) -> Option<String> {
        let name = metadata.name();
        let latest = metadata.latest_version().as_str();
        // The key is quoted: an unquoted YAML plain scalar can't start with `@`
        // (allowed by `is_safe_package_name` for npm/Deno-shaped names), which would
        // otherwise emit invalid YAML instead of a dependency entry.
        Some(format!("\"{name}\": ^{latest}"))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    /// Fetches `name`'s best-effort detected license (issue #660/#688) — `version` is
    /// unused, since pub.dev's `/score` endpoint is per-*package*, not per-version. See
    /// [`crate::registry::PubDevRegistry::get_license`] for the source and its
    /// "detected, not declared" caveat.
    fn fetch_license<'a>(
        &'a self,
        name: &'a str,
        _version: &'a str,
    ) -> deps_core::ecosystem::BoxFuture<'a, Vec<String>> {
        Box::pin(self.registry.get_license(name))
    }

    /// pub.dev's `/score` endpoint is pana's own license-detection heuristic, not an
    /// author-declared registry field — see [`deps_core::LicenseSource::DetectedSpdx`].
    fn license_source(&self) -> deps_core::LicenseSource {
        deps_core::LicenseSource::DetectedSpdx
    }
}

/// pubspec.yaml's top-level (unindented) dependency-like keys.
const SECTION_KEYS: &[&str] = &[
    "dependencies:",
    "dev_dependencies:",
    "dependency_overrides:",
];

/// Checks if `line_number` of `content` is inside a pubspec.yaml dependency section.
///
/// Dart's `dependencies`, `dev_dependencies`, and `dependency_overrides` keys are
/// top-level (unindented) YAML mappings; their entries stay part of the section until
/// the next unindented key starts a new one. For `deps-lsp`'s raw-text fallback
/// completion (parse-failure path).
fn is_in_dependencies_section(content: &str, line_number: usize) -> bool {
    let mut in_dependencies = false;

    for (i, line) in content.lines().enumerate() {
        if i > line_number {
            break;
        }

        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Top-level (unindented) key: starts a new section, or leaves the current one.
        if trimmed.len() == line.len() {
            in_dependencies = SECTION_KEYS.iter().any(|key| trimmed.starts_with(key));
        }
    }

    in_dependencies
}

/// Extracts the fallback-completion prefix on `line` up to `character` — a bare YAML
/// key, with no manifest-syntax wrapper to strip.
fn extract_prefix(line: &str, character: u32) -> &str {
    deps_core::fallback_completion::raw_prefix(line, character)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ecosystem_id() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = DartEcosystem::new(cache);
        assert_eq!(eco.id(), "dart");
    }

    #[test]
    fn test_ecosystem_display_name() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = DartEcosystem::new(cache);
        assert_eq!(eco.display_name(), "Dart (Pub)");
    }

    #[test]
    fn test_ecosystem_manifest_filenames() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = DartEcosystem::new(cache);
        assert_eq!(eco.manifest_filenames(), &["pubspec.yaml"]);
    }

    #[test]
    fn test_ecosystem_lockfile_filenames() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = DartEcosystem::new(cache);
        assert_eq!(eco.lockfile_filenames(), &["pubspec.lock"]);
    }

    #[test]
    fn test_as_any() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = DartEcosystem::new(cache);
        assert!(eco.as_any().is::<DartEcosystem>());
    }

    #[tokio::test]
    async fn test_package_name_completion_context_has_real_range() {
        // Regression test for #232: the textEdit range for a package-name completion
        // must be the real name token span, not the (0,0)-(0,0) placeholder.
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = DartEcosystem::new(cache);
        let content = "name: my_app\ndependencies:\n  http: ^1.0.0\n";
        let uri = deps_core::test_util::test_uri("/test/pubspec.yaml");

        let parse_result = eco.parse_manifest(content, &uri).await.unwrap();
        let position = Position::new(2, 4); // cursor after "ht" in "http"

        let context = deps_core::completion::detect_completion_context(
            parse_result.as_ref(),
            position,
            content,
        );

        match context {
            deps_core::completion::CompletionContext::PackageName { prefix, range } => {
                assert_eq!(prefix, "ht");
                assert_ne!(range, Range::default());
                assert_eq!(range, Range::new(Position::new(2, 2), Position::new(2, 6)));
            }
            other => panic!("Expected PackageName context, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_complete_package_names_min_prefix() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = DartEcosystem::new(cache);
        assert!(
            eco.complete_package_names("h", Range::default())
                .await
                .is_empty()
        );
        assert!(
            eco.complete_package_names("", Range::default())
                .await
                .is_empty()
        );
    }

    #[tokio::test]
    async fn test_complete_package_names_max_length() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = DartEcosystem::new(cache);
        let long = "a".repeat(201);
        assert!(
            eco.complete_package_names(&long, Range::default())
                .await
                .is_empty()
        );
    }

    #[tokio::test]
    async fn test_lockfile_provider() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = DartEcosystem::new(cache);
        assert!(eco.lockfile_provider().is_some());
    }

    #[tokio::test]
    async fn test_parse_manifest() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = DartEcosystem::new(cache);

        let yaml = "name: app\ndependencies:\n  http: ^1.0.0\n";
        #[cfg(windows)]
        let path = "C:/test/pubspec.yaml";
        #[cfg(not(windows))]
        let path = "/test/pubspec.yaml";
        let uri = Uri::from_file_path(path).unwrap();

        let result = eco.parse_manifest(yaml, &uri).await.unwrap();
        assert_eq!(result.dependencies().len(), 1);
    }

    /// Composition regression guard (#390/#282 bug class): proves `line_at` +
    /// `is_in_dependencies_section`'s top-level-key scan compose correctly through
    /// the real trait method on realistic multi-line `pubspec.yaml` content.
    #[test]
    fn test_fallback_completion_prefix_multi_line_composition() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = DartEcosystem::new(cache);
        let content = "name: myapp\ndependencies:\n  pa";
        let line = content.lines().nth(2).unwrap();
        let position = Position::new(2, line.chars().count() as u32);
        assert_eq!(
            eco.fallback_completion_prefix(content, position),
            Some("pa")
        );
    }

    #[test]
    fn test_is_in_dependencies_section_basic() {
        let content =
            "name: myapp\ndependencies:\n  http: ^1.0.0\nenvironment:\n  sdk: '>=3.0.0'\n";
        assert!(is_in_dependencies_section(content, 2));
        assert!(!is_in_dependencies_section(content, 4));
    }

    /// A column-0 `#` comment inside a section must not read as a new top-level key
    /// and reset `in_dependencies` to false.
    #[test]
    fn test_is_in_dependencies_section_column_zero_comment() {
        let content = "name: myapp\ndependencies:\n# a comment\n  http: ^1.0.0\n";
        assert!(is_in_dependencies_section(content, 2));
        assert!(is_in_dependencies_section(content, 3));
    }

    #[test]
    fn test_completion_insert_text() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = DartEcosystem::new(cache);
        struct MockMetadata {
            name: deps_core::PackageName,
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
                None
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
        let meta = MockMetadata {
            name: deps_core::PackageName::new("path"),
            latest_version: "1.9.0".into(),
        };
        assert_eq!(
            eco.completion_insert_text(&meta),
            Some("\"path\": ^1.9.0".to_string())
        );
    }
}
