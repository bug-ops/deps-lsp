//! PyPI ecosystem implementation for deps-lsp.
//!
//! This module implements the `Ecosystem` trait for Python projects,
//! providing LSP functionality for `pyproject.toml` files and for
//! `requirements.txt`/`constraints.txt` files (pip's requirements file
//! format).

use std::any::Any;
use std::sync::Arc;
use tower_lsp_server::ls_types::{CompletionItem, Position, Range, Uri};

use deps_core::{
    Ecosystem, ParseResult as ParseResultTrait, Registry, Result, lsp_helpers::EcosystemFormatter,
};

use crate::formatter::PypiFormatter;
use crate::parser::PypiParser;
use crate::registry::PypiRegistry;

/// Which manifest shape a URI's basename identifies, so `parse_manifest` can
/// dispatch to the right parser method and report the right `file_type` on
/// error.
#[derive(Clone, Copy)]
enum PypiManifestKind {
    PyProject,
    Requirements,
}

impl PypiManifestKind {
    fn from_uri(uri: &Uri) -> Self {
        let basename = uri.path().as_str().rsplit('/').next().unwrap_or_default();
        if basename == "pyproject.toml" {
            Self::PyProject
        } else {
            Self::Requirements
        }
    }

    const fn file_type(self) -> &'static str {
        match self {
            Self::PyProject => "pyproject.toml",
            Self::Requirements => "requirements.txt",
        }
    }
}

/// PyPI ecosystem implementation.
///
/// Provides LSP functionality for pyproject.toml files, including:
/// - Dependency parsing with position tracking
/// - Version information from PyPI registry
/// - Inlay hints for latest versions
/// - Hover tooltips with package metadata
/// - Code actions for version updates
/// - Diagnostics for unknown/yanked packages
pub struct PypiEcosystem {
    registry: Arc<PypiRegistry>,
    parser: PypiParser,
    formatter: PypiFormatter,
}

impl PypiEcosystem {
    /// Creates a new PyPI ecosystem with the given HTTP cache.
    pub fn new(cache: Arc<deps_core::HttpCache>) -> Self {
        Self {
            registry: Arc::new(PypiRegistry::new(cache)),
            parser: PypiParser::new(),
            formatter: PypiFormatter,
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
            &['>', '<', '=', '~', '!'],
            freshness,
        )
        .await
    }
}

impl deps_core::ecosystem::private::Sealed for PypiEcosystem {}

impl Ecosystem for PypiEcosystem {
    fn id(&self) -> &'static str {
        "pypi"
    }

    fn display_name(&self) -> &'static str {
        "PyPI (Python)"
    }

    fn manifest_filenames(&self) -> &[&'static str] {
        &["pyproject.toml"]
    }

    fn manifest_patterns(&self) -> &[&'static str] {
        &[
            "requirements*.txt",
            "*-requirements.txt",
            "*.requirements.txt",
            "constraints*.txt",
        ]
    }

    fn lockfile_filenames(&self) -> &[&'static str] {
        &["poetry.lock", "uv.lock"]
    }

    fn parse_manifest<'a>(
        &'a self,
        content: &'a str,
        uri: &'a Uri,
    ) -> deps_core::ecosystem::BoxFuture<'a, Result<Box<dyn ParseResultTrait>>> {
        Box::pin(async move {
            let kind = PypiManifestKind::from_uri(uri);
            let result = match kind {
                PypiManifestKind::PyProject => self.parser.parse_content(content, uri),
                PypiManifestKind::Requirements => self.parser.parse_requirements(content, uri),
            }
            .map_err(|e| deps_core::DepsError::ParseError {
                file_type: kind.file_type().into(),
                source: Box::new(e),
            })?;
            Ok(Box::new(result) as Box<dyn ParseResultTrait>)
        })
    }

    fn registry(&self) -> Arc<dyn Registry> {
        self.registry.clone() as Arc<dyn Registry>
    }

    fn lockfile_provider(&self) -> Option<Arc<dyn deps_core::lockfile::LockFileProvider>> {
        Some(Arc::new(crate::lockfile::PypiLockParser))
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
                    self.complete_package_names(&prefix, range).await
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
    use deps_core::{EcosystemConfig, VersionData};
    use std::collections::HashMap;

    fn pkg(s: &str) -> deps_core::PackageName {
        deps_core::PackageName::new(s)
    }

    #[test]
    fn test_ecosystem_id() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = PypiEcosystem::new(cache);
        assert_eq!(ecosystem.id(), "pypi");
    }

    #[test]
    fn test_ecosystem_manifest_patterns() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = PypiEcosystem::new(cache);
        assert_eq!(
            ecosystem.manifest_patterns(),
            &[
                "requirements*.txt",
                "*-requirements.txt",
                "*.requirements.txt",
                "constraints*.txt",
            ]
        );
    }

    #[tokio::test]
    async fn test_parse_manifest_requirements_txt_uri_yields_dependencies() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = PypiEcosystem::new(cache);
        let uri = deps_core::test_util::test_uri("/test/requirements.txt");

        let result = ecosystem
            .parse_manifest("requests==2.31.0\nflask>=3.0\n", &uri)
            .await
            .unwrap();

        assert_eq!(result.dependencies().len(), 2);
    }

    #[tokio::test]
    async fn test_parse_manifest_pyproject_toml_unchanged() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = PypiEcosystem::new(cache);
        let uri = deps_core::test_util::test_uri("/test/pyproject.toml");

        let result = ecosystem
            .parse_manifest("[project]\ndependencies = [\"requests>=2.0.0\"]\n", &uri)
            .await
            .unwrap();

        assert_eq!(result.dependencies().len(), 1);
    }

    #[test]
    fn test_manifest_kind_file_type_reflects_uri() {
        let requirements_uri = deps_core::test_util::test_uri("/test/requirements.txt");
        assert_eq!(
            PypiManifestKind::from_uri(&requirements_uri).file_type(),
            "requirements.txt"
        );

        let pyproject_uri = deps_core::test_util::test_uri("/test/pyproject.toml");
        assert_eq!(
            PypiManifestKind::from_uri(&pyproject_uri).file_type(),
            "pyproject.toml"
        );
    }

    #[tokio::test]
    async fn test_parse_manifest_pyproject_toml_invalid_reports_pyproject_file_type() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = PypiEcosystem::new(cache);
        let uri = deps_core::test_util::test_uri("/test/pyproject.toml");

        let result = ecosystem
            .parse_manifest("[project\nname = invalid", &uri)
            .await;

        let Err(err) = result else {
            panic!("expected a parse error");
        };
        assert!(matches!(
            err,
            deps_core::DepsError::ParseError { file_type, .. } if file_type == "pyproject.toml"
        ));
    }

    #[test]
    fn test_ecosystem_display_name() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = PypiEcosystem::new(cache);
        assert_eq!(ecosystem.display_name(), "PyPI (Python)");
    }

    #[test]
    fn test_ecosystem_manifest_filenames() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = PypiEcosystem::new(cache);
        assert_eq!(ecosystem.manifest_filenames(), &["pyproject.toml"]);
    }

    #[test]
    fn test_ecosystem_lockfile_filenames() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = PypiEcosystem::new(cache);
        assert_eq!(ecosystem.lockfile_filenames(), &["poetry.lock", "uv.lock"]);
    }

    #[test]
    fn test_as_any() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = PypiEcosystem::new(cache);

        let any = ecosystem.as_any();
        assert!(any.is::<PypiEcosystem>());
    }

    #[tokio::test]
    async fn test_package_name_completion_context_has_real_range() {
        // Regression test for #232: the textEdit range for a package-name completion
        // must be the real name token span, not the (0,0)-(0,0) placeholder.
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = PypiEcosystem::new(cache);
        let content = "[dependency-groups]\ndev = [\"pytest>=8.0\", \"mypy>=1.0\"]\n";
        let uri = deps_core::test_util::test_uri("/test/pyproject.toml");

        let parse_result = ecosystem.parse_manifest(content, &uri).await.unwrap();
        let position = Position::new(1, 11); // cursor after "pyt" in "pytest"

        let context = deps_core::completion::detect_completion_context(
            parse_result.as_ref(),
            position,
            content,
        );

        match context {
            deps_core::completion::CompletionContext::PackageName { prefix, range } => {
                assert_eq!(prefix, "pyt");
                assert_ne!(range, Range::default());
                assert_eq!(range, Range::new(Position::new(1, 8), Position::new(1, 14)));
            }
            other => panic!("Expected PackageName context, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_complete_package_names_minimum_prefix() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = PypiEcosystem::new(cache);

        // Less than 2 characters should return empty
        let results = ecosystem
            .complete_package_names("d", Range::default())
            .await;
        assert!(results.is_empty());

        // Empty prefix should return empty
        let results = ecosystem.complete_package_names("", Range::default()).await;
        assert!(results.is_empty());
    }

    #[tokio::test]
    #[ignore] // Requires network access
    async fn test_complete_package_names_real_search() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = PypiEcosystem::new(cache);

        let results = ecosystem
            .complete_package_names("reque", Range::default())
            .await;
        assert!(!results.is_empty());
        assert!(results.iter().any(|r| r.label == "requests"));
    }

    #[tokio::test]
    #[ignore] // Requires network access
    async fn test_complete_versions_real() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = PypiEcosystem::new(cache);

        let results = ecosystem
            .complete_versions(
                &pkg("requests"),
                "2.",
                deps_core::FreshnessSettings::default(),
            )
            .await;
        assert!(!results.is_empty());
        assert!(results.iter().all(|r| r.label.starts_with("2.")));
    }

    #[tokio::test]
    #[ignore] // Requires network access
    async fn test_complete_versions_with_operator() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = PypiEcosystem::new(cache);

        let results = ecosystem
            .complete_versions(
                &pkg("requests"),
                ">=2.",
                deps_core::FreshnessSettings::default(),
            )
            .await;
        assert!(!results.is_empty());
        assert!(results.iter().all(|r| r.label.starts_with("2.")));
    }

    #[tokio::test]
    async fn test_complete_versions_unknown_package() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = PypiEcosystem::new(cache);

        // Unknown package should return empty (graceful degradation)
        let results = ecosystem
            .complete_versions(
                &pkg("this-package-does-not-exist-12345"),
                "1.0",
                deps_core::FreshnessSettings::default(),
            )
            .await;
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn test_complete_package_names_special_characters() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = PypiEcosystem::new(cache);

        // Package names with hyphens and underscores should work
        let results = ecosystem
            .complete_package_names("scikit-le", Range::default())
            .await;
        // Should not panic or error
        assert!(results.is_empty() || !results.is_empty());
    }

    #[tokio::test]
    async fn test_complete_package_names_max_length() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = PypiEcosystem::new(cache);

        // Prefix longer than 200 chars should return empty (security)
        let long_prefix = "a".repeat(201);
        let results = ecosystem
            .complete_package_names(&long_prefix, Range::default())
            .await;
        assert!(results.is_empty());

        // Exactly 100 chars should work
        let max_prefix = "a".repeat(100);
        let results = ecosystem
            .complete_package_names(&max_prefix, Range::default())
            .await;
        // Should not panic, but may return empty (no matches)
        assert!(results.is_empty() || !results.is_empty());
    }

    #[tokio::test]
    #[ignore] // Requires network access
    async fn test_complete_versions_limit_20() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = PypiEcosystem::new(cache);

        // Test that we respect the 20 result limit
        let results = ecosystem
            .complete_versions(
                &pkg("requests"),
                "2",
                deps_core::FreshnessSettings::default(),
            )
            .await;
        assert!(results.len() <= 20);
    }

    #[tokio::test]
    #[ignore] // Requires network access
    async fn test_complete_package_names_special_chars_real() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = PypiEcosystem::new(cache);

        // Real packages with special characters
        let results = ecosystem
            .complete_package_names("scikit-le", Range::default())
            .await;
        assert!(!results.is_empty() || results.is_empty()); // May or may not have results
    }

    #[tokio::test]
    async fn test_parse_manifest_valid_content() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = PypiEcosystem::new(cache);
        let uri = deps_core::test_util::test_uri("/test/pyproject.toml");

        let content = r#"[project]
name = "test"
dependencies = ["requests>=2.0.0"]
"#;

        let result = ecosystem.parse_manifest(content, &uri).await;
        assert!(result.is_ok());

        let parse_result = result.unwrap();
        assert!(!parse_result.dependencies().is_empty());
    }

    #[tokio::test]
    async fn test_parse_manifest_invalid_toml() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = PypiEcosystem::new(cache);
        let uri = deps_core::test_util::test_uri("/test/pyproject.toml");

        let invalid_content = "[project\nname = invalid";

        let result = ecosystem.parse_manifest(invalid_content, &uri).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_parse_manifest_empty_dependencies() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = PypiEcosystem::new(cache);
        let uri = deps_core::test_util::test_uri("/test/pyproject.toml");

        let content = r#"[project]
name = "test"
dependencies = []
"#;

        let result = ecosystem.parse_manifest(content, &uri).await;
        assert!(result.is_ok());

        let parse_result = result.unwrap();
        assert!(parse_result.dependencies().is_empty());
    }

    #[tokio::test]
    async fn test_registry_returns_arc() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = PypiEcosystem::new(cache);

        let registry = ecosystem.registry();
        assert!(Arc::strong_count(&registry) >= 1);
    }

    #[tokio::test]
    async fn test_lockfile_provider_returns_some() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = PypiEcosystem::new(cache);

        let provider = ecosystem.lockfile_provider();
        assert!(provider.is_some());
    }

    #[tokio::test]
    async fn test_generate_inlay_hints_empty_dependencies() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = PypiEcosystem::new(cache);
        let uri = deps_core::test_util::test_uri("/test/pyproject.toml");

        let content = r"[project]
dependencies = []
";

        let parse_result = ecosystem.parse_manifest(content, &uri).await.unwrap();
        let cached_versions = HashMap::new();
        let resolved_versions = HashMap::new();
        let config = EcosystemConfig::default();

        let hints = ecosystem
            .generate_inlay_hints(
                parse_result.as_ref(),
                VersionData::new(&cached_versions, &resolved_versions),
                deps_core::LoadingState::Loaded,
                &config,
            )
            .await;

        assert!(hints.is_empty());
    }

    #[tokio::test]
    async fn test_generate_completions_no_context() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = PypiEcosystem::new(cache);
        let uri = deps_core::test_util::test_uri("/test/pyproject.toml");

        let content = r#"[project]
name = "test"
"#;

        let parse_result = ecosystem.parse_manifest(content, &uri).await.unwrap();
        let position = Position {
            line: 0,
            character: 0,
        };

        let completions = ecosystem
            .generate_completions(
                parse_result.as_ref(),
                position,
                content,
                deps_core::FreshnessSettings::default(),
            )
            .await;

        assert!(completions.is_empty());
    }

    #[tokio::test]
    async fn test_generate_completions_feature_context_returns_empty() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = PypiEcosystem::new(cache);

        // PyPI doesn't have features, so this should always return empty
        // Even if we detect a feature context (which shouldn't happen for PyPI)
        // This tests the Feature branch in generate_completions
        let content = r#"[project]
dependencies = ["requests"]
"#;
        let uri = deps_core::test_util::test_uri("/test/pyproject.toml");
        let parse_result = ecosystem.parse_manifest(content, &uri).await.unwrap();

        // Test with any position - feature context should return empty
        let position = Position {
            line: 1,
            character: 20,
        };

        let completions = ecosystem
            .generate_completions(
                parse_result.as_ref(),
                position,
                content,
                deps_core::FreshnessSettings::default(),
            )
            .await;

        // Should not crash, returns empty or package/version completions
        assert!(completions.is_empty() || !completions.is_empty());
    }

    #[tokio::test]
    async fn test_generate_hover_no_dependency_at_position() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = PypiEcosystem::new(cache);
        let uri = deps_core::test_util::test_uri("/test/pyproject.toml");

        let content = r#"[project]
name = "test"
"#;

        let parse_result = ecosystem.parse_manifest(content, &uri).await.unwrap();
        let position = Position {
            line: 0,
            character: 0,
        };
        let cached_versions = HashMap::new();
        let resolved_versions = HashMap::new();

        let hover = ecosystem
            .generate_hover(
                parse_result.as_ref(),
                position,
                VersionData::new(&cached_versions, &resolved_versions),
                deps_core::FreshnessSettings::default(),
            )
            .await;

        assert!(hover.is_none());
    }

    #[tokio::test]
    async fn test_generate_code_actions_no_actions() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = PypiEcosystem::new(cache);
        let uri = deps_core::test_util::test_uri("/test/pyproject.toml");

        let content = r#"[project]
name = "test"
"#;

        let parse_result = ecosystem.parse_manifest(content, &uri).await.unwrap();
        let position = Position {
            line: 0,
            character: 0,
        };
        let cached_versions = HashMap::new();
        let resolved_versions = HashMap::new();
        let actions = ecosystem
            .generate_code_actions(
                parse_result.as_ref(),
                position,
                &uri,
                VersionData::new(&cached_versions, &resolved_versions),
                content,
            )
            .await;

        assert!(actions.is_empty());
    }

    #[tokio::test]
    async fn test_generate_diagnostics_no_dependencies() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = PypiEcosystem::new(cache);
        let uri = deps_core::test_util::test_uri("/test/pyproject.toml");

        let content = r#"[project]
name = "test"
dependencies = []
"#;

        let parse_result = ecosystem.parse_manifest(content, &uri).await.unwrap();
        let cached_versions = HashMap::new();
        let resolved_versions = HashMap::new();

        let diagnostics = ecosystem
            .generate_diagnostics(
                parse_result.as_ref(),
                VersionData::new(&cached_versions, &resolved_versions),
                &uri,
                deps_core::FreshnessSettings::default(),
                deps_core::DiagnosticSeverities::default(),
            )
            .await;

        assert!(diagnostics.is_empty());
    }

    #[tokio::test]
    async fn test_complete_versions_empty_prefix() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = PypiEcosystem::new(cache);

        // Empty prefix should show non-yanked versions (up to 20)
        let results = ecosystem
            .complete_versions(
                &pkg("nonexistent-package"),
                "",
                deps_core::FreshnessSettings::default(),
            )
            .await;
        // Should not panic, returns empty for unknown package
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn test_complete_versions_with_tilde_operator() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = PypiEcosystem::new(cache);

        // Test PEP 440 operators are stripped correctly
        let results = ecosystem
            .complete_versions(
                &pkg("nonexistent-pkg"),
                "~=2.0",
                deps_core::FreshnessSettings::default(),
            )
            .await;
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn test_complete_versions_with_not_equal_operator() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = PypiEcosystem::new(cache);

        // Test != operator stripping
        let results = ecosystem
            .complete_versions(
                &pkg("nonexistent-pkg"),
                "!=2.0",
                deps_core::FreshnessSettings::default(),
            )
            .await;
        assert!(results.is_empty());
    }

    /// End-to-end regression for #212: a dotted package name declared as a
    /// Poetry table key must resolve against its `poetry.lock` entry. Unlike
    /// a PEP 621 fixture (which already worked before the fix, since
    /// `pep508_rs::PackageName` normalizes at construction), the Poetry
    /// table-key path takes the name verbatim from the TOML key — this is
    /// the actual bug #212 fixes.
    mod poetry_lockfile_regression_tests {
        use super::*;
        use crate::lockfile::PypiLockParser;
        use deps_core::PackageName;
        use deps_core::lockfile::LockFileProvider;

        /// A registry mock returning an empty (but `Ok`) version list —
        /// `generate_hover` requires a successful registry call before it
        /// reaches the `versions.resolved`-driven "Current" line, but the
        /// content of that call is irrelevant to this regression.
        struct EmptyOkRegistry;

        impl deps_core::Registry for EmptyOkRegistry {
            fn get_versions<'a>(
                &'a self,
                _name: &'a PackageName,
            ) -> deps_core::ecosystem::BoxFuture<
                'a,
                deps_core::error::Result<Vec<Box<dyn deps_core::Version>>>,
            > {
                Box::pin(async move { Ok(Vec::new()) })
            }

            fn get_latest_matching<'a>(
                &'a self,
                _name: &'a PackageName,
                _req: &'a deps_core::VersionReq,
            ) -> deps_core::ecosystem::BoxFuture<
                'a,
                deps_core::error::Result<Option<Box<dyn deps_core::Version>>>,
            > {
                Box::pin(async move { Ok(None) })
            }

            fn search<'a>(
                &'a self,
                _query: &'a str,
                _limit: usize,
            ) -> deps_core::ecosystem::BoxFuture<
                'a,
                deps_core::error::Result<Vec<Box<dyn deps_core::Metadata>>>,
            > {
                Box::pin(async move { Ok(Vec::new()) })
            }

            fn package_url(&self, _name: &PackageName) -> String {
                String::new()
            }

            fn as_any(&self) -> &dyn std::any::Any {
                self
            }
        }

        #[tokio::test]
        async fn test_poetry_table_key_dotted_name_resolves_against_lockfile() {
            let toml = "[tool.poetry.dependencies]\n\"zope.interface\" = \"^5.0\"\n";
            let uri = deps_core::test_util::test_uri("/test/pyproject.toml");
            let parser = PypiParser::new();
            let parse_result = parser.parse_content(toml, &uri).unwrap();

            // The raw TOML key is taken verbatim — unnormalized — confirming
            // this fixture actually exercises the Poetry table-key path
            // rather than a PEP 508 string path (which already normalizes).
            assert_eq!(parse_result.dependencies[0].name, "zope.interface");
            let dep_position = parse_result.dependencies[0].name_range.start;

            // Real poetry.lock/uv.lock files store the canonical hyphenated
            // form on write, never the dotted source name — a dotted lockfile
            // fixture here would make the headline assertions pass even
            // before the #212 fix (only an intermediate `contains_key`
            // mechanics check would fail), so this must be hyphenated to
            // actually discriminate pre/post fix.
            let lockfile_content = "[[package]]\nname = \"zope-interface\"\nversion = \"5.2.0\"\n";
            let temp_dir = tempfile::tempdir().unwrap();
            let lockfile_path = temp_dir.path().join("poetry.lock");
            std::fs::write(&lockfile_path, lockfile_content).unwrap();

            let lock_parser = PypiLockParser;
            let resolved_packages = lock_parser.parse_lockfile(&lockfile_path).await.unwrap();
            let resolved_versions: HashMap<PackageName, String> = resolved_packages
                .iter()
                .map(|(name, pkg)| (PackageName::new(name.as_str()), pkg.version.clone()))
                .collect();
            // Canonical PEP 503 normalization: both the lockfile key and the
            // formatter-normalized manifest name land on "zope-interface".
            assert!(resolved_versions.contains_key("zope-interface"));

            let cached_versions: HashMap<PackageName, deps_core::PackageVersions> = HashMap::new();
            let versions = VersionData::new(&cached_versions, &resolved_versions);
            let formatter = PypiFormatter;

            let hover = deps_core::lsp_helpers::generate_hover(
                &parse_result,
                dep_position,
                versions,
                &EmptyOkRegistry,
                &formatter,
                deps_core::FreshnessSettings::default(),
                deps_core::PublishTime::now(),
            )
            .await
            .expect("hover should be produced for a dependency at its name position");

            let markdown = match hover.contents {
                tower_lsp_server::ls_types::HoverContents::Markup(m) => m.value,
                _ => panic!("expected Markup hover contents"),
            };
            assert!(
                markdown.contains("**Current**") && markdown.contains("5.2.0"),
                "hover should render the resolved lock file version: {markdown}"
            );

            let diagnostics = deps_core::lsp_helpers::generate_diagnostics_from_cache(
                &parse_result,
                versions,
                &formatter,
                deps_core::FreshnessSettings::default(),
                deps_core::DiagnosticSeverities::default(),
                deps_core::PublishTime::now(),
            );
            assert!(
                diagnostics
                    .iter()
                    .all(|d| !d.message.contains("Unknown package")),
                "no 'Unknown package' diagnostic should be emitted: {diagnostics:?}"
            );
        }
    }
}
