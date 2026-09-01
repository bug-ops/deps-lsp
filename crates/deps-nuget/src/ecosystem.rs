//! NuGet ecosystem implementation for deps-lsp.
//!
//! # Unknown/unresolvable packages
//!
//! Only `api.nuget.org` is queried — private feeds (`NuGet.config` `<packageSources>`,
//! Azure Artifacts, GitHub Packages, internal Artifactory) are out of scope (D4). A 404 or
//! otherwise-unknown package must degrade to **no diagnostic, no inlay hint, no error
//! marker** (S4) — this already falls out of `deps-lsp`'s generic error handling around
//! `Registry::get_latest_matching` (a fetch error or `Ok(None)` both simply omit the
//! package from `cached_versions`), so no special-casing is needed here.

use std::any::Any;
use std::sync::Arc;
use tower_lsp_server::ls_types::{CompletionItem, Position, Range, Uri};

use deps_core::{
    Ecosystem, ParseResult as ParseResultTrait, Registry, Result, completion::Completions,
    lsp_helpers::EcosystemFormatter,
};

use crate::formatter::NuGetFormatter;
use crate::lockfile::NuGetLockParser;
use crate::registry::NuGetRegistry;
use crate::types::NuGetParseResult;

/// NuGet/.NET ecosystem implementation.
///
/// Provides LSP functionality for `.csproj`/`.fsproj`/`.vbproj`, `Directory.Packages.props`,
/// and `packages.config` files, backed by the NuGet V3 registry API.
pub struct NuGetEcosystem {
    registry: Arc<NuGetRegistry>,
    formatter: NuGetFormatter,
    lockfile_provider: Arc<NuGetLockParser>,
}

impl NuGetEcosystem {
    pub fn new(cache: Arc<deps_core::HttpCache>) -> Self {
        Self {
            registry: Arc::new(NuGetRegistry::new(cache)),
            formatter: NuGetFormatter,
            lockfile_provider: Arc::new(NuGetLockParser),
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
            &[],
            freshness,
        )
        .await
    }

    /// Dispatches to the manifest-kind-specific parser based on the URI's basename.
    /// `.csproj`/`.fsproj`/`.vbproj` (routed to this ecosystem via `manifest_extensions`)
    /// all share the `PackageReference` MSBuild schema, so anything not matching one of the
    /// two fixed filenames falls through to the project-file parser.
    fn parse_by_filename(content: &str, uri: &Uri) -> Result<NuGetParseResult> {
        let path = uri.path().as_str();
        let filename = path.rsplit('/').next().unwrap_or(path);

        match filename.to_lowercase().as_str() {
            "directory.packages.props" => {
                crate::parser::parse_directory_packages_props(content, uri)
            }
            "packages.config" => crate::parser::parse_packages_config(content, uri),
            _ => crate::parser::parse_project_file(content, uri),
        }
    }
}

impl deps_core::ecosystem::private::Sealed for NuGetEcosystem {}

impl Ecosystem for NuGetEcosystem {
    fn id(&self) -> &'static str {
        "nuget"
    }

    fn display_name(&self) -> &'static str {
        "NuGet (.NET)"
    }

    fn manifest_filenames(&self) -> &[&'static str] {
        &["Directory.Packages.props", "packages.config"]
    }

    fn manifest_extensions(&self) -> &[&'static str] {
        &[".csproj", ".fsproj", ".vbproj"]
    }

    fn lockfile_filenames(&self) -> &[&'static str] {
        &["packages.lock.json"]
    }

    fn parse_manifest<'a>(
        &'a self,
        content: &'a str,
        uri: &'a Uri,
    ) -> deps_core::ecosystem::BoxFuture<'a, Result<Box<dyn ParseResultTrait>>> {
        Box::pin(async move {
            let result = Self::parse_by_filename(content, uri)?;
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
    ) -> deps_core::ecosystem::BoxFuture<'a, Completions> {
        Box::pin(async move {
            use deps_core::completion::{CompletionContext, detect_completion_context};

            match detect_completion_context(parse_result, position, content) {
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
                CompletionContext::Feature { .. } | CompletionContext::None => vec![],
            }
            .into()
        })
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ecosystem_id() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = NuGetEcosystem::new(cache);
        assert_eq!(eco.id(), "nuget");
    }

    #[test]
    fn test_ecosystem_display_name() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = NuGetEcosystem::new(cache);
        assert_eq!(eco.display_name(), "NuGet (.NET)");
    }

    #[test]
    fn test_manifest_filenames_and_extensions() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = NuGetEcosystem::new(cache);
        assert_eq!(
            eco.manifest_filenames(),
            &["Directory.Packages.props", "packages.config"]
        );
        assert_eq!(
            eco.manifest_extensions(),
            &[".csproj", ".fsproj", ".vbproj"]
        );
    }

    #[test]
    fn test_lockfile_filenames() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = NuGetEcosystem::new(cache);
        assert_eq!(eco.lockfile_filenames(), &["packages.lock.json"]);
    }

    #[test]
    fn test_lockfile_provider_some() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = NuGetEcosystem::new(cache);
        assert!(eco.lockfile_provider().is_some());
    }

    #[test]
    fn test_as_any() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = NuGetEcosystem::new(cache);
        assert!(eco.as_any().is::<NuGetEcosystem>());
    }

    #[tokio::test]
    async fn test_package_name_completion_context_has_real_range() {
        // Regression test for #232: the textEdit range for a package-name completion
        // must be the real name token span, not the (0,0)-(0,0) placeholder.
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = NuGetEcosystem::new(cache);
        let content = "<Project>\n  <ItemGroup>\n    <PackageReference Include=\"Foo\" Version=\"1.0.0\" />\n  </ItemGroup>\n</Project>";
        let uri = deps_core::test_util::test_uri("/test/App.csproj");

        let parse_result = eco.parse_manifest(content, &uri).await.unwrap();
        let position = Position::new(2, 33); // cursor after "Fo" in "Foo"

        let context = deps_core::completion::detect_completion_context(
            parse_result.as_ref(),
            position,
            content,
        );

        match context {
            deps_core::completion::CompletionContext::PackageName { prefix, range } => {
                assert_eq!(prefix, "Fo");
                assert_ne!(range, Range::default());
                assert_eq!(
                    range,
                    Range::new(Position::new(2, 31), Position::new(2, 34))
                );
            }
            other => panic!("Expected PackageName context, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_parse_manifest_csproj() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = NuGetEcosystem::new(cache);
        let uri = deps_core::test_util::test_uri("/test/App.csproj");
        let content = r#"<Project><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="13.0.3" /></ItemGroup></Project>"#;

        let result = eco.parse_manifest(content, &uri).await.unwrap();
        assert_eq!(result.dependencies().len(), 1);
    }

    #[tokio::test]
    async fn test_parse_manifest_fsproj_routes_as_project_file() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = NuGetEcosystem::new(cache);
        let uri = deps_core::test_util::test_uri("/test/App.fsproj");
        let content = r#"<Project><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="13.0.3" /></ItemGroup></Project>"#;

        let result = eco.parse_manifest(content, &uri).await.unwrap();
        assert_eq!(result.dependencies().len(), 1);
    }

    #[tokio::test]
    async fn test_parse_manifest_directory_packages_props() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = NuGetEcosystem::new(cache);
        let uri = deps_core::test_util::test_uri("/test/Directory.Packages.props");
        let content = r#"<Project><ItemGroup><PackageVersion Include="Serilog" Version="3.1.1" /></ItemGroup></Project>"#;

        let result = eco.parse_manifest(content, &uri).await.unwrap();
        assert_eq!(result.dependencies().len(), 1);
    }

    #[tokio::test]
    async fn test_parse_manifest_packages_config() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = NuGetEcosystem::new(cache);
        let uri = deps_core::test_util::test_uri("/test/packages.config");
        let content = r#"<packages><package id="Newtonsoft.Json" version="13.0.3" targetFramework="net48" /></packages>"#;

        let result = eco.parse_manifest(content, &uri).await.unwrap();
        assert_eq!(result.dependencies().len(), 1);
    }

    #[tokio::test]
    async fn test_parse_manifest_invalid_xml_errors() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = NuGetEcosystem::new(cache);
        let uri = deps_core::test_util::test_uri("/test/App.csproj");
        let content = r#"<Project attr="unclosed></Project>"#;

        let result = eco.parse_manifest(content, &uri).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_complete_package_names_min_prefix() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = NuGetEcosystem::new(cache);
        assert!(
            eco.complete_package_names("", Range::default())
                .await
                .is_empty()
        );
    }

    /// End-to-end regression for issue #163: a `.csproj`/`Directory.Packages.props`
    /// bare-floor `Version` pinned behind the latest registry release must render `❌
    /// {latest}`, not `✅` — see `NuGetFormatter::is_requirement_up_to_date`.
    async fn inlay_hint_labels(
        eco: &NuGetEcosystem,
        content: &str,
        uri: &tower_lsp_server::ls_types::Uri,
        latest: &str,
    ) -> Vec<String> {
        use deps_core::lsp_helpers::VersionData;
        use deps_core::{EcosystemConfig, LoadingState, PackageVersions};
        use tower_lsp_server::ls_types::InlayHintLabel;

        let parse_result = eco.parse_manifest(content, uri).await.unwrap();
        let mut cached = std::collections::HashMap::new();
        cached.insert(
            "newtonsoft.json".into(),
            PackageVersions::latest_only(latest),
        );
        let resolved = std::collections::HashMap::new();

        let hints = eco
            .generate_inlay_hints(
                parse_result.as_ref(),
                VersionData::new(&cached, &resolved),
                LoadingState::Idle,
                &EcosystemConfig::default(),
            )
            .await;

        hints
            .into_iter()
            .map(|h| match h.label {
                InlayHintLabel::String(s) => s,
                InlayHintLabel::LabelParts(_) => unreachable!("NuGet never emits label parts"),
            })
            .collect()
    }

    #[tokio::test]
    async fn test_inlay_hint_flags_outdated_csproj_package_reference() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = NuGetEcosystem::new(cache);
        let uri = deps_core::test_util::test_uri("/test/App.csproj");
        let content = r#"<Project><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="13.0.3" /></ItemGroup></Project>"#;

        let labels = inlay_hint_labels(&eco, content, &uri, "13.0.4").await;
        assert_eq!(labels, vec!["❌ 13.0.4"]);
    }

    #[tokio::test]
    async fn test_inlay_hint_marks_up_to_date_csproj_package_reference() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = NuGetEcosystem::new(cache);
        let uri = deps_core::test_util::test_uri("/test/App.csproj");
        let content = r#"<Project><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="13.0.3" /></ItemGroup></Project>"#;

        let labels = inlay_hint_labels(&eco, content, &uri, "13.0.3").await;
        assert_eq!(labels, vec!["✅"]);
    }

    #[tokio::test]
    async fn test_inlay_hint_flags_outdated_directory_packages_props() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = NuGetEcosystem::new(cache);
        let uri = deps_core::test_util::test_uri("/test/Directory.Packages.props");
        let content = r#"<Project><ItemGroup><PackageVersion Include="Newtonsoft.Json" Version="13.0.3" /></ItemGroup></Project>"#;

        let labels = inlay_hint_labels(&eco, content, &uri, "13.0.4").await;
        assert_eq!(labels, vec!["❌ 13.0.4"]);
    }

    #[tokio::test]
    async fn test_inlay_hint_packages_config_exact_pin_unaffected() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = NuGetEcosystem::new(cache);
        let uri = deps_core::test_util::test_uri("/test/packages.config");
        let content = r#"<packages><package id="Newtonsoft.Json" version="13.0.3" targetFramework="net48" /></packages>"#;

        assert_eq!(
            inlay_hint_labels(&eco, content, &uri, "13.0.4").await,
            vec!["❌ 13.0.4"]
        );
        assert_eq!(
            inlay_hint_labels(&eco, content, &uri, "13.0.3").await,
            vec!["✅"]
        );
    }

    /// Diagnostics counterpart of the inlay-hint regressions above: `generate_diagnostics`
    /// (default impl, delegates to `lsp_helpers::generate_diagnostics_from_cache`) shares
    /// the same `EcosystemFormatter::is_requirement_up_to_date` call site, so it was
    /// affected by the same bug and must be verified separately (no inlay-hint test
    /// exercises this path).
    async fn diagnostic_messages(
        eco: &NuGetEcosystem,
        content: &str,
        uri: &tower_lsp_server::ls_types::Uri,
        latest: &str,
    ) -> Vec<String> {
        use deps_core::PackageVersions;
        use deps_core::lsp_helpers::VersionData;

        let parse_result = eco.parse_manifest(content, uri).await.unwrap();
        let mut cached = std::collections::HashMap::new();
        cached.insert(
            "newtonsoft.json".into(),
            PackageVersions::latest_only(latest),
        );
        let resolved = std::collections::HashMap::new();

        eco.generate_diagnostics(
            parse_result.as_ref(),
            VersionData::new(&cached, &resolved),
            uri,
            deps_core::FreshnessSettings::default(),
            deps_core::DiagnosticSeverities::default(),
        )
        .await
        .into_iter()
        .map(|d| d.message)
        .collect()
    }

    #[tokio::test]
    async fn test_diagnostics_flag_outdated_csproj_package_reference() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = NuGetEcosystem::new(cache);
        let uri = deps_core::test_util::test_uri("/test/App.csproj");
        let content = r#"<Project><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="13.0.3" /></ItemGroup></Project>"#;

        let messages = diagnostic_messages(&eco, content, &uri, "13.0.4").await;
        assert_eq!(messages, vec!["Newer version available: 13.0.4"]);
    }

    #[tokio::test]
    async fn test_diagnostics_silent_when_up_to_date() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = NuGetEcosystem::new(cache);
        let uri = deps_core::test_util::test_uri("/test/App.csproj");
        let content = r#"<Project><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="13.0.3" /></ItemGroup></Project>"#;

        assert!(
            diagnostic_messages(&eco, content, &uri, "13.0.3")
                .await
                .is_empty()
        );
    }
}
