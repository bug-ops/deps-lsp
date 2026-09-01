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
use std::collections::HashSet;
use std::sync::Arc;
use tower_lsp_server::ls_types::{CompletionItem, Hover, HoverContents, Position, Range, Uri};

use deps_core::{
    Ecosystem, ParseResult as ParseResultTrait, Registry, Result, completion::Completions,
    lsp_helpers::EcosystemFormatter,
};

use crate::formatter::NuGetFormatter;
use crate::lockfile::NuGetLockParser;
use crate::registry::NuGetRegistry;
use crate::types::NuGetParseResult;

/// Bounds `NuGetEcosystem::generate_hover`'s `unlisted_versions_for_hover` fetch (S4, #451
/// follow-up) — mirrors `deps_core::lsp_helpers::hover`'s own private `HOVER_FALLBACK_TIMEOUT`
/// for its analogous fallback fetch: hover responses must return quickly, and without this
/// bound a pathological feed's registration-hive walk could run unbounded.
const HOVER_UNLISTED_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

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

    /// Test-only hook to inject a [`NuGetRegistry`] pointed at a mock service index
    /// (`NuGetRegistry::new`/`Self::new` always resolve the real `api.nuget.org`).
    #[cfg(test)]
    fn with_registry(registry: NuGetRegistry) -> Self {
        Self {
            registry: Arc::new(registry),
            formatter: NuGetFormatter,
            lockfile_provider: Arc::new(NuGetLockParser),
        }
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
        // `packages.*.lock.json` isn't a real filename `EcosystemRegistry::get_for_lockfile`
        // can exact-match — it exists here only so `all_lockfile_patterns()` registers a
        // glob watcher for per-project lock files with the LSP client (D3, #451).
        // `NuGetLockParser::locate_lockfile` is what actually finds them, independent of
        // this list, via its own directory scan.
        &["packages.lock.json", "packages.*.lock.json"]
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

    /// Overrides the default (`lsp_helpers::generate_hover`) to add a hover-only unlisted
    /// marker (D1, #451): alongside the ordinary hover render, a separate
    /// [`NuGetRegistry::unlisted_versions_for_hover`] fetch decorates each unlisted entry
    /// in the "Recent versions" list with `*(unlisted)*`, matching how other ecosystems in
    /// this codebase mark a `*(yanked)*` version — see that method's doc comment for why
    /// this enrichment is deliberately kept out of `Version::removal_status` (and so out of
    /// completion/inlay hints/diagnostics, which all share the cached version list hover
    /// itself renders via the *ordinary*, non-enriched path above).
    ///
    /// The two fetches run concurrently via `tokio::join!`, not sequentially (S4, #451
    /// follow-up): serializing them would double hover's worst-case latency, and the
    /// unlisted fetch alone is additionally bounded by `HOVER_UNLISTED_TIMEOUT` — without
    /// it, a pathological feed's registration-hive walk (up to `MAX_EXTERNAL_PAGE_FETCHES`
    /// sequential page fetches, each with its own HTTP-client timeout) could run
    /// unbounded, exactly the failure mode `deps_core::lsp_helpers::hover`'s own
    /// `HOVER_FALLBACK_TIMEOUT` exists to prevent for its analogous fallback fetch. `dep` is
    /// resolved once, up front, and reused for the unlisted lookup rather than re-derived
    /// from the rendered hover afterward.
    fn generate_hover<'a>(
        &'a self,
        parse_result: &'a dyn ParseResultTrait,
        position: Position,
        versions: deps_core::VersionData<'a>,
        freshness: deps_core::FreshnessSettings,
    ) -> deps_core::ecosystem::BoxFuture<'a, Option<Hover>> {
        Box::pin(async move {
            let base_hover = deps_core::lsp_generate_hover(
                parse_result,
                position,
                versions,
                self.registry.as_ref(),
                self.formatter(),
                freshness,
                deps_core::PublishTime::now(),
            );

            // Same predicate `lsp_generate_hover` uses internally to pick a dependency: if
            // it finds none, the render above resolves to `None` too, so the unlisted fetch
            // is skipped rather than issued for a hover that will be empty anyway.
            let dep = parse_result.dependencies().into_iter().find(|d| {
                deps_core::position_in_range(position, d.name_range())
                    || d.version_range()
                        .is_some_and(|r| deps_core::position_in_range(position, r))
            });
            let Some(dep) = dep else {
                return base_hover.await;
            };

            let unlisted_fetch = tokio::time::timeout(
                HOVER_UNLISTED_TIMEOUT,
                self.registry
                    .unlisted_versions_for_hover(dep.name().as_str()),
            );

            let (hover, unlisted_result) = tokio::join!(base_hover, unlisted_fetch);
            let mut hover = hover?;

            let unlisted = match unlisted_result {
                Ok(Ok(unlisted)) => unlisted,
                Ok(Err(error)) => {
                    tracing::debug!(package = %dep.name(), %error, "hover unlisted-versions fetch failed");
                    return Some(hover);
                }
                Err(_) => {
                    tracing::warn!(
                        package = %dep.name(),
                        timeout_secs = HOVER_UNLISTED_TIMEOUT.as_secs(),
                        "hover unlisted-versions fetch timed out"
                    );
                    return Some(hover);
                }
            };
            if unlisted.is_empty() {
                return Some(hover);
            }

            if let HoverContents::Markup(content) = &mut hover.contents {
                content.value = annotate_unlisted_versions(&content.value, &unlisted);
            }

            Some(hover)
        })
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Injects a `*(unlisted)*` marker into each `"- \`VERSION\` ..."` "Recent versions" bullet
/// line whose version is in `unlisted`, right after the version literal and before any
/// existing tag (`*(latest)*`, an age suffix, ...) — matching the position/spacing
/// `formatter.yanked_label()` occupies for other ecosystems' `*(yanked)*` markers. Lines
/// that don't match the bullet format (the `**Latest**`/`**Requirement**` lines, the footer)
/// pass through unchanged.
fn annotate_unlisted_versions(markdown: &str, unlisted: &HashSet<String>) -> String {
    let mut out = String::with_capacity(markdown.len() + unlisted.len() * 14);
    for line in markdown.split_inclusive('\n') {
        let body = line.strip_suffix('\n').unwrap_or(line);
        let matched = body.strip_prefix("- `").and_then(|rest| {
            let tick = rest.find('`')?;
            Some((&rest[..tick], &rest[tick + 1..]))
        });
        match matched {
            Some((version, rest)) if unlisted.contains(version) => {
                out.push_str("- `");
                out.push_str(version);
                out.push_str("` *(unlisted)*");
                out.push_str(rest);
            }
            _ => out.push_str(body),
        }
        if line.ends_with('\n') {
            out.push('\n');
        }
    }
    out
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
        assert_eq!(
            eco.lockfile_filenames(),
            &["packages.lock.json", "packages.*.lock.json"]
        );
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

    // --- annotate_unlisted_versions (D1, #451) ---

    #[test]
    fn test_annotate_unlisted_versions_tags_matching_bullet() {
        let markdown = "**Recent versions**:\n- `2.0.0` *(latest)*\n- `1.0.0`\n";
        let unlisted: HashSet<String> = HashSet::from(["1.0.0".to_string()]);
        let out = annotate_unlisted_versions(markdown, &unlisted);
        assert!(out.contains("- `1.0.0` *(unlisted)*\n"));
        assert!(out.contains("- `2.0.0` *(latest)*\n"));
    }

    #[test]
    fn test_annotate_unlisted_versions_preserves_existing_tags_and_age_suffix() {
        let markdown = "- `1.2.1` *(yanked)* — 5 months ago\n";
        let unlisted: HashSet<String> = HashSet::from(["1.2.1".to_string()]);
        let out = annotate_unlisted_versions(markdown, &unlisted);
        assert_eq!(out, "- `1.2.1` *(unlisted)* *(yanked)* — 5 months ago\n");
    }

    #[test]
    fn test_annotate_unlisted_versions_untagged_line_when_no_match() {
        let markdown = "- `1.0.0`\n";
        let unlisted: HashSet<String> = HashSet::from(["2.0.0".to_string()]);
        assert_eq!(annotate_unlisted_versions(markdown, &unlisted), markdown);
    }

    #[test]
    fn test_annotate_unlisted_versions_leaves_non_bullet_lines_untouched() {
        let markdown = "**Latest**: `1.0.0`\n\n---\n⌨️ **Press `Cmd+.` to update version**";
        let unlisted: HashSet<String> = HashSet::from(["1.0.0".to_string()]);
        assert_eq!(annotate_unlisted_versions(markdown, &unlisted), markdown);
    }

    #[test]
    fn test_annotate_unlisted_versions_no_trailing_newline_preserved() {
        let markdown = "- `1.0.0`";
        let unlisted: HashSet<String> = HashSet::from(["1.0.0".to_string()]);
        assert_eq!(
            annotate_unlisted_versions(markdown, &unlisted),
            "- `1.0.0` *(unlisted)*"
        );
    }

    // --- generate_hover: hover-only unlisted enrichment (D1, #451) ---

    fn nuget_service_index_body(base: &str) -> String {
        format!(
            r#"{{"version": "3.0.0", "resources": [
                {{"@id": "{base}/flatcontainer", "@type": "PackageBaseAddress/3.0.0"}},
                {{"@id": "{base}/query", "@type": "SearchQueryService/3.5.0"}},
                {{"@id": "{base}/registrations", "@type": "RegistrationsBaseUrl/3.6.0"}}
            ]}}"#
        )
    }

    #[tokio::test]
    async fn test_generate_hover_marks_unlisted_recent_version() {
        let mut server = mockito::Server::new_async().await;
        let base = server.url();

        let _service_index_mock = server
            .mock("GET", "/index.json")
            .with_status(200)
            .with_body(nuget_service_index_body(&base))
            .create_async()
            .await;
        let _flat_mock = server
            .mock("GET", "/flatcontainer/newtonsoft.json/index.json")
            .with_status(200)
            .with_body(r#"{"versions": ["12.0.1", "13.0.3"]}"#)
            .create_async()
            .await;
        let _reg_mock = server
            .mock("GET", "/registrations/newtonsoft.json/index.json")
            .with_status(200)
            .with_body(
                r#"{"count": 1, "items": [{"@id": "x", "count": 2, "items": [
                    {"catalogEntry": {"version": "12.0.1", "listed": true}},
                    {"catalogEntry": {"version": "13.0.3", "listed": false}}
                ]}]}"#,
            )
            .create_async()
            .await;

        let registry = NuGetRegistry::with_service_index_url(
            Arc::new(deps_core::HttpCache::new()),
            format!("{base}/index.json"),
        );
        let eco = NuGetEcosystem::with_registry(registry);

        let uri = deps_core::test_util::test_uri("/test/App.csproj");
        let content = r#"<Project><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="13.0.3" /></ItemGroup></Project>"#;
        let parse_result = eco.parse_manifest(content, &uri).await.unwrap();

        let cached = std::collections::HashMap::new();
        let resolved = std::collections::HashMap::new();
        // Freshness disabled: proves the unlisted marker doesn't depend on the freshness
        // toggle at all (unlike `published_at`, which is gated by it) — see
        // `unlisted_versions_for_hover`'s doc comment.
        let freshness = deps_core::FreshnessSettings {
            enabled: false,
            cooldown_secs: deps_core::DEFAULT_COOLDOWN_SECS,
        };

        let hover = eco
            .generate_hover(
                parse_result.as_ref(),
                Position::new(0, 49), // inside "Newtonsoft.Json"
                deps_core::VersionData::new(&cached, &resolved),
                freshness,
            )
            .await
            .expect("hover for a resolvable in-range dependency must not be None");

        let HoverContents::Markup(content) = hover.contents else {
            panic!("expected markup hover contents");
        };
        assert!(
            content.value.contains("- `13.0.3` *(unlisted)*"),
            "unlisted version must be tagged, got: {}",
            content.value
        );
        assert!(
            !content.value.contains("`12.0.1` *(unlisted)*"),
            "listed version must not be tagged, got: {}",
            content.value
        );
    }

    #[tokio::test]
    async fn test_generate_hover_degrades_gracefully_when_registration_fetch_fails() {
        let mut server = mockito::Server::new_async().await;
        let base = server.url();

        let _service_index_mock = server
            .mock("GET", "/index.json")
            .with_status(200)
            .with_body(nuget_service_index_body(&base))
            .create_async()
            .await;
        let _flat_mock = server
            .mock("GET", "/flatcontainer/newtonsoft.json/index.json")
            .with_status(200)
            .with_body(r#"{"versions": ["13.0.3"]}"#)
            .create_async()
            .await;
        let _reg_mock = server
            .mock("GET", "/registrations/newtonsoft.json/index.json")
            .with_status(500)
            .create_async()
            .await;

        let registry = NuGetRegistry::with_service_index_url(
            Arc::new(deps_core::HttpCache::new()),
            format!("{base}/index.json"),
        );
        let eco = NuGetEcosystem::with_registry(registry);

        let uri = deps_core::test_util::test_uri("/test/App.csproj");
        let content = r#"<Project><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="13.0.3" /></ItemGroup></Project>"#;
        let parse_result = eco.parse_manifest(content, &uri).await.unwrap();

        let cached = std::collections::HashMap::new();
        let resolved = std::collections::HashMap::new();

        let hover = eco
            .generate_hover(
                parse_result.as_ref(),
                Position::new(0, 49),
                deps_core::VersionData::new(&cached, &resolved),
                deps_core::FreshnessSettings {
                    enabled: false,
                    cooldown_secs: deps_core::DEFAULT_COOLDOWN_SECS,
                },
            )
            .await
            .expect("a registration-hive failure must still degrade to the base hover");

        let HoverContents::Markup(content) = hover.contents else {
            panic!("expected markup hover contents");
        };
        assert!(content.value.contains("`13.0.3`"));
        assert!(!content.value.contains("*(unlisted)*"));
    }

    /// S4 regression (#451 follow-up): with no dependency at `position`, the base render
    /// resolves to `None` — the unlisted-versions fetch must be skipped entirely rather than
    /// issued (and awaited) for a hover response that will end up empty anyway. The `.expect(0)`
    /// mocks fail the test if either endpoint is hit.
    #[tokio::test]
    async fn test_generate_hover_skips_unlisted_fetch_when_no_dependency_at_position() {
        let mut server = mockito::Server::new_async().await;
        let base = server.url();

        let _service_index_mock = server
            .mock("GET", "/index.json")
            .with_status(200)
            .with_body(nuget_service_index_body(&base))
            .expect(0)
            .create_async()
            .await;

        let registry = NuGetRegistry::with_service_index_url(
            Arc::new(deps_core::HttpCache::new()),
            format!("{base}/index.json"),
        );
        let eco = NuGetEcosystem::with_registry(registry);

        let uri = deps_core::test_util::test_uri("/test/App.csproj");
        let content = r#"<Project><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="13.0.3" /></ItemGroup></Project>"#;
        let parse_result = eco.parse_manifest(content, &uri).await.unwrap();

        let cached = std::collections::HashMap::new();
        let resolved = std::collections::HashMap::new();

        let hover = eco
            .generate_hover(
                parse_result.as_ref(),
                Position::new(0, 0), // outside any dependency's name/version range
                deps_core::VersionData::new(&cached, &resolved),
                deps_core::FreshnessSettings {
                    enabled: false,
                    cooldown_secs: deps_core::DEFAULT_COOLDOWN_SECS,
                },
            )
            .await;

        assert!(hover.is_none());
        // `.expect(0)` above already asserts this, but check() surfaces a clear message.
        _service_index_mock.assert_async().await;
    }
}
