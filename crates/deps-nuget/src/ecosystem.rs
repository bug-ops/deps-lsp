//! NuGet ecosystem implementation for deps-lsp.
//!
//! # Private/custom feeds (issue #523)
//!
//! `NuGetEcosystem::parse_manifest` resolves the manifest directory's in-repo `NuGet.Config`
//! ancestor chain (`crate::config::resolve_with_context`) after parsing, stamps each dependency's
//! [`deps_core::parser::DependencySource`] from it, and registers every implied routing chain
//! against the shared [`NuGetRegistry`] — see `crate::config`'s module doc for the full
//! `<packageSources>`/`<packageSourceMapping>` resolution model. Parsers in `parser.rs` stay
//! config-blind (always construct `DependencySource::Registry`); only this module threads
//! config resolution in, mirroring `deps-pypi`'s/`deps-cargo`'s split.
//!
//! # Unknown/unresolvable packages
//!
//! A 404 or otherwise-unknown package must degrade to **no diagnostic, no inlay hint, no
//! error marker** (S4) — this already falls out of `deps-lsp`'s generic error handling around
//! `Registry::get_latest_matching` (a fetch error or `Ok(None)` both simply omit the
//! package from `cached_versions`), so no special-casing is needed here.

use std::any::Any;
use std::collections::HashSet;
use std::sync::Arc;
use tower_lsp_server::ls_types::{CompletionItem, Hover, HoverContents, Position, Range, Uri};

use deps_core::{
    Ecosystem, ParseResult as ParseResultTrait, Registry, Result, completion::Completions,
    lsp_helpers::EcosystemFormatter, parser::DependencySource,
};

use crate::config::NuGetParseContext;
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
    context: NuGetParseContext,
}

impl NuGetEcosystem {
    pub fn new(cache: Arc<deps_core::HttpCache>) -> Self {
        Self::with_context(
            Arc::new(NuGetRegistry::new(cache)),
            NuGetParseContext::default(),
        )
    }

    /// Creates a new NuGet ecosystem sharing `context`'s reachability policy and
    /// `NuGet.Config` memoization cache, around an existing [`NuGetRegistry`] instance — the
    /// production constructor, used by `deps-lsp`'s `register_ecosystems` so
    /// `initialize`/`workspace/didChangeConfiguration` can update the same
    /// `Arc<RegistryAccessPolicy>` this ecosystem's every parse reads (mirrors `deps-npm`'s/
    /// `deps-pypi`'s identical split — `Self::new`'s default, disconnected policy would never
    /// see a live update).
    #[must_use]
    pub fn with_context(registry: Arc<NuGetRegistry>, context: NuGetParseContext) -> Self {
        Self {
            registry,
            formatter: NuGetFormatter,
            lockfile_provider: Arc::new(NuGetLockParser),
            context,
        }
    }

    /// Completes package names by searching the NuGet registry.
    ///
    /// Deliberately source-blind (mirrors `deps-npm::ecosystem::NpmEcosystem::
    /// complete_package_names`'s identical rationale): the string here is a prefix the user
    /// typed into the name field, not a resolved private dependency name, so it is safe to
    /// send to api.nuget.org unconditionally — unlike [`Self::complete_versions`].
    async fn complete_package_names(&self, prefix: &str, range: Range) -> Vec<CompletionItem> {
        deps_core::completion::complete_package_names_generic(
            self.registry.as_ref(),
            prefix,
            20,
            range,
        )
        .await
    }

    /// Completes version requirements for the dependency at `position`, resolved by cursor
    /// position rather than by name (issue #593) — delegates to
    /// [`deps_core::completion::complete_versions_at_position`], which mirrors
    /// `deps_gitlab_ci::ecosystem::GitLabCiEcosystem::generate_completions`'s reference
    /// pattern. Position-based lookup also fixes a residual gap in the old name-based
    /// routing (issue #523): two dependencies sharing one `PackageName` but resolving to
    /// different sources used to collapse into an ambiguous, empty result for both
    /// occurrences, even though the cursor position unambiguously identifies which one the
    /// user is editing.
    ///
    /// An unresolvable source still offers no completions rather than risking a private
    /// package name lookup against api.nuget.org — the shared helper's gate is what keeps
    /// `Registry::get_versions_from`'s permissive routing of an unrecognized source to the
    /// default public client (matching hover/diagnostics/code-actions' identical gate) from
    /// leaking one for completions too.
    async fn complete_versions(
        &self,
        parse_result: &dyn ParseResultTrait,
        position: Position,
        prefix: &str,
        freshness: deps_core::FreshnessSettings,
    ) -> Vec<CompletionItem> {
        deps_core::completion::complete_versions_at_position(
            self.registry.as_ref(),
            &self.formatter,
            parse_result,
            position,
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
        Self::with_context(Arc::new(registry), NuGetParseContext::default())
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
            let mut result = Self::parse_by_filename(content, uri)?;

            // Issue #523: a non-file URI (or one `Uri::to_file_path` cannot resolve) has no
            // directory to walk `NuGet.Config` discovery from — falls back to the default
            // (empty) `NuGetConfig`, which resolves every dependency to
            // `DependencySource::Registry` (byte-identical to pre-feature behavior), rather
            // than failing the whole parse.
            let config = uri
                .to_file_path()
                .and_then(|path| path.parent().map(std::path::Path::to_path_buf))
                .map(|dir| {
                    crate::config::resolve_with_context(
                        &dir,
                        &self.context.config_cache,
                        &self.context.policy,
                        self.context.user_profile_config.as_deref(),
                        &self.context.user_profile_sources,
                    )
                })
                .unwrap_or_default();

            for dep in &mut result.dependencies {
                dep.source = config.resolve_source_for(&dep.name);
            }
            result.resolved_chains = config.resolved_chains();
            for chain in &result.resolved_chains {
                NuGetRegistry::register_chain(&self.registry, chain, &self.context.policy);
            }

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
                CompletionContext::Version { prefix, .. } => {
                    self.complete_versions(parse_result, position, &prefix, freshness)
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
    ///
    /// **Issue #523 fix**: the unlisted fetch is only issued when `dep.source()` is plain
    /// `DependencySource::Registry` — `self.registry` here is always the `Public`-tier root,
    /// so calling `unlisted_versions_for_hover` unconditionally would send a private-feed
    /// dependency's real package name to `api.nuget.org`, defeating the entire feature
    /// (`NuGetRegistry::unlisted_versions_for_hover`'s own tier gate only fires when the
    /// *callee* instance is `WorkspaceDeclared`, which the root never is). A private-feed
    /// dependency simply renders without the `*(unlisted)*` decoration — registration-hive
    /// enrichment is already skipped entirely for alternate feeds in phase 1 (see that
    /// method's own tier gate), so this loses nothing a private-feed hover would have shown
    /// anyway.
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

            // C1 fix (issue #523), widened by #562/FR-012: an `AlternateRegistry` dependency
            // now routes the unlisted-versions fetch through its own registered alternate
            // client (registration-hive enrichment is no longer skipped for alternate feeds) —
            // never against `self.registry` (the `Public`-tier root), which would send a
            // private-feed dependency's real package name to `api.nuget.org`. An unregistered
            // (unresolvable) alternate index, or any other source kind, skips the fetch
            // entirely rather than risk that leak.
            let unlisted_client: Option<Arc<NuGetRegistry>> = match dep.source() {
                DependencySource::Registry => Some(Arc::clone(&self.registry)),
                DependencySource::AlternateRegistry { index, .. } => {
                    self.registry.alternate_client(&index)
                }
                _ => None,
            };
            let Some(unlisted_client) = unlisted_client else {
                return base_hover.await;
            };

            let unlisted_fetch = tokio::time::timeout(
                HOVER_UNLISTED_TIMEOUT,
                unlisted_client.unlisted_versions_for_hover(dep.name().as_str()),
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
    use crate::types::NuGetDependency;

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

    // --- complete_versions: position-based dependency lookup + can_resolve_source gate (issue #593) ---

    /// A dependency on `line`, with a `version_range` there so position-based lookup (issue
    /// #593) can find it — mirrors `deps_go::ecosystem::tests::dep_with_source`.
    fn dep_with_source(name: &str, source: DependencySource, line: u32) -> NuGetDependency {
        NuGetDependency {
            name: name.into(),
            name_range: Range::new(Position::new(line, 0), Position::new(line, 0)),
            version_requirement: Some("1.0.0".into()),
            version_range: Some(Range::new(Position::new(line, 0), Position::new(line, 10))),
            source,
        }
    }

    #[tokio::test]
    async fn test_complete_versions_position_based_lookup_finds_correct_dependency() {
        let mut server = mockito::Server::new_async().await;
        let base = server.url();
        let _index_mock = server
            .mock("GET", "/index.json")
            .with_status(200)
            .with_body(nuget_service_index_body(&base))
            .create_async()
            .await;
        let _flat_mock = server
            .mock("GET", "/flatcontainer/targetpkg/index.json")
            .with_status(200)
            .with_body(r#"{"versions": ["1.0.0", "1.2.0"]}"#)
            .create_async()
            .await;

        let registry = NuGetRegistry::with_service_index_url(
            Arc::new(deps_core::HttpCache::new()),
            format!("{base}/index.json"),
        );
        let eco = NuGetEcosystem::with_registry(registry);

        // "otherpkg" has no mock registered — if position-based lookup picked it instead of
        // the dependency actually under the cursor, this would fail closed to empty instead
        // of returning `targetpkg`'s versions.
        let other = dep_with_source("otherpkg", DependencySource::Registry, 0);
        let target = dep_with_source("targetpkg", DependencySource::Registry, 1);
        let target_position = target.version_range.unwrap().start;
        let parse_result = NuGetParseResult {
            dependencies: vec![other, target],
            uri: deps_core::test_util::test_uri("/test/App.csproj"),
            resolved_chains: Vec::new(),
        };

        let results = eco
            .complete_versions(
                &parse_result,
                target_position,
                "1",
                deps_core::FreshnessSettings::default(),
            )
            .await;
        assert!(
            !results.is_empty(),
            "position-based lookup must resolve the dependency at the cursor position"
        );
    }

    #[tokio::test]
    async fn test_complete_versions_no_dependency_at_position_offers_nothing() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = NuGetEcosystem::new(cache);

        let dep = dep_with_source("somepkg", DependencySource::Registry, 0);
        let parse_result = NuGetParseResult {
            dependencies: vec![dep],
            uri: deps_core::test_util::test_uri("/test/App.csproj"),
            resolved_chains: Vec::new(),
        };

        let results = eco
            .complete_versions(
                &parse_result,
                Position::new(99, 0),
                "1",
                deps_core::FreshnessSettings::default(),
            )
            .await;
        assert!(results.is_empty());
    }

    /// `can_resolve_source`'s gate (matching hover/diagnostics/code-actions' identical check,
    /// #248 leak class) must keep an unresolvable `CustomRegistry` source from ever reaching
    /// api.nuget.org. The `.expect(0)` mock fails the test if that endpoint is hit at all.
    #[tokio::test]
    async fn test_complete_versions_gate_blocks_unresolvable_source() {
        let mut server = mockito::Server::new_async().await;
        let base = server.url();
        let _index_mock = server
            .mock("GET", "/index.json")
            .expect(0)
            .create_async()
            .await;

        let registry = NuGetRegistry::with_service_index_url(
            Arc::new(deps_core::HttpCache::new()),
            format!("{base}/index.json"),
        );
        let eco = NuGetEcosystem::with_registry(registry);

        let dep = dep_with_source(
            "privatepkg",
            DependencySource::CustomRegistry {
                url: "https://feed.mycorp.example/v3/index.json".to_string(),
            },
            0,
        );
        let position = dep.version_range.unwrap().start;
        let parse_result = NuGetParseResult {
            dependencies: vec![dep],
            uri: deps_core::test_util::test_uri("/test/App.csproj"),
            resolved_chains: Vec::new(),
        };

        let results = eco
            .complete_versions(
                &parse_result,
                position,
                "1",
                deps_core::FreshnessSettings::default(),
            )
            .await;
        assert!(
            results.is_empty(),
            "an unresolvable CustomRegistry source must offer no completions"
        );
        _index_mock.assert_async().await;
    }

    /// An `AlternateRegistry` source whose index has no registered client offers no
    /// completions rather than falling back to the public registry.
    #[tokio::test]
    async fn test_complete_versions_unregistered_alternate_offers_nothing() {
        let mut server = mockito::Server::new_async().await;
        let base = server.url();
        let _index_mock = server
            .mock("GET", "/index.json")
            .expect(0)
            .create_async()
            .await;

        let registry = NuGetRegistry::with_service_index_url(
            Arc::new(deps_core::HttpCache::new()),
            format!("{base}/index.json"),
        );
        let eco = NuGetEcosystem::with_registry(registry);

        let dep = dep_with_source(
            "internal.auth",
            DependencySource::AlternateRegistry {
                index: "nuget-chain:never-registered".to_string(),
                mirrors_crates_io: false,
            },
            0,
        );
        let position = dep.version_range.unwrap().start;
        let parse_result = NuGetParseResult {
            dependencies: vec![dep],
            uri: deps_core::test_util::test_uri("/test/App.csproj"),
            resolved_chains: Vec::new(),
        };

        let results = eco
            .complete_versions(
                &parse_result,
                position,
                "1.",
                deps_core::FreshnessSettings::default(),
            )
            .await;
        assert!(
            results.is_empty(),
            "unregistered alternate index must offer no completions"
        );
        _index_mock.assert_async().await;
    }

    /// A registered `AlternateRegistry` chain routes `complete_versions` through its own
    /// client, never the public root registry.
    #[tokio::test]
    async fn test_complete_versions_routes_to_registered_alternate_client() {
        let mut alt_server = mockito::Server::new_async().await;
        let alt_base = alt_server.url();
        let _alt_index_mock = alt_server
            .mock("GET", "/index.json")
            .with_status(200)
            .with_body(nuget_service_index_body(&alt_base))
            .create_async()
            .await;
        let _alt_flat_mock = alt_server
            .mock("GET", "/flatcontainer/internal.auth/index.json")
            .with_status(200)
            .with_body(r#"{"versions": ["1.2.3", "1.3.0"]}"#)
            .create_async()
            .await;

        let mut public_server = mockito::Server::new_async().await;
        let public_base = public_server.url();
        let _public_index_mock = public_server
            .mock("GET", "/index.json")
            .expect(0)
            .create_async()
            .await;

        let policy = Arc::new(deps_core::net_policy::RegistryAccessPolicy::new(
            deps_core::net_policy::WorkspaceRegistryAccess::All,
        ));
        let root = Arc::new(NuGetRegistry::with_service_index_url(
            Arc::new(deps_core::HttpCache::new()),
            format!("{public_base}/index.json"),
        ));

        let feed_url =
            crate::config::NuGetFeedUrl::new(&format!("{alt_base}/index.json"), &policy).unwrap();
        let chain = crate::config::NuGetSourceChain {
            key: "nuget-chain:test-alt".to_string(),
            hops: vec![crate::config::ResolvedHop {
                url: feed_url,
                slot: None,
                auth: None,
            }],
            implicit_public_fallback: false,
        };
        NuGetRegistry::register_chain(&root, &chain, &policy);

        let context = crate::config::NuGetParseContext {
            policy: Arc::clone(&policy),
            config_cache: Arc::new(crate::config::NuGetConfigCache::new()),
            user_profile_config: None,
            user_profile_sources: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };
        let eco = NuGetEcosystem::with_context(root, context);

        let dep = dep_with_source(
            "internal.auth",
            DependencySource::AlternateRegistry {
                index: "nuget-chain:test-alt".to_string(),
                mirrors_crates_io: false,
            },
            0,
        );
        let position = dep.version_range.unwrap().start;
        let parse_result = NuGetParseResult {
            dependencies: vec![dep],
            uri: deps_core::test_util::test_uri("/test/App.csproj"),
            resolved_chains: Vec::new(),
        };

        let results = eco
            .complete_versions(
                &parse_result,
                position,
                "1.",
                deps_core::FreshnessSettings::default(),
            )
            .await;
        assert!(
            !results.is_empty(),
            "a registered alternate index must route completions through its own client"
        );
        _public_index_mock.assert_async().await;
    }

    /// Two dependencies sharing one `PackageName` but resolving to different sources must
    /// route independently by cursor position, not collapse into an ambiguous "offer nothing
    /// for either" result.
    #[tokio::test]
    async fn test_complete_versions_same_name_different_sources_routes_by_position() {
        let mut server = mockito::Server::new_async().await;
        let base = server.url();
        let _index_mock = server
            .mock("GET", "/index.json")
            .expect(0)
            .create_async()
            .await;

        let registry = NuGetRegistry::with_service_index_url(
            Arc::new(deps_core::HttpCache::new()),
            format!("{base}/index.json"),
        );
        let eco = NuGetEcosystem::with_registry(registry);

        let registry_dep = dep_with_source("shared.pkg", DependencySource::Registry, 0);
        let alternate_dep = dep_with_source(
            "shared.pkg",
            DependencySource::AlternateRegistry {
                index: "nuget-chain:never-registered".to_string(),
                mirrors_crates_io: false,
            },
            1,
        );
        let alternate_position = alternate_dep.version_range.unwrap().start;
        let parse_result = NuGetParseResult {
            dependencies: vec![registry_dep, alternate_dep],
            uri: deps_core::test_util::test_uri("/test/App.csproj"),
            resolved_chains: Vec::new(),
        };

        // The alternate occurrence resolves deterministically without network: its index was
        // never registered, so the fetch fails closed with `PackageNotFound` before any HTTP
        // call — proving its own source, not the co-occurring `Registry`-sourced entry, drove
        // the routing. The `.expect(0)` mock proves no fallback to the public registry either.
        let results = eco
            .complete_versions(
                &parse_result,
                alternate_position,
                "1",
                deps_core::FreshnessSettings::default(),
            )
            .await;
        assert!(
            results.is_empty(),
            "unregistered alternate index must offer no completions, not fall back to the \
             co-occurring Registry-sourced entry"
        );
        _index_mock.assert_async().await;
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

    // --- private feed end-to-end (issue #523) ---

    /// C1 end-to-end: a root `NuGet.Config` `<clear/>` + CorpFeed must resolve a private
    /// package's versions from CorpFeed alone — the root registry's own service index (the
    /// production api.nuget.org stand-in here) must receive **zero** requests, proving the
    /// resurrection bug (#248 class) is closed at the real `parse_manifest`/`Registry`
    /// call path, not just at `NuGetConfig`'s own unit-test level.
    #[tokio::test]
    async fn test_private_feed_clear_resolves_zero_requests_to_public_registry() {
        let mut server = mockito::Server::new_async().await;
        let base = server.url();

        let _public_index_mock = server
            .mock("GET", "/public/index.json")
            .with_status(200)
            .expect(0)
            .create_async()
            .await;
        let _corp_index_mock = server
            .mock("GET", "/corp/index.json")
            .with_status(200)
            .with_body(nuget_service_index_body(&format!("{base}/corp")))
            .create_async()
            .await;
        let _corp_flat_mock = server
            .mock("GET", "/corp/flatcontainer/mycompany.internal/index.json")
            .with_status(200)
            .with_body(r#"{"versions": ["1.2.3"]}"#)
            .create_async()
            .await;

        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("NuGet.Config"),
            format!(
                r#"<configuration><packageSources>
                    <clear />
                    <add key="CorpFeed" value="{base}/corp/index.json" />
                </packageSources></configuration>"#
            ),
        )
        .unwrap();
        let manifest_path = dir.path().join("App.csproj");
        let content = r#"<Project><ItemGroup><PackageReference Include="MyCompany.Internal" Version="1.0.0" /></ItemGroup></Project>"#;
        std::fs::write(&manifest_path, content).unwrap();
        let uri = tower_lsp_server::ls_types::Uri::from_file_path(&manifest_path).unwrap();

        let registry = NuGetRegistry::with_service_index_url(
            Arc::new(deps_core::HttpCache::new()),
            format!("{base}/public/index.json"),
        );
        let policy = Arc::new(deps_core::net_policy::RegistryAccessPolicy::new(
            deps_core::net_policy::WorkspaceRegistryAccess::All,
        ));
        let context = crate::config::NuGetParseContext {
            policy: Arc::clone(&policy),
            config_cache: Arc::new(crate::config::NuGetConfigCache::new()),
            user_profile_config: None,
            user_profile_sources: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };
        let eco = NuGetEcosystem::with_context(Arc::new(registry), context);

        let parse_result = eco.parse_manifest(content, &uri).await.unwrap();
        let dep = parse_result
            .dependencies()
            .into_iter()
            .find(|d| d.name().as_str() == "MyCompany.Internal")
            .expect("dependency must be present");
        let source = dep.source();
        assert!(
            matches!(source, DependencySource::AlternateRegistry { .. }),
            "expected AlternateRegistry, got {source:?}"
        );
        let name = dep.name().clone();

        let versions = eco
            .registry
            .as_ref()
            .get_versions_from(&name, &source, deps_core::FreshnessSettings::default())
            .await
            .unwrap();
        assert_eq!(versions.len(), 1);

        _public_index_mock.assert_async().await;
        _corp_index_mock.assert_async().await;
        _corp_flat_mock.assert_async().await;
    }

    /// C1 regression (impl-critic): `generate_hover`'s unlisted-versions decoration must
    /// never fire against the public root registry for a dependency that resolved to a
    /// private feed — before the fix, `unlisted_versions_for_hover` was called unconditionally
    /// on `self.registry` (always `Public`-tier), sending the private package's real name to
    /// the mocked-as-public-registry endpoint regardless of which feed it actually resolved
    /// to. The `.expect(0)` mock fails the test if that endpoint is ever hit.
    #[tokio::test]
    async fn test_generate_hover_skips_unlisted_fetch_for_private_feed_dependency() {
        let mut server = mockito::Server::new_async().await;
        let base = server.url();

        let _public_index_mock = server
            .mock("GET", "/public/index.json")
            .with_status(200)
            .expect(0)
            .create_async()
            .await;
        let _corp_index_mock = server
            .mock("GET", "/corp/index.json")
            .with_status(200)
            .with_body(nuget_service_index_body(&format!("{base}/corp")))
            .create_async()
            .await;
        let _corp_flat_mock = server
            .mock("GET", "/corp/flatcontainer/mycompany.internal/index.json")
            .with_status(200)
            .with_body(r#"{"versions": ["1.2.3"]}"#)
            .create_async()
            .await;

        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("NuGet.Config"),
            format!(
                r#"<configuration><packageSources>
                    <clear />
                    <add key="CorpFeed" value="{base}/corp/index.json" />
                </packageSources></configuration>"#
            ),
        )
        .unwrap();
        let manifest_path = dir.path().join("App.csproj");
        let content = r#"<Project><ItemGroup><PackageReference Include="MyCompany.Internal" Version="1.0.0" /></ItemGroup></Project>"#;
        std::fs::write(&manifest_path, content).unwrap();
        let uri = tower_lsp_server::ls_types::Uri::from_file_path(&manifest_path).unwrap();

        let registry = NuGetRegistry::with_service_index_url(
            Arc::new(deps_core::HttpCache::new()),
            format!("{base}/public/index.json"),
        );
        let policy = Arc::new(deps_core::net_policy::RegistryAccessPolicy::new(
            deps_core::net_policy::WorkspaceRegistryAccess::All,
        ));
        let context = crate::config::NuGetParseContext {
            policy: Arc::clone(&policy),
            config_cache: Arc::new(crate::config::NuGetConfigCache::new()),
            user_profile_config: None,
            user_profile_sources: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };
        let eco = NuGetEcosystem::with_context(Arc::new(registry), context);

        let parse_result = eco.parse_manifest(content, &uri).await.unwrap();
        // Position inside "MyCompany.Internal" in the Include attribute.
        let position = Position::new(0, 49);

        let cached = std::collections::HashMap::new();
        let resolved = std::collections::HashMap::new();
        let hover = eco
            .generate_hover(
                parse_result.as_ref(),
                position,
                deps_core::VersionData::new(&cached, &resolved),
                deps_core::FreshnessSettings {
                    enabled: false,
                    cooldown_secs: deps_core::DEFAULT_COOLDOWN_SECS,
                },
            )
            .await;

        assert!(
            hover.is_some(),
            "expected a hover render for a resolvable in-range dependency"
        );
        _public_index_mock.assert_async().await;
    }

    /// SC-004/US-004 (issue #562, FR-012): a package resolved via a workspace-declared
    /// (`AlternateRegistry`) feed now gets the same hover-only `*(unlisted)*` marker a
    /// public-registry dependency gets — registration-hive enrichment is no longer skipped for
    /// alternate feeds.
    #[tokio::test]
    async fn test_generate_hover_marks_unlisted_for_alternate_registry_dependency() {
        let mut server = mockito::Server::new_async().await;
        let base = server.url();

        let _corp_index_mock = server
            .mock("GET", "/corp/index.json")
            .with_status(200)
            .with_body(nuget_service_index_body(&format!("{base}/corp")))
            .create_async()
            .await;
        let _corp_flat_mock = server
            .mock("GET", "/corp/flatcontainer/mycompany.internal/index.json")
            .with_status(200)
            .with_body(r#"{"versions": ["1.2.3"]}"#)
            .create_async()
            .await;
        let _corp_reg_mock = server
            .mock("GET", "/corp/registrations/mycompany.internal/index.json")
            .with_status(200)
            .with_body(
                r#"{"count": 1, "items": [{"@id": "x", "count": 1, "items": [
                    {"catalogEntry": {"version": "1.2.3", "listed": false}}
                ]}]}"#,
            )
            .create_async()
            .await;

        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("NuGet.Config"),
            format!(
                r#"<configuration><packageSources>
                    <clear />
                    <add key="CorpFeed" value="{base}/corp/index.json" />
                </packageSources></configuration>"#
            ),
        )
        .unwrap();
        let manifest_path = dir.path().join("App.csproj");
        let content = r#"<Project><ItemGroup><PackageReference Include="MyCompany.Internal" Version="1.2.3" /></ItemGroup></Project>"#;
        std::fs::write(&manifest_path, content).unwrap();
        let uri = tower_lsp_server::ls_types::Uri::from_file_path(&manifest_path).unwrap();

        let registry = NuGetRegistry::with_service_index_url(
            Arc::new(deps_core::HttpCache::new()),
            format!("{base}/public/index.json"),
        );
        let policy = Arc::new(deps_core::net_policy::RegistryAccessPolicy::new(
            deps_core::net_policy::WorkspaceRegistryAccess::All,
        ));
        let context = crate::config::NuGetParseContext {
            policy: Arc::clone(&policy),
            config_cache: Arc::new(crate::config::NuGetConfigCache::new()),
            user_profile_config: None,
            user_profile_sources: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };
        let eco = NuGetEcosystem::with_context(Arc::new(registry), context);

        let parse_result = eco.parse_manifest(content, &uri).await.unwrap();
        let position = Position::new(0, 49); // inside "MyCompany.Internal"

        let cached = std::collections::HashMap::new();
        let resolved = std::collections::HashMap::new();
        let hover = eco
            .generate_hover(
                parse_result.as_ref(),
                position,
                deps_core::VersionData::new(&cached, &resolved),
                deps_core::FreshnessSettings {
                    enabled: false,
                    cooldown_secs: deps_core::DEFAULT_COOLDOWN_SECS,
                },
            )
            .await
            .expect("hover for a resolvable alternate-feed dependency must not be None");

        let HoverContents::Markup(content) = hover.contents else {
            panic!("expected markup hover contents");
        };
        assert!(
            content.value.contains("- `1.2.3` *(unlisted)*"),
            "expected the alternate-feed dependency's unlisted marker, got: {}",
            content.value
        );
        _corp_index_mock.assert_async().await;
        _corp_flat_mock.assert_async().await;
        _corp_reg_mock.assert_async().await;
    }
}
