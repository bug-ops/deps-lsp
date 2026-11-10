//! [`TypedEcosystem`]: the typed, document-reading half of an ecosystem.
//!
//! It pairs the one parse result and formatter an ecosystem owns, and a blanket implementation
//! turns it into the erased [`Ecosystem`].

use std::sync::Arc;
#[cfg(feature = "lsp-responses")]
use tower_lsp_server::ls_types::{
    CodeAction, CodeLens, DocumentLink, InlayHint, Position, TextEdit,
};

#[cfg(feature = "lsp-responses")]
use super::EcosystemConfig;
use super::manifest::EcosystemManifest;
use super::{BoxFuture, Ecosystem, EcosystemBase, ParsedManifest};
#[cfg(feature = "lsp-responses")]
use crate::completion::Completions;
use crate::diagnostic::Diagnostic;
#[cfg(feature = "lsp-responses")]
use crate::hover::Hover;
use crate::lsp_helpers::{DependencyFormatter, EcosystemFormatter, VersionData};
use crate::typed_boundary::{ParsedView, TypedParseResult};

mod sealed {
    /// Makes [`super::super::Ecosystem`] implementable only through its blanket impl.
    pub trait BlanketOnly {}
    impl<T: super::TypedEcosystem> BlanketOnly for T {}
}

pub(super) use sealed::BlanketOnly;

/// An edit of a finished [`Hover`], produced by [`TypedEcosystem::decorate_hover`].
#[cfg(feature = "lsp-responses")]
pub type HoverDecorator<'a> = Box<dyn FnOnce(&mut Hover) + Send + 'a>;

/// When [`TypedEcosystem::decorate_hover`]'s lookup runs relative to the shared hover.
#[cfg(feature = "lsp-responses")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HoverDecoration {
    /// Alongside the shared hover, so the two requests overlap instead of stacking. Pick it for
    /// an independent fetch (NuGet's unlisted-versions lookup); the lookup cannot see anything
    /// the shared hover's own fetches record.
    Concurrent,
    /// After the shared hover returned a hover, and not at all when it is empty. Pick it when
    /// the lookup must see the interactive-fetch failure memo the shared fetch writes (GitLab
    /// CI's component-pin resolution), so a dead endpoint is asked once, not twice.
    AfterHover,
}

/// An ecosystem as its own crate writes it: [`EcosystemBase`] plus the typed pairing of a
/// parser, its parse result, and the formatter that reads that parse result's dependencies.
///
/// [`Self::Formatter`]'s [`DependencyFormatter::Dep`] must equal the parse result's
/// [`TypedParseResult::Dep`], so handing an ecosystem's formatter a dependency of another
/// ecosystem does not compile. Hooks receive a [`ParsedView`] of [`Self::Parsed`]: its
/// dependency accessors yield the first [`crate::MAX_DEPENDENCIES_PER_DOCUMENT`] dependencies,
/// while [`ParsedView::typed`] is the parser's own, already-budgeted result.
///
/// This trait is not dyn-compatible and is never used as a trait object; the blanket
/// `impl<T: TypedEcosystem> Ecosystem for T` provides the erased [`Ecosystem`].
///
/// # Examples
///
/// ```no_run
/// use deps_core::lsp_helpers::{
///     DependencyFormatter, DiagnosticMessages, DiagnosticPolicy, OsvNaming, PackageNaming,
///     PackageRendering, RequirementResolution, SourcePolicy,
/// };
/// use deps_core::position::Range;
/// use deps_core::ecosystem::{BoxFuture, private};
/// use deps_core::{
///     ConcreteVersion, EcosystemBase, EcosystemId, Metadata, PackageName, Registry,
///     TypedEcosystem, VersionReq, impl_dependency, impl_parse_result,
/// };
/// use std::sync::Arc;
/// use url::Url;
///
/// struct MyDependency {
///     name: PackageName,
///     name_range: Range,
///     version: Option<VersionReq>,
///     version_range: Option<Range>,
/// }
/// # deps_core::impl_unprobed_dependency!(MyDependency);
/// impl_dependency!(MyDependency {
///     name: name,
///     name_range: name_range,
///     version: version,
///     version_range: version_range,
/// });
///
/// struct MyParsed {
///     dependencies: Vec<MyDependency>,
///     uri: Url,
/// }
/// impl_parse_result!(MyParsed, MyDependency {
///     dependencies: dependencies,
///     uri: uri,
/// });
///
/// struct MyFormatter;
/// impl PackageNaming for MyFormatter {}
/// impl PackageRendering for MyFormatter {
///     fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String {
///         version.to_string()
///     }
///     fn package_url(&self, name: &PackageName) -> String {
///         format!("https://example.com/{}", name.as_str())
///     }
/// }
/// impl RequirementResolution for MyFormatter {}
/// impl DiagnosticMessages for MyFormatter {}
/// impl DiagnosticPolicy for MyFormatter {}
/// impl SourcePolicy for MyFormatter {}
/// impl OsvNaming for MyFormatter {}
/// impl DependencyFormatter for MyFormatter {
///     type Dep = MyDependency;
/// }
///
/// struct MyEcosystem {
///     registry: Arc<dyn Registry>,
///     formatter: MyFormatter,
/// }
/// impl private::Sealed for MyEcosystem {}
///
/// impl EcosystemBase for MyEcosystem {
///     fn ecosystem_id(&self) -> EcosystemId { EcosystemId::Cargo }
///     fn display_name(&self) -> &'static str { "My Ecosystem" }
///     fn manifest_filenames(&self) -> &[&'static str] { &["my-manifest.toml"] }
///     fn registry(&self) -> Arc<dyn Registry> { self.registry.clone() }
///     fn completion_insert_text(&self, metadata: &dyn Metadata) -> Option<String> {
///         Some(format!("\"{}\" = \"{}\"", metadata.name().as_str(), metadata.latest_version()))
///     }
/// }
///
/// impl TypedEcosystem for MyEcosystem {
///     type Parsed = MyParsed;
///     type Formatter = MyFormatter;
///
///     fn own_formatter(&self) -> &MyFormatter { &self.formatter }
///
///     fn parse<'a>(
///         &'a self,
///         _content: &'a str,
///         _uri: &'a Url,
///     ) -> BoxFuture<'a, deps_core::error::Result<MyParsed>> {
///         Box::pin(async move { todo!() })
///     }
/// }
/// ```
pub trait TypedEcosystem: EcosystemBase + Sized + 'static {
    /// The parse result this ecosystem's parser produces.
    type Parsed: TypedParseResult + 'static;

    /// The formatter that reads [`Self::Parsed`]'s dependencies; the equality of the two
    /// dependency types is what ties formatter and parser together at compile time.
    type Formatter: DependencyFormatter<Dep = <Self::Parsed as TypedParseResult>::Dep>;

    /// When [`Self::decorate_hover`]'s future runs relative to the shared hover.
    #[cfg(feature = "lsp-responses")]
    const HOVER_DECORATION: HoverDecoration = HoverDecoration::Concurrent;

    /// The ecosystem-specific formatter for LSP response generation.
    ///
    /// The formatter handles version comparison, package URLs, and text formatting.
    fn own_formatter(&self) -> &Self::Formatter;

    /// Parse a manifest file and return parsed result
    ///
    /// # Arguments
    ///
    /// * `content` - Raw file content
    /// * `uri` - Document URI for position tracking
    ///
    /// # Errors
    ///
    /// Returns error if manifest cannot be parsed
    ///
    /// # Invariant
    ///
    /// Implementations must not contain a real `.await` (no network/file I/O, no yielding to
    /// the scheduler) — the body must be synchronous work wrapped in an immediately-ready
    /// `async move` block. [`super::parse_manifest_blocking`] relies on this to drive the future via
    /// `Handle::block_on` on the blocking-thread pool; violating it doesn't deadlock, but
    /// silently reintroduces the exact worker-thread stall #743 fixed.
    fn parse<'a>(
        &'a self,
        content: &'a str,
        uri: &'a url::Url,
    ) -> BoxFuture<'a, crate::error::Result<Self::Parsed>>;

    /// Synchronous variant of [`Self::parse`] for [`super::parse_manifest_now`]'s FR-024
    /// fallback-edit-guard re-parse (spec 076, issue #1570), which only needs the re-parsed
    /// requirement's text/shape, never fully resolved source classification.
    ///
    /// The default drives [`Self::parse`]'s future via `now_or_never()`, relying on
    /// this trait's documented no-real-`.await` invariant. Override this — never make
    /// [`Self::parse`] itself lie about that invariant — when a genuine await exists
    /// (Composer's `ComposerEcosystem` overrides this for its bare vcs/path/artifact repository
    /// plus a `composer.lock` case) so this guard-only call can skip whatever that await would
    /// have resolved instead of racing `now_or_never()` against it.
    fn parse_sync(&self, content: &str, uri: &url::Url) -> Option<Self::Parsed> {
        use futures::FutureExt;
        self.parse(content, uri).now_or_never()?.ok()
    }

    /// Whether `parse_result` consulted the parse input `input` names, so a
    /// [`RefreshEvent::ReparseOpenDocuments`](crate::RefreshEvent::ReparseOpenDocuments) for it
    /// must re-parse the document.
    ///
    /// Only the ecosystem that mints [`ParseInputKey`](crate::ParseInputKey)s implements this
    /// meaningfully. The default is `true`, the safe direction: an ecosystem without an
    /// override gets every open document re-parsed, as before targeted re-parsing existed. A
    /// lagged receiver re-parses every document without asking.
    fn depends_on(
        &self,
        parsed: ParsedView<'_, Self::Parsed>,
        input: &crate::ParseInputKey,
    ) -> bool {
        let _ = (parsed, input);
        true
    }

    /// Gathers evidence in the background that synchronous, network-free diagnostics cannot
    /// (a branch of a partial tag ref, the lineage of a SHA pin, a registry identity of a
    /// source dependency), and reports whether anything changed.
    ///
    /// Called by the server from a spawned task after a document opens or changes and after a
    /// [`RefreshEvent::TagIndex`](crate::RefreshEvent::TagIndex) for a repository the document
    /// references, and by the CLI once per run. `phase` says whether the registry fetch of the
    /// document has run: a probe that decides what to fetch belongs to
    /// [`ProbePhase::PreFetch`](crate::lsp_helpers::ProbePhase::PreFetch), one that needs the
    /// fetched tag index to
    /// [`ProbePhase::PostFetch`](crate::lsp_helpers::ProbePhase::PostFetch). An implementor
    /// stores only authoritative answers, draws every optional request from its rate budget
    /// and never blocks a handler.
    ///
    /// The default does nothing and reports
    /// [`ProbeEffect::Unchanged`](crate::lsp_helpers::ProbeEffect::Unchanged).
    fn probes<'a>(
        &'a self,
        parsed: ParsedView<'a, Self::Parsed>,
        phase: crate::lsp_helpers::ProbePhase,
    ) -> BoxFuture<'a, crate::lsp_helpers::ProbeReport> {
        let _ = (parsed, phase);
        Box::pin(std::future::ready(
            crate::lsp_helpers::ProbeReport::default(),
        ))
    }

    /// Generate inlay hints for the document.
    ///
    /// Default implementation delegates to `lsp_helpers::generate_inlay_hints`
    /// using `self.own_formatter()`. Override only if custom behavior is needed.
    #[cfg(feature = "lsp-responses")]
    fn inlay_hints<'a>(
        &'a self,
        parsed: ParsedView<'a, Self::Parsed>,
        versions: VersionData<'a>,
        loading_state: crate::LoadingState,
        config: &'a EcosystemConfig,
    ) -> BoxFuture<'a, Vec<InlayHint>> {
        Box::pin(async move {
            crate::lsp_helpers::generate_inlay_hints(
                &parsed,
                versions,
                loading_state,
                config,
                self.own_formatter(),
            )
        })
    }

    /// Appends this ecosystem's own diagnostics to the shared output, which
    /// [`diagnostics`] always generates first.
    ///
    /// The shared generator cannot be skipped or re-run with different arguments, so anything
    /// it attaches (the typosquat-suspect diagnostic, `versions.license_source`, ...) reaches
    /// every ecosystem. Nothing by default.
    ///
    /// An implementation must stay cheap: it may read cached data but must not start a fetch,
    /// since every diagnostics pass of the document waits for it.
    fn decorate_diagnostics<'a>(
        &'a self,
        parsed: ParsedView<'a, Self::Parsed>,
        severities: crate::lsp_helpers::DiagnosticSeverities,
        out: &'a mut Vec<Diagnostic>,
    ) -> BoxFuture<'a, ()> {
        let _ = (parsed, severities, out);
        Box::pin(std::future::ready(()))
    }

    /// Appends this ecosystem's own code actions to the shared output, which [`code_actions`]
    /// always generates first.
    ///
    /// Async because an ecosystem may need a cached lookup (GitLab CI resolves a component
    /// pin). Nothing by default.
    #[cfg(feature = "lsp-responses")]
    fn decorate_code_actions<'a>(
        &'a self,
        parsed: ParsedView<'a, Self::Parsed>,
        position: Position,
        uri: &'a url::Url,
        versions: VersionData<'a>,
        out: &'a mut Vec<CodeAction>,
    ) -> BoxFuture<'a, ()> {
        let _ = (parsed, position, uri, versions, out);
        Box::pin(std::future::ready(()))
    }

    /// Prepares an edit of the shared hover for `hovered`, the dependency [`hover`] found once
    /// for both the shared generator and this hook.
    ///
    /// The returned future runs concurrently with the shared hover's own fetches, so any lookup
    /// belongs in it; the returned [`HoverDecorator`] is then applied to the finished hover and
    /// must not block. The default decorates nothing.
    ///
    /// [`Self::HOVER_DECORATION`] says whether the future runs beside the shared hover or after
    /// it. A decorator is applied after the shared hover either way, so it may read what the
    /// shared hover's fetches warmed (a tag index).
    #[cfg(feature = "lsp-responses")]
    fn decorate_hover<'a>(
        &'a self,
        parsed: ParsedView<'a, Self::Parsed>,
        hovered: &'a <Self::Parsed as TypedParseResult>::Dep,
        versions: VersionData<'a>,
    ) -> BoxFuture<'a, HoverDecorator<'a>> {
        let _ = (parsed, hovered, versions);
        Box::pin(std::future::ready(
            Box::new(|_: &mut Hover| {}) as HoverDecorator<'a>
        ))
    }

    /// Generate `textDocument/documentLink` targets for the document.
    ///
    /// A document link is a clickable reference from a byte range in this
    /// manifest to another resource — e.g. a `-r other.txt` / `-c
    /// constraints.txt` reference inside a pip requirements file, resolved
    /// to the absolute file it points at. Purely local (no registry access),
    /// so unlike the other `generate_*` methods this is synchronous rather
    /// than a [`BoxFuture`]. Empty by default: most ecosystems' manifest
    /// formats have no such intra-file-graph references.
    #[cfg(feature = "lsp-responses")]
    fn document_links(
        &self,
        parsed: ParsedView<'_, Self::Parsed>,
        uri: &url::Url,
    ) -> Vec<DocumentLink> {
        let _ = (parsed, uri);
        Vec::new()
    }

    /// Generate the "Update N outdated dependencies" code lens for the document.
    ///
    /// The shared "update all outdated" lens has no enable/disable toggle of its own —
    /// that's `code_lens.enabled` in `deps-lsp`'s config, gating the whole handler before
    /// this method is ever called. An ecosystem-specific bulk lens gated on a
    /// `DiagnosticSeverities` flag (e.g. GitHub Actions' "Pin N actions to commit SHA",
    /// issue #633) is wired directly in `deps-lsp`'s `handlers::code_lens`, not through an
    /// override of this method — see [`Self::pin_all_to_sha_edits`].
    ///
    /// Default implementation delegates to `lsp_helpers::generate_code_lenses` using
    /// `self.own_formatter()`. Override only if custom behavior is needed.
    #[cfg(feature = "lsp-responses")]
    fn code_lenses<'a>(
        &'a self,
        parsed: ParsedView<'a, Self::Parsed>,
        content: &'a str,
        versions: VersionData<'a>,
        uri: &'a url::Url,
        command_id: &'a str,
    ) -> BoxFuture<'a, Vec<CodeLens>> {
        Box::pin(async move {
            crate::lsp_helpers::generate_code_lenses(
                &parsed,
                content,
                versions,
                self.own_formatter(),
                uri,
                command_id,
            )
        })
    }

    /// Lifecycle hook run synchronously, once per [`Self::completions`] call,
    /// before context detection — for setup that must happen regardless of which
    /// [`crate::completion::CompletionContext`] the request turns out to be (e.g. warming a
    /// local search index that a later `PackageName` completion in the *same* manifest will
    /// want ready, even though this specific call might resolve to a different context).
    ///
    /// Must return immediately: it runs inside the async dispatch before any `.await`, so
    /// any real work (an index rebuild, a network warm-up) must be spawned rather than
    /// awaited here — never block the dispatch. Default no-op; the sole override today is
    /// `deps-pypi`'s `warm_search_index()`.
    fn prepare_completions(&self) {}

    /// Generate completions for a position.
    ///
    /// Provides autocomplete suggestions for package names, versions, and features by
    /// detecting the [`crate::completion::CompletionContext`] at `position` and dispatching
    /// to the matching hook — [`Self::complete_package_name`], [`Self::complete_version`], or
    /// [`Self::complete_feature`].
    ///
    /// The exhaustive `match` over [`crate::completion::CompletionContext`] lives here, in
    /// the crate that defines the enum, so `#[non_exhaustive]` does not apply and a new
    /// variant is a compile error in this one place instead of a silent no-op downstream
    /// (issue #793). An ecosystem that overrides this default opts out of that guarantee and
    /// takes the obligation on itself — `deps-maven` and `deps-gradle` do, because they route
    /// on their own XML/Groovy context type instead of
    /// [`crate::completion::CompletionContext`].
    ///
    /// `freshness.is_enabled()` gates whether version completion items carry a
    /// relative-age `label_details` suffix (issue #145); implementations that
    /// delegate to [`crate::completion::complete_versions_at_position`] get this for
    /// free by threading `freshness` through.
    ///
    /// The returned [`Completions::is_incomplete`] must reflect *this specific call*
    /// (the completion context actually served), not a static worst case for the
    /// ecosystem as a whole (#427): a package-name search over an unranked,
    /// truncated index should report `true`, while a version completion or any
    /// other exhaustive context in the same manifest must report `false`, even for
    /// an ecosystem where some contexts are incomplete and others are not.
    #[cfg(feature = "lsp-responses")]
    fn completions<'a>(
        &'a self,
        parsed: ParsedView<'a, Self::Parsed>,
        position: Position,
        content: &'a str,
        freshness: crate::FreshnessSettings,
    ) -> BoxFuture<'a, Completions> {
        Box::pin(async move {
            self.prepare_completions();
            let request = crate::completion::CompletionRequest::new(parsed, position, freshness);
            // Exhaustive on purpose (#793): no wildcard arm, so a new
            // `CompletionContext` variant is a compile error right here.
            match crate::completion::detect_completion_context(&parsed, position, content) {
                crate::completion::CompletionContext::PackageName { prefix, range } => self
                    .complete_package_name(request, prefix, range)
                    .await
                    .with_origin(crate::completion::CompletionOrigin::PackageName),
                crate::completion::CompletionContext::Version {
                    package_name,
                    prefix,
                } => self
                    .complete_version(request, package_name, prefix)
                    .await
                    .with_origin(crate::completion::CompletionOrigin::Version),
                crate::completion::CompletionContext::Feature {
                    package_name,
                    prefix,
                } => self
                    .complete_feature(request, package_name, prefix)
                    .await
                    .with_origin(crate::completion::CompletionOrigin::Feature),
                crate::completion::CompletionContext::None => Completions::default(),
            }
        })
    }

    /// Completion hook for a [`crate::completion::CompletionContext::PackageName`]
    /// context — called only by [`Self::completions`]'s default dispatch.
    ///
    /// `_request` is unused by most implementations (a package-name search is driven purely
    /// by `prefix`/`range`), but kept uniform with [`Self::complete_version`]/
    /// [`Self::complete_feature`] rather than dropped per-hook — a future input costs one
    /// field on [`crate::completion::CompletionRequest`] instead of a signature break on only
    /// the hooks that happen to need it today.
    ///
    /// Default: no package-name search (`Completions::default()`) — correct for an ecosystem
    /// with no package-name index (`deps-github-actions`, `deps-gitlab-ci`). Says nothing
    /// about an ecosystem that overrides [`Self::completions`] wholesale
    /// (`deps-maven`, `deps-gradle`) and so never calls this hook at all — both actually do
    /// serve package-name completion (`groupId`/`artifactId`, a Gradle coordinate), just not
    /// through this method.
    #[cfg(feature = "lsp-responses")]
    fn complete_package_name<'a>(
        &'a self,
        _request: crate::completion::CompletionRequest<'a, Self::Parsed>,
        _prefix: String,
        _range: tower_lsp_server::ls_types::Range,
    ) -> BoxFuture<'a, Completions> {
        Box::pin(std::future::ready(Completions::default()))
    }

    /// Leading version-constraint operators this ecosystem's syntax allows before a bare
    /// version (e.g. npm's `^`/`~`, PyPI's `>=`/`!=`, NuGet's bracket-interval `[`/`(`),
    /// stripped from a completion prefix before matching it against registry versions.
    ///
    /// Consumed by [`Self::complete_version`]'s default implementation, which threads it
    /// into [`crate::completion::complete_versions_at_position`]. Empty by default —
    /// correct for an ecosystem whose version requirements are bare version strings with no
    /// operator prefix (e.g. `deps-go`, `deps-swift`). An ecosystem overriding
    /// [`Self::complete_version`] directly instead of using the default is free to ignore
    /// this method entirely.
    ///
    /// A `&self` method, like [`Self::own_formatter`] and [`EcosystemBase::registry`], so every
    /// per-ecosystem value is read the same way.
    #[cfg(feature = "lsp-responses")]
    fn version_operator_chars(&self) -> &'static [char] {
        &[]
    }

    /// Completion hook for a [`crate::completion::CompletionContext::Version`] context —
    /// called only by [`Self::completions`]'s default dispatch.
    ///
    /// Required in spirit: every ecosystem serves version completion (the one property this
    /// method preserves from before #793 — requiredness is orthogonal to the wildcard-match
    /// bug class itself, which is fixed by the dispatch match's *location*, not by which hook
    /// is required). `package_name`/`prefix` come from the resolved context; several
    /// implementations ignore them and instead re-derive the dependency at
    /// `request.position` from `request.parse_result` (cursor-position-based routing, issue
    /// #593) — deliberate divergence between ecosystems, not a mistake to unify, since the
    /// two lookups can disagree (see `deps-cargo`'s position-based migration history).
    ///
    /// Default implementation delegates to
    /// [`crate::completion::complete_versions_at_position`] using `self.registry()`,
    /// `self.own_formatter()`, and [`Self::version_operator_chars`] — the pattern `deps-npm`,
    /// `deps-pypi`, `deps-go`, `deps-composer`, `deps-swift`, `deps-nuget`, `deps-cargo`,
    /// `deps-dart`, `deps-bundler`, and `deps-deno` all hand-implemented identically before
    /// this default existed (#1223). Only `deps-gradle` and `deps-maven` (both route by
    /// dependency *name* through [`crate::completion::complete_versions_generic_from`]
    /// directly, not by cursor position) and `deps-github-actions`/`deps-gitlab-ci` (each
    /// wraps [`crate::completion::complete_versions_at_position`] in ecosystem-specific
    /// guard logic — GitHub Actions withholds completion past a SHA pin's trailing comment;
    /// GitLab CI re-derives its own position-based dependency lookup with an extra
    /// literal-range check) have genuinely different version-completion behavior and
    /// override this method instead of `version_operator_chars`.
    #[cfg(feature = "lsp-responses")]
    fn complete_version<'a>(
        &'a self,
        request: crate::completion::CompletionRequest<'a, Self::Parsed>,
        _package_name: crate::PackageName,
        prefix: String,
    ) -> BoxFuture<'a, Completions> {
        Box::pin(async move {
            let registry = self.registry();
            crate::completion::complete_versions_at_position(
                self.ecosystem_id(),
                registry.as_ref(),
                self.own_formatter(),
                &request.parsed,
                request.position,
                &prefix,
                self.version_operator_chars(),
                request.freshness,
            )
            .await
            .into()
        })
    }

    /// Completion hook for a [`crate::completion::CompletionContext::Feature`] context —
    /// called only by [`Self::completions`]'s default dispatch.
    ///
    /// Default: no feature completion (`Completions::default()`) — correct for every
    /// ecosystem without a feature-flag concept. Overridden today by `deps-cargo` and
    /// `deps-go`.
    #[cfg(feature = "lsp-responses")]
    fn complete_feature<'a>(
        &'a self,
        _request: crate::completion::CompletionRequest<'a, Self::Parsed>,
        _package_name: crate::PackageName,
        _prefix: String,
    ) -> BoxFuture<'a, Completions> {
        Box::pin(std::future::ready(Completions::default()))
    }

    /// Builds the edits for this ecosystem's bulk "Pin N {noun} to commit SHA" code lens
    /// and `deps-lsp.pinAllToSha` command (issue #633, generalized cross-ecosystem in
    /// #640) — one [`TextEdit`] per mutable-ref pin resolvable to a commit SHA from
    /// already-in-hand data, mirroring [`crate::collect_update_all_edits`]'s
    /// recompute-at-click-time contract for the sibling "Update N outdated
    /// dependencies" lens.
    ///
    /// `versions` is threaded through for an ecosystem (e.g. `deps-gitlab-ci`) whose
    /// dynamic pin forms need the caller's already-fetched version data to resolve
    /// without an extra network round trip — a lens is push-based and must never block
    /// on, or trigger, a fetch. Empty by default: most ecosystems have no mutable-ref
    /// pin concept at all. The lens/command wiring itself lives in `deps-lsp`'s
    /// `handlers::code_lens` (not a trait default here), so no override of
    /// [`Self::code_lenses`] can accidentally suppress it.
    #[cfg(feature = "lsp-responses")]
    fn pin_all_to_sha_edits(
        &self,
        _parsed: ParsedView<'_, Self::Parsed>,
        _versions: VersionData<'_>,
    ) -> Vec<TextEdit> {
        Vec::new()
    }
}

impl<T: TypedEcosystem> Ecosystem for T {
    fn formatter(&self) -> &dyn EcosystemFormatter {
        self.own_formatter()
    }

    fn parse_manifest<'a>(
        self: Arc<Self>,
        content: &'a str,
        uri: &'a url::Url,
    ) -> BoxFuture<'a, crate::error::Result<Box<dyn ParsedManifest>>> {
        Box::pin(async move {
            let parsed = self.parse(content, uri).await?;
            Ok(Box::new(EcosystemManifest::new(self, parsed)) as Box<dyn ParsedManifest>)
        })
    }

    fn parse_manifest_sync(
        self: Arc<Self>,
        content: &str,
        uri: &url::Url,
    ) -> Option<Box<dyn ParsedManifest>> {
        let parsed = self.parse_sync(content, uri)?;
        Some(Box::new(EcosystemManifest::new(self, parsed)))
    }

    #[cfg(any(test, feature = "test-util"))]
    fn probe_non_public_route(
        &self,
        name: crate::PackageName,
        source: crate::parser::DependencySource,
    ) -> crate::osv::NonPublicRoute {
        use crate::lsp_helpers::ProbeDependency;
        let dep =
            <<T::Formatter as DependencyFormatter>::Dep as ProbeDependency>::probe(name, source);
        self.own_formatter().non_public_route(&dep)
    }

    #[cfg(any(test, feature = "test-util"))]
    fn probe_route_non_public_routes(
        &self,
        name: crate::PackageName,
    ) -> Vec<crate::osv::NonPublicRoute> {
        use crate::lsp_helpers::ProbeDependency;
        let formatter = self.own_formatter();
        <<T::Formatter as DependencyFormatter>::Dep as ProbeDependency>::route_probes(name)
            .iter()
            .map(|dep| formatter.non_public_route(dep))
            .collect()
    }
}

/// Generates the hover for `position`: the shared hover, edited by
/// [`TypedEcosystem::decorate_hover`] for the one dependency under the cursor.
///
/// Returns `None` when no dependency covers `position`. `versions.license_source` is attached
/// by the caller (`deps-lsp::handlers::hover`), not here, so it reaches every ecosystem alike.
///
/// # Examples
///
/// ```no_run
/// use deps_core::ecosystem::hover;
/// use deps_core::{FreshnessSettings, ParsedView, TypedEcosystem, VersionData};
/// use tower_lsp_server::ls_types::Position;
///
/// async fn hover_at<E: TypedEcosystem>(
///     eco: &E,
///     parsed: ParsedView<'_, E::Parsed>,
///     versions: VersionData<'_>,
///     freshness: FreshnessSettings,
/// ) {
///     let _ = hover(eco, parsed, Position::new(0, 0), versions, freshness).await;
/// }
/// ```
#[cfg(feature = "lsp-responses")]
pub async fn hover<'a, E: TypedEcosystem>(
    eco: &'a E,
    parsed: ParsedView<'a, E::Parsed>,
    position: Position,
    versions: VersionData<'a>,
    freshness: crate::freshness::FreshnessSettings,
) -> Option<Hover> {
    let hovered =
        crate::lsp_helpers::find_hovered_dependency(parsed.dependencies_slice(), position)?;
    let registry = eco.registry();
    let shared = crate::lsp_helpers::generate_hover(
        &parsed,
        position,
        versions,
        registry.as_ref(),
        eco.own_formatter(),
        freshness,
        crate::freshness::PublishTime::now(),
    );
    let decoration = eco.decorate_hover(parsed, hovered, versions);
    let (mut hover, decorator) = match E::HOVER_DECORATION {
        HoverDecoration::Concurrent => {
            let (hover, decorator) = futures::join!(shared, decoration);
            (hover?, decorator)
        }
        HoverDecoration::AfterHover => {
            let hover = shared.await?;
            (hover, decoration.await)
        }
    };
    decorator(&mut hover);
    Some(hover)
}

/// Generates the code actions for `position`: the shared actions, then
/// [`TypedEcosystem::decorate_code_actions`]'s.
///
/// `versions` carries the OSV scan results the shared hover and diagnostics use, so a
/// vulnerable dependency gets a "fix vulnerability" quickfix beside the plain version updates.
/// `content` is the manifest source, needed to refuse rewriting a `version_range` that no
/// longer slices to its declared requirement text.
///
/// # Examples
///
/// ```no_run
/// use deps_core::ecosystem::code_actions;
/// use deps_core::{ParsedView, TypedEcosystem, VersionData};
/// use tower_lsp_server::ls_types::Position;
///
/// async fn actions_at<E: TypedEcosystem>(
///     eco: &E,
///     parsed: ParsedView<'_, E::Parsed>,
///     uri: &url::Url,
///     versions: VersionData<'_>,
///     content: &str,
/// ) {
///     let _ = code_actions(eco, parsed, Position::new(0, 0), uri, versions, content).await;
/// }
/// ```
#[cfg(feature = "lsp-responses")]
pub async fn code_actions<'a, E: TypedEcosystem>(
    eco: &'a E,
    parsed: ParsedView<'a, E::Parsed>,
    position: Position,
    uri: &'a url::Url,
    versions: VersionData<'a>,
    content: &'a str,
) -> Vec<CodeAction> {
    let registry = eco.registry();
    let mut actions = crate::lsp_helpers::generate_code_actions(
        &parsed,
        position,
        uri,
        versions,
        content,
        registry.as_ref(),
        eco.own_formatter(),
    )
    .await;
    eco.decorate_code_actions(parsed, position, uri, versions, &mut actions)
        .await;
    actions
}

/// Generates the diagnostics for the document: the shared diagnostics, then
/// [`TypedEcosystem::decorate_diagnostics`]'s.
///
/// `versions.license_source` is attached by the caller (`deps-lsp::handlers::diagnostics`),
/// not here. The typosquat-suspect diagnostic needs nothing from an ecosystem: the shared
/// generator reads it from `versions.typosquat_prefetch`, with no `.await` on this path.
///
/// # Examples
///
/// ```no_run
/// use deps_core::ecosystem::diagnostics;
/// use deps_core::lsp_helpers::DiagnosticSeverities;
/// use deps_core::{FreshnessSettings, ParsedView, TypedEcosystem, VersionData};
///
/// async fn diagnose<E: TypedEcosystem>(
///     eco: &E,
///     parsed: ParsedView<'_, E::Parsed>,
///     versions: VersionData<'_>,
///     uri: &url::Url,
///     freshness: FreshnessSettings,
///     severities: DiagnosticSeverities,
/// ) {
///     let _ = diagnostics(eco, parsed, versions, uri, freshness, severities).await;
/// }
/// ```
pub async fn diagnostics<'a, E: TypedEcosystem>(
    eco: &'a E,
    parsed: ParsedView<'a, E::Parsed>,
    versions: VersionData<'a>,
    uri: &'a url::Url,
    freshness: crate::freshness::FreshnessSettings,
    severities: crate::lsp_helpers::DiagnosticSeverities,
) -> Vec<Diagnostic> {
    let mut out = crate::lsp_helpers::generate_diagnostics_from_cache(
        &parsed,
        versions,
        eco.own_formatter(),
        uri,
        freshness,
        severities,
        crate::freshness::PublishTime::now(),
    );
    eco.decorate_diagnostics(parsed, severities, &mut out).await;
    out
}
