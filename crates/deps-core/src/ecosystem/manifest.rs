//! [`ParsedManifest`]: a parsed document paired with the ecosystem that parsed it.
//!
//! Erased code (`deps-lsp`'s document state, `deps-engine`, `deps-cli`) never holds a
//! [`ParseResult`] apart from its [`TypedEcosystem`]: it holds a `Box<dyn ParsedManifest>`, whose
//! vtable was instantiated for exactly one ecosystem. The hooks below are the erased
//! counterparts of [`TypedEcosystem`]'s typed hooks, without the parse-result argument, so a
//! mismatched pairing cannot be expressed.

use std::collections::HashMap;
use std::sync::Arc;
#[cfg(feature = "lsp-responses")]
use tower_lsp_server::ls_types::{
    CodeAction, CodeLens, DocumentLink, InlayHint, Position, TextEdit,
};

#[cfg(feature = "lsp-responses")]
use super::EcosystemConfig;
use super::{
    BlockedRegistryOccurrence, BoxFuture, Dependency, ParseResult, RejectedRegistryOccurrence,
    TypedEcosystem,
};
#[cfg(feature = "lsp-responses")]
use crate::completion::Completions;
use crate::dependency_cap::MAX_DEPENDENCIES_PER_DOCUMENT;
use crate::diagnostic::Diagnostic;
use crate::edit::UpdateCandidate;
#[cfg(feature = "lsp-responses")]
use crate::hover::Hover;
use crate::lsp_helpers::{BoundDependency, FormattedDependency, VersionData};
use crate::osv::VulnKeys;
use crate::selection::{InvalidStabilityOccurrence, SelectionContext};
use crate::typed_boundary::{ParsedView, TypedParseResult};
use crate::{ConcreteVersion, NormalizedName};

/// A parsed document together with the [`TypedEcosystem`] that produced it.
///
/// Returned by [`Ecosystem::parse_manifest`](super::Ecosystem::parse_manifest). Its hooks mirror
/// [`TypedEcosystem`]'s, with the document and the ecosystem's formatter supplied by the object
/// itself. The document is capped: [`ParseResult::dependencies`] and
/// [`Self::for_each_formatted_dependency`] yield the same first
/// [`MAX_DEPENDENCIES_PER_DOCUMENT`] dependencies, in the same order, and
/// [`ParseResult::dependency_truncation`] reports what was dropped.
///
/// # Examples
///
/// ```
/// use deps_core::test_util::{stub_document, stub_parse_result};
///
/// let manifest = stub_document(stub_parse_result(2));
/// let mut names = Vec::new();
/// manifest.for_each_formatted_dependency(&mut |dep| {
///     names.push(dep.dependency().name().as_str().to_owned());
/// });
/// assert_eq!(names, ["dep-0", "dep-1"]);
/// ```
pub trait ParsedManifest: ParseResult + crate::sealed::ParsedManifest {
    /// Whether the document consulted the parse input `input` names, see
    /// [`TypedEcosystem::depends_on`].
    fn parse_depends_on(&self, input: &crate::ParseInputKey) -> bool;

    /// The identity of the ecosystem that parsed the document.
    ///
    /// Callers read it here instead of taking it as a separate parameter, so a manifest can never
    /// be paired with the identity of another ecosystem.
    fn ecosystem_id(&self) -> crate::EcosystemId;

    /// The formatter of the ecosystem instance that parsed the document.
    ///
    /// The same instance [`Self::for_each_formatted_dependency`] binds each dependency to, so
    /// keys normalized with it agree with every verdict computed from the document.
    fn formatter(&self) -> &dyn crate::lsp_helpers::EcosystemFormatter;

    /// Gathers background evidence for the document, see [`TypedEcosystem::probes`].
    fn background_probes(
        &self,
        phase: crate::lsp_helpers::ProbePhase,
    ) -> BoxFuture<'_, crate::lsp_helpers::ProbeReport>;

    /// Inlay hints for the document, see [`TypedEcosystem::inlay_hints`].
    #[cfg(feature = "lsp-responses")]
    fn generate_inlay_hints<'a>(
        &'a self,
        versions: VersionData<'a>,
        loading_state: crate::LoadingState,
        config: &'a EcosystemConfig,
    ) -> BoxFuture<'a, Vec<InlayHint>>;

    /// Hover for a position, see [`super::hover`].
    #[cfg(feature = "lsp-responses")]
    fn generate_hover<'a>(
        &'a self,
        position: Position,
        versions: VersionData<'a>,
        freshness: crate::freshness::FreshnessSettings,
    ) -> BoxFuture<'a, Option<Hover>>;

    /// Code actions for a position, see [`super::code_actions`].
    #[cfg(feature = "lsp-responses")]
    fn generate_code_actions<'a>(
        &'a self,
        position: Position,
        uri: &'a url::Url,
        versions: VersionData<'a>,
        content: &'a str,
    ) -> BoxFuture<'a, Vec<CodeAction>>;

    /// Diagnostics for the document, see [`super::diagnostics`].
    fn generate_diagnostics<'a>(
        &'a self,
        versions: VersionData<'a>,
        uri: &'a url::Url,
        freshness: crate::freshness::FreshnessSettings,
        severities: crate::lsp_helpers::DiagnosticSeverities,
    ) -> BoxFuture<'a, Vec<Diagnostic>>;

    /// Document links, see [`TypedEcosystem::document_links`].
    #[cfg(feature = "lsp-responses")]
    fn generate_document_links(&self, uri: &url::Url) -> Vec<DocumentLink>;

    /// Code lenses, see [`TypedEcosystem::code_lenses`].
    #[cfg(feature = "lsp-responses")]
    fn generate_code_lenses<'a>(
        &'a self,
        content: &'a str,
        versions: VersionData<'a>,
        uri: &'a url::Url,
        command_id: &'a str,
    ) -> BoxFuture<'a, Vec<CodeLens>>;

    /// Completions at a position, see [`TypedEcosystem::completions`].
    #[cfg(feature = "lsp-responses")]
    fn generate_completions<'a>(
        &'a self,
        position: Position,
        content: &'a str,
        freshness: crate::FreshnessSettings,
    ) -> BoxFuture<'a, Completions>;

    /// Edits of the bulk "pin to commit SHA" lens, see [`TypedEcosystem::pin_all_to_sha_edits`].
    #[cfg(feature = "lsp-responses")]
    fn collect_pin_all_to_sha_edits(&self, versions: VersionData<'_>) -> Vec<TextEdit>;

    /// Edits of the "update all outdated dependencies" lens, see
    /// [`crate::lsp_helpers::collect_update_all_edits`].
    #[cfg(feature = "lsp-responses")]
    fn collect_update_all_edits(&self, content: &str, versions: VersionData<'_>) -> Vec<TextEdit>;

    /// The update candidates of the document, see [`crate::edit::collect_update_candidates`].
    fn collect_update_candidates(
        &self,
        content: &str,
        versions: VersionData<'_>,
    ) -> Vec<UpdateCandidate>;

    /// The vulnerability lookup keys of the document, see [`crate::osv::vulnerability_keys`].
    ///
    /// The ecosystem identity is the one of the ecosystem that parsed the document.
    fn vulnerability_keys(
        &self,
        resolved: &HashMap<NormalizedName, ConcreteVersion>,
        resolved_candidates: Option<&crate::lsp_helpers::ResolvedCandidatesMap>,
    ) -> VulnKeys;

    /// Calls `visit` once per dependency, in [`ParseResult::dependencies`] order, with the
    /// dependency bound to its ecosystem's formatter.
    ///
    /// The visitor is synchronous: collect owned data inside the callback and await outside it.
    /// The `&dyn FormattedDependency` is valid only during the call; only
    /// [`FormattedDependency::dependency`], which borrows from the document, may escape.
    fn for_each_formatted_dependency<'a>(
        &'a self,
        visit: &mut dyn FnMut(&dyn FormattedDependency<'a>),
    );
}

/// The one [`ParsedManifest`]: the document `parsed` by an `Arc<E>`, capped to
/// [`MAX_DEPENDENCIES_PER_DOCUMENT`] dependencies.
pub(crate) struct EcosystemManifest<E: TypedEcosystem> {
    ecosystem: Arc<E>,
    parsed: E::Parsed,
    total: usize,
    limit: usize,
}

impl<E: TypedEcosystem> EcosystemManifest<E> {
    /// Pairs `parsed` with the `ecosystem` that produced it.
    pub(crate) fn new(ecosystem: Arc<E>, parsed: E::Parsed) -> Self {
        let total = parsed.own_dependencies().len();
        Self {
            ecosystem,
            parsed,
            total,
            limit: total.min(MAX_DEPENDENCIES_PER_DOCUMENT),
        }
    }

    fn view(&self) -> ParsedView<'_, E::Parsed> {
        ParsedView::capped(&self.parsed, self, self.limit)
    }
}

#[deny(clippy::missing_trait_methods)]
impl<E: TypedEcosystem> ParseResult for EcosystemManifest<E> {
    fn dependencies(&self) -> Vec<&dyn Dependency> {
        self.view()
            .dependencies_slice()
            .iter()
            .map(|dep| dep as &dyn Dependency)
            .collect()
    }

    fn workspace_root(&self) -> Option<&std::path::Path> {
        self.parsed.workspace_root()
    }

    fn uri(&self) -> &url::Url {
        self.parsed.uri()
    }

    fn blocked_registries(&self) -> Vec<BlockedRegistryOccurrence> {
        self.parsed.blocked_registries()
    }

    fn selection_context(&self) -> SelectionContext {
        self.parsed.selection_context()
    }

    fn invalid_minimum_stability(&self) -> Option<InvalidStabilityOccurrence> {
        self.parsed.invalid_minimum_stability()
    }

    fn rejected_registries(&self) -> Vec<RejectedRegistryOccurrence> {
        self.parsed.rejected_registries()
    }

    fn dependency_truncation(&self) -> Option<crate::DependencyTruncation> {
        if self.total > MAX_DEPENDENCIES_PER_DOCUMENT {
            Some(crate::DependencyTruncation {
                kept: MAX_DEPENDENCIES_PER_DOCUMENT,
                total: self.total,
            })
        } else {
            self.parsed.dependency_truncation()
        }
    }
}

impl<E: TypedEcosystem> crate::sealed::ParsedManifest for EcosystemManifest<E> {}

impl<E: TypedEcosystem> ParsedManifest for EcosystemManifest<E> {
    fn parse_depends_on(&self, input: &crate::ParseInputKey) -> bool {
        self.ecosystem.depends_on(self.view(), input)
    }

    fn ecosystem_id(&self) -> crate::EcosystemId {
        self.ecosystem.ecosystem_id()
    }

    fn formatter(&self) -> &dyn crate::lsp_helpers::EcosystemFormatter {
        self.ecosystem.own_formatter()
    }

    fn background_probes(
        &self,
        phase: crate::lsp_helpers::ProbePhase,
    ) -> BoxFuture<'_, crate::lsp_helpers::ProbeReport> {
        self.ecosystem.probes(self.view(), phase)
    }

    #[cfg(feature = "lsp-responses")]
    fn generate_inlay_hints<'a>(
        &'a self,
        versions: VersionData<'a>,
        loading_state: crate::LoadingState,
        config: &'a EcosystemConfig,
    ) -> BoxFuture<'a, Vec<InlayHint>> {
        self.ecosystem
            .inlay_hints(self.view(), versions, loading_state, config)
    }

    #[cfg(feature = "lsp-responses")]
    fn generate_hover<'a>(
        &'a self,
        position: Position,
        versions: VersionData<'a>,
        freshness: crate::freshness::FreshnessSettings,
    ) -> BoxFuture<'a, Option<Hover>> {
        Box::pin(super::hover(
            &*self.ecosystem,
            self.view(),
            position,
            versions,
            freshness,
        ))
    }

    #[cfg(feature = "lsp-responses")]
    fn generate_code_actions<'a>(
        &'a self,
        position: Position,
        uri: &'a url::Url,
        versions: VersionData<'a>,
        content: &'a str,
    ) -> BoxFuture<'a, Vec<CodeAction>> {
        Box::pin(super::code_actions(
            &*self.ecosystem,
            self.view(),
            position,
            uri,
            versions,
            content,
        ))
    }

    fn generate_diagnostics<'a>(
        &'a self,
        versions: VersionData<'a>,
        uri: &'a url::Url,
        freshness: crate::freshness::FreshnessSettings,
        severities: crate::lsp_helpers::DiagnosticSeverities,
    ) -> BoxFuture<'a, Vec<Diagnostic>> {
        Box::pin(super::diagnostics(
            &*self.ecosystem,
            self.view(),
            versions,
            uri,
            freshness,
            severities,
        ))
    }

    #[cfg(feature = "lsp-responses")]
    fn generate_document_links(&self, uri: &url::Url) -> Vec<DocumentLink> {
        self.ecosystem.document_links(self.view(), uri)
    }

    #[cfg(feature = "lsp-responses")]
    fn generate_code_lenses<'a>(
        &'a self,
        content: &'a str,
        versions: VersionData<'a>,
        uri: &'a url::Url,
        command_id: &'a str,
    ) -> BoxFuture<'a, Vec<CodeLens>> {
        self.ecosystem
            .code_lenses(self.view(), content, versions, uri, command_id)
    }

    #[cfg(feature = "lsp-responses")]
    fn generate_completions<'a>(
        &'a self,
        position: Position,
        content: &'a str,
        freshness: crate::FreshnessSettings,
    ) -> BoxFuture<'a, Completions> {
        self.ecosystem
            .completions(self.view(), position, content, freshness)
    }

    #[cfg(feature = "lsp-responses")]
    fn collect_pin_all_to_sha_edits(&self, versions: VersionData<'_>) -> Vec<TextEdit> {
        self.ecosystem.pin_all_to_sha_edits(self.view(), versions)
    }

    #[cfg(feature = "lsp-responses")]
    fn collect_update_all_edits(&self, content: &str, versions: VersionData<'_>) -> Vec<TextEdit> {
        crate::lsp_helpers::collect_update_all_edits(
            &self.view(),
            content,
            versions,
            self.ecosystem.own_formatter(),
        )
    }

    fn collect_update_candidates(
        &self,
        content: &str,
        versions: VersionData<'_>,
    ) -> Vec<UpdateCandidate> {
        crate::edit::collect_update_candidates(
            &self.view(),
            content,
            versions,
            self.ecosystem.own_formatter(),
        )
    }

    fn vulnerability_keys(
        &self,
        resolved: &HashMap<NormalizedName, ConcreteVersion>,
        resolved_candidates: Option<&crate::lsp_helpers::ResolvedCandidatesMap>,
    ) -> VulnKeys {
        crate::osv::vulnerability_keys(
            &self.view(),
            resolved,
            resolved_candidates,
            self.ecosystem.own_formatter(),
            self.ecosystem.ecosystem_id(),
        )
    }

    fn for_each_formatted_dependency<'a>(
        &'a self,
        visit: &mut dyn FnMut(&dyn FormattedDependency<'a>),
    ) {
        let formatter = self.ecosystem.own_formatter();
        for dep in self.view().dependencies_slice() {
            visit(&BoundDependency::new(formatter, dep));
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use crate::net_policy::{BlockedHost, HostClass, RegistryRejectionReason};
    use crate::position::{Position as CorePosition, Range};
    use crate::selection::StabilityFloor;
    use crate::test_util::{StubDependency, StubEcosystem, test_uri};

    /// A parse result with every optional [`ParseResult`] value set to a non-default.
    struct Fixture {
        deps: Vec<StubDependency>,
        uri: url::Url,
    }

    impl Fixture {
        fn with_dependencies(count: usize) -> Self {
            Self {
                deps: (0..count)
                    .map(|i| StubDependency::new(&format!("dep-{i}")))
                    .collect(),
                uri: test_uri("/project/manifest.json"),
            }
        }
    }

    fn range() -> Range {
        Range::new(CorePosition::new(1, 2), CorePosition::new(1, 6))
    }

    impl ParseResult for Fixture {
        fn dependencies(&self) -> Vec<&dyn Dependency> {
            self.deps.iter().map(|d| d as &dyn Dependency).collect()
        }

        fn workspace_root(&self) -> Option<&Path> {
            Some(Path::new("/project"))
        }

        fn uri(&self) -> &url::Url {
            &self.uri
        }

        fn blocked_registries(&self) -> Vec<BlockedRegistryOccurrence> {
            vec![BlockedRegistryOccurrence {
                range: range(),
                block: BlockedHost::floor(HostClass::Loopback).unwrap(),
                raw_value: "https://blocked.example".to_string(),
                declaration_key: "blocked-key".to_string(),
            }]
        }

        fn selection_context(&self) -> SelectionContext {
            SelectionContext::with_minimum_stability(StabilityFloor::Beta)
        }

        fn invalid_minimum_stability(&self) -> Option<InvalidStabilityOccurrence> {
            Some(InvalidStabilityOccurrence {
                range: range(),
                raw: "betta".to_string(),
            })
        }

        fn rejected_registries(&self) -> Vec<RejectedRegistryOccurrence> {
            vec![RejectedRegistryOccurrence {
                range: range(),
                reason: RegistryRejectionReason::InvalidUrl,
                raw_value: "not-a-url".to_string(),
                declaration_key: "rejected-key".to_string(),
            }]
        }

        fn dependency_truncation(&self) -> Option<crate::DependencyTruncation> {
            Some(crate::DependencyTruncation { kept: 7, total: 9 })
        }
    }

    impl TypedParseResult for Fixture {
        type Dep = StubDependency;

        fn own_dependencies(&self) -> &[StubDependency] {
            &self.deps
        }
    }

    fn manifest(count: usize) -> EcosystemManifest<StubEcosystem<Fixture>> {
        EcosystemManifest::new(
            Arc::new(StubEcosystem::new()),
            Fixture::with_dependencies(count),
        )
    }

    fn assert_forwards_inner(outer: &dyn ParseResult, inner: &Fixture) {
        assert_eq!(outer.workspace_root(), Some(Path::new("/project")));
        assert_eq!(outer.uri(), inner.uri());
        assert_eq!(outer.selection_context(), inner.selection_context());
        let blocked = outer.blocked_registries();
        assert_eq!(blocked.len(), 1);
        assert_eq!(blocked[0].declaration_key, "blocked-key");
        let rejected = outer.rejected_registries();
        assert_eq!(rejected.len(), 1);
        assert_eq!(rejected[0].declaration_key, "rejected-key");
        assert_eq!(
            outer.invalid_minimum_stability().map(|o| o.raw),
            Some("betta".to_string())
        );
    }

    #[test]
    fn forwards_every_parse_result_method() {
        let manifest = manifest(3);
        assert_forwards_inner(&manifest, &manifest.parsed);
        assert_forwards_inner(&manifest.view(), &manifest.parsed);
        assert_eq!(manifest.dependencies().len(), 3);
        assert_eq!(
            manifest.dependency_truncation(),
            Some(crate::DependencyTruncation { kept: 7, total: 9 }),
            "an uncapped document reports the parser's own truncation"
        );
        assert_eq!(
            manifest.view().dependency_truncation(),
            Some(crate::DependencyTruncation { kept: 7, total: 9 })
        );
    }

    #[test]
    fn caps_dependencies_over_the_ceiling_and_reports_the_truncation() {
        let manifest = manifest(MAX_DEPENDENCIES_PER_DOCUMENT + 1);

        assert_eq!(manifest.dependencies().len(), MAX_DEPENDENCIES_PER_DOCUMENT);
        assert_eq!(
            manifest.view().own_dependencies().len(),
            MAX_DEPENDENCIES_PER_DOCUMENT
        );
        assert_eq!(
            manifest.dependency_truncation(),
            Some(crate::DependencyTruncation {
                kept: MAX_DEPENDENCIES_PER_DOCUMENT,
                total: MAX_DEPENDENCIES_PER_DOCUMENT + 1,
            })
        );
        assert_forwards_inner(&manifest, &manifest.parsed);
    }

    #[test]
    fn formatted_dependencies_match_capped_dependencies() {
        let manifest = manifest(MAX_DEPENDENCIES_PER_DOCUMENT + 1);
        let mut visited = Vec::new();
        manifest.for_each_formatted_dependency(&mut |dep| {
            visited.push(dep.dependency().name().as_str().to_owned());
        });

        let erased: Vec<String> = manifest
            .dependencies()
            .iter()
            .map(|dep| dep.name().as_str().to_owned())
            .collect();
        assert_eq!(visited.len(), MAX_DEPENDENCIES_PER_DOCUMENT);
        assert_eq!(visited, erased, "same set, same order");
    }

    #[test]
    fn a_document_exactly_at_the_ceiling_is_not_truncated() {
        let manifest = manifest(MAX_DEPENDENCIES_PER_DOCUMENT);

        assert_eq!(manifest.dependencies().len(), MAX_DEPENDENCIES_PER_DOCUMENT);
        assert_eq!(
            manifest.dependency_truncation(),
            Some(crate::DependencyTruncation { kept: 7, total: 9 }),
            "at the ceiling the parser's own truncation is reported, not a cap"
        );

        let plain = crate::test_util::stub_document(crate::test_util::stub_parse_result(
            MAX_DEPENDENCIES_PER_DOCUMENT,
        ));
        assert_eq!(plain.dependency_truncation(), None);
    }

    /// Formatter that counts `public_content` calls, which `vulnerability_keys` makes once per
    /// dependency it sees.
    struct CountingFormatter {
        public_content_calls: std::sync::atomic::AtomicUsize,
    }

    impl crate::lsp_helpers::PackageNaming for CountingFormatter {}
    impl crate::lsp_helpers::PackageRendering for CountingFormatter {
        fn format_version_for_text_edit(&self, version: &crate::ConcreteVersion) -> String {
            version.to_string()
        }
        fn package_url(&self, name: &crate::PackageName) -> String {
            name.as_str().to_string()
        }
    }
    impl crate::lsp_helpers::RequirementResolution for CountingFormatter {}
    impl crate::lsp_helpers::DiagnosticMessages for CountingFormatter {}
    impl crate::lsp_helpers::DiagnosticPolicy for CountingFormatter {}
    impl crate::lsp_helpers::SourcePolicy for CountingFormatter {}
    impl crate::lsp_helpers::OsvNaming for CountingFormatter {}
    impl crate::lsp_helpers::DependencyFormatter for CountingFormatter {
        type Dep = StubDependency;

        fn public_content<'d>(
            &self,
            dep: &'d StubDependency,
        ) -> Option<crate::lsp_helpers::PublicContent<'d>> {
            self.public_content_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Some(crate::lsp_helpers::PublicContent {
                name: std::borrow::Cow::Borrowed(dep.name()),
            })
        }
    }

    type Observed = std::sync::Arc<std::sync::Mutex<Vec<(&'static str, usize)>>>;

    /// Ecosystem whose every typed hook records how many dependencies its view exposes, both
    /// typed and erased.
    struct RecordingEcosystem {
        observed: Observed,
        formatter: CountingFormatter,
    }

    impl RecordingEcosystem {
        fn record(
            &self,
            hook: &'static str,
            parsed: ParsedView<'_, crate::test_util::StubParseResult>,
        ) {
            let typed = parsed.own_dependencies().len();
            assert_eq!(
                typed,
                parsed.dependencies().len(),
                "{hook}: typed and erased views differ"
            );
            self.observed.lock().unwrap().push((hook, typed));
        }
    }

    impl crate::ecosystem::private::Sealed for RecordingEcosystem {}

    impl crate::EcosystemBase for RecordingEcosystem {
        fn ecosystem_id(&self) -> crate::EcosystemId {
            crate::EcosystemId::Cargo
        }
        fn display_name(&self) -> &'static str {
            "Recording"
        }
        fn manifest_filenames(&self) -> &[&'static str] {
            &[]
        }
        fn registry(&self) -> Arc<dyn crate::Registry> {
            Arc::new(crate::test_util::MockRegistry::new())
        }
        fn completion_insert_text(&self, _metadata: &dyn crate::Metadata) -> Option<String> {
            None
        }
    }

    impl TypedEcosystem for RecordingEcosystem {
        type Parsed = crate::test_util::StubParseResult;
        type Formatter = CountingFormatter;

        fn own_formatter(&self) -> &CountingFormatter {
            &self.formatter
        }

        fn parse<'a>(
            &'a self,
            _content: &'a str,
            _uri: &'a url::Url,
        ) -> BoxFuture<'a, crate::error::Result<Self::Parsed>> {
            Box::pin(async move { unimplemented!() })
        }

        fn depends_on(
            &self,
            parsed: ParsedView<'_, Self::Parsed>,
            _input: &crate::ParseInputKey,
        ) -> bool {
            self.record("depends_on", parsed);
            true
        }

        fn probes<'a>(
            &'a self,
            parsed: ParsedView<'a, Self::Parsed>,
            _phase: crate::lsp_helpers::ProbePhase,
        ) -> BoxFuture<'a, crate::lsp_helpers::ProbeReport> {
            self.record("probes", parsed);
            Box::pin(std::future::ready(
                crate::lsp_helpers::ProbeReport::default(),
            ))
        }

        fn decorate_diagnostics<'a>(
            &'a self,
            parsed: ParsedView<'a, Self::Parsed>,
            _severities: crate::lsp_helpers::DiagnosticSeverities,
            _out: &'a mut Vec<Diagnostic>,
        ) -> BoxFuture<'a, ()> {
            self.record("diagnostics", parsed);
            Box::pin(std::future::ready(()))
        }

        #[cfg(feature = "lsp-responses")]
        fn inlay_hints<'a>(
            &'a self,
            parsed: ParsedView<'a, Self::Parsed>,
            _versions: VersionData<'a>,
            _loading_state: crate::LoadingState,
            _config: &'a EcosystemConfig,
        ) -> BoxFuture<'a, Vec<InlayHint>> {
            self.record("inlay_hints", parsed);
            Box::pin(std::future::ready(Vec::new()))
        }

        #[cfg(feature = "lsp-responses")]
        fn decorate_hover<'a>(
            &'a self,
            parsed: ParsedView<'a, Self::Parsed>,
            _hovered: &'a crate::test_util::StubDependency,
            _versions: VersionData<'a>,
        ) -> BoxFuture<'a, crate::ecosystem::HoverDecorator<'a>> {
            self.record("hover", parsed);
            Box::pin(std::future::ready(
                Box::new(|_: &mut Hover| {}) as crate::ecosystem::HoverDecorator<'a>
            ))
        }

        #[cfg(feature = "lsp-responses")]
        fn decorate_code_actions<'a>(
            &'a self,
            parsed: ParsedView<'a, Self::Parsed>,
            _position: Position,
            _uri: &'a url::Url,
            _versions: VersionData<'a>,
            _out: &'a mut Vec<CodeAction>,
        ) -> BoxFuture<'a, ()> {
            self.record("code_actions", parsed);
            Box::pin(std::future::ready(()))
        }

        #[cfg(feature = "lsp-responses")]
        fn document_links(
            &self,
            parsed: ParsedView<'_, Self::Parsed>,
            _uri: &url::Url,
        ) -> Vec<DocumentLink> {
            self.record("document_links", parsed);
            Vec::new()
        }

        #[cfg(feature = "lsp-responses")]
        fn code_lenses<'a>(
            &'a self,
            parsed: ParsedView<'a, Self::Parsed>,
            _content: &'a str,
            _versions: VersionData<'a>,
            _uri: &'a url::Url,
            _command_id: &'a str,
        ) -> BoxFuture<'a, Vec<CodeLens>> {
            self.record("code_lenses", parsed);
            Box::pin(std::future::ready(Vec::new()))
        }

        #[cfg(feature = "lsp-responses")]
        fn completions<'a>(
            &'a self,
            parsed: ParsedView<'a, Self::Parsed>,
            _position: Position,
            _content: &'a str,
            _freshness: crate::FreshnessSettings,
        ) -> BoxFuture<'a, Completions> {
            self.record("completions", parsed);
            Box::pin(std::future::ready(Completions::default()))
        }

        #[cfg(feature = "lsp-responses")]
        fn pin_all_to_sha_edits(
            &self,
            parsed: ParsedView<'_, Self::Parsed>,
            _versions: VersionData<'_>,
        ) -> Vec<TextEdit> {
            self.record("pin_all_to_sha_edits", parsed);
            Vec::new()
        }
    }

    fn recording_manifest(
        count: usize,
    ) -> (Box<dyn ParsedManifest>, Observed, Arc<RecordingEcosystem>) {
        let observed = Observed::default();
        let ecosystem = Arc::new(RecordingEcosystem {
            observed: Arc::clone(&observed),
            formatter: CountingFormatter {
                public_content_calls: std::sync::atomic::AtomicUsize::new(0),
            },
        });
        let parsed =
            crate::test_util::StubParseResult::new(test_uri("/project/manifest.json"), count);
        let manifest = EcosystemManifest::new(Arc::clone(&ecosystem), parsed);
        (Box::new(manifest), observed, ecosystem)
    }

    fn public_content_calls(ecosystem: &RecordingEcosystem) -> usize {
        ecosystem
            .formatter
            .public_content_calls
            .swap(0, std::sync::atomic::Ordering::SeqCst)
    }

    /// A parse result whose erased `dependencies()` disagrees with its typed slice.
    struct Disagreeing(crate::test_util::StubParseResult);

    impl ParseResult for Disagreeing {
        fn dependencies(&self) -> Vec<&dyn Dependency> {
            let mut deps = self.0.dependencies();
            deps.reverse();
            deps
        }

        fn workspace_root(&self) -> Option<&Path> {
            None
        }

        fn uri(&self) -> &url::Url {
            self.0.uri()
        }
    }

    impl TypedParseResult for Disagreeing {
        type Dep = StubDependency;

        fn own_dependencies(&self) -> &[StubDependency] {
            self.0.own_dependencies()
        }
    }

    #[test]
    fn erased_dependencies_follow_the_typed_slice_the_visitor_uses() {
        let parsed = crate::test_util::StubParseResult::new(test_uri("/project/manifest.json"), 3);
        let manifest = crate::test_util::stub_document(Disagreeing(parsed));
        let erased: Vec<String> = manifest
            .dependencies()
            .iter()
            .map(|dep| dep.name().as_str().to_owned())
            .collect();
        let mut visited = Vec::new();
        manifest.for_each_formatted_dependency(&mut |bound| {
            visited.push(bound.dependency().name().as_str().to_owned());
        });
        assert_eq!(erased, ["dep-0", "dep-1", "dep-2"]);
        assert_eq!(erased, visited);
    }

    #[test]
    fn the_manifest_reports_the_identity_and_formatter_of_its_parsing_ecosystem() {
        let document = crate::test_util::stub_document_with(
            crate::test_util::stub_parse_result(1),
            crate::test_util::StubFormatter::DEFAULT.for_dependency::<StubDependency>(),
            crate::EcosystemId::Pypi,
        );
        assert_eq!(document.ecosystem_id(), crate::EcosystemId::Pypi);
        let mut seen = Vec::new();
        document.for_each_formatted_dependency(&mut |bound| {
            seen.push(std::ptr::addr_eq(
                std::ptr::from_ref(bound.formatter()),
                std::ptr::from_ref(document.formatter()),
            ));
        });
        assert_eq!(seen, [true]);
    }

    #[tokio::test]
    async fn every_hook_sees_exactly_the_capped_dependencies() {
        let (manifest, observed, ecosystem) = recording_manifest(MAX_DEPENDENCIES_PER_DOCUMENT + 1);
        let cached = HashMap::new();
        let resolved = HashMap::new();
        let versions =
            || VersionData::new(&cached, &resolved).with_ecosystem(crate::EcosystemId::Cargo);
        let uri = test_uri("/project/manifest.json");

        manifest.parse_depends_on(&crate::ParseInputKey::minted_by(
            crate::EcosystemId::Cargo,
            "input",
        ));
        manifest
            .background_probes(crate::lsp_helpers::ProbePhase::PreFetch)
            .await;
        manifest
            .generate_diagnostics(
                versions(),
                &uri,
                crate::freshness::FreshnessSettings::default(),
                crate::lsp_helpers::DiagnosticSeverities::default(),
            )
            .await;
        #[cfg(feature = "lsp-responses")]
        {
            let position = Position::new(0, 0);
            let freshness = crate::FreshnessSettings::default();
            manifest
                .generate_inlay_hints(
                    versions(),
                    crate::LoadingState::default(),
                    &EcosystemConfig::new(),
                )
                .await;
            manifest
                .generate_hover(position, versions(), freshness)
                .await;
            manifest
                .generate_code_actions(position, &uri, versions(), "")
                .await;
            manifest.generate_document_links(&uri);
            manifest
                .generate_code_lenses("", versions(), &uri, "cmd")
                .await;
            manifest.generate_completions(position, "", freshness).await;
            manifest.collect_pin_all_to_sha_edits(versions());
        }

        let observed = observed.lock().unwrap().clone();
        let expected_hooks: &[&str] = &[
            "depends_on",
            "probes",
            "diagnostics",
            #[cfg(feature = "lsp-responses")]
            "inlay_hints",
            #[cfg(feature = "lsp-responses")]
            "hover",
            #[cfg(feature = "lsp-responses")]
            "code_actions",
            #[cfg(feature = "lsp-responses")]
            "document_links",
            #[cfg(feature = "lsp-responses")]
            "code_lenses",
            #[cfg(feature = "lsp-responses")]
            "completions",
            #[cfg(feature = "lsp-responses")]
            "pin_all_to_sha_edits",
        ];
        let hooks: Vec<&str> = observed.iter().map(|(hook, _)| *hook).collect();
        assert_eq!(hooks, expected_hooks);
        for (hook, seen) in observed {
            assert_eq!(
                seen, MAX_DEPENDENCIES_PER_DOCUMENT,
                "{hook} saw an uncapped document"
            );
        }

        // The operations that go through `vulnerability_keys` ask the formatter once per
        // dependency they see.
        public_content_calls(&ecosystem);
        manifest.vulnerability_keys(&HashMap::new(), None);
        assert_eq!(
            public_content_calls(&ecosystem),
            MAX_DEPENDENCIES_PER_DOCUMENT
        );
        manifest.collect_update_candidates("", versions());
        assert_eq!(
            public_content_calls(&ecosystem),
            MAX_DEPENDENCIES_PER_DOCUMENT
        );
        #[cfg(feature = "lsp-responses")]
        {
            manifest.collect_update_all_edits("", versions());
            assert_eq!(
                public_content_calls(&ecosystem),
                MAX_DEPENDENCIES_PER_DOCUMENT
            );
        }
    }
}
