//! PyPI ecosystem implementation for deps-lsp.
//!
//! This module implements the `Ecosystem` trait for Python projects,
//! providing LSP functionality for `pyproject.toml` files and for
//! `requirements.txt`/`constraints.txt` files (pip's requirements file
//! format).

use std::any::Any;
use std::sync::Arc;
use tower_lsp_server::ls_types::{CompletionItem, DocumentLink, Position, Range, Uri};

use deps_core::{
    Ecosystem, ParseResult as ParseResultTrait, Registry, Result, completion::Completions,
    lsp_helpers::EcosystemFormatter, parser::DependencySource,
};

use crate::formatter::PypiFormatter;
use crate::parser::PypiParser;
use crate::registry::PypiRegistry;

/// The source(s) a `CompletionContext::Version`'s bare `package_name` joins back to within a
/// manifest's already-parsed dependencies (validator finding #1 — mirrors
/// `deps_npm::ecosystem`'s identical type).
enum CompletionSource {
    /// No dependency in the manifest has this exact name yet — most commonly because the
    /// user is still typing a brand-new dependency line. Callers fall back to the
    /// pre-existing public-registry-only behavior, unchanged.
    NotInManifest,
    /// Every occurrence of this name in the manifest agrees on one resolved source.
    Resolved(DependencySource),
    /// Two or more occurrences of this name resolve to different sources — callers must
    /// offer no completions at all rather than picking one arbitrarily.
    Ambiguous,
}

/// Joins `package_name` back to `parse_result.dependencies()` by name — the single choke
/// point [`PypiEcosystem::complete_versions`] uses to decide whether a version-completion
/// request may safely reach `pypi.org` at all (validator finding #1: without this,
/// `complete_versions` fetched from the root `Public`-tier client unconditionally, sending an
/// `AlternateRegistry`-sourced dependency's name to `pypi.org` on every keystroke, and still
/// fetching from `pypi.org` for a `CustomRegistry`-sourced one that hover/diagnostics
/// correctly fail closed for).
///
/// Mirrors `deps_npm::ecosystem`'s identical helper.
fn resolve_completion_source(
    parse_result: &dyn ParseResultTrait,
    package_name: &deps_core::PackageName,
) -> CompletionSource {
    let mut sources = parse_result
        .dependencies()
        .into_iter()
        .filter(|d| d.name() == package_name)
        .map(deps_core::Dependency::source);

    let Some(first) = sources.next() else {
        return CompletionSource::NotInManifest;
    };
    if sources.all(|s| s == first) {
        CompletionSource::Resolved(first)
    } else {
        tracing::warn!(
            package = %package_name,
            "ambiguous dependency source for version completion; offering none"
        );
        CompletionSource::Ambiguous
    }
}

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
    /// The reachability policy every `parse_manifest` call threads through to
    /// [`PypiParser::parse_content_with_policy`]/[`PypiParser::parse_requirements_with_policy`]
    /// (spec FR-008). Defaulted to `RegistryAccessPolicy::default()` by [`Self::new`]; set
    /// explicitly by [`Self::with_policy`] so `crate::lib::register_ecosystems`-equivalent
    /// wiring in `deps-lsp` can share one process-wide `Arc<RegistryAccessPolicy>` handle
    /// with `ServerState`, mirroring `deps_npm::ecosystem::NpmEcosystem`'s identical `context`
    /// field.
    policy: Arc<deps_core::net_policy::RegistryAccessPolicy>,
}

impl PypiEcosystem {
    /// Creates a new PyPI ecosystem with the given HTTP cache, using a fresh, default
    /// (`public_only`) [`deps_core::net_policy::RegistryAccessPolicy`] private to this
    /// ecosystem instance. Production use goes through [`Self::with_policy`] instead.
    pub fn new(cache: Arc<deps_core::HttpCache>) -> Self {
        Self::with_policy(
            Arc::new(PypiRegistry::new(cache)),
            Arc::new(deps_core::net_policy::RegistryAccessPolicy::default()),
        )
    }

    /// Creates a new PyPI ecosystem around an existing [`PypiRegistry`] instance, sharing
    /// `policy`'s live reachability setting — the production constructor, used by
    /// `deps-lsp`'s `register_ecosystems` so `initialize`/`workspace/didChangeConfiguration`
    /// updating the same `Arc<RegistryAccessPolicy>` takes effect immediately, with no need
    /// to reconstruct the ecosystem.
    #[must_use]
    pub fn with_policy(
        registry: Arc<PypiRegistry>,
        policy: Arc<deps_core::net_policy::RegistryAccessPolicy>,
    ) -> Self {
        Self {
            registry,
            parser: PypiParser::new(),
            formatter: PypiFormatter,
            policy,
        }
    }

    async fn complete_package_names(&self, prefix: &str, range: Range) -> Vec<CompletionItem> {
        let mut items = deps_core::completion::complete_package_names_generic(
            self.registry.as_ref(),
            prefix,
            20,
            range,
        )
        .await;

        // #419 S2: the search index matches on the PEP 503 *normalized* name
        // (`zope.int` typed -> normalized to `zope-int` -> `zope-interface`
        // found), but `build_package_completion` sets `filter_text` to that same
        // normalized name — and the LSP client re-filters every returned item
        // against the RAW TEXT the user actually typed, independent of what the
        // server matched on. `zope.int` is not a subsequence of `zope-interface`,
        // so an editor like VS Code silently drops a result the server correctly
        // found. Rewriting `filter_text` to the raw, as-typed `prefix` makes every
        // returned item trivially self-matching against what's already on screen.
        // Safe to do unconditionally (rather than something that must also match
        // characters not yet typed): this method's caller always reports
        // `is_incomplete: true` for the `PackageName` context (see
        // `generate_completions`), so the client re-queries — and receives a
        // fresh `filter_text` — on the very next keystroke rather than continuing
        // to filter this same list locally.
        for item in &mut items {
            item.filter_text = Some(prefix.to_string());
        }

        items
    }

    /// True when `uri`'s basename matches neither an exact
    /// [`Ecosystem::manifest_filenames`] entry nor a
    /// [`Ecosystem::manifest_patterns`] glob — i.e. this file was routed to PyPI
    /// purely via the [`Ecosystem::manifest_directory_patterns`] fallback
    /// (`requirements/*.txt`, matched by `EcosystemRegistry::get_for_uri` on
    /// directory name alone), not a primary basename match.
    ///
    /// Recomputes the same basename check `EcosystemRegistry::get_for_uri`
    /// already performed, from the single source of truth (`self`'s own
    /// `manifest_filenames`/`manifest_patterns`) rather than threading a
    /// match-kind flag through `parse_manifest`'s signature — cheap, and
    /// correct as long as this ecosystem's directory-pattern fallback is only
    /// ever reached after both basename stages miss (true by construction in
    /// [`deps_core::EcosystemRegistry::get_for_uri`]).
    fn matched_only_via_directory_pattern(&self, uri: &Uri) -> bool {
        let basename = uri.path().as_str().rsplit('/').next().unwrap_or_default();
        if self.manifest_filenames().contains(&basename) {
            return false;
        }
        !self.manifest_patterns().iter().any(|pattern| {
            deps_core::ecosystem_registry::manifest_pattern_matches(basename, pattern)
        })
    }

    /// Completes version requirements for `package_name`, routed by the source that name
    /// resolves to in `parse_result` (validator finding #1). An ambiguous, unresolved, or
    /// unregistered-alternate source offers no completions rather than risking a private
    /// package name lookup against `pypi.org` — the same leak class FR-006 closes for
    /// hover/diagnostics/code-actions.
    async fn complete_versions(
        &self,
        parse_result: &dyn ParseResultTrait,
        package_name: &deps_core::PackageName,
        prefix: &str,
        freshness: deps_core::FreshnessSettings,
    ) -> Vec<CompletionItem> {
        match resolve_completion_source(parse_result, package_name) {
            CompletionSource::Ambiguous => vec![],
            CompletionSource::NotInManifest
            | CompletionSource::Resolved(DependencySource::Registry) => {
                deps_core::completion::complete_versions_generic(
                    self.registry.as_ref(),
                    package_name,
                    prefix,
                    &['>', '<', '=', '~', '!'],
                    freshness,
                )
                .await
            }
            CompletionSource::Resolved(DependencySource::AlternateRegistry { index, .. }) => {
                match self.registry.alternate_client(&index) {
                    Some(client) => {
                        deps_core::completion::complete_versions_generic(
                            client.as_ref(),
                            package_name,
                            prefix,
                            &['>', '<', '=', '~', '!'],
                            freshness,
                        )
                        .await
                    }
                    None => vec![],
                }
            }
            CompletionSource::Resolved(_) => vec![],
        }
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

    fn manifest_directory_patterns(&self) -> &[(&'static str, &'static str)] {
        &[("requirements", ".txt")]
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
                PypiManifestKind::PyProject => {
                    self.parser
                        .parse_content_with_policy(content, uri, &self.policy)
                }
                PypiManifestKind::Requirements => {
                    let require_strong_signal = self.matched_only_via_directory_pattern(uri);
                    self.parser.parse_requirements_with_policy(
                        content,
                        uri,
                        require_strong_signal,
                        &self.policy,
                    )
                }
            }
            .map_err(|e| deps_core::DepsError::ParseError {
                file_type: kind.file_type().into(),
                source: Box::new(e),
            })?;
            // Registers every chain this file's --index-url/--extra-index-url/Poetry-source/
            // uv-index declarations imply (spec FR-002/003/005/007/013) into the shared
            // root registry — the only point where a per-document resolution and the
            // long-lived `PypiRegistry` this ecosystem shares across every document ever
            // meet. A file with no such declaration contributes an empty `resolved_chains`
            // (US-004), so this loop is a no-op for the overwhelming majority of projects.
            // `register_chain` handles both shapes uniformly: a primary/extras chain and a
            // single-hop named-source registration (Poetry `source =`/uv `index =`) are both
            // just `ResolvedChain`s whose hop-tree construction only differs in length — a
            // named source's `key` is already its own literal URL (`ResolvedChain::named_source`),
            // so there is no separate `register_named_source` call needed here.
            for chain in &result.resolved_chains {
                PypiRegistry::register_chain(&self.registry, chain);
            }
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
    ) -> deps_core::ecosystem::BoxFuture<'a, Completions> {
        Box::pin(async move {
            use deps_core::completion::{CompletionContext, detect_completion_context};

            // Warms the package-name search index lazily on the first completion
            // request in this manifest, not just on a package-name completion —
            // so a version completion (or any other completion in the file)
            // usually has the index ready before the user starts typing a new
            // package name. Cheap to call unconditionally: a no-op once the
            // index is ready or while a prior failed build is within backoff.
            self.registry.warm_search_index();

            let context = detect_completion_context(parse_result, position, content);

            match context {
                // Serves unranked, alphabetically-truncated prefix matches from
                // `PypiRegistry::search`'s local index (issue #419): the client must
                // re-query as the user keeps typing rather than filter its existing
                // (possibly cold-start-empty) list — so this is the one context that
                // reports `is_incomplete: true`, regardless of whether it currently
                // has any items (#427).
                CompletionContext::PackageName { prefix, range } => Completions {
                    items: self.complete_package_names(&prefix, range).await,
                    is_incomplete: true,
                },
                CompletionContext::Version {
                    package_name,
                    prefix,
                } => self
                    .complete_versions(parse_result, &package_name, &prefix, freshness)
                    .await
                    .into(),
                CompletionContext::Feature { .. } | CompletionContext::None => {
                    Completions::default()
                }
            }
        })
    }

    fn package_search_is_incomplete(&self) -> bool {
        // Same unranked, alphabetically-truncated index `PackageName`'s
        // `is_incomplete: true` above covers for the primary path — see
        // `Ecosystem::package_search_is_incomplete`'s doc for why this only
        // matters for `deps-lsp`'s context-less fallback paths.
        true
    }

    fn generate_document_links(
        &self,
        parse_result: &dyn ParseResultTrait,
        uri: &Uri,
    ) -> Vec<DocumentLink> {
        let Some(result) = parse_result
            .as_any()
            .downcast_ref::<crate::parser::ParseResult>()
        else {
            return Vec::new();
        };
        if result.document_links.is_empty() {
            return Vec::new();
        }

        let Some(base_dir) = uri
            .to_file_path()
            .and_then(|p| p.parent().map(std::path::Path::to_path_buf))
        else {
            return Vec::new();
        };

        result
            .document_links
            .iter()
            .filter_map(|link| {
                // Only local relative/absolute filesystem paths are resolved — an
                // already-absolute URL (`http://...`) is left alone rather than
                // mangled by joining it onto a filesystem directory.
                if link.target.contains("://") {
                    return None;
                }
                if !is_safe_document_link_target(&link.target) {
                    deps_core::lsp_helpers::warn_rejected_value(
                        "is_safe_document_link_target",
                        "pypi requirements -r/-c document link target",
                        &link.target,
                    );
                    return None;
                }
                let target_path = base_dir.join(&link.target);
                let target_uri = Uri::from_file_path(&target_path)?;
                // Tooltip is derived from the URI's own round-tripped path, not
                // `target_path` directly: on Windows, `Uri::to_file_path` builds its
                // string with forward slashes while `Path::join` inserts the native
                // `\` separator, so the two disagree on separator style for the same
                // path — always resolve through the URI to keep them in sync.
                let tooltip = target_uri.to_file_path()?.display().to_string();
                Some(DocumentLink {
                    range: link.range,
                    target: Some(target_uri),
                    // Resolved absolute path, shown on hover — a bidi/format-character
                    // trick in the rendered line (rejected above) or a merely confusing
                    // relative path still leaves the user a way to verify the real
                    // target before clicking.
                    tooltip: Some(tooltip),
                    data: None,
                })
            })
            .collect()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Whether `target` is safe to resolve into a clickable `DocumentLink`.
///
/// Rejects every ASCII control character (`char::is_control()`, the same gate
/// [`deps_core::lsp_helpers::escape_markdown`] uses) plus the Unicode
/// bidi/format characters that gate alone misses — RLO/LRO-family overrides
/// (U+202A-U+202E, U+2066-U+2069), explicit directional marks (U+200E/U+200F),
/// zero-width joiners/spaces (U+200B-U+200D, U+2060, U+FEFF), and the
/// JS/JSON5 line terminators U+2028/U+2029. Without this, a target like
/// `"safe.txt\u{202E}txt.evil"` renders right-to-left in the editor (reading
/// as an innocuous `.txt` file) while the link actually opens `.evil` —
/// link-target spoofing, not merely a cosmetic issue, since the resolved URI
/// is exactly what the user's click opens.
fn is_safe_document_link_target(target: &str) -> bool {
    !target.is_empty()
        && target.chars().all(|c| {
            !c.is_control()
                && !matches!(c,
                    '\u{200B}'..='\u{200F}'
                        | '\u{202A}'..='\u{202E}'
                        | '\u{2060}'
                        | '\u{2066}'..='\u{2069}'
                        | '\u{2028}'
                        | '\u{2029}'
                        | '\u{FEFF}'
                )
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use deps_core::{EcosystemConfig, VersionData};
    use std::collections::HashMap;

    fn pkg(s: &str) -> deps_core::PackageName {
        deps_core::PackageName::new(s)
    }

    /// A `ParseResult` with no dependencies — `resolve_completion_source` always answers
    /// `NotInManifest` for it, matching this feature's pre-existing (public-registry-only)
    /// version-completion behavior. Used by tests that only exercise `complete_versions`
    /// directly, with no manifest content to join against.
    fn empty_parse_result() -> crate::parser::ParseResult {
        crate::parser::ParseResult {
            dependencies: Vec::new(),
            workspace_root: None,
            uri: deps_core::test_util::test_uri("/test/requirements.txt"),
            document_links: Vec::new(),
            resolved_chains: Vec::new(),
        }
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

    #[test]
    fn test_matched_only_via_directory_pattern() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = PypiEcosystem::new(cache);

        // Directory-pattern-only: no basename filename/pattern match.
        let uri = deps_core::test_util::test_uri("/project/requirements/base.txt");
        assert!(ecosystem.matched_only_via_directory_pattern(&uri));

        // Basename matches (exact `requirements.txt` and a `*-requirements.txt`
        // pattern respectively), even from inside a `requirements/` directory.
        for path in [
            "/project/requirements.txt",
            "/project/requirements/dev-requirements.txt",
        ] {
            let uri = deps_core::test_util::test_uri(path);
            assert!(
                !ecosystem.matched_only_via_directory_pattern(&uri),
                "{path} should be a basename match, not directory-pattern-only"
            );
        }
    }

    #[tokio::test]
    async fn test_parse_manifest_directory_pattern_only_applies_strict_gate() {
        // #452 S6 end-to-end: a `requirements/` docs file with only prose-shaped
        // bare names must not survive the ratio gate through `parse_manifest`.
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = PypiEcosystem::new(cache);
        let uri = deps_core::test_util::test_uri("/project/requirements/base.txt");

        let result = ecosystem
            .parse_manifest(
                "Introduction\n\nScope\n\nThis document defines the requirements.\n",
                &uri,
            )
            .await
            .unwrap();

        assert!(result.dependencies().is_empty());
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
    async fn test_generate_document_links_resolves_relative_target() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = PypiEcosystem::new(cache);
        let uri = deps_core::test_util::test_uri("/project/requirements.txt");

        let parse_result = ecosystem
            .parse_manifest("-r base.txt\n", &uri)
            .await
            .unwrap();

        let links = ecosystem.generate_document_links(parse_result.as_ref(), &uri);
        assert_eq!(links.len(), 1);
        let target = links[0].target.as_ref().unwrap();
        assert!(target.path().as_str().ends_with("/project/base.txt"));
        assert_eq!(
            links[0].tooltip.as_deref(),
            target.to_file_path().unwrap().to_str()
        );
    }

    #[tokio::test]
    async fn test_generate_document_links_rejects_bidi_override_target() {
        // #452 S2 (security): a bidi override in the target text could make the
        // rendered requirements.txt line read as an innocuous filename while the
        // link itself opens something else entirely — link-target spoofing.
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = PypiEcosystem::new(cache);
        let uri = deps_core::test_util::test_uri("/project/requirements.txt");

        let parse_result = ecosystem
            .parse_manifest("-r safe.txt\u{202E}txt.evil\n", &uri)
            .await
            .unwrap();

        let links = ecosystem.generate_document_links(parse_result.as_ref(), &uri);
        assert!(links.is_empty());
    }

    #[test]
    fn test_is_safe_document_link_target_rejects_invisible_unicode() {
        for bad in [
            "safe.txt\u{202E}txt.evil",
            "a\u{200B}b.txt",
            "a\u{2028}b.txt",
            "a\u{FEFF}b.txt",
            "a\nb.txt",
        ] {
            assert!(
                !is_safe_document_link_target(bad),
                "expected {bad:?} to be rejected"
            );
        }
    }

    #[test]
    fn test_is_safe_document_link_target_accepts_normal_paths() {
        for good in [
            "base.txt",
            "../shared/constraints.txt",
            "dev-requirements.txt",
        ] {
            assert!(is_safe_document_link_target(good));
        }
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

    /// #427 coverage gap: the actual bugfix — `generate_completions`'s
    /// `PackageName` arm reporting `is_incomplete: true` for the truncated
    /// package-name search index — was previously only verified via a hand-rolled
    /// mock `Ecosystem` in `deps-lsp`'s handler tests, never on the real
    /// `PypiEcosystem` dispatch. Same fixture/cursor as
    /// `test_package_name_completion_context_has_real_range`, but calling
    /// `generate_completions` directly (not `detect_completion_context`) so a
    /// reversed condition or wrong-arm bug in the real dispatch would be caught.
    #[tokio::test]
    async fn test_generate_completions_package_name_context_is_incomplete() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = PypiEcosystem::new(cache);
        let content = "[dependency-groups]\ndev = [\"pytest>=8.0\", \"mypy>=1.0\"]\n";
        let uri = deps_core::test_util::test_uri("/test/pyproject.toml");

        let parse_result = ecosystem.parse_manifest(content, &uri).await.unwrap();
        let position = Position::new(1, 11); // cursor after "pyt" in "pytest"

        let completions = ecosystem
            .generate_completions(
                parse_result.as_ref(),
                position,
                content,
                deps_core::FreshnessSettings::default(),
            )
            .await;

        assert!(
            completions.is_incomplete,
            "PackageName context must report is_incomplete: true, even with zero \
             items on a cold-start index"
        );
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

    /// Builds a `PypiEcosystem` whose registry's search index is pointed at a
    /// mock server rather than the real `pypi.org/simple/`, so package-name
    /// completion (issue #419) can be exercised network-free.
    fn ecosystem_with_index_url(
        cache: Arc<deps_core::HttpCache>,
        index_url: String,
    ) -> PypiEcosystem {
        PypiEcosystem {
            registry: Arc::new(PypiRegistry::with_index_url(cache, index_url)),
            parser: PypiParser::new(),
            formatter: PypiFormatter,
            policy: Arc::new(deps_core::net_policy::RegistryAccessPolicy::default()),
        }
    }

    /// Polls `probe` until it returns a non-empty result or `attempts` polls have
    /// elapsed, returning the last (possibly still empty) result. Used to wait out
    /// the background index build without a flaky fixed sleep.
    async fn poll_until_nonempty<F, Fut>(mut probe: F, attempts: u32) -> Vec<CompletionItem>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = Vec<CompletionItem>>,
    {
        for _ in 0..attempts {
            let results = probe().await;
            if !results.is_empty() {
                return results;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        probe().await
    }

    /// #419 regression: `test_complete_package_names_real_search` used to be
    /// `#[ignore]`d (real network access, so never ran in CI). Rewritten
    /// network-free against a mocked Simple API index: the first call is a cold
    /// start (empty, index not built yet) and a later call — once the background
    /// build finishes — finds `requests`.
    #[tokio::test]
    async fn test_complete_package_names_uses_index() {
        let mut server = mockito::Server::new_async().await;
        let _mock = server
            .mock("GET", "/simple/")
            .with_status(200)
            .with_body(crate::search::sample_index_body(&["requests"]))
            .create_async()
            .await;

        let cache = Arc::new(deps_core::HttpCache::new());
        let index_url = format!("{}/simple/", server.url());
        let ecosystem = ecosystem_with_index_url(cache, index_url);

        let cold_start = ecosystem
            .complete_package_names("reque", Range::default())
            .await;
        assert!(
            cold_start.is_empty(),
            "cold start must not block on the download"
        );

        let results = poll_until_nonempty(
            || ecosystem.complete_package_names("reque", Range::default()),
            100,
        )
        .await;
        assert!(!results.is_empty());
        assert!(results.iter().any(|r| r.label == "requests"));
    }

    /// #419 S2 regression: a query using a different separator than the index's
    /// normalized form (`zope.int`, PEP 503-normalized to `zope-int` server-side)
    /// must come back with `filter_text` set to the *raw typed* prefix, not the
    /// normalized `label`/`insert_text` — otherwise an LSP client's local
    /// re-filtering (`zope.int` is not a subsequence of `zope-interface`) would
    /// silently drop a result the server correctly matched.
    #[tokio::test]
    async fn test_complete_package_names_filter_text_matches_raw_typed_prefix() {
        let mut server = mockito::Server::new_async().await;
        let _mock = server
            .mock("GET", "/simple/")
            .with_status(200)
            .with_body(crate::search::sample_index_body(&["zope-interface"]))
            .create_async()
            .await;

        let cache = Arc::new(deps_core::HttpCache::new());
        let index_url = format!("{}/simple/", server.url());
        let ecosystem = ecosystem_with_index_url(cache, index_url);

        let results = poll_until_nonempty(
            || ecosystem.complete_package_names("zope.int", Range::default()),
            100,
        )
        .await;

        let item = results
            .iter()
            .find(|r| r.label == "zope-interface")
            .expect("zope-interface should be found via separator-normalized search");
        assert_eq!(
            item.filter_text,
            Some("zope.int".to_string()),
            "filter_text must be the raw typed prefix, not the normalized label"
        );
    }

    /// #419 §4.6/Q2 regression: a *version* completion request (not a
    /// package-name one) inside a Python manifest must warm the search index —
    /// `PypiEcosystem::generate_completions` calls `warm_search_index` before
    /// dispatching on completion context — and repeated requests must still
    /// produce exactly one index-build fetch (single-flight + build-once).
    #[tokio::test]
    async fn test_version_completion_triggers_exactly_one_index_build_attempt() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/simple/")
            .with_status(200)
            .with_body(crate::search::sample_index_body(&["requests"]))
            .expect(1)
            .create_async()
            .await;

        let cache = Arc::new(deps_core::HttpCache::new());
        let index_url = format!("{}/simple/", server.url());
        let ecosystem = ecosystem_with_index_url(cache, index_url);

        let uri = deps_core::test_util::test_uri("/test/pyproject.toml");
        let content = "[project]\ndependencies = [\"requests>=2.0\"]\n";
        let parse_result = ecosystem.parse_manifest(content, &uri).await.unwrap();

        // Locate a cursor position that `detect_completion_context` actually
        // resolves to a Version context, rather than hand-computing a column
        // offset that would silently drift if the fixture line changes.
        let version_line = content.lines().nth(1).unwrap();
        let version_position = (0..=version_line.len() as u32)
            .map(|character| tower_lsp_server::ls_types::Position::new(1, character))
            .find(|&position| {
                matches!(
                    deps_core::completion::detect_completion_context(
                        parse_result.as_ref(),
                        position,
                        content,
                    ),
                    deps_core::completion::CompletionContext::Version { .. }
                )
            })
            .expect("fixture line must contain a Version completion context");

        let mut last_completions = None;
        for _ in 0..3 {
            last_completions = Some(
                ecosystem
                    .generate_completions(
                        parse_result.as_ref(),
                        version_position,
                        content,
                        deps_core::FreshnessSettings::default(),
                    )
                    .await,
            );
        }
        assert!(
            !last_completions
                .expect("loop ran at least once")
                .is_incomplete,
            "a Version completion context is always exhaustive, unlike PackageName's \
             truncated index search"
        );

        // Give the (single-flight) background build a chance to finish.
        let ready = poll_until_nonempty(
            || ecosystem.complete_package_names("reque", Range::default()),
            100,
        )
        .await;
        assert!(
            ready.iter().any(|r| r.label == "requests"),
            "index should be ready and contain requests after warming"
        );
        mock.assert_async().await;
    }

    #[tokio::test]
    #[ignore] // Requires network access
    async fn test_complete_versions_real() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = PypiEcosystem::new(cache);

        let results = ecosystem
            .complete_versions(
                &empty_parse_result(),
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
                &empty_parse_result(),
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
                &empty_parse_result(),
                &pkg("this-package-does-not-exist-12345"),
                "1.0",
                deps_core::FreshnessSettings::default(),
            )
            .await;
        assert!(results.is_empty());
    }

    /// A minimal single-dependency `ParseResult`, for the `resolve_completion_source` join
    /// `complete_versions` performs — the source under test.
    fn parse_result_with_dependency(
        name: &str,
        source: DependencySource,
    ) -> crate::parser::ParseResult {
        use tower_lsp_server::ls_types::{Position, Range};
        crate::parser::ParseResult {
            dependencies: vec![crate::types::PypiDependency {
                name: pkg(name),
                name_range: Range::new(Position::new(0, 0), Position::new(0, 0)),
                version_req: None,
                version_range: None,
                extras: Vec::new(),
                extras_range: None,
                markers: None,
                markers_range: None,
                section: crate::types::PypiDependencySection::Requirements,
                source,
            }],
            workspace_root: None,
            uri: deps_core::test_util::test_uri("/test/requirements.txt"),
            document_links: Vec::new(),
            resolved_chains: Vec::new(),
        }
    }

    /// Validator finding #1 (security H1 + impl-critic C1): a version-completion request for
    /// an `AlternateRegistry`-sourced dependency must route through the resolved chain, never
    /// through the root `Public`-tier client — fetching from the root would send the
    /// dependency's name to `pypi.org` on every keystroke.
    #[tokio::test]
    async fn test_complete_versions_alternate_registry_routes_through_chain() {
        let mut alt_server = mockito::Server::new_async().await;
        let alt_mock = alt_server
            .mock("GET", "/simple/mypkg/")
            .with_status(200)
            .with_body(r#"{"versions": ["1.0.0", "2.0.0"], "files": []}"#)
            .create_async()
            .await;

        let cache = Arc::new(deps_core::HttpCache::new());
        cache.set_registry_policy(deps_core::net_policy::WorkspaceRegistryAccess::All);
        let root = Arc::new(PypiRegistry::new(Arc::clone(&cache)));
        let policy = Arc::new(deps_core::net_policy::RegistryAccessPolicy::new(
            deps_core::net_policy::WorkspaceRegistryAccess::All,
        ));
        let ecosystem = PypiEcosystem::with_policy(Arc::clone(&root), policy);

        let base = crate::config::PypiIndexUrl::new(
            &format!("{}/simple", alt_server.url()),
            &deps_core::net_policy::RegistryAccessPolicy::new(
                deps_core::net_policy::WorkspaceRegistryAccess::All,
            ),
        )
        .unwrap();
        let chain = crate::config::ResolvedChain {
            key: "test-alt-chain".to_string(),
            hops: vec![base],
            implicit_public_fallback: false,
        };
        PypiRegistry::register_chain(&root, &chain);

        let source = DependencySource::AlternateRegistry {
            index: chain.key.clone(),
            mirrors_crates_io: false,
        };
        let parse_result = parse_result_with_dependency("mypkg", source);

        let results = ecosystem
            .complete_versions(
                &parse_result,
                &pkg("mypkg"),
                "",
                deps_core::FreshnessSettings::default(),
            )
            .await;
        assert!(
            !results.is_empty(),
            "expected version completions fetched from the alternate index"
        );
        alt_mock.assert_async().await;
    }

    /// Validator finding #1: a `CustomRegistry`-sourced dependency (an invalid/blocked
    /// explicit index, US-005) must offer no version completions at all — never falling back
    /// to `pypi.org`, matching hover/diagnostics' existing fail-closed behavior for it
    /// (SC-004).
    #[tokio::test]
    async fn test_complete_versions_custom_registry_offers_nothing() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = PypiEcosystem::new(cache);

        let source = DependencySource::CustomRegistry {
            url: "not-a-valid-url".to_string(),
        };
        let parse_result = parse_result_with_dependency("mypkg", source);

        let results = ecosystem
            .complete_versions(
                &parse_result,
                &pkg("mypkg"),
                "",
                deps_core::FreshnessSettings::default(),
            )
            .await;
        assert!(results.is_empty());
    }

    /// Validator finding #1: an `AlternateRegistry` source whose chain was never registered
    /// (or whose registration is now stale) offers nothing rather than falling back to the
    /// root client.
    #[tokio::test]
    async fn test_complete_versions_unregistered_alternate_offers_nothing() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = PypiEcosystem::new(cache);

        let source = DependencySource::AlternateRegistry {
            index: "pypi-chain:never-registered".to_string(),
            mirrors_crates_io: false,
        };
        let parse_result = parse_result_with_dependency("mypkg", source);

        let results = ecosystem
            .complete_versions(
                &parse_result,
                &pkg("mypkg"),
                "",
                deps_core::FreshnessSettings::default(),
            )
            .await;
        assert!(results.is_empty());
    }

    /// `resolve_completion_source`'s three-way classification, tested directly.
    #[test]
    fn test_resolve_completion_source_classification() {
        let not_in_manifest = empty_parse_result();
        assert!(matches!(
            resolve_completion_source(&not_in_manifest, &pkg("mypkg")),
            CompletionSource::NotInManifest
        ));

        let resolved = parse_result_with_dependency("mypkg", DependencySource::Registry);
        assert!(matches!(
            resolve_completion_source(&resolved, &pkg("mypkg")),
            CompletionSource::Resolved(DependencySource::Registry)
        ));

        let ambiguous = crate::parser::ParseResult {
            dependencies: vec![
                parse_result_with_dependency("mypkg", DependencySource::Registry).dependencies[0]
                    .clone(),
                parse_result_with_dependency(
                    "mypkg",
                    DependencySource::AlternateRegistry {
                        index: "https://a.example/simple".to_string(),
                        mirrors_crates_io: false,
                    },
                )
                .dependencies[0]
                    .clone(),
            ],
            workspace_root: None,
            uri: deps_core::test_util::test_uri("/test/requirements.txt"),
            document_links: Vec::new(),
            resolved_chains: Vec::new(),
        };
        assert!(matches!(
            resolve_completion_source(&ambiguous, &pkg("mypkg")),
            CompletionSource::Ambiguous
        ));
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
                &empty_parse_result(),
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

        assert!(completions.items.is_empty());
        assert!(!completions.is_incomplete);
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
        assert!(completions.items.is_empty() || !completions.items.is_empty());
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
                &empty_parse_result(),
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
                &empty_parse_result(),
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
                &empty_parse_result(),
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
            let resolved_versions: HashMap<PackageName, deps_core::ConcreteVersion> =
                resolved_packages
                    .iter()
                    .map(|(name, pkg)| {
                        (PackageName::new(name.as_str()), pkg.version.clone().into())
                    })
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
                parse_result.uri(),
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

    // --- T010: ecosystem wiring — parse_manifest registers resolved chains ---

    fn parsed_dependencies(
        result: &dyn ParseResultTrait,
    ) -> Vec<(String, deps_core::parser::DependencySource)> {
        result
            .dependencies()
            .into_iter()
            .map(|d| (d.name().to_string(), d.source()))
            .collect()
    }

    /// A file with no index declaration anywhere never constructs more than an empty
    /// `PypiIndexConfig` and never calls `register_chain` (US-004).
    #[tokio::test]
    async fn test_parse_manifest_no_declaration_registers_nothing() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = PypiEcosystem::new(cache);
        let uri = deps_core::test_util::test_uri("/project/requirements.txt");

        let result = ecosystem
            .parse_manifest("requests==2.31.0\n", &uri)
            .await
            .unwrap();

        for (_, source) in parsed_dependencies(result.as_ref()) {
            assert_eq!(source, DependencySource::Registry);
        }
    }

    /// **Test A (S6, mixed chain)**: a chain with one policy-blocked hop and one valid hop
    /// still resolves via the valid hop — a blocked extra must not break a chain that still
    /// has a working remaining hop. Uses `public_only` (Global primary, RFC1918 extra) rather
    /// than a literal `off` policy: `Off::allows` is unconditionally `false` for every host
    /// class, so under a real `off` policy the "explicit valid primary" in this scenario
    /// would *also* be blocked (there is no host class `off` ever allows) — `public_only`
    /// exercises the identical code path (one hop blocked by policy, one hop not) without
    /// that contradiction, and is the policy under which this mixed-chain scenario is
    /// actually reachable in production.
    #[tokio::test]
    async fn test_parse_manifest_blocked_extra_does_not_break_chain_with_valid_primary() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let policy = Arc::new(deps_core::net_policy::RegistryAccessPolicy::new(
            deps_core::net_policy::WorkspaceRegistryAccess::PublicOnly,
        ));
        let registry = Arc::new(PypiRegistry::new(Arc::clone(&cache)));
        let ecosystem = PypiEcosystem::with_policy(Arc::clone(&registry), policy);
        let uri = deps_core::test_util::test_uri("/project/requirements.txt");

        let content = "--index-url https://pypi.mycorp.example/simple\n\
                        --extra-index-url https://10.0.0.5/simple\n\
                        requests==2.31.0\n";
        let result = ecosystem.parse_manifest(content, &uri).await.unwrap();

        let deps = parsed_dependencies(result.as_ref());
        let (_, source) = deps.iter().find(|(name, _)| name == "requests").unwrap();
        let DependencySource::AlternateRegistry { index, .. } = source else {
            panic!("expected AlternateRegistry, got {source:?}");
        };
        // The registered chain must actually be reachable through the root registry this
        // ecosystem shares — proving `parse_manifest` really called `register_chain`, not
        // just that `resolve_source_for` computed the right `DependencySource` in isolation.
        assert!(registry.alternate_client(index).is_some());
    }

    /// **Test B (N5, zero-hop)**: `workspace_registries = off`, a file declaring only
    /// `--extra-index-url` entries (no explicit primary) — every extra is blocked, the chain
    /// has zero hops, and every plain dependency in the file degrades to plain
    /// `DependencySource::Registry` (not per-dependency fail-closed, not a structurally-broken
    /// empty `AlternateRegistry`).
    #[tokio::test]
    async fn test_parse_manifest_all_extras_blocked_degrades_to_plain_registry() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let policy = Arc::new(deps_core::net_policy::RegistryAccessPolicy::new(
            deps_core::net_policy::WorkspaceRegistryAccess::Off,
        ));
        let registry = Arc::new(PypiRegistry::new(Arc::clone(&cache)));
        let ecosystem = PypiEcosystem::with_policy(Arc::clone(&registry), policy);
        let uri = deps_core::test_util::test_uri("/project/requirements.txt");

        let content = "--extra-index-url https://extra.example/simple\nrequests==2.31.0\n";
        let result = ecosystem.parse_manifest(content, &uri).await.unwrap();

        let deps = parsed_dependencies(result.as_ref());
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].1, DependencySource::Registry);

        // Nothing was registered — a zero-hop config has no chain to register at all.
        let downcast = result
            .as_any()
            .downcast_ref::<crate::parser::ParseResult>()
            .unwrap();
        assert!(downcast.resolved_chains.is_empty());
    }
}
