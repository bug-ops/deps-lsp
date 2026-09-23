//! PyPI ecosystem implementation for deps-lsp.
//!
//! This module implements the `Ecosystem` trait for Python projects,
//! providing LSP functionality for `pyproject.toml` files and for
//! `requirements.txt`/`constraints.txt` files (pip's requirements file
//! format).

use std::any::Any;
use std::sync::Arc;
#[cfg(feature = "lsp-responses")]
use tower_lsp_server::ls_types::{CompletionItem, DocumentLink, Range, Uri};
use url::Url;

#[cfg(feature = "lsp-responses")]
use deps_core::completion::Completions;
use deps_core::{
    Ecosystem, ParseResult as ParseResultTrait, Registry, Result, lsp_helpers::EcosystemFormatter,
};

use crate::formatter::PypiFormatter;
use crate::parser::PypiParser;
use crate::registry::PypiRegistry;

/// Leading version-constraint operators stripped from a completion prefix before matching
/// it against registry versions: PEP 508's `==`, `!=`, `<=`, `>=`, `<`, `>`, `~=` plus
/// Poetry's caret (`^2.28`, `[tool.poetry.dependencies]`) — `^` was missing here despite
/// `parser::pyproject::parse_poetry_dependencies` accepting caret constraints, so a Poetry
/// manifest's completion silently fell back to an unfiltered list (#1137).
#[cfg(feature = "lsp-responses")]
const VERSION_OPERATOR_CHARS: &[char] = &['>', '<', '=', '~', '!', '^'];

/// Which manifest shape a URI's basename identifies, so `parse_manifest` can
/// dispatch to the right parser method and report the right `file_type` on
/// error.
#[derive(Clone, Copy)]
enum PypiManifestKind {
    PyProject,
    Requirements,
}

impl PypiManifestKind {
    fn from_uri(uri: &Url) -> Self {
        let basename = uri.path().rsplit('/').next().unwrap_or_default();
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
    /// explicitly by [`Self::with_policy`] so `deps_engine::setup::register_ecosystems`-equivalent
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
    /// `deps_engine::setup::register_ecosystems` so `initialize`/`workspace/didChangeConfiguration`
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

    #[cfg(feature = "lsp-responses")]
    async fn complete_package_names(&self, prefix: &str, range: Range) -> Vec<CompletionItem> {
        // #419 S2 / #1289: `filter_text` rewriting for PyPI's PEP 503 normalized search is
        // now handled generically by `complete_package_names_generic` via
        // `Registry::search_normalizes_query` (see `PypiRegistry`'s override) and
        // `deps_core::completion::apply_raw_prefix_filter_text` — no PyPI-local step needed.
        deps_core::completion::complete_package_names_generic(
            self.registry.as_ref(),
            prefix,
            20,
            range,
        )
        .await
    }

    /// True when `uri`'s basename matches neither an exact
    /// [`Ecosystem::manifest_filenames`] entry nor a
    /// [`Ecosystem::manifest_patterns`] glob — i.e. this file was routed to PyPI
    /// purely via the [`Ecosystem::manifest_directory_patterns`] fallback
    /// (`requirements/*.txt`, matched by `EcosystemRegistry::for_uri` on
    /// directory name alone), not a primary basename match.
    ///
    /// Recomputes the same basename check `EcosystemRegistry::for_uri`
    /// already performed, from the single source of truth (`self`'s own
    /// `manifest_filenames`/`manifest_patterns`) rather than threading a
    /// match-kind flag through `parse_manifest`'s signature — cheap, and
    /// correct as long as this ecosystem's directory-pattern fallback is only
    /// ever reached after both basename stages miss (true by construction in
    /// [`deps_core::EcosystemRegistry::for_uri`]).
    fn matched_only_via_directory_pattern(&self, uri: &Url) -> bool {
        let basename = uri.path().rsplit('/').next().unwrap_or_default();
        if self.manifest_filenames().contains(&basename) {
            return false;
        }
        !self.manifest_patterns().iter().any(|pattern| {
            deps_core::ecosystem_registry::manifest_pattern_matches(basename, pattern)
        })
    }
}

impl deps_core::ecosystem::private::Sealed for PypiEcosystem {}

impl Ecosystem for PypiEcosystem {
    fn ecosystem_id(&self) -> deps_core::EcosystemId {
        deps_core::EcosystemId::Pypi
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
        uri: &'a Url,
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
            .map_err(|e| deps_core::DepsError::parse_error(kind.file_type(), &e))?;
            // Registers every chain this file's --index-url/--extra-index-url/Poetry-source/
            // uv-index declarations imply (spec FR-002/003/005/007/013) into the shared
            // root registry — the only point where a per-document resolution and the
            // long-lived `PypiRegistry` this ecosystem shares across every document ever
            // meet. A file with no such declaration contributes an empty `resolved_chains`
            // (US-004), so this loop is a no-op for the overwhelming majority of projects.
            // `register_alternate` handles both shapes uniformly: a primary/extras chain and
            // a single-hop named-source registration (Poetry `source =`/uv `index =`) are
            // both just `ResolvedChain`s whose hop-tree construction only differs in length —
            // a named source's `key` is already its own literal URL
            // (`ResolvedChain::named_source`), so no separate call is needed here.
            for chain in &result.resolved_chains {
                PypiRegistry::register_alternate(&self.registry, chain);
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

    /// Warms the package-name search index lazily on the first completion request in this
    /// manifest, not just on a package-name completion — so a version completion (or any
    /// other completion in the file) usually has the index ready before the user starts
    /// typing a new package name. Cheap to call unconditionally: a no-op once the index is
    /// ready or while a prior failed build is within backoff. Must run for *every* context
    /// (including `None`), which is why this is `prepare_completions` rather than folded
    /// into `complete_package_name` alone.
    fn prepare_completions(&self) {
        self.registry.warm_search_index();
    }

    /// Serves unranked, alphabetically-truncated prefix matches from `PypiRegistry::search`'s
    /// local index (issue #419): the client must re-query as the user keeps typing rather
    /// than filter its existing (possibly cold-start-empty) list — so this is the one
    /// context that reports `is_incomplete: true`, regardless of whether it currently has
    /// any items (#427).
    #[cfg(feature = "lsp-responses")]
    fn complete_package_name<'a>(
        &'a self,
        _request: deps_core::completion::CompletionRequest<'a>,
        prefix: String,
        range: Range,
    ) -> deps_core::ecosystem::BoxFuture<'a, Completions> {
        Box::pin(async move {
            Completions::new(self.complete_package_names(&prefix, range).await)
                .with_incomplete(true)
        })
    }

    #[cfg(feature = "lsp-responses")]
    fn version_operator_chars(&self) -> &'static [char] {
        VERSION_OPERATOR_CHARS
    }

    fn package_search_is_incomplete(&self) -> bool {
        // Same unranked, alphabetically-truncated index `PackageName`'s
        // `is_incomplete: true` above covers for the primary path — see
        // `Ecosystem::package_search_is_incomplete`'s doc for why this only
        // matters for `deps-lsp`'s context-less fallback paths.
        true
    }

    #[cfg(feature = "lsp-responses")]
    fn generate_document_links(
        &self,
        parse_result: &dyn ParseResultTrait,
        uri: &Url,
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

        // #1090: routed through `resolve_manifest_file_path` rather than a bare
        // `to_file_path()` so a non-`file:` scheme or remote-host URI can't resolve a
        // document-link target against a real local directory.
        let Some(base_dir) = deps_core::lockfile::resolve_manifest_file_path(uri)
            .and_then(|p| p.parent().map(std::path::Path::to_path_buf))
        else {
            return Vec::new();
        };

        // No workspace-root discovery exists for pypi today (`ParseResult::workspace_root`
        // is always `None` — see its field doc), so the containment check below is a no-op
        // until that lands; it activates automatically once a root is ever populated. Only
        // an absolute root is usable: `lexically_normalize` assumes an absolute input (see
        // its doc), and a relative root (e.g. `".."`) would normalize to `""`, against
        // which every path spuriously `starts_with` — silently defeating the containment
        // check instead of the intended skip-if-unknown fallback (#937 finding R2).
        //
        // Absoluteness is checked with `is_absolute_document_link_target` (on the root's
        // string form), not `Path::is_absolute()`: that method's notion of "absolute" is
        // platform-dependent, and a POSIX-style root like `/project` is NOT absolute per
        // `Path` on Windows (no drive prefix) — using it here would silently skip
        // containment for exactly this shape on Windows, the same C1-class bug the target
        // check was already written to avoid.
        let workspace_root = result
            .workspace_root
            .as_deref()
            .filter(|root| root.to_str().is_some_and(is_absolute_document_link_target))
            .map(lexically_normalize);

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
                // An absolute target (`/etc/shadow`, `C:\...`) silently discards
                // `base_dir` on join and is never a meaningful pip relative include
                // (#937) — checked on the raw string, not `Path::is_absolute()`,
                // since that's platform-dependent and a Windows-style prefix must be
                // rejected even when deps-lsp itself runs on a POSIX host.
                if is_absolute_document_link_target(&link.target) {
                    deps_core::lsp_helpers::warn_rejected_value(
                        "is_absolute_document_link_target",
                        "pypi requirements -r/-c document link target",
                        &link.target,
                    );
                    return None;
                }
                let target_path = lexically_normalize(&base_dir.join(&link.target));
                // `../requirements-base.txt` is a standard, legitimate pip layout
                // (#937) — only reject once normalization proves the target escaped
                // the workspace root entirely, not merely for containing `..`.
                if let Some(root) = &workspace_root
                    && !target_path.starts_with(root)
                {
                    deps_core::lsp_helpers::warn_rejected_value(
                        "workspace_root_containment",
                        "pypi requirements -r/-c document link target",
                        &link.target,
                    );
                    return None;
                }
                let target_uri = Uri::from_file_path(&target_path)?;
                // Tooltip is derived from the URI's own round-tripped path, not
                // `target_path` directly: on Windows, `Uri::to_file_path` builds its
                // string with forward slashes while `Path::join` inserts the native
                // `\` separator, so the two disagree on separator style for the same
                // path — always resolve through the URI to keep them in sync.
                let tooltip = target_uri.to_file_path()?.display().to_string();
                Some(DocumentLink {
                    range: link.range.into(),
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

    fn fallback_completion_prefix<'a>(
        &self,
        content: &'a str,
        position: deps_core::position::Position,
    ) -> Option<&'a str> {
        let line = deps_core::fallback_completion::line_at(content, position)?;
        if !is_in_dependencies_section(content, position.line as usize) {
            return None;
        }
        Some(extract_prefix(line, position.character))
    }

    fn fallback_completion_is_bare(
        &self,
        content: &str,
        position: deps_core::position::Position,
    ) -> bool {
        // A genuinely still-open quoted string — an odd, escape-aware real-quote count
        // via `open_quoted_tail` (the same primitive `extract_prefix` uses below, so
        // the two methods always agree on the same `content`/`position`) — means the
        // opening quote already exists in the manifest: the bare package name is the
        // correct insert there, same as today. Zero real quotes (nothing typed yet, or
        // only an escaped `\"`) means nothing has opened a quote to insert into: e.g.
        // `req` alone on its own line under `dependencies = [...]`.
        // `completion_insert_text` must then supply both quotes itself, or the
        // fallback insert produces an unquoted, invalid TOML array element (#737). An
        // already-closed value (an even, non-zero count, e.g. `"pytest"`) also reports
        // `false` here, but that state is unreachable in practice: `extract_prefix`
        // already collapses it to an empty prefix, which the caller rejects before
        // this method is ever invoked.
        let Some(line) = deps_core::fallback_completion::line_at(content, position) else {
            return false;
        };
        let raw = deps_core::fallback_completion::raw_prefix(line, position.character);
        deps_core::fallback_completion::open_quoted_tail(raw).is_some()
    }

    fn completion_insert_text(&self, metadata: &dyn deps_core::Metadata) -> Option<String> {
        // Only reached when `fallback_completion_is_bare` reports no quote typed at
        // all — see that method. Both real PEP 621 shapes (`dependencies = [...]` and
        // an `[project.optional-dependencies]` group) are TOML string-array elements,
        // not a key=value table entry like Cargo's, so the full insert here is the
        // quoted array element itself rather than a `key = value` pair.
        Some(format!("\"{}\"", metadata.name().as_str()))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Checks if `line_number` of `content` is inside a PyPI dependencies-like section:
/// either a real TOML section header (`[project.optional-dependencies]`) or PEP 621's
/// `dependencies = [...]` array under `[project]`, for `deps-lsp`'s raw-text fallback
/// completion (parse-failure path).
fn is_in_dependencies_section(content: &str, line_number: usize) -> bool {
    deps_core::fallback_completion::is_in_toml_dependencies(content, line_number)
        || is_in_pypi_project_dependencies_array(content, line_number)
}

/// Checks if a line is inside PEP 621's `dependencies = [...]` array under the
/// `[project]` table.
///
/// Unlike `[dependencies]`/`[project.optional-dependencies]`, PEP 621's primary
/// dependency list is a *value* (an array assigned to the `dependencies` key), not a
/// section header — no real `pyproject.toml` ever writes a literal
/// `[project.dependencies]` header — so it needs its own bracket-depth scan rather
/// than [`deps_core::fallback_completion::is_in_toml_dependencies`]'s header-string
/// match.
///
/// The bracket-depth counter has no string awareness, so an unbalanced `[` inside a
/// still-typed extras spec (`"uvicorn[stan`) or a comment would otherwise desync it
/// permanently. TOML forbids a table header inside an array value, so a bare `[...]`
/// header line (checked on every line, not just outside the array) is used as an
/// unambiguous resync point regardless of the counter's state.
fn is_in_pypi_project_dependencies_array(content: &str, line_number: usize) -> bool {
    let mut in_project = false;
    let mut in_array = false;
    let mut depth: i32 = 0;

    for (i, line) in content.lines().enumerate() {
        if i > line_number {
            break;
        }
        let trimmed = strip_trailing_toml_comment(line.trim());

        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            in_array = false;
            in_project = trimmed == "[project]";
            continue;
        }

        if !in_array && in_project && is_dependencies_array_start(trimmed) {
            in_array = true;
            depth = 0;
        }

        if in_array {
            if i == line_number {
                return true;
            }
            for ch in trimmed.chars() {
                match ch {
                    '[' => depth += 1,
                    ']' => depth -= 1,
                    _ => {}
                }
            }
            if depth <= 0 {
                in_array = false;
            }
        }
    }

    false
}

/// Strips a trailing TOML comment (`# ...`) from `line`, ignoring a `#` that appears
/// inside a quoted string.
///
/// Thin wrapper over the shared [`deps_core::quote_scan::strip_line_comment`] (#1022),
/// which is escape-aware for `"..."` literals (a `\"` inside one no longer ends the
/// string a character early — the bug this module's own hand-rolled scanner had).
fn strip_trailing_toml_comment(line: &str) -> &str {
    deps_core::quote_scan::strip_line_comment(line, deps_core::quote_scan::ScanSyntax::Toml)
        .trim_end()
}

/// Whether `trimmed` opens the `dependencies = [...]` array (`dependencies = [` or
/// the single-line `dependencies = [...]`), used by
/// [`is_in_pypi_project_dependencies_array`].
fn is_dependencies_array_start(trimmed: &str) -> bool {
    trimmed
        .strip_prefix("dependencies")
        .map(str::trim_start)
        .and_then(|rest| rest.strip_prefix('='))
        .is_some_and(|rest| rest.trim_start().starts_with('['))
}

/// Extracts the fallback-completion prefix on `line` up to `character` — PyPI's
/// dependency entries are TOML string-array elements (`"pytes`), a different quoting
/// shape from JSON-quoted keys.
///
/// Returns an empty prefix when the cursor sits right after an already-closed value
/// (`"pytest"`), rather than unconditionally stripping quotes on either side:
/// [`PypiEcosystem::completion_insert_text`]'s fallback arm always bare-inserts the
/// package name, so reporting a prefix for an already-closed value would fire a
/// registry search and bare-insert the result straight into the manifest text next to
/// it, producing invalid TOML (`"pytest"pytest-cov`, #734) — the same defect class as
/// #729 for npm/Composer's JSON keys, just without a key-vs-value split since a TOML
/// array element has no `:` clause to disambiguate.
///
/// Uses [`deps_core::fallback_completion::count_real_quotes`]'s escape-aware
/// quote-parity check directly rather than
/// [`deps_core::fallback_completion::open_quoted_tail`]: a *zero* real-quote count
/// (the opening quote not typed yet — a realistic mid-edit state, since the fallback
/// path only runs on parse failure) must return `prefix` unchanged, matching this
/// function's pre-#734 no-op behavior on unquoted text, not the empty string
/// `open_quoted_tail` returns for that count. Only a non-zero, even count (a genuinely
/// closed value) suppresses the prefix.
///
/// Only tracks `"` (TOML basic strings), not `'` (TOML literal strings, e.g.
/// `'requests'`) — deliberately out of scope: `crate::name::normalize`'s query never
/// strips a `'`, so a prefix containing one never matches a real (apostrophe-free)
/// PyPI project name, and the registry search that would drive a bare/wrapped insert
/// never returns a result to insert in the first place.
fn extract_prefix(line: &str, character: u32) -> &str {
    let prefix = deps_core::fallback_completion::raw_prefix(line, character);
    let (count, last_quote) = deps_core::fallback_completion::count_real_quotes(prefix);
    if count == 0 {
        return prefix;
    }
    if count.is_multiple_of(2) {
        return "";
    }
    // `count` odd (so >= 1) guarantees `count_real_quotes` found a real quote; `"` is
    // a single-byte ASCII char, so `pos + 1` is always a char boundary.
    #[allow(clippy::string_slice)]
    last_quote.map_or("", |pos| &prefix[pos + 1..])
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
#[cfg(feature = "lsp-responses")]
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

/// Whether `target` is written as an absolute filesystem path — a POSIX-style
/// `/...`/`\...` root, or a Windows drive prefix (`C:\...`, `C:/...`, or the
/// drive-*relative* `C:evil.txt`/bare `C:` forms).
///
/// Checked on the raw string rather than `std::path::Path::is_absolute()`: that method's
/// notion of "absolute" is platform-dependent (a Windows drive prefix is not absolute per
/// `Path` on a POSIX host), but `link.target` is manifest text that could name either
/// path style regardless of which OS `deps-lsp` itself runs on. The drive-letter check
/// deliberately has no separator requirement after the colon: per `std::path`'s own docs,
/// `Path::join`ing a "prefix but no root" path (Windows' term for exactly this
/// `C:evil.txt`/`C:` shape) onto any base discards the base entirely, same as a fully
/// separator-rooted `C:\...` — requiring a separator here would let that variant silently
/// bypass the whole guard on Windows (#937 finding C1). That base-discard is
/// Windows-specific — on POSIX, `Path::join` treats `C:evil.txt` as an ordinary relative
/// segment (`Path::new("/project").join("C:x") == "/project/C:x"`) — but this function has
/// no way to know which platform authored the requirements file, so it rejects the shape
/// uniformly rather than trusting the host OS's own `Path::join` semantics.
#[cfg(feature = "lsp-responses")]
fn is_absolute_document_link_target(target: &str) -> bool {
    target.starts_with('/')
        || target.starts_with('\\')
        || matches!(target.as_bytes(), [drive, b':', ..] if drive.is_ascii_alphabetic())
}

/// Lexically resolves `.`/`..` components in `path` without touching the filesystem — no
/// `canonicalize`, no symlink resolution, since `generate_document_links` never opens the
/// target, only publishes it as a clickable `DocumentLink`.
///
/// Assumes `path` is rooted: a `..` with nothing left to pop is simply dropped rather
/// than kept as a literal component — the same clamp-at-root behavior a real filesystem
/// gives `/..`. Keeping it (a prior version of this function did) produces a non-canonical
/// path like `/../etc/shadow`: still rejected by the workspace-root containment check
/// today, but a misleading tooltip if that check is ever skipped (#937 finding C2). Every
/// call site upholds the assumption: the join-target call always sees `base_dir.join(...)`
/// (rooted, since `base_dir` comes from the manifest's own file URI), and the
/// workspace-root call site filters through [`is_absolute_document_link_target`] first
/// (#937 finding R2) rather than `Path::is_absolute()` — the latter is platform-dependent
/// (a POSIX-style root like `/project` is not "absolute" per `Path` on Windows, only
/// "has_root"), which would silently skip containment for exactly that shape on Windows. A
/// relative `path` isn't rejected here either way, it just won't clamp to a meaningful
/// root.
#[cfg(feature = "lsp-responses")]
fn lexically_normalize(path: &std::path::Path) -> std::path::PathBuf {
    let mut result = std::path::PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::ParentDir => {
                result.pop();
            }
            std::path::Component::CurDir => {}
            other => result.push(other),
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "lsp-responses")]
    use deps_core::EcosystemConfig;
    use deps_core::{VersionData, parser::DependencySource};
    use std::assert_matches;
    use std::collections::HashMap;
    #[cfg(feature = "lsp-responses")]
    use tower_lsp_server::ls_types::Position;

    #[cfg(feature = "lsp-responses")]
    deps_core::complete_versions_test_shim!(PypiEcosystem);

    fn pkg(s: &str) -> deps_core::PackageName {
        deps_core::PackageName::new(s)
    }

    // #758: exact-value `Ecosystem` conformance, replacing the hand-written
    // test_ecosystem_id/test_ecosystem_display_name/test_ecosystem_manifest_filenames/
    // test_ecosystem_lockfile_filenames/test_as_any/test_registry_returns_arc family.
    // test_ecosystem_manifest_patterns below stays hand-written: `manifest_patterns()` isn't
    // part of the macro's exact-value set.
    deps_core::ecosystem_conformance! {
        mod pypi_ecosystem_conformance;
        build: PypiEcosystem::new(Arc::new(deps_core::HttpCache::new()));
        ty: PypiEcosystem;
        id: "pypi";
        display_name: "PyPI (Python)";
        manifest_filenames: &["pyproject.toml"];
        lockfile_filenames: &["poetry.lock", "uv.lock"];
        non_registry_fixture: "requirements.txt" => "mylib @ https://example.com/mylib.tar.gz\n";
    }

    // #1354 security audit: PyPI has no `${VAR}`-expansion syntax of its own — an unresolved
    // shell-style placeholder inside a version specifier fails PEP 440 parsing, so
    // `parse_requirements`'s per-line "log and skip" behavior drops the whole line rather than
    // producing a dependency with `version_requirement: None`. This is an even stronger form
    // of "never reaches the gate" than the other `reachable: false` ecosystems.
    deps_core::unresolved_requirement_conformance! {
        mod pypi_unresolved_requirement_conformance;
        build: PypiEcosystem::new(Arc::new(deps_core::HttpCache::new()));
        reachable: false;
        fixture: "requirements.txt" => "known-good-control==1.0.0\nmylib==${VERSION}\n";
    }

    // #1374: unlike the PEP 440 `mylib==${VERSION}` requirements.txt/PEP 621 form above,
    // `[tool.poetry.dependencies]`'s string-form entries have no upstream PEP 440/508
    // validation (`PypiParser::parse_poetry_dependency` takes the raw TOML string value
    // directly) — a `$VAR`/`${VAR}`-style external-templating placeholder there stays a
    // normal `Some(version_requirement)` and reaches `plan_vulnerability_fix`/
    // `format_version_replacing_for` directly, depending entirely on `PypiFormatter`'s own
    // `requirement_contains_dollar_placeholder` guard.
    deps_core::unresolved_requirement_conformance! {
        mod pypi_poetry_dollar_placeholder_conformance;
        build: PypiEcosystem::new(Arc::new(deps_core::HttpCache::new()));
        reachable: true;
        fixture: "pyproject.toml" =>
            "[tool.poetry.dependencies]\nnumpy = \"${NUMPY}\"\n";
    }

    // #758: the shared completion-prefix-length guard
    // (`deps_core::completion::complete_package_names_generic`), replacing
    // test_complete_package_names_minimum_prefix/test_complete_package_names_max_length.
    #[cfg(feature = "lsp-responses")]
    deps_core::completion_guard_conformance! {
        mod pypi_completion_guard_conformance;
        complete: |registry: &dyn deps_core::Registry, prefix: String| -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Vec<tower_lsp_server::ls_types::CompletionItem>> + Send + '_>,
        > {
            Box::pin(async move {
                deps_core::completion::complete_package_names_generic(
                    registry,
                    &prefix,
                    20,
                    Range::default(),
                )
                .await
            })
        };
    }

    // #1137: regression guard, not independent parser verification (see
    // `operator_chars_conformance!`'s doc) — `required` mirrors `VERSION_OPERATOR_CHARS`'s
    // own doc comment (PEP 508 plus Poetry's caret), so an edit to one without the other
    // fails loudly instead of silently degrading completion.
    #[cfg(feature = "lsp-responses")]
    deps_core::operator_chars_conformance! {
        mod pypi_operator_chars_conformance;
        ecosystem: "pypi";
        operator_chars: VERSION_OPERATOR_CHARS;
        required: &['>', '<', '=', '~', '!', '^'];
    }

    // #1136: a dependency whose only registry source is blocked by the default reachability
    // policy (SSRF-class host) must yield zero version completions and never reach PyPI.
    #[cfg(feature = "lsp-responses")]
    deps_core::completion_source_gate_conformance! {
        mod pypi_completion_source_gate_conformance;
        build: async {
            let mut server = mockito::Server::new_async().await;
            let mock = server
                .mock("GET", mockito::Matcher::Any)
                .expect(0)
                .create_async()
                .await;
            let cache = Arc::new(deps_core::HttpCache::new());
            let registry = Arc::new(PypiRegistry::with_public_base_for_test(
                Arc::clone(&cache),
                server.url(),
            ));
            let policy = Arc::new(deps_core::net_policy::RegistryAccessPolicy::default());
            let eco = PypiEcosystem::with_policy(registry, policy);
            (eco, mock, server)
        };
        manifest: "pyproject.toml" => "[[tool.poetry.source]]\nname = \"internal\"\nurl = \"https://169.254.169.254/simple\"\n\n[tool.poetry.dependencies]\nrequests = \"^2.28.0\"\n";
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

    #[cfg(feature = "lsp-responses")]
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

    /// #1090: a non-`file:`-scheme (or remote-host `file:`) manifest URI must not resolve a
    /// document-link target against a real local directory — same guard gap class as
    /// #1084/#1089's lock file fix, applied here to `generate_document_links`' base
    /// directory resolution.
    #[cfg(feature = "lsp-responses")]
    #[tokio::test]
    async fn test_generate_document_links_rejects_malicious_uri() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = PypiEcosystem::new(cache);
        let file_uri = deps_core::test_util::test_uri("/project/requirements.txt");
        let path_part = file_uri.as_str().strip_prefix("file://").unwrap();

        // `"file://attacker.example"` used to be a second prefix here. It was removed (#1090
        // guard-gap follow-up): `deps_core::test_util::test_uri` builds a Windows-shaped
        // absolute path (`C:/...`) on Windows CI, and when the path is
        // Windows-drive-letter-shaped like that, a `file:` URI with a non-empty host cannot
        // be represented by a parsed `url::Url` at all — the WHATWG URL Standard's file-host
        // parsing rule (`SyntaxViolation::FileWithHostAndWindowsDrive`) strips the host
        // before `generate_document_links` (or any code holding only a `&Url`) can see it, so
        // that sub-case asserted an unreachable invariant and failed on `windows-latest` CI.
        // On Unix the path is never drive-letter-shaped, so the host survives parsing and the
        // per-layer host guard stays live and testable there — this comment only concerns the
        // Windows-shaped case, not a claim that the guard is dead on every platform. This
        // exact bypass is guarded and tested platform-independently at the point where
        // untrusted URIs are first parsed: `deps_lsp::lsp_types_interop::from_lsp_uri`, see
        // its test `test_from_lsp_uri_rejects_windows_drive_host_bypass`.
        let prefix = "https://attacker.example";
        let uri: Url = format!("{prefix}{path_part}").parse().unwrap();

        let parse_result = ecosystem
            .parse_manifest("-r base.txt\n", &uri)
            .await
            .unwrap();

        let links = ecosystem.generate_document_links(parse_result.as_ref(), &uri);
        assert!(
            links.is_empty(),
            "a malicious-scheme/host URI ({prefix}) must not resolve document link targets \
             against a real directory"
        );
    }

    #[cfg(feature = "lsp-responses")]
    #[tokio::test]
    async fn test_generate_document_links_rejects_absolute_target() {
        // #937: an absolute `-r`/`-c` target silently discards `base_dir` on
        // `Path::join`, resolving to the absolute path verbatim instead of
        // anything under the manifest's own directory.
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = PypiEcosystem::new(cache);
        let uri = deps_core::test_util::test_uri("/project/requirements.txt");

        let parse_result = ecosystem
            .parse_manifest("-r /etc/shadow\n", &uri)
            .await
            .unwrap();

        let links = ecosystem.generate_document_links(parse_result.as_ref(), &uri);
        assert!(links.is_empty());
    }

    #[cfg(feature = "lsp-responses")]
    #[tokio::test]
    async fn test_generate_document_links_rejects_windows_style_absolute_target() {
        // #937: a Windows drive-letter prefix must be rejected even when
        // `deps-lsp` itself runs on a POSIX host, where `Path::is_absolute()`
        // would not recognize it as absolute.
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = PypiEcosystem::new(cache);
        let uri = deps_core::test_util::test_uri("/project/requirements.txt");

        let parse_result = ecosystem
            .parse_manifest("-r C:\\Windows\\System32\\config\\SAM\n", &uri)
            .await
            .unwrap();

        let links = ecosystem.generate_document_links(parse_result.as_ref(), &uri);
        assert!(links.is_empty());
    }

    #[cfg(feature = "lsp-responses")]
    #[tokio::test]
    async fn test_generate_document_links_allows_parent_dir_without_workspace_root() {
        // `-r ../requirements-base.txt` is a standard, legitimate multi-directory pip
        // layout (#937) — it must not be rejected outright the way an absolute path is,
        // and with no workspace root known (pypi's `ParseResult::workspace_root` is
        // always `None` today) there is nothing to contain it against.
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = PypiEcosystem::new(cache);
        let uri = deps_core::test_util::test_uri("/project/sub/requirements.txt");

        let parse_result = ecosystem
            .parse_manifest("-r ../requirements-base.txt\n", &uri)
            .await
            .unwrap();

        let links = ecosystem.generate_document_links(parse_result.as_ref(), &uri);
        assert_eq!(links.len(), 1);
        let target = links[0].target.as_ref().unwrap();
        assert!(
            target
                .path()
                .as_str()
                .ends_with("/project/requirements-base.txt")
        );
    }

    /// Builds a workspace-root `PathBuf` fixture that matches
    /// [`deps_core::test_util::test_uri`]'s own platform handling: on Windows,
    /// `test_uri` prepends `C:` to its POSIX-style input so `Uri::from_file_path`
    /// accepts it (a drive-less path isn't a valid Windows file URI), so a
    /// `workspace_root` fixture built from the same POSIX-style string must get the
    /// same prefix — otherwise it and the `base_dir` derived from a `test_uri`
    /// document (which *does* carry the drive) never share a common root, and the
    /// containment check spuriously rejects every target on Windows.
    #[cfg(feature = "lsp-responses")]
    fn test_workspace_root(unix_path: &str) -> std::path::PathBuf {
        #[cfg(windows)]
        {
            std::path::PathBuf::from(format!("C:{unix_path}"))
        }
        #[cfg(not(windows))]
        {
            std::path::PathBuf::from(unix_path)
        }
    }

    /// A single-document-link `ParseResult` with an explicit `workspace_root`, used to
    /// exercise the containment check directly (`parse_manifest` never produces a
    /// non-`None` `workspace_root` for pypi today — see the field's own doc).
    #[cfg(feature = "lsp-responses")]
    fn parse_result_with_document_link(
        uri: Url,
        workspace_root: Option<std::path::PathBuf>,
        target: &str,
    ) -> crate::parser::ParseResult {
        use deps_core::position::{Position as DomainPosition, Range as DomainRange};
        crate::parser::ParseResult {
            dependencies: Vec::new(),
            workspace_root,
            uri,
            document_links: vec![crate::parser::RequirementRef {
                range: DomainRange::new(DomainPosition::new(0, 0), DomainPosition::new(0, 0)),
                target: target.to_string(),
            }],
            resolved_chains: Vec::new(),
            blocked_registries: Vec::new(),
            dependency_truncation: None,
        }
    }

    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_generate_document_links_rejects_escape_past_workspace_root() {
        // #937: once a workspace root is known, a relative target with enough `../`
        // segments to climb out of it entirely must be rejected — unlike a `..` that
        // stays within the root (covered above), this is a real containment escape.
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = PypiEcosystem::new(cache);
        let uri = deps_core::test_util::test_uri("/project/sub/deep/requirements.txt");

        let parse_result = parse_result_with_document_link(
            uri.clone(),
            Some(test_workspace_root("/project")),
            "../../../../etc/shadow",
        );

        let links = ecosystem.generate_document_links(&parse_result, &uri);
        assert!(links.is_empty());
    }

    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_generate_document_links_accepts_path_that_climbs_to_root_then_reenters() {
        // #937 (impl-critic C2/second pass): discriminates `lexically_normalize`'s
        // pop-vs-push-back behavior on an unpoppable `..`, which the escape test above
        // does not — both variants reject every input there. Base `/project/sub`, root
        // `/project`, target `../../../project/x.txt`: after climbing past the root, the
        // current (pop/drop) implementation normalizes to the clean, contained
        // `/project/x.txt` (accepted, correctly — this genuinely resolves inside the
        // root). The prior (push-back) implementation would instead have left a stray
        // `..` component, normalizing to the non-canonical `/../project/x.txt`, which
        // fails `starts_with("/project")` and gets wrongly rejected.
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = PypiEcosystem::new(cache);
        let uri = deps_core::test_util::test_uri("/project/sub/requirements.txt");

        let parse_result = parse_result_with_document_link(
            uri.clone(),
            Some(test_workspace_root("/project")),
            "../../../project/x.txt",
        );

        let links = ecosystem.generate_document_links(&parse_result, &uri);
        assert_eq!(links.len(), 1);
        let target = links[0].target.as_ref().unwrap();
        assert!(target.path().as_str().ends_with("/project/x.txt"));
    }

    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_generate_document_links_allows_parent_dir_with_workspace_root_set() {
        // #937 (impl-critic C4): a legitimate `../` include that stays inside the
        // workspace root must still be accepted once a root is known — the only other
        // legitimate-`../` test (`..._allows_parent_dir_without_workspace_root`) runs with
        // `workspace_root: None`, which skips the containment branch entirely.
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = PypiEcosystem::new(cache);
        let uri = deps_core::test_util::test_uri("/project/sub/requirements.txt");

        let parse_result = parse_result_with_document_link(
            uri.clone(),
            Some(test_workspace_root("/project")),
            "../shared/req.txt",
        );

        let links = ecosystem.generate_document_links(&parse_result, &uri);
        assert_eq!(links.len(), 1);
        let target = links[0].target.as_ref().unwrap();
        assert!(target.path().as_str().ends_with("/project/shared/req.txt"));
    }

    #[cfg(feature = "lsp-responses")]
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

    #[cfg(feature = "lsp-responses")]
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

    #[cfg(feature = "lsp-responses")]
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

    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_is_absolute_document_link_target_detects_every_absolute_form() {
        // #937 (impl-critic C1/C4): `C:evil.txt` and bare `C:` are Windows
        // *drive-relative* paths — no separator after the colon — that still discard
        // `base_dir` on `Path::join` exactly like a fully separator-rooted `C:\...` does.
        for bad in [
            "/etc/shadow",
            "\\Windows\\System32",
            "C:\\Windows\\System32\\config\\SAM",
            "c:/Windows/System32",
            "C:evil.txt",
            "C:",
            "\\\\server\\share\\secret.txt",
            "//server/share/secret.txt",
        ] {
            assert!(
                is_absolute_document_link_target(bad),
                "expected {bad:?} to be treated as absolute"
            );
        }
    }

    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_is_absolute_document_link_target_accepts_relative_paths() {
        for good in [
            "base.txt",
            "../shared/constraints.txt",
            "dev-requirements.txt",
        ] {
            assert!(!is_absolute_document_link_target(good));
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
        assert_matches!(
            err,
            deps_core::DepsError::ParseError { file_type, .. } if file_type == "pyproject.toml"
        );
    }

    #[cfg(feature = "lsp-responses")]
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
    #[cfg(feature = "lsp-responses")]
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

    /// Builds a `PypiEcosystem` whose registry's search index is pointed at a
    /// mock server rather than the real `pypi.org/simple/`, so package-name
    /// completion (issue #419) can be exercised network-free.
    #[cfg(feature = "lsp-responses")]
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
    #[cfg(feature = "lsp-responses")]
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
    #[cfg(feature = "lsp-responses")]
    #[tokio::test]
    async fn test_complete_package_names_uses_index() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
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
        mock.assert_async().await;
        assert!(!results.is_empty());
        assert!(results.iter().any(|r| r.label == "requests"));
    }

    /// #419 S2 regression: a query using a different separator than the index's
    /// normalized form (`zope.int`, PEP 503-normalized to `zope-int` server-side)
    /// must come back with `filter_text` set to the *raw typed* prefix, not the
    /// normalized `label`/`insert_text` — otherwise an LSP client's local
    /// re-filtering (`zope.int` is not a subsequence of `zope-interface`) would
    /// silently drop a result the server correctly matched.
    #[cfg(feature = "lsp-responses")]
    #[tokio::test]
    async fn test_complete_package_names_filter_text_matches_raw_typed_prefix() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
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

        mock.assert_async().await;
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
    #[cfg(feature = "lsp-responses")]
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

    #[cfg(feature = "lsp-responses")]
    #[tokio::test]
    #[ignore = "requires network access"]
    async fn test_complete_versions_real() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = PypiEcosystem::new(cache);
        let parse_result = parse_result_with_dependency("requests", DependencySource::Registry);

        let results = ecosystem
            .complete_versions(
                &parse_result,
                DEP_POSITION,
                "2.",
                deps_core::FreshnessSettings::default(),
            )
            .await;
        assert!(!results.is_empty());
        assert!(results.iter().all(|r| r.label.starts_with("2.")));
    }

    #[cfg(feature = "lsp-responses")]
    #[tokio::test]
    #[ignore = "requires network access"]
    async fn test_complete_versions_with_operator() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = PypiEcosystem::new(cache);
        let parse_result = parse_result_with_dependency("requests", DependencySource::Registry);

        let results = ecosystem
            .complete_versions(
                &parse_result,
                DEP_POSITION,
                ">=2.",
                deps_core::FreshnessSettings::default(),
            )
            .await;
        assert!(!results.is_empty());
        assert!(results.iter().all(|r| r.label.starts_with("2.")));
    }

    /// Sentinel package name for a package that does not exist in the registry (#1038): every
    /// "unknown package" completion test below shares it, resolved against a mockito 404 via
    /// [`mock_unknown_package_ecosystem`] rather than the live `pypi.org`.
    #[cfg(feature = "lsp-responses")]
    const UNKNOWN_PACKAGE: &str = "this-package-does-not-exist-12345";

    /// Builds a [`PypiEcosystem`] wired to a mockito server that 404s `name` (#1038), plus the
    /// `Mock`/`ServerGuard` handles the caller must keep alive and assert on — shared by every
    /// "unknown package" completion test below to avoid repeating the same
    /// live-registry-avoiding wiring per test. A regression that makes zero requests (and so
    /// also produces an empty result) can no longer pass vacuously, since
    /// `mock.assert_async()` requires the request to actually have been made.
    #[cfg(feature = "lsp-responses")]
    async fn mock_unknown_package_ecosystem(
        name: &str,
    ) -> (mockito::ServerGuard, mockito::Mock, PypiEcosystem) {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", format!("/simple/{name}/").as_str())
            .with_status(404)
            .create_async()
            .await;
        let cache = Arc::new(deps_core::HttpCache::new());
        let registry = PypiRegistry::with_public_base_for_test(
            Arc::clone(&cache),
            format!("{}/simple", server.url()),
        );
        let ecosystem = PypiEcosystem::with_policy(
            Arc::new(registry),
            Arc::new(deps_core::net_policy::RegistryAccessPolicy::default()),
        );
        (server, mock, ecosystem)
    }

    #[cfg(feature = "lsp-responses")]
    #[tokio::test]
    async fn test_complete_versions_unknown_package() {
        let (_server, mock, ecosystem) = mock_unknown_package_ecosystem(UNKNOWN_PACKAGE).await;
        let parse_result =
            parse_result_with_dependency(UNKNOWN_PACKAGE, DependencySource::Registry);

        let results = ecosystem
            .complete_versions(
                &parse_result,
                DEP_POSITION,
                "1.0",
                deps_core::FreshnessSettings::default(),
            )
            .await;
        mock.assert_async().await;
        assert!(results.is_empty());
    }

    /// The single dependency `parse_result_with_dependency` constructs always has its
    /// `version_range` start here — every call site below passes this as `complete_versions`'
    /// `position` argument so the position-based lookup finds it.
    #[cfg(feature = "lsp-responses")]
    const DEP_POSITION: Position = Position {
        line: 0,
        character: 0,
    };

    /// A minimal single-dependency `ParseResult`, used to exercise `complete_versions`'
    /// per-source routing (issue #593) — the dependency's `version_range` starts at
    /// [`DEP_POSITION`].
    #[cfg(feature = "lsp-responses")]
    fn parse_result_with_dependency(
        name: &str,
        source: DependencySource,
    ) -> crate::parser::ParseResult {
        use deps_core::position::{Position as DomainPosition, Range};
        crate::parser::ParseResult {
            dependencies: vec![crate::types::PypiDependency {
                name: pkg(name),
                name_range: Range::new(DomainPosition::new(0, 0), DomainPosition::new(0, 0)),
                version_req: None,
                version_range: Some(Range::new(DEP_POSITION.into(), DomainPosition::new(0, 10))),
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
            blocked_registries: Vec::new(),
            dependency_truncation: None,
        }
    }

    /// Validator finding #1 (security H1 + impl-critic C1): a version-completion request for
    /// an `AlternateRegistry`-sourced dependency must route through the resolved chain, never
    /// through the root `Public`-tier client — fetching from the root would send the
    /// dependency's name to `pypi.org` on every keystroke.
    #[cfg(feature = "lsp-responses")]
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
            key_shape: deps_core::registry::KeyShape::Opaque,
            hops: vec![base],
            implicit_public_fallback: false,
        };
        PypiRegistry::register_alternate(&root, &chain);

        let source = DependencySource::AlternateRegistry {
            index: chain.key.clone(),
            mirrors_crates_io: false,
        };
        let parse_result = parse_result_with_dependency("mypkg", source);

        let results = ecosystem
            .complete_versions(
                &parse_result,
                DEP_POSITION,
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
    #[cfg(feature = "lsp-responses")]
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
                DEP_POSITION,
                "",
                deps_core::FreshnessSettings::default(),
            )
            .await;
        assert!(results.is_empty());
    }

    /// Validator finding #1: an `AlternateRegistry` source whose chain was never registered
    /// (or whose registration is now stale) offers nothing rather than falling back to the
    /// root client.
    #[cfg(feature = "lsp-responses")]
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
                DEP_POSITION,
                "",
                deps_core::FreshnessSettings::default(),
            )
            .await;
        assert!(results.is_empty());
    }

    /// Issue #593: two dependencies sharing one `PackageName` but resolving to different
    /// sources no longer collapse into the old name-based "offer nothing for either" result
    /// — cursor position now identifies exactly one dependency, so each occurrence routes
    /// independently through its own source.
    #[cfg(feature = "lsp-responses")]
    #[tokio::test]
    async fn test_complete_versions_same_name_different_sources_routes_by_position() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = PypiEcosystem::new(cache);

        use deps_core::position::{Position as DomainPosition, Range as DomainRange};

        let mut registry_dep =
            parse_result_with_dependency("shared-name", DependencySource::Registry)
                .dependencies
                .remove(0);
        registry_dep.name_range =
            DomainRange::new(DomainPosition::new(0, 0), DomainPosition::new(0, 0));
        registry_dep.version_range = Some(DomainRange::new(
            DomainPosition::new(0, 0),
            DomainPosition::new(0, 10),
        ));

        let mut alternate_dep = parse_result_with_dependency(
            "shared-name",
            DependencySource::AlternateRegistry {
                index: "pypi-chain:never-registered".to_string(),
                mirrors_crates_io: false,
            },
        )
        .dependencies
        .remove(0);
        alternate_dep.name_range =
            DomainRange::new(DomainPosition::new(1, 0), DomainPosition::new(1, 0));
        alternate_dep.version_range = Some(DomainRange::new(
            DomainPosition::new(1, 0),
            DomainPosition::new(1, 10),
        ));
        let alternate_position = alternate_dep.version_range.unwrap().start;

        let parse_result = crate::parser::ParseResult {
            dependencies: vec![registry_dep, alternate_dep],
            workspace_root: None,
            uri: deps_core::test_util::test_uri("/test/requirements.txt"),
            document_links: Vec::new(),
            resolved_chains: Vec::new(),
            blocked_registries: Vec::new(),
            dependency_truncation: None,
        };

        // The alternate occurrence resolves deterministically without network: its chain was
        // never registered, so the fetch fails closed with `PackageNotFound` before any HTTP
        // call — proving its own source, not the co-occurring `Registry`-sourced entry, drove
        // the routing.
        let results = ecosystem
            .complete_versions(
                &parse_result,
                alternate_position.into(),
                "1",
                deps_core::FreshnessSettings::default(),
            )
            .await;
        assert!(
            results.is_empty(),
            "unregistered alternate chain must offer no completions"
        );
    }

    /// #1066: was `assert!(results.is_empty() || !results.is_empty())` — a tautology that
    /// could never fail identically whether cold-start behaved correctly, the network was
    /// down, `complete_package_names` were replaced with `vec![]` unconditionally, or the
    /// prefix-length gate rejected before the index was ever consulted. Mirrors
    /// `test_complete_package_names_uses_index`: a mocked index proves the cold start is
    /// genuinely empty (not just "empty for the wrong reason"), then `poll_until_nonempty` +
    /// `mock.assert_async()` + a concrete label prove the index actually works once built.
    #[cfg(feature = "lsp-responses")]
    #[tokio::test]
    async fn test_complete_package_names_special_characters() {
        // #1055: was a live, unmocked search index build that asserted the tautology
        // `results.is_empty() || !results.is_empty()`. Mocked via the same
        // `ecosystem_with_index_url`/`sample_index_body` seam `test_complete_package_names_uses_index`
        // (issue #419) already established.
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/simple/")
            .with_status(200)
            .with_body(crate::search::sample_index_body(&["scikit-learn"]))
            .expect_at_least(1)
            .create_async()
            .await;

        let cache = Arc::new(deps_core::HttpCache::new());
        let index_url = format!("{}/simple/", server.url());
        let ecosystem = ecosystem_with_index_url(cache, index_url);

        let cold_start = ecosystem
            .complete_package_names("scikit-le", Range::default())
            .await;
        assert!(
            cold_start.is_empty(),
            "cold start must not block on the index download"
        );

        let results = poll_until_nonempty(
            || ecosystem.complete_package_names("scikit-le", Range::default()),
            100,
        )
        .await;
        mock.assert_async().await;
        assert!(results.iter().any(|r| r.label == "scikit-learn"));
    }

    /// #1066: was `assert!(results.len() <= 20)` against a live registry — a tautology given
    /// the actual display cap (`MAX_COMPLETION_VERSIONS`, `deps-core`) is 5, not 20, so it
    /// passed vacuously (even for 0 results) and could never catch a cap regression. Mocks 8
    /// matching versions and asserts the count is exactly the real cap.
    #[cfg(feature = "lsp-responses")]
    #[tokio::test]
    async fn test_complete_versions_capped_at_max_completion_versions() {
        let mut server = mockito::Server::new_async().await;
        let versions = (0..8)
            .map(|i| format!(r#""2.{i}.0""#))
            .collect::<Vec<_>>()
            .join(", ");
        let mock = server
            .mock("GET", "/simple/requests/")
            .with_status(200)
            .with_body(format!(r#"{{"versions": [{versions}], "files": []}}"#))
            .create_async()
            .await;

        let cache = Arc::new(deps_core::HttpCache::new());
        let registry = PypiRegistry::with_public_base_for_test(
            Arc::clone(&cache),
            format!("{}/simple", server.url()),
        );
        let ecosystem = PypiEcosystem::with_policy(
            Arc::new(registry),
            Arc::new(deps_core::net_policy::RegistryAccessPolicy::default()),
        );

        let parse_result = parse_result_with_dependency("requests", DependencySource::Registry);
        let results = ecosystem
            .complete_versions(
                &parse_result,
                DEP_POSITION,
                "2",
                deps_core::FreshnessSettings::default(),
            )
            .await;
        mock.assert_async().await;
        assert_eq!(results.len(), 5);
    }

    /// End-to-end regression for #1137: a Poetry-style caret prefix (`^2.28`) must filter
    /// completions to matching versions, not fall through `VERSION_OPERATOR_CHARS`'s strip
    /// (which was previously missing `^`) into the unfiltered top-N fallback the issue
    /// reported. `operator_chars_conformance!` above only proves the array *contains* `^`; it
    /// does not exercise `complete_versions`/`complete_versions_generic_from` with a real
    /// prefix, which is what actually reproduces the reported symptom.
    #[cfg(feature = "lsp-responses")]
    #[tokio::test]
    async fn test_complete_versions_with_poetry_caret_operator_filters_matching_versions() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/simple/requests/")
            .with_status(200)
            .with_body(
                r#"{"versions": ["1.0.0", "2.27.0", "2.28.0", "2.28.1", "2.29.0"], "files": []}"#,
            )
            .create_async()
            .await;

        let cache = Arc::new(deps_core::HttpCache::new());
        let registry = PypiRegistry::with_public_base_for_test(
            Arc::clone(&cache),
            format!("{}/simple", server.url()),
        );
        let ecosystem = PypiEcosystem::with_policy(
            Arc::new(registry),
            Arc::new(deps_core::net_policy::RegistryAccessPolicy::default()),
        );

        let parse_result = parse_result_with_dependency("requests", DependencySource::Registry);
        let results = ecosystem
            .complete_versions(
                &parse_result,
                DEP_POSITION,
                "^2.28",
                deps_core::FreshnessSettings::default(),
            )
            .await;
        mock.assert_async().await;

        assert_eq!(
            results.len(),
            2,
            "expected only the two 2.28.x versions, got: {results:?}"
        );
        assert!(
            results.iter().all(|r| r.label.starts_with("2.28")),
            "a stripped `^` prefix must filter out 1.0.0/2.27.0/2.29.0, got: {results:?}"
        );
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
    async fn test_lockfile_provider_returns_some() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = PypiEcosystem::new(cache);

        let provider = ecosystem.lockfile_provider();
        assert!(provider.is_some());
    }

    #[cfg(feature = "lsp-responses")]
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

    #[cfg(feature = "lsp-responses")]
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

    #[cfg(feature = "lsp-responses")]
    #[tokio::test]
    async fn test_generate_completions_package_name_context_returns_matches() {
        // #1055: position (1, 20) lands inside the bare `requests` entry (no version
        // specifier), which `detect_completion_context` resolves as a `PackageName` context,
        // not a `Feature` one (pypi never overrides `complete_feature`) — so this previously
        // drove an unmocked, live search-index build while asserting the tautology
        // `completions.items.is_empty() || !completions.items.is_empty()`. Mocked via the same
        // seam as `test_complete_package_names_uses_index` (#419).
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/simple/")
            .with_status(200)
            .with_body(crate::search::sample_index_body(&["requests"]))
            .expect_at_least(1)
            .create_async()
            .await;

        let cache = Arc::new(deps_core::HttpCache::new());
        let index_url = format!("{}/simple/", server.url());
        let ecosystem = ecosystem_with_index_url(cache, index_url);

        let content = r#"[project]
dependencies = ["requests"]
"#;
        let uri = deps_core::test_util::test_uri("/test/pyproject.toml");
        let parse_result = ecosystem.parse_manifest(content, &uri).await.unwrap();

        let position = Position {
            line: 1,
            character: 20,
        };

        let cold_start = ecosystem
            .generate_completions(
                parse_result.as_ref(),
                position,
                content,
                deps_core::FreshnessSettings::default(),
            )
            .await;
        assert!(
            cold_start.items.is_empty(),
            "cold start must not block on the index download"
        );

        let completions = poll_until_nonempty(
            || async {
                ecosystem
                    .generate_completions(
                        parse_result.as_ref(),
                        position,
                        content,
                        deps_core::FreshnessSettings::default(),
                    )
                    .await
                    .items
            },
            100,
        )
        .await;

        mock.assert_async().await;
        assert!(completions.iter().any(|r| r.label == "requests"));
    }

    /// #1195 M4 regression: a bare `>` comparator (`this-package-does-not-exist-12345>2.0`)
    /// has no `=` character anywhere on the line, so `deps-lsp`'s
    /// `fallback_completion`-gate's `prefix.contains('=')` guard offers no protection —
    /// before this PR, an empty `complete_versions` result at this position would fall
    /// through to a raw-text package-name search for the literal string
    /// `"this-package-does-not-exist-12345>2."`. Runs through the real parser and the real
    /// `generate_completions` dispatch (not a synthetic `ParseResult`), with a mocked 404 so
    /// the empty result is deterministic and `mock.assert_async()` proves the `Version`
    /// context was actually reached rather than resolving to `None`/`Unresolved`.
    #[cfg(feature = "lsp-responses")]
    #[tokio::test]
    async fn test_generate_completions_bare_comparator_version_empty_result_stamps_version_origin()
    {
        let (_server, mock, ecosystem) = mock_unknown_package_ecosystem(UNKNOWN_PACKAGE).await;

        let content = format!("{UNKNOWN_PACKAGE}>2.0\n");
        let uri = deps_core::test_util::test_uri("/test/requirements.txt");
        let parse_result = ecosystem.parse_manifest(&content, &uri).await.unwrap();
        assert_eq!(
            parse_result.dependencies().len(),
            1,
            "fixture must parse the bare `>` comparator as one dependency: {content}"
        );

        // Cursor between "2." and "0" — mid-typing, prefix "2.", no "=" on the line.
        let cursor = u32::try_from(content.find("2.0").unwrap() + 2).unwrap();
        let position = Position {
            line: 0,
            character: cursor,
        };

        let completions = ecosystem
            .generate_completions(
                parse_result.as_ref(),
                position,
                &content,
                deps_core::FreshnessSettings::default(),
            )
            .await;

        mock.assert_async().await;
        assert!(completions.items.is_empty());
        assert_eq!(
            completions.origin,
            deps_core::completion::CompletionOrigin::Version,
            "a bare `>` comparator has no `=` on the line — CompletionOrigin::Version, not \
             the prefix.contains('=') guard, is what must stop deps-lsp's fallback here"
        );
    }

    #[cfg(feature = "lsp-responses")]
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

    #[cfg(feature = "lsp-responses")]
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

    /// #1038: was a live-registry round-trip asserting only `results.is_empty()` — vacuous
    /// under a dead network, since a regression that made zero requests would produce the
    /// same empty result. Now mocked, with `mock.assert_async()` requiring the request to
    /// actually have been made.
    #[cfg(feature = "lsp-responses")]
    #[tokio::test]
    async fn test_complete_versions_empty_prefix() {
        let (_server, mock, ecosystem) =
            mock_unknown_package_ecosystem("nonexistent-package").await;
        let parse_result =
            parse_result_with_dependency("nonexistent-package", DependencySource::Registry);

        let results = ecosystem
            .complete_versions(
                &parse_result,
                DEP_POSITION,
                "",
                deps_core::FreshnessSettings::default(),
            )
            .await;
        mock.assert_async().await;
        assert!(results.is_empty());
    }

    /// #1038: see [`test_complete_versions_empty_prefix`]'s doc for why this is now mocked.
    #[cfg(feature = "lsp-responses")]
    #[tokio::test]
    async fn test_complete_versions_with_tilde_operator() {
        let (_server, mock, ecosystem) = mock_unknown_package_ecosystem("nonexistent-pkg").await;
        let parse_result =
            parse_result_with_dependency("nonexistent-pkg", DependencySource::Registry);

        let results = ecosystem
            .complete_versions(
                &parse_result,
                DEP_POSITION,
                "~=2.0",
                deps_core::FreshnessSettings::default(),
            )
            .await;
        mock.assert_async().await;
        assert!(results.is_empty());
    }

    /// #1038: see [`test_complete_versions_empty_prefix`]'s doc for why this is now mocked.
    #[cfg(feature = "lsp-responses")]
    #[tokio::test]
    async fn test_complete_versions_with_not_equal_operator() {
        let (_server, mock, ecosystem) = mock_unknown_package_ecosystem("nonexistent-pkg").await;
        let parse_result =
            parse_result_with_dependency("nonexistent-pkg", DependencySource::Registry);

        let results = ecosystem
            .complete_versions(
                &parse_result,
                DEP_POSITION,
                "!=2.0",
                deps_core::FreshnessSettings::default(),
            )
            .await;
        mock.assert_async().await;
        assert!(results.is_empty());
    }

    /// End-to-end regression for #212: a dotted package name declared as a
    /// Poetry table key must resolve against its `poetry.lock` entry. Unlike
    /// a PEP 621 fixture (which already worked before the fix, since
    /// `pep508_rs::PackageName` normalizes at construction), the Poetry
    /// table-key path takes the name verbatim from the TOML key — this is
    /// the actual bug #212 fixes.
    mod poetry_lockfile_regression_tests {
        #[cfg(feature = "lsp-responses")]
        use super::*;
        #[cfg(feature = "lsp-responses")]
        use crate::lockfile::PypiLockParser;
        #[cfg(feature = "lsp-responses")]
        use deps_core::PackageName;
        #[cfg(feature = "lsp-responses")]
        use deps_core::lockfile::LockFileProvider;

        /// A registry mock returning an empty (but `Ok`) version list —
        /// `generate_hover` requires a successful registry call before it
        /// reaches the `versions.resolved`-driven "Current" line, but the
        /// content of that call is irrelevant to this regression.
        #[cfg(feature = "lsp-responses")]
        struct EmptyOkRegistry;

        #[cfg(feature = "lsp-responses")]
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

            fn search_raw<'a>(
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

        #[cfg(feature = "lsp-responses")]
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
                dep_position.into(),
                versions,
                &EmptyOkRegistry,
                &formatter,
                deps_core::FreshnessSettings::default(),
                deps_core::PublishTime::now(),
            )
            .await
            .expect("hover should be produced for a dependency at its name position");

            let markdown = hover.markdown();
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
                    .all(|d| !d.message().contains("Unknown package")),
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
            .map(|d| (d.name().as_str().to_string(), d.source()))
            .collect()
    }

    /// A file with no index declaration anywhere never constructs more than an empty
    /// `PypiIndexConfig` and never calls `register_alternate` (US-004).
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
        // ecosystem shares — proving `parse_manifest` really called `register_alternate`, not
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

    /// Composition regression guard (#390 C5 bug class, mirrors the deleted
    /// `deps-lsp` end-to-end test
    /// `test_fallback_completion_pypi_project_array_query_has_no_leaked_quote`):
    /// proves `line_at` + `is_in_pypi_project_dependencies_array` + quote-stripping
    /// compose correctly through the real trait method on realistic multi-line
    /// `pyproject.toml` content — the primitives were each individually correct in
    /// isolation but their composition was the actual #390 bug.
    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_fallback_completion_prefix_multi_line_composition_project_array() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = PypiEcosystem::new(cache);
        let content = "[project]\nname = \"myapp\"\nversion = \"0.1.0\"\ndependencies = [\n    \"requests>=2.31.0\",\n    \"flas";
        let line = content.lines().nth(5).unwrap();
        let position = Position::new(5, line.chars().count() as u32);
        assert_eq!(
            eco.fallback_completion_prefix(content, position.into()),
            Some("flas")
        );
    }

    /// Same composition, `[project.optional-dependencies]`'s real section-header
    /// shape rather than the headerless primary `dependencies = [...]` array.
    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_fallback_completion_prefix_multi_line_composition_optional_dependencies() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = PypiEcosystem::new(cache);
        let content = "[project.optional-dependencies]\ndev = [\n    \"pytest\",\n    \"flas";
        let line = content.lines().nth(3).unwrap();
        let position = Position::new(3, line.chars().count() as u32);
        assert_eq!(
            eco.fallback_completion_prefix(content, position.into()),
            Some("flas")
        );
    }

    #[test]
    fn test_is_in_dependencies_section_optional_dependencies_header() {
        let content = "\n[project.optional-dependencies]\nrequests\n";
        assert!(is_in_dependencies_section(content, 2));
    }

    /// Real PEP 621 files never write a literal `[project.dependencies]` header — the
    /// primary dependency list is a `dependencies = [...]` array under `[project]`.
    #[test]
    fn test_is_in_dependencies_section_project_array_no_literal_header() {
        let content = "[project]\nname = \"myapp\"\nversion = \"0.1.0\"\ndependencies = [\n    \"requests>=2.31.0\",\n    \"flas\n]\n";
        // Unterminated entry line ("flas), mid-array.
        assert!(is_in_dependencies_section(content, 5));
        // A completed entry line.
        assert!(is_in_dependencies_section(content, 4));
        // Unrelated `[project]` keys must not be treated as inside the array.
        assert!(!is_in_dependencies_section(content, 1));
        assert!(!is_in_dependencies_section(content, 2));
        // The `[project]` header line itself is not "inside" the array.
        assert!(!is_in_dependencies_section(content, 0));
    }

    #[test]
    fn test_is_in_dependencies_section_project_array_single_line() {
        let content = "[project]\ndependencies = [\"requests>=2.0.0\"]\n";
        assert!(is_in_dependencies_section(content, 1));
    }

    /// A `dependencies = [...]` array under a table other than `[project]` (e.g. an
    /// optional-dependencies group using the same key name) must not be picked up by
    /// the `[project]`-scoped array scan.
    #[test]
    fn test_is_in_dependencies_section_project_array_scoped_to_project_table() {
        let content = "[tool.other]\ndependencies = [\n    \"foo\n]\n";
        assert!(!is_in_dependencies_section(content, 2));
    }

    /// An unbalanced `[` inside a still-typed extras spec (`"uvicorn[stan`, common
    /// real syntax like `celery[redis]`) must not permanently desync the
    /// bracket-depth counter. A later, real table header is an unambiguous resync
    /// point (TOML forbids a header inside an array), so lines under it must not be
    /// misreported as still inside the dependencies array.
    #[test]
    fn test_is_in_dependencies_section_project_array_resyncs_after_unbalanced_extras_bracket() {
        let content = "[project]\ndependencies = [\n    \"uvicorn[stan\n]\n\n[tool.pytest.ini_options]\naddopts = \"-v\"\n";
        // Mid-typing the extras spec: still correctly inside the array.
        assert!(is_in_dependencies_section(content, 2));
        // A line under the unrelated later table must not be swept in by the
        // desynced counter.
        assert!(!is_in_dependencies_section(content, 6));
    }

    /// A `#` comment containing `[` inside the array (e.g. `# pinned per [PEP 621`)
    /// must not be counted as a real bracket — the comment is stripped before depth
    /// tracking, so the array still closes at its real `]`.
    #[test]
    fn test_is_in_dependencies_section_project_array_ignores_bracket_in_comment() {
        let content = "[project]\ndependencies = [\n    \"requests>=2.0.0\",  # pinned per [PEP 621\n    \"flas\n]\nrequires-python = \">=3.9\"\n";
        // Still inside the array on the unterminated entry.
        assert!(is_in_dependencies_section(content, 3));
        // The array has closed by the time an unrelated `[project]` key follows.
        assert!(!is_in_dependencies_section(content, 5));
    }

    /// A trailing comment on the `[project]` header itself (ordinary TOML) must not
    /// make the whole array-detection scan inert.
    #[test]
    fn test_is_in_dependencies_section_project_header_with_trailing_comment() {
        let content = "[project]  # main metadata\ndependencies = [\n    \"flas\n]\n";
        assert!(is_in_dependencies_section(content, 2));
    }

    /// A commented non-`[project]` header must correctly clear `in_project` (fixed for
    /// free by comment stripping) — a later table's own `dependencies = [...]` array
    /// must not be mistaken for PEP 621's.
    #[test]
    fn test_is_in_dependencies_section_project_state_cleared_by_commented_other_header() {
        let content = "[project]\nname = \"x\"\n\n[tool.hatch.envs.default] # test env\ndependencies = [\n    \"other\n]\n";
        assert!(!is_in_dependencies_section(content, 5));
    }

    #[test]
    fn test_extract_prefix_strips_leading_quote() {
        let line = "    \"flas";
        assert_eq!(extract_prefix(line, line.len() as u32), "flas");
    }

    /// No quote typed yet at all (zero real-quote count) must return the raw prefix
    /// unchanged, not empty — a still-reachable mid-edit state (e.g. a bare
    /// `requests` line under `[project.optional-dependencies]` before the user has
    /// typed the opening quote), and the pre-#734 no-op behavior on unquoted text.
    /// Regression guard: routing this case through
    /// `open_quoted_tail`'s `None` would wrongly collapse it to `""`, suppressing
    /// completion entirely.
    #[test]
    fn test_extract_prefix_no_quote_returns_unchanged() {
        let line = "    req";
        assert_eq!(extract_prefix(line, line.len() as u32), "req");
    }

    /// #734: the cursor sits right after an already-closed value (both quotes
    /// present) — reporting `"pytest"` here would fire a registry search and
    /// bare-insert the result right next to it, producing invalid TOML
    /// (`"pytest"pytest-cov`). Must fall back to an empty prefix instead.
    #[test]
    fn test_extract_prefix_closed_value_is_empty() {
        let line = "    \"pytest\"";
        assert_eq!(extract_prefix(line, line.len() as u32), "");
    }

    /// The escaped `\"` inside the value must not be counted as a real delimiter,
    /// otherwise this would misclassify a still-open value as closed.
    #[test]
    fn test_extract_prefix_skips_escaped_quote() {
        let line = "    \"py\\\"te";
        assert_eq!(extract_prefix(line, line.len() as u32), "py\\\"te");
    }

    #[test]
    fn test_is_in_dependencies_section_and_extract_prefix_optional_dependencies_group() {
        let content = "[project.optional-dependencies]\ndev = [\n    \"pytest\",\n    \"flas\n]\n";
        assert!(is_in_dependencies_section(content, 3));

        let line = content.lines().nth(3).unwrap();
        assert_eq!(extract_prefix(line, line.len() as u32), "flas");
    }

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

    #[test]
    fn test_completion_insert_text_quotes_the_name() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = PypiEcosystem::new(cache);
        let meta = MockMetadata {
            name: pkg("requests"),
            latest_version: "2.31.0".into(),
        };
        assert_eq!(
            ecosystem.completion_insert_text(&meta),
            Some("\"requests\"".to_string())
        );
    }

    /// A dotted PyPI name (`zope.interface`) has no TOML-key-injection meaning once
    /// the insert is a quoted array-element string, unlike Cargo's key=value shape.
    #[test]
    fn test_completion_insert_text_dotted_name_stays_quoted_string() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let ecosystem = PypiEcosystem::new(cache);
        let meta = MockMetadata {
            name: pkg("zope.interface"),
            latest_version: "6.1".into(),
        };
        assert_eq!(
            ecosystem.completion_insert_text(&meta),
            Some("\"zope.interface\"".to_string())
        );
    }

    /// #737: zero quotes typed at all (`req` alone on its own line under
    /// `dependencies = [...]`) must not be reported as bare — otherwise the fallback
    /// path bare-inserts the unquoted name straight into the TOML array.
    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_fallback_completion_is_bare_false_with_no_quote_typed() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = PypiEcosystem::new(cache);
        let content = "[project]\ndependencies = [\n    \"pytest\",\n    req\n]\n";
        let line = content.lines().nth(3).unwrap();
        let position = Position::new(3, line.chars().count() as u32);
        assert!(!eco.fallback_completion_is_bare(content, position.into()));
    }

    /// An already-open quote (`"req`, mid-typing) must still route to the bare insert
    /// — this is the pre-#737 behavior and must not regress.
    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_fallback_completion_is_bare_true_with_open_quote() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = PypiEcosystem::new(cache);
        let content = "[project]\ndependencies = [\n    \"req";
        let line = content.lines().nth(2).unwrap();
        let position = Position::new(2, line.chars().count() as u32);
        assert!(eco.fallback_completion_is_bare(content, position.into()));
    }

    /// Same two states as the primary PEP 621 `dependencies = [...]` array, exercised
    /// against `[project.optional-dependencies]` instead — coverage gap flagged in
    /// #737 validation: only the primary array branch was previously tested.
    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_fallback_completion_is_bare_false_with_no_quote_typed_optional_dependencies() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = PypiEcosystem::new(cache);
        let content = "[project.optional-dependencies]\ndev = [\n    \"pytest\",\n    req\n]\n";
        let line = content.lines().nth(3).unwrap();
        let position = Position::new(3, line.chars().count() as u32);
        assert!(!eco.fallback_completion_is_bare(content, position.into()));
    }

    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_fallback_completion_is_bare_true_with_open_quote_optional_dependencies() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = PypiEcosystem::new(cache);
        let content = "[project.optional-dependencies]\ndev = [\n    \"req";
        let line = content.lines().nth(2).unwrap();
        let position = Position::new(2, line.chars().count() as u32);
        assert!(eco.fallback_completion_is_bare(content, position.into()));
    }

    /// #737 critic S1: a `\"` preceded by an odd backslash run is an *escaped* quote,
    /// not a real one — `count_real_quotes`/`open_quoted_tail` correctly report zero
    /// real quotes here, so this must still route through `completion_insert_text`
    /// (quoted insert), not the bare path. A naive `.contains('"')` check would
    /// wrongly report `true` since the literal `"` character is present in the text.
    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_fallback_completion_is_bare_false_with_only_escaped_quote() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = PypiEcosystem::new(cache);
        let content = "[project]\ndependencies = [\n    \\\"req";
        let line = content.lines().nth(2).unwrap();
        let position = Position::new(2, line.chars().count() as u32);
        assert!(!eco.fallback_completion_is_bare(content, position.into()));
    }

    /// #737 validation gap: multiple entries on one line, cursor after a bare trailing
    /// candidate following an already-CLOSED quoted entry
    /// (`dependencies = ["pytest", req]`). A naive `.contains('"')` check on the raw
    /// line prefix would wrongly report `true` — the prior entry's quotes still appear
    /// in the prefix — routing to bare-insert and reproducing #737's exact corruption
    /// in a different manifest shape. `open_quoted_tail`'s escape-aware parity check
    /// correctly reports `false` (an even, non-zero quote count means no string is
    /// currently open).
    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_fallback_completion_is_bare_false_with_multiple_deps_same_line() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = PypiEcosystem::new(cache);
        let content = "[project]\ndependencies = [\"pytest\", req]\n";
        let cursor = "dependencies = [\"pytest\", req";
        let position = Position::new(1, cursor.chars().count() as u32);
        assert!(!eco.fallback_completion_is_bare(content, position.into()));
    }

    /// Same shape, with an escaped quote inside the prior closed entry — must not
    /// misclassify the escape as a still-open string either.
    #[cfg(feature = "lsp-responses")]
    #[test]
    fn test_fallback_completion_is_bare_false_with_escaped_quote_in_prior_closed_entry_same_line() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = PypiEcosystem::new(cache);
        let content = "[project]\ndependencies = [\"a\\\"b\", req]\n";
        let cursor = "dependencies = [\"a\\\"b\", req";
        let position = Position::new(1, cursor.chars().count() as u32);
        assert!(!eco.fallback_completion_is_bare(content, position.into()));
    }

    /// #737 critic S2: pins the trait default `fallback_bare_insert_text` (bare
    /// `metadata.name()`) as the correct behavior for PyPI's open-quote case — PyPI has
    /// no override, unlike Maven's `group:artifact` split, so this must not regress
    /// silently if a future change adds one. Mirrors npm/Composer's own
    /// `test_fallback_bare_insert_text_default_is_bare_name` (#729/#732).
    #[test]
    fn test_fallback_bare_insert_text_default_is_bare_name() {
        let cache = Arc::new(deps_core::HttpCache::new());
        let eco = PypiEcosystem::new(cache);
        let meta = MockMetadata {
            name: pkg("requests"),
            latest_version: "2.31.0".into(),
        };
        assert_eq!(
            eco.fallback_bare_insert_text(&meta),
            Some("requests".to_string())
        );
    }
}
