use std::any::Any;
use std::pin::Pin;
use std::sync::Arc;
use tower_lsp_server::ls_types::{
    CodeAction, CodeLens, Diagnostic, DocumentLink, Hover, InlayHint, Position, TextEdit, Uri,
};

use crate::{
    Registry,
    completion::Completions,
    lsp_helpers::{EcosystemFormatter, VersionData},
    registry::Metadata,
};

/// Soft-sealing mechanism for [`Ecosystem`], shared by every ecosystem crate in this
/// workspace (`deps-cargo`, `deps-npm`, ...) — each implements [`private::Sealed`] for
/// its own ecosystem type.
///
/// Rust's privacy system has no "visible to this workspace, not beyond" level: `pub(crate)`
/// would restrict `Sealed` to `deps-core` alone, breaking every sibling ecosystem crate's
/// `impl Sealed for ...`, since each of those is a separate compilation unit. Making this
/// module `pub` is therefore required, not a mistake — but it means [`private::Sealed`] is
/// technically nameable, and implementable, from any crate that depends on `deps-core`, not
/// only from within this workspace. `#[doc(hidden)]` keeps it out of generated public docs to
/// avoid inviting that. There is no compiler-enforced wall against it: this is a documented
/// contract enforced by code review, not a hard guarantee, and [`Ecosystem`]'s default
/// methods may gain new required behavior without that counting as a breaking change for an
/// external implementor who ignored this notice.
#[doc(hidden)]
pub mod private {
    /// Marker trait every ecosystem crate in this workspace implements for its own
    /// ecosystem type, per [`super::private`]'s module doc.
    ///
    /// [`Ecosystem`](super::Ecosystem) requires `Self: Sealed`, which is how the
    /// trait stays extensible (new default methods can be added without
    /// breaking in-workspace implementors).
    pub trait Sealed {}
}

/// A boxed, type-erased future used throughout the [`Ecosystem`] trait's async methods.
pub type BoxFuture<'a, T> = Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

/// Runs `ecosystem.parse_manifest(content, uri)` on the blocking-thread pool instead of the
/// calling tokio worker.
///
/// Every [`Ecosystem::parse_manifest`] implementation is synchronous work wrapped in an
/// immediately-ready `async move` block (verified: no implementation contains a real
/// `.await`). Driving that future to completion via [`tokio::runtime::Handle::block_on`]
/// from inside [`tokio::task::spawn_blocking`] moves the CPU-bound parse off the tokio
/// worker without changing the trait's async signature — mirrors
/// [`crate::lockfile::read_and_parse_lockfile`]'s `spawn_blocking` pattern for the
/// equivalent lock-file path (#723/#730). This closes #743: a large minified manifest
/// parsed synchronously on an LSP request's tokio worker would otherwise stall every other
/// request sharing that worker for the parse's full duration.
///
/// `content`/`uri` are cloned internally rather than moved+returned: the caller's own copy
/// must remain valid (to store into `DocumentState`) even if the blocking task panics, and a
/// panic here is already an anomalous condition, not a path worth optimizing a clone away
/// for. Manifest sizes are capped (10MB) and typically far smaller, so the clone's added
/// *time* cost is negligible next to the parse itself and the thread-pool hop. It does
/// briefly double transient *peak memory* (both the caller's and the cloned copy live at
/// once) on exactly the large-manifest path this function targets; a future `Arc<str>`
/// threaded through the caller would remove that duplication if it ever proves significant.
///
/// `Handle::block_on` called from inside a `spawn_blocking` closure is a documented,
/// supported tokio pattern (distinct from `Runtime::block_on`, which panics if called from
/// within a runtime). Since the future never actually yields (`Poll::Pending`), `block_on`
/// resolves on the first poll — negligible overhead beyond the `spawn_blocking` thread-hop
/// itself.
///
/// # Errors
///
/// Returns whatever [`Ecosystem::parse_manifest`] returns for a malformed manifest, or a
/// [`crate::error::DepsError::ParseError`] if the blocking task panics or is cancelled.
///
/// # Examples
///
/// ```no_run
/// use deps_core::Ecosystem;
/// use std::sync::Arc;
/// use tower_lsp_server::ls_types::Uri;
///
/// # async fn example(ecosystem: Arc<dyn Ecosystem>, uri: Uri) -> deps_core::error::Result<()> {
/// let parsed = deps_core::ecosystem::parse_manifest_blocking(&ecosystem, "content", &uri).await?;
/// println!("{} dependencies", parsed.dependencies().len());
/// # Ok(())
/// # }
/// ```
pub async fn parse_manifest_blocking(
    ecosystem: &Arc<dyn Ecosystem>,
    content: &str,
    uri: &Uri,
) -> crate::error::Result<Box<dyn ParseResult>> {
    let ecosystem = Arc::clone(ecosystem);
    let owned_content = content.to_owned();
    let owned_uri = uri.clone();
    let handle = tokio::runtime::Handle::current();
    tokio::task::spawn_blocking(move || {
        handle.block_on(ecosystem.parse_manifest(&owned_content, &owned_uri))
    })
    .await
    .map_err(|e| crate::error::DepsError::ParseError {
        file_type: format!("manifest at {uri:?}"),
        source: Box::new(std::io::Error::other(e)),
    })?
}

/// Defines [`EcosystemId`] together with [`EcosystemId::ALL`], [`EcosystemId::id`] and its
/// [`std::str::FromStr`] impl from one variant list, so the four can never drift apart
/// (#758) — a 15th ecosystem is added in exactly this one place or the workspace does not
/// compile. `macro_rules!` is textual-order scoped, so this definition must precede its
/// invocation below.
macro_rules! ecosystem_ids {
    ( $( $(#[$vmeta:meta])* $variant:ident => $id:literal ),+ $(,)? ) => {
        /// Canonical, exhaustive identifier for every package ecosystem the workspace supports.
        ///
        /// [`Ecosystem::id`] returns a `&'static str` for registry lookups and document
        /// storage, but any code that needs to *branch* on ecosystem identity should match on
        /// this enum instead of re-deriving its own partial match over that string: an
        /// unhandled variant here is a compile error, while an unhandled string is a silent
        /// runtime bug (see the fix for issue #118, where two call sites silently mishandled
        /// ecosystems missing from an incomplete string match).
        ///
        /// Deliberately **not** `#[non_exhaustive]`: adding a new ecosystem must force every
        /// exhaustive `match` on this type across the workspace to be updated at compile time.
        ///
        /// # Examples
        ///
        /// ```
        /// use deps_core::EcosystemId;
        ///
        /// let id: EcosystemId = "npm".parse().unwrap();
        /// assert_eq!(id, EcosystemId::Npm);
        /// assert_eq!(id.id(), "npm");
        /// assert_eq!(id.to_string(), "npm");
        ///
        /// assert!("unknown".parse::<EcosystemId>().is_err());
        /// ```
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum EcosystemId {
            $( $(#[$vmeta])* $variant, )+
        }

        impl EcosystemId {
            /// Every [`EcosystemId`] variant, in declaration order.
            ///
            /// Generated from the same list as [`Self::id`] and this type's
            /// [`std::str::FromStr`] impl, so none of the three can silently drift out of
            /// sync with the enum's variants (#758) — a forgotten 15th variant here is a
            /// missing-match compile error, not a silently incomplete set.
            pub const ALL: &'static [Self] = &[ $( Self::$variant ),+ ];

            /// Returns the canonical string identifier, matching [`Ecosystem::id`] for the
            /// corresponding ecosystem implementation.
            #[must_use]
            pub const fn id(self) -> &'static str {
                match self {
                    $( Self::$variant => $id, )+
                }
            }
        }

        impl std::str::FromStr for EcosystemId {
            type Err = crate::error::DepsError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                match s {
                    $( $id => Ok(Self::$variant), )+
                    _ => Err(crate::error::DepsError::UnsupportedEcosystem(s.to_string())),
                }
            }
        }
    };
}

ecosystem_ids! {
    /// Rust Cargo ecosystem (`Cargo.toml`).
    Cargo => "cargo",
    /// JavaScript/TypeScript npm ecosystem (`package.json`).
    Npm => "npm",
    /// Python PyPI ecosystem (`pyproject.toml`).
    Pypi => "pypi",
    /// Go modules ecosystem (`go.mod`).
    Go => "go",
    /// Ruby Bundler ecosystem (`Gemfile`).
    Bundler => "bundler",
    /// Dart/Flutter pub ecosystem (`pubspec.yaml`).
    Dart => "dart",
    /// Java/Kotlin Maven ecosystem (`pom.xml`).
    Maven => "maven",
    /// PHP Composer ecosystem (`composer.json`).
    Composer => "composer",
    /// Java/Kotlin Gradle ecosystem (`build.gradle`, `build.gradle.kts`, version catalogs).
    Gradle => "gradle",
    /// Swift Package Manager ecosystem (`Package.swift`).
    Swift => "swift",
    /// .NET NuGet ecosystem (`.csproj`/`.fsproj`/`.vbproj`, `Directory.Packages.props`, `packages.config`).
    NuGet => "nuget",
    /// Deno ecosystem (`deno.json`/`deno.jsonc`), mixing `jsr:` and `npm:` specifiers.
    Deno => "deno",
    /// GitHub Actions ecosystem (`.github/workflows/*.yml`/`*.yaml`).
    GithubActions => "github-actions",
    /// GitLab CI/CD ecosystem (`.gitlab-ci.yml`, `.gitlab/ci/*.yml`/`*.yaml`).
    GitlabCi => "gitlab-ci",
}

impl EcosystemId {
    /// OSV.dev `package.ecosystem` value for this ecosystem, or `None` if
    /// OSV has no equivalent.
    ///
    /// An exhaustive `match` rather than a lookup table: adding a 12th
    /// ecosystem becomes a compile error here instead of a silent
    /// zero-results ecosystem in OSV queries. Every arm below was verified
    /// live against `https://api.osv.dev` (each returned real advisories for
    /// a known-vulnerable version) — see `architecture.md` §2.
    ///
    /// Hand-written rather than generated by the `ecosystem_ids!` macro: this mapping is not 1:1
    /// (`Npm | Deno` both map to `"npm"`, `Maven | Gradle` both map to `"Maven"`, `GitlabCi`
    /// maps to `None`), so folding it into the shared list would need per-arm escape
    /// hatches that cost more than they save — and match exhaustiveness already forces
    /// this `match` to be updated for a new variant, which is the property that matters.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::EcosystemId;
    ///
    /// assert_eq!(EcosystemId::Cargo.osv_ecosystem(), Some("crates.io"));
    /// assert_eq!(EcosystemId::Gradle.osv_ecosystem(), Some("Maven"));
    /// ```
    #[must_use]
    pub const fn osv_ecosystem(self) -> Option<&'static str> {
        match self {
            Self::Cargo => Some("crates.io"),
            Self::Npm | Self::Deno => Some("npm"),
            Self::Pypi => Some("PyPI"),
            Self::Go => Some("Go"),
            Self::Bundler => Some("RubyGems"),
            Self::Dart => Some("Pub"),
            Self::Maven | Self::Gradle => Some("Maven"),
            Self::Composer => Some("Packagist"),
            Self::Swift => Some("SwiftURL"),
            Self::NuGet => Some("NuGet"),
            Self::GithubActions => Some("GitHub Actions"),
            // A git-tag/release pin has no OSV coordinate by name (mirrors
            // `deps_gitlab_ci::formatter::GitlabCiFormatter`'s `OsvNaming` docs).
            Self::GitlabCi => None,
        }
    }
}

impl std::fmt::Display for EcosystemId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.id())
    }
}

/// Parse result trait containing dependencies and metadata.
///
/// Implementations hold ecosystem-specific dependency types
/// but expose them through trait object interfaces.
pub trait ParseResult: Send + Sync {
    /// All dependencies found in the manifest
    fn dependencies(&self) -> Vec<&dyn Dependency>;

    /// Workspace root path (for monorepo support)
    fn workspace_root(&self) -> Option<&std::path::Path>;

    /// Document URI
    fn uri(&self) -> &Uri;

    /// Dependency lines whose registry-index resolution was blocked by a workspace-registry
    /// reachability policy (spec `.local/specs/023-cargo-custom-registries/plan-1b.md` §1.7,
    /// #443) — `(name_range, blocked host class, raw declared value)` triples, where the raw
    /// value is the exact `registry`/`registry-index` alias or URL the dependency declared
    /// (so two different blocked aliases render as two distinguishable messages, not one
    /// byte-identical warning). Used by
    /// [`crate::lsp_helpers::generate_diagnostics_from_cache`] to surface an
    /// [`tower_lsp_server::ls_types::DiagnosticSeverity::INFORMATION`] diagnostic on the
    /// blocked dependency's line so the block never degrades silently.
    ///
    /// Default empty — only `deps_cargo::parser::ParseResult` overrides this today;
    /// every other ecosystem has no equivalent reachability policy to report.
    fn blocked_registries(
        &self,
    ) -> Vec<(
        tower_lsp_server::ls_types::Range,
        crate::net_policy::HostClass,
        String,
    )> {
        Vec::new()
    }

    /// Downcast to concrete type for ecosystem-specific operations
    fn as_any(&self) -> &dyn Any;
}

/// Generic dependency trait.
///
/// All parsed dependencies must implement this for generic handler access.
pub trait Dependency: Send + Sync {
    /// Package name
    fn name(&self) -> &crate::PackageName;

    /// LSP range of the dependency name
    fn name_range(&self) -> tower_lsp_server::ls_types::Range;

    /// Version requirement string (e.g., "^1.0", ">=2.0")
    fn version_requirement(&self) -> Option<&crate::VersionReq>;

    /// LSP range of the version string
    fn version_range(&self) -> Option<tower_lsp_server::ls_types::Range>;

    /// Dependency source (registry, git, path)
    fn source(&self) -> crate::parser::DependencySource;

    /// Feature flags (ecosystem-specific, empty if not supported)
    fn features(&self) -> &[String] {
        &[]
    }

    /// LSP range of the features array (ecosystem-specific, None if not supported)
    fn features_range(&self) -> Option<tower_lsp_server::ls_types::Range> {
        None
    }

    /// Environment marker expression gating this dependency (e.g. PEP 508's
    /// `python_version >= '3.8'`). Ecosystem-specific, `None` if not supported
    /// or not present on this dependency.
    fn markers(&self) -> Option<&str> {
        None
    }

    /// LSP range of the environment marker expression (ecosystem-specific,
    /// `None` if not supported or not present).
    fn markers_range(&self) -> Option<tower_lsp_server::ls_types::Range> {
        None
    }

    /// The raw manifest text spanned by [`version_range`](Dependency::version_range),
    /// when it differs from [`version_requirement`](Dependency::version_requirement).
    ///
    /// Most ecosystems' `version_requirement()` is (up to whitespace) exactly the text at
    /// `version_range()`, so the default `None` — telling callers to fall back to
    /// `version_requirement()` — is correct for them. An ecosystem whose parser synthesizes
    /// a comparator string from a bare literal (e.g. `deps-swift`'s `.exact("4.50.0")`
    /// becoming requirement `"=4.50.0"` while `version_range()` still spans only `4.50.0`)
    /// overrides this to return that literal, so `lsp_helpers`' literal-span guard
    /// (`literal_span_matches`, used by both `generate_code_actions` and
    /// `collect_update_all_edits`) compares `version_range`'s slice against the text it was
    /// actually derived from instead of the synthesized comparator, which would otherwise
    /// never match and silently suppress every fix action for that dependency.
    ///
    /// A sibling mechanism already exists for the same underlying problem: `deps-nuget`
    /// wraps a bare source version as requirement `[1.0.0]`, and `literal_span_matches`
    /// special-cases that bracket wrapping inline rather than going through this hook. This
    /// method exists for the general case — an ecosystem whose synthesized requirement is
    /// not a simple wrap (`deps-swift`'s comparator range is not recoverable from
    /// `version_requirement()` by stripping fixed characters) needs its own literal, not a
    /// transform `literal_span_matches` could hard-code.
    ///
    /// **Must not** be set when `version_range()` spans only part of a multi-literal
    /// requirement whose other part(s) are not being rewritten — e.g. a `"lower"..<"upper"`
    /// range, where `version_range()` covers only `lower`. Reporting `lower` as the literal
    /// would let the guard pass and an edit rewrite `lower` alone, corrupting the
    /// requirement (`deps-swift` leaves this `None` for both its range-literal forms for
    /// exactly this reason — see `crates/deps-swift/src/parser.rs`'s range-form comments).
    fn version_literal(&self) -> Option<&str> {
        None
    }

    /// Downcast to concrete type
    fn as_any(&self) -> &dyn Any;
}

/// Configuration for LSP inlay hints feature.
#[derive(Debug, Clone)]
pub struct EcosystemConfig {
    /// Whether to show inlay hints for up-to-date dependencies
    pub show_up_to_date_hints: bool,
    /// Text to display for up-to-date dependencies
    pub up_to_date_text: String,
    /// Text to display for dependencies needing updates (use {} for version placeholder)
    pub needs_update_text: String,
    /// Text to display while loading registry data
    pub loading_text: String,
    /// Whether to show loading hints in inlay hints
    pub show_loading_hints: bool,
    /// Whether `network.offline` is set (issue #483): when `true` and no cached latest
    /// version exists for a dependency, [`crate::lsp_helpers::generate_inlay_hints`]
    /// shows an offline marker instead of silently falling back to the resolved-version
    /// display, which would otherwise look identical to a normal pre-fetch state.
    pub offline: bool,
}

impl Default for EcosystemConfig {
    fn default() -> Self {
        Self {
            show_up_to_date_hints: true,
            up_to_date_text: "✅".to_string(),
            needs_update_text: "❌ {}".to_string(),
            loading_text: "⏳".to_string(),
            show_loading_hints: true,
            offline: false,
        }
    }
}

/// How this ecosystem's license strings are sourced.
///
/// Drives three ecosystem-specific license behaviors that used to be re-derived
/// independently at each consumer via a non-exhaustive `matches!`/`==` on
/// [`EcosystemId`] instead of the sealed [`Ecosystem`] trait every other per-ecosystem
/// capability goes through (issue #688): hover's "(detected)" qualifier, which only
/// applies to [`Self::DetectedSpdx`]; whether
/// [`crate::licenses::resolve_license_entries`] must normalize free text to SPDX
/// identifiers before hover displays it or a [`crate::licenses::LicensePolicy`]
/// evaluates it, which only applies to [`Self::PomFreeText`]; and, via
/// [`Self::requires_dedicated_fetch`] (issue #697), whether
/// [`Ecosystem::fetch_license`] is a dedicated async fetch or a no-op because the
/// license already arrived in the hot-path registry response.
///
/// # Examples
///
/// ```
/// use deps_core::LicenseSource;
///
/// assert_eq!(LicenseSource::default(), LicenseSource::RegistryDeclaredSpdx);
/// assert_ne!(LicenseSource::PomFreeText, LicenseSource::DetectedSpdx);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LicenseSource {
    /// Author-declared SPDX identifier(s) already present in the hot-path registry
    /// response — the default for every ecosystem that doesn't override
    /// [`Ecosystem::license_source`], and the only variant for which
    /// [`Self::requires_dedicated_fetch`] is `false`.
    #[default]
    RegistryDeclaredSpdx,
    /// Author-declared SPDX identifier(s) that require a dedicated fetch separate
    /// from the hot-path registry response: JSR's package-metadata endpoint (Deno).
    FetchedDeclaredSpdx,
    /// A detector's best-effort guess, not an author declaration, that requires a
    /// dedicated fetch: pub.dev's `/score` endpoint (Dart) and GitHub's
    /// `license.spdx_id` (Swift) are both driven by a license-detection heuristic run
    /// against repository content, rather than metadata the package author explicitly
    /// declared to a registry.
    DetectedSpdx,
    /// Maven POM `<licenses><license><name>` free text (Gradle), fetched via a
    /// dedicated request — never an SPDX identifier, so it must be normalized via
    /// [`crate::licenses::resolve_license_entries`] before display or policy evaluation.
    PomFreeText,
}

impl LicenseSource {
    /// Whether this source requires [`Ecosystem::fetch_license`]'s dedicated async
    /// fetch, as opposed to arriving for free in the hot-path registry response.
    ///
    /// This is the single answer to "is this a tier-3 license ecosystem" (issue #697):
    /// capability and shape can no longer disagree, because both come from the same
    /// [`Ecosystem::license_source`] call.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::LicenseSource;
    ///
    /// assert!(!LicenseSource::RegistryDeclaredSpdx.requires_dedicated_fetch());
    /// assert!(LicenseSource::FetchedDeclaredSpdx.requires_dedicated_fetch());
    /// assert!(LicenseSource::DetectedSpdx.requires_dedicated_fetch());
    /// assert!(LicenseSource::PomFreeText.requires_dedicated_fetch());
    /// ```
    #[must_use]
    pub const fn requires_dedicated_fetch(self) -> bool {
        match self {
            Self::RegistryDeclaredSpdx => false,
            Self::FetchedDeclaredSpdx | Self::DetectedSpdx | Self::PomFreeText => true,
        }
    }
}

/// Main trait that all ecosystem implementations must implement.
///
/// Each ecosystem (Cargo, npm, PyPI, etc.) provides its own implementation.
/// This trait defines the contract for parsing manifests, fetching registry data,
/// and generating LSP responses.
///
/// # Type Erasure
///
/// This trait uses `Box<dyn Trait>` instead of associated types to allow
/// runtime polymorphism and dynamic ecosystem registration.
///
/// # Sealing
///
/// This trait requires `Self: private::Sealed`, making it sealed in the sense described
/// on that module's doc: a documented contract enforced by code review, not a
/// compiler-enforced wall. Every sibling ecosystem crate in this workspace (`deps-cargo`,
/// `deps-npm`, ...) implements [`private::Sealed`] for its own ecosystem type, which requires
/// `private` to be `pub`; Rust has no visibility level that admits sibling crates while
/// excluding a truly external one, so this guarantee cannot be enforced any harder than that
/// without inverting the crate's whole multi-crate extension-point architecture. See
/// [`private::Sealed`]'s own doc for the full reasoning, and the `impl private::Sealed`
/// line in the example below for what implementing it in practice looks like.
///
/// # Examples
///
/// ```no_run
/// use deps_core::{Ecosystem, ParseResult, Registry, EcosystemConfig, PackageName, ConcreteVersion, Metadata};
/// use deps_core::completion::Completions;
/// use deps_core::lsp_helpers::{
///     DiagnosticMessages, DiagnosticPolicy, EcosystemFormatter, OsvNaming, PackageNaming,
///     PackageRendering, RequirementResolution, SourcePolicy,
/// };
/// use std::sync::Arc;
/// use std::any::Any;
/// use tower_lsp_server::ls_types::{Uri, CompletionItem, Position};
///
/// struct MyFormatter;
/// impl PackageNaming for MyFormatter {}
/// impl PackageRendering for MyFormatter {
///     fn format_version_for_text_edit(&self, version: &ConcreteVersion) -> String { version.to_string() }
///     fn package_url(&self, name: &PackageName) -> String { format!("https://example.com/{name}") }
/// }
/// impl RequirementResolution for MyFormatter {}
/// impl DiagnosticMessages for MyFormatter {}
/// impl DiagnosticPolicy for MyFormatter {}
/// impl SourcePolicy for MyFormatter {}
/// impl OsvNaming for MyFormatter {}
///
/// struct MyEcosystem {
///     registry: Arc<dyn Registry>,
///     formatter: MyFormatter,
/// }
///
/// // Real in-workspace ecosystem crates implement `Sealed` exactly like this. This line
/// // compiling here, out-of-crate, is not a bug: as the `# Sealing` section above explains,
/// // `private::Sealed` is a documented contract, not a compiler-enforced wall — Rust has no
/// // visibility level that admits sibling workspace crates while excluding a truly external
/// // one, so any crate that names this path can technically do the same.
/// impl deps_core::ecosystem::private::Sealed for MyEcosystem {}
///
/// impl Ecosystem for MyEcosystem {
///     fn id(&self) -> &'static str { "my-ecosystem" }
///     fn display_name(&self) -> &'static str { "My Ecosystem" }
///     fn manifest_filenames(&self) -> &[&'static str] { &["my-manifest.toml"] }
///
///     fn parse_manifest<'a>(
///         &'a self,
///         _content: &'a str,
///         _uri: &'a Uri,
///     ) -> deps_core::ecosystem::BoxFuture<'a, deps_core::error::Result<Box<dyn ParseResult>>> {
///         Box::pin(async move { todo!() })
///     }
///
///     fn registry(&self) -> Arc<dyn Registry> { self.registry.clone() }
///
///     fn formatter(&self) -> &dyn EcosystemFormatter { &self.formatter }
///
///     fn generate_completions<'a>(
///         &'a self,
///         _parse_result: &'a dyn ParseResult,
///         _position: Position,
///         _content: &'a str,
///         _freshness: deps_core::FreshnessSettings,
///     ) -> deps_core::ecosystem::BoxFuture<'a, Completions> {
///         Box::pin(async move { Completions::default() })
///     }
///
///     fn completion_insert_text(&self, metadata: &dyn Metadata) -> Option<String> {
///         Some(format!("\"{}\" = \"{}\"", metadata.name(), metadata.latest_version()))
///     }
///
///     fn as_any(&self) -> &dyn Any { self }
/// }
/// ```
pub trait Ecosystem: Send + Sync + private::Sealed {
    /// Unique identifier (e.g., "cargo", "npm", "pypi")
    ///
    /// This identifier is used for ecosystem registration and routing.
    fn id(&self) -> &'static str;

    /// Human-readable name (e.g., "Cargo (Rust)", "npm (JavaScript)")
    ///
    /// This name is displayed in diagnostic messages and logs.
    fn display_name(&self) -> &'static str;

    /// Manifest filenames this ecosystem handles (e.g., ["Cargo.toml"])
    ///
    /// The ecosystem registry uses these filenames to route file URIs
    /// to the appropriate ecosystem implementation.
    fn manifest_filenames(&self) -> &[&'static str];

    /// File extensions this ecosystem handles when the manifest basename is
    /// not fixed (e.g. `[".csproj", ".fsproj"]` for NuGet project files).
    ///
    /// Consulted by [`crate::EcosystemRegistry::get_for_filename`] only after
    /// an exact [`manifest_filenames`](Ecosystem::manifest_filenames) match
    /// fails. Empty by default, indicating this ecosystem is routed solely by
    /// exact filename.
    fn manifest_extensions(&self) -> &[&'static str] {
        &[]
    }

    /// Basename glob patterns this ecosystem handles, each containing exactly
    /// one `*` wildcard (e.g. `["requirements*.txt"]`).
    ///
    /// Consulted by [`crate::EcosystemRegistry::get_for_filename`] as a third
    /// routing stage, tried after an exact
    /// [`manifest_filenames`](Ecosystem::manifest_filenames) match fails and
    /// before [`manifest_extensions`](Ecosystem::manifest_extensions) — for
    /// basenames that are neither fixed nor identified by extension alone
    /// (e.g. `requirements.txt`, `requirements-dev.txt`). Empty by default.
    /// Matching is case-sensitive, unlike the extension stage: these patterns
    /// target canonically-lowercase filenames (pip, Renovate and Dependabot
    /// all treat `requirements.txt` as lowercase), whereas the extension
    /// stage exists specifically for Windows/MSBuild project files whose
    /// case genuinely varies.
    fn manifest_patterns(&self) -> &[&'static str] {
        &[]
    }

    /// `(directory_path, file_suffix)` pairs identifying a file solely by its
    /// containing directory path and suffix. `directory_path` may be a single
    /// segment (e.g. `[("requirements", ".txt")]` for Python's
    /// `requirements/base.txt` split-file layout) or multiple `/`-joined
    /// segments (e.g. `[(".github/workflows", ".yml")]` for GitHub Actions
    /// workflow files) — either way it is matched against the *tail* of the
    /// file's directory path on segment boundaries, not just the immediate
    /// parent, so a multi-segment pattern matches regardless of how many
    /// ancestor directories precede it. Used when the basename alone carries
    /// no ecosystem signal.
    ///
    /// Consulted by [`crate::EcosystemRegistry::get_for_uri`] only, after both
    /// [`manifest_patterns`](Ecosystem::manifest_patterns) and
    /// [`manifest_extensions`](Ecosystem::manifest_extensions) miss on the
    /// basename — it needs the full path, so it is never reachable from
    /// [`crate::EcosystemRegistry::get_for_filename`]. Empty by default.
    fn manifest_directory_patterns(&self) -> &[(&'static str, &'static str)] {
        &[]
    }

    /// Lock file filenames this ecosystem uses (e.g., ["Cargo.lock"])
    ///
    /// Used for file watching - LSP will monitor changes to these files
    /// and refresh UI when they change. Returns empty slice if ecosystem
    /// doesn't use lock files.
    ///
    /// # Default Implementation
    ///
    /// Returns empty slice by default, indicating no lock files are used.
    fn lockfile_filenames(&self) -> &[&'static str] {
        &[]
    }

    /// Non-lockfile config filenames this ecosystem resolves *during* [`Self::parse_manifest`]
    /// (e.g. `["pnpm-workspace.yaml", ".npmrc"]` for npm's catalog and registry resolution),
    /// whose values end up baked into a manifest's `ParseResult` rather than looked up
    /// separately the way a [`Self::lockfile_provider`] is.
    ///
    /// Used for file watching alongside [`Self::lockfile_filenames`] — LSP monitors changes
    /// to these files too, but reacts by fully re-parsing every open document of this
    /// ecosystem (not merely refreshing cached resolved versions, since the value isn't kept
    /// separately from the parse result to refresh in place). Returns empty slice by default.
    fn watched_config_filenames(&self) -> &[&'static str] {
        &[]
    }

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
    /// `async move` block. [`parse_manifest_blocking`] relies on this to drive the future via
    /// `Handle::block_on` on the blocking-thread pool; violating it doesn't deadlock, but
    /// silently reintroduces the exact worker-thread stall #743 fixed.
    fn parse_manifest<'a>(
        &'a self,
        content: &'a str,
        uri: &'a Uri,
    ) -> BoxFuture<'a, crate::error::Result<Box<dyn ParseResult>>>;

    /// Get the registry client for this ecosystem
    ///
    /// The registry provides version lookup and package search capabilities.
    fn registry(&self) -> Arc<dyn Registry>;

    /// Get the lock file provider for this ecosystem.
    ///
    /// Returns `None` if the ecosystem doesn't support lock files.
    /// Lock files provide resolved dependency versions without network requests.
    fn lockfile_provider(&self) -> Option<Arc<dyn crate::lockfile::LockFileProvider>> {
        None
    }

    /// Get the ecosystem-specific formatter for LSP response generation.
    ///
    /// The formatter handles version comparison, package URLs, and text formatting.
    /// Override this to customize LSP response generation.
    fn formatter(&self) -> &dyn EcosystemFormatter;

    /// Generate inlay hints for the document.
    ///
    /// Default implementation delegates to `lsp_helpers::generate_inlay_hints`
    /// using `self.formatter()`. Override only if custom behavior is needed.
    fn generate_inlay_hints<'a>(
        &'a self,
        parse_result: &'a dyn ParseResult,
        versions: VersionData<'a>,
        loading_state: crate::LoadingState,
        config: &'a EcosystemConfig,
    ) -> BoxFuture<'a, Vec<InlayHint>> {
        Box::pin(async move {
            crate::lsp_helpers::generate_inlay_hints(
                parse_result,
                versions,
                loading_state,
                config,
                self.formatter(),
            )
        })
    }

    /// Generate hover information for a position.
    ///
    /// Default implementation delegates to `lsp_helpers::generate_hover`
    /// using `self.formatter()` and `self.registry()`. `versions.license_source` is
    /// attached by the caller (`deps-lsp::handlers::hover`), not here — the single
    /// `VersionData` construction site every path funnels through, override or not
    /// (issue #688 critic M1: attaching it in this default only would silently drop it
    /// for the ecosystems that override `generate_hover` instead of using this default).
    fn generate_hover<'a>(
        &'a self,
        parse_result: &'a dyn ParseResult,
        position: Position,
        versions: VersionData<'a>,
        freshness: crate::freshness::FreshnessSettings,
    ) -> BoxFuture<'a, Option<Hover>> {
        Box::pin(async move {
            let registry = self.registry();
            crate::lsp_helpers::generate_hover(
                parse_result,
                position,
                versions,
                registry.as_ref(),
                self.formatter(),
                freshness,
                crate::freshness::PublishTime::now(),
            )
            .await
        })
    }

    /// Generate code actions for a position.
    ///
    /// Default implementation delegates to `lsp_helpers::generate_code_actions`
    /// using `self.formatter()` and `self.registry()`. `versions` carries the
    /// same OSV scan results `generate_hover` and `generate_diagnostics` use,
    /// so a vulnerable dependency at `position` gets a "fix vulnerability"
    /// quickfix alongside the plain version-update actions. `content` is the
    /// manifest source, needed to guard against rewriting a `version_range`
    /// that no longer slices to its declared requirement text (see
    /// `lsp_helpers::literal_span_matches`).
    fn generate_code_actions<'a>(
        &'a self,
        parse_result: &'a dyn ParseResult,
        position: Position,
        uri: &'a Uri,
        versions: VersionData<'a>,
        content: &'a str,
    ) -> BoxFuture<'a, Vec<CodeAction>> {
        Box::pin(async move {
            let registry = self.registry();
            crate::lsp_helpers::generate_code_actions(
                parse_result,
                position,
                uri,
                versions,
                content,
                registry.as_ref(),
                self.formatter(),
            )
            .await
        })
    }

    /// Generate diagnostics for the document.
    ///
    /// Default implementation delegates to `lsp_helpers::generate_diagnostics_from_cache`
    /// using `self.formatter()`. `versions.license_source` is attached by the caller
    /// (`deps-lsp::handlers::diagnostics`), not here — see [`Self::generate_hover`]'s doc
    /// for why (issue #688 critic M1).
    fn generate_diagnostics<'a>(
        &'a self,
        parse_result: &'a dyn ParseResult,
        versions: VersionData<'a>,
        uri: &'a Uri,
        freshness: crate::freshness::FreshnessSettings,
        severities: crate::lsp_helpers::DiagnosticSeverities,
    ) -> BoxFuture<'a, Vec<Diagnostic>> {
        Box::pin(async move {
            crate::lsp_helpers::generate_diagnostics_from_cache(
                parse_result,
                versions,
                self.formatter(),
                uri,
                freshness,
                severities,
                crate::freshness::PublishTime::now(),
            )
        })
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
    fn generate_document_links(
        &self,
        _parse_result: &dyn ParseResult,
        _uri: &Uri,
    ) -> Vec<DocumentLink> {
        Vec::new()
    }

    /// Generate the "Update N outdated dependencies" code lens for the document.
    ///
    /// `severities` is unused by the default implementation (the shared "update all
    /// outdated" lens has no enable/disable toggle of its own — that's `code_lens.enabled`
    /// in `deps-lsp`'s config, gating the whole handler before this method is ever
    /// called) but is threaded through so an override can gate an *additional*,
    /// ecosystem-specific lens on a `DiagnosticSeverities` flag the way
    /// `generate_diagnostics`'s `severities` parameter already does — see
    /// `deps_github_actions::GithubActionsEcosystem`'s override, which gates its bulk
    /// "Pin N actions to commit SHA" lens on `severities.mutable_ref_pin_enabled` so
    /// disabling that flag suppresses the lens the same way it suppresses the
    /// diagnostic (issue #633).
    ///
    /// Default implementation delegates to `lsp_helpers::generate_code_lenses` using
    /// `self.formatter()`. Override only if custom behavior is needed.
    fn generate_code_lenses<'a>(
        &'a self,
        parse_result: &'a dyn ParseResult,
        content: &'a str,
        versions: VersionData<'a>,
        uri: &'a Uri,
        command_id: &'a str,
        _severities: crate::lsp_helpers::DiagnosticSeverities,
    ) -> BoxFuture<'a, Vec<CodeLens>> {
        Box::pin(async move {
            crate::lsp_helpers::generate_code_lenses(
                parse_result,
                content,
                versions,
                self.formatter(),
                uri,
                command_id,
            )
        })
    }

    /// Generate completions for a position.
    ///
    /// Provides autocomplete suggestions for package names and versions.
    ///
    /// `freshness.enabled` gates whether version completion items carry a
    /// relative-age `label_details` suffix (issue #145); implementations that
    /// delegate to [`crate::completion::complete_versions_generic`] get this for
    /// free by threading `freshness` through.
    ///
    /// The returned [`Completions::is_incomplete`] must reflect *this specific call*
    /// (the completion context actually served), not a static worst case for the
    /// ecosystem as a whole (#427): a package-name search over an unranked,
    /// truncated index should report `true`, while a version completion or any
    /// other exhaustive context in the same manifest must report `false`, even for
    /// an ecosystem where some contexts are incomplete and others are not.
    fn generate_completions<'a>(
        &'a self,
        parse_result: &'a dyn ParseResult,
        position: Position,
        content: &'a str,
        freshness: crate::FreshnessSettings,
    ) -> BoxFuture<'a, Completions>;

    /// Raw-text search prefix at `position` for `deps-lsp`'s fallback (parse-failure)
    /// completion path, used when the manifest failed to parse (typically mid-edit) so
    /// [`Self::generate_completions`]'s parsed-AST path has no [`ParseResult`] to work
    /// from.
    ///
    /// `content` is the whole manifest text; the implementation locates the line at
    /// `position`, decides whether that line falls inside a dependencies-like section
    /// using its own raw-text heuristic (see `deps_core::fallback_completion` for the
    /// scanners shared across ecosystems, e.g. [`crate::fallback_completion::
    /// is_in_toml_dependencies`]), and — only when it does — extracts the text the user
    /// has typed up to the cursor, stripping any manifest-syntax wrapper (a JSON
    /// string's quotes, an XML tag or attribute value) so the returned prefix is a bare
    /// candidate package-name fragment. `None` means either the cursor is not at a
    /// completable position at all, or this ecosystem's manifest format has no raw-text
    /// section boundary cheap enough to detect this way (e.g. Gradle's five manifest
    /// formats, or Swift's/Bundler's whole-file-scoped dependency calls).
    ///
    /// The caller applies its own ecosystem-agnostic guards to the returned prefix
    /// (length 2-200 chars, no `=` character) before searching the registry — this method
    /// only answers "is there a prefix here, and what manifest-syntax wrapper does it
    /// need stripped", not "is this prefix worth searching for".
    ///
    /// Default `None`: correct for every ecosystem with no raw-text section boundary.
    /// Unlike [`Self::completion_insert_text`], deliberately *not* required — a missing
    /// override only disables fallback completion for a 15th ecosystem (a feature gap),
    /// never silently emits wrong manifest syntax the way an unhandled
    /// [`Self::completion_insert_text`] arm could (see issue #118's failure mode).
    fn fallback_completion_prefix<'a>(
        &self,
        _content: &'a str,
        _position: Position,
    ) -> Option<&'a str> {
        None
    }

    /// Manifest-syntax snippet to insert for a completed package, given its registry
    /// search `metadata` — the ecosystem-specific counterpart to
    /// [`Self::fallback_completion_prefix`]. Called only from `deps-lsp`'s raw-text
    /// fallback (parse-failure) completion path; the primary (parsed) completion path
    /// builds its own insert text via `deps_core::completion::build_package_completion`
    /// / `complete_package_names_generic` and never calls this method.
    ///
    /// Takes `&dyn Metadata` rather than separate `name`/`latest_version` parameters:
    /// an ecosystem's snippet may need more than those two fields (Swift's needs
    /// [`Metadata::repository`] to build a `.package(url:, from:)` call). Returns `None`
    /// to reject the completion entirely — e.g. a per-ecosystem gate on a structural
    /// character that would otherwise let a malicious/compromised registry response
    /// break out of the inserted snippet's syntax (Maven's coordinate-segment gate,
    /// Swift's registry-URL gate, GitHub Actions' `owner/repo` shape check). The caller
    /// (`deps-lsp`) does not log a rejection itself — an implementation that rejects a
    /// value is expected to log it via [`crate::lsp_helpers::warn_rejected_value`]
    /// first, the way Maven/Swift/GitHub Actions do inside their own overrides.
    ///
    /// Deliberately **required**, no default: a missing override here would silently
    /// insert wrong manifest syntax for whatever ecosystem forgot to implement it
    /// (exactly the failure mode issue #118 fixed for ecosystem-identity matching in
    /// general — this is the same principle applied to completion-insert syntax).
    ///
    /// The two upfront, ecosystem-agnostic gates — [`crate::lsp_helpers::
    /// is_safe_package_name`] on `metadata.name()` and [`crate::lsp_helpers::
    /// is_safe_version_string`] on `metadata.latest_version()` (whenever non-empty) —
    /// run in the caller before this method is invoked, not inside it: every ecosystem
    /// interpolates those two fields, so checking them once in `deps-lsp` avoids
    /// re-deriving the same two allowlist checks in every implementation.
    fn completion_insert_text(&self, metadata: &dyn Metadata) -> Option<String>;

    /// Whether the prefix [`Self::fallback_completion_prefix`] just returned for this
    /// `content`/`position` sits inside manifest markup that can only safely hold the
    /// bare candidate text — an already-open XML tag/attribute value, JSON object key,
    /// or TOML quoted string — rather than [`Self::completion_insert_text`]'s normal
    /// full snippet.
    ///
    /// Inserting the full snippet where markup is already open would nest a duplicate
    /// copy of it (issue #724, the original NuGet report: `Include="Newt` accepting a
    /// completion produced `Include="Newt<PackageReference Include="..." .../>`).
    /// `deps-lsp`'s fallback-completion caller checks this once per call, alongside
    /// [`Self::fallback_completion_prefix`], and routes to
    /// [`Self::fallback_bare_insert_text`] instead of [`Self::completion_insert_text`]
    /// when it returns `true`.
    ///
    /// Default `false`: correct for every ecosystem whose manifest syntax has no
    /// concept of "already open" markup around a fallback-completion cursor. Overridden
    /// today by Maven/NuGet (XML tag/attribute), npm/Composer (JSON object key), and
    /// PyPI (TOML quoted string). Not required, like [`Self::fallback_completion_prefix`]:
    /// a missing override only means a future markup-shaped ecosystem always gets the
    /// full-snippet insert, a feature gap rather than #118's "silently wrong syntax"
    /// failure mode.
    fn fallback_completion_is_bare(&self, _content: &str, _position: Position) -> bool {
        false
    }

    /// Bare candidate-name text to insert when [`Self::fallback_completion_is_bare`]
    /// reports the cursor already sits inside open markup — the counterpart to
    /// [`Self::completion_insert_text`] for that case. Only called when
    /// [`Self::fallback_completion_is_bare`] returned `true` for the same
    /// `content`/`position`.
    ///
    /// Returns `None` to reject the completion entirely, the same rejection semantics
    /// as [`Self::completion_insert_text`] — e.g. Maven's `artifactId` half still needs
    /// its own [`crate::is_safe_maven_coordinate_segment`] gate here, since the two
    /// upfront ecosystem-agnostic gates the caller runs beforehand
    /// ([`crate::lsp_helpers::is_safe_package_name`] on `metadata.name()` and
    /// [`crate::lsp_helpers::is_safe_version_string`] on `metadata.latest_version()`)
    /// validate the *whole* `name`, not a substring split out of it.
    ///
    /// Default: `metadata.name()` verbatim — correct for NuGet (and any future
    /// attribute-valued ecosystem whose full snippet's name field is the bare name
    /// unmodified), since `metadata.name()` already passed the caller's
    /// `is_safe_package_name` gate before this method runs. Maven overrides this: its
    /// `name` is a `group:artifact` compound, and only the `artifact` half belongs in
    /// an already-open `<artifactId>` tag.
    fn fallback_bare_insert_text(&self, metadata: &dyn Metadata) -> Option<String> {
        Some(metadata.name().to_string())
    }

    /// Whether this ecosystem's package-name search may return a truncated view of
    /// a larger candidate set (see e.g. `PypiRegistry::search`'s doc comment).
    ///
    /// [`generate_completions`](Ecosystem::generate_completions) already reports
    /// this precisely per call via [`Completions::is_incomplete`] whenever a real
    /// completion context is available. This method exists only for the two
    /// `deps-lsp` code paths that cannot compute that precise per-call signal
    /// because no context has been resolved yet:
    ///
    /// - the raw-text fallback search (`fallback_completion`), which always
    ///   performs a package-name lookup via [`crate::Registry::search`] regardless
    ///   of what completion context (or lack thereof) triggered it;
    /// - the document-not-loaded early return, before any `ParseResult` — and so
    ///   any completion context — exists to call `generate_completions` with.
    ///
    /// Unlike the ecosystem-wide `completions_are_incomplete()` flag this method
    /// superseded (#419, removed in #427), it never gates the *primary*
    /// `generate_completions` response — only these two context-less fallbacks.
    /// Default `false` preserves existing behavior for every ecosystem whose
    /// package-name search is always exhaustive.
    fn package_search_is_incomplete(&self) -> bool {
        false
    }

    /// Fetches `name`'s license at `version` from this ecosystem's own tier-3 license
    /// source (issue #660/#688/#697), for
    /// `deps-lsp::document::osv_scan::run_license_prefetch`'s background pre-fetch —
    /// never called from the hover critical path directly, since it may perform network
    /// I/O.
    ///
    /// Only ever called when
    /// <code>self.[license_source](Self::license_source)().[requires_dedicated_fetch](LicenseSource::requires_dedicated_fetch)()</code>
    /// is `true`; the default implementation returns an already-resolved empty result
    /// and is never actually awaited by a correctly gated caller. Overriding this
    /// without also overriding [`Self::license_source`] to a variant whose
    /// `requires_dedicated_fetch()` is `true` leaves the override dead code — nothing
    /// automated cross-checks the two methods against each other, so keeping them in
    /// sync for a new override is the implementor's responsibility.
    fn fetch_license<'a>(
        &'a self,
        _name: &'a str,
        _version: &'a str,
    ) -> BoxFuture<'a, Vec<String>> {
        Box::pin(std::future::ready(Vec::new()))
    }

    /// How this ecosystem's license strings are sourced. See [`LicenseSource`].
    ///
    /// Default [`LicenseSource::RegistryDeclaredSpdx`] is correct for every ecosystem
    /// whose license is an author-declared SPDX identifier already present in the
    /// hot-path registry response. This is also the single answer to whether
    /// [`Self::fetch_license`] is ever called for this ecosystem — see
    /// [`LicenseSource::requires_dedicated_fetch`].
    fn license_source(&self) -> LicenseSource {
        LicenseSource::RegistryDeclaredSpdx
    }

    /// Support for downcasting to concrete ecosystem type
    ///
    /// This allows ecosystem-specific operations when needed.
    fn as_any(&self) -> &dyn Any;

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
    /// [`Self::generate_code_lenses`] can accidentally suppress it.
    fn collect_pin_all_to_sha_edits(
        &self,
        _parse_result: &dyn ParseResult,
        _versions: VersionData<'_>,
    ) -> Vec<TextEdit> {
        Vec::new()
    }

    /// Singular/plural noun for this ecosystem's bulk "Pin N {noun} to commit SHA" lens
    /// title (e.g. `{ singular: "action", plural: "actions" }` for GitHub Actions),
    /// consulted only when [`Self::collect_pin_all_to_sha_edits`] returns at least one
    /// edit. Default `{ "ref", "refs" }` is a generic fallback; override to match the
    /// ecosystem's own vocabulary.
    fn pin_all_to_sha_noun(&self) -> crate::lsp_helpers::PinNoun {
        crate::lsp_helpers::PinNoun {
            singular: "ref",
            plural: "refs",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::assert_matches;

    #[test]
    fn test_ecosystem_id_roundtrip() {
        const ALL: &[EcosystemId] = &[
            EcosystemId::Cargo,
            EcosystemId::Npm,
            EcosystemId::Pypi,
            EcosystemId::Go,
            EcosystemId::Bundler,
            EcosystemId::Dart,
            EcosystemId::Maven,
            EcosystemId::Composer,
            EcosystemId::Gradle,
            EcosystemId::Swift,
            EcosystemId::NuGet,
            EcosystemId::Deno,
            EcosystemId::GithubActions,
            EcosystemId::GitlabCi,
        ];

        for id in ALL {
            let parsed: EcosystemId = id.id().parse().unwrap();
            assert_eq!(parsed, *id);
            assert_eq!(id.to_string(), id.id());
        }
    }

    #[test]
    fn test_osv_ecosystem_mapping_pinned() {
        let expected: &[(EcosystemId, &str)] = &[
            (EcosystemId::Cargo, "crates.io"),
            (EcosystemId::Npm, "npm"),
            (EcosystemId::Pypi, "PyPI"),
            (EcosystemId::Go, "Go"),
            (EcosystemId::Bundler, "RubyGems"),
            (EcosystemId::Dart, "Pub"),
            (EcosystemId::Maven, "Maven"),
            (EcosystemId::Composer, "Packagist"),
            (EcosystemId::Gradle, "Maven"),
            (EcosystemId::Swift, "SwiftURL"),
            (EcosystemId::NuGet, "NuGet"),
            (EcosystemId::Deno, "npm"),
            (EcosystemId::GithubActions, "GitHub Actions"),
        ];

        for (id, expected_str) in expected {
            assert_eq!(
                id.osv_ecosystem(),
                Some(*expected_str),
                "unexpected OSV ecosystem string for {id:?}"
            );
        }

        // A git-tag/release pin has no OSV coordinate by name (see `osv_ecosystem`'s doc).
        assert_eq!(EcosystemId::GitlabCi.osv_ecosystem(), None);
    }

    #[test]
    fn test_ecosystem_id_from_str_unknown() {
        let err = "unknown".parse::<EcosystemId>().unwrap_err();
        assert_matches!(err, crate::error::DepsError::UnsupportedEcosystem(s) if s == "unknown");
    }

    #[test]
    fn test_ecosystem_config_default() {
        let config = EcosystemConfig::default();
        assert!(config.show_up_to_date_hints);
        assert_eq!(config.up_to_date_text, "✅");
        assert_eq!(config.needs_update_text, "❌ {}");
    }

    #[test]
    fn test_ecosystem_config_custom() {
        let config = EcosystemConfig {
            show_up_to_date_hints: false,
            up_to_date_text: "OK".to_string(),
            needs_update_text: "Update to {}".to_string(),
            loading_text: "Loading...".to_string(),
            show_loading_hints: false,
            offline: false,
        };
        assert!(!config.show_up_to_date_hints);
        assert_eq!(config.up_to_date_text, "OK");
        assert_eq!(config.needs_update_text, "Update to {}");
    }

    #[test]
    fn test_ecosystem_config_clone() {
        let config1 = EcosystemConfig::default();
        let config2 = config1.clone();
        assert_eq!(config1.up_to_date_text, config2.up_to_date_text);
        assert_eq!(config1.show_up_to_date_hints, config2.show_up_to_date_hints);
        assert_eq!(config1.needs_update_text, config2.needs_update_text);
    }

    #[test]
    fn test_dependency_default_features() {
        struct MockDep;
        impl Dependency for MockDep {
            fn name(&self) -> &crate::PackageName {
                static NAME: std::sync::LazyLock<crate::PackageName> =
                    std::sync::LazyLock::new(|| crate::PackageName::new("test"));
                &NAME
            }
            fn name_range(&self) -> tower_lsp_server::ls_types::Range {
                tower_lsp_server::ls_types::Range::default()
            }
            fn version_requirement(&self) -> Option<&crate::VersionReq> {
                None
            }
            fn version_range(&self) -> Option<tower_lsp_server::ls_types::Range> {
                None
            }
            fn source(&self) -> crate::parser::DependencySource {
                crate::parser::DependencySource::Registry
            }
            fn as_any(&self) -> &dyn std::any::Any {
                self
            }
        }

        let dep = MockDep;
        assert_eq!(dep.features(), &[] as &[String]);
    }

    /// Minimal [`ParseResult`] returned by [`StubEcosystem::parse_manifest`] below —
    /// only [`parse_manifest_blocking`] tests need it, so it carries nothing beyond a URI.
    struct StubParseResult {
        uri: Uri,
    }

    impl ParseResult for StubParseResult {
        fn dependencies(&self) -> Vec<&dyn Dependency> {
            Vec::new()
        }

        fn workspace_root(&self) -> Option<&std::path::Path> {
            None
        }

        fn uri(&self) -> &Uri {
            &self.uri
        }

        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    /// Ecosystem stub for [`parse_manifest_blocking`] tests: `parse_manifest` either
    /// asserts it runs off `calling_thread` or panics, per `should_panic`.
    struct StubEcosystem {
        calling_thread: std::thread::ThreadId,
        should_panic: bool,
    }

    impl private::Sealed for StubEcosystem {}

    impl Ecosystem for StubEcosystem {
        fn id(&self) -> &'static str {
            "stub"
        }

        fn display_name(&self) -> &'static str {
            "Stub"
        }

        fn manifest_filenames(&self) -> &[&'static str] {
            &[]
        }

        fn parse_manifest<'a>(
            &'a self,
            _content: &'a str,
            uri: &'a Uri,
        ) -> BoxFuture<'a, crate::error::Result<Box<dyn ParseResult>>> {
            Box::pin(async move {
                assert!(!self.should_panic, "boom");
                assert_ne!(
                    std::thread::current().id(),
                    self.calling_thread,
                    "parse must run on the blocking pool, not the calling thread"
                );
                Ok(Box::new(StubParseResult { uri: uri.clone() }) as Box<dyn ParseResult>)
            })
        }

        fn registry(&self) -> Arc<dyn crate::Registry> {
            unimplemented!()
        }

        fn formatter(&self) -> &dyn crate::lsp_helpers::EcosystemFormatter {
            unimplemented!()
        }

        fn generate_completions<'a>(
            &'a self,
            _parse_result: &'a dyn ParseResult,
            _position: Position,
            _content: &'a str,
            _freshness: crate::FreshnessSettings,
        ) -> BoxFuture<'a, crate::completion::Completions> {
            unimplemented!()
        }

        fn completion_insert_text(&self, _metadata: &dyn crate::Metadata) -> Option<String> {
            unimplemented!()
        }

        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    /// Proves `parse_manifest_blocking` actually runs the parse off the calling (async)
    /// thread via `spawn_blocking`, mirroring `lockfile.rs`'s
    /// `test_read_and_parse_lockfile_runs_parse_off_calling_thread`.
    #[tokio::test]
    async fn test_parse_manifest_blocking_runs_parse_off_calling_thread() {
        let ecosystem: Arc<dyn Ecosystem> = Arc::new(StubEcosystem {
            calling_thread: std::thread::current().id(),
            should_panic: false,
        });
        let uri = crate::test_util::test_uri("/test/manifest.toml");

        let parsed = parse_manifest_blocking(&ecosystem, "content", &uri)
            .await
            .unwrap();
        assert_eq!(parsed.uri(), &uri);
    }

    /// A panicking `parse_manifest` must surface as `Err(DepsError::ParseError)` with the
    /// panic message preserved, mirroring `lockfile.rs`'s
    /// `test_read_and_parse_lockfile_panic_in_parse_becomes_parse_error`.
    #[tokio::test]
    async fn test_parse_manifest_blocking_panic_becomes_parse_error() {
        let ecosystem: Arc<dyn Ecosystem> = Arc::new(StubEcosystem {
            calling_thread: std::thread::current().id(),
            should_panic: true,
        });
        let uri = crate::test_util::test_uri("/test/manifest.toml");

        let Err(err) = parse_manifest_blocking(&ecosystem, "content", &uri).await else {
            panic!("expected parse_manifest_blocking to return an error");
        };

        match err {
            crate::error::DepsError::ParseError { file_type, source } => {
                assert!(file_type.contains("manifest at"));
                assert!(
                    source.to_string().contains("boom"),
                    "panic message should be preserved in the error source, got: {source}"
                );
            }
            other => panic!("Expected ParseError, got: {other:?}"),
        }
    }
}
