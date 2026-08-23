use std::any::Any;
use std::pin::Pin;
use std::sync::Arc;
use tower_lsp_server::ls_types::{
    CodeAction, CodeLens, CompletionItem, Diagnostic, Hover, InlayHint, Position, Uri,
};

use crate::{
    Registry,
    lsp_helpers::{EcosystemFormatter, VersionData},
};

pub mod private {
    pub trait Sealed {}
}

pub type BoxFuture<'a, T> = Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

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
    /// Rust Cargo ecosystem (`Cargo.toml`).
    Cargo,
    /// JavaScript/TypeScript npm ecosystem (`package.json`).
    Npm,
    /// Python PyPI ecosystem (`pyproject.toml`).
    Pypi,
    /// Go modules ecosystem (`go.mod`).
    Go,
    /// Ruby Bundler ecosystem (`Gemfile`).
    Bundler,
    /// Dart/Flutter pub ecosystem (`pubspec.yaml`).
    Dart,
    /// Java/Kotlin Maven ecosystem (`pom.xml`).
    Maven,
    /// PHP Composer ecosystem (`composer.json`).
    Composer,
    /// Java/Kotlin Gradle ecosystem (`build.gradle`, `build.gradle.kts`, version catalogs).
    Gradle,
    /// Swift Package Manager ecosystem (`Package.swift`).
    Swift,
    /// .NET NuGet ecosystem (`.csproj`/`.fsproj`/`.vbproj`, `Directory.Packages.props`, `packages.config`).
    NuGet,
}

impl EcosystemId {
    /// Returns the canonical string identifier, matching [`Ecosystem::id`] for the
    /// corresponding ecosystem implementation.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::Cargo => "cargo",
            Self::Npm => "npm",
            Self::Pypi => "pypi",
            Self::Go => "go",
            Self::Bundler => "bundler",
            Self::Dart => "dart",
            Self::Maven => "maven",
            Self::Composer => "composer",
            Self::Gradle => "gradle",
            Self::Swift => "swift",
            Self::NuGet => "nuget",
        }
    }

    /// OSV.dev `package.ecosystem` value for this ecosystem, or `None` if
    /// OSV has no equivalent.
    ///
    /// An exhaustive `match` rather than a lookup table: adding a 12th
    /// ecosystem becomes a compile error here instead of a silent
    /// zero-results ecosystem in OSV queries. Every arm below was verified
    /// live against `https://api.osv.dev` (each returned real advisories for
    /// a known-vulnerable version) — see `architecture.md` §2.
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
        Some(match self {
            Self::Cargo => "crates.io",
            Self::Npm => "npm",
            Self::Pypi => "PyPI",
            Self::Go => "Go",
            Self::Bundler => "RubyGems",
            Self::Dart => "Pub",
            Self::Maven | Self::Gradle => "Maven",
            Self::Composer => "Packagist",
            Self::Swift => "SwiftURL",
            Self::NuGet => "NuGet",
        })
    }
}

impl std::fmt::Display for EcosystemId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.id())
    }
}

impl std::str::FromStr for EcosystemId {
    type Err = crate::error::DepsError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "cargo" => Ok(Self::Cargo),
            "npm" => Ok(Self::Npm),
            "pypi" => Ok(Self::Pypi),
            "go" => Ok(Self::Go),
            "bundler" => Ok(Self::Bundler),
            "dart" => Ok(Self::Dart),
            "maven" => Ok(Self::Maven),
            "composer" => Ok(Self::Composer),
            "gradle" => Ok(Self::Gradle),
            "swift" => Ok(Self::Swift),
            "nuget" => Ok(Self::NuGet),
            _ => Err(crate::error::DepsError::UnsupportedEcosystem(s.to_string())),
        }
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
}

impl Default for EcosystemConfig {
    fn default() -> Self {
        Self {
            show_up_to_date_hints: true,
            up_to_date_text: "✅".to_string(),
            needs_update_text: "❌ {}".to_string(),
            loading_text: "⏳".to_string(),
            show_loading_hints: true,
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
/// # Examples
///
/// ```no_run
/// use deps_core::{Ecosystem, ParseResult, Registry, EcosystemConfig, PackageName};
/// use deps_core::lsp_helpers::EcosystemFormatter;
/// use std::sync::Arc;
/// use std::any::Any;
/// use tower_lsp_server::ls_types::{Uri, CompletionItem, Position};
///
/// struct MyFormatter;
/// impl EcosystemFormatter for MyFormatter {
///     fn format_version_for_text_edit(&self, version: &str) -> String { version.to_string() }
///     fn package_url(&self, name: &PackageName) -> String { format!("https://example.com/{name}") }
/// }
///
/// struct MyEcosystem {
///     registry: Arc<dyn Registry>,
///     formatter: MyFormatter,
/// }
///
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
///     ) -> deps_core::ecosystem::BoxFuture<'a, Vec<CompletionItem>> {
///         Box::pin(async move { vec![] })
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
    /// using `self.formatter()` and `self.registry()`.
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
            )
            .await
        })
    }

    /// Generate code actions for a position.
    ///
    /// Default implementation delegates to `lsp_helpers::generate_code_actions`
    /// using `self.formatter()` and `self.registry()`. `content` is the
    /// manifest source, needed to guard against rewriting a `version_range`
    /// that no longer slices to its declared requirement text (see
    /// `lsp_helpers::literal_span_matches`).
    fn generate_code_actions<'a>(
        &'a self,
        parse_result: &'a dyn ParseResult,
        position: Position,
        uri: &'a Uri,
        content: &'a str,
    ) -> BoxFuture<'a, Vec<CodeAction>> {
        Box::pin(async move {
            let registry = self.registry();
            crate::lsp_helpers::generate_code_actions(
                parse_result,
                position,
                uri,
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
    /// using `self.formatter()`.
    fn generate_diagnostics<'a>(
        &'a self,
        parse_result: &'a dyn ParseResult,
        versions: VersionData<'a>,
        _uri: &'a Uri,
        freshness: crate::freshness::FreshnessSettings,
        severities: crate::lsp_helpers::DiagnosticSeverities,
    ) -> BoxFuture<'a, Vec<Diagnostic>> {
        Box::pin(async move {
            crate::lsp_helpers::generate_diagnostics_from_cache(
                parse_result,
                versions,
                self.formatter(),
                freshness,
                severities,
            )
        })
    }

    /// Generate the "Update N outdated dependencies" code lens for the document.
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
    fn generate_completions<'a>(
        &'a self,
        parse_result: &'a dyn ParseResult,
        position: Position,
        content: &'a str,
        freshness: crate::FreshnessSettings,
    ) -> BoxFuture<'a, Vec<CompletionItem>>;

    /// Support for downcasting to concrete ecosystem type
    ///
    /// This allows ecosystem-specific operations when needed.
    fn as_any(&self) -> &dyn Any;
}

#[cfg(test)]
mod tests {
    use super::*;

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
        ];

        for (id, expected_str) in expected {
            assert_eq!(
                id.osv_ecosystem(),
                Some(*expected_str),
                "unexpected OSV ecosystem string for {id:?}"
            );
        }
    }

    #[test]
    fn test_ecosystem_id_from_str_unknown() {
        let err = "unknown".parse::<EcosystemId>().unwrap_err();
        assert!(matches!(err, crate::error::DepsError::UnsupportedEcosystem(s) if s == "unknown"));
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
}
