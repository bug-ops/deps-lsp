# Ecosystem Implementation Guide

This guide explains how to add support for a new package ecosystem (e.g., Go modules, Maven, Gradle) to deps-lsp.

## Supported Ecosystems

deps-lsp provides comprehensive LSP support for 11 package ecosystems:

| Ecosystem | Language | Manifest File(s) | Lock File(s) | Features |
|-----------|----------|-----------------|--------------|----------|
| **Cargo** | Rust | `Cargo.toml` | `Cargo.lock` | Hover, inlay hints, completion, code actions, diagnostics, code lens, feature flag completion |
| **npm** | JavaScript/TypeScript | `package.json` | `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` | Hover, inlay hints, completion, code actions, diagnostics, code lens |
| **PyPI** | Python | `pyproject.toml`, `setup.py` | `poetry.lock`, `uv.lock`, `requirements.lock` | Hover with PEP 508 environment marker display ("Active when: `<marker>`"), inlay hints, completion, code actions, diagnostics, code lens |
| **Go** | Go | `go.mod` | `go.sum` | Hover, inlay hints, completion, code actions, diagnostics, code lens, pseudo-version support |
| **Bundler** | Ruby | `Gemfile` | `Gemfile.lock` | Hover, inlay hints, completion, code actions, diagnostics, code lens |
| **Dart** | Dart | `pubspec.yaml` | `pubspec.lock` | Hover, inlay hints, completion, code actions, diagnostics, code lens |
| **Maven** | Java | `pom.xml` | `maven-metadata.xml` (CDN) | Hover with corrected version ordering (numeric segments outrank qualifiers, prereleases sort below base release), inlay hints, completion, code actions, diagnostics, code lens (property-versioned dependencies not covered — see below) |
| **Gradle** | Kotlin/Groovy | `build.gradle`, `build.gradle.kts`, `gradle/libs.versions.toml` | — | Hover with corrected version ordering (same as Maven), inlay hints, completion, code actions, diagnostics, code lens (variable/catalog-versioned dependencies not covered — see below), variable resolution (`gradle.properties`) |
| **Composer** | PHP | `composer.json` | `composer.lock` | Hover, inlay hints, completion, code actions, diagnostics, code lens |
| **Swift** | Swift | `Package.swift` | `Package.resolved` | Hover, inlay hints, completion, code actions, diagnostics, GitHub API support (code lens not covered — see below) |
| **NuGet** | .NET | `.csproj`, `.fsproj`, `.vbproj`, `Directory.Packages.props`, `packages.config` | `packages.lock.json` | Hover, inlay hints, completion, code actions, diagnostics, code lens, central package management support, SemVer2 prerelease handling |

### PyPI Environment Markers (PEP 508)

When a Python dependency is gated by an environment marker (e.g., `numpy>=1.24; python_version>='3.9'`), the hover popup displays:
```
Active when: python_version >= '3.9'
```
This helps you understand when conditional dependencies apply. Markers are shown for dependencies in `pyproject.toml` (PEP 621), Poetry `[tool.poetry.dependencies]` tables, and both PEP 621 requirement strings and Poetry string-form suffixes.

### Maven/Gradle Version Comparison

Versions are now ranked with correct Maven semantics:
- **Numeric segments outrank non-numeric qualifiers**: `33` > `r09` (previously the reverse)
- **Prerelease qualifiers sort below their base release**: `1.0-RC1` < `1.0` (previously the reverse)
- **Qualifier precedence**: `alpha` < `beta` < `milestone` < `rc`/`cr` < `snapshot` < `release` < `sp` (case-insensitive)
- **Numeric suffixes within qualifiers are compared numerically**: `M10` > `M2` (previously `M2` > `M10`)

These fixes ensure hover's "Recent versions" list and completion sort order match Maven's actual version ordering.

### Maven/Gradle Version Range Matching

`version_satisfies_requirement` now recognizes bracket-interval range syntax instead of only exact string equality, so a dependency pinned to a range no longer always renders as "outdated":

- **Maven** (`pom.xml`): interval notation — `[1.0,2.0)`, `[1.0]` (exact pin), `[1.5,)`, `(,2.0]` — and top-level comma unions, e.g. `(,1.0),(1.2,)`. Bounds are compared with Maven's qualifier-aware ordering, so `[1.0-beta,2.0-rc)` orders correctly. A bare, non-bracketed requirement (`1.0`) is still Maven's "soft" recommended version and compared for plain equality, not as a range.
- **Gradle** (`build.gradle`, `build.gradle.kts`, `gradle/libs.versions.toml`): the same bracket-interval syntax as Maven (no comma unions — Gradle's grammar doesn't have them), plus Gradle-specific forms: dynamic versions (`1.0+`, `2.10.+`), `latest.release`/`latest.integration` selectors, and Gradle's reversed-bracket exclusive notation (`]1.2,1.5]` for an exclusive lower bound, `[1.1,2.0[` for an exclusive upper bound).
- **Malformed input fails closed**: an unparseable range (unbalanced/stray brackets, an extra comma-separated component, a mismatched no-comma pin like `[1.0)`, or any unparseable member of a Maven union) is rejected as a whole — `version_satisfies_requirement` returns `false` rather than matching on a corrupted or partial parse.

### Maven/Gradle Unresolved Requirements

A requirement that couldn't be resolved to a concrete version (Maven's `${property}` missing from `<properties>`, Gradle's `$var`/`${var}` variable reference, or a Gradle version-catalog `version.ref` alias missing from `[versions]`) is treated as `RequirementStatus::Unresolved`, distinct from `UpToDate`/`Outdated`:

- **Diagnostics**: no "Newer version available" hint is shown — same as before, since the server can't verify either way.
- **Inlay hints**: no badge is shown at all, neither "up to date" nor "needs update" — showing "up to date" for a requirement that was never actually checked against the latest version would be misleading.
- **CodeLens "Update N outdated dependencies"** (below): an unresolved requirement is also never counted or edited — it already fails the literal-span guard (the tracked span covers a placeholder/variable, not a version literal), so the two mechanisms agree independently rather than one depending on the other.

### CodeLens: "Update N Outdated Dependencies"

An open manifest with at least one outdated, safely-editable dependency shows a code lens at
the top of the document, titled `Update N outdated dependencies`. Clicking it applies a
single batch edit that rewrites every such dependency's version to the latest known
version, sharing the same "is this outdated" definition as diagnostics (a requirement
already satisfied by the latest version — e.g. Cargo's `^1.2` accepting `1.9` — is left
alone; that lag is the lock file's, not the manifest's, to fix).

**Coverage caveat.** Before rewriting a dependency's declared version text, the feature
verifies the manifest span it is about to edit actually *is* that version literal. Some
ecosystems point the tracked span at something else instead:

- **`pom.xml`** dependencies versioned through a `<properties>` placeholder (`<version>${my.version}</version>`) are skipped — the span covers the placeholder, not a literal.
- **Gradle** dependencies versioned through a DSL variable (`"...:$myVersion"`, resolved from `gradle.properties`) or a `libs.versions.toml` version-catalog alias (`version.ref = "spring"`) are skipped for the same reason.
- **`Package.swift`** dependencies are always skipped, for every declaration form (`from:`, `.upToNextMajor`, `.exact`, a `..<`/`...` range, `.branch`, `.revision`) — the tracked span is only ever the lower-bound literal of a synthesized comparator range, never the full requirement.

For these, no lens appears even when the dependency is genuinely outdated — this is the
correct, conservative behavior (silently declining to edit is far better than corrupting a
build file), not a bug.

> [!WARNING]
> The per-line "Update to latest version" code action does **not** have this guard yet —
> for these same declarations, it currently applies the edit anyway, which corrupts the
> property reference, DSL variable, catalog alias, or Swift comparator range it targets.
> Until that is fixed, edit these specific declarations by hand rather than through the
> code action. Lifting the restriction requires moving the same check into each
> affected parser, which fixes both surfaces at once and is tracked as a follow-up, out
> of scope for the initial CodeLens implementation.

**Known divergence from inlay hints (accepted, documented).** Inlay hints use a
lock-file-aware "outdated" check (resolved version vs. latest), while the lens and
diagnostics use the manifest-requirement check described above. With a lagging lock file
and a requirement permissive enough to already accept the latest version, inlay hints can
render `❌ <version>` on a dependency with no matching diagnostic and no lens — the fix
in that case is regenerating the lock file, which only the package manager can do, so
there is nothing for the lens to edit. Unifying the two definitions is tracked as a
follow-up.

### npm Package Name Validation

When a dependency in `package.json` fails to resolve against the npm registry, the diagnostic distinguishes between two cases instead of always reporting "Unknown package":

- **`Invalid package name '<name>': <reason>`** — the name itself violates npm's own naming rules (e.g. it starts with `.`/`_`, exceeds 214 characters, contains a character outside npm's URL-friendly set, or is a reserved name like `node_modules`).
- **`Unknown package '<name>'`** — the name is syntactically valid but was not found in the registry (typo, private/unpublished package, etc.).

The check is deliberately permissive: uppercase names are still accepted (npm only warns on those for legacy packages, never rejects), and it accepts every character npm's own `encodeURIComponent(segment) === segment` predicate accepts, including `! ' ( ) * - . _ ~` — not just alphanumerics and hyphens.

## Architecture Overview

Each ecosystem is implemented as a separate crate under `crates/deps-{ecosystem}/` with the following structure:

```
crates/deps-{ecosystem}/
├── Cargo.toml
└── src/
    ├── lib.rs          # Re-exports and module declarations
    ├── ecosystem.rs    # Ecosystem trait implementation
    ├── error.rs        # Ecosystem-specific error types
    ├── formatter.rs    # Version display formatting
    ├── lockfile.rs     # Lock file parsing
    ├── parser.rs       # Manifest file parsing with position tracking
    ├── registry.rs     # Package registry API client
    └── types.rs        # Dependency, Version, and other types
```

## Step 1: Create the Crate

Create a new crate with workspace dependencies:

```toml
# crates/deps-{ecosystem}/Cargo.toml
[package]
name = "deps-{ecosystem}"
version.workspace = true
edition.workspace = true
rust-version.workspace = true
authors.workspace = true
license.workspace = true
repository.workspace = true
description = "{Ecosystem} support for deps-lsp"

[dependencies]
deps-core = { path = "../deps-core" }
serde = { workspace = true }
serde_json = { workspace = true }
thiserror = { workspace = true }
tokio = { workspace = true }
tower-lsp-server = { workspace = true }
tracing = { workspace = true }

[dev-dependencies]
tokio-test = { workspace = true }
```

Add to workspace in root `Cargo.toml`:

```toml
[workspace]
members = [
    # ... existing members
    "crates/deps-{ecosystem}",
]
```

## Step 2: Define Error Types

Create ecosystem-specific errors in `error.rs`:

```rust
//! Errors specific to {Ecosystem} dependency handling.

use thiserror::Error;

#[derive(Error, Debug)]
pub enum {Ecosystem}Error {
    /// Failed to parse manifest file
    #[error("Failed to parse {manifest_file}: {source}")]
    ParseError {
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// Invalid version specifier
    #[error("Invalid version specifier '{specifier}': {message}")]
    InvalidVersionSpecifier {
        specifier: String,
        message: String,
    },

    /// Package not found
    #[error("Package '{package}' not found")]
    PackageNotFound { package: String },

    /// Registry request failed
    #[error("Registry request failed for '{package}': {source}")]
    RegistryError {
        package: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// Cache error
    #[error("Cache error: {0}")]
    CacheError(String),

    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Result type alias for {Ecosystem} operations.
pub type Result<T> = std::result::Result<T, {Ecosystem}Error>;

// Implement conversions to/from deps_core::DepsError
impl From<{Ecosystem}Error> for deps_core::DepsError {
    fn from(err: {Ecosystem}Error) -> Self {
        match err {
            {Ecosystem}Error::ParseError { source } => deps_core::DepsError::ParseError {
                file_type: "{manifest_file}".into(),
                source,
            },
            {Ecosystem}Error::InvalidVersionSpecifier { message, .. } => {
                deps_core::DepsError::InvalidVersionReq(message)
            }
            {Ecosystem}Error::PackageNotFound { package } => {
                deps_core::DepsError::CacheError(format!("Package '{}' not found", package))
            }
            {Ecosystem}Error::RegistryError { package, source } => {
                deps_core::DepsError::ParseError {
                    file_type: format!("registry for {}", package),
                    source,
                }
            }
            {Ecosystem}Error::CacheError(msg) => deps_core::DepsError::CacheError(msg),
            {Ecosystem}Error::Io(e) => deps_core::DepsError::Io(e),
        }
    }
}
```

## Step 3: Define Types

Create ecosystem-specific types in `types.rs`:

```rust
//! Types for {Ecosystem} dependency management.

use std::any::Any;
use tower_lsp_server::ls_types::Range;

pub use deps_core::parser::DependencySource;

/// A dependency from the manifest file.
#[derive(Debug, Clone)]
pub struct {Ecosystem}Dependency {
    /// Package name
    pub name: deps_core::PackageName,
    /// LSP range of the name in source
    pub name_range: Range,
    /// Version requirement (e.g., "^1.0", ">=2.0")
    pub version_req: Option<deps_core::VersionReq>,
    /// LSP range of version in source
    pub version_range: Option<Range>,
    /// Dependency source (registry, git, path)
    pub source: DependencySource,
    /// Dependency section (dependencies, dev, etc.)
    pub section: {Ecosystem}DependencySection,
}

/// Dependency section types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum {Ecosystem}DependencySection {
    Dependencies,
    DevDependencies,
    // Add ecosystem-specific sections
}

/// Version information from the registry.
#[derive(Debug, Clone)]
pub struct {Ecosystem}Version {
    pub version: String,
    pub yanked: bool,
    // Add ecosystem-specific fields
}

// Implement deps_core traits
impl deps_core::Dependency for {Ecosystem}Dependency {
    fn name(&self) -> &deps_core::PackageName {
        &self.name
    }

    fn name_range(&self) -> Range {
        self.name_range
    }

    fn version_requirement(&self) -> Option<&deps_core::VersionReq> {
        self.version_req.as_ref()
    }

    fn version_range(&self) -> Option<Range> {
        self.version_range
    }

    fn source(&self) -> DependencySource {
        self.source
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

impl deps_core::Version for {Ecosystem}Version {
    fn version_string(&self) -> &str {
        &self.version
    }

    fn is_yanked(&self) -> bool {
        self.yanked
    }

    fn is_prerelease(&self) -> bool {
        // Implement based on ecosystem's prerelease conventions
        self.version.contains('-') || self.version.contains("alpha") || self.version.contains("beta")
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
```

## Step 4: Implement the Parser

Create manifest parser in `parser.rs` with **position tracking**:

```rust
//! {Manifest} parser with position tracking.

use crate::error::Result;
use crate::types::{Ecosystem}Dependency;
use std::any::Any;
use tower_lsp_server::ls_types::{Uri};
use deps_core::lsp_helpers::LineOffsetTable;

/// Parse result containing dependencies and metadata.
#[derive(Debug)]
pub struct {Ecosystem}ParseResult {
    pub dependencies: Vec<{Ecosystem}Dependency>,
    pub uri: Uri,
}

impl deps_core::ParseResult for {Ecosystem}ParseResult {
    fn dependencies(&self) -> Vec<&dyn deps_core::Dependency> {
        self.dependencies
            .iter()
            .map(|d| d as &dyn deps_core::Dependency)
            .collect()
    }

    fn workspace_root(&self) -> Option<&std::path::Path> {
        None // Override if ecosystem supports workspaces
    }

    fn uri(&self) -> &Uri {
        &self.uri
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Parse manifest file and extract dependencies with positions.
pub fn parse_{manifest}(content: &str, uri: &Uri) -> Result<{Ecosystem}ParseResult> {
    let line_table = LineOffsetTable::new(content);

    // TODO: Implement actual parsing logic
    // Key requirements:
    // 1. Track byte offsets for every dependency name and version
    // 2. Convert offsets to LSP Position using line_table.byte_offset_to_position(content, offset)
    // 3. Handle all dependency sections

    Ok({Ecosystem}ParseResult {
        dependencies: vec![],
        uri: uri.clone(),
    })
}
```

## Step 5: Implement the Registry Client

Create registry client in `registry.rs`:

```rust
//! {Registry} API client with HTTP caching.

use crate::error::Result;
use crate::types::{Ecosystem}Version;
use deps_core::{HttpCache, ecosystem::BoxFuture};
use std::any::Any;
use std::sync::Arc;

const REGISTRY_URL: &str = "https://registry.example.com";

/// {Registry} API client.
pub struct {Ecosystem}Registry {
    cache: Arc<HttpCache>,
}

impl {Ecosystem}Registry {
    pub fn new(cache: Arc<HttpCache>) -> Self {
        Self { cache }
    }

    /// Fetches all versions for a package.
    pub async fn get_versions(&self, name: &str) -> Result<Vec<{Ecosystem}Version>> {
        let url = format!("{}/{}", REGISTRY_URL, urlencoding::encode(name));

        let data = self.cache
            .get_cached(&url)
            .await
            .map_err(|e| crate::error::{Ecosystem}Error::CacheError(e.to_string()))?;

        // TODO: Parse response and return versions
        Ok(vec![])
    }

    /// Gets the latest version matching a requirement.
    pub async fn get_latest_matching(
        &self,
        name: &str,
        version_req: &str,
    ) -> Result<Option<{Ecosystem}Version>> {
        let versions = self.get_versions(name).await?;

        // TODO: Implement version matching logic
        Ok(versions.into_iter().find(|v| !v.yanked))
    }
}

// Implement deps_core::Registry trait using BoxFuture (no async_trait).
// The trait takes PackageName/VersionReq; the inherent methods above stay
// &str, so each forward converts with .as_str().
impl deps_core::Registry for {Ecosystem}Registry {
    fn get_versions<'a>(
        &'a self,
        name: &'a deps_core::PackageName,
    ) -> BoxFuture<'a, deps_core::error::Result<Vec<Box<dyn deps_core::Version>>>> {
        Box::pin(async move {
            let versions = self.get_versions(name.as_str()).await?;
            Ok(versions
                .into_iter()
                .map(|v| Box::new(v) as Box<dyn deps_core::Version>)
                .collect())
        })
    }

    fn get_latest_matching<'a>(
        &'a self,
        name: &'a deps_core::PackageName,
        req: &'a deps_core::VersionReq,
    ) -> BoxFuture<'a, deps_core::error::Result<Option<Box<dyn deps_core::Version>>>> {
        Box::pin(async move {
            let version = self.get_latest_matching(name.as_str(), req.as_str()).await?;
            Ok(version.map(|v| Box::new(v) as Box<dyn deps_core::Version>))
        })
    }

    fn search<'a>(
        &'a self,
        _query: &'a str,
        _limit: usize,
    ) -> BoxFuture<'a, deps_core::error::Result<Vec<Box<dyn deps_core::Metadata>>>> {
        Box::pin(async move { Ok(vec![]) })
    }

    fn package_url(&self, name: &deps_core::PackageName) -> String {
        format!("{}/{}", REGISTRY_URL, urlencoding::encode(name.as_str()))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
```

## Step 6: Implement the Ecosystem Trait

Create the main ecosystem implementation in `ecosystem.rs`:

```rust
//! {Ecosystem} implementation for deps-lsp.

use std::any::Any;
use std::sync::Arc;
use tower_lsp_server::ls_types::{CompletionItem, Position, Uri};

use deps_core::{
    Ecosystem, HttpCache, ParseResult as ParseResultTrait, Registry, Result,
    ecosystem::BoxFuture,
    lockfile::LockFileProvider,
    lsp_helpers::EcosystemFormatter,
};

use crate::formatter::{Ecosystem}Formatter;
use crate::lockfile::{Ecosystem}LockfileParser;
use crate::parser::parse_{manifest};
use crate::registry::{Ecosystem}Registry;

/// {Ecosystem} ecosystem implementation.
pub struct {Ecosystem}Ecosystem {
    registry: Arc<{Ecosystem}Registry>,
    formatter: {Ecosystem}Formatter,
}

impl {Ecosystem}Ecosystem {
    pub fn new(cache: Arc<HttpCache>) -> Self {
        Self {
            registry: Arc::new({Ecosystem}Registry::new(cache)),
            formatter: {Ecosystem}Formatter,
        }
    }
}

// Required sealed trait impl — prevents external implementations
impl deps_core::ecosystem::private::Sealed for {Ecosystem}Ecosystem {}

impl Ecosystem for {Ecosystem}Ecosystem {
    fn id(&self) -> &'static str {
        "{ecosystem_id}"
    }

    fn display_name(&self) -> &'static str {
        "{Ecosystem Name}"
    }

    fn manifest_filenames(&self) -> &[&'static str] {
        &["{manifest_filename}"]
    }

    fn lockfile_filenames(&self) -> &[&'static str] {
        &["{lockfile_filename}"]
    }

    fn parse_manifest<'a>(
        &'a self,
        content: &'a str,
        uri: &'a Uri,
    ) -> BoxFuture<'a, Result<Box<dyn ParseResultTrait>>> {
        Box::pin(async move {
            let result = parse_{manifest}(content, uri)?;
            Ok(Box::new(result) as Box<dyn ParseResultTrait>)
        })
    }

    fn registry(&self) -> Arc<dyn Registry> {
        self.registry.clone() as Arc<dyn Registry>
    }

    fn lockfile_provider(&self) -> Option<Arc<dyn LockFileProvider>> {
        Some(Arc::new({Ecosystem}LockfileParser))
    }

    fn formatter(&self) -> &dyn EcosystemFormatter {
        &self.formatter
    }

    // generate_inlay_hints, generate_hover, generate_code_actions, generate_diagnostics
    // all have default implementations in the Ecosystem trait that delegate to lsp_helpers.
    // Override only if custom behavior is needed.

    fn generate_completions<'a>(
        &'a self,
        _parse_result: &'a dyn ParseResultTrait,
        _position: Position,
        _content: &'a str,
    ) -> BoxFuture<'a, Vec<CompletionItem>> {
        Box::pin(async move { vec![] })
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
```

## Step 7: Implement the Lock File Provider

Create lock file parser in `lockfile.rs`:

```rust
//! Lock file parsing for {Ecosystem}.

use std::path::{Path, PathBuf};

use deps_core::lockfile::{
    LockFileProvider, ResolvedPackage, ResolvedPackages, ResolvedSource,
    locate_lockfile_for_manifest,
};
use tower_lsp_server::ls_types::Uri;

/// Lock file parser for {Ecosystem}.
pub struct {Ecosystem}LockfileParser;

impl LockFileProvider for {Ecosystem}LockfileParser {
    fn locate_lockfile(&self, manifest_uri: &Uri) -> Option<PathBuf> {
        locate_lockfile_for_manifest(manifest_uri, &["{lockfile_name}"])
    }

    fn parse_lockfile<'a>(
        &'a self,
        lockfile_path: &'a Path,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = deps_core::error::Result<ResolvedPackages>> + Send + 'a>> {
        Box::pin(async move {
            let content = tokio::fs::read_to_string(lockfile_path)
                .await
                .map_err(deps_core::DepsError::Io)?;

            parse_lock_content(&content)
        })
    }
}

fn parse_lock_content(content: &str) -> deps_core::error::Result<ResolvedPackages> {
    let mut packages = ResolvedPackages::new();

    // TODO: Parse lock file and call packages.insert(ResolvedPackage { ... })

    Ok(packages)
}
```

## Step 8: Implement the Formatter

Create the formatter in `formatter.rs`:

```rust
use deps_core::lsp_helpers::EcosystemFormatter;

pub struct {Ecosystem}Formatter;

impl EcosystemFormatter for {Ecosystem}Formatter {
    fn format_version_for_text_edit(&self, version: &str) -> String {
        // Format version string for use in code action text edits
        format!("\"{}\"", version)
    }

    fn package_url(&self, name: &deps_core::PackageName) -> String {
        format!("https://registry.example.com/packages/{}", name)
    }

    // Optional: lint manifest-declared names against this ecosystem's naming
    // rules. Default is always `Ok(())` — only override to warn on names the
    // ecosystem's own tooling would never accept (see `deps-npm`'s
    // `NpmFormatter` for a full example). Never used as a construction gate:
    // `PackageName::new` stays infallible regardless of this check.
    fn validate_package_name(&self, _name: &str) -> Result<(), deps_core::InvalidPackageName> {
        Ok(())
    }
}
```

## Step 9: Create lib.rs

Expose public API in `lib.rs`:

```rust
//! {Ecosystem} support for deps-lsp.

pub mod ecosystem;
pub mod error;
pub mod formatter;
pub mod lockfile;
pub mod parser;
pub mod registry;
pub mod types;

pub use ecosystem::{Ecosystem}Ecosystem;
pub use error::{Ecosystem}Error, Result;
pub use parser::parse_{manifest};
pub use registry::{Ecosystem}Registry;
pub use types::{{Ecosystem}Dependency, {Ecosystem}Version};
```

## Step 10: Register the Ecosystem

In `deps-lsp/src/lib.rs`, add your ecosystem using the macros:

```rust
// 1. Add re-exports using the ecosystem! macro
ecosystem!(
    "{ecosystem_id}",        // Feature flag name
    deps_{ecosystem},        // Crate name
    {Ecosystem}Ecosystem,    // Main ecosystem type
    [
        {Ecosystem}Dependency,
        {Ecosystem}Version,
        {Ecosystem}Registry,
        // ... other public types
    ]
);

// 2. Add registration in register_ecosystems() using the register! macro
pub fn register_ecosystems(registry: &EcosystemRegistry, cache: Arc<HttpCache>) {
    register!("cargo", CargoEcosystem, registry, &cache);
    register!("npm", NpmEcosystem, registry, &cache);
    register!("pypi", PypiEcosystem, registry, &cache);
    register!("go", GoEcosystem, registry, &cache);
    register!("bundler", BundlerEcosystem, registry, &cache);
    register!("dart", DartEcosystem, registry, &cache);
    register!("maven", MavenEcosystem, registry, &cache);
    register!("gradle", GradleEcosystem, registry, &cache);

    // Add your ecosystem here:
    register!("{ecosystem_id}", {Ecosystem}Ecosystem, registry, &cache);
}
```

The macros handle feature-gating automatically. When the feature is disabled, both the re-exports and registration are compiled out.

## Step 11: Add Tests

Create comprehensive tests co-located with each module:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn test_uri() -> Uri {
        Uri::from_str("file:///test/{manifest_file}").unwrap()
    }

    #[test]
    fn test_parse_simple_dependencies() {
        let content = r#"..."#;
        let result = parse_{manifest}(content, &test_uri()).unwrap();
        assert!(!result.dependencies.is_empty());
    }

    #[test]
    fn test_position_tracking() {
        let content = r#"..."#;
        let result = parse_{manifest}(content, &test_uri()).unwrap();
        let dep = &result.dependencies[0];

        // Verify positions are correct
        assert!(dep.name_range.start.line > 0);
        assert!(dep.version_range.is_some());
    }

    #[tokio::test]
    async fn test_ecosystem_trait() {
        let cache = Arc::new(HttpCache::new());
        let ecosystem = {Ecosystem}Ecosystem::new(cache);

        assert_eq!(ecosystem.id(), "{ecosystem_id}");
        assert!(ecosystem.manifest_filenames().contains(&"{manifest_file}"));
    }
}
```

## Checklist

Before submitting a PR for a new ecosystem:

- [ ] Error types with conversions to `deps_core::DepsError`
- [ ] Types implementing `Dependency` and `Version` traits (with `source()` method)
- [ ] Parser with accurate position tracking for names AND versions
- [ ] Lock file parser implementing `LockFileProvider` trait (`locate_lockfile` + `parse_lockfile`)
- [ ] Formatter implementing `EcosystemFormatter` trait (`format_version_for_text_edit` + `package_url`)
- [ ] Registry client implementing `deps_core::Registry` trait with BoxFuture signatures
- [ ] Ecosystem impl with `impl deps_core::ecosystem::private::Sealed` block
- [ ] Unit tests for parser edge cases
- [ ] Integration tests for registry (can be `#[ignore]`)
- [ ] Documentation in lib.rs with examples
- [ ] Added to workspace members in root Cargo.toml
- [ ] Feature flag added in deps-lsp/Cargo.toml
- [ ] Re-exports via `ecosystem!()` macro in deps-lsp/src/lib.rs
- [ ] Registration via `register!()` macro in deps-lsp/src/lib.rs

## Reference Implementations

See existing implementations for reference:
- `crates/deps-cargo/` - Rust/Cargo.toml with crates.io sparse index
- `crates/deps-npm/` - JavaScript/package.json with npm registry
- `crates/deps-pypi/` - Python/pyproject.toml/poetry with PyPI API and PEP 508 marker support
- `crates/deps-go/` - Go/go.mod with proxy.golang.org
- `crates/deps-bundler/` - Ruby/Gemfile with RubyGems API
- `crates/deps-dart/` - Dart/pubspec.yaml with pub.dev API
- `crates/deps-maven/` - Java/pom.xml with Maven Central (CDN metadata + Solr search)
- `crates/deps-gradle/` - Kotlin/Groovy with version catalogs and property resolution
- `crates/deps-composer/` - PHP/composer.json with Packagist V2 API
- `crates/deps-swift/` - Swift/Package.swift with GitHub API support
- `crates/deps-nuget/` - C#/.NET/.csproj/packages.config with NuGet V3 registry (SemVer2 prerelease, central package management)

## Key API Contracts

### No async_trait

All trait methods use `BoxFuture` instead of `#[async_trait]`:

```rust
// Correct
fn parse_manifest<'a>(
    &'a self,
    content: &'a str,
    uri: &'a Uri,
) -> deps_core::ecosystem::BoxFuture<'a, Result<Box<dyn ParseResult>>> {
    Box::pin(async move { ... })
}

// Wrong — do not use
#[async_trait]
async fn parse_manifest(&self, content: &str, uri: &Uri) -> Result<Box<dyn ParseResult>> { ... }
```

### Position Tracking

Use `deps_core::lsp_helpers::LineOffsetTable` for byte offset to LSP position conversion:

```rust
use deps_core::lsp_helpers::LineOffsetTable;

let table = LineOffsetTable::new(content);
let position = table.byte_offset_to_position(content, byte_offset);
```

### LockFileProvider Signatures

```rust
impl LockFileProvider for MyLockParser {
    fn locate_lockfile(&self, manifest_uri: &Uri) -> Option<PathBuf> { ... }
    fn parse_lockfile<'a>(&'a self, lockfile_path: &'a Path)
        -> Pin<Box<dyn Future<Output = Result<ResolvedPackages>> + Send + 'a>> { ... }
}
```

## Templates

Use the templates in `templates/deps-ecosystem/` as a starting point for new ecosystems.
