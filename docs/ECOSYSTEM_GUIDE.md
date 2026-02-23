# Ecosystem Implementation Guide

This guide explains how to add support for a new package ecosystem (e.g., Go modules, Maven, Gradle) to deps-lsp.

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
    pub name: String,
    /// LSP range of the name in source
    pub name_range: Range,
    /// Version requirement (e.g., "^1.0", ">=2.0")
    pub version_req: Option<String>,
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
    fn name(&self) -> &str {
        &self.name
    }

    fn name_range(&self) -> Range {
        self.name_range
    }

    fn version_requirement(&self) -> Option<&str> {
        self.version_req.as_deref()
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

// Implement deps_core::Registry trait using BoxFuture (no async_trait)
impl deps_core::Registry for {Ecosystem}Registry {
    fn get_versions<'a>(
        &'a self,
        name: &'a str,
    ) -> BoxFuture<'a, deps_core::error::Result<Vec<Box<dyn deps_core::Version>>>> {
        Box::pin(async move {
            let versions = self.get_versions(name).await?;
            Ok(versions
                .into_iter()
                .map(|v| Box::new(v) as Box<dyn deps_core::Version>)
                .collect())
        })
    }

    fn get_latest_matching<'a>(
        &'a self,
        name: &'a str,
        req: &'a str,
    ) -> BoxFuture<'a, deps_core::error::Result<Option<Box<dyn deps_core::Version>>>> {
        Box::pin(async move {
            let version = self.get_latest_matching(name, req).await?;
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

    fn package_url(&self, name: &str) -> String {
        format!("{}/{}", REGISTRY_URL, urlencoding::encode(name))
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

    fn package_url(&self, name: &str) -> String {
        format!("https://registry.example.com/packages/{}", name)
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
- `crates/deps-pypi/` - Python/pyproject.toml with PyPI API
- `crates/deps-go/` - Go/go.mod with proxy.golang.org
- `crates/deps-bundler/` - Ruby/Gemfile with RubyGems
- `crates/deps-dart/` - Dart/pubspec.yaml with pub.dev
- `crates/deps-maven/` - Java/pom.xml with Maven Central
- `crates/deps-gradle/` - Kotlin/Gradle version catalogs

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
