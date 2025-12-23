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
    ├── parser.rs       # Manifest file parsing with position tracking
    ├── registry.rs     # Package registry API client
    ├── types.rs        # Dependency, Version, and other types
    └── lockfile.rs     # Lock file parsing (optional)
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
async-trait = { workspace = true }
serde = { workspace = true }
serde_json = { workspace = true }
thiserror = { workspace = true }
tokio = { workspace = true }
tower-lsp = { workspace = true }
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

use tower_lsp::lsp_types::Range;

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

    fn is_workspace_inherited(&self) -> bool {
        false // Override if ecosystem supports workspace inheritance
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
        self.version.contains("-") || self.version.contains("alpha") || self.version.contains("beta")
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
use tower_lsp::lsp_types::{Position, Range, Url};

/// Parse result containing dependencies and metadata.
#[derive(Debug)]
pub struct {Ecosystem}ParseResult {
    pub dependencies: Vec<{Ecosystem}Dependency>,
    pub uri: Url,
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

    fn uri(&self) -> &Url {
        &self.uri
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Line offset table for O(log n) position lookups.
struct LineOffsetTable {
    offsets: Vec<usize>,
}

impl LineOffsetTable {
    fn new(content: &str) -> Self {
        let mut offsets = vec![0];
        for (i, c) in content.char_indices() {
            if c == '\n' {
                offsets.push(i + 1);
            }
        }
        Self { offsets }
    }

    fn position_from_offset(&self, offset: usize) -> Position {
        let line = match self.offsets.binary_search(&offset) {
            Ok(line) => line,
            Err(line) => line.saturating_sub(1),
        };
        let character = (offset - self.offsets[line]) as u32;
        Position::new(line as u32, character)
    }
}

/// Parse manifest file and extract dependencies with positions.
pub fn parse_{manifest}(content: &str, uri: &Url) -> Result<{Ecosystem}ParseResult> {
    let line_table = LineOffsetTable::new(content);

    // TODO: Implement actual parsing logic
    // Key requirements:
    // 1. Track byte offsets for every dependency name and version
    // 2. Convert offsets to LSP Position using LineOffsetTable
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
use deps_core::HttpCache;
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

    /// Fetch all versions for a package.
    pub async fn get_versions(&self, name: &str) -> Result<Vec<{Ecosystem}Version>> {
        let url = format!("{}/{}", REGISTRY_URL, urlencoding::encode(name));

        let data = self.cache
            .get_cached(&url)
            .await
            .map_err(|e| crate::error::{Ecosystem}Error::CacheError(e.to_string()))?;

        // TODO: Parse response and return versions
        Ok(vec![])
    }

    /// Get latest version matching a requirement.
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

// Implement deps_core::Registry trait
#[async_trait::async_trait]
impl deps_core::Registry for {Ecosystem}Registry {
    async fn get_versions(&self, name: &str) -> deps_core::Result<Vec<Box<dyn deps_core::Version>>> {
        let versions = self.get_versions(name).await?;
        Ok(versions
            .into_iter()
            .map(|v| Box::new(v) as Box<dyn deps_core::Version>)
            .collect())
    }

    async fn get_latest_matching(
        &self,
        name: &str,
        version_req: &str,
    ) -> deps_core::Result<Option<Box<dyn deps_core::Version>>> {
        let version = self.get_latest_matching(name, version_req).await?;
        Ok(version.map(|v| Box::new(v) as Box<dyn deps_core::Version>))
    }
}
```

## Step 6: Implement the Ecosystem Trait

Create the main ecosystem implementation in `ecosystem.rs`:

```rust
//! {Ecosystem} implementation for deps-lsp.

use async_trait::async_trait;
use std::any::Any;
use std::collections::HashMap;
use std::sync::Arc;
use tower_lsp::lsp_types::*;

use deps_core::{
    Ecosystem, EcosystemConfig, HttpCache,
    ParseResult as ParseResultTrait, Registry, Result,
};

use crate::parser::parse_{manifest};
use crate::registry::{Ecosystem}Registry;

/// {Ecosystem} implementation.
pub struct {Ecosystem}Ecosystem {
    registry: Arc<{Ecosystem}Registry>,
}

impl {Ecosystem}Ecosystem {
    pub fn new(cache: Arc<HttpCache>) -> Self {
        Self {
            registry: Arc::new({Ecosystem}Registry::new(cache)),
        }
    }
}

#[async_trait]
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

    async fn parse_manifest(
        &self,
        content: &str,
        uri: &Url,
    ) -> Result<Box<dyn ParseResultTrait>> {
        let result = parse_{manifest}(content, uri)?;
        Ok(Box::new(result))
    }

    fn registry(&self) -> Arc<dyn Registry> {
        self.registry.clone()
    }

    async fn generate_inlay_hints(
        &self,
        parse_result: &dyn ParseResultTrait,
        cached_versions: &HashMap<String, String>,
        config: &EcosystemConfig,
    ) -> Vec<InlayHint> {
        let mut hints = Vec::new();

        for dep in parse_result.dependencies() {
            let Some(version_range) = dep.version_range() else {
                continue;
            };

            let Some(latest) = cached_versions.get(dep.name()) else {
                continue;
            };

            let current = dep.version_requirement().unwrap_or("");
            let is_up_to_date = /* implement version comparison */;

            let label = if is_up_to_date {
                if config.show_up_to_date_hints {
                    config.up_to_date_text.clone()
                } else {
                    continue;
                }
            } else {
                config.needs_update_text.replace("{}", latest)
            };

            hints.push(InlayHint {
                position: version_range.end,
                label: InlayHintLabel::String(label),
                kind: Some(InlayHintKind::TYPE),
                padding_left: Some(true),
                padding_right: None,
                text_edits: None,
                tooltip: None,
                data: None,
            });
        }

        hints
    }

    async fn generate_hover(
        &self,
        parse_result: &dyn ParseResultTrait,
        position: Position,
        cached_versions: &HashMap<String, String>,
    ) -> Option<Hover> {
        // Find dependency at position
        let dep = parse_result
            .dependencies()
            .into_iter()
            .find(|d| position_in_range(position, d.name_range()))?;

        let versions = self.registry.get_versions(dep.name()).await.ok()?;

        // Build hover markdown
        let mut markdown = format!("# {}\n\n", dep.name());

        if let Some(req) = dep.version_requirement() {
            markdown.push_str(&format!("**Current**: `{}`\n\n", req));
        }

        if let Some(latest) = cached_versions.get(dep.name()) {
            markdown.push_str(&format!("**Latest**: `{}`\n\n", latest));
        }

        markdown.push_str("**Recent versions**:\n");
        for version in versions.iter().take(8) {
            markdown.push_str(&format!("- {}\n", version.version_string()));
        }

        Some(Hover {
            contents: HoverContents::Markup(MarkupContent {
                kind: MarkupKind::Markdown,
                value: markdown,
            }),
            range: Some(dep.name_range()),
        })
    }

    async fn generate_code_actions(
        &self,
        parse_result: &dyn ParseResultTrait,
        position: Position,
        _cached_versions: &HashMap<String, String>,
        uri: &Url,
    ) -> Vec<CodeAction> {
        // Similar pattern: find dep at position, offer version updates
        vec![]
    }

    async fn generate_diagnostics(
        &self,
        parse_result: &dyn ParseResultTrait,
        _cached_versions: &HashMap<String, String>,
        _uri: &Url,
    ) -> Vec<Diagnostic> {
        // Check for unknown packages, outdated versions, etc.
        vec![]
    }

    async fn generate_completions(
        &self,
        _parse_result: &dyn ParseResultTrait,
        _position: Position,
        _content: &str,
    ) -> Vec<CompletionItem> {
        vec![]
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

fn position_in_range(pos: Position, range: Range) -> bool {
    !(range.end.line < pos.line
        || (range.end.line == pos.line && range.end.character < pos.character)
        || pos.line < range.start.line
        || (pos.line == range.start.line && pos.character < range.start.character))
}
```

## Step 7: Create lib.rs

Expose public API in `lib.rs`:

```rust
//! {Ecosystem} support for deps-lsp.

pub mod ecosystem;
pub mod error;
pub mod lockfile;  // if implemented
pub mod parser;
pub mod registry;
pub mod types;

pub use ecosystem::{Ecosystem}Ecosystem;
pub use error::{Ecosystem}Error, Result;
pub use parser::parse_{manifest};
pub use registry::{Ecosystem}Registry;
pub use types::{{Ecosystem}Dependency, {Ecosystem}Version};
```

## Step 8: Register the Ecosystem

In `deps-lsp/src/document.rs`, register your ecosystem:

```rust
impl ServerState {
    pub fn new() -> Self {
        let cache = Arc::new(HttpCache::new());
        let mut registry = EcosystemRegistry::new();

        // Register existing ecosystems
        registry.register(Arc::new(CargoEcosystem::new(Arc::clone(&cache))));
        registry.register(Arc::new(NpmEcosystem::new(Arc::clone(&cache))));
        registry.register(Arc::new(PypiEcosystem::new(Arc::clone(&cache))));

        // Register your new ecosystem
        registry.register(Arc::new({Ecosystem}Ecosystem::new(Arc::clone(&cache))));

        Self {
            documents: DashMap::new(),
            background_tasks: tokio::sync::RwLock::new(HashMap::new()),
            ecosystem_registry: registry,
            http_cache: cache,
        }
    }
}
```

## Step 9: Add Tests

Create comprehensive tests:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn test_uri() -> Url {
        Url::parse("file:///test/{manifest_file}").unwrap()
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
- [ ] Types implementing `Dependency` and `Version` traits
- [ ] Parser with accurate position tracking for names AND versions
- [ ] Registry client with HTTP caching
- [ ] Ecosystem trait implementation with all LSP features
- [ ] Unit tests for parser edge cases
- [ ] Integration tests for registry (can be `#[ignore]`)
- [ ] Documentation in lib.rs with examples
- [ ] Added to workspace members in root Cargo.toml
- [ ] Registered in `ServerState::new()`

## Examples

See existing implementations for reference:
- `crates/deps-cargo/` - Rust/Cargo.toml with crates.io
- `crates/deps-npm/` - JavaScript/package.json with npm
- `crates/deps-pypi/` - Python/pyproject.toml with PyPI
