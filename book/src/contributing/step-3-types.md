# Step 3: Define Types

Create ecosystem-specific types in `types.rs`. **Every public type must be prefixed with
`<Ecosystem>`** (e.g. `NpmDependency`, `NpmParseResult`, `NpmDependencySection` — not bare
`Dependency`, `ParseResult`, `DependencySection`), matching the convention every ecosystem
crate now follows (`deps-cargo` was the sole historical exception, fixed in #760).

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
    pub version: deps_core::ConcreteVersion,
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
    fn version_string(&self) -> &deps_core::ConcreteVersion {
        &self.version
    }

    fn is_yanked(&self) -> bool {
        self.yanked
    }

    fn is_prerelease(&self) -> bool {
        // Implement based on ecosystem's prerelease conventions
        let version = self.version.as_str();
        version.contains('-') || version.contains("alpha") || version.contains("beta")
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
```

