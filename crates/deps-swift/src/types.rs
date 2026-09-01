//! Swift/SPM dependency types.

use deps_core::parser::DependencySource;
use tower_lsp_server::ls_types::Range;

/// Parsed dependency from Package.swift with position tracking.
///
/// Package names use `owner/repo` format derived from the Git URL.
/// Position tracking enables hover, completion, and inlay hints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwiftDependency {
    /// Package identity: owner/repo (e.g. "apple/swift-nio")
    pub name: deps_core::PackageName,
    /// LSP range of the URL string content (excluding quotes)
    pub name_range: Range,
    /// Normalized version requirement or None for branch/revision/path deps
    pub version_req: Option<deps_core::VersionReq>,
    /// LSP range of the version string content (excluding quotes), None for non-registry deps
    pub version_range: Option<Range>,
    /// The bare literal text `version_range` spans (e.g. `"4.50.0"`), when it differs from
    /// `version_req` — every registry-form syntax synthesizes a comparator requirement
    /// (`.exact("4.50.0")` -> `"=4.50.0"`, `.upToNextMajor(from: "4.77.0")` ->
    /// `">=4.77.0, <5.0.0"`) that never matches the bare literal text at `version_range`.
    /// `None` for branch/revision/path deps, which have no `version_range` to guard.
    pub version_literal: Option<String>,
    /// Original Git URL from Package.swift
    pub url: String,
    /// Dependency source (registry, git, or path)
    pub source: DependencySource,
}

impl deps_core::ecosystem::Dependency for SwiftDependency {
    fn name(&self) -> &deps_core::PackageName {
        &self.name
    }

    fn name_range(&self) -> tower_lsp_server::ls_types::Range {
        self.name_range
    }

    fn version_requirement(&self) -> Option<&deps_core::VersionReq> {
        self.version_req.as_ref()
    }

    fn version_range(&self) -> Option<tower_lsp_server::ls_types::Range> {
        self.version_range
    }

    fn source(&self) -> DependencySource {
        self.source.clone()
    }

    fn version_literal(&self) -> Option<&str> {
        self.version_literal.as_deref()
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// Version information for a Swift package (GitHub tag).
#[derive(Debug, Clone)]
pub struct SwiftVersion {
    /// Semver version string (v prefix stripped)
    pub version: deps_core::ConcreteVersion,
    /// Always false for GitHub tags
    pub yanked: bool,
    /// GitHub Release publish time for this tag, if a matching Release exists
    /// among the newest ~100 (see `SwiftRegistry::release_dates`). `None` for a
    /// tag-only version or one outside that window — never a wrong date (#223).
    pub published_at: Option<deps_core::PublishTime>,
    /// Whether the tag's semver `pre` component is non-empty, computed once
    /// from the `semver::Version` already parsed by `tags_to_versions` (#327 M5).
    pub prerelease: bool,
}

// `prerelease` is threaded from the single semver parse `tags_to_versions`
// already performs and discards, instead of re-parsing `version` on every
// `is_prerelease()` call (#327 M5). GitHub release tags are parsed as strict
// semver (the `v` prefix already stripped) there, so this reflects a
// reliable `pre` component instead of falling back to deps-core's default
// hyphen-substring heuristic (#322).
deps_core::impl_version!(SwiftVersion {
    version: version,
    status: |v: &SwiftVersion| deps_core::RemovalStatus::from_yanked(v.yanked),
    published_at: published_at,
    prerelease: |v: &SwiftVersion| v.prerelease,
});

/// Package metadata from GitHub API.
#[derive(Debug, Clone)]
pub struct SwiftPackage {
    /// owner/repo identity
    pub name: deps_core::PackageName,
    /// GitHub repo description
    pub description: Option<String>,
    /// GitHub URL
    pub repository: Option<String>,
    /// GitHub URL (same as repository)
    pub homepage: Option<String>,
    /// Latest semver tag
    pub latest_version: deps_core::ConcreteVersion,
}

deps_core::impl_metadata!(SwiftPackage {
    name: name,
    description: description,
    repository: repository,
    documentation: homepage,
    latest_version: latest_version,
});

/// Result of parsing a Package.swift file.
#[derive(Debug)]
pub struct SwiftParseResult {
    pub dependencies: Vec<SwiftDependency>,
    pub uri: tower_lsp_server::ls_types::Uri,
}

impl deps_core::ParseResult for SwiftParseResult {
    fn dependencies(&self) -> Vec<&dyn deps_core::Dependency> {
        self.dependencies
            .iter()
            .map(|d| d as &dyn deps_core::Dependency)
            .collect()
    }

    fn workspace_root(&self) -> Option<&std::path::Path> {
        None
    }

    fn uri(&self) -> &tower_lsp_server::ls_types::Uri {
        &self.uri
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use deps_core::{Dependency, Metadata, Version};
    use tower_lsp_server::ls_types::Position;

    #[test]
    fn test_swift_dependency_registry() {
        let dep = SwiftDependency {
            name: "apple/swift-nio".into(),
            name_range: Range::new(Position::new(0, 0), Position::new(0, 15)),
            version_req: Some(">=2.0.0, <3.0.0".into()),
            version_range: Some(Range::new(Position::new(0, 20), Position::new(0, 27))),
            version_literal: Some("2.0.0".into()),
            url: "https://github.com/apple/swift-nio.git".into(),
            source: DependencySource::Registry,
        };

        assert_eq!(dep.name(), "apple/swift-nio");
        assert_eq!(
            dep.version_requirement().map(deps_core::VersionReq::as_str),
            Some(">=2.0.0, <3.0.0")
        );
        assert!(matches!(dep.source(), DependencySource::Registry));
    }

    #[test]
    fn test_swift_version() {
        let ver = SwiftVersion {
            version: "2.40.0".into(),
            yanked: false,
            published_at: None,
            prerelease: false,
        };
        assert_eq!(ver.version_string(), "2.40.0");
        assert!(!ver.removal_status().blocks_resolution());
    }

    #[test]
    fn test_swift_version_is_prerelease() {
        let stable = SwiftVersion {
            version: "2.40.0".into(),
            yanked: false,
            published_at: None,
            prerelease: false,
        };
        let prerelease = SwiftVersion {
            version: "2.40.0-beta.1".into(),
            yanked: false,
            published_at: None,
            prerelease: true,
        };

        assert!(!stable.is_prerelease());
        assert!(stable.is_stable());
        assert!(prerelease.is_prerelease());
        assert!(!prerelease.is_stable());
    }

    #[test]
    fn test_swift_package_metadata() {
        let pkg = SwiftPackage {
            name: "apple/swift-nio".into(),
            description: Some("Networking framework".into()),
            repository: Some("https://github.com/apple/swift-nio".into()),
            homepage: Some("https://github.com/apple/swift-nio".into()),
            latest_version: "2.62.0".into(),
        };
        assert_eq!(pkg.name(), "apple/swift-nio");
        assert_eq!(pkg.description(), Some("Networking framework"));
        assert_eq!(pkg.latest_version(), "2.62.0");
    }
}
