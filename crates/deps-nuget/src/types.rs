//! Domain types for NuGet/.NET project dependencies.

use std::any::Any;
use tower_lsp_server::ls_types::{Range, Uri};

/// A single `PackageReference` / `PackageVersion` / `package` entry from a manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NuGetDependency {
    pub name: deps_core::PackageName,
    pub name_range: Range,
    /// Absent when the manifest omits an explicit version — central package management
    /// entries and unresolvable MSBuild property expressions (`$(...)`) both degrade to
    /// `None` rather than a bogus or unresolved-looking requirement.
    pub version_requirement: Option<deps_core::VersionReq>,
    pub version_range: Option<Range>,
    /// Resolved against the manifest's `NuGet.Config` `<packageSources>`/
    /// `<packageSourceMapping>` (issue #523) by `NuGetEcosystem::parse_manifest`, after
    /// parsing — every parser in `parser.rs` stays config-blind and always constructs this as
    /// `DependencySource::Registry`.
    pub source: deps_core::parser::DependencySource,
}

// Hand-written, not `impl_dependency!`: the macro's `source: $source:expr` arm substitutes
// the expression into a generated `fn source(&self)` body, so `self.source.clone()` cannot be
// passed through it — see `deps-npm/src/types.rs`'s identical precedent/comment.
impl deps_core::Dependency for NuGetDependency {
    fn name(&self) -> &deps_core::PackageName {
        &self.name
    }

    fn name_range(&self) -> Range {
        self.name_range
    }

    fn version_requirement(&self) -> Option<&deps_core::VersionReq> {
        self.version_requirement.as_ref()
    }

    fn version_range(&self) -> Option<Range> {
        self.version_range
    }

    fn source(&self) -> deps_core::parser::DependencySource {
        self.source.clone()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Parsed result of a single manifest file (`.csproj`, `Directory.Packages.props`,
/// `packages.config`).
#[derive(Debug)]
pub struct NuGetParseResult {
    pub dependencies: Vec<NuGetDependency>,
    pub uri: Uri,
    /// Every routing chain this manifest's resolved `NuGet.Config` implies (issue #523) — one
    /// per distinct `<packageSourceMapping>` hop-set, or the single plain accumulated chain
    /// when no mapping is declared. Registered against the shared `NuGetRegistry` by
    /// `NuGetEcosystem::parse_manifest`; empty when nothing is registrable (no config, or
    /// every dependency resolves to plain `Registry`/a fail-closed `CustomRegistry`).
    pub resolved_chains: Vec<crate::config::NuGetSourceChain>,
}

deps_core::impl_parse_result!(
    NuGetParseResult,
    NuGetDependency {
        dependencies: dependencies,
        uri: uri,
    }
);

/// A single version of a package, as returned by the NuGet flat-container endpoint.
///
/// Deliberately a single field. `removal_status` always reports `Available` (the
/// trait default, no override here) because the flat container carries no `listed`
/// flag — unlisted detection requires the registration hive and is deferred (spec
/// §1, follow-up D1) to hover-only enrichment.
///
/// Hand-writes `deps_core::Version` instead of using `impl_version!` because the macro's
/// `is_prerelease` cannot be overridden and the shared default (a keyword sniff for
/// `-alpha|-beta|-rc|-dev|-pre|-snapshot|-canary|-nightly`) does not recognize standard
/// .NET prerelease labels (`-rtm`, `-servicing.23`, `-CI-*`, `-final`, ...). This follows
/// the same precedent as `deps-maven`'s and `deps-go`'s hand-written `Version` impls for
/// ecosystems with a structural (non-keyword) prerelease convention.
#[derive(Debug, Clone)]
pub struct NuGetVersion {
    pub version: deps_core::ConcreteVersion,
    /// Publish timestamp, populated only when `Registry::get_versions_with` is called with
    /// freshness enabled and the version was covered by the registration-hive walk.
    pub published_at: Option<deps_core::PublishTime>,
}

impl deps_core::Version for NuGetVersion {
    fn version_string(&self) -> &deps_core::ConcreteVersion {
        &self.version
    }

    fn is_prerelease(&self) -> bool {
        crate::version::is_prerelease(self.version.as_str())
    }

    fn published_at(&self) -> Option<deps_core::PublishTime> {
        self.published_at
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Package metadata from a NuGet search result.
#[derive(Debug, Clone)]
pub struct PackageInfo {
    pub name: deps_core::PackageName,
    pub description: Option<String>,
    pub repository: Option<String>,
    pub documentation: Option<String>,
    pub latest_version: deps_core::ConcreteVersion,
}

deps_core::impl_metadata!(PackageInfo {
    name: name,
    description: description,
    repository: repository,
    documentation: documentation,
    latest_version: latest_version,
});

#[cfg(test)]
mod tests {
    use super::*;
    use std::assert_matches;
    use tower_lsp_server::ls_types::Position;

    fn test_dep() -> NuGetDependency {
        NuGetDependency {
            name: "Newtonsoft.Json".into(),
            name_range: Range::new(Position::new(2, 4), Position::new(2, 20)),
            version_requirement: Some("13.0.3".into()),
            version_range: Some(Range::new(Position::new(2, 30), Position::new(2, 36))),
            source: deps_core::parser::DependencySource::Registry,
        }
    }

    #[test]
    fn test_dependency_trait() {
        use deps_core::Dependency;

        let dep = test_dep();
        assert_eq!(dep.name(), "Newtonsoft.Json");
        assert_eq!(
            dep.version_requirement().map(deps_core::VersionReq::as_str),
            Some("13.0.3")
        );
        assert!(dep.features().is_empty());
        assert!(dep.as_any().is::<NuGetDependency>());
        assert_matches!(dep.source(), deps_core::parser::DependencySource::Registry);
    }

    #[test]
    fn test_dependency_without_version() {
        use deps_core::Dependency;

        let dep = NuGetDependency {
            name: "MyCompany.Shared".into(),
            name_range: Range::default(),
            version_requirement: None,
            version_range: None,
            source: deps_core::parser::DependencySource::Registry,
        };
        assert!(dep.version_requirement().is_none());
        assert!(dep.version_range().is_none());
    }

    #[test]
    fn test_parse_result_trait() {
        use deps_core::ParseResult;

        let result = NuGetParseResult {
            dependencies: vec![test_dep()],
            uri: deps_core::test_util::test_uri("/test/App.csproj"),
            resolved_chains: Vec::new(),
        };

        assert_eq!(result.dependencies().len(), 1);
        assert!(result.workspace_root().is_none());
        assert!(result.as_any().is::<NuGetParseResult>());
    }

    #[test]
    fn test_version_trait() {
        use deps_core::Version;

        let ver = NuGetVersion {
            version: "13.0.3".into(),
            published_at: None,
        };
        assert_eq!(ver.version_string(), "13.0.3");
        assert!(!ver.removal_status().blocks_resolution());
        assert!(!ver.is_prerelease());
        assert!(ver.as_any().is::<NuGetVersion>());
    }

    #[test]
    fn test_version_prerelease_dotnet_label() {
        use deps_core::Version;

        // Real .NET label that the shared keyword-sniff default would misclassify as stable.
        let ver = NuGetVersion {
            version: "13.0.0-rtm".into(),
            published_at: None,
        };
        assert!(ver.is_prerelease());
        assert!(!ver.is_stable());
    }

    #[test]
    fn test_version_never_yanked() {
        use deps_core::Version;

        let ver = NuGetVersion {
            version: "1.0.0".into(),
            published_at: None,
        };
        assert!(!ver.removal_status().blocks_resolution());
    }

    #[test]
    fn test_metadata_trait() {
        use deps_core::Metadata;

        let info = PackageInfo {
            name: "Newtonsoft.Json".into(),
            description: Some("Popular high-performance JSON framework".into()),
            repository: None,
            documentation: None,
            latest_version: "13.0.3".into(),
        };
        assert_eq!(info.name(), "Newtonsoft.Json");
        assert_eq!(
            info.description(),
            Some("Popular high-performance JSON framework")
        );
        assert_eq!(info.latest_version(), "13.0.3");
        assert!(info.repository().is_none());
        assert!(info.as_any().is::<PackageInfo>());
    }
}
