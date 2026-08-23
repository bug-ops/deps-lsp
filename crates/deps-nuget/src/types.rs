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
}

deps_core::impl_dependency!(NuGetDependency {
    name: name,
    name_range: name_range,
    version: version_requirement,
    version_range: version_range,
});

/// Parsed result of a single manifest file (`.csproj`, `Directory.Packages.props`,
/// `packages.config`).
#[derive(Debug)]
pub struct NuGetParseResult {
    pub dependencies: Vec<NuGetDependency>,
    pub uri: Uri,
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
/// Deliberately a single field. `is_yanked` always reports `false` because the flat
/// container carries no `listed` flag — unlisted detection requires the registration
/// hive and is deferred (spec §1, follow-up D1) to hover-only enrichment.
///
/// Hand-writes `deps_core::Version` instead of using `impl_version!` because the macro's
/// `is_prerelease` cannot be overridden and the shared default (a keyword sniff for
/// `-alpha|-beta|-rc|-dev|-pre|-snapshot|-canary|-nightly`) does not recognize standard
/// .NET prerelease labels (`-rtm`, `-servicing.23`, `-CI-*`, `-final`, ...). This follows
/// the same precedent as `deps-maven`'s and `deps-go`'s hand-written `Version` impls for
/// ecosystems with a structural (non-keyword) prerelease convention.
#[derive(Debug, Clone)]
pub struct NuGetVersion {
    pub version: String,
}

impl deps_core::Version for NuGetVersion {
    fn version_string(&self) -> &str {
        &self.version
    }

    fn is_yanked(&self) -> bool {
        false
    }

    fn is_prerelease(&self) -> bool {
        crate::version::is_prerelease(&self.version)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Package metadata from a NuGet search result.
#[derive(Debug, Clone)]
pub struct PackageInfo {
    pub name: String,
    pub description: Option<String>,
    pub repository: Option<String>,
    pub documentation: Option<String>,
    pub latest_version: String,
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
    use tower_lsp_server::ls_types::Position;

    fn test_dep() -> NuGetDependency {
        NuGetDependency {
            name: "Newtonsoft.Json".into(),
            name_range: Range::new(Position::new(2, 4), Position::new(2, 20)),
            version_requirement: Some("13.0.3".into()),
            version_range: Some(Range::new(Position::new(2, 30), Position::new(2, 36))),
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
        assert!(matches!(
            dep.source(),
            deps_core::parser::DependencySource::Registry
        ));
    }

    #[test]
    fn test_dependency_without_version() {
        use deps_core::Dependency;

        let dep = NuGetDependency {
            name: "MyCompany.Shared".into(),
            name_range: Range::default(),
            version_requirement: None,
            version_range: None,
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
        };
        assert_eq!(ver.version_string(), "13.0.3");
        assert!(!ver.is_yanked());
        assert!(!ver.is_prerelease());
        assert!(ver.as_any().is::<NuGetVersion>());
    }

    #[test]
    fn test_version_prerelease_dotnet_label() {
        use deps_core::Version;

        // Real .NET label that the shared keyword-sniff default would misclassify as stable.
        let ver = NuGetVersion {
            version: "13.0.0-rtm".into(),
        };
        assert!(ver.is_prerelease());
        assert!(!ver.is_stable());
    }

    #[test]
    fn test_version_never_yanked() {
        use deps_core::Version;

        let ver = NuGetVersion {
            version: "1.0.0".into(),
        };
        assert!(!ver.is_yanked());
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
