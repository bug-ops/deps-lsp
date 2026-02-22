//! Domain types for Maven/pom.xml dependencies.

use std::any::Any;
use tower_lsp_server::ls_types::Range;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MavenDependency {
    pub group_id: String,
    pub artifact_id: String,
    /// Canonical identifier: "{groupId}:{artifactId}"
    pub name: String,
    pub name_range: Range,
    pub version_req: Option<String>,
    pub version_range: Option<Range>,
    pub scope: MavenScope,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum MavenScope {
    #[default]
    Compile,
    Test,
    Runtime,
    Provided,
    System,
    Import,
}

impl std::str::FromStr for MavenScope {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Ok(match s.to_lowercase().as_str() {
            "test" => Self::Test,
            "runtime" => Self::Runtime,
            "provided" => Self::Provided,
            "system" => Self::System,
            "import" => Self::Import,
            _ => Self::Compile,
        })
    }
}

#[derive(Debug, Clone)]
pub struct MavenVersion {
    pub version: String,
    pub timestamp: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct ArtifactInfo {
    pub group_id: String,
    pub artifact_id: String,
    /// "{groupId}:{artifactId}"
    pub name: String,
    pub description: Option<String>,
    pub latest_version: String,
    pub repository: Option<String>,
}

// deps-core trait implementations

impl deps_core::DependencyInfo for MavenDependency {
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

    fn source(&self) -> deps_core::parser::DependencySource {
        deps_core::parser::DependencySource::Registry
    }

    fn features(&self) -> &[String] {
        &[]
    }
}

impl deps_core::Dependency for MavenDependency {
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

    fn source(&self) -> deps_core::parser::DependencySource {
        deps_core::parser::DependencySource::Registry
    }

    fn features(&self) -> &[String] {
        &[]
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl deps_core::Version for MavenVersion {
    fn version_string(&self) -> &str {
        &self.version
    }

    fn is_yanked(&self) -> bool {
        // Maven Central does not support version retraction
        false
    }

    fn is_prerelease(&self) -> bool {
        crate::version::is_prerelease(&self.version)
    }

    fn features(&self) -> Vec<String> {
        vec![]
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl deps_core::Metadata for ArtifactInfo {
    fn name(&self) -> &str {
        &self.name
    }

    fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    fn repository(&self) -> Option<&str> {
        self.repository.as_deref()
    }

    fn documentation(&self) -> Option<&str> {
        None
    }

    fn latest_version(&self) -> &str {
        &self.latest_version
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tower_lsp_server::ls_types::Position;

    fn test_dep() -> MavenDependency {
        MavenDependency {
            group_id: "org.apache.commons".into(),
            artifact_id: "commons-lang3".into(),
            name: "org.apache.commons:commons-lang3".into(),
            name_range: Range::new(Position::new(5, 4), Position::new(5, 17)),
            version_req: Some("3.14.0".into()),
            version_range: Some(Range::new(Position::new(7, 13), Position::new(7, 19))),
            scope: MavenScope::Compile,
        }
    }

    #[test]
    fn test_scope_variants() {
        use std::str::FromStr;
        assert!(matches!(
            "test".parse::<MavenScope>().unwrap(),
            MavenScope::Test
        ));
        assert!(matches!(
            "runtime".parse::<MavenScope>().unwrap(),
            MavenScope::Runtime
        ));
        assert!(matches!(
            "provided".parse::<MavenScope>().unwrap(),
            MavenScope::Provided
        ));
        assert!(matches!(
            "system".parse::<MavenScope>().unwrap(),
            MavenScope::System
        ));
        assert!(matches!(
            "import".parse::<MavenScope>().unwrap(),
            MavenScope::Import
        ));
        assert!(matches!(
            "compile".parse::<MavenScope>().unwrap(),
            MavenScope::Compile
        ));
        assert!(matches!(
            "unknown".parse::<MavenScope>().unwrap(),
            MavenScope::Compile
        ));
        let _ = MavenScope::from_str; // ensure trait is accessible
    }

    #[test]
    fn test_scope_default() {
        assert!(matches!(MavenScope::default(), MavenScope::Compile));
    }

    #[test]
    fn test_dependency_trait() {
        use deps_core::Dependency;

        let dep = test_dep();
        assert_eq!(dep.name(), "org.apache.commons:commons-lang3");
        assert_eq!(dep.version_requirement(), Some("3.14.0"));
        assert!(dep.features().is_empty());
        assert!(dep.as_any().is::<MavenDependency>());
        assert!(matches!(
            dep.source(),
            deps_core::parser::DependencySource::Registry
        ));
    }

    #[test]
    fn test_dependency_info_trait() {
        use deps_core::DependencyInfo;

        let dep = test_dep();
        assert_eq!(dep.name(), "org.apache.commons:commons-lang3");
        assert!(dep.version_range().is_some());
        assert!(matches!(
            dep.source(),
            deps_core::parser::DependencySource::Registry
        ));
    }

    #[test]
    fn test_dependency_without_version() {
        use deps_core::Dependency;

        let dep = MavenDependency {
            group_id: "com.example".into(),
            artifact_id: "test".into(),
            name: "com.example:test".into(),
            name_range: Range::default(),
            version_req: None,
            version_range: None,
            scope: MavenScope::Compile,
        };
        assert!(dep.version_requirement().is_none());
        assert!(dep.version_range().is_none());
    }

    #[test]
    fn test_version_trait() {
        use deps_core::Version;

        let ver = MavenVersion {
            version: "3.14.0".into(),
            timestamp: Some(1_699_000_000),
        };
        assert_eq!(ver.version_string(), "3.14.0");
        assert!(!ver.is_yanked());
        assert!(!ver.is_prerelease());
        assert!(ver.features().is_empty());
        assert!(ver.as_any().is::<MavenVersion>());
    }

    #[test]
    fn test_version_prerelease() {
        use deps_core::Version;

        let ver = MavenVersion {
            version: "1.0.0-SNAPSHOT".into(),
            timestamp: None,
        };
        assert!(ver.is_prerelease());

        let ver = MavenVersion {
            version: "2.0.0-M1".into(),
            timestamp: None,
        };
        assert!(ver.is_prerelease());
    }

    #[test]
    fn test_metadata_trait() {
        use deps_core::Metadata;

        let info = ArtifactInfo {
            group_id: "org.apache.commons".into(),
            artifact_id: "commons-lang3".into(),
            name: "org.apache.commons:commons-lang3".into(),
            description: Some("Apache Commons Lang".into()),
            latest_version: "3.14.0".into(),
            repository: None,
        };
        assert_eq!(info.name(), "org.apache.commons:commons-lang3");
        assert_eq!(info.description(), Some("Apache Commons Lang"));
        assert_eq!(info.latest_version(), "3.14.0");
        assert!(info.repository().is_none());
        assert!(info.documentation().is_none());
        assert!(info.as_any().is::<ArtifactInfo>());
    }
}
