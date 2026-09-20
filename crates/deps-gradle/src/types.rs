//! Domain types for Gradle dependencies.

use deps_core::position::Range;

pub use deps_maven::MavenVersion as GradleVersion;

/// A single dependency declaration parsed from a Gradle build script.
#[non_exhaustive]
#[derive(Clone, PartialEq, Eq)]
pub struct GradleDependency {
    /// Maven `groupId`.
    pub group_id: String,
    /// Maven `artifactId`.
    pub artifact_id: String,
    /// Canonical identifier: "{groupId}:{artifactId}"
    pub name: deps_core::PackageName,
    /// Document range of the coordinate, for hover/diagnostic positioning.
    pub name_range: Range,
    /// Version requirement, if the build script specifies one.
    pub version_req: Option<deps_core::VersionReq>,
    /// Document range of the version string.
    pub version_range: Option<Range>,
    /// Gradle configuration (e.g. "implementation", "api", "testImplementation")
    pub configuration: String,
    /// Resolved source (#1212): `Registry` unless a `repositories { }` block declares a
    /// repository whose `content { includeGroup(...) }` (or `includeGroupByRegex`/
    /// `includeModule`) restriction statically binds this dependency's group/module to it
    /// (see `parser::parse_repository_content_restrictions`). General-purpose `repositories
    /// { }` evaluation (an arbitrary repo with no content filter) has no static per-package
    /// binding in the Gradle DSL at all, so those stay `Registry`.
    pub source: deps_core::parser::DependencySource,
}

impl std::fmt::Debug for GradleDependency {
    /// Manual, not derived: same `group_id`/`artifact_id` leak class as
    /// `deps_maven::MavenDependency`'s manual `Debug` impl (#1220).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GradleDependency")
            .field(
                "group_id",
                &deps_core::net_policy::redact_declaration_key(&self.group_id),
            )
            .field(
                "artifact_id",
                &deps_core::net_policy::redact_declaration_key(&self.artifact_id),
            )
            .field("name", &self.name)
            .field("name_range", &self.name_range)
            .field("version_req", &self.version_req)
            .field("version_range", &self.version_range)
            .field("configuration", &self.configuration)
            .field("source", &self.source)
            .finish()
    }
}

deps_core::impl_dependency!(GradleDependency {
    name: name,
    name_range: name_range,
    version: version_req,
    version_range: version_range,
    source: source,
});

#[cfg(test)]
mod tests {
    use super::*;
    use deps_core::position::Position;
    use std::assert_matches;

    fn test_dep() -> GradleDependency {
        GradleDependency {
            group_id: "org.springframework.boot".into(),
            artifact_id: "spring-boot-starter".into(),
            name: "org.springframework.boot:spring-boot-starter".into(),
            name_range: Range::new(Position::new(5, 4), Position::new(5, 30)),
            version_req: Some("3.2.0".into()),
            version_range: Some(Range::new(Position::new(5, 35), Position::new(5, 40))),
            configuration: "implementation".into(),
            source: deps_core::parser::DependencySource::Registry,
        }
    }

    #[test]
    fn test_dependency_trait() {
        use deps_core::Dependency;

        let dep = test_dep();
        assert_eq!(dep.name(), "org.springframework.boot:spring-boot-starter");
        assert_eq!(
            dep.version_requirement().map(deps_core::VersionReq::as_str),
            Some("3.2.0")
        );
        assert!(dep.features().is_empty());
        assert!(dep.as_any().is::<GradleDependency>());
        assert_matches!(dep.source(), deps_core::parser::DependencySource::Registry);
    }

    #[test]
    fn test_dependency_info_trait() {
        use deps_core::Dependency;

        let dep = test_dep();
        assert_eq!(dep.name(), "org.springframework.boot:spring-boot-starter");
        assert!(dep.version_range().is_some());
        assert_matches!(dep.source(), deps_core::parser::DependencySource::Registry);
    }

    #[test]
    fn test_dependency_without_version() {
        use deps_core::Dependency;

        let dep = GradleDependency {
            group_id: "com.example".into(),
            artifact_id: "test".into(),
            name: "com.example:test".into(),
            name_range: Range::default(),
            version_req: None,
            version_range: None,
            configuration: "api".into(),
            source: deps_core::parser::DependencySource::Registry,
        };
        assert!(dep.version_requirement().is_none());
        assert!(dep.version_range().is_none());
    }

    /// `GradleVersion` is a re-export of `deps_maven::MavenVersion` (see the `pub use` at
    /// the top of this module), not a type this crate defines — so `published_at` is wired
    /// by construction rather than by anything `deps-gradle` implements itself. This test
    /// exists so a future change that breaks the re-export (e.g. swapping it for a
    /// gradle-specific newtype) fails loudly here instead of silently losing freshness data.
    #[test]
    fn test_gradle_version_published_at_is_wired_through_the_maven_reexport() {
        use deps_core::Version;

        let published = deps_core::PublishTime::parse_rfc3339("2026-07-18T23:05:13Z").unwrap();
        let version = GradleVersion::new("3.2.0".into()).with_published_at(published);

        assert_eq!(version.published_at(), Some(published));
    }

    #[test]
    fn test_gradle_dependency_debug_redacts_credential_shaped_group_id() {
        let dep = GradleDependency {
            group_id: "org.example:secretA@hostA.internal".into(),
            artifact_id: "artifact:secretB@hostB.internal".into(),
            name: "org.example:artifact".into(),
            name_range: Range::default(),
            version_req: None,
            version_range: None,
            configuration: "implementation".into(),
            source: deps_core::parser::DependencySource::Registry,
        };
        let rendered = format!("{dep:?}");
        assert!(!rendered.contains("secretA"));
        assert!(!rendered.contains("secretB"));
        assert!(rendered.contains(r#"group_id: "***@hostA.internal""#));
        assert!(rendered.contains(r#"artifact_id: "***@hostB.internal""#));
    }
}
