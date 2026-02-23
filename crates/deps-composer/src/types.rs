use tower_lsp_server::ls_types::Range;

/// Parsed dependency from composer.json with position tracking.
///
/// Stores all information about a dependency declaration, including its name,
/// version requirement, and source positions for LSP operations.
///
/// # Examples
///
/// ```
/// use deps_composer::types::{ComposerDependency, ComposerSection};
/// use tower_lsp_server::ls_types::{Position, Range};
///
/// let dep = ComposerDependency {
///     name: "symfony/console".into(),
///     name_range: Range::new(Position::new(3, 4), Position::new(3, 20)),
///     version_req: Some("^6.0".into()),
///     version_range: Some(Range::new(Position::new(3, 23), Position::new(3, 28))),
///     section: ComposerSection::Require,
/// };
///
/// assert_eq!(dep.name, "symfony/console");
/// assert!(matches!(dep.section, ComposerSection::Require));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComposerDependency {
    pub name: String,
    pub name_range: Range,
    pub version_req: Option<String>,
    pub version_range: Option<Range>,
    pub section: ComposerSection,
}

deps_core::impl_dependency!(ComposerDependency {
    name: name,
    name_range: name_range,
    version: version_req,
    version_range: version_range,
});

/// Section in composer.json where a dependency is declared.
///
/// # Examples
///
/// ```
/// use deps_composer::types::ComposerSection;
///
/// let section = ComposerSection::Require;
/// assert!(matches!(section, ComposerSection::Require));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComposerSection {
    /// Production dependencies (`require`)
    Require,
    /// Development dependencies (`require-dev`)
    RequireDev,
}

/// Version information for a Packagist package.
///
/// Retrieved from the Packagist v2 API.
/// Contains version number and abandonment status.
///
/// # Examples
///
/// ```
/// use deps_composer::types::ComposerVersion;
///
/// let version = ComposerVersion {
///     version: "6.0.0".into(),
///     version_normalized: "6.0.0.0".into(),
///     abandoned: false,
/// };
///
/// assert!(!version.abandoned);
/// ```
#[derive(Debug, Clone)]
pub struct ComposerVersion {
    pub version: String,
    pub version_normalized: String,
    pub abandoned: bool,
}

deps_core::impl_version!(ComposerVersion {
    version: version,
    yanked: abandoned,
});

/// Package metadata from Packagist search.
///
/// Contains basic information about a Packagist package for display in
/// completion suggestions.
///
/// # Examples
///
/// ```
/// use deps_composer::types::ComposerPackage;
///
/// let pkg = ComposerPackage {
///     name: "symfony/console".into(),
///     description: Some("Symfony Console Component".into()),
///     repository: Some("https://github.com/symfony/console".into()),
///     homepage: Some("https://packagist.org/packages/symfony/console".into()),
///     latest_version: "6.0.0".into(),
/// };
///
/// assert_eq!(pkg.name, "symfony/console");
/// ```
#[derive(Debug, Clone)]
pub struct ComposerPackage {
    pub name: String,
    pub description: Option<String>,
    pub repository: Option<String>,
    pub homepage: Option<String>,
    pub latest_version: String,
}

deps_core::impl_metadata!(ComposerPackage {
    name: name,
    description: description,
    repository: repository,
    documentation: homepage,
    latest_version: latest_version,
});

#[cfg(test)]
mod tests {
    use super::*;
    use deps_core::{Metadata, Version};
    use tower_lsp_server::ls_types::Position;

    #[test]
    fn test_composer_dependency_creation() {
        let dep = ComposerDependency {
            name: "symfony/console".into(),
            name_range: Range::new(Position::new(0, 0), Position::new(0, 15)),
            version_req: Some("^6.0".into()),
            version_range: Some(Range::new(Position::new(0, 18), Position::new(0, 22))),
            section: ComposerSection::Require,
        };

        assert_eq!(dep.name, "symfony/console");
        assert_eq!(dep.version_req, Some("^6.0".into()));
        assert!(matches!(dep.section, ComposerSection::Require));
    }

    #[test]
    fn test_composer_section_variants() {
        assert!(matches!(ComposerSection::Require, ComposerSection::Require));
        assert!(matches!(
            ComposerSection::RequireDev,
            ComposerSection::RequireDev
        ));
    }

    #[test]
    fn test_composer_version_trait() {
        let version = ComposerVersion {
            version: "2.0.0".into(),
            version_normalized: "2.0.0.0".into(),
            abandoned: true,
        };

        assert_eq!(version.version_string(), "2.0.0");
        assert!(version.is_yanked());
    }

    #[test]
    fn test_composer_package_metadata_trait() {
        let pkg = ComposerPackage {
            name: "monolog/monolog".into(),
            description: Some(
                "Sends your logs to files, sockets, inboxes, databases and various web services"
                    .into(),
            ),
            repository: Some("https://github.com/Seldaek/monolog".into()),
            homepage: Some("https://packagist.org/packages/monolog/monolog".into()),
            latest_version: "3.0.0".into(),
        };

        assert_eq!(pkg.name(), "monolog/monolog");
        assert_eq!(pkg.latest_version(), "3.0.0");
        assert_eq!(pkg.repository(), Some("https://github.com/Seldaek/monolog"));
    }
}
