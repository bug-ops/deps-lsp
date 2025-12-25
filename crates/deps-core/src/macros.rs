//! Macro utilities for reducing boilerplate in ecosystem implementations.
//!
//! Provides macros for implementing common traits with minimal code duplication.

/// Implement `Dependency` and `DependencyInfo` traits for a struct.
///
/// # Arguments
///
/// * `$type` - The struct type name
/// * `name` - Field name for the dependency name (`String`)
/// * `name_range` - Field name for the name range (`Range`)
/// * `version` - Field name for version requirement (`Option<String>`)
/// * `version_range` - Field name for version range (`Option<Range>`)
/// * `source` - Optional: expression for dependency source (defaults to `Registry`)
///
/// # Examples
///
/// ```ignore
/// use deps_core::impl_dependency;
///
/// pub struct MyDependency {
///     pub name: String,
///     pub name_range: Range,
///     pub version_req: Option<String>,
///     pub version_range: Option<Range>,
/// }
///
/// impl_dependency!(MyDependency {
///     name: name,
///     name_range: name_range,
///     version: version_req,
///     version_range: version_range,
/// });
/// ```
#[macro_export]
macro_rules! impl_dependency {
    ($type:ty {
        name: $name:ident,
        name_range: $name_range:ident,
        version: $version:ident,
        version_range: $version_range:ident $(,)?
    }) => {
        $crate::impl_dependency!($type {
            name: $name,
            name_range: $name_range,
            version: $version,
            version_range: $version_range,
            source: $crate::parser::DependencySource::Registry,
        });
    };
    ($type:ty {
        name: $name:ident,
        name_range: $name_range:ident,
        version: $version:ident,
        version_range: $version_range:ident,
        source: $source:expr $(,)?
    }) => {
        impl $crate::parser::DependencyInfo for $type {
            fn name(&self) -> &str {
                &self.$name
            }

            fn name_range(&self) -> ::tower_lsp_server::ls_types::Range {
                self.$name_range
            }

            fn version_requirement(&self) -> Option<&str> {
                self.$version.as_deref()
            }

            fn version_range(&self) -> Option<::tower_lsp_server::ls_types::Range> {
                self.$version_range
            }

            fn source(&self) -> $crate::parser::DependencySource {
                $source
            }
        }

        impl $crate::ecosystem::Dependency for $type {
            fn name(&self) -> &str {
                &self.$name
            }

            fn name_range(&self) -> ::tower_lsp_server::ls_types::Range {
                self.$name_range
            }

            fn version_requirement(&self) -> Option<&str> {
                self.$version.as_deref()
            }

            fn version_range(&self) -> Option<::tower_lsp_server::ls_types::Range> {
                self.$version_range
            }

            fn source(&self) -> $crate::parser::DependencySource {
                $source
            }

            fn as_any(&self) -> &dyn ::std::any::Any {
                self
            }
        }
    };
}

/// Implement `Version` and `VersionInfo` traits for a struct.
///
/// # Arguments
///
/// * `$type` - The struct type name
/// * `version` - Field name for version string (`String`)
/// * `yanked` - Field name for yanked/deprecated status (`bool`)
///
/// # Examples
///
/// ```ignore
/// use deps_core::impl_version;
///
/// pub struct MyVersion {
///     pub version: String,
///     pub deprecated: bool,
/// }
///
/// impl_version!(MyVersion {
///     version: version,
///     yanked: deprecated,
/// });
/// ```
#[macro_export]
macro_rules! impl_version {
    ($type:ty {
        version: $version:ident,
        yanked: $yanked:ident $(,)?
    }) => {
        impl $crate::registry::VersionInfo for $type {
            fn version_string(&self) -> &str {
                &self.$version
            }

            fn is_yanked(&self) -> bool {
                self.$yanked
            }
        }

        impl $crate::registry::Version for $type {
            fn version_string(&self) -> &str {
                &self.$version
            }

            fn is_yanked(&self) -> bool {
                self.$yanked
            }

            fn as_any(&self) -> &dyn ::std::any::Any {
                self
            }
        }
    };
}

/// Implement `Metadata` and `PackageMetadata` traits for a struct.
///
/// # Arguments
///
/// * `$type` - The struct type name
/// * `name` - Field name for package name (`String`)
/// * `description` - Field name for description (`Option<String>`)
/// * `repository` - Field name for repository (`Option<String>`)
/// * `documentation` - Field name for documentation URL (`Option<String>`)
/// * `latest_version` - Field name for latest version (`String`)
///
/// # Examples
///
/// ```ignore
/// use deps_core::impl_metadata;
///
/// pub struct MyPackage {
///     pub name: String,
///     pub description: Option<String>,
///     pub repository: Option<String>,
///     pub homepage: Option<String>,
///     pub latest_version: String,
/// }
///
/// impl_metadata!(MyPackage {
///     name: name,
///     description: description,
///     repository: repository,
///     documentation: homepage,
///     latest_version: latest_version,
/// });
/// ```
#[macro_export]
macro_rules! impl_metadata {
    ($type:ty {
        name: $name:ident,
        description: $description:ident,
        repository: $repository:ident,
        documentation: $documentation:ident,
        latest_version: $latest_version:ident $(,)?
    }) => {
        impl $crate::registry::PackageMetadata for $type {
            fn name(&self) -> &str {
                &self.$name
            }

            fn description(&self) -> Option<&str> {
                self.$description.as_deref()
            }

            fn repository(&self) -> Option<&str> {
                self.$repository.as_deref()
            }

            fn documentation(&self) -> Option<&str> {
                self.$documentation.as_deref()
            }

            fn latest_version(&self) -> &str {
                &self.$latest_version
            }
        }

        impl $crate::registry::Metadata for $type {
            fn name(&self) -> &str {
                &self.$name
            }

            fn description(&self) -> Option<&str> {
                self.$description.as_deref()
            }

            fn repository(&self) -> Option<&str> {
                self.$repository.as_deref()
            }

            fn documentation(&self) -> Option<&str> {
                self.$documentation.as_deref()
            }

            fn latest_version(&self) -> &str {
                &self.$latest_version
            }

            fn as_any(&self) -> &dyn ::std::any::Any {
                self
            }
        }
    };
}

/// Implement `ParseResult` trait for a struct.
///
/// # Arguments
///
/// * `$type` - The struct type name
/// * `$dep_type` - The dependency type that implements `Dependency`
/// * `dependencies` - Field name for dependencies vec (`Vec<DepType>`)
/// * `uri` - Field name for document URI (`Url`)
/// * `workspace_root` - Optional: field name for workspace root (`Option<PathBuf>`)
///
/// # Examples
///
/// ```ignore
/// use deps_core::impl_parse_result;
///
/// pub struct MyParseResult {
///     pub dependencies: Vec<MyDependency>,
///     pub uri: Uri,
/// }
///
/// impl_parse_result!(MyParseResult, MyDependency {
///     dependencies: dependencies,
///     uri: uri,
/// });
///
/// // With workspace root:
/// impl_parse_result!(MyParseResult, MyDependency {
///     dependencies: dependencies,
///     uri: uri,
///     workspace_root: workspace_root,
/// });
/// ```
#[macro_export]
macro_rules! impl_parse_result {
    ($type:ty, $dep_type:ty {
        dependencies: $dependencies:ident,
        uri: $uri:ident $(,)?
    }) => {
        impl $crate::ecosystem::ParseResult for $type {
            fn dependencies(&self) -> Vec<&dyn $crate::ecosystem::Dependency> {
                self.$dependencies
                    .iter()
                    .map(|d| d as &dyn $crate::ecosystem::Dependency)
                    .collect()
            }

            fn workspace_root(&self) -> Option<&::std::path::Path> {
                None
            }

            fn uri(&self) -> &::tower_lsp_server::ls_types::Uri {
                &self.$uri
            }

            fn as_any(&self) -> &dyn ::std::any::Any {
                self
            }
        }
    };
    ($type:ty, $dep_type:ty {
        dependencies: $dependencies:ident,
        uri: $uri:ident,
        workspace_root: $workspace_root:ident $(,)?
    }) => {
        impl $crate::ecosystem::ParseResult for $type {
            fn dependencies(&self) -> Vec<&dyn $crate::ecosystem::Dependency> {
                self.$dependencies
                    .iter()
                    .map(|d| d as &dyn $crate::ecosystem::Dependency)
                    .collect()
            }

            fn workspace_root(&self) -> Option<&::std::path::Path> {
                self.$workspace_root.as_deref()
            }

            fn uri(&self) -> &::tower_lsp_server::ls_types::Uri {
                &self.$uri
            }

            fn as_any(&self) -> &dyn ::std::any::Any {
                self
            }
        }
    };
}

/// Delegate a method call to all enum variants.
///
/// This macro generates a match expression that delegates to the same
/// method on each enum variant, eliminating boilerplate.
///
/// # Examples
///
/// ```ignore
/// impl UnifiedDependency {
///     pub fn name(&self) -> &str {
///         delegate_to_variants!(self, name)
///     }
/// }
/// ```
#[macro_export]
macro_rules! delegate_to_variants {
    ($self:ident, $method:ident $(, $arg:expr)*) => {
        match $self {
            Self::Cargo(dep) => dep.$method($($arg),*),
            Self::Npm(dep) => dep.$method($($arg),*),
            Self::Pypi(dep) => dep.$method($($arg),*),
        }
    };
}

#[cfg(test)]
mod tests {
    use tower_lsp_server::ls_types::{Position, Range, Uri};

    // Test structs
    #[derive(Debug, Clone)]
    struct TestDependency {
        name: String,
        name_range: Range,
        version_req: Option<String>,
        version_range: Option<Range>,
    }

    #[derive(Debug, Clone)]
    struct TestVersion {
        version: String,
        yanked: bool,
    }

    #[derive(Debug, Clone)]
    struct TestPackage {
        name: String,
        description: Option<String>,
        repository: Option<String>,
        homepage: Option<String>,
        latest_version: String,
    }

    #[derive(Debug)]
    struct TestParseResult {
        dependencies: Vec<TestDependency>,
        uri: Uri,
    }

    // Apply macros
    impl_dependency!(TestDependency {
        name: name,
        name_range: name_range,
        version: version_req,
        version_range: version_range,
    });

    impl_version!(TestVersion {
        version: version,
        yanked: yanked,
    });

    impl_metadata!(TestPackage {
        name: name,
        description: description,
        repository: repository,
        documentation: homepage,
        latest_version: latest_version,
    });

    impl_parse_result!(
        TestParseResult,
        TestDependency {
            dependencies: dependencies,
            uri: uri,
        }
    );

    #[test]
    fn test_impl_dependency_macro() {
        use crate::ecosystem::Dependency;

        let dep = TestDependency {
            name: "test-pkg".into(),
            name_range: Range::new(Position::new(0, 0), Position::new(0, 8)),
            version_req: Some("1.0.0".into()),
            version_range: Some(Range::new(Position::new(0, 10), Position::new(0, 15))),
        };

        assert_eq!(dep.name(), "test-pkg");
        assert_eq!(dep.version_requirement(), Some("1.0.0"));
        assert!(dep.as_any().is::<TestDependency>());
    }

    #[test]
    fn test_impl_version_macro() {
        use crate::registry::Version;

        let version = TestVersion {
            version: "2.0.0".into(),
            yanked: true,
        };

        assert_eq!(version.version_string(), "2.0.0");
        assert!(version.is_yanked());
        assert!(version.as_any().is::<TestVersion>());
    }

    #[test]
    fn test_impl_metadata_macro() {
        use crate::registry::Metadata;

        let pkg = TestPackage {
            name: "my-pkg".into(),
            description: Some("A test package".into()),
            repository: Some("user/repo".into()),
            homepage: Some("https://example.com".into()),
            latest_version: "3.0.0".into(),
        };

        assert_eq!(pkg.name(), "my-pkg");
        assert_eq!(pkg.description(), Some("A test package"));
        assert_eq!(pkg.documentation(), Some("https://example.com"));
        assert!(pkg.as_any().is::<TestPackage>());
    }

    #[test]
    fn test_impl_parse_result_macro() {
        use crate::ecosystem::ParseResult;

        let result = TestParseResult {
            dependencies: vec![TestDependency {
                name: "dep1".into(),
                name_range: Range::default(),
                version_req: None,
                version_range: None,
            }],
            uri: Uri::from_file_path("/test").unwrap(),
        };

        assert_eq!(result.dependencies().len(), 1);
        assert!(result.workspace_root().is_none());
        assert!(result.as_any().is::<TestParseResult>());
    }
}
