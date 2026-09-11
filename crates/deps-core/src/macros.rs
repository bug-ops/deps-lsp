//! Macro utilities for reducing boilerplate in ecosystem implementations.
//!
//! Provides macros for implementing common traits with minimal code duplication.

/// Implement the `Dependency` trait for a struct.
///
/// # Arguments
///
/// * `$type` - The struct type name
/// * `name` - Field name for the dependency name (`PackageName`)
/// * `name_range` - Field name for the name range (`Range`)
/// * `version` - Field name for version requirement (`Option<VersionReq>`)
/// * `version_range` - Field name for version range (`Option<Range>`)
/// * `source` - Optional: field name for dependency source (`DependencySource`), cloned
///   (defaults to the constant `DependencySource::Registry` when omitted). A *field name*
///   rather than an arbitrary expression: a `$source:expr` fragment can express the same
///   thing as a closure (`impl_version!`'s `status`/`prerelease` arguments use exactly that
///   pattern), but a closure returning a *borrow* out of `self` (as `source()`'s caller-side
///   equivalent would need for, e.g., a non-cloning accessor) hits a real lifetime footgun —
///   the closure's return type can't name a lifetime tied to its `&self` parameter without
///   HRTB ceremony the call sites here shouldn't have to write. A bare field identifier,
///   substituted into the generated method's own `self.$field`, sidesteps that entirely and
///   keeps every call site a one-line field name — the same reasoning that makes `name`,
///   `name_range`, `version` and `version_range` above plain idents rather than expressions.
/// * `version_literal` - Optional, requires `source` to also be given (fields are matched in
///   this exact order — `version_literal` alone, or before `source`, matches no arm): field
///   name for [`Dependency::version_literal`](crate::ecosystem::Dependency::version_literal)
///   (`Option<String>`), read via `.as_deref()` (defaults to the trait's `None` when omitted)
///
/// # Examples
///
/// ```ignore
/// use deps_core::{impl_dependency, PackageName, VersionReq};
///
/// pub struct MyDependency {
///     pub name: PackageName,
///     pub name_range: Range,
///     pub version_req: Option<VersionReq>,
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
        impl $crate::ecosystem::Dependency for $type {
            fn name(&self) -> &$crate::PackageName {
                &self.$name
            }

            fn name_range(&self) -> ::tower_lsp_server::ls_types::Range {
                self.$name_range
            }

            fn version_requirement(&self) -> Option<&$crate::VersionReq> {
                self.$version.as_ref()
            }

            fn version_range(&self) -> Option<::tower_lsp_server::ls_types::Range> {
                self.$version_range
            }

            fn source(&self) -> $crate::parser::DependencySource {
                $crate::parser::DependencySource::Registry
            }

            fn as_any(&self) -> &dyn ::std::any::Any {
                self
            }
        }
    };
    ($type:ty {
        name: $name:ident,
        name_range: $name_range:ident,
        version: $version:ident,
        version_range: $version_range:ident,
        source: $source:ident $(,)?
    }) => {
        impl $crate::ecosystem::Dependency for $type {
            fn name(&self) -> &$crate::PackageName {
                &self.$name
            }

            fn name_range(&self) -> ::tower_lsp_server::ls_types::Range {
                self.$name_range
            }

            fn version_requirement(&self) -> Option<&$crate::VersionReq> {
                self.$version.as_ref()
            }

            fn version_range(&self) -> Option<::tower_lsp_server::ls_types::Range> {
                self.$version_range
            }

            fn source(&self) -> $crate::parser::DependencySource {
                self.$source.clone()
            }

            fn as_any(&self) -> &dyn ::std::any::Any {
                self
            }
        }
    };
    ($type:ty {
        name: $name:ident,
        name_range: $name_range:ident,
        version: $version:ident,
        version_range: $version_range:ident,
        source: $source:ident,
        version_literal: $version_literal:ident $(,)?
    }) => {
        impl $crate::ecosystem::Dependency for $type {
            fn name(&self) -> &$crate::PackageName {
                &self.$name
            }

            fn name_range(&self) -> ::tower_lsp_server::ls_types::Range {
                self.$name_range
            }

            fn version_requirement(&self) -> Option<&$crate::VersionReq> {
                self.$version.as_ref()
            }

            fn version_range(&self) -> Option<::tower_lsp_server::ls_types::Range> {
                self.$version_range
            }

            fn source(&self) -> $crate::parser::DependencySource {
                self.$source.clone()
            }

            fn version_literal(&self) -> Option<&str> {
                self.$version_literal.as_deref()
            }

            fn as_any(&self) -> &dyn ::std::any::Any {
                self
            }
        }
    };
}

/// Implement `Version` trait for a struct.
///
/// # Arguments
///
/// * `$type` - The struct type name
/// * `version` - Field name for version string (`ConcreteVersion`)
/// * `status` - Expression evaluating to a closure `Fn(&$type) -> RemovalStatus`,
///   restating at every declaration site whether the ecosystem's flag is a hard
///   removal ([`RemovalStatus::from_yanked`](crate::RemovalStatus::from_yanked)) or an
///   advisory one ([`RemovalStatus::from_advisory`](crate::RemovalStatus::from_advisory))
///   — see [`RemovalStatus`](crate::RemovalStatus).
/// * `published_at` - Optional: field name for publish timestamp
///   (`Option<PublishTime>`), already parsed eagerly at construction
/// * `prerelease` - Optional: expression evaluating to a closure
///   `Fn(&$type) -> bool`, used when the ecosystem has its own reliable
///   prerelease signal (e.g. a semver-parsed `pre` component) instead of
///   falling back to the trait's default hyphen-substring heuristic.
///   Omitting this arm silently installs the default heuristic, with no
///   compile-time signal that it may be wrong for the ecosystem — only omit
///   it when the default is provably correct for the registry's version
///   format (as of #322, `deps-composer` is the sole deliberate holdout,
///   since Packagist versions aren't strict semver).
/// * `deprecation` - Optional, requires both `published_at` and `prerelease` to also be
///   given: expression evaluating to a closure `Fn(&$type) -> Option<&Deprecation>`,
///   for an ecosystem whose registry exposes a package-level deprecation payload
///   (issue #205). Omitting this arm installs the trait default (`None`).
///
/// # Examples
///
/// ```ignore
/// use deps_core::{ConcreteVersion, impl_version, RemovalStatus};
///
/// pub struct MyVersion {
///     pub version: ConcreteVersion,
///     pub deprecated: bool,
/// }
///
/// impl_version!(MyVersion {
///     version: version,
///     status: |v: &MyVersion| RemovalStatus::from_advisory(v.deprecated),
/// });
/// ```
///
/// With a publish timestamp:
///
/// ```ignore
/// use deps_core::{ConcreteVersion, impl_version, PublishTime, RemovalStatus};
///
/// pub struct MyVersion {
///     pub version: ConcreteVersion,
///     pub deprecated: bool,
///     pub published_at: Option<PublishTime>,
/// }
///
/// impl_version!(MyVersion {
///     version: version,
///     status: |v: &MyVersion| RemovalStatus::from_advisory(v.deprecated),
///     published_at: published_at,
/// });
/// ```
///
/// With a structured prerelease signal:
///
/// ```ignore
/// use deps_core::{ConcreteVersion, impl_version, RemovalStatus};
///
/// pub struct MyVersion {
///     pub version: ConcreteVersion,
///     pub deprecated: bool,
/// }
///
/// impl_version!(MyVersion {
///     version: version,
///     status: |v: &MyVersion| RemovalStatus::from_advisory(v.deprecated),
///     prerelease: |v: &MyVersion| v.version.as_str().contains("-pre"),
/// });
/// ```
#[macro_export]
macro_rules! impl_version {
    ($type:ty {
        version: $version:ident,
        status: $status:expr $(,)?
    }) => {
        impl $crate::registry::Version for $type {
            fn version_string(&self) -> &$crate::ConcreteVersion {
                &self.$version
            }

            fn removal_status(&self) -> $crate::registry::RemovalStatus {
                ($status)(self)
            }

            fn as_any(&self) -> &dyn ::std::any::Any {
                self
            }
        }
    };
    ($type:ty {
        version: $version:ident,
        status: $status:expr,
        published_at: $published_at:ident $(,)?
    }) => {
        impl $crate::registry::Version for $type {
            fn version_string(&self) -> &$crate::ConcreteVersion {
                &self.$version
            }

            fn removal_status(&self) -> $crate::registry::RemovalStatus {
                ($status)(self)
            }

            fn published_at(&self) -> Option<$crate::freshness::PublishTime> {
                self.$published_at
            }

            fn as_any(&self) -> &dyn ::std::any::Any {
                self
            }
        }
    };
    ($type:ty {
        version: $version:ident,
        status: $status:expr,
        prerelease: $prerelease:expr $(,)?
    }) => {
        impl $crate::registry::Version for $type {
            fn version_string(&self) -> &$crate::ConcreteVersion {
                &self.$version
            }

            fn removal_status(&self) -> $crate::registry::RemovalStatus {
                ($status)(self)
            }

            fn is_prerelease(&self) -> bool {
                ($prerelease)(self)
            }

            fn as_any(&self) -> &dyn ::std::any::Any {
                self
            }
        }
    };
    ($type:ty {
        version: $version:ident,
        status: $status:expr,
        published_at: $published_at:ident,
        prerelease: $prerelease:expr $(,)?
    }) => {
        impl $crate::registry::Version for $type {
            fn version_string(&self) -> &$crate::ConcreteVersion {
                &self.$version
            }

            fn removal_status(&self) -> $crate::registry::RemovalStatus {
                ($status)(self)
            }

            fn published_at(&self) -> Option<$crate::freshness::PublishTime> {
                self.$published_at
            }

            fn is_prerelease(&self) -> bool {
                ($prerelease)(self)
            }

            fn as_any(&self) -> &dyn ::std::any::Any {
                self
            }
        }
    };
    ($type:ty {
        version: $version:ident,
        status: $status:expr,
        published_at: $published_at:ident,
        prerelease: $prerelease:expr,
        deprecation: $deprecation:expr $(,)?
    }) => {
        impl $crate::registry::Version for $type {
            fn version_string(&self) -> &$crate::ConcreteVersion {
                &self.$version
            }

            fn removal_status(&self) -> $crate::registry::RemovalStatus {
                ($status)(self)
            }

            fn published_at(&self) -> Option<$crate::freshness::PublishTime> {
                self.$published_at
            }

            fn is_prerelease(&self) -> bool {
                ($prerelease)(self)
            }

            fn deprecation(&self) -> Option<&$crate::registry::Deprecation> {
                // Coerced through a plain `fn` pointer (rather than calling the closure
                // expression directly) so it is forced to be `for<'a> Fn(&'a Self) ->
                // Option<&'a Deprecation>` — a bare closure literal here infers a single
                // concrete lifetime from its first call site instead of generalizing,
                // which fails to typecheck against `self`'s elided lifetime.
                let f: fn(&$type) -> Option<&$crate::registry::Deprecation> = $deprecation;
                f(self)
            }

            fn as_any(&self) -> &dyn ::std::any::Any {
                self
            }
        }
    };
    ($type:ty {
        version: $version:ident,
        status: $status:expr,
        published_at: $published_at:ident,
        prerelease: $prerelease:expr,
        deprecation: $deprecation:expr,
        license: $license:ident $(,)?
    }) => {
        impl $crate::registry::Version for $type {
            fn version_string(&self) -> &$crate::ConcreteVersion {
                &self.$version
            }

            fn removal_status(&self) -> $crate::registry::RemovalStatus {
                ($status)(self)
            }

            fn published_at(&self) -> Option<$crate::freshness::PublishTime> {
                self.$published_at
            }

            fn is_prerelease(&self) -> bool {
                ($prerelease)(self)
            }

            fn deprecation(&self) -> Option<&$crate::registry::Deprecation> {
                let f: fn(&$type) -> Option<&$crate::registry::Deprecation> = $deprecation;
                f(self)
            }

            fn license(&self) -> &[String] {
                &self.$license
            }

            fn as_any(&self) -> &dyn ::std::any::Any {
                self
            }
        }
    };
}

/// Implement `Metadata` trait for a struct.
///
/// # Arguments
///
/// * `$type` - The struct type name
/// * `name` - Field name for package name (`PackageName`)
/// * `description` - Field name for description (`Option<String>`)
/// * `repository` - Field name for repository (`Option<String>`)
/// * `documentation` - Field name for documentation URL (`Option<String>`)
/// * `latest_version` - Field name for latest version (`ConcreteVersion`)
///
/// # Examples
///
/// ```ignore
/// use deps_core::{ConcreteVersion, PackageName, impl_metadata};
///
/// pub struct MyPackage {
///     pub name: PackageName,
///     pub description: Option<String>,
///     pub repository: Option<String>,
///     pub homepage: Option<String>,
///     pub latest_version: ConcreteVersion,
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
        impl $crate::registry::Metadata for $type {
            fn name(&self) -> &$crate::PackageName {
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

            fn latest_version(&self) -> &$crate::ConcreteVersion {
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
/// * `dependency_truncation` - Optional: field name for the `Option<(usize, usize)>`
///   [`ecosystem::ParseResult::dependency_truncation`](crate::ecosystem::ParseResult::dependency_truncation)
///   override (#796) — omit when the parser has no [`crate::DependencyBudget`] wired in yet
///   (the trait default `None` applies).
///
/// # Examples
///
/// ```ignore
/// use deps_core::impl_parse_result;
///
/// pub struct MyParseResult {
///     pub dependencies: Vec<MyDependency>,
///     pub uri: Uri,
///     pub dependency_truncation: Option<(usize, usize)>,
/// }
///
/// impl_parse_result!(MyParseResult, MyDependency {
///     dependencies: dependencies,
///     uri: uri,
/// });
///
/// // With workspace root and/or dependency-truncation tracking:
/// impl_parse_result!(MyParseResult, MyDependency {
///     dependencies: dependencies,
///     uri: uri,
///     workspace_root: workspace_root,
///     dependency_truncation: dependency_truncation,
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
    ($type:ty, $dep_type:ty {
        dependencies: $dependencies:ident,
        uri: $uri:ident,
        dependency_truncation: $dependency_truncation:ident $(,)?
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

            fn dependency_truncation(&self) -> Option<(usize, usize)> {
                self.$dependency_truncation
            }
        }
    };
    ($type:ty, $dep_type:ty {
        dependencies: $dependencies:ident,
        uri: $uri:ident,
        workspace_root: $workspace_root:ident,
        dependency_truncation: $dependency_truncation:ident $(,)?
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

            fn dependency_truncation(&self) -> Option<(usize, usize)> {
                self.$dependency_truncation
            }
        }
    };
}

/// Generates one `Registry` trait-impl method that boxes an inherent method's result.
///
/// Turns a concrete `Vec<T>` into `Vec<Box<dyn Version>>` (#834 code review: this exact
/// boilerplate was independently hand-written ~11 times for `get_versions` and ~7 times for
/// `get_versions_with` across the workspace's ecosystem crates before this macro).
///
/// Requires an inherent method of the same name, taking `(&self, name: &str)` —
/// `get_versions` — or `(&self, name: &str, freshness: FreshnessSettings)` —
/// `get_versions_with` — and returning `Result<Vec<T>>` where `T: Version`. Use inside your
/// own `impl deps_core::Registry for MyRegistry { ... }` block; every other trait method
/// (`get_latest_matching`, `search`, ...) is unaffected and still hand-written, since their
/// boxing shape is either `Option<Box<dyn Version>>` (a single value, not a `Vec`) or
/// `Box<dyn Metadata>` (a different trait entirely).
///
/// # Examples
///
/// ```ignore
/// use deps_core::impl_registry_versions_method;
///
/// impl deps_core::Registry for MyRegistry {
///     impl_registry_versions_method!(get_versions);
///     impl_registry_versions_method!(get_versions_with);
///     // ... get_latest_matching, search, as_any still hand-written ...
/// }
/// ```
#[macro_export]
macro_rules! impl_registry_versions_method {
    (get_versions) => {
        fn get_versions<'a>(
            &'a self,
            name: &'a $crate::PackageName,
        ) -> $crate::ecosystem::BoxFuture<
            'a,
            $crate::error::Result<::std::vec::Vec<::std::boxed::Box<dyn $crate::Version>>>,
        > {
            ::std::boxed::Box::pin(async move {
                let versions = self.get_versions(name.as_str()).await?;
                Ok(versions
                    .into_iter()
                    .map(|v| ::std::boxed::Box::new(v) as ::std::boxed::Box<dyn $crate::Version>)
                    .collect())
            })
        }
    };
    (get_versions_with) => {
        fn get_versions_with<'a>(
            &'a self,
            name: &'a $crate::PackageName,
            freshness: $crate::FreshnessSettings,
        ) -> $crate::ecosystem::BoxFuture<
            'a,
            $crate::error::Result<::std::vec::Vec<::std::boxed::Box<dyn $crate::Version>>>,
        > {
            ::std::boxed::Box::pin(async move {
                let versions = self.get_versions_with(name.as_str(), freshness).await?;
                Ok(versions
                    .into_iter()
                    .map(|v| ::std::boxed::Box::new(v) as ::std::boxed::Box<dyn $crate::Version>)
                    .collect())
            })
        }
    };
}

/// Generates a trivial inherent `get_versions_with` that ignores `freshness`.
///
/// Delegates to `Self::get_versions` (#834 code review: this exact body was independently
/// hand-written 6 times across the workspace before this macro).
///
/// For ecosystems whose base version listing already carries everything
/// `get_versions_with` would otherwise fetch separately — there is no second request for
/// `freshness` to gate today, so the flag is accepted (matching every other ecosystem's
/// `get_versions_with` signature) but otherwise unused. Not appropriate for an ecosystem
/// that *does* have a separate freshness-enrichment fetch (e.g. `deps-maven`, `deps-nuget`,
/// `deps-swift`) — those keep their own hand-written `get_versions_with`. If a registry
/// generated by this macro ever gains its own publish-time enrichment, switch it to a
/// hand-written `get_versions_with` too (issue #588 critic M10) — this macro's whole point
/// is a pass-through, not a promise that `freshness` stays forever irrelevant.
///
/// # Examples
///
/// ```ignore
/// use deps_core::impl_get_versions_with_passthrough;
///
/// impl MyRegistry {
///     pub async fn get_versions(&self, name: &str) -> Result<Vec<MyVersion>> { todo!() }
/// }
///
/// impl_get_versions_with_passthrough!(MyRegistry, MyVersion);
/// ```
#[macro_export]
macro_rules! impl_get_versions_with_passthrough {
    ($type:ty, $version:ty $(,)?) => {
        impl $type {
            /// Same as [`Self::get_versions`] — the publish date, if any, already arrives
            /// with the base listing, so `freshness` has no extra fetch to gate. Accepted
            /// (matching every other ecosystem's `get_versions_with` signature, #834
            /// critic S2) but otherwise unused.
            ///
            /// # Errors
            ///
            /// Same as [`Self::get_versions`].
            pub async fn get_versions_with(
                &self,
                name: &str,
                _freshness: $crate::FreshnessSettings,
            ) -> $crate::error::Result<::std::vec::Vec<$version>> {
                self.get_versions(name).await
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use crate::ConcreteVersion;
    use tower_lsp_server::ls_types::{Position, Range, Uri};

    // Test structs
    #[derive(Debug, Clone)]
    struct TestDependency {
        name: crate::PackageName,
        name_range: Range,
        version_req: Option<crate::VersionReq>,
        version_range: Option<Range>,
    }

    #[derive(Debug, Clone)]
    struct TestDependencyWithSource {
        name: crate::PackageName,
        name_range: Range,
        version_req: Option<crate::VersionReq>,
        version_range: Option<Range>,
        source: crate::parser::DependencySource,
        version_literal: Option<String>,
    }

    #[derive(Debug, Clone)]
    struct TestVersion {
        version: ConcreteVersion,
        yanked: bool,
    }

    #[derive(Debug, Clone)]
    struct TestVersionWithPublishedAt {
        version: ConcreteVersion,
        yanked: bool,
        published_at: Option<crate::freshness::PublishTime>,
    }

    #[derive(Debug, Clone)]
    struct TestVersionWithPrerelease {
        version: ConcreteVersion,
        yanked: bool,
    }

    #[derive(Debug, Clone)]
    struct TestVersionWithPublishedAtAndPrerelease {
        version: ConcreteVersion,
        yanked: bool,
        published_at: Option<crate::freshness::PublishTime>,
    }

    #[derive(Debug, Clone)]
    struct TestPackage {
        name: crate::PackageName,
        description: Option<String>,
        repository: Option<String>,
        homepage: Option<String>,
        latest_version: ConcreteVersion,
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

    impl_dependency!(TestDependencyWithSource {
        name: name,
        name_range: name_range,
        version: version_req,
        version_range: version_range,
        source: source,
        version_literal: version_literal,
    });

    impl_version!(TestVersion {
        version: version,
        status: |v: &TestVersion| crate::registry::RemovalStatus::from_yanked(v.yanked),
    });

    impl_version!(TestVersionWithPublishedAt {
        version: version,
        status: |v: &TestVersionWithPublishedAt| crate::registry::RemovalStatus::from_yanked(
            v.yanked
        ),
        published_at: published_at,
    });

    impl_version!(TestVersionWithPrerelease {
        version: version,
        status: |v: &TestVersionWithPrerelease| crate::registry::RemovalStatus::from_yanked(
            v.yanked
        ),
        prerelease: |v: &TestVersionWithPrerelease| v.version.as_str().contains(".pre"),
    });

    impl_version!(TestVersionWithPublishedAtAndPrerelease {
        version: version,
        status: |v: &TestVersionWithPublishedAtAndPrerelease| {
            crate::registry::RemovalStatus::from_yanked(v.yanked)
        },
        published_at: published_at,
        prerelease: |v: &TestVersionWithPublishedAtAndPrerelease| v
            .version
            .as_str()
            .contains(".pre"),
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
        assert_eq!(
            dep.version_requirement().map(crate::VersionReq::as_str),
            Some("1.0.0")
        );
        assert!(dep.as_any().is::<TestDependency>());
        assert!(matches!(
            dep.source(),
            crate::parser::DependencySource::Registry
        ));
    }

    #[test]
    fn test_impl_dependency_macro_with_source_and_version_literal() {
        use crate::ecosystem::Dependency;

        let dep = TestDependencyWithSource {
            name: "test-pkg".into(),
            name_range: Range::new(Position::new(0, 0), Position::new(0, 8)),
            version_req: Some("1.0.0".into()),
            version_range: Some(Range::new(Position::new(0, 10), Position::new(0, 15))),
            source: crate::parser::DependencySource::Git {
                url: "https://example.com/repo.git".into(),
                rev: None,
            },
            version_literal: Some("v1.0.0".into()),
        };

        assert!(matches!(
            dep.source(),
            crate::parser::DependencySource::Git { .. }
        ));
        assert_eq!(dep.version_literal(), Some("v1.0.0"));
    }

    #[test]
    fn test_impl_version_macro() {
        use crate::registry::Version;

        let version = TestVersion {
            version: "2.0.0".into(),
            yanked: true,
        };

        assert_eq!(version.version_string().as_str(), "2.0.0");
        assert!(version.removal_status().blocks_resolution());
        assert!(version.as_any().is::<TestVersion>());
        assert!(version.published_at().is_none());
    }

    #[test]
    fn test_impl_version_macro_with_published_at() {
        use crate::freshness::PublishTime;
        use crate::registry::Version;

        let version = TestVersionWithPublishedAt {
            version: "3.0.0".into(),
            yanked: false,
            published_at: Some(PublishTime::from_unix_secs(1_000)),
        };

        assert_eq!(version.version_string().as_str(), "3.0.0");
        assert!(!version.removal_status().blocks_resolution());
        assert_eq!(
            version.published_at(),
            Some(PublishTime::from_unix_secs(1_000))
        );
        assert!(version.as_any().is::<TestVersionWithPublishedAt>());
    }

    #[test]
    fn test_impl_version_macro_with_prerelease() {
        use crate::registry::Version;

        let stable = TestVersionWithPrerelease {
            version: "1.0.0".into(),
            yanked: false,
        };
        let prerelease = TestVersionWithPrerelease {
            version: "1.0.0.pre1".into(),
            yanked: false,
        };

        assert!(!stable.is_prerelease());
        assert!(prerelease.is_prerelease());
        assert!(stable.is_stable());
        assert!(!prerelease.is_stable());
    }

    #[test]
    fn test_impl_version_macro_with_published_at_and_prerelease() {
        use crate::freshness::PublishTime;
        use crate::registry::Version;

        let version = TestVersionWithPublishedAtAndPrerelease {
            version: "2.0.0.pre1".into(),
            yanked: false,
            published_at: Some(PublishTime::from_unix_secs(2_000)),
        };

        assert!(version.is_prerelease());
        assert_eq!(
            version.published_at(),
            Some(PublishTime::from_unix_secs(2_000))
        );
    }

    #[test]
    fn test_impl_metadata_macro() {
        use crate::registry::Metadata;

        let pkg = TestPackage {
            name: crate::PackageName::new("my-pkg"),
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
            uri: crate::test_util::test_uri("/test"),
        };

        assert_eq!(result.dependencies().len(), 1);
        assert!(result.workspace_root().is_none());
        assert!(result.as_any().is::<TestParseResult>());
    }
}
