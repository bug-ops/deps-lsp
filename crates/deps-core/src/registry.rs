use crate::error::Result;
use async_trait::async_trait;
use std::any::Any;

/// Generic package registry interface.
///
/// Implementors provide access to a package registry (crates.io, npm, PyPI, etc.)
/// with version lookup, search, and metadata retrieval capabilities.
///
/// All methods return `Result<T>` to allow graceful error handling.
/// LSP handlers must never panic on registry errors.
///
/// # Type Erasure
///
/// This trait uses `Box<dyn Trait>` return types instead of associated types
/// to allow runtime polymorphism and dynamic ecosystem registration.
///
/// # Examples
///
/// ```no_run
/// use deps_core::{Registry, Version, Metadata};
/// use async_trait::async_trait;
/// use std::any::Any;
///
/// struct MyRegistry;
///
/// #[derive(Clone)]
/// struct MyVersion {
///     version: String,
/// }
///
/// impl Version for MyVersion {
///     fn version_string(&self) -> &str {
///         &self.version
///     }
///
///     fn is_yanked(&self) -> bool {
///         false
///     }
///
///     fn as_any(&self) -> &dyn Any {
///         self
///     }
/// }
///
/// #[derive(Clone)]
/// struct MyMetadata {
///     name: String,
/// }
///
/// impl Metadata for MyMetadata {
///     fn name(&self) -> &str {
///         &self.name
///     }
///
///     fn description(&self) -> Option<&str> {
///         None
///     }
///
///     fn repository(&self) -> Option<&str> {
///         None
///     }
///
///     fn documentation(&self) -> Option<&str> {
///         None
///     }
///
///     fn latest_version(&self) -> &str {
///         "1.0.0"
///     }
///
///     fn as_any(&self) -> &dyn Any {
///         self
///     }
/// }
///
/// #[async_trait]
/// impl Registry for MyRegistry {
///     async fn get_versions(&self, name: &str) -> deps_core::error::Result<Vec<Box<dyn Version>>> {
///         Ok(vec![Box::new(MyVersion { version: "1.0.0".into() })])
///     }
///
///     async fn get_latest_matching(
///         &self,
///         _name: &str,
///         _req: &str,
///     ) -> deps_core::error::Result<Option<Box<dyn Version>>> {
///         Ok(None)
///     }
///
///     async fn search(&self, _query: &str, _limit: usize) -> deps_core::error::Result<Vec<Box<dyn Metadata>>> {
///         Ok(vec![])
///     }
///
///     fn package_url(&self, name: &str) -> String {
///         format!("https://example.com/packages/{}", name)
///     }
///
///     fn as_any(&self) -> &dyn Any {
///         self
///     }
/// }
/// ```
#[async_trait]
pub trait Registry: Send + Sync {
    /// Fetches all available versions for a package.
    ///
    /// Returns versions sorted newest-first. May include yanked/deprecated versions.
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Package does not exist
    /// - Network request fails
    /// - Response parsing fails
    async fn get_versions(&self, name: &str) -> Result<Vec<Box<dyn Version>>>;

    /// Finds the latest version matching a version requirement.
    ///
    /// Only returns stable (non-yanked, non-deprecated) versions unless
    /// explicitly requested in the version requirement.
    ///
    /// # Arguments
    ///
    /// * `name` - Package name
    /// * `req` - Version requirement string (e.g., "^1.0", ">=2.0")
    ///
    /// # Returns
    ///
    /// - `Ok(Some(version))` - Latest matching version found
    /// - `Ok(None)` - No matching version found
    /// - `Err(_)` - Network or parsing error
    async fn get_latest_matching(&self, name: &str, req: &str) -> Result<Option<Box<dyn Version>>>;

    /// Searches for packages by name or keywords.
    ///
    /// Returns up to `limit` results sorted by relevance/popularity.
    ///
    /// # Errors
    ///
    /// Returns error if network request or parsing fails.
    async fn search(&self, query: &str, limit: usize) -> Result<Vec<Box<dyn Metadata>>>;

    /// Package URL for ecosystem (e.g., <https://crates.io/crates/serde>)
    ///
    /// Returns a URL that links to the package page on the registry website.
    fn package_url(&self, name: &str) -> String;

    /// Downcast to concrete registry type for ecosystem-specific operations
    fn as_any(&self) -> &dyn Any;
}

/// Version information trait.
///
/// All version types must implement this to work with generic handlers.
pub trait Version: Send + Sync {
    /// Version string (e.g., "1.0.214", "14.21.3").
    fn version_string(&self) -> &str;

    /// Whether this version is yanked/deprecated.
    fn is_yanked(&self) -> bool;

    /// Whether this version is a pre-release (alpha, beta, rc, etc.).
    ///
    /// Default implementation returns `false` (stable version).
    /// Implementations should override this for ecosystems that support pre-releases.
    fn is_prerelease(&self) -> bool {
        false
    }

    /// Available feature flags (empty if not supported by ecosystem).
    fn features(&self) -> Vec<String> {
        vec![]
    }

    /// Downcast to concrete version type
    fn as_any(&self) -> &dyn Any;
}

/// Package metadata trait.
///
/// Used for completion items and hover documentation.
pub trait Metadata: Send + Sync {
    /// Package name.
    fn name(&self) -> &str;

    /// Short description (optional).
    fn description(&self) -> Option<&str>;

    /// Repository URL (optional).
    fn repository(&self) -> Option<&str>;

    /// Documentation URL (optional).
    fn documentation(&self) -> Option<&str>;

    /// Latest stable version.
    fn latest_version(&self) -> &str;

    /// Downcast to concrete metadata type
    fn as_any(&self) -> &dyn Any;
}

// Legacy traits for backward compatibility during migration
// DEPRECATED: Use Registry, Version, Metadata instead
//
// These traits will be removed in Phase 3 after all ecosystem implementations
// are migrated to the new trait object-based system.

/// Legacy package registry trait with associated types.
///
/// # Deprecation Notice
///
/// This trait is deprecated. Use `Registry` trait instead which uses
/// trait objects (`Box<dyn Version>`) for better extensibility.
#[async_trait]
pub trait PackageRegistry: Send + Sync {
    /// Version information type for this registry.
    type Version: VersionInfo + Clone + Send + Sync;

    /// Metadata type for search results.
    type Metadata: PackageMetadata + Clone + Send + Sync;

    /// Version requirement type (e.g., semver::VersionReq for Cargo, npm semver for npm).
    type VersionReq: Clone + Send + Sync;

    /// Fetches all available versions for a package.
    async fn get_versions(&self, name: &str) -> Result<Vec<Self::Version>>;

    /// Finds the latest version matching a version requirement.
    async fn get_latest_matching(
        &self,
        name: &str,
        req: &Self::VersionReq,
    ) -> Result<Option<Self::Version>>;

    /// Searches for packages by name or keywords.
    async fn search(&self, query: &str, limit: usize) -> Result<Vec<Self::Metadata>>;
}

/// Legacy version information trait.
///
/// # Deprecation Notice
///
/// This trait is deprecated. Use `Version` trait instead.
pub trait VersionInfo {
    /// Version string (e.g., "1.0.214", "14.21.3").
    fn version_string(&self) -> &str;

    /// Whether this version is yanked/deprecated.
    fn is_yanked(&self) -> bool;

    /// Available feature flags (empty if not supported by ecosystem).
    fn features(&self) -> Vec<String> {
        vec![]
    }
}

/// Legacy package metadata trait.
///
/// # Deprecation Notice
///
/// This trait is deprecated. Use `Metadata` trait instead.
pub trait PackageMetadata {
    /// Package name.
    fn name(&self) -> &str;

    /// Short description (optional).
    fn description(&self) -> Option<&str>;

    /// Repository URL (optional).
    fn repository(&self) -> Option<&str>;

    /// Documentation URL (optional).
    fn documentation(&self) -> Option<&str>;

    /// Latest stable version.
    fn latest_version(&self) -> &str;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockVersion {
        version: String,
        yanked: bool,
    }

    impl Version for MockVersion {
        fn version_string(&self) -> &str {
            &self.version
        }

        fn is_yanked(&self) -> bool {
            self.yanked
        }

        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    #[test]
    fn test_version_default_features() {
        let version = MockVersion {
            version: "1.0.0".into(),
            yanked: false,
        };

        assert_eq!(version.features(), Vec::<String>::new());
    }

    #[test]
    fn test_version_trait_object() {
        let version = MockVersion {
            version: "1.2.3".into(),
            yanked: false,
        };

        let boxed: Box<dyn Version> = Box::new(version);
        assert_eq!(boxed.version_string(), "1.2.3");
        assert!(!boxed.is_yanked());
    }

    #[test]
    fn test_version_downcast() {
        let version = MockVersion {
            version: "1.0.0".into(),
            yanked: true,
        };

        let boxed: Box<dyn Version> = Box::new(version);
        let any = boxed.as_any();

        assert!(any.is::<MockVersion>());
    }

    struct MockMetadata {
        name: String,
        latest: String,
    }

    impl Metadata for MockMetadata {
        fn name(&self) -> &str {
            &self.name
        }

        fn description(&self) -> Option<&str> {
            None
        }

        fn repository(&self) -> Option<&str> {
            None
        }

        fn documentation(&self) -> Option<&str> {
            None
        }

        fn latest_version(&self) -> &str {
            &self.latest
        }

        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    #[test]
    fn test_metadata_trait_object() {
        let metadata = MockMetadata {
            name: "test-package".into(),
            latest: "2.0.0".into(),
        };

        let boxed: Box<dyn Metadata> = Box::new(metadata);
        assert_eq!(boxed.name(), "test-package");
        assert_eq!(boxed.latest_version(), "2.0.0");
        assert!(boxed.description().is_none());
        assert!(boxed.repository().is_none());
        assert!(boxed.documentation().is_none());
    }

    #[test]
    fn test_metadata_with_full_info() {
        struct FullMetadata {
            name: String,
            desc: String,
            repo: String,
            docs: String,
            latest: String,
        }

        impl Metadata for FullMetadata {
            fn name(&self) -> &str {
                &self.name
            }
            fn description(&self) -> Option<&str> {
                Some(&self.desc)
            }
            fn repository(&self) -> Option<&str> {
                Some(&self.repo)
            }
            fn documentation(&self) -> Option<&str> {
                Some(&self.docs)
            }
            fn latest_version(&self) -> &str {
                &self.latest
            }
            fn as_any(&self) -> &dyn Any {
                self
            }
        }

        let meta = FullMetadata {
            name: "serde".into(),
            desc: "Serialization framework".into(),
            repo: "https://github.com/serde-rs/serde".into(),
            docs: "https://docs.rs/serde".into(),
            latest: "1.0.214".into(),
        };

        assert_eq!(meta.description(), Some("Serialization framework"));
        assert_eq!(meta.repository(), Some("https://github.com/serde-rs/serde"));
        assert_eq!(meta.documentation(), Some("https://docs.rs/serde"));
    }
}
