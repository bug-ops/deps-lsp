use crate::error::Result;
use std::any::Any;
use std::pin::Pin;

type BoxFuture<'a, T> = Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

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
/// use std::any::Any;
/// use std::pin::Pin;
///
/// struct MyRegistry;
///
/// #[derive(Clone)]
/// struct MyVersion { version: String }
///
/// impl Version for MyVersion {
///     fn version_string(&self) -> &str { &self.version }
///     fn is_yanked(&self) -> bool { false }
///     fn as_any(&self) -> &dyn Any { self }
/// }
///
/// #[derive(Clone)]
/// struct MyMetadata { name: String }
///
/// impl Metadata for MyMetadata {
///     fn name(&self) -> &str { &self.name }
///     fn description(&self) -> Option<&str> { None }
///     fn repository(&self) -> Option<&str> { None }
///     fn documentation(&self) -> Option<&str> { None }
///     fn latest_version(&self) -> &str { "1.0.0" }
///     fn as_any(&self) -> &dyn Any { self }
/// }
///
/// impl Registry for MyRegistry {
///     fn get_versions<'a>(&'a self, _name: &'a str)
///         -> Pin<Box<dyn std::future::Future<Output = deps_core::error::Result<Vec<Box<dyn Version>>>> + Send + 'a>>
///     {
///         Box::pin(async move { Ok(vec![Box::new(MyVersion { version: "1.0.0".into() }) as Box<dyn Version>]) })
///     }
///
///     fn get_latest_matching<'a>(&'a self, _name: &'a str, _req: &'a str)
///         -> Pin<Box<dyn std::future::Future<Output = deps_core::error::Result<Option<Box<dyn Version>>>> + Send + 'a>>
///     {
///         Box::pin(async move { Ok(None) })
///     }
///
///     fn search<'a>(&'a self, _query: &'a str, _limit: usize)
///         -> Pin<Box<dyn std::future::Future<Output = deps_core::error::Result<Vec<Box<dyn Metadata>>>> + Send + 'a>>
///     {
///         Box::pin(async move { Ok(vec![]) })
///     }
///
///     fn package_url(&self, name: &str) -> String {
///         format!("https://example.com/packages/{}", name)
///     }
///
///     fn as_any(&self) -> &dyn Any { self }
/// }
/// ```
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
    fn get_versions<'a>(&'a self, name: &'a str) -> BoxFuture<'a, Result<Vec<Box<dyn Version>>>>;

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
    fn get_latest_matching<'a>(
        &'a self,
        name: &'a str,
        req: &'a str,
    ) -> BoxFuture<'a, Result<Option<Box<dyn Version>>>>;

    /// Searches for packages by name or keywords.
    ///
    /// Returns up to `limit` results sorted by relevance/popularity.
    ///
    /// # Errors
    ///
    /// Returns error if network request or parsing fails.
    fn search<'a>(
        &'a self,
        query: &'a str,
        limit: usize,
    ) -> BoxFuture<'a, Result<Vec<Box<dyn Metadata>>>>;

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
    /// Default implementation checks for common pre-release patterns.
    fn is_prerelease(&self) -> bool {
        let v = self.version_string().to_lowercase();
        v.contains("-alpha")
            || v.contains("-beta")
            || v.contains("-rc")
            || v.contains("-dev")
            || v.contains("-pre")
            || v.contains("-snapshot")
            || v.contains("-canary")
            || v.contains("-nightly")
    }

    /// Available feature flags (empty if not supported by ecosystem).
    fn features(&self) -> Vec<String> {
        vec![]
    }

    /// Downcast to concrete version type
    fn as_any(&self) -> &dyn Any;

    /// Whether this version is stable (not yanked and not pre-release).
    fn is_stable(&self) -> bool {
        !self.is_yanked() && !self.is_prerelease()
    }
}

/// Finds the latest stable version from a list of versions.
///
/// Returns the first version that is:
/// - Not yanked/deprecated
/// - Not a pre-release (alpha, beta, rc, etc.)
///
/// Assumes versions are sorted newest-first (as returned by registries).
///
/// # Examples
///
/// ```
/// use deps_core::registry::{Version, find_latest_stable};
/// use std::any::Any;
///
/// struct MyVersion { version: String, yanked: bool }
///
/// impl Version for MyVersion {
///     fn version_string(&self) -> &str { &self.version }
///     fn is_yanked(&self) -> bool { self.yanked }
///     fn as_any(&self) -> &dyn Any { self }
/// }
///
/// let versions: Vec<Box<dyn Version>> = vec![
///     Box::new(MyVersion { version: "2.0.0-alpha.1".into(), yanked: false }),
///     Box::new(MyVersion { version: "1.5.0".into(), yanked: true }),
///     Box::new(MyVersion { version: "1.4.0".into(), yanked: false }),
/// ];
///
/// let latest = find_latest_stable(&versions);
/// assert_eq!(latest.map(|v| v.version_string()), Some("1.4.0"));
/// ```
pub fn find_latest_stable(versions: &[Box<dyn Version>]) -> Option<&dyn Version> {
    versions.iter().find(|v| v.is_stable()).map(|v| v.as_ref())
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

    #[test]
    fn test_is_prerelease_alpha() {
        let version = MockVersion {
            version: "4.0.0-alpha.13".into(),
            yanked: false,
        };
        assert!(version.is_prerelease());
    }

    #[test]
    fn test_is_prerelease_beta() {
        let version = MockVersion {
            version: "2.0.0-beta.1".into(),
            yanked: false,
        };
        assert!(version.is_prerelease());
    }

    #[test]
    fn test_is_prerelease_rc() {
        let version = MockVersion {
            version: "1.5.0-rc.2".into(),
            yanked: false,
        };
        assert!(version.is_prerelease());
    }

    #[test]
    fn test_is_prerelease_dev() {
        let version = MockVersion {
            version: "3.0.0-dev".into(),
            yanked: false,
        };
        assert!(version.is_prerelease());
    }

    #[test]
    fn test_is_prerelease_canary() {
        let version = MockVersion {
            version: "5.0.0-canary".into(),
            yanked: false,
        };
        assert!(version.is_prerelease());
    }

    #[test]
    fn test_is_prerelease_nightly() {
        let version = MockVersion {
            version: "6.0.0-nightly".into(),
            yanked: false,
        };
        assert!(version.is_prerelease());
    }

    #[test]
    fn test_is_not_prerelease_stable() {
        let version = MockVersion {
            version: "1.2.3".into(),
            yanked: false,
        };
        assert!(!version.is_prerelease());
    }

    #[test]
    fn test_is_not_prerelease_patch() {
        let version = MockVersion {
            version: "1.0.214".into(),
            yanked: false,
        };
        assert!(!version.is_prerelease());
    }

    #[test]
    fn test_is_stable_true() {
        let version = MockVersion {
            version: "1.0.0".into(),
            yanked: false,
        };
        assert!(version.is_stable());
    }

    #[test]
    fn test_is_stable_false_yanked() {
        let version = MockVersion {
            version: "1.0.0".into(),
            yanked: true,
        };
        assert!(!version.is_stable());
    }

    #[test]
    fn test_is_stable_false_prerelease() {
        let version = MockVersion {
            version: "1.0.0-alpha.1".into(),
            yanked: false,
        };
        assert!(!version.is_stable());
    }

    #[test]
    fn test_find_latest_stable_skips_prerelease() {
        let versions: Vec<Box<dyn Version>> = vec![
            Box::new(MockVersion {
                version: "2.0.0-alpha.1".into(),
                yanked: false,
            }),
            Box::new(MockVersion {
                version: "1.5.0".into(),
                yanked: false,
            }),
        ];
        let latest = super::find_latest_stable(&versions);
        assert_eq!(latest.map(|v| v.version_string()), Some("1.5.0"));
    }

    #[test]
    fn test_find_latest_stable_skips_yanked() {
        let versions: Vec<Box<dyn Version>> = vec![
            Box::new(MockVersion {
                version: "2.0.0".into(),
                yanked: true,
            }),
            Box::new(MockVersion {
                version: "1.5.0".into(),
                yanked: false,
            }),
        ];
        let latest = super::find_latest_stable(&versions);
        assert_eq!(latest.map(|v| v.version_string()), Some("1.5.0"));
    }

    #[test]
    fn test_find_latest_stable_returns_first_stable() {
        let versions: Vec<Box<dyn Version>> = vec![
            Box::new(MockVersion {
                version: "3.0.0-beta.1".into(),
                yanked: false,
            }),
            Box::new(MockVersion {
                version: "2.0.0".into(),
                yanked: true,
            }),
            Box::new(MockVersion {
                version: "1.5.0".into(),
                yanked: false,
            }),
            Box::new(MockVersion {
                version: "1.4.0".into(),
                yanked: false,
            }),
        ];
        let latest = super::find_latest_stable(&versions);
        assert_eq!(latest.map(|v| v.version_string()), Some("1.5.0"));
    }

    #[test]
    fn test_find_latest_stable_empty_list() {
        let versions: Vec<Box<dyn Version>> = vec![];
        let latest = super::find_latest_stable(&versions);
        assert!(latest.is_none());
    }

    #[test]
    fn test_find_latest_stable_no_stable_versions() {
        let versions: Vec<Box<dyn Version>> = vec![
            Box::new(MockVersion {
                version: "2.0.0-alpha.1".into(),
                yanked: false,
            }),
            Box::new(MockVersion {
                version: "1.0.0".into(),
                yanked: true,
            }),
        ];
        let latest = super::find_latest_stable(&versions);
        assert!(latest.is_none());
    }
}
