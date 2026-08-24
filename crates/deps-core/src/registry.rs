use crate::error::Result;
use crate::{PackageName, VersionReq};
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
/// use deps_core::{Registry, Version, Metadata, PackageName};
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
/// struct MyMetadata { name: PackageName }
///
/// impl Metadata for MyMetadata {
///     fn name(&self) -> &PackageName { &self.name }
///     fn description(&self) -> Option<&str> { None }
///     fn repository(&self) -> Option<&str> { None }
///     fn documentation(&self) -> Option<&str> { None }
///     fn latest_version(&self) -> &str { "1.0.0" }
///     fn as_any(&self) -> &dyn Any { self }
/// }
///
/// impl Registry for MyRegistry {
///     fn get_versions<'a>(&'a self, _name: &'a PackageName)
///         -> Pin<Box<dyn std::future::Future<Output = deps_core::error::Result<Vec<Box<dyn Version>>>> + Send + 'a>>
///     {
///         Box::pin(async move { Ok(vec![Box::new(MyVersion { version: "1.0.0".into() }) as Box<dyn Version>]) })
///     }
///
///     fn get_latest_matching<'a>(&'a self, _name: &'a PackageName, _req: &'a deps_core::VersionReq)
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
    fn get_versions<'a>(
        &'a self,
        name: &'a PackageName,
    ) -> BoxFuture<'a, Result<Vec<Box<dyn Version>>>>;

    /// Like [`get_versions`](Self::get_versions), but lets a registry that can obtain
    /// [`Version::published_at`] only through an *extra* request gate that request behind
    /// `freshness.enabled` instead of always paying for it.
    ///
    /// Implementors overriding this method MUST keep every other aspect of
    /// [`get_versions`](Self::get_versions)'s behavior — set, order, and content of the
    /// returned versions — identical; the only difference the override may introduce is
    /// populating [`Version::published_at`]. Callers that render publish ages MUST call this
    /// method rather than [`get_versions`](Self::get_versions): the default implementation
    /// below simply forwards to `get_versions` and ignores `freshness`, so a caller that
    /// keeps calling `get_versions` silently gets no freshness signal even from a registry
    /// that implements this override.
    ///
    /// Default: forwards to [`get_versions`](Self::get_versions), ignoring `freshness`. This
    /// keeps the ten registries with no extra publish-time source unchanged, and keeps
    /// [`FreshnessSettings`](crate::freshness::FreshnessSettings) — a `Copy + 'static` DTO —
    /// out of every `Registry::new` signature and the `register!` ecosystem-registration
    /// macro.
    fn get_versions_with<'a>(
        &'a self,
        name: &'a PackageName,
        freshness: crate::freshness::FreshnessSettings,
    ) -> BoxFuture<'a, Result<Vec<Box<dyn Version>>>> {
        let _ = freshness;
        self.get_versions(name)
    }

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
        name: &'a PackageName,
        req: &'a VersionReq,
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

    /// Index of the latest version in `versions` satisfying `req`, with no I/O.
    ///
    /// `versions` must be a newest-first list as returned by this registry's
    /// [`get_versions`](Self::get_versions). Returns an index rather than a reference so
    /// callers holding an owned `Vec` can move the chosen element out
    /// (`versions.into_iter().nth(i)`) — a borrow into the list would keep it frozen while
    /// [`get_latest_matching`](Self::get_latest_matching) needs to return an owned
    /// `Box<dyn Version>`, and `Version` has no `clone_box`.
    ///
    /// Default: `None`. Every registry reachable from the LSP fetch path overrides this so
    /// the fetch loop can obtain both "latest" and the full version list from one round
    /// trip; the default exists so test doubles that never resolve a "latest" compile
    /// unchanged.
    fn select_latest_matching(
        &self,
        _versions: &[Box<dyn Version>],
        _req: &VersionReq,
    ) -> Option<usize> {
        None
    }

    /// Whether [`get_versions`](Self::get_versions) results carry meaningful
    /// per-version yank/deprecation data via [`Version::is_yanked`].
    ///
    /// Default `true`: a registry is opted into the yanked-version diagnostic
    /// unless it explicitly says it cannot answer. This fails toward
    /// correctness — a registry whose `is_yanked` later becomes real data
    /// starts participating automatically, by deleting its opt-out rather
    /// than by someone remembering to add an opt-in. Return `false` only
    /// when `is_yanked()` is hardcoded (e.g. always `false`) or otherwise
    /// cannot reflect real registry data; a `true` return authorizes callers
    /// to trust `is_yanked()` on versions from this registry's normal
    /// [`get_versions`](Self::get_versions)/
    /// [`get_latest_matching`](Self::get_latest_matching) results — it does
    /// not trigger any additional network request.
    fn reports_yanked(&self) -> bool {
        true
    }

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

    /// When this version was published, if the registry exposes it.
    ///
    /// Default `None` — ecosystems without publish metadata (or where
    /// fetching it would add a network round trip) degrade to pre-feature
    /// behavior: no freshness signal shown, no error, no change in ranking.
    fn published_at(&self) -> Option<crate::freshness::PublishTime> {
        None
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
    /// The package name as the *registry* reports it.
    ///
    /// This is the identifier the registry displays and that completion
    /// pastes into a manifest. It is not guaranteed byte-identical to the
    /// manifest-declared [`Dependency::name`](crate::ecosystem::Dependency::name)
    /// for the same package: casing may differ (NuGet, Composer, Swift), and
    /// for Maven/Gradle it is a `"group:artifact"` value synthesized from two
    /// separate response fields. Do not compare it to a manifest name
    /// without going through
    /// [`EcosystemFormatter::normalize_package_name`](crate::lsp_helpers::EcosystemFormatter::normalize_package_name).
    fn name(&self) -> &crate::PackageName;

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
        name: crate::PackageName,
        latest: String,
    }

    impl Metadata for MockMetadata {
        fn name(&self) -> &crate::PackageName {
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
            name: crate::PackageName::new("test-package"),
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
            name: crate::PackageName,
            desc: String,
            repo: String,
            docs: String,
            latest: String,
        }

        impl Metadata for FullMetadata {
            fn name(&self) -> &crate::PackageName {
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
            name: crate::PackageName::new("serde"),
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
