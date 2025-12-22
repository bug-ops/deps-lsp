use crate::error::Result;
use async_trait::async_trait;

/// Generic package registry interface.
///
/// Implementors provide access to a package registry (crates.io, npm, PyPI, etc.)
/// with version lookup, search, and metadata retrieval capabilities.
///
/// All methods return `Result<T>` to allow graceful error handling.
/// LSP handlers must never panic on registry errors.
///
/// # Examples
///
/// ```no_run
/// use deps_core::{PackageRegistry, VersionInfo};
/// use async_trait::async_trait;
///
/// # struct MyRegistry;
/// # #[derive(Clone)]
/// # struct MyVersion { version: String }
/// # impl VersionInfo for MyVersion {
/// #     fn version_string(&self) -> &str { &self.version }
/// #     fn is_yanked(&self) -> bool { false }
/// # }
/// # #[derive(Clone)]
/// # struct MyMetadata { name: String }
/// # impl deps_core::PackageMetadata for MyMetadata {
/// #     fn name(&self) -> &str { &self.name }
/// #     fn description(&self) -> Option<&str> { None }
/// #     fn repository(&self) -> Option<&str> { None }
/// #     fn documentation(&self) -> Option<&str> { None }
/// #     fn latest_version(&self) -> &str { "1.0.0" }
/// # }
/// #[async_trait]
/// impl PackageRegistry for MyRegistry {
///     type Version = MyVersion;
///     type Metadata = MyMetadata;
///     type VersionReq = String;
///
///     async fn get_versions(&self, name: &str) -> deps_core::error::Result<Vec<Self::Version>> {
///         Ok(vec![MyVersion { version: "1.0.0".into() }])
///     }
///
///     async fn get_latest_matching(
///         &self,
///         _name: &str,
///         _req: &Self::VersionReq,
///     ) -> deps_core::error::Result<Option<Self::Version>> {
///         Ok(None)
///     }
///
///     async fn search(&self, _query: &str, _limit: usize) -> deps_core::error::Result<Vec<Self::Metadata>> {
///         Ok(vec![])
///     }
/// }
/// ```
#[async_trait]
pub trait PackageRegistry: Send + Sync {
    /// Version information type for this registry.
    type Version: VersionInfo + Clone + Send + Sync;

    /// Metadata type for search results.
    type Metadata: PackageMetadata + Clone + Send + Sync;

    /// Version requirement type (e.g., semver::VersionReq for Cargo, npm semver for npm).
    type VersionReq: Clone + Send + Sync;

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
    async fn get_versions(&self, name: &str) -> Result<Vec<Self::Version>>;

    /// Finds the latest version matching a version requirement.
    ///
    /// Only returns stable (non-yanked, non-deprecated) versions unless
    /// explicitly requested in the version requirement.
    ///
    /// # Returns
    ///
    /// - `Ok(Some(version))` - Latest matching version found
    /// - `Ok(None)` - No matching version found
    /// - `Err(_)` - Network or parsing error
    async fn get_latest_matching(
        &self,
        name: &str,
        req: &Self::VersionReq,
    ) -> Result<Option<Self::Version>>;

    /// Searches for packages by name or keywords.
    ///
    /// Returns up to `limit` results sorted by relevance/popularity.
    ///
    /// # Errors
    ///
    /// Returns error if network request or parsing fails.
    async fn search(&self, query: &str, limit: usize) -> Result<Vec<Self::Metadata>>;
}

/// Version information trait.
///
/// All version types must implement this to work with generic handlers.
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

/// Package metadata trait.
///
/// Used for completion items and hover documentation.
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
