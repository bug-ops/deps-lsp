use crate::error::Result;
use crate::{ConcreteVersion, PackageName, VersionReq};
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
/// use deps_core::{Registry, Version, Metadata, PackageName, ConcreteVersion};
/// use std::any::Any;
/// use std::pin::Pin;
///
/// struct MyRegistry;
///
/// #[derive(Clone)]
/// struct MyVersion { version: ConcreteVersion }
///
/// impl Version for MyVersion {
///     fn version_string(&self) -> &ConcreteVersion { &self.version }
///     fn as_any(&self) -> &dyn Any { self }
/// }
///
/// #[derive(Clone)]
/// struct MyMetadata { name: PackageName, latest: ConcreteVersion }
///
/// impl Metadata for MyMetadata {
///     fn name(&self) -> &PackageName { &self.name }
///     fn description(&self) -> Option<&str> { None }
///     fn repository(&self) -> Option<&str> { None }
///     fn documentation(&self) -> Option<&str> { None }
///     fn latest_version(&self) -> &ConcreteVersion { &self.latest }
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
    /// Filter with [`RemovalStatus::blocks_resolution`], never with
    /// [`RemovalStatus::is_flagged`]. An `AdvisoryDeprecated` version is fully
    /// installable — excluding it turns an existing package into a false
    /// "Unknown package" (#347). Under a wildcard/empty requirement
    /// (`"*"`/`""`, see [`is_existence_wildcard`]) this is an *existence* check ("does this
    /// package exist / what is its newest version for display purposes"), not an upgrade
    /// recommendation: an implementation may prefer a non-yanked version but fall back to a
    /// yanked one rather than returning `None` when no non-yanked version exists — a yanked
    /// package still exists. `deps-npm` implements this fallback (mirrored by
    /// [`select_latest_matching`](Self::select_latest_matching)'s wildcard branch on the
    /// same registry, which every caller reaching this trait method through the shared
    /// fetch loop actually goes through first); the exception never applies to a concrete
    /// requirement.
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

    /// Like [`get_latest_matching`](Self::get_latest_matching), but lets a registry whose
    /// "latest matching" selection can be refined by ecosystem-specific manifest state (e.g.
    /// Composer's `minimum-stability` field, #424) read it, alongside `req`.
    ///
    /// `minimum_stability` is an opaque, ecosystem-defined string (Composer's own stability
    /// keyword: `"dev"`, `"alpha"`, `"beta"`, `"RC"`, or `"stable"`) rather than a shared type,
    /// mirroring [`get_versions_with`](Self::get_versions_with)'s
    /// [`FreshnessSettings`](crate::freshness::FreshnessSettings) precedent for "an optional
    /// extra parameter most registries ignore" — except here even the *shape* of the extra
    /// context is ecosystem-specific, so no shared DTO is introduced for it; only the one
    /// registry that understands the string overrides this method.
    ///
    /// Default: forwards to [`get_latest_matching`](Self::get_latest_matching), ignoring
    /// `minimum_stability`. This keeps every registry with no manifest-level stability
    /// concept unchanged.
    fn get_latest_matching_with_context<'a>(
        &'a self,
        name: &'a PackageName,
        req: &'a VersionReq,
        minimum_stability: Option<&'a str>,
    ) -> BoxFuture<'a, Result<Option<Box<dyn Version>>>> {
        let _ = minimum_stability;
        self.get_latest_matching(name, req)
    }

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
    /// Filter with [`RemovalStatus::blocks_resolution`], never with
    /// [`RemovalStatus::is_flagged`]. An `AdvisoryDeprecated` version is fully
    /// installable — excluding it turns an existing package into a false
    /// "Unknown package" (#347). Under a wildcard/empty requirement (see
    /// [`is_existence_wildcard`]) this is an *existence* check, not an upgrade
    /// recommendation: Cargo, PyPI, Dart, npm, and Deno implement it by gating on
    /// [`is_existence_wildcard`] and delegating to [`select_latest_for_existence`].
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

    /// Like [`select_latest_matching`](Self::select_latest_matching), but lets a registry
    /// whose selection can be refined by ecosystem-specific manifest state (e.g. Composer's
    /// `minimum-stability` field, #424) read it, alongside `versions` and `req`. See
    /// [`get_latest_matching_with_context`](Self::get_latest_matching_with_context) for why
    /// `minimum_stability` is an opaque per-ecosystem string rather than a shared type.
    ///
    /// Default: forwards to [`select_latest_matching`](Self::select_latest_matching), ignoring
    /// `minimum_stability`. This keeps every registry with no manifest-level stability concept
    /// unchanged.
    fn select_latest_matching_with_context(
        &self,
        versions: &[Box<dyn Version>],
        req: &VersionReq,
        minimum_stability: Option<&str>,
    ) -> Option<usize> {
        let _ = minimum_stability;
        self.select_latest_matching(versions, req)
    }

    /// Whether [`get_versions`](Self::get_versions) results carry meaningful
    /// per-version yank/deprecation data via [`Version::removal_status`].
    ///
    /// Default `true`: a registry is opted into the yanked-version diagnostic
    /// unless it explicitly says it cannot answer. This fails toward
    /// correctness — a registry whose `removal_status` later becomes real
    /// data starts participating automatically, by deleting its opt-out
    /// rather than by someone remembering to add an opt-in. Return `false`
    /// only when `removal_status()` is hardcoded (e.g. always
    /// `RemovalStatus::Available`) or otherwise cannot reflect real registry
    /// data; a `true` return authorizes callers to trust `removal_status()`
    /// on versions from this registry's normal
    /// [`get_versions`](Self::get_versions)/
    /// [`get_latest_matching`](Self::get_latest_matching) results — it does
    /// not trigger any additional network request.
    fn reports_yanked(&self) -> bool {
        true
    }

    /// Downcast to concrete registry type for ecosystem-specific operations
    fn as_any(&self) -> &dyn Any;
}

/// Whether `version` contains one of the common pre-release substrings
/// (`-alpha`, `-beta`, `-rc`, `-dev`, `-pre`, `-snapshot`, `-canary`,
/// `-nightly`), case-insensitively.
///
/// This is [`Version::is_prerelease`]'s default heuristic, extracted so an
/// ecosystem that overrides `is_prerelease` to cover format-specific gaps
/// (e.g. Composer's `dev-` branch-alias prefix) can extend this baseline
/// instead of copy-pasting the substring list out of sync with it.
///
/// # Examples
///
/// ```
/// use deps_core::has_default_prerelease_marker;
///
/// assert!(has_default_prerelease_marker("1.0.0-beta"));
/// assert!(has_default_prerelease_marker("1.0.0-RC1"));
/// assert!(!has_default_prerelease_marker("1.0.0"));
/// ```
#[must_use]
pub fn has_default_prerelease_marker(version: &str) -> bool {
    let v = version.to_lowercase();
    v.contains("-alpha")
        || v.contains("-beta")
        || v.contains("-rc")
        || v.contains("-dev")
        || v.contains("-pre")
        || v.contains("-snapshot")
        || v.contains("-canary")
        || v.contains("-nightly")
}

/// Outcome of a registry's per-version removal/deprecation signal.
///
/// Replaces a bare `is_yanked(): bool`, which could not distinguish a version
/// a registry has *hard-removed from resolution* (`Yanked`) from one that is
/// merely flagged as deprecated/abandoned but still fully installable
/// (`AdvisoryDeprecated`). Conflating the two caused #347: Composer's
/// package-level `abandoned` flag was read through `is_yanked()`, so every
/// version of an abandoned-but-installable package was filtered out of
/// resolution, turning an existing package into a false "Unknown package"
/// diagnostic.
///
/// Call [`blocks_resolution`](Self::blocks_resolution) to decide whether a
/// version may be selected as an upgrade/latest candidate. Call
/// [`is_flagged`](Self::is_flagged) only to surface the registry's flag to
/// the user (e.g. a yanked/deprecated diagnostic) — never to filter
/// resolution.
///
/// # Examples
///
/// ```
/// use deps_core::RemovalStatus;
///
/// assert!(!RemovalStatus::Available.blocks_resolution());
/// assert!(!RemovalStatus::AdvisoryDeprecated.blocks_resolution());
/// assert!(RemovalStatus::Yanked.blocks_resolution());
///
/// assert!(RemovalStatus::AdvisoryDeprecated.is_flagged());
/// assert!(RemovalStatus::Yanked.is_flagged());
/// assert!(!RemovalStatus::Available.is_flagged());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RemovalStatus {
    /// The registry reports no removal/deprecation signal for this version.
    Available,
    /// The registry flags this version (or its package) as
    /// deprecated/abandoned, but the version remains fully resolvable and
    /// installable.
    AdvisoryDeprecated,
    /// The registry has hard-removed this version from fresh resolution (a
    /// real yank/retraction). Existing installs may keep using it, but it
    /// must not be selected as an upgrade/latest candidate.
    Yanked,
}

impl RemovalStatus {
    /// Whether fresh resolution must skip this version.
    ///
    /// `true` only for [`Yanked`](Self::Yanked). An
    /// [`AdvisoryDeprecated`](Self::AdvisoryDeprecated) version is fully
    /// installable — excluding it from resolution is what caused #347.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::RemovalStatus;
    ///
    /// assert!(!RemovalStatus::AdvisoryDeprecated.blocks_resolution());
    /// assert!(RemovalStatus::Yanked.blocks_resolution());
    /// ```
    #[must_use]
    pub const fn blocks_resolution(self) -> bool {
        matches!(self, Self::Yanked)
    }

    /// Whether the registry flags this version at all, hard or advisory.
    ///
    /// Use this only to decide whether to surface a warning to the user —
    /// never to filter resolution; use
    /// [`blocks_resolution`](Self::blocks_resolution) for that.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::RemovalStatus;
    ///
    /// assert!(!RemovalStatus::Available.is_flagged());
    /// assert!(RemovalStatus::AdvisoryDeprecated.is_flagged());
    /// assert!(RemovalStatus::Yanked.is_flagged());
    /// ```
    #[must_use]
    pub const fn is_flagged(self) -> bool {
        !matches!(self, Self::Available)
    }

    /// Builds a status from a registry's hard yanked/retracted boolean flag.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::RemovalStatus;
    ///
    /// assert_eq!(RemovalStatus::from_yanked(true), RemovalStatus::Yanked);
    /// assert_eq!(RemovalStatus::from_yanked(false), RemovalStatus::Available);
    /// ```
    #[must_use]
    pub const fn from_yanked(flag: bool) -> Self {
        if flag { Self::Yanked } else { Self::Available }
    }

    /// Builds a status from a registry's advisory deprecated/abandoned boolean flag.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::RemovalStatus;
    ///
    /// assert_eq!(RemovalStatus::from_advisory(true), RemovalStatus::AdvisoryDeprecated);
    /// assert_eq!(RemovalStatus::from_advisory(false), RemovalStatus::Available);
    /// ```
    #[must_use]
    pub const fn from_advisory(flag: bool) -> Self {
        if flag {
            Self::AdvisoryDeprecated
        } else {
            Self::Available
        }
    }
}

/// Version information trait.
///
/// All version types must implement this to work with generic handlers.
pub trait Version: Send + Sync {
    /// Version string (e.g., "1.0.214", "14.21.3").
    fn version_string(&self) -> &ConcreteVersion;

    /// This version's removal/deprecation status as reported by the registry.
    ///
    /// Default: [`RemovalStatus::Available`] — ecosystems with no
    /// yank/deprecation signal need no override.
    fn removal_status(&self) -> RemovalStatus {
        RemovalStatus::Available
    }

    /// Whether this version is a pre-release (alpha, beta, rc, etc.).
    ///
    /// Default implementation checks for common pre-release patterns via
    /// [`has_default_prerelease_marker`].
    fn is_prerelease(&self) -> bool {
        has_default_prerelease_marker(self.version_string().as_str())
    }

    /// Available feature flags (empty if not supported by ecosystem).
    fn features(&self) -> Vec<String> {
        vec![]
    }

    /// Downcast to concrete version type
    fn as_any(&self) -> &dyn Any;

    /// Whether this version is stable: not hard-yanked and not a pre-release.
    ///
    /// An [`AdvisoryDeprecated`](RemovalStatus::AdvisoryDeprecated) version counts as
    /// stable here — it remains fully resolvable, just flagged. Only
    /// [`Yanked`](RemovalStatus::Yanked) disqualifies a version; see
    /// [`RemovalStatus::blocks_resolution`].
    fn is_stable(&self) -> bool {
        !self.removal_status().blocks_resolution() && !self.is_prerelease()
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
/// - Not hard-yanked ([`RemovalStatus::Yanked`]) — an
///   [`AdvisoryDeprecated`](RemovalStatus::AdvisoryDeprecated) version still counts as
///   stable, since it remains fully resolvable
/// - Not a pre-release (alpha, beta, rc, etc.)
///
/// Assumes versions are sorted newest-first (as returned by registries).
///
/// # Examples
///
/// ```
/// use deps_core::registry::{RemovalStatus, Version, find_latest_stable};
/// use deps_core::ConcreteVersion;
/// use std::any::Any;
///
/// struct MyVersion { version: ConcreteVersion, yanked: bool }
///
/// impl Version for MyVersion {
///     fn version_string(&self) -> &ConcreteVersion { &self.version }
///     fn removal_status(&self) -> RemovalStatus { RemovalStatus::from_yanked(self.yanked) }
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
/// assert_eq!(latest.map(|v| v.version_string().as_str()), Some("1.4.0"));
/// ```
pub fn find_latest_stable(versions: &[Box<dyn Version>]) -> Option<&dyn Version> {
    versions.iter().find(|v| v.is_stable()).map(|v| v.as_ref())
}

/// Whether `req` is a wildcard/empty requirement (`""` or `"*"`, ignoring surrounding
/// whitespace) rather than a concrete version constraint.
///
/// A wildcard requirement turns [`get_latest_matching`](Registry::get_latest_matching) and
/// [`select_latest_matching`](Registry::select_latest_matching) into an *existence* check
/// ("does this package exist / what is its newest version for display purposes") instead of
/// an upgrade recommendation — see [`select_latest_for_existence`], which callers must gate
/// on this function before use.
///
/// # Examples
///
/// ```
/// use deps_core::{VersionReq, is_existence_wildcard};
///
/// assert!(is_existence_wildcard(&VersionReq::new("*")));
/// assert!(is_existence_wildcard(&VersionReq::new("")));
/// assert!(!is_existence_wildcard(&VersionReq::new("^1.2")));
/// ```
#[must_use]
pub fn is_existence_wildcard(req: &crate::VersionReq) -> bool {
    is_existence_wildcard_str(req.as_str())
}

/// [`is_existence_wildcard`] for a raw `&str`, without allocating a [`VersionReq`] wrapper.
///
/// Exists for callers that hold a version requirement as `&str` rather than a `VersionReq`
/// (e.g. an inherent method taking `req_str: &str` for its own parsing needs) — going through
/// [`is_existence_wildcard`] there would allocate a `String` via `VersionReq::new` on every
/// call just to check it.
///
/// # Examples
///
/// ```
/// use deps_core::registry::is_existence_wildcard_str;
///
/// assert!(is_existence_wildcard_str("*"));
/// assert!(is_existence_wildcard_str(""));
/// assert!(!is_existence_wildcard_str("^1.2"));
/// ```
#[must_use]
pub fn is_existence_wildcard_str(req: &str) -> bool {
    matches!(req.trim(), "" | "*")
}

/// Index of the version an *existence* check should report as "latest", ignoring `req`
/// entirely.
///
/// This is the shared 3-rung fallback ladder used under a wildcard/empty requirement, where
/// every version satisfies by definition and the question is only which one to prefer for
/// display:
///
/// 1. The newest version that is neither flagged
///    ([`RemovalStatus::is_flagged`]) nor a pre-release ([`Version::is_prerelease`]).
/// 2. Else, the newest version that does not block resolution
///    ([`RemovalStatus::blocks_resolution`]) — an `AdvisoryDeprecated` version counts here.
/// 3. Else, index `0` unconditionally — the newest version overall, however it is flagged.
///    A yanked-or-prerelease-only package still exists; this rung is what turns that case
///    into "here is its newest version" instead of a false "Unknown package" (#347, #364).
///
/// `versions` must be sorted newest-first, as returned by [`Registry::get_versions`]. Returns
/// `None` only when `versions` is empty.
///
/// # Requirement-blindness is deliberate and dangerous
///
/// This function takes no `req` parameter and does not check whether the caller is under a
/// wildcard requirement — it always returns rung 3 as a last resort, regardless of what a
/// concrete requirement might demand. It is **only correct once the caller has already
/// confirmed the requirement is a wildcard** via [`is_existence_wildcard`]. Calling it
/// ungated — e.g. under a concrete `^1.2` requirement — can return a version that does not
/// satisfy that requirement at all, silently corrupting upgrade resolution.
///
/// # Examples
///
/// ```
/// use deps_core::registry::{RemovalStatus, Version, select_latest_for_existence};
/// use deps_core::ConcreteVersion;
/// use std::any::Any;
///
/// struct MyVersion { version: ConcreteVersion, status: RemovalStatus, prerelease: bool }
///
/// impl Version for MyVersion {
///     fn version_string(&self) -> &ConcreteVersion { &self.version }
///     fn removal_status(&self) -> RemovalStatus { self.status }
///     fn is_prerelease(&self) -> bool { self.prerelease }
///     fn as_any(&self) -> &dyn Any { self }
/// }
///
/// // Newest version is yanked; rung 3 still returns it rather than `None`.
/// let versions = vec![
///     MyVersion { version: "2.0.0".into(), status: RemovalStatus::Yanked, prerelease: false },
///     MyVersion { version: "1.5.0".into(), status: RemovalStatus::Yanked, prerelease: false },
/// ];
///
/// let idx = select_latest_for_existence(&versions, |v| v as &dyn Version);
/// assert_eq!(idx, Some(0));
///
/// assert_eq!(select_latest_for_existence::<MyVersion>(&[], |v| v as &dyn Version), None);
/// ```
#[must_use]
pub fn select_latest_for_existence<T>(
    versions: &[T],
    as_version: impl Fn(&T) -> &dyn Version,
) -> Option<usize> {
    if versions.is_empty() {
        return None;
    }
    Some(
        versions
            .iter()
            .position(|v| {
                let v = as_version(v);
                !v.removal_status().is_flagged() && !v.is_prerelease()
            })
            .or_else(|| {
                versions
                    .iter()
                    .position(|v| !as_version(v).removal_status().blocks_resolution())
            })
            .unwrap_or(0),
    )
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
    fn latest_version(&self) -> &ConcreteVersion;

    /// Downcast to concrete metadata type
    fn as_any(&self) -> &dyn Any;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockVersion {
        version: ConcreteVersion,
        yanked: bool,
    }

    impl Version for MockVersion {
        fn version_string(&self) -> &ConcreteVersion {
            &self.version
        }

        fn removal_status(&self) -> RemovalStatus {
            RemovalStatus::from_yanked(self.yanked)
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
        assert_eq!(boxed.version_string().as_str(), "1.2.3");
        assert!(!boxed.removal_status().blocks_resolution());
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
        latest: ConcreteVersion,
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

        fn latest_version(&self) -> &ConcreteVersion {
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
        assert_eq!(boxed.latest_version().as_str(), "2.0.0");
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
            latest: ConcreteVersion,
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
            fn latest_version(&self) -> &ConcreteVersion {
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
        assert_eq!(latest.map(|v| v.version_string().as_str()), Some("1.5.0"));
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
        assert_eq!(latest.map(|v| v.version_string().as_str()), Some("1.5.0"));
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
        assert_eq!(latest.map(|v| v.version_string().as_str()), Some("1.5.0"));
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

    struct StatusVersion {
        version: ConcreteVersion,
        status: RemovalStatus,
    }

    impl Version for StatusVersion {
        fn version_string(&self) -> &ConcreteVersion {
            &self.version
        }

        fn removal_status(&self) -> RemovalStatus {
            self.status
        }

        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    #[test]
    fn test_is_stable_true_for_advisory_deprecated() {
        let version = StatusVersion {
            version: "1.0.0".into(),
            status: RemovalStatus::AdvisoryDeprecated,
        };
        assert!(version.is_stable());
    }

    #[test]
    fn test_is_stable_false_for_yanked() {
        let version = StatusVersion {
            version: "1.0.0".into(),
            status: RemovalStatus::Yanked,
        };
        assert!(!version.is_stable());
    }

    #[test]
    fn test_removal_status_blocks_resolution() {
        assert!(!RemovalStatus::Available.blocks_resolution());
        assert!(!RemovalStatus::AdvisoryDeprecated.blocks_resolution());
        assert!(RemovalStatus::Yanked.blocks_resolution());
    }

    #[test]
    fn test_removal_status_is_flagged() {
        assert!(!RemovalStatus::Available.is_flagged());
        assert!(RemovalStatus::AdvisoryDeprecated.is_flagged());
        assert!(RemovalStatus::Yanked.is_flagged());
    }

    #[test]
    fn test_removal_status_from_yanked() {
        assert_eq!(RemovalStatus::from_yanked(true), RemovalStatus::Yanked);
        assert_eq!(RemovalStatus::from_yanked(false), RemovalStatus::Available);
    }

    #[test]
    fn test_removal_status_from_advisory() {
        assert_eq!(
            RemovalStatus::from_advisory(true),
            RemovalStatus::AdvisoryDeprecated
        );
        assert_eq!(
            RemovalStatus::from_advisory(false),
            RemovalStatus::Available
        );
    }
}
