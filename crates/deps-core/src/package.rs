//! Newtypes distinguishing package names, version requirement strings, and
//! concrete resolved versions.
//!
//! [`PackageName`], [`VersionReq`], and [`ConcreteVersion`] wrap `String` to
//! give these kinds of manifest and registry data their own types, so a
//! function that expects one cannot accidentally be called with another.
//! None of these types validate, trim, or normalize their contents:
//! ecosystem-specific normalization (case folding, separator rewriting,
//! etc.) belongs to `EcosystemFormatter`, not to these types. See each
//! type's documentation for details.

use std::borrow::Borrow;
use std::fmt;

/// A package/crate name as it appears in a manifest file.
///
/// This is deliberately permissive: it stores whatever bytes the manifest
/// contained, including the empty string, leading/trailing whitespace, or
/// non-ASCII characters. No validation, trimming, or normalization is
/// performed by this type.
///
/// For several ecosystems this is not a "package name" in the narrow sense
/// but a registry lookup key: Maven and Gradle store `"group:artifact"`, Swift
/// stores `"owner/repo"`, and Go stores a URL-like module path. All of these
/// are valid `PackageName` values. Ecosystem-specific normalization (case
/// folding, separator rewriting, etc.) is the responsibility of
/// `EcosystemFormatter`, not this type — do not add validation rules here,
/// as it would silently break those ecosystems.
///
/// # Examples
///
/// ```
/// use deps_core::PackageName;
///
/// let name = PackageName::new("serde");
/// assert_eq!(name.as_str(), "serde");
/// assert_eq!(name, "serde");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PackageName(String);

impl PackageName {
    /// Wraps `value` as a `PackageName`, unchanged.
    ///
    /// This never fails and never modifies its input: an empty string is a
    /// valid `PackageName`, as is a string with surrounding whitespace.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::PackageName;
    ///
    /// let name = PackageName::new(String::from("tokio"));
    /// assert_eq!(name.as_str(), "tokio");
    /// ```
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Returns the package name as a string slice.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::PackageName;
    ///
    /// let name = PackageName::new("axum");
    /// assert_eq!(name.as_str(), "axum");
    /// ```
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consumes the `PackageName`, returning the wrapped `String`.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::PackageName;
    ///
    /// let name = PackageName::new("axum");
    /// let owned: String = name.into_string();
    /// assert_eq!(owned, "axum");
    /// ```
    #[must_use]
    pub fn into_string(self) -> String {
        self.0
    }
}

impl fmt::Display for PackageName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<String> for PackageName {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for PackageName {
    fn from(value: &str) -> Self {
        Self(value.to_string())
    }
}

impl AsRef<str> for PackageName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Enables `&str` lookups into `HashMap<PackageName, _>`/`HashSet<PackageName>`.
///
/// Sound because derived `Hash`/`Eq` on `PackageName(String)` delegate to
/// `String`'s implementations, which in turn are defined to match `str`'s
/// exactly (`String: Borrow<str>` in `std` rests on the same guarantee) — so
/// `PackageName` and the `str` it borrows always hash and compare equal.
impl Borrow<str> for PackageName {
    fn borrow(&self) -> &str {
        &self.0
    }
}

impl PartialEq<str> for PackageName {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<&str> for PackageName {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

/// A package name that failed a [`PackageNaming::validate_package_name`] lint.
///
/// This is not a construction-time gate — [`PackageName::new`] stays infallible — it
/// only carries *why* a name looks wrong so an LSP diagnostic can say something more
/// specific than "invalid name".
///
/// [`PackageNaming::validate_package_name`]: crate::lsp_helpers::PackageNaming::validate_package_name
///
/// # Examples
///
/// ```
/// use deps_core::InvalidPackageName;
///
/// let err = InvalidPackageName::new("name is longer than 214 characters");
/// assert_eq!(err.reason(), "name is longer than 214 characters");
/// assert_eq!(err.to_string(), "name is longer than 214 characters");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct InvalidPackageName(std::borrow::Cow<'static, str>);

impl InvalidPackageName {
    /// Creates an `InvalidPackageName` carrying `reason` as the explanation.
    pub fn new(reason: impl Into<std::borrow::Cow<'static, str>>) -> Self {
        Self(reason.into())
    }

    /// Returns why the name was rejected.
    #[must_use]
    pub fn reason(&self) -> &str {
        &self.0
    }
}

/// A version requirement string as it appears in a manifest file.
///
/// This is deliberately permissive: it stores whatever bytes the manifest
/// contained (e.g. `"^1.0"`, `">=2.0,<3.0"`, `"*"`), including the empty
/// string. No parsing, validation, trimming, or normalization is performed
/// by this type — ecosystems that need to parse a requirement (via `semver`,
/// `node-semver`, `pep440_rs`, etc.) do so from [`VersionReq::as_str`], not
/// from this type. Note that `deps-go`'s `GoDependency.version` also uses this
/// type even though it holds an exact pinned version (e.g. `"v1.9.1"`), not a
/// range or constraint — Go modules don't have a separate "requirement"
/// concept, so the exact version doubles as the requirement.
///
/// # Examples
///
/// ```
/// use deps_core::VersionReq;
///
/// let req = VersionReq::new("^1.0");
/// assert_eq!(req.as_str(), "^1.0");
/// assert_eq!(req, "^1.0");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct VersionReq(String);

impl VersionReq {
    /// Wraps `value` as a `VersionReq`, unchanged.
    ///
    /// This never fails and never modifies its input: an empty string is a
    /// valid `VersionReq`, as is a string with surrounding whitespace.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::VersionReq;
    ///
    /// let req = VersionReq::new(String::from(">=1.0"));
    /// assert_eq!(req.as_str(), ">=1.0");
    /// ```
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Returns the version requirement as a string slice.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::VersionReq;
    ///
    /// let req = VersionReq::new("~1.2");
    /// assert_eq!(req.as_str(), "~1.2");
    /// ```
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consumes the `VersionReq`, returning the wrapped `String`.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::VersionReq;
    ///
    /// let req = VersionReq::new("~1.2");
    /// let owned: String = req.into_string();
    /// assert_eq!(owned, "~1.2");
    /// ```
    #[must_use]
    pub fn into_string(self) -> String {
        self.0
    }
}

impl fmt::Display for VersionReq {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<String> for VersionReq {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for VersionReq {
    fn from(value: &str) -> Self {
        Self(value.to_string())
    }
}

impl AsRef<str> for VersionReq {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl PartialEq<str> for VersionReq {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<&str> for VersionReq {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

/// A concrete, resolved version string as returned by a registry.
///
/// This is deliberately permissive: it stores whatever bytes the registry
/// returned (e.g. `"1.2.3"`, `"2.0.0-beta.1"`), including the empty string.
/// No parsing, validation, trimming, or normalization is performed by this
/// type — ecosystems that need to parse a version (via `semver`,
/// `node-semver`, `pep440_rs`, etc.) do so from [`ConcreteVersion::as_str`],
/// not from this type. It is distinct from [`VersionReq`]: a `VersionReq` is
/// a constraint written in a manifest (`"^1.0"`), while a `ConcreteVersion`
/// is a single resolved version (`"1.0.4"`).
///
/// # Examples
///
/// ```
/// use deps_core::ConcreteVersion;
///
/// let version = ConcreteVersion::new("1.2.3");
/// assert_eq!(version.as_str(), "1.2.3");
/// assert_eq!(version, "1.2.3");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ConcreteVersion(String);

impl ConcreteVersion {
    /// Wraps `value` as a `ConcreteVersion`, unchanged.
    ///
    /// This never fails and never modifies its input: an empty string is a
    /// valid `ConcreteVersion`, as is a string with surrounding whitespace.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::ConcreteVersion;
    ///
    /// let version = ConcreteVersion::new(String::from("1.0.0"));
    /// assert_eq!(version.as_str(), "1.0.0");
    /// ```
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Returns the concrete version as a string slice.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::ConcreteVersion;
    ///
    /// let version = ConcreteVersion::new("4.5.6");
    /// assert_eq!(version.as_str(), "4.5.6");
    /// ```
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consumes the `ConcreteVersion`, returning the wrapped `String`.
    ///
    /// # Examples
    ///
    /// ```
    /// use deps_core::ConcreteVersion;
    ///
    /// let version = ConcreteVersion::new("4.5.6");
    /// let owned: String = version.into_string();
    /// assert_eq!(owned, "4.5.6");
    /// ```
    #[must_use]
    pub fn into_string(self) -> String {
        self.0
    }
}

impl fmt::Display for ConcreteVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<String> for ConcreteVersion {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for ConcreteVersion {
    fn from(value: &str) -> Self {
        Self(value.to_string())
    }
}

impl AsRef<str> for ConcreteVersion {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl PartialEq<str> for ConcreteVersion {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<&str> for ConcreteVersion {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

#[cfg(test)]
mod tests {
    use super::{ConcreteVersion, PackageName, VersionReq};

    #[test]
    fn package_name_round_trips_empty_string() {
        let name = PackageName::new("");
        assert_eq!(name.as_str(), "");
        assert_eq!(name, "");
    }

    #[test]
    fn package_name_round_trips_surrounding_whitespace() {
        let name = PackageName::new("  serde  ");
        assert_eq!(name.as_str(), "  serde  ");
        assert_eq!(name, "  serde  ");
    }

    #[test]
    fn package_name_round_trips_non_ascii() {
        let name = PackageName::new("パッケージ");
        assert_eq!(name.as_str(), "パッケージ");
        assert_eq!(name, "パッケージ");
    }

    #[test]
    fn package_name_compares_byte_wise_like_string() {
        assert_ne!(PackageName::new("Foo"), PackageName::new("foo"));
        assert_eq!(
            PackageName::new("Foo") == PackageName::new("foo"),
            "Foo" == "foo"
        );
    }

    #[test]
    fn package_name_into_string_roundtrip() {
        let original = String::from("tokio");
        let name = PackageName::new(original.clone());
        assert_eq!(name.into_string(), original);
    }

    #[test]
    fn package_name_hashmap_reachable_by_str_and_by_package_name() {
        use std::collections::HashMap;

        let mut map: HashMap<PackageName, u32> = HashMap::new();
        map.insert(PackageName::new("serde"), 1);

        assert_eq!(map.get("serde"), Some(&1));
        assert_eq!(map.get(&PackageName::new("serde")), Some(&1));
    }

    #[test]
    fn version_req_round_trips_empty_string() {
        let req = VersionReq::new("");
        assert_eq!(req.as_str(), "");
        assert_eq!(req, "");
    }

    #[test]
    fn version_req_round_trips_surrounding_whitespace() {
        let req = VersionReq::new("  ^1.0  ");
        assert_eq!(req.as_str(), "  ^1.0  ");
        assert_eq!(req, "  ^1.0  ");
    }

    #[test]
    fn version_req_round_trips_non_ascii() {
        let req = VersionReq::new("非対応");
        assert_eq!(req.as_str(), "非対応");
        assert_eq!(req, "非対応");
    }

    #[test]
    fn version_req_compares_byte_wise_like_string() {
        assert_ne!(VersionReq::new("^1.0"), VersionReq::new("^1.0 "));
    }

    #[test]
    fn version_req_into_string_roundtrip() {
        let original = String::from("~2.3.4");
        let req = VersionReq::new(original.clone());
        assert_eq!(req.into_string(), original);
    }

    #[test]
    fn concrete_version_round_trips_empty_string() {
        let version = ConcreteVersion::new("");
        assert_eq!(version.as_str(), "");
        assert_eq!(version, "");
    }

    #[test]
    fn concrete_version_round_trips_surrounding_whitespace() {
        let version = ConcreteVersion::new("  1.0.0  ");
        assert_eq!(version.as_str(), "  1.0.0  ");
        assert_eq!(version, "  1.0.0  ");
    }

    #[test]
    fn concrete_version_round_trips_non_ascii() {
        let version = ConcreteVersion::new("バージョン");
        assert_eq!(version.as_str(), "バージョン");
        assert_eq!(version, "バージョン");
    }

    #[test]
    fn concrete_version_compares_byte_wise_like_string() {
        assert_ne!(
            ConcreteVersion::new("1.0.0"),
            ConcreteVersion::new("1.0.0 ")
        );
    }

    #[test]
    fn concrete_version_into_string_roundtrip() {
        let original = String::from("2.3.4");
        let version = ConcreteVersion::new(original.clone());
        assert_eq!(version.into_string(), original);
    }
}
