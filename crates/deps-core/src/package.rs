//! Newtypes distinguishing package names from version requirement strings.
//!
//! [`PackageName`] and [`VersionReq`] wrap `String` to give the two kinds of
//! manifest data their own types, so a function that expects one cannot
//! accidentally be called with the other. Neither type validates, trims, or
//! normalizes its contents: ecosystem-specific normalization (case folding,
//! separator rewriting, etc.) belongs to `EcosystemFormatter`, not to these
//! types. See each type's documentation for details.

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
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize)]
#[serde(transparent)]
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
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize)]
#[serde(transparent)]
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

#[cfg(test)]
mod tests {
    use super::{PackageName, VersionReq};

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
    fn package_name_serializes_as_bare_string() {
        assert_eq!(
            serde_json::to_string(&PackageName::new("a/b")).unwrap(),
            "\"a/b\""
        );
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
    fn version_req_serializes_as_bare_string() {
        assert_eq!(
            serde_json::to_string(&VersionReq::new(">=1.0,<2.0")).unwrap(),
            "\">=1.0,<2.0\""
        );
    }
}
