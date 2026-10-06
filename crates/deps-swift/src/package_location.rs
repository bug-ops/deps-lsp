//! Typed first argument of a registry-form `.package(...)` call: a Git URL or an SE-0292 registry id.

use std::fmt;

const MAX_SCOPE_LEN: usize = 39;
const MAX_NAME_LEN: usize = 100;

/// A canonical (ASCII-lowercase) SE-0292 registry scope, the single key `registries.json`
/// scopes are matched by.
///
/// SwiftPM identities are case-insensitive, so `Acme` and `acme` must select the same entry.
/// The inner string is private: a value can only come from [`Self::parse`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) struct RegistryScope(String);

impl RegistryScope {
    /// Parses `scope` on the SE-0292 scope grammar and lowercases it; `None` if it does not conform.
    pub(crate) fn parse(scope: &str) -> Option<Self> {
        is_valid_part(scope, MAX_SCOPE_LEN, b"-").then(|| Self(scope.to_ascii_lowercase()))
    }

    #[cfg(test)]
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RegistryScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A validated SE-0292 registry package identity (`scope.name`).
///
/// Fields are private, so a value can only be produced by [`Self::parse`] and is always
/// grammatically valid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RegistryIdentity<'a> {
    scope: &'a str,
    name: &'a str,
}

impl<'a> RegistryIdentity<'a> {
    /// Parses `scope.name` per SwiftPM's `PackageIdentity` grammar; `None` if it does not conform.
    ///
    /// Scope: 1-39 ASCII alphanumerics with single interior `-`. Name: 1-100 ASCII
    /// alphanumerics with single interior `-` or `_`.
    pub(crate) fn parse(id: &'a str) -> Option<Self> {
        let (scope, name) = id.split_once('.')?;
        (is_valid_part(scope, MAX_SCOPE_LEN, b"-") && is_valid_part(name, MAX_NAME_LEN, b"-_"))
            .then_some(Self { scope, name })
    }

    /// The registry scope as written.
    #[cfg(test)]
    pub(crate) const fn scope(&self) -> &'a str {
        self.scope
    }

    /// The case-folded scope, the key `registries.json` entries are matched by.
    pub(crate) fn scope_key(&self) -> RegistryScope {
        RegistryScope(self.scope.to_ascii_lowercase())
    }

    /// The case-folded package name, the second path segment of a registry request.
    pub(crate) fn name_key(&self) -> String {
        self.name.to_ascii_lowercase()
    }

    /// The lowercase `scope.name` identity, as sent on the wire and written in `Package.resolved`.
    pub(crate) fn canonical(&self) -> CanonicalIdentity {
        CanonicalIdentity(self.to_string().to_ascii_lowercase())
    }
}

/// A lowercase `scope.name` identity, usable as a map key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct CanonicalIdentity(String);

impl CanonicalIdentity {
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RegistryIdentity<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.scope, self.name)
    }
}

fn is_valid_part(part: &str, max_len: usize, separators: &[u8]) -> bool {
    let bytes = part.as_bytes();
    if bytes.is_empty() || bytes.len() > max_len {
        return false;
    }
    bytes.iter().enumerate().all(|(i, b)| {
        b.is_ascii_alphanumeric()
            || (separators.contains(b)
                && i.checked_sub(1)
                    .and_then(|p| bytes.get(p))
                    .is_some_and(u8::is_ascii_alphanumeric)
                && bytes.get(i + 1).is_some_and(u8::is_ascii_alphanumeric))
    })
}

/// Where a registry-form `.package(...)` dependency comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PackageLocation<'a> {
    /// `url: "<git url>"`.
    Url(&'a str),
    /// `id: "<scope>.<name>"`.
    Id(RegistryIdentity<'a>),
}

impl PackageLocation<'_> {
    /// The `url:` literal, or `""` for an `id:` dependency (no Git URL exists).
    pub(crate) const fn url(&self) -> &str {
        match self {
            Self::Url(url) => url,
            Self::Id(_) => "",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid_identities() {
        for id in ["mona.LinkedList", "a.b", "my-scope.my_pkg-1", "A1.b2"] {
            assert!(RegistryIdentity::parse(id).is_some(), "{id}");
        }
        let parsed = RegistryIdentity::parse("mona.LinkedList").unwrap();
        assert_eq!(parsed.scope(), "mona");
        assert_eq!(parsed.to_string(), "mona.LinkedList");
    }

    #[test]
    fn test_parse_rejects_invalid_identities() {
        let long_scope = format!("{}.n", "a".repeat(40));
        let long_name = format!("s.{}", "a".repeat(101));
        for id in [
            "noscope",
            ".name",
            "scope.",
            "sc--ope.n",
            "-a.b",
            "a-.b",
            "a.-b",
            "a.b-",
            "a.b--c",
            "a.b-_c",
            "a_b.c",
            "a.b.c",
            "sc ope.n",
            "é.n",
            &long_scope,
            &long_name,
        ] {
            assert!(RegistryIdentity::parse(id).is_none(), "{id}");
        }
    }

    #[test]
    fn test_scope_key_and_canonical_fold_case() {
        let id = RegistryIdentity::parse("Apple.Swift-NIO").unwrap();
        assert_eq!(id.scope_key().as_str(), "apple");
        assert_eq!(id.canonical().as_str(), "apple.swift-nio");
        assert_eq!(Some(id.scope_key()), RegistryScope::parse("APPLE"));
    }

    #[test]
    fn test_registry_scope_rejects_invalid_scopes() {
        let too_long = "a".repeat(40);
        for scope in ["", "a.b", "-a", "a-", "a--b", "a b", too_long.as_str()] {
            assert!(RegistryScope::parse(scope).is_none(), "{scope}");
        }
    }

    #[test]
    fn test_parse_length_boundaries() {
        assert!(RegistryIdentity::parse(&format!("{}.n", "a".repeat(39))).is_some());
        assert!(RegistryIdentity::parse(&format!("s.{}", "a".repeat(100))).is_some());
    }
}
