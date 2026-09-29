//! Typed first argument of a registry-form `.package(...)` call: a Git URL or an SE-0292 registry id.

use std::fmt;

const MAX_SCOPE_LEN: usize = 39;
const MAX_NAME_LEN: usize = 100;

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

    /// The registry scope, i.e. the alias key looked up in `registries.json`.
    pub(crate) const fn scope(&self) -> &'a str {
        self.scope
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
    fn test_parse_length_boundaries() {
        assert!(RegistryIdentity::parse(&format!("{}.n", "a".repeat(39))).is_some());
        assert!(RegistryIdentity::parse(&format!("s.{}", "a".repeat(100))).is_some());
    }
}
