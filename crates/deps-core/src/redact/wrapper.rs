//! Pre-redacted text wrappers: a [`super::url::url_for_tracing`]/
//! [`super::key::redact_declaration_key`] result held as a distinct type ([`RedactedUrl`]/
//! [`RedactedName`]) so nothing raw is ever retained past construction.

use std::marker::PhantomData;

use super::key::redact_declaration_key;
use super::url::url_for_tracing;

mod private {
    pub trait Sealed {}
}

/// Selects which redaction function a [`RedactedText`] applies at construction.
///
/// Sealed (issue #1216): mirrors `crate::net_policy`'s `RegistryUrlKind`/`private::Sealed`
/// pattern for the same reason — [`UrlRedaction`] and [`NameRedaction`] are the only two
/// kinds this crate ever needs, and a foreign implementor could otherwise mint a
/// [`RedactedText`] that claims to be redacted without actually running either redaction
/// function. Unlike `RegistryUrlKind`'s sealing module (`pub mod private`, deliberately
/// reachable so sibling ecosystem crates in this workspace can implement it for their own
/// marker types), this trait's `private` module is not `pub` at all: no crate outside this
/// one ever needs to implement `RedactionKind`, so the plain same-crate sealed-trait idiom
/// applies — even a downstream crate's own doctest cannot name `private::Sealed` to implement
/// it.
///
/// # Examples
///
/// ```
/// use deps_core::redact::{RedactionKind, UrlRedaction};
///
/// assert_eq!(
///     UrlRedaction::redact("https://user:hunter2@registry.example/simple"),
///     "https://***@registry.example/simple"
/// );
/// ```
pub trait RedactionKind: private::Sealed {
    /// Redacts `raw`, producing the text a [`RedactedText<Self>`] retains.
    fn redact(raw: &str) -> String;
}

/// [`RedactedText`] marker selecting [`super::url::url_for_tracing`] — see [`RedactedUrl`].
pub enum UrlRedaction {}

impl private::Sealed for UrlRedaction {}

impl RedactionKind for UrlRedaction {
    fn redact(raw: &str) -> String {
        url_for_tracing(raw)
    }
}

/// [`RedactedText`] marker selecting [`super::key::redact_declaration_key`] — see
/// [`RedactedName`].
pub enum NameRedaction {}

impl private::Sealed for NameRedaction {}

impl RedactionKind for NameRedaction {
    fn redact(raw: &str) -> String {
        redact_declaration_key(raw).into_owned()
    }
}

/// A value that has already been redacted (via `K::redact`) for safe inclusion in error or
/// log output — the shared implementation behind [`RedactedUrl`] and [`RedactedName`] (issue
/// #1216).
///
/// Eagerly redacted at construction: [`Self::new`] applies `K::redact` immediately and
/// retains only the resulting text, so the raw value passed in is never stored, not even
/// transiently. The only public read surface — [`Display`](std::fmt::Display),
/// [`AsRef<str>`], a [`Debug`](std::fmt::Debug) impl that forwards to the redacted text, and
/// [`Self::into_inner`] (which hands back that same already-redacted text by value) — is
/// therefore always safe to log: there is no `expose()`-style escape hatch, because nothing raw
/// remains to expose.
///
/// `PartialEq`/`Eq`/`Hash` compare the *redacted* text, not the original input — see
/// [`RedactedUrl`]'s own doc for why this is intentional and what it means for using either
/// alias as a cache key.
///
/// Carries no bound on `K` itself in its own definition — [`Clone`], [`Debug`](std::fmt::Debug),
/// [`PartialEq`], [`Eq`], [`Hash`](std::hash::Hash), and [`Display`](std::fmt::Display) are all
/// hand-written (not derived) so that none of them require `K: Clone`/`K: Hash`/etc., and
/// `PhantomData<fn() -> K>` (rather than `PhantomData<K>`) keeps [`Send`]/[`Sync`]
/// unconditional regardless of `K` — mirrors `crate::net_policy::ValidatedRegistryUrl<K>`'s
/// identical shape for the identical reason.
///
/// # Examples
///
/// ```
/// use deps_core::redact::{RedactedName, RedactedUrl};
///
/// let redacted = RedactedUrl::new("https://user:hunter2@registry.example/simple");
/// assert_eq!(redacted.to_string(), "https://***@registry.example/simple");
///
/// let redacted = RedactedName::new("com.google.guava:guava");
/// assert_eq!(redacted.to_string(), "com.google.guava:guava");
/// ```
pub struct RedactedText<K: RedactionKind>(String, PhantomData<fn() -> K>);

impl<K: RedactionKind> RedactedText<K> {
    /// Redacts `raw` immediately via `K::redact`, retaining only the resulting text.
    #[must_use]
    pub fn new(raw: &str) -> Self {
        Self(K::redact(raw), PhantomData)
    }

    /// Takes ownership of the redacted text without allocating a second copy — unlike
    /// [`Display`](std::fmt::Display)/[`AsRef<str>`], which only ever hand back a borrow and so
    /// require the caller to clone if it needs an owned `String`.
    #[must_use]
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl<K: RedactionKind> From<&str> for RedactedText<K> {
    fn from(raw: &str) -> Self {
        Self::new(raw)
    }
}

impl<K: RedactionKind> From<String> for RedactedText<K> {
    fn from(raw: String) -> Self {
        Self::new(&raw)
    }
}

impl<K: RedactionKind> Clone for RedactedText<K> {
    fn clone(&self) -> Self {
        Self(self.0.clone(), PhantomData)
    }
}

impl<K: RedactionKind> PartialEq for RedactedText<K> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<K: RedactionKind> Eq for RedactedText<K> {}

impl<K: RedactionKind> std::hash::Hash for RedactedText<K> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl<K: RedactionKind> std::fmt::Display for RedactedText<K> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl<K: RedactionKind> std::fmt::Debug for RedactedText<K> {
    /// Forwards to the redacted text's own `Debug` (a quoted string), not a struct-wrapper
    /// rendering — so a `RedactedText` embedded in a hand-written `Debug` impl (see
    /// `deps_core::error::DepsError`) reads identically to the plain `String` field it
    /// replaces.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&self.0, f)
    }
}

impl<K: RedactionKind> AsRef<str> for RedactedText<K> {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl<K: RedactionKind> PartialEq<str> for RedactedText<K> {
    /// # Warning
    ///
    /// Compares against the *redacted* text, not `other` as raw input — e.g.
    /// `RedactedUrl::new(u) == "https://h/p?token=a"` is `false` by construction, since the
    /// left side has already dropped the query string.
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl<K: RedactionKind> PartialEq<&str> for RedactedText<K> {
    /// # Warning
    ///
    /// Same redacted-text comparison as `PartialEq<str>` above — `other` is compared against
    /// the redacted text, not treated as raw input.
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

/// A URL-bearing value that has already been redacted for safe inclusion in error or log
/// output — the structural chokepoint for outbound-URL redaction (issue #789).
///
/// Applies [`super::url::url_for_tracing`]'s rules at construction (via `Self::new`) and
/// retains only the resulting text — nothing raw is stored, not even transiently, and there
/// is no escape hatch that could return it.
///
/// # Examples
///
/// ```
/// use deps_core::redact::RedactedUrl;
///
/// let redacted = RedactedUrl::new("https://npm.internal/pkg?token=super-secret-value");
/// assert_eq!(redacted.to_string(), "https://npm.internal/pkg");
///
/// let redacted = RedactedUrl::new("https://user:hunter2@registry.example/simple");
/// assert_eq!(redacted.to_string(), "https://***@registry.example/simple");
/// ```
///
/// `PartialEq`/`Eq`/`Hash` compare the *redacted* text, not the original input: two distinct
/// URLs differing only by a stripped component (query string, fragment, or userinfo) compare
/// equal here even though they were different requests — e.g. `?token=a` and `?token=b`
/// against the same path both redact to the same value. This is intentional for this type's
/// own purpose (deduplicating/comparing error variants in tests, `deps_core::error`'s own
/// `assert_eq!` usage), but makes `RedactedUrl` unsuitable as a cache key or any other context
/// that needs to distinguish the underlying raw URLs — use the raw `String`/`reqwest::Url`
/// value for that instead.
pub type RedactedUrl = RedactedText<UrlRedaction>;

/// A package/coordinate name, stored pre-redacted via [`super::key::redact_declaration_key`] so
/// it is always safe to log or surface in a client-visible message (#1209).
///
/// Unlike [`RedactedUrl`] (built for actual URLs, which mangles ordinary Maven/Gradle
/// coordinates such as `com.google.guava:guava` into `com.google.guava:***`), this alias uses
/// `redact_declaration_key`'s credential-shape gate: a genuine package/coordinate name is left
/// untouched, while a credential-shaped value (e.g. `deploy:TOKEN@host` embedded where a
/// manifest expected a name) is redacted the same way.
///
/// # Examples
///
/// ```
/// use deps_core::redact::RedactedName;
///
/// let redacted = RedactedName::new("com.google.guava:guava");
/// assert_eq!(redacted.to_string(), "com.google.guava:guava");
///
/// let redacted = RedactedName::new("com.google.guava:deploy:TOKEN@git.internal.corp");
/// assert_eq!(redacted.to_string(), "***@git.internal.corp");
/// ```
pub type RedactedName = RedactedText<NameRedaction>;

#[cfg(test)]
mod tests {
    use super::*;

    /// FR-003: `RedactedUrl::new` must match `url_for_tracing`'s output byte-for-byte for
    /// every input this module's own regression suite already pins.
    #[test]
    fn test_redacted_url_matches_url_for_tracing_byte_for_byte() {
        let inputs = [
            "https://npm.internal/pkg?token=super-secret-value",
            "https://user:hunter2@registry.example/simple?token=x",
            "https://registry.example/simple",
            "not-a-url-at-all",
            "@types/node",
            "c:/user:hunter2@evil",
            "c:///user:hunter2@evil",
        ];
        for raw in inputs {
            assert_eq!(RedactedUrl::new(raw).to_string(), url_for_tracing(raw));
        }
    }

    /// The `RedactedName` equivalent of the `RedactedUrl` consistency check above (#1216).
    #[test]
    fn test_redacted_name_matches_redact_declaration_key_byte_for_byte() {
        let inputs = [
            "com.google.guava:guava",
            "com.google.guava:deploy:TOKEN@git.internal.corp",
            "source:Blocked",
            "scope:@myorg",
            "top-level",
        ];
        for raw in inputs {
            assert_eq!(
                RedactedName::new(raw).to_string(),
                redact_declaration_key(raw)
            );
        }
    }

    /// NFR-004: the public read surface (`Display`/`AsRef<str>`/`into_inner`) returns redacted
    /// text only, for a known-sensitive input — there is no accessor that could return `raw`.
    /// `into_inner` is checked last since it consumes `self` (#1317 critic S3: this accessor
    /// was added after this test was written and had gone uncovered by it).
    #[test]
    fn test_redacted_url_display_and_as_ref_never_expose_raw_credential() {
        let raw = "https://user:hunter2@registry.example/simple?token=super-secret-value";
        let redacted = RedactedUrl::new(raw);
        assert!(!redacted.to_string().contains("hunter2"));
        assert!(!redacted.to_string().contains("super-secret-value"));
        assert!(!redacted.as_ref().contains("hunter2"));
        assert!(!redacted.as_ref().contains("super-secret-value"));
        assert_eq!(redacted.to_string(), "https://***@registry.example/simple");

        let owned = redacted.into_inner();
        assert!(!owned.contains("hunter2"));
        assert!(!owned.contains("super-secret-value"));
        assert_eq!(owned, "https://***@registry.example/simple");
    }

    /// `into_inner`'s equivalent of the `RedactedUrl`/`RedactedName` byte-for-byte checks above
    /// (#1317 critic S3): it must never diverge from `Display`, since it hands back the exact
    /// same already-redacted `String` instead of a clone of it.
    #[test]
    fn test_into_inner_matches_display_byte_for_byte() {
        for raw in [
            "https://npm.internal/pkg?token=super-secret-value",
            "https://user:hunter2@registry.example/simple?token=x",
            "https://registry.example/simple",
            "@types/node",
        ] {
            assert_eq!(RedactedUrl::new(raw).into_inner(), url_for_tracing(raw));
        }
        for raw in [
            "com.google.guava:guava",
            "com.google.guava:deploy:TOKEN@git.internal.corp",
            "source:Blocked",
        ] {
            assert_eq!(
                RedactedName::new(raw).into_inner(),
                redact_declaration_key(raw)
            );
        }
    }

    /// `Debug` forwards to the redacted text's own quoted-string rendering, not a
    /// struct-wrapper form, and must never expose the raw credential either.
    #[test]
    fn test_redacted_url_debug_forwards_to_inner_string_and_redacts() {
        let redacted = RedactedUrl::new("https://user:hunter2@registry.example/simple");
        assert_eq!(
            format!("{redacted:?}"),
            "\"https://***@registry.example/simple\""
        );
    }

    /// The scoped-package-name no-op (#767 M1) must hold through `RedactedUrl` too.
    #[test]
    fn test_redacted_url_noop_for_scoped_package_name() {
        assert_eq!(RedactedUrl::new("@types/node").to_string(), "@types/node");
    }

    /// #1216: `PartialEq<str>`/`PartialEq<&str>` are on the generic `RedactedText<K>`, so both
    /// aliases have them — compares against the redacted text, not raw input.
    #[test]
    fn test_redacted_url_partial_eq_str_compares_redacted_text() {
        let redacted = RedactedUrl::new("https://user:hunter2@registry.example/simple");
        let expected: &str = "https://***@registry.example/simple";
        // `PartialEq<&str>` (RHS is a `&str` value).
        assert_eq!(redacted, expected);
        // `PartialEq<str>` (RHS is a dereferenced, unsized `str`).
        assert_eq!(redacted, *expected);
        assert_ne!(redacted, "https://user:hunter2@registry.example/simple");
    }

    /// #1216: same guarantee as the `RedactedUrl` case above, for `RedactedName`.
    #[test]
    fn test_redacted_name_partial_eq_str_compares_redacted_text() {
        let redacted = RedactedName::new("com.google.guava:guava");
        let expected: &str = "com.google.guava:guava";
        assert_eq!(redacted, expected);
        assert_eq!(redacted, *expected);
    }
}
