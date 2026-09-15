//! Conversions between `deps-core`'s protocol-agnostic domain types
//! (`url::Url`, [`deps_core::position::Position`], [`deps_core::position::Range`]) and
//! `tower_lsp_server::ls_types`.
//!
//! `deps-lsp` is the sole adapter boundary where these two type families meet (issue
//! #1071): `deps-core`/`deps-engine` never construct or consume an `ls_types` type for their
//! domain data, and every handler in this crate converts at the edge, right before building
//! an LSP response or right after reading one from a request. This is the **only** module
//! that is allowed to perform the `url::Url` ⇄ `ls_types::Uri` conversion — keeping it in one
//! named place means a future accidental reimplementation elsewhere is easy to spot in review.
//!
//! These are plain free functions, not [`From`]/[`Into`] trait impls: neither `url::Url` nor
//! `tower_lsp_server::ls_types::Uri` is local to this crate, so a `From` impl in either
//! direction would violate Rust's orphan rules. [`deps_core::position::Position`]/
//! [`deps_core::position::Range`] do not have this problem (they're local to `deps-core`, so
//! `deps-core` itself defines `From` impls for those — see [`deps_core::position`]'s module
//! doc) but the free-function pair here is kept for symmetry and so every conversion in this
//! module reads the same way at a call site.

use tower_lsp_server::ls_types;

/// Converts an LSP-protocol `Uri` (from a client request) into the domain `url::Url` that
/// `deps-core`/`deps-engine` operate on.
///
/// Returns `None` when `uri` cannot be represented as a `url::Url` at all — a real,
/// client-triggerable case, not a defensive-only guard: `tower_lsp_server::ls_types::Uri`
/// parses generic RFC 3986 URIs (via `fluent-uri`), while `url::Url` implements the WHATWG
/// URL Standard with `file`-scheme special-casing, and the two grammars diverge on
/// acceptance. For example, `file://host:8080/x` is a valid RFC 3986 URI (and thus a valid
/// `Uri`) but `Url::parse` rejects it, since a port is illegal for WHATWG's special `file`
/// scheme. Every caller must treat `None` the same as "no ecosystem handles this URI" — see
/// `EcosystemRegistry::for_uri`'s callers in this crate for the pattern.
#[must_use]
pub fn from_lsp_uri(uri: &ls_types::Uri) -> Option<url::Url> {
    uri.as_str().parse().ok()
}

/// Converts a domain `url::Url` back into the `tower_lsp_server::ls_types::Uri` an LSP
/// response object (`Location`, `WorkspaceEdit`, ...) requires.
///
/// # Panics
///
/// Panics if `url` does not round-trip into an `ls_types::Uri`. In practice this never
/// happens: every `url::Url` reaching this function either came from [`from_lsp_uri`] moments
/// earlier in the same request, or was constructed by a `deps-core`/`deps-engine` ecosystem
/// parser directly from that same round-tripped value.
#[must_use]
pub fn to_lsp_uri(url: &url::Url) -> ls_types::Uri {
    url.as_str()
        .parse()
        .unwrap_or_else(|e| panic!("Url {url} did not round-trip to an LSP Uri: {e}"))
}

/// Converts an LSP-protocol `Position` into the domain [`deps_core::position::Position`].
#[must_use]
pub fn from_lsp_position(position: ls_types::Position) -> deps_core::position::Position {
    position.into()
}

/// Converts a domain [`deps_core::position::Position`] into the LSP-protocol `Position` a
/// response object requires.
#[must_use]
pub fn to_lsp_position(position: deps_core::position::Position) -> ls_types::Position {
    position.into()
}

/// Converts an LSP-protocol `Range` into the domain [`deps_core::position::Range`].
#[must_use]
pub fn from_lsp_range(range: ls_types::Range) -> deps_core::position::Range {
    range.into()
}

/// Converts a domain [`deps_core::position::Range`] into the LSP-protocol `Range` a response
/// object requires.
#[must_use]
pub fn to_lsp_range(range: deps_core::position::Range) -> ls_types::Range {
    range.into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::test_helpers::platform_path;

    #[test]
    fn test_uri_roundtrips_unix_path() {
        let ls_uri =
            ls_types::Uri::from_file_path(platform_path("/home/user/project/Cargo.toml")).unwrap();
        let url = from_lsp_uri(&ls_uri).unwrap();
        // `url.to_file_path()` returns a decoded native path (e.g. `C:\...` on Windows),
        // while `ls_uri.path()` is the raw, still-percent-encoded URI path component (a
        // Windows drive-letter colon is encoded as `%3A` there) — comparing those two
        // directly diverges on Windows even for a correct round-trip, so this checks the
        // decoded path against the original filesystem path instead, then verifies the
        // full URI round-trip below the same way the other tests in this module do.
        assert_eq!(
            url.to_file_path().unwrap(),
            std::path::PathBuf::from(platform_path("/home/user/project/Cargo.toml"))
        );
        let back = to_lsp_uri(&url);
        assert_eq!(back, ls_uri);
    }

    /// Per plan.md's gotchas: `url::Url` and `ls_types::Uri` are not always byte-identical
    /// for the same file path across platforms — a path with spaces/percent-encoding-worthy
    /// characters and a nested directory structure exercises more than the trivial
    /// single-segment Unix case above.
    #[test]
    fn test_uri_roundtrips_non_trivial_path_shape() {
        let ls_uri =
            ls_types::Uri::from_file_path(platform_path("/home/user/My Projects/a b/Cargo.toml"))
                .unwrap();
        let url = from_lsp_uri(&ls_uri).unwrap();
        let back = to_lsp_uri(&url);
        assert_eq!(
            back, ls_uri,
            "a path with spaces must round-trip through Url and back to an identical Uri"
        );
    }

    /// Non-ASCII path segments (accented Latin characters, CJK text) exercise
    /// `url::Url`'s percent-encoding of multi-byte UTF-8 bytes — a different code path
    /// from the plain-ASCII space-encoding case above, and this module's core risk
    /// (`url::Url`/`ls_types::Uri` platform/encoding divergence).
    #[test]
    fn test_uri_roundtrips_unicode_path() {
        let ls_uri =
            ls_types::Uri::from_file_path(platform_path("/home/usér/prøjects/café/包.json"))
                .unwrap();
        let url = from_lsp_uri(&ls_uri).unwrap();
        let back = to_lsp_uri(&url);
        assert_eq!(
            back, ls_uri,
            "a path with non-ASCII characters must round-trip through Url and back to an \
             identical Uri"
        );
    }

    /// S1 regression: `file://host:8080/x` is a valid RFC 3986 URI (`fluent-uri`, which
    /// backs `ls_types::Uri`, accepts it) but a port is illegal for WHATWG's special
    /// `file` scheme, so `Url::parse` rejects it. `from_lsp_uri` must degrade to `None`
    /// instead of panicking on a shape a real LSP client can send.
    #[test]
    fn test_from_lsp_uri_returns_none_for_a_url_incompatible_uri() {
        let ls_uri: ls_types::Uri = "file://host:8080/x/Cargo.toml".parse().unwrap();
        assert!(
            from_lsp_uri(&ls_uri).is_none(),
            "a file: URI with a port is valid RFC 3986 but invalid WHATWG url::Url"
        );
    }

    /// S3 documentation: `Url::parse` normalizes several `ls_types::Uri`-valid spellings
    /// to a different string — round-tripping through `from_lsp_uri`/`to_lsp_uri` does
    /// NOT reproduce the client's original `Uri` in these cases. Callers that need to key
    /// a response (e.g. a `WorkspaceEdit`'s `changes` map) by the exact URI the client
    /// holds open must reuse the original `Uri` from the request, not `to_lsp_uri`'s
    /// output — see `handlers::code_actions`' `WorkspaceEdit` re-keying for the fix this
    /// documents.
    #[test]
    fn test_url_parse_normalizes_some_uri_spellings() {
        let cases = [
            (
                "file://localhost/home/u/Cargo.toml",
                "file:///home/u/Cargo.toml",
            ),
            ("FILE:///x/Cargo.toml", "file:///x/Cargo.toml"),
            ("file:///a/./b/../Cargo.toml", "file:///a/Cargo.toml"),
            (
                "file:////server/share/Cargo.toml",
                "file:///server/share/Cargo.toml",
            ),
        ];
        for (input, expected_normalized) in cases {
            let ls_uri: ls_types::Uri = input.parse().unwrap();
            let url = from_lsp_uri(&ls_uri).unwrap();
            let back = to_lsp_uri(&url);
            assert_eq!(
                back.as_str(),
                expected_normalized,
                "expected {input:?} to normalize to {expected_normalized:?}, got {:?} — if \
                 this now fails, url::Url's normalization behavior changed and S3's \
                 re-keying fix in handlers::code_actions may need revisiting",
                back.as_str()
            );
        }
    }

    #[test]
    fn test_position_roundtrips() {
        let ls_position = ls_types::Position::new(12, 34);
        let domain = from_lsp_position(ls_position);
        assert_eq!(domain.line, 12);
        assert_eq!(domain.character, 34);
        assert_eq!(to_lsp_position(domain), ls_position);
    }

    #[test]
    fn test_range_roundtrips() {
        let ls_range =
            ls_types::Range::new(ls_types::Position::new(0, 0), ls_types::Position::new(2, 5));
        let domain = from_lsp_range(ls_range);
        assert_eq!(domain.start.line, 0);
        assert_eq!(domain.end.line, 2);
        assert_eq!(to_lsp_range(domain), ls_range);
    }
}
