//! Conversions between `deps-core`'s protocol-agnostic domain types
//! (`url::Url`, [`deps_core::position::Position`], [`deps_core::position::Range`],
//! [`deps_core::diagnostic::Diagnostic`] and its nested types) and `tower_lsp_server::ls_types`.
//!
//! `deps-core`/`deps-engine` never construct or consume an `ls_types` type for their own
//! domain data; every `deps-lsp` handler converts at the edge, right before building an LSP
//! response or right after reading one from a request. This module is where the `url::Url`
//! ⇄ `ls_types::Uri` conversion for a *request/response boundary* URI is meant to happen —
//! but it is not, in practice, the only place a `url::Url`/`ls_types::Uri` conversion exists
//! in the workspace: `deps_core::lsp_helpers::to_ls_uri` performs an identical one-way
//! `Url -> Uri` conversion, called directly by `deps-github-actions`/`deps-composer`/
//! `deps-gitlab-ci` for edits they build themselves (`WorkspaceEdit` changes, hover links) —
//! a pre-existing duplication this module's introduction did not create and does not resolve
//! (tracked as a follow-up, not fixed here). Likewise,
//! [`crate::lsp_types_interop::from_lsp_position`]/
//! [`crate::lsp_types_interop::to_lsp_position`]/[`crate::lsp_types_interop::from_lsp_range`]
//! below are unused outside this module's own unit tests — real call sites (e.g.
//! `handlers::completion`) convert via the bare `.into()`
//! [`deps_core::position::Position`]/[`deps_core::position::Range`] already provide (see
//! [`deps_core::position`]'s module doc for those `From` impls), not through these wrappers.
//! [`crate::lsp_types_interop::to_lsp_uri`], [`crate::lsp_types_interop::to_lsp_diagnostic`],
//! and the other `to_lsp_*`/`from_lsp_uri` functions genuinely are each's single
//! implementation within `deps-lsp` itself.
//!
//! The `Uri`/`Diagnostic`-shaped conversions here are plain free functions, not
//! [`From`]/[`Into`] trait impls: neither `url::Url` nor `tower_lsp_server::ls_types::Uri` (nor
//! `ls_types::Diagnostic` and friends) is local to this crate, so a `From` impl in either
//! direction would violate Rust's orphan rules. [`deps_core::position::Position`]/
//! [`deps_core::position::Range`] do not have this problem (they're local to `deps-core`, so
//! `deps-core` itself defines `From` impls for those) but the free-function pair here is kept
//! for symmetry with the `Uri`/`Diagnostic` conversions that have no other option.

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
///
/// Also returns `None` when parsing raises [`url::SyntaxViolation::FileWithHostAndWindowsDrive`]
/// (issue #1090's guard gap): for a `file:` URI with a non-empty host whose first path segment
/// is shaped like a Windows drive letter (e.g. `file://attacker.example/C:/x`), the WHATWG
/// parser silently discards the host and returns a `Url` that looks like a legitimate
/// host-less `file:///C:/x` URI — indistinguishable, after the fact, from a trusted local
/// path. This is not `cfg!(windows)`-gated; it reproduces on every host OS because it depends
/// only on the shape of the input string. This function is the last point with access to the
/// original, unparsed string, so it is the only place that can still detect the violation and
/// reject the URI instead of silently downgrading a remote-host reference to a local one.
#[must_use]
pub fn from_lsp_uri(uri: &ls_types::Uri) -> Option<url::Url> {
    let host_stripped_by_windows_drive_rule = std::cell::Cell::new(false);
    let url = url::Url::options()
        .syntax_violation_callback(Some(&|violation| {
            if violation == url::SyntaxViolation::FileWithHostAndWindowsDrive {
                host_stripped_by_windows_drive_rule.set(true);
            }
        }))
        .parse(uri.as_str())
        .ok()?;
    (!host_stripped_by_windows_drive_rule.get()).then_some(url)
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

/// Converts a domain [`deps_core::diagnostic::Severity`] into the LSP-protocol
/// `DiagnosticSeverity` a response object requires.
#[must_use]
pub const fn to_lsp_diagnostic_severity(
    severity: deps_core::diagnostic::Severity,
) -> ls_types::DiagnosticSeverity {
    match severity {
        deps_core::diagnostic::Severity::Error => ls_types::DiagnosticSeverity::ERROR,
        deps_core::diagnostic::Severity::Warning => ls_types::DiagnosticSeverity::WARNING,
        deps_core::diagnostic::Severity::Information => ls_types::DiagnosticSeverity::INFORMATION,
        deps_core::diagnostic::Severity::Hint => ls_types::DiagnosticSeverity::HINT,
    }
}

/// Converts a domain [`deps_core::diagnostic::CodeDescription`] into the LSP-protocol
/// `CodeDescription` a response object requires.
///
/// Takes `code_description` by value: every call site owns a [`deps_core::diagnostic::Diagnostic`]
/// it's converting and discards right after, so there's no reason to clone out of a
/// reference here.
#[must_use]
pub fn to_lsp_code_description(
    code_description: deps_core::diagnostic::CodeDescription,
) -> ls_types::CodeDescription {
    ls_types::CodeDescription {
        href: to_lsp_uri(&code_description.href),
    }
}

/// Converts a domain [`deps_core::diagnostic::RelatedInformation`] into the LSP-protocol
/// `DiagnosticRelatedInformation` a response object requires.
///
/// Takes `related` by value — see [`to_lsp_code_description`]'s doc for why.
#[must_use]
pub fn to_lsp_related_information(
    related: deps_core::diagnostic::RelatedInformation,
) -> ls_types::DiagnosticRelatedInformation {
    ls_types::DiagnosticRelatedInformation {
        location: ls_types::Location {
            uri: to_lsp_uri(&related.uri),
            range: to_lsp_range(related.range),
        },
        message: related.message,
    }
}

/// Converts a domain [`deps_core::diagnostic::Diagnostic`] into the LSP-protocol `Diagnostic`
/// [`crate::handlers::diagnostics`] publishes to the client.
///
/// The domain type is what [`deps_core::ecosystem::Ecosystem::generate_diagnostics`] returns.
///
/// `source` is always `"deps-lsp"`: every diagnostic this server emits carries the same
/// constant value, so the domain type (shared with `deps-cli`, which has no use for an
/// LSP-protocol `source` label) does not carry the field at all — this is the single place
/// that attaches it.
#[must_use]
pub fn to_lsp_diagnostic(diagnostic: deps_core::diagnostic::Diagnostic) -> ls_types::Diagnostic {
    ls_types::Diagnostic {
        range: to_lsp_range(diagnostic.range),
        severity: diagnostic.severity.map(to_lsp_diagnostic_severity),
        code: diagnostic.code.map(ls_types::NumberOrString::String),
        code_description: diagnostic.code_description.map(to_lsp_code_description),
        source: Some("deps-lsp".into()),
        message: diagnostic.message,
        related_information: diagnostic.related_information.map(|related| {
            related
                .into_iter()
                .map(to_lsp_related_information)
                .collect()
        }),
        ..Default::default()
    }
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
        // Compares the decoded path, not raw `ls_uri.path()`: percent-encoding (e.g. a
        // Windows drive-letter `:` as `%3A`) makes those diverge even on a correct round-trip.
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

    /// Issue #1090 guard-gap regression: `url::Url`'s WHATWG parser silently discards a
    /// `file:` URI's host when the first path segment is a literal, unencoded Windows drive
    /// letter (`SyntaxViolation::FileWithHostAndWindowsDrive`), turning
    /// `file://attacker.example/C:/real/path` into a host-less `file:///C:/real/path` — a
    /// shape indistinguishable, once parsed, from a trusted local URI. This reproduces on
    /// every host OS (it depends only on input shape, not `cfg!(windows)`), so this test
    /// needs no Windows runner: the malicious value is built directly as a raw string with a
    /// literal, unencoded colon (mirroring an actual malicious wire-format LSP request from a
    /// client, which is not obligated to percent-encode it) rather than via
    /// `Uri::from_file_path`, which always percent-encodes the colon as `%3A` and therefore
    /// never reproduces this exact bypass — see `server::tests::
    /// test_did_change_watched_files_rejects_malicious_uri`'s doc comment for why its
    /// `from_file_path`-derived malicious case does not exercise this shape either.
    #[test]
    fn test_from_lsp_uri_rejects_windows_drive_host_bypass() {
        let malicious: ls_types::Uri = "file://attacker.example/C:/real/temp/dir/Cargo.toml"
            .parse()
            .expect("a literal-colon drive-letter path is valid RFC 3986");
        assert!(
            from_lsp_uri(&malicious).is_none(),
            "a file: URI with a non-empty host and a Windows-drive-letter-shaped path must be \
             rejected, not silently downgraded to a host-less local path"
        );

        // Positive control: an equivalent legitimate URI must still convert — the guard above
        // must not be overbroad and reject ordinary `file:` URIs.
        let temp_dir = tempfile::tempdir().unwrap();
        let real_path = temp_dir.path().join("Cargo.toml");
        std::fs::write(&real_path, "[package]\n").unwrap();
        let legitimate = ls_types::Uri::from_file_path(&real_path).unwrap();
        let url = from_lsp_uri(&legitimate)
            .expect("a legitimate, host-less file: URI must still convert to a Url");
        assert_eq!(url.to_file_path().unwrap(), real_path);
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

    #[test]
    fn test_to_lsp_diagnostic_converts_every_field() {
        use deps_core::diagnostic::{CodeDescription, Diagnostic, RelatedInformation, Severity};
        use deps_core::position::{Position, Range};

        let related_uri = url::Url::parse("file:///Cargo.toml").unwrap();
        let code_href = url::Url::parse("https://osv.dev/GHSA-xxxx").unwrap();
        let diagnostic = Diagnostic::new(
            Range::new(Position::new(0, 0), Position::new(0, 5)),
            "vulnerable",
        )
        .with_severity(Severity::Error)
        .with_code("GHSA-xxxx")
        .with_code_description(CodeDescription::new(code_href.clone()))
        .with_related_information(vec![RelatedInformation::new(
            related_uri.clone(),
            Range::new(Position::new(1, 0), Position::new(1, 4)),
            "also here",
        )]);

        let ls_diagnostic = to_lsp_diagnostic(diagnostic);
        assert_eq!(
            ls_diagnostic.range,
            ls_types::Range::new(ls_types::Position::new(0, 0), ls_types::Position::new(0, 5))
        );
        assert_eq!(
            ls_diagnostic.severity,
            Some(ls_types::DiagnosticSeverity::ERROR)
        );
        assert_eq!(
            ls_diagnostic.code,
            Some(ls_types::NumberOrString::String("GHSA-xxxx".into()))
        );
        assert_eq!(
            ls_diagnostic.code_description.unwrap().href,
            to_lsp_uri(&code_href)
        );
        assert_eq!(ls_diagnostic.source.as_deref(), Some("deps-lsp"));
        assert_eq!(ls_diagnostic.message, "vulnerable");
        let related = ls_diagnostic.related_information.unwrap();
        assert_eq!(related.len(), 1);
        assert_eq!(related[0].location.uri, to_lsp_uri(&related_uri));
        assert_eq!(related[0].message, "also here");
    }

    #[test]
    fn test_to_lsp_diagnostic_severity_mapping() {
        use deps_core::diagnostic::Severity;

        assert_eq!(
            to_lsp_diagnostic_severity(Severity::Error),
            ls_types::DiagnosticSeverity::ERROR
        );
        assert_eq!(
            to_lsp_diagnostic_severity(Severity::Warning),
            ls_types::DiagnosticSeverity::WARNING
        );
        assert_eq!(
            to_lsp_diagnostic_severity(Severity::Information),
            ls_types::DiagnosticSeverity::INFORMATION
        );
        assert_eq!(
            to_lsp_diagnostic_severity(Severity::Hint),
            ls_types::DiagnosticSeverity::HINT
        );
    }
}
