//! Conversions between `deps-core`'s protocol-agnostic domain types
//! (`url::Url`, [`deps_core::position::Range`], [`deps_core::diagnostic::Diagnostic`] and its
//! nested types) and `tower_lsp_server::ls_types`.
//!
//! `deps-core`/`deps-engine` never construct or consume an `ls_types` type for their own
//! domain data; every `deps-lsp` handler converts at the edge, right before building an LSP
//! response or right after reading one from a request. `Position`/`Range` conversions in the
//! other direction (LSP-protocol to domain) go through the bare `.into()`
//! [`deps_core::position::Position`]/[`deps_core::position::Range`] already provide (see
//! [`deps_core::position`]'s module doc for those `From` impls) — real call sites (e.g.
//! `handlers::completion`) use that, not a wrapper here, so this module only keeps
//! [`crate::lsp_types_interop::to_lsp_range`] for the domain-to-LSP direction, plus the
//! `Uri`/`Diagnostic` conversions that have no `From`-impl option (see below).
//!
//! [`crate::lsp_types_interop::to_lsp_uri`] wraps [`deps_core::to_ls_uri`] rather than
//! reimplementing the `url::Url -> Uri` conversion: `deps-core` is the shared crate ecosystem
//! crates (`deps-github-actions`, `deps-composer`, `deps-gitlab-ci`) can depend on for edits
//! they build themselves (`WorkspaceEdit` changes, hover links), while this binary crate
//! cannot be a dependency of any of them — so [`deps_core::to_ls_uri`] is the one underlying
//! implementation, and this module's [`crate::lsp_types_interop::to_lsp_uri`] is `deps-lsp`'s
//! thin wrapper over it, not a second, independent copy.
//!
//! The `Uri`/`Diagnostic`-shaped conversions here are plain free functions, not
//! [`From`]/[`Into`] trait impls: neither `url::Url` nor `tower_lsp_server::ls_types::Uri` (nor
//! `ls_types::Diagnostic` and friends) is local to this crate, so a `From` impl in either
//! direction would violate Rust's orphan rules. [`deps_core::position::Position`]/
//! [`deps_core::position::Range`] do not have this problem (they're local to `deps-core`, so
//! `deps-core` itself defines `From` impls for those).

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
/// Thin wrapper over [`deps_core::to_ls_uri`] — see the module doc for why the conversion
/// itself lives in `deps-core` rather than being reimplemented here.
///
/// # Panics
///
/// Panics if `url` does not round-trip into an `ls_types::Uri` — see [`deps_core::to_ls_uri`]'s
/// own `# Panics` section.
#[must_use]
pub fn to_lsp_uri(url: &url::Url) -> ls_types::Uri {
    deps_core::to_ls_uri(url)
}

/// Computes the one canonical spelling of a client-supplied `Uri`.
///
/// Every LSP entry point keys `ServerState::documents` and echoes response URIs by the same
/// identity regardless of how the client spelled the request. Round-trips through [`from_lsp_uri`]/[`to_lsp_uri`] to reuse `url::Url`'s WHATWG
/// normalization (`file://localhost/x` -> `file:///x`, case, `.`/`..` segments, UNC form) —
/// see `test_url_parse_normalizes_some_uri_spellings` for the exact variants folded together.
///
/// When `from_lsp_uri` rejects `uri` (malformed, or the #1090 Windows-drive-with-host guard),
/// this returns `uri` unchanged rather than falling back to some other key: callers downstream
/// already treat an unparseable `Uri` as "no ecosystem handles this" (`EcosystemRegistry::for_uri`
/// returns `None`), so no document is ever created under this non-canonical value — the
/// passthrough is inert, not a silent bypass of the rejection.
#[must_use]
pub fn canonicalize_uri(uri: &ls_types::Uri) -> ls_types::Uri {
    from_lsp_uri(uri).map_or_else(|| uri.clone(), |url| to_lsp_uri(&url))
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
        message: related.message().to_string(),
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
    let message = diagnostic.message().to_string();
    let code = diagnostic.code().map(ToString::to_string);
    ls_types::Diagnostic {
        range: to_lsp_range(diagnostic.range),
        severity: diagnostic.severity.map(to_lsp_diagnostic_severity),
        code: code.map(ls_types::NumberOrString::String),
        code_description: diagnostic.code_description.map(to_lsp_code_description),
        source: Some("deps-lsp".into()),
        message,
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
    /// NOT reproduce the client's original `Uri` in these cases. This is exactly the
    /// divergence [`canonicalize_uri`] exists to fold onto one identity (issue #1086):
    /// every `server.rs` entry point canonicalizes a request's `Uri` before it reaches
    /// `ServerState::documents` or any response, so a `WorkspaceEdit`'s `changes` map key
    /// (or any other response `Uri`) is always built from the same canonical form the
    /// document is stored under, rather than needing a per-handler rekey back to the
    /// client's original spelling.
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
                 this now fails, url::Url's normalization behavior changed and \
                 canonicalize_uri's spelling-variant coverage may need revisiting",
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
    fn test_canonicalize_uri_is_identity_for_already_canonical_input() {
        let ls_uri: ls_types::Uri = "file:///x/Cargo.toml".parse().unwrap();
        assert_eq!(canonicalize_uri(&ls_uri).as_str(), "file:///x/Cargo.toml");
    }

    #[test]
    fn test_canonicalize_uri_normalizes_documented_spelling_variants() {
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
        for (input, expected) in cases {
            let ls_uri: ls_types::Uri = input.parse().unwrap();
            assert_eq!(
                canonicalize_uri(&ls_uri).as_str(),
                expected,
                "expected {input:?} to canonicalize to {expected:?}"
            );
        }
    }

    #[test]
    fn test_canonicalize_uri_passes_through_rejected_windows_drive_host_bypass() {
        let malicious: ls_types::Uri = "file://attacker.example/C:/real/temp/dir/Cargo.toml"
            .parse()
            .expect("a literal-colon drive-letter path is valid RFC 3986");
        assert_eq!(
            canonicalize_uri(&malicious),
            malicious,
            "a from_lsp_uri-rejected Uri must pass through unchanged, not be silently dropped \
             or substituted"
        );
    }

    #[test]
    fn test_to_lsp_range_converts_domain_range() {
        use deps_core::position::{Position, Range};

        let domain = Range::new(Position::new(0, 0), Position::new(2, 5));
        let ls_range =
            ls_types::Range::new(ls_types::Position::new(0, 0), ls_types::Position::new(2, 5));
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
