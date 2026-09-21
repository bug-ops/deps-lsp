use thiserror::Error;

/// Wraps `pep508_rs::Pep508Error` so it is not directly exposed in a `deps-pypi` public signature.
///
/// Keeps the pre-1.0 `pep508_rs` dependency type (#835) out of [`PypiError`]'s public
/// signature — `pep508_rs` can introduce a breaking change to `Pep508Error` without that
/// counting as a breaking change for `deps-pypi` itself.
///
/// Has no derived `Debug`, and a hand-written `Display`, both forwarding to `Self::kind_str`
/// rather than the wrapped error's own — mirrors `PackageName`'s #1219/#1217 pattern. Every
/// current internal call site already used `kind_str()`/`reason_for_log()` explicitly (#1228
/// critic rounds 2-3), so this closes the type itself against a *future* call site that writes
/// `tracing::warn!("{}", err)`/`err.to_string()`/`{err:?}` directly and reopens the leak with no
/// compiler or test signal — the same class of gap #1219 closed for `PackageName`.
pub struct Pep508ParseError(pep508_rs::Pep508Error);

impl std::fmt::Display for Pep508ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.kind_str())
    }
}

impl std::fmt::Debug for Pep508ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Pep508ParseError")
            .field(&self.kind_str())
            .finish()
    }
}

impl std::error::Error for Pep508ParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.0.source()
    }
}

impl Pep508ParseError {
    /// Constructs from the raw `pep508_rs` error. `pub(crate)`, not a public `From` impl —
    /// a public conversion would put the pre-1.0 `pep508_rs::Pep508Error` type back in this
    /// crate's public API surface (as the argument type), undoing the point of wrapping it.
    pub(crate) fn new(error: pep508_rs::Pep508Error) -> Self {
        Self(error)
    }

    /// A safe-to-log category for the wrapped error — see [`pep508_error_kind_str`]'s doc for
    /// why neither this error's `Display` nor its `message` field alone is safe to interpolate.
    pub(crate) fn kind_str(&self) -> &'static str {
        pep508_error_kind_str(&self.0)
    }
}

/// Classifies a `pep508_rs::Pep508Error` into a static, content-free label.
///
/// Neither `Pep508Error::Display` (which echoes its `input` field verbatim — "the input string
/// so we can print it underlined") nor its `message` field alone is safe to log: `message` can
/// *also* embed the offending substring verbatim (e.g. `` "found `<token>`" ``, where `<token>`
/// can be the entire unparsed remainder — including a credential, in the PEP 508
/// direct-reference-URL case this classifier exists to guard against, #1228). Passing either
/// through a generic URL-credential redactor (`deps_core::net_policy::redact_userinfo`/
/// `url_for_tracing`) is *also* unsafe in the other direction — those heuristics are tuned for
/// URL-shaped values, not free-form prose, and over-trigger on an ordinary English sentence
/// containing an unrelated `:`/`@` (#1228, critic round 2), erasing genuinely useful,
/// credential-free diagnostic text. The only representation that is safe regardless of what
/// `pep508_rs` decides to embed in a future version is a fixed label carrying zero data drawn
/// from `e` itself.
///
/// Shared by [`Pep508ParseError::kind_str`] (the [`crate::error::PypiError::InvalidDependencySpec`]
/// case) and `crate::parser::normalize_marker_string` (`MarkerTree::from_str`'s error, which is
/// this same upstream type but never wrapped by [`PypiError`] at all).
pub(crate) fn pep508_error_kind_str<T: pep508_rs::Pep508Url>(
    e: &pep508_rs::Pep508Error<T>,
) -> &'static str {
    match &e.message {
        pep508_rs::Pep508ErrorSource::String(_) => "invalid PEP 508 syntax",
        pep508_rs::Pep508ErrorSource::UrlError(_) => "invalid direct-reference URL",
        pep508_rs::Pep508ErrorSource::UnsupportedRequirement(_) => {
            "unsupported version requirement"
        }
    }
}

/// Errors specific to PyPI/Python dependency handling.
///
/// These errors cover parsing pyproject.toml files and validating PEP 508
/// dependency specifications. Registry communication errors are reported as
/// `deps_core::DepsError` directly (see `crate::registry`).
///
/// `#[non_exhaustive]` (matching [`crate::types::PypiDependencySection`]):
/// this enum grows as new parse-failure modes are distinguished (e.g.
/// [`PypiError::RequirementTooLong`], added without a matching
/// `cargo-semver-checks` gate), so an external exhaustive `match` must not
/// be able to break on a future addition.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum PypiError {
    /// Failed to parse pyproject.toml
    #[error("Failed to parse pyproject.toml: {message}")]
    TomlParseError {
        /// Description of the TOML parse failure.
        message: String,
    },

    /// Invalid PEP 508 dependency specification
    #[error("Invalid PEP 508 dependency specification: {source}")]
    InvalidDependencySpec {
        /// The underlying PEP 508 parser error.
        #[source]
        source: Pep508ParseError,
    },

    /// Unsupported dependency format
    #[error("Unsupported dependency format: {message}")]
    UnsupportedFormat {
        /// Description of why the format is unsupported.
        message: String,
    },

    /// PEP 508 requirement string exceeded the length cap protecting against
    /// `pep508_rs`'s O(n²) extras-list parser (see
    /// `crate::parser::MAX_REQUIREMENT_LEN`). Kept as a distinct variant
    /// (rather than folded into `UnsupportedFormat`) so callers can tell a
    /// deliberate length rejection apart from a genuine syntax error — the
    /// two must be counted differently by heuristics like the
    /// `requirements.txt` "is this really a manifest" signal.
    #[error("requirement string too long: {len} bytes (max {max} bytes)")]
    RequirementTooLong {
        /// Length of the rejected requirement string, in bytes.
        len: usize,
        /// The length cap that was exceeded, in bytes.
        max: usize,
    },
}

/// Result type alias for PyPI operations.
pub type Result<T> = std::result::Result<T, PypiError>;

impl PypiError {
    /// Create an unsupported format error.
    pub fn unsupported_format(message: impl Into<String>) -> Self {
        Self::UnsupportedFormat {
            message: message.into(),
        }
    }

    /// A safe-to-log description of why parsing failed (#1228).
    ///
    /// [`Self::InvalidDependencySpec`] wraps a third-party `pep508_rs` error — [`Pep508ParseError`]'s
    /// own `Display`/`Debug` are hardened at the type level (reduced to
    /// [`Pep508ParseError::kind_str`]'s fixed category, never interpolating the wrapped error's
    /// content), so this arm, and any future direct `{}`/`{:?}` of a bare [`Pep508ParseError`],
    /// cannot leak regardless of what `pep508_rs` embeds in its own error text.
    ///
    /// [`Self::UnsupportedFormat`]/[`Self::TomlParseError`]'s `message` field, by contrast, is
    /// shown in full and carries no such type-level guarantee — it is *not* inherently free of
    /// third-party-parser text (a [`crate::parser::pyproject`] construction site sets
    /// [`Self::TomlParseError`]'s `message` from `toml_span::Error::Display`, which echoes a
    /// duplicate key/table's name verbatim). Safe today only because every current construction
    /// site redacts/bounds dynamic content (via `truncate_for_log`) before it reaches `message`
    /// — a discipline, not an invariant the type enforces.
    pub(crate) fn reason_for_log(&self) -> String {
        match self {
            Self::InvalidDependencySpec { source } => source.kind_str().to_string(),
            Self::UnsupportedFormat { message } | Self::TomlParseError { message } => {
                message.clone()
            }
            // `len`/`max` are plain `usize`s, never attacker text — `Self::to_string()` (the
            // variant's own `#[error(...)]` template) is already exactly this, so no need to
            // rebuild the format string here.
            Self::RequirementTooLong { .. } => self.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = PypiError::unsupported_format("invalid table format");
        assert_eq!(
            err.to_string(),
            "Unsupported dependency format: invalid table format"
        );
    }

    #[test]
    fn test_toml_parse_error_display() {
        let err = PypiError::TomlParseError {
            message: "unexpected token".into(),
        };
        assert_eq!(
            err.to_string(),
            "Failed to parse pyproject.toml: unexpected token"
        );
    }

    /// A `pep508_rs::Pep508Error::message` (`Pep508ErrorSource::String`) can embed the
    /// offending substring verbatim — this fixture mirrors that shape without needing a real
    /// parse failure.
    fn pep508_error_with_credential_in_message() -> pep508_rs::Pep508Error {
        pep508_rs::Pep508Error {
            message: pep508_rs::Pep508ErrorSource::String(
                "found `https://user:hunter2@evil.example/x`".into(),
            ),
            start: 0,
            len: 1,
            input: "https://user:hunter2@evil.example/x".into(),
        }
    }

    #[test]
    fn test_pep508_error_kind_str_never_echoes_message_or_input() {
        let e = pep508_error_with_credential_in_message();
        let kind = pep508_error_kind_str(&e);
        assert_eq!(kind, "invalid PEP 508 syntax");
        assert!(!kind.contains("hunter2") && !kind.contains("evil.example"));
    }

    #[test]
    fn test_pep508_error_kind_str_url_error_variant() {
        let e: pep508_rs::Pep508Error = pep508_rs::Pep508Error {
            message: pep508_rs::Pep508ErrorSource::UrlError(
                pep508_rs::VerbatimUrlError::WorkingDirectory(
                    "relative/path/user:hunter2@evil.example".into(),
                ),
            ),
            start: 0,
            len: 1,
            input: "relative/path/user:hunter2@evil.example".into(),
        };
        assert_eq!(pep508_error_kind_str(&e), "invalid direct-reference URL");
    }

    #[test]
    fn test_pep508_error_kind_str_unsupported_requirement_variant() {
        let e: pep508_rs::Pep508Error = pep508_rs::Pep508Error {
            message: pep508_rs::Pep508ErrorSource::UnsupportedRequirement(
                "found `user:hunter2@evil.example`".into(),
            ),
            start: 0,
            len: 1,
            input: "user:hunter2@evil.example".into(),
        };
        assert_eq!(pep508_error_kind_str(&e), "unsupported version requirement");
    }

    #[test]
    fn test_reason_for_log_invalid_dependency_spec_is_a_fixed_category() {
        let err = PypiError::InvalidDependencySpec {
            source: Pep508ParseError::new(pep508_error_with_credential_in_message()),
        };
        assert_eq!(err.reason_for_log(), "invalid PEP 508 syntax");
    }

    /// Regression for #1228 critic round 4 (REQUIRED FIX 2): `PypiError`'s own derived
    /// `Display`/`Debug` — not just `reason_for_log`, an opt-in method a future call site could
    /// simply not call — must never leak a credential embedded in a wrapped `pep508_rs` error.
    #[test]
    fn test_invalid_dependency_spec_display_and_debug_never_echo_credential() {
        let err = PypiError::InvalidDependencySpec {
            source: Pep508ParseError::new(pep508_error_with_credential_in_message()),
        };
        let displayed = err.to_string();
        let debugged = format!("{err:?}");
        for rendered in [&displayed, &debugged] {
            assert!(
                !rendered.contains("hunter2") && !rendered.contains("evil.example"),
                "PypiError must never echo the credential directly: {rendered:?}"
            );
        }
    }

    #[test]
    fn test_reason_for_log_unsupported_format_shows_full_self_authored_message() {
        let err = PypiError::unsupported_format("PEP 508 requirement parser panicked");
        assert_eq!(err.reason_for_log(), "PEP 508 requirement parser panicked");
    }

    #[test]
    fn test_reason_for_log_requirement_too_long_reports_the_bounds() {
        let err = PypiError::RequirementTooLong {
            len: 5000,
            max: 4096,
        };
        assert_eq!(
            err.reason_for_log(),
            "requirement string too long: 5000 bytes (max 4096 bytes)"
        );
    }
}
