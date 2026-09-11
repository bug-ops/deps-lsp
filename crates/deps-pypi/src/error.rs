use thiserror::Error;

/// Wraps `pep508_rs::Pep508Error` so it is not directly exposed in a `deps-pypi` public signature.
///
/// Keeps the pre-1.0 `pep508_rs` dependency type (#835) out of [`PypiError`]'s public
/// signature — `pep508_rs` can introduce a breaking change to `Pep508Error` without that
/// counting as a breaking change for `deps-pypi` itself.
#[derive(Debug)]
pub struct Pep508ParseError(pep508_rs::Pep508Error);

impl std::fmt::Display for Pep508ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
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
}
