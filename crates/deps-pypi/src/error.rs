use thiserror::Error;

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
    TomlParseError { message: String },

    /// Invalid PEP 508 dependency specification
    #[error("Invalid PEP 508 dependency specification: {source}")]
    InvalidDependencySpec {
        #[source]
        source: pep508_rs::Pep508Error,
    },

    /// Unsupported dependency format
    #[error("Unsupported dependency format: {message}")]
    UnsupportedFormat { message: String },

    /// PEP 508 requirement string exceeded the length cap protecting against
    /// `pep508_rs`'s O(n²) extras-list parser (see
    /// `crate::parser::MAX_REQUIREMENT_LEN`). Kept as a distinct variant
    /// (rather than folded into `UnsupportedFormat`) so callers can tell a
    /// deliberate length rejection apart from a genuine syntax error — the
    /// two must be counted differently by heuristics like the
    /// `requirements.txt` "is this really a manifest" signal.
    #[error("requirement string too long: {len} bytes (max {max} bytes)")]
    RequirementTooLong { len: usize, max: usize },
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
