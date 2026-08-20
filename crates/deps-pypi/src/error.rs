use thiserror::Error;

/// Errors specific to PyPI/Python dependency handling.
///
/// These errors cover parsing pyproject.toml files and validating PEP 508
/// dependency specifications. Registry communication errors are reported as
/// `deps_core::DepsError` directly (see `crate::registry`).
#[derive(Error, Debug)]
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
