//! Errors specific to Cargo/Rust dependency handling.
//!
//! These errors cover parsing Cargo.toml files. Registry communication
//! errors are reported as `deps_core::DepsError` directly (see
//! `crate::registry`).

use thiserror::Error;

/// Errors specific to Cargo/Rust dependency handling.
#[derive(Error, Debug)]
pub enum CargoError {
    /// Failed to parse Cargo.toml
    #[error("Failed to parse Cargo.toml: {message}")]
    TomlParseError { message: String },

    /// Invalid file URI
    #[error("Invalid file URI: {uri}")]
    InvalidUri { uri: String },
}

/// Result type alias for Cargo operations.
pub type Result<T> = std::result::Result<T, CargoError>;

impl CargoError {
    /// Create an invalid URI error.
    pub fn invalid_uri(uri: impl Into<String>) -> Self {
        Self::InvalidUri { uri: uri.into() }
    }
}

/// Convert to deps_core::DepsError for interoperability
impl From<CargoError> for deps_core::DepsError {
    fn from(err: CargoError) -> Self {
        match err {
            CargoError::TomlParseError { message } => Self::ParseError {
                file_type: "Cargo.toml".into(),
                source: Box::new(std::io::Error::other(message)),
            },
            CargoError::InvalidUri { uri } => Self::CacheError(format!("Invalid URI: {uri}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = CargoError::TomlParseError {
            message: "unexpected token".into(),
        };
        assert_eq!(
            err.to_string(),
            "Failed to parse Cargo.toml: unexpected token"
        );

        let err = CargoError::invalid_uri("not-a-valid-uri");
        assert!(err.to_string().contains("not-a-valid-uri"));
    }

    #[test]
    fn test_conversion_to_deps_error() {
        let cargo_err = CargoError::TomlParseError {
            message: "test".into(),
        };
        let deps_err: deps_core::DepsError = cargo_err.into();
        assert!(matches!(deps_err, deps_core::DepsError::ParseError { .. }));

        let cargo_err = CargoError::invalid_uri("bad");
        let deps_err: deps_core::DepsError = cargo_err.into();
        assert!(matches!(deps_err, deps_core::DepsError::CacheError(_)));
    }
}
