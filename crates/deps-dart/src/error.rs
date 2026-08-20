//! Errors specific to Dart/Pub dependency handling.
//!
//! These errors cover parsing pubspec.yaml files. Registry communication
//! errors are reported as `deps_core::DepsError` directly (see
//! `crate::registry`).

use thiserror::Error;

#[derive(Error, Debug)]
pub enum DartError {
    #[error("Failed to parse pubspec.yaml: {message}")]
    ParseError { message: String },
}

pub type Result<T> = std::result::Result<T, DartError>;

impl From<DartError> for deps_core::DepsError {
    fn from(err: DartError) -> Self {
        match err {
            DartError::ParseError { message } => Self::ParseError {
                file_type: "pubspec.yaml".into(),
                source: Box::new(std::io::Error::other(message)),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = DartError::ParseError {
            message: "unexpected token".into(),
        };
        assert_eq!(
            err.to_string(),
            "Failed to parse pubspec.yaml: unexpected token"
        );
    }

    #[test]
    fn test_conversion_to_deps_error() {
        let err = DartError::ParseError {
            message: "syntax error".into(),
        };
        let deps_err: deps_core::DepsError = err.into();
        assert!(matches!(deps_err, deps_core::DepsError::ParseError { .. }));
    }
}
