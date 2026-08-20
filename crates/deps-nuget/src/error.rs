//! Errors specific to NuGet/.NET project file handling.
//!
//! These errors cover parsing project files. Registry communication errors
//! are reported as `deps_core::DepsError` directly (see `crate::registry`).

use thiserror::Error;

#[derive(Error, Debug)]
pub enum NuGetError {
    #[error("Failed to parse project file: {message}")]
    ParseError { message: String },
}

pub type Result<T> = std::result::Result<T, NuGetError>;

impl From<NuGetError> for deps_core::DepsError {
    fn from(err: NuGetError) -> Self {
        match err {
            NuGetError::ParseError { message } => Self::ParseError {
                file_type: "NuGet project file".into(),
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
        let err = NuGetError::ParseError {
            message: "syntax error".into(),
        };
        assert_eq!(
            err.to_string(),
            "Failed to parse project file: syntax error"
        );
    }

    #[test]
    fn test_conversion_to_deps_error() {
        let err = NuGetError::ParseError {
            message: "syntax error".into(),
        };
        let deps_err: deps_core::DepsError = err.into();
        assert!(matches!(deps_err, deps_core::DepsError::ParseError { .. }));
    }
}
