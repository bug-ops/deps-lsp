//! Errors specific to Gradle dependency handling.

use thiserror::Error;

#[derive(Error, Debug)]
pub enum GradleError {
    #[error("Failed to parse Gradle file: {message}")]
    ParseError { message: String },
}

pub type Result<T> = std::result::Result<T, GradleError>;

impl From<GradleError> for deps_core::DepsError {
    fn from(err: GradleError) -> Self {
        match err {
            GradleError::ParseError { message } => Self::ParseError {
                file_type: "Gradle".into(),
                source: Box::new(std::io::Error::other(message)),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_error_display() {
        let err = GradleError::ParseError {
            message: "syntax error".into(),
        };
        assert!(err.to_string().contains("syntax error"));
    }

    #[test]
    fn test_conversion_to_deps_error() {
        let err = GradleError::ParseError {
            message: "test".into(),
        };
        let deps_err: deps_core::DepsError = err.into();
        assert!(matches!(deps_err, deps_core::DepsError::ParseError { .. }));
    }
}
