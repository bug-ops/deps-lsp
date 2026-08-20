//! Errors specific to Maven/pom.xml dependency handling.

use thiserror::Error;

/// Errors specific to Maven/pom.xml dependency handling.
///
/// These errors cover parsing pom.xml files. Registry communication errors
/// are reported as `deps_core::DepsError` directly (see `crate::registry`).
#[derive(Error, Debug)]
pub enum MavenError {
    #[error("Failed to parse pom.xml: {message}")]
    ParseError { message: String },
}

pub type Result<T> = std::result::Result<T, MavenError>;

impl From<MavenError> for deps_core::DepsError {
    fn from(err: MavenError) -> Self {
        match err {
            MavenError::ParseError { message } => Self::ParseError {
                file_type: "pom.xml".into(),
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
        let err = MavenError::ParseError {
            message: "syntax error".into(),
        };
        assert_eq!(err.to_string(), "Failed to parse pom.xml: syntax error");
    }

    #[test]
    fn test_parse_error_to_deps_error() {
        let err = MavenError::ParseError {
            message: "syntax error".into(),
        };
        let deps_err: deps_core::DepsError = err.into();
        assert!(matches!(deps_err, deps_core::DepsError::ParseError { .. }));
    }
}
