//! Errors specific to Gradle dependency handling.

use thiserror::Error;

#[derive(Error, Debug)]
pub enum GradleError {
    #[error("Failed to parse Gradle file: {message}")]
    ParseError { message: String },

    #[error("Invalid Gradle dependency format: {message}")]
    InvalidDependency { message: String },

    #[error(transparent)]
    Maven(#[from] deps_maven::MavenError),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, GradleError>;

impl From<GradleError> for deps_core::DepsError {
    fn from(err: GradleError) -> Self {
        match err {
            GradleError::ParseError { message } => Self::ParseError {
                file_type: "Gradle".into(),
                source: Box::new(std::io::Error::other(message)),
            },
            GradleError::InvalidDependency { message } => Self::InvalidVersionReq(message),
            GradleError::Maven(e) => e.into(),
            GradleError::Io(e) => Self::Io(e),
        }
    }
}

impl From<deps_core::DepsError> for GradleError {
    fn from(err: deps_core::DepsError) -> Self {
        match err {
            deps_core::DepsError::ParseError { source, .. } => Self::ParseError {
                message: source.to_string(),
            },
            deps_core::DepsError::CacheError(msg) => Self::ParseError { message: msg },
            deps_core::DepsError::InvalidVersionReq(msg) => {
                Self::InvalidDependency { message: msg }
            }
            deps_core::DepsError::Io(e) => Self::Io(e),
            other => Self::ParseError {
                message: other.to_string(),
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
    fn test_invalid_dependency_display() {
        let err = GradleError::InvalidDependency {
            message: "bad format".into(),
        };
        assert!(err.to_string().contains("bad format"));
    }

    #[test]
    fn test_conversion_to_deps_error() {
        let err = GradleError::ParseError {
            message: "test".into(),
        };
        let deps_err: deps_core::DepsError = err.into();
        assert!(matches!(deps_err, deps_core::DepsError::ParseError { .. }));
    }

    #[test]
    fn test_invalid_dep_to_deps_error() {
        let err = GradleError::InvalidDependency {
            message: "bad".into(),
        };
        let deps_err: deps_core::DepsError = err.into();
        assert!(matches!(
            deps_err,
            deps_core::DepsError::InvalidVersionReq(_)
        ));
    }

    #[test]
    fn test_io_error_conversion() {
        let io_err = std::io::Error::from(std::io::ErrorKind::NotFound);
        let err: GradleError = io_err.into();
        assert!(matches!(err, GradleError::Io(_)));
        let deps_err: deps_core::DepsError = err.into();
        assert!(matches!(deps_err, deps_core::DepsError::Io(_)));
    }

    #[test]
    fn test_deps_error_to_gradle_error() {
        let deps_err = deps_core::DepsError::CacheError("cache miss".into());
        let gradle_err: GradleError = deps_err.into();
        assert!(matches!(gradle_err, GradleError::ParseError { .. }));
    }
}
