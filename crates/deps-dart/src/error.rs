//! Errors specific to Dart/Pub dependency handling.

use thiserror::Error;

#[derive(Error, Debug)]
pub enum DartError {
    #[error("Failed to parse pubspec.yaml: {message}")]
    ParseError { message: String },

    #[error("Invalid version constraint '{constraint}': {message}")]
    InvalidVersionConstraint { constraint: String, message: String },

    #[error("Package '{package}' not found on pub.dev")]
    PackageNotFound { package: String },

    #[error("pub.dev request failed for '{package}': {source}")]
    RegistryError {
        package: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    #[error("Failed to parse pub.dev API response for '{package}': {source}")]
    ApiResponseError {
        package: String,
        #[source]
        source: serde_json::Error,
    },

    #[error("Invalid pubspec.yaml structure: {message}")]
    InvalidStructure { message: String },

    #[error("Invalid file URI: {uri}")]
    InvalidUri { uri: String },

    #[error("Cache error: {0}")]
    CacheError(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Other(#[from] Box<dyn std::error::Error + Send + Sync>),
}

pub type Result<T> = std::result::Result<T, DartError>;

impl From<deps_core::DepsError> for DartError {
    fn from(err: deps_core::DepsError) -> Self {
        match err {
            deps_core::DepsError::ParseError { source, .. } => Self::CacheError(source.to_string()),
            deps_core::DepsError::CacheError(msg) => Self::CacheError(msg),
            deps_core::DepsError::InvalidVersionReq(msg) => Self::InvalidVersionConstraint {
                constraint: String::new(),
                message: msg,
            },
            deps_core::DepsError::Io(e) => Self::Io(e),
            deps_core::DepsError::Json(e) => Self::ApiResponseError {
                package: String::new(),
                source: e,
            },
            other => Self::CacheError(other.to_string()),
        }
    }
}

impl From<DartError> for deps_core::DepsError {
    fn from(err: DartError) -> Self {
        match err {
            DartError::ParseError { message } => Self::ParseError {
                file_type: "pubspec.yaml".into(),
                source: Box::new(std::io::Error::other(message)),
            },
            DartError::InvalidVersionConstraint { message, .. } => Self::InvalidVersionReq(message),
            DartError::PackageNotFound { package } => {
                Self::CacheError(format!("Package '{package}' not found"))
            }
            DartError::RegistryError { package, source } => Self::ParseError {
                file_type: format!("pub.dev for {package}"),
                source,
            },
            DartError::ApiResponseError { source, .. } => Self::Json(source),
            DartError::InvalidStructure { message } => Self::CacheError(message),
            DartError::InvalidUri { uri } => Self::CacheError(format!("Invalid URI: {uri}")),
            DartError::CacheError(msg) => Self::CacheError(msg),
            DartError::Io(e) => Self::Io(e),
            DartError::Other(e) => Self::CacheError(e.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = DartError::PackageNotFound {
            package: "nonexistent".into(),
        };
        assert_eq!(
            err.to_string(),
            "Package 'nonexistent' not found on pub.dev"
        );

        let err = DartError::InvalidStructure {
            message: "missing name".into(),
        };
        assert_eq!(
            err.to_string(),
            "Invalid pubspec.yaml structure: missing name"
        );
    }

    #[test]
    fn test_conversion_to_deps_error() {
        let err = DartError::PackageNotFound {
            package: "test".into(),
        };
        let deps_err: deps_core::DepsError = err.into();
        assert!(deps_err.to_string().contains("not found"));
    }

    #[test]
    fn test_parse_error_to_deps_error() {
        let err = DartError::ParseError {
            message: "syntax error".into(),
        };
        let deps_err: deps_core::DepsError = err.into();
        assert!(matches!(deps_err, deps_core::DepsError::ParseError { .. }));
    }

    #[test]
    fn test_invalid_constraint_to_deps_error() {
        let err = DartError::InvalidVersionConstraint {
            constraint: "bad".into(),
            message: "invalid".into(),
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
        let err: DartError = io_err.into();
        assert!(matches!(err, DartError::Io(_)));

        let deps_err: deps_core::DepsError = err.into();
        assert!(matches!(deps_err, deps_core::DepsError::Io(_)));
    }

    #[test]
    fn test_deps_error_to_dart_error() {
        let deps_err = deps_core::DepsError::CacheError("cache miss".into());
        let dart_err: DartError = deps_err.into();
        assert!(matches!(dart_err, DartError::CacheError(_)));

        let deps_err = deps_core::DepsError::InvalidVersionReq("bad".into());
        let dart_err: DartError = deps_err.into();
        assert!(matches!(
            dart_err,
            DartError::InvalidVersionConstraint { .. }
        ));
    }

    #[test]
    fn test_api_response_error_to_deps_error() {
        let json_err = serde_json::from_str::<serde_json::Value>("{invalid}").unwrap_err();
        let err = DartError::ApiResponseError {
            package: "test".into(),
            source: json_err,
        };
        let deps_err: deps_core::DepsError = err.into();
        assert!(matches!(deps_err, deps_core::DepsError::Json(_)));
    }

    #[test]
    fn test_invalid_uri_to_deps_error() {
        let err = DartError::InvalidUri {
            uri: "bad://uri".into(),
        };
        let deps_err: deps_core::DepsError = err.into();
        assert!(matches!(deps_err, deps_core::DepsError::CacheError(_)));
    }

    #[test]
    fn test_other_error_to_deps_error() {
        let other: Box<dyn std::error::Error + Send + Sync> =
            Box::new(std::io::Error::other("unknown"));
        let err = DartError::Other(other);
        let deps_err: deps_core::DepsError = err.into();
        assert!(matches!(deps_err, deps_core::DepsError::CacheError(_)));
    }
}
