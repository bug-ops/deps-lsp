//! Errors specific to Maven/pom.xml dependency handling.

use thiserror::Error;

#[derive(Error, Debug)]
pub enum MavenError {
    #[error("Failed to parse pom.xml: {message}")]
    ParseError { message: String },

    #[error("Invalid version '{version}': {message}")]
    InvalidVersion { version: String, message: String },

    #[error("Package '{package}' not found on Maven Central")]
    PackageNotFound { package: String },

    #[error("Maven Central request failed for '{package}': {source}")]
    RegistryError {
        package: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    #[error("Failed to parse Maven Central API response for '{package}': {source}")]
    ApiResponseError {
        package: String,
        #[source]
        source: serde_json::Error,
    },

    #[error("Invalid Maven coordinates '{coordinates}': expected 'groupId:artifactId'")]
    InvalidCoordinates { coordinates: String },

    #[error("Cache error: {0}")]
    CacheError(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Other(#[from] Box<dyn std::error::Error + Send + Sync>),
}

pub type Result<T> = std::result::Result<T, MavenError>;

impl From<deps_core::DepsError> for MavenError {
    fn from(err: deps_core::DepsError) -> Self {
        match err {
            deps_core::DepsError::ParseError { source, .. } => Self::CacheError(source.to_string()),
            deps_core::DepsError::CacheError(msg) => Self::CacheError(msg),
            deps_core::DepsError::InvalidVersionReq(msg) => Self::InvalidVersion {
                version: String::new(),
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

impl From<MavenError> for deps_core::DepsError {
    fn from(err: MavenError) -> Self {
        match err {
            MavenError::ParseError { message } => Self::ParseError {
                file_type: "pom.xml".into(),
                source: Box::new(std::io::Error::other(message)),
            },
            MavenError::InvalidVersion { message, .. } => Self::InvalidVersionReq(message),
            MavenError::PackageNotFound { package } => {
                Self::CacheError(format!("Package '{package}' not found"))
            }
            MavenError::RegistryError { package, source } => Self::ParseError {
                file_type: format!("Maven Central for {package}"),
                source,
            },
            MavenError::ApiResponseError { source, .. } => Self::Json(source),
            MavenError::InvalidCoordinates { coordinates } => {
                Self::CacheError(format!("Invalid coordinates: {coordinates}"))
            }
            MavenError::CacheError(msg) => Self::CacheError(msg),
            MavenError::Io(e) => Self::Io(e),
            MavenError::Other(e) => Self::CacheError(e.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = MavenError::PackageNotFound {
            package: "org.apache.commons:commons-lang3".into(),
        };
        assert_eq!(
            err.to_string(),
            "Package 'org.apache.commons:commons-lang3' not found on Maven Central"
        );

        let err = MavenError::InvalidCoordinates {
            coordinates: "badcoords".into(),
        };
        assert!(err.to_string().contains("badcoords"));
    }

    #[test]
    fn test_conversion_to_deps_error() {
        let err = MavenError::PackageNotFound {
            package: "test:pkg".into(),
        };
        let deps_err: deps_core::DepsError = err.into();
        assert!(deps_err.to_string().contains("not found"));
    }

    #[test]
    fn test_parse_error_to_deps_error() {
        let err = MavenError::ParseError {
            message: "syntax error".into(),
        };
        let deps_err: deps_core::DepsError = err.into();
        assert!(matches!(deps_err, deps_core::DepsError::ParseError { .. }));
    }

    #[test]
    fn test_invalid_version_to_deps_error() {
        let err = MavenError::InvalidVersion {
            version: "bad".into(),
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
        let err: MavenError = io_err.into();
        assert!(matches!(err, MavenError::Io(_)));

        let deps_err: deps_core::DepsError = err.into();
        assert!(matches!(deps_err, deps_core::DepsError::Io(_)));
    }

    #[test]
    fn test_deps_error_to_maven_error() {
        let deps_err = deps_core::DepsError::CacheError("cache miss".into());
        let maven_err: MavenError = deps_err.into();
        assert!(matches!(maven_err, MavenError::CacheError(_)));

        let deps_err = deps_core::DepsError::InvalidVersionReq("bad".into());
        let maven_err: MavenError = deps_err.into();
        assert!(matches!(maven_err, MavenError::InvalidVersion { .. }));
    }

    #[test]
    fn test_api_response_error_to_deps_error() {
        let json_err = serde_json::from_str::<serde_json::Value>("{invalid}").unwrap_err();
        let err = MavenError::ApiResponseError {
            package: "test:pkg".into(),
            source: json_err,
        };
        let deps_err: deps_core::DepsError = err.into();
        assert!(matches!(deps_err, deps_core::DepsError::Json(_)));
    }

    #[test]
    fn test_other_error_to_deps_error() {
        let other: Box<dyn std::error::Error + Send + Sync> =
            Box::new(std::io::Error::other("unknown"));
        let err = MavenError::Other(other);
        let deps_err: deps_core::DepsError = err.into();
        assert!(matches!(deps_err, deps_core::DepsError::CacheError(_)));
    }
}
