//! Errors specific to NuGet/.NET project file handling.

use thiserror::Error;

#[derive(Error, Debug)]
pub enum NuGetError {
    #[error("Failed to parse project file: {message}")]
    ParseError { message: String },

    #[error("Invalid version '{version}': {message}")]
    InvalidVersion { version: String, message: String },

    #[error("Package '{package}' not found on NuGet")]
    PackageNotFound { package: String },

    #[error("NuGet request failed for '{package}': {source}")]
    RegistryError {
        package: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    #[error("Failed to resolve NuGet service index: {source}")]
    ServiceIndexError {
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    #[error("Failed to parse NuGet API response for '{package}': {source}")]
    ApiResponseError {
        package: String,
        #[source]
        source: serde_json::Error,
    },

    #[error("Cache error: {0}")]
    CacheError(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Other(#[from] Box<dyn std::error::Error + Send + Sync>),
}

pub type Result<T> = std::result::Result<T, NuGetError>;

impl From<deps_core::DepsError> for NuGetError {
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

impl From<NuGetError> for deps_core::DepsError {
    fn from(err: NuGetError) -> Self {
        match err {
            NuGetError::ParseError { message } => Self::ParseError {
                file_type: "NuGet project file".into(),
                source: Box::new(std::io::Error::other(message)),
            },
            NuGetError::InvalidVersion { message, .. } => Self::InvalidVersionReq(message),
            NuGetError::PackageNotFound { package } => {
                Self::CacheError(format!("Package '{package}' not found"))
            }
            NuGetError::RegistryError { package, source } => Self::ParseError {
                file_type: format!("NuGet registry for {package}"),
                source,
            },
            NuGetError::ServiceIndexError { source } => Self::ParseError {
                file_type: "NuGet service index".into(),
                source,
            },
            NuGetError::ApiResponseError { source, .. } => Self::Json(source),
            NuGetError::CacheError(msg) => Self::CacheError(msg),
            NuGetError::Io(e) => Self::Io(e),
            NuGetError::Other(e) => Self::CacheError(e.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = NuGetError::PackageNotFound {
            package: "Newtonsoft.Json".into(),
        };
        assert_eq!(
            err.to_string(),
            "Package 'Newtonsoft.Json' not found on NuGet"
        );
    }

    #[test]
    fn test_conversion_to_deps_error() {
        let err = NuGetError::PackageNotFound {
            package: "test-pkg".into(),
        };
        let deps_err: deps_core::DepsError = err.into();
        assert!(deps_err.to_string().contains("not found"));
    }

    #[test]
    fn test_parse_error_to_deps_error() {
        let err = NuGetError::ParseError {
            message: "syntax error".into(),
        };
        let deps_err: deps_core::DepsError = err.into();
        assert!(matches!(deps_err, deps_core::DepsError::ParseError { .. }));
    }

    #[test]
    fn test_invalid_version_to_deps_error() {
        let err = NuGetError::InvalidVersion {
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
        let err: NuGetError = io_err.into();
        assert!(matches!(err, NuGetError::Io(_)));

        let deps_err: deps_core::DepsError = err.into();
        assert!(matches!(deps_err, deps_core::DepsError::Io(_)));
    }

    #[test]
    fn test_deps_error_to_nuget_error() {
        let deps_err = deps_core::DepsError::CacheError("cache miss".into());
        let nuget_err: NuGetError = deps_err.into();
        assert!(matches!(nuget_err, NuGetError::CacheError(_)));

        let deps_err = deps_core::DepsError::InvalidVersionReq("bad".into());
        let nuget_err: NuGetError = deps_err.into();
        assert!(matches!(nuget_err, NuGetError::InvalidVersion { .. }));
    }

    #[test]
    fn test_service_index_error_to_deps_error() {
        let err = NuGetError::ServiceIndexError {
            source: Box::new(std::io::Error::other("index fetch failed")),
        };
        let deps_err: deps_core::DepsError = err.into();
        assert!(matches!(deps_err, deps_core::DepsError::ParseError { .. }));
    }

    #[test]
    fn test_api_response_error_to_deps_error() {
        let json_err = serde_json::from_str::<serde_json::Value>("{invalid}").unwrap_err();
        let err = NuGetError::ApiResponseError {
            package: "test-pkg".into(),
            source: json_err,
        };
        let deps_err: deps_core::DepsError = err.into();
        assert!(matches!(deps_err, deps_core::DepsError::Json(_)));
    }

    #[test]
    fn test_other_error_to_deps_error() {
        let other: Box<dyn std::error::Error + Send + Sync> =
            Box::new(std::io::Error::other("unknown"));
        let err = NuGetError::Other(other);
        let deps_err: deps_core::DepsError = err.into();
        assert!(matches!(deps_err, deps_core::DepsError::CacheError(_)));
    }
}
