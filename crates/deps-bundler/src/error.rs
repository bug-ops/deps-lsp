//! Errors specific to Bundler/Ruby dependency handling.

use thiserror::Error;

/// Errors specific to Bundler/Ruby dependency handling.
#[derive(Error, Debug)]
pub enum BundlerError {
    /// Failed to parse Gemfile
    #[error("Failed to parse Gemfile: {message}")]
    ParseError { message: String },

    /// Invalid version specifier
    #[error("Invalid version specifier '{specifier}': {message}")]
    InvalidVersionSpecifier { specifier: String, message: String },

    /// Package not found on rubygems.org
    #[error("Gem '{package}' not found on rubygems.org")]
    PackageNotFound { package: String },

    /// rubygems.org registry request failed
    #[error("rubygems.org request failed for '{package}': {source}")]
    RegistryError {
        package: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// Failed to deserialize rubygems API response
    #[error("Failed to parse rubygems API response for '{package}': {source}")]
    ApiResponseError {
        package: String,
        #[source]
        source: serde_json::Error,
    },

    /// Invalid Gemfile structure
    #[error("Invalid Gemfile structure: {message}")]
    InvalidStructure { message: String },

    /// Invalid file URI
    #[error("Invalid file URI: {uri}")]
    InvalidUri { uri: String },

    /// Cache error
    #[error("Cache error: {0}")]
    CacheError(String),

    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Generic error wrapper
    #[error(transparent)]
    Other(#[from] Box<dyn std::error::Error + Send + Sync>),
}

/// Result type alias for Bundler operations.
pub type Result<T> = std::result::Result<T, BundlerError>;

impl BundlerError {
    /// Create a registry error from any error type.
    pub fn registry_error(
        package: impl Into<String>,
        error: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self::RegistryError {
            package: package.into(),
            source: Box::new(error),
        }
    }

    /// Create an API response error.
    pub fn api_response_error(package: impl Into<String>, error: serde_json::Error) -> Self {
        Self::ApiResponseError {
            package: package.into(),
            source: error,
        }
    }

    /// Create an invalid structure error.
    pub fn invalid_structure(message: impl Into<String>) -> Self {
        Self::InvalidStructure {
            message: message.into(),
        }
    }

    /// Create an invalid version specifier error.
    pub fn invalid_version_specifier(
        specifier: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self::InvalidVersionSpecifier {
            specifier: specifier.into(),
            message: message.into(),
        }
    }

    /// Create an invalid URI error.
    pub fn invalid_uri(uri: impl Into<String>) -> Self {
        Self::InvalidUri { uri: uri.into() }
    }
}

impl From<deps_core::DepsError> for BundlerError {
    fn from(err: deps_core::DepsError) -> Self {
        match err {
            deps_core::DepsError::ParseError { source, .. } => Self::CacheError(source.to_string()),
            deps_core::DepsError::CacheError(msg) => Self::CacheError(msg),
            deps_core::DepsError::InvalidVersionReq(msg) => Self::InvalidVersionSpecifier {
                specifier: String::new(),
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

impl From<BundlerError> for deps_core::DepsError {
    fn from(err: BundlerError) -> Self {
        match err {
            BundlerError::ParseError { message } => Self::ParseError {
                file_type: "Gemfile".into(),
                source: Box::new(std::io::Error::other(message)),
            },
            BundlerError::InvalidVersionSpecifier { message, .. } => {
                Self::InvalidVersionReq(message)
            }
            BundlerError::PackageNotFound { package } => {
                Self::CacheError(format!("Gem '{package}' not found"))
            }
            BundlerError::RegistryError { package, source } => Self::ParseError {
                file_type: format!("rubygems.org for {package}"),
                source,
            },
            BundlerError::ApiResponseError { source, .. } => Self::Json(source),
            BundlerError::InvalidStructure { message } => Self::CacheError(message),
            BundlerError::InvalidUri { uri } => Self::CacheError(format!("Invalid URI: {uri}")),
            BundlerError::CacheError(msg) => Self::CacheError(msg),
            BundlerError::Io(e) => Self::Io(e),
            BundlerError::Other(e) => Self::CacheError(e.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = BundlerError::PackageNotFound {
            package: "nonexistent".into(),
        };
        assert_eq!(
            err.to_string(),
            "Gem 'nonexistent' not found on rubygems.org"
        );

        let err = BundlerError::invalid_structure("missing source");
        assert_eq!(err.to_string(), "Invalid Gemfile structure: missing source");
    }

    #[test]
    fn test_error_construction() {
        let err = BundlerError::registry_error(
            "rails",
            std::io::Error::from(std::io::ErrorKind::NotFound),
        );
        assert!(matches!(err, BundlerError::RegistryError { .. }));

        let json_err = serde_json::from_str::<serde_json::Value>("invalid").unwrap_err();
        let err = BundlerError::api_response_error("rails", json_err);
        assert!(matches!(err, BundlerError::ApiResponseError { .. }));
    }

    #[test]
    fn test_invalid_version_specifier() {
        let err = BundlerError::invalid_version_specifier("invalid", "not a valid version");
        assert!(err.to_string().contains("invalid"));
        assert!(err.to_string().contains("not a valid version"));
    }

    #[test]
    fn test_invalid_uri() {
        let err = BundlerError::invalid_uri("not-a-valid-uri");
        assert!(err.to_string().contains("not-a-valid-uri"));
    }

    #[test]
    fn test_conversion_to_deps_error() {
        let bundler_err = BundlerError::PackageNotFound {
            package: "test".into(),
        };
        let deps_err: deps_core::DepsError = bundler_err.into();
        assert!(deps_err.to_string().contains("not found"));
    }
}
