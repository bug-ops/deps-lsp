//! Errors specific to npm/JavaScript dependency handling.
//!
//! These errors cover parsing package.json files, validating npm semver specifications,
//! and communicating with the npm registry.

use thiserror::Error;

/// Errors specific to npm/JavaScript dependency handling.
///
/// These errors cover parsing package.json files, validating npm semver specifications,
/// and communicating with the npm registry.
#[derive(Error, Debug)]
pub enum NpmError {
    /// Failed to parse package.json
    #[error("Failed to parse package.json: {source}")]
    JsonParseError {
        #[source]
        source: serde_json::Error,
    },

    /// Invalid npm semver version specifier
    #[error("Invalid npm semver version specifier '{specifier}': {message}")]
    InvalidVersionSpecifier { specifier: String, message: String },

    /// Package not found on npm registry
    #[error("Package '{package}' not found on npm registry")]
    PackageNotFound { package: String },

    /// npm registry request failed
    #[error("npm registry request failed for '{package}': {source}")]
    RegistryError {
        package: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// Failed to deserialize npm API response
    #[error("Failed to parse npm API response for '{package}': {source}")]
    ApiResponseError {
        package: String,
        #[source]
        source: serde_json::Error,
    },

    /// Invalid package.json structure
    #[error("Invalid package.json structure: {message}")]
    InvalidStructure { message: String },

    /// Missing required field in package.json
    #[error("Missing required field '{field}' in {section}")]
    MissingField { section: String, field: String },

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

/// Result type alias for npm operations.
pub type Result<T> = std::result::Result<T, NpmError>;

impl NpmError {
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

    /// Create a missing field error.
    pub fn missing_field(section: impl Into<String>, field: impl Into<String>) -> Self {
        Self::MissingField {
            section: section.into(),
            field: field.into(),
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
}

/// Convert from deps_core::DepsError for compatibility
impl From<deps_core::DepsError> for NpmError {
    fn from(err: deps_core::DepsError) -> Self {
        match err {
            deps_core::DepsError::ParseError { source, .. } => {
                NpmError::CacheError(source.to_string())
            }
            deps_core::DepsError::CacheError(msg) => NpmError::CacheError(msg),
            deps_core::DepsError::InvalidVersionReq(msg) => NpmError::InvalidVersionSpecifier {
                specifier: String::new(),
                message: msg,
            },
            deps_core::DepsError::Io(e) => NpmError::Io(e),
            deps_core::DepsError::Json(e) => NpmError::JsonParseError { source: e },
            other => NpmError::CacheError(other.to_string()),
        }
    }
}

/// Convert to deps_core::DepsError for interoperability
impl From<NpmError> for deps_core::DepsError {
    fn from(err: NpmError) -> Self {
        match err {
            NpmError::JsonParseError { source } => deps_core::DepsError::Json(source),
            NpmError::InvalidVersionSpecifier { message, .. } => {
                deps_core::DepsError::InvalidVersionReq(message)
            }
            NpmError::PackageNotFound { package } => {
                deps_core::DepsError::CacheError(format!("Package '{}' not found", package))
            }
            NpmError::RegistryError { package, source } => deps_core::DepsError::ParseError {
                file_type: format!("npm registry for {}", package),
                source,
            },
            NpmError::ApiResponseError { source, .. } => deps_core::DepsError::Json(source),
            NpmError::InvalidStructure { message } => deps_core::DepsError::CacheError(message),
            NpmError::MissingField { section, field } => {
                deps_core::DepsError::CacheError(format!("Missing '{}' in {}", field, section))
            }
            NpmError::CacheError(msg) => deps_core::DepsError::CacheError(msg),
            NpmError::Io(e) => deps_core::DepsError::Io(e),
            NpmError::Other(e) => deps_core::DepsError::CacheError(e.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = NpmError::PackageNotFound {
            package: "nonexistent".into(),
        };
        assert_eq!(
            err.to_string(),
            "Package 'nonexistent' not found on npm registry"
        );

        let err = NpmError::missing_field("dependencies", "express");
        assert_eq!(
            err.to_string(),
            "Missing required field 'express' in dependencies"
        );

        let err = NpmError::invalid_structure("missing name field");
        assert_eq!(
            err.to_string(),
            "Invalid package.json structure: missing name field"
        );
    }

    #[test]
    fn test_error_construction() {
        let err = NpmError::registry_error(
            "express",
            std::io::Error::from(std::io::ErrorKind::NotFound),
        );
        assert!(matches!(err, NpmError::RegistryError { .. }));

        let json_err = serde_json::from_str::<serde_json::Value>("invalid").unwrap_err();
        let err = NpmError::api_response_error("lodash", json_err);
        assert!(matches!(err, NpmError::ApiResponseError { .. }));
    }

    #[test]
    fn test_invalid_version_specifier() {
        let err = NpmError::invalid_version_specifier("invalid", "not a valid semver");
        assert!(err.to_string().contains("invalid"));
        assert!(err.to_string().contains("not a valid semver"));
    }

    #[test]
    fn test_conversion_to_deps_error() {
        let npm_err = NpmError::PackageNotFound {
            package: "test".into(),
        };
        let deps_err: deps_core::DepsError = npm_err.into();
        assert!(deps_err.to_string().contains("not found"));
    }
}
