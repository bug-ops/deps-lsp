use thiserror::Error;

/// Errors specific to PyPI/Python dependency handling.
///
/// These errors cover parsing pyproject.toml files, validating PEP 440/508 specifications,
/// and communicating with the PyPI registry.
#[derive(Error, Debug)]
pub enum PypiError {
    /// Failed to parse pyproject.toml
    #[error("Failed to parse pyproject.toml: {source}")]
    TomlParseError {
        #[source]
        source: toml_edit::TomlError,
    },

    /// Invalid PEP 440 version specifier
    #[error("Invalid PEP 440 version specifier '{specifier}': {source}")]
    InvalidVersionSpecifier {
        specifier: String,
        #[source]
        source: pep440_rs::VersionSpecifiersParseError,
    },

    /// Invalid PEP 508 dependency specification
    #[error("Invalid PEP 508 dependency specification: {source}")]
    InvalidDependencySpec {
        #[source]
        source: pep508_rs::Pep508Error,
    },

    /// Package not found on PyPI
    #[error("Package '{package}' not found on PyPI")]
    PackageNotFound { package: String },

    /// PyPI registry request failed
    #[error("PyPI registry request failed for '{package}': {source}")]
    RegistryError {
        package: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// Failed to deserialize PyPI API response
    #[error("Failed to parse PyPI API response for '{package}': {source}")]
    ApiResponseError {
        package: String,
        #[source]
        source: serde_json::Error,
    },

    /// Unsupported dependency format
    #[error("Unsupported dependency format: {message}")]
    UnsupportedFormat { message: String },

    /// Missing required field in pyproject.toml
    #[error("Missing required field '{field}' in {section}")]
    MissingField { section: String, field: String },

    /// Cache error
    #[error("Cache error: {0}")]
    CacheError(String),

    /// Generic error wrapper
    #[error(transparent)]
    Other(#[from] Box<dyn std::error::Error + Send + Sync>),
}

/// Result type alias for PyPI operations.
pub type Result<T> = std::result::Result<T, PypiError>;

impl PypiError {
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

    /// Create an unsupported format error.
    pub fn unsupported_format(message: impl Into<String>) -> Self {
        Self::UnsupportedFormat {
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = PypiError::PackageNotFound {
            package: "nonexistent".into(),
        };
        assert_eq!(err.to_string(), "Package 'nonexistent' not found on PyPI");

        let err = PypiError::missing_field("project", "dependencies");
        assert_eq!(
            err.to_string(),
            "Missing required field 'dependencies' in project"
        );

        let err = PypiError::unsupported_format("invalid table format");
        assert_eq!(
            err.to_string(),
            "Unsupported dependency format: invalid table format"
        );
    }

    #[test]
    fn test_error_construction() {
        let err = PypiError::registry_error(
            "requests",
            std::io::Error::from(std::io::ErrorKind::NotFound),
        );
        assert!(matches!(err, PypiError::RegistryError { .. }));

        let json_err = serde_json::from_str::<serde_json::Value>("invalid").unwrap_err();
        let err = PypiError::api_response_error("flask", json_err);
        assert!(matches!(err, PypiError::ApiResponseError { .. }));
    }
}
