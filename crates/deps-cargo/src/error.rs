//! Errors specific to Cargo/Rust dependency handling.
//!
//! These errors cover parsing Cargo.toml files, validating semver specifications,
//! and communicating with the crates.io registry.

use thiserror::Error;

/// Errors specific to Cargo/Rust dependency handling.
///
/// These errors cover parsing Cargo.toml files, validating semver specifications,
/// and communicating with the crates.io registry.
#[derive(Error, Debug)]
pub enum CargoError {
    /// Failed to parse Cargo.toml
    #[error("Failed to parse Cargo.toml: {source}")]
    TomlParseError {
        #[source]
        source: toml_edit::TomlError,
    },

    /// Invalid semver version specifier
    #[error("Invalid semver version specifier '{specifier}': {message}")]
    InvalidVersionSpecifier { specifier: String, message: String },

    /// Package not found on crates.io
    #[error("Crate '{package}' not found on crates.io")]
    PackageNotFound { package: String },

    /// crates.io registry request failed
    #[error("crates.io registry request failed for '{package}': {source}")]
    RegistryError {
        package: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// Failed to deserialize crates.io API response
    #[error("Failed to parse crates.io API response for '{package}': {source}")]
    ApiResponseError {
        package: String,
        #[source]
        source: serde_json::Error,
    },

    /// Invalid Cargo.toml structure
    #[error("Invalid Cargo.toml structure: {message}")]
    InvalidStructure { message: String },

    /// Missing required field in Cargo.toml
    #[error("Missing required field '{field}' in {section}")]
    MissingField { section: String, field: String },

    /// Workspace configuration error
    #[error("Workspace error: {message}")]
    WorkspaceError { message: String },

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

/// Result type alias for Cargo operations.
pub type Result<T> = std::result::Result<T, CargoError>;

impl CargoError {
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

    /// Create a workspace error.
    pub fn workspace_error(message: impl Into<String>) -> Self {
        Self::WorkspaceError {
            message: message.into(),
        }
    }

    /// Create an invalid URI error.
    pub fn invalid_uri(uri: impl Into<String>) -> Self {
        Self::InvalidUri { uri: uri.into() }
    }
}

/// Convert from deps_core::DepsError for compatibility
impl From<deps_core::DepsError> for CargoError {
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

/// Convert to deps_core::DepsError for interoperability
impl From<CargoError> for deps_core::DepsError {
    fn from(err: CargoError) -> Self {
        match err {
            CargoError::TomlParseError { source } => Self::ParseError {
                file_type: "Cargo.toml".into(),
                source: Box::new(source),
            },
            CargoError::InvalidVersionSpecifier { message, .. } => Self::InvalidVersionReq(message),
            CargoError::PackageNotFound { package } => {
                Self::CacheError(format!("Crate '{package}' not found"))
            }
            CargoError::RegistryError { package, source } => Self::ParseError {
                file_type: format!("crates.io registry for {package}"),
                source,
            },
            CargoError::ApiResponseError { source, .. } => Self::Json(source),
            CargoError::InvalidStructure { message } => Self::CacheError(message),
            CargoError::MissingField { section, field } => {
                Self::CacheError(format!("Missing '{field}' in {section}"))
            }
            CargoError::WorkspaceError { message } => Self::CacheError(message),
            CargoError::InvalidUri { uri } => Self::CacheError(format!("Invalid URI: {uri}")),
            CargoError::CacheError(msg) => Self::CacheError(msg),
            CargoError::Io(e) => Self::Io(e),
            CargoError::Other(e) => Self::CacheError(e.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = CargoError::PackageNotFound {
            package: "nonexistent".into(),
        };
        assert_eq!(
            err.to_string(),
            "Crate 'nonexistent' not found on crates.io"
        );

        let err = CargoError::missing_field("dependencies", "serde");
        assert_eq!(
            err.to_string(),
            "Missing required field 'serde' in dependencies"
        );

        let err = CargoError::invalid_structure("missing [package] section");
        assert_eq!(
            err.to_string(),
            "Invalid Cargo.toml structure: missing [package] section"
        );
    }

    #[test]
    fn test_error_construction() {
        let err =
            CargoError::registry_error("serde", std::io::Error::from(std::io::ErrorKind::NotFound));
        assert!(matches!(err, CargoError::RegistryError { .. }));

        let json_err = serde_json::from_str::<serde_json::Value>("invalid").unwrap_err();
        let err = CargoError::api_response_error("tokio", json_err);
        assert!(matches!(err, CargoError::ApiResponseError { .. }));
    }

    #[test]
    fn test_invalid_version_specifier() {
        let err = CargoError::invalid_version_specifier("invalid", "not a valid semver");
        assert!(err.to_string().contains("invalid"));
        assert!(err.to_string().contains("not a valid semver"));
    }

    #[test]
    fn test_workspace_error() {
        let err = CargoError::workspace_error("workspace root not found");
        assert!(err.to_string().contains("workspace root not found"));
    }

    #[test]
    fn test_invalid_uri() {
        let err = CargoError::invalid_uri("not-a-valid-uri");
        assert!(err.to_string().contains("not-a-valid-uri"));
    }

    #[test]
    fn test_conversion_to_deps_error() {
        let cargo_err = CargoError::PackageNotFound {
            package: "test".into(),
        };
        let deps_err: deps_core::DepsError = cargo_err.into();
        assert!(deps_err.to_string().contains("not found"));
    }
}
