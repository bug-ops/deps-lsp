//! Errors specific to PHP/Composer dependency handling.

use thiserror::Error;

/// Errors specific to PHP/Composer dependency handling.
#[derive(Error, Debug)]
pub enum ComposerError {
    /// Failed to parse composer.json
    #[error("Failed to parse composer.json: {source}")]
    JsonParseError {
        #[source]
        source: serde_json::Error,
    },

    /// Package not found on Packagist
    #[error("Package '{package}' not found on Packagist")]
    PackageNotFound { package: String },

    /// Packagist registry request failed
    #[error("Packagist registry request failed for '{package}': {source}")]
    RegistryError {
        package: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Result type alias for Composer operations.
pub type Result<T> = std::result::Result<T, ComposerError>;

impl From<ComposerError> for deps_core::DepsError {
    fn from(err: ComposerError) -> Self {
        match err {
            ComposerError::JsonParseError { source } => Self::Json(source),
            ComposerError::PackageNotFound { package } => {
                Self::CacheError(format!("Package '{package}' not found"))
            }
            ComposerError::RegistryError { package, source } => Self::ParseError {
                file_type: format!("Packagist registry for {package}"),
                source,
            },
            ComposerError::Io(e) => Self::Io(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = ComposerError::PackageNotFound {
            package: "vendor/package".into(),
        };
        assert_eq!(
            err.to_string(),
            "Package 'vendor/package' not found on Packagist"
        );
    }

    #[test]
    fn test_conversion_to_deps_error() {
        let err = ComposerError::PackageNotFound {
            package: "test/pkg".into(),
        };
        let deps_err: deps_core::DepsError = err.into();
        assert!(deps_err.to_string().contains("not found"));
    }
}
