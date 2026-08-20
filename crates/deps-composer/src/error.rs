//! Errors specific to PHP/Composer dependency handling.
//!
//! These errors cover parsing composer.json files. Registry communication
//! errors are reported as `deps_core::DepsError` directly (see
//! `crate::registry`).

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
}

/// Result type alias for Composer operations.
pub type Result<T> = std::result::Result<T, ComposerError>;

impl From<ComposerError> for deps_core::DepsError {
    fn from(err: ComposerError) -> Self {
        match err {
            ComposerError::JsonParseError { source } => Self::Json(source),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let json_err = serde_json::from_str::<serde_json::Value>("invalid").unwrap_err();
        let err = ComposerError::JsonParseError { source: json_err };
        assert!(err.to_string().contains("Failed to parse composer.json"));
    }

    #[test]
    fn test_conversion_to_deps_error() {
        let json_err = serde_json::from_str::<serde_json::Value>("invalid").unwrap_err();
        let err = ComposerError::JsonParseError { source: json_err };
        let deps_err: deps_core::DepsError = err.into();
        assert!(matches!(deps_err, deps_core::DepsError::Json(_)));
    }
}
